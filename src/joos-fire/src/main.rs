// A custom firecracker launcher that embeds vmlinux/initrd.cpio/config
// directly (see build.rs) and calls vmm's VMM-construction API in-process,
// instead of this project's usual wrapper (memfd_create + write + fexecve
// into a stock firecracker binary). Eliminates that wrapper's ~10-11ms of
// memfd writes entirely - see FIRECRACKER.md and BOOT_PROFILE.md in the
// parent joos project for the full reasoning and measurements.
//
// No control/API socket - this is deliberately the run-without-api
// equivalent of firecracker's own main.rs, with the HTTP API server left
// out entirely, matching how this project actually uses firecracker today
// (single-shot boot, no interactive API calls).
//
// Expects fire.ext4 in the current directory, same as build/fire.

use vmm::arch::GUEST_PAGE_SIZE;
use vmm::builder::build_and_boot_microvm;
use vmm::logger::{LOGGER, LevelFilter, LoggerConfig};
use vmm::resources::{VmResources, ZeroCopyLayout};
use vmm::seccomp::get_empty_filters;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vmm_config::machine_config::HugePageConfig;
use vmm::{EventManager, FcExitCode};


/// Parses an ASCII-digit-only compile-time string into a `usize`, for
/// turning `env!("JOOS_VMLINUX_MAX")` (build.rs's resolved slot capacity,
/// see resolve_size() there) into an array-size constant. `str::parse`
/// isn't const-evaluable, hence the manual byte-by-byte parse.
const fn parse_usize(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut result: usize = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        assert!(b.is_ascii_digit(), "JOOS_*_MAX must be a plain integer (bytes)");
        result = result * 10 + (b - b'0') as usize;
        i += 1;
    }
    result
}

// Configurable at build time, e.g. `JOOS_VMLINUX_MAX=33554432 cargo build
// ...` (see the Makefile) - build.rs resolves these (with defaults) and
// re-exports them via cargo:rustc-env, so the value read here always
// matches what build.rs padded the slot files to. CONFIG_MAX isn't
// build-time-configurable (config is tiny, unlikely to need it) but could
// be given the same treatment if that changes.
const VMLINUX_MAX: usize = parse_usize(env!("JOOS_VMLINUX_MAX"));
const INITRD_MAX: usize = parse_usize(env!("JOOS_INITRD_MAX"));
const CONFIG_MAX: usize = 64 * 1024;

// Each slot lives in its own dedicated ELF section (rather than sharing
// .rodata with everything else) so `objcopy --update-section` can overwrite
// just that section's bytes directly in the already-built binary when only
// the asset changes - no cargo/rustc/mold at all. See build.rs and
// tools/patch_fire2.sh. Slot format: 8-byte LE length prefix + real bytes +
// zero padding out to the MAX capacity above (falls back to a real rebuild
// if an asset ever exceeds its capacity - build.rs panics in that case).
//
// PageAligned forces each slot's section to a 4096-byte alignment. Without
// it, `#[link_section]` only gives the section natural (1-byte, for a plain
// byte array) alignment, and the linker packs it at whatever file offset
// follows the previous section - not page-aligned in general (confirmed via
// readelf: .joos_vmlinux/.joos_initrd landed at offsets like 0x660740).
// zero-copy's runtime mmap() calls (see joos/INIT.md) require a page-aligned
// *file offset*, so an unaligned section fails every such mmap with EINVAL.
#[repr(C, align(4096))]
struct PageAligned<const N: usize>([u8; N]);

// `static mut`, not `static`: Rust derives an ELF section's *flags* (in
// particular, writable or not) from the static's mutability, not from
// `#[link_section]`'s name - a plain immutable `static` here lands in a
// read-only segment regardless of the custom section name (confirmed via
// readelf: `.joos_vmlinux`/`.joos_initrd` were segment-flagged `R` only).
// That's a real correctness problem, not just a naming nuance: the
// zero-copy plan (joos/INIT.md) wants to expose this memory directly as
// guest RAM via `MmapRegion::build_raw()` (wrapping the ELF loader's own
// existing mapping, no extra mmap() call needed), but the guest genuinely
// writes into both regions - vmlinux's own `RW`/`RWE` PT_LOAD segments
// during boot, and initrd's memory once the kernel frees it after
// unpacking and reuses that GPA range as ordinary RAM. A read-only host
// mapping there would fault the guest the first time either happens.
// `static mut` (accessed only via `&raw const`/`&raw mut`, never through an
// actual `&mut` reference, so no aliasing UB - see vmlinux_slot()/
// initrd_slot() below) makes the ELF loader map this MAP_PRIVATE + writable
// (COW) instead, same semantics a fresh mmap would give, just reusing the
// mapping that's already there.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".joos_vmlinux")]
static mut VMLINUX_SLOT: PageAligned<{ 8 + VMLINUX_MAX }> =
    PageAligned(*include_bytes!(env!("JOOS_VMLINUX_SLOT_PATH")));

#[unsafe(no_mangle)]
#[unsafe(link_section = ".joos_initrd")]
static mut INITRD_SLOT: PageAligned<{ 8 + INITRD_MAX }> =
    PageAligned(*include_bytes!(env!("JOOS_INITRD_SLOT_PATH")));

#[unsafe(no_mangle)]
#[unsafe(link_section = ".joos_config")]
static CONFIG_SLOT: [u8; 8 + CONFIG_MAX] = *include_bytes!(env!("JOOS_CONFIG_SLOT_PATH"));

/// Returns the *full padded* byte range a `PageAligned<N>` occupies -
/// `size_of::<PageAligned<N>>()` bytes, which `repr(align(4096))` can (and
/// normally does) make *larger* than `N`, rounding up to the next 4096
/// multiple. Deliberately not just `&self.0` (the inner `[u8; N]` array,
/// `N` bytes): the ELF section this type lives in is sized to match the
/// struct's full padded footprint (that's what the linker actually
/// allocates), not `N` - and `joos-fire-patch` only ever sees that ELF
/// section, with no Rust-level knowledge of `N`, so it necessarily
/// computes the slot's capacity (and therefore where it writes the length
/// trailer - see `write_slot()` in build.rs) from the *section's* size.
/// Reading based on `N` instead of the section's padded size disagrees
/// with that by exactly the padding gap - confirmed via a core dump: a
/// hot-patched binary had byte-correct content, but the runtime trailer
/// read landed 4088 bytes short of where `joos-fire-patch` had actually
/// written it, on now-zeroed padding, reading a length of 0 and failing to
/// parse an "empty" vmlinux. Using the same padded size everywhere (this
/// function) makes a full rebuild and a hot patch agree unconditionally.
///
/// # Safety
/// `ptr` must point at a valid, live `PageAligned<N>`.
unsafe fn slot_full_bytes<const N: usize>(ptr: *const PageAligned<N>) -> &'static [u8] {
    // SAFETY: caller guarantees `ptr` is valid; the returned slice's
    // length exactly matches the type's own size, so it never reads past
    // the object's extent.
    unsafe { std::slice::from_raw_parts(ptr as *const u8, size_of::<PageAligned<N>>()) }
}

/// Safe accessors for the two `static mut` slots above - a single `unsafe`
/// block each, using `&raw const` (never an actual `&`/`&mut` reference to
/// the static itself) so there's no aliasing hazard even though the
/// underlying storage is technically mutable.
fn vmlinux_slot() -> &'static [u8] {
    unsafe { slot_full_bytes(&raw const VMLINUX_SLOT) }
}
fn initrd_slot() -> &'static [u8] {
    unsafe { slot_full_bytes(&raw const INITRD_SLOT) }
}

/// Extracts the real (unpadded) bytes out of a slot: real content, zero
/// padding, then an 8-byte LE length trailer at the very end (see
/// build.rs's `write_slot` for why the length is a trailer, not a prefix).
fn slot_data(slot: &'static [u8]) -> &'static [u8] {
    let n = slot.len();
    let len = u64::from_le_bytes(slot[n - 8..n].try_into().unwrap()) as usize;
    &slot[..len]
}

/// Reads the number of currently-free 2M hugetlbfs pages on this host, or
/// `None` if the sysfs file doesn't exist (no hugetlbfs support/reservation
/// at all) or doesn't parse - both treated as "don't use huge pages" by the
/// caller, not a hard error.
fn free_hugepages_2m() -> Option<usize> {
    std::fs::read_to_string("/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// (file_offset_within_vmlinux, guest_paddr, filesz, memsz) per `PT_LOAD`
/// segment, `e_entry`, and the Xen PVH entry address if a `PT_NOTE` segment
/// contains one (see `find_pvh_entry`). Matches what firecracker's own
/// `load_kernel()` (via `linux_loader::loader::elf::Elf::load()`, that
/// crate's `src/loader/elf/mod.rs`) would otherwise compute *by copying the
/// kernel into guest memory first* - `PT_LOAD` segments (for building
/// matching file-backed guest memory regions instead of copying) and the
/// entry point (for `configure_system_for_boot()`, entirely independent of
/// the copy).
struct VmlinuxLayout {
    segments: Vec<(u64, u64, u64, u64)>,
    e_entry: u64,
    pvh_entry: Option<u64>,
}

const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;

/// Scans a `PT_NOTE` segment's bytes for the Xen PHYS32_ENTRY note, matching
/// `linux-loader`'s `parse_elf_note()` exactly (including its 4-byte-only
/// read of the descriptor, even though this note's descsz is 8) - confirmed
/// present in this project's actual vmlinux via `readelf -n build/vmlinux`
/// (entry 0x1000490, PVH boot), so this isn't a hypothetical branch, it's
/// the one actually taken today.
fn find_pvh_entry(note_bytes: &[u8]) -> Option<u64> {
    fn read_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }
    fn align_up_u64(addr: u64, align: u64) -> u64 {
        (addr + align - 1) & !(align - 1)
    }

    let mut off = 0usize;
    while off + 12 <= note_bytes.len() {
        let namesz = read_u32(note_bytes, off) as u64;
        let descsz = read_u32(note_bytes, off + 4) as u64;
        let n_type = read_u32(note_bytes, off + 8);
        let name_off = off + 12;
        let name_aligned = align_up_u64(namesz, 4) as usize;
        let desc_off = name_off + name_aligned;
        if n_type == XEN_ELFNOTE_PHYS32_ENTRY
            && namesz == 4
            && note_bytes.get(name_off..name_off + 4) == Some(b"Xen\0".as_slice())
        {
            if descsz < 4 || desc_off + 4 > note_bytes.len() {
                return None;
            }
            return Some(read_u32(note_bytes, desc_off) as u64);
        }
        let desc_aligned = align_up_u64(descsz, 4) as usize;
        off = desc_off + desc_aligned;
    }
    None
}

/// Parses `bytes` (the *actually embedded* vmlinux, `slot_data(vmlinux_slot())`
/// - never a build-time snapshot, see the module-level comment on why that
/// was wrong) as an ELF64 file, `None` on any structural problem so the
/// caller falls back to the copy-based path instead of hard-failing boot.
fn parse_vmlinux_layout(bytes: &[u8]) -> Option<VmlinuxLayout> {
    fn read_u16(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
    }
    fn read_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }
    fn read_u64(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    if bytes.len() < ELF64_EHDR_SIZE || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return None;
    }

    let e_entry = read_u64(bytes, 24);
    let e_phoff = read_u64(bytes, 32) as usize;
    let e_phentsize = read_u16(bytes, 54) as usize;
    let e_phnum = read_u16(bytes, 56) as usize;
    if e_phentsize != ELF64_PHDR_SIZE {
        return None;
    }

    let mut segments = Vec::new();
    let mut pvh_entry = None;

    for i in 0..e_phnum {
        let p = e_phoff + i * ELF64_PHDR_SIZE;
        if p + ELF64_PHDR_SIZE > bytes.len() {
            return None;
        }
        let p_type = read_u32(bytes, p);
        let p_offset = read_u64(bytes, p + 8);
        let p_paddr = read_u64(bytes, p + 24);
        let p_filesz = read_u64(bytes, p + 32);
        let p_memsz = read_u64(bytes, p + 40);

        if p_type == PT_LOAD && p_filesz > 0 {
            segments.push((p_offset, p_paddr, p_filesz, p_memsz));
        } else if p_type == PT_NOTE {
            let start = p_offset as usize;
            let end = start + p_filesz as usize;
            if end > bytes.len() {
                return None;
            }
            if let Some(addr) = find_pvh_entry(&bytes[start..end]) {
                pvh_entry = Some(addr);
            }
        }
    }

    if segments.is_empty() {
        return None;
    }
    Some(VmlinuxLayout { segments, e_entry, pvh_entry })
}

/// Builds a `ZeroCopyLayout` from this process's own current section
/// offsets + the actually-embedded vmlinux's freshly-parsed segment table,
/// or `None` (logging
/// why, to stderr, same as `[joos-fire]`-prefixed messages elsewhere in
/// this file) if anything doesn't check out - the caller then leaves
/// `vm_resources.zero_copy` unset, and builder.rs's existing
/// `kernel_bytes`/`initrd_bytes` copy-based path runs exactly as it did
/// before this feature existed. See joos/INIT.md's "Plan: zero-copy
/// vmlinux/initrd loading in VMM construction".
fn try_build_zero_copy_layout(vm_resources: &VmResources) -> Option<ZeroCopyLayout> {
    // Parsed fresh from the actually-embedded bytes every time (not a
    // build-time snapshot - see the module-level comment on VmlinuxLayout
    // for why that was a real bug, caught via a real `make patch-fire2`).
    let vmlinux_bytes = slot_data(vmlinux_slot());
    let layout = parse_vmlinux_layout(vmlinux_bytes).or_else(|| {
        eprintln!("[joos-fire] zero-copy: embedded vmlinux doesn't parse as a valid ELF64 image - falling back");
        None
    })?;

    // host_addr = the real, in-process address of each segment's bytes -
    // no file/offset lookup needed at all, since VMLINUX_SLOT's bytes are
    // already mapped (by the ELF loader, at process start) exactly where
    // vmlinux_bytes.as_ptr() points right now. builder.rs wraps this
    // directly via MmapRegion::build_raw() instead of a separate mmap() of
    // /proc/self/exe - see ZeroCopyLayout's doc comment for why this only
    // works because VMLINUX_SLOT/INITRD_SLOT are `static mut` (writable).
    let vmlinux_base = vmlinux_bytes.as_ptr() as usize;
    let kernel_segments: Vec<(usize, u64, u64, u64)> = layout
        .segments
        .iter()
        .map(|&(off, paddr, filesz, memsz)| (vmlinux_base + off as usize, paddr, filesz, memsz))
        .collect();
    let (kernel_entry_addr, kernel_boot_protocol_is_pvh) = match layout.pvh_entry {
        Some(pvh) => (pvh, true),
        None => (layout.e_entry, false),
    };
    let initrd_bytes = slot_data(initrd_slot());
    let initrd_host_addr = initrd_bytes.as_ptr() as usize;
    let initrd_size = initrd_bytes.len() as u64;

    let mem_size_mib = vm_resources.machine_config.mem_size_mib as u64;
    let lowmem_size = mem_size_mib * 1024 * 1024;
    if initrd_size >= lowmem_size {
        eprintln!("[joos-fire] zero-copy: initrd doesn't fit in configured guest memory - falling back");
        return None;
    }
    let page = GUEST_PAGE_SIZE as u64;
    let initrd_guest_addr = (lowmem_size - initrd_size) & !(page - 1);

    Some(ZeroCopyLayout {
        kernel_segments: Box::leak(kernel_segments.into_boxed_slice()),
        kernel_entry_addr,
        kernel_boot_protocol_is_pvh,
        initrd_host_addr,
        initrd_guest_addr,
        initrd_size,
    })
}

fn main() {
    // Matches the wrapper's unlink() of stale sockets from a previous run -
    // vsock's bind() fails with EADDRINUSE otherwise. No fire.sock/API
    // socket to worry about here since there's no API server in this binary.
    let _ = std::fs::remove_file("./v.sock");

    // Without this, log::warn!/info! (used by e.g. the boot-timer device's
    // Guest-boot-time line) are silent no-ops - firecracker's own main.rs
    // does this via its --level CLI arg, which joos-fire doesn't have.
    LOGGER.init().expect("failed to init logger");
    LOGGER
        .update(LoggerConfig {
            log_path: None,
            level: Some(LevelFilter::Warn),
            show_level: None,
            show_log_origin: None,
            module: None,
        })
        .expect("failed to configure logger level");

    let instance_info = InstanceInfo {
        id: "anonymous-instance".to_string(),
        state: VmState::NotStarted,
        vmm_version: "joos-fire".to_string(),
        app_name: "joos-fire".to_string(),
    };

    let mut event_manager = EventManager::new().expect("failed to create EventManager");

    let config_json =
        std::str::from_utf8(slot_data(&CONFIG_SLOT)).expect("embedded config JSON is not UTF-8");
    let mut vm_resources = VmResources::from_json(config_json, &instance_info, 0, None)
        .expect("failed to parse embedded config JSON");
    // Matches --boot-timer on the stock firecracker launch this replaces.
    vm_resources.boot_timer = true;
    // The whole point: load straight from the embedded bytes above, instead
    // of boot_source.builder's File (which the embedded config's patched
    // boot-source section deliberately points at /dev/null - see build.rs).
    vm_resources.kernel_bytes = Some(slot_data(vmlinux_slot()));
    vm_resources.initrd_bytes = Some(slot_data(initrd_slot()));

    // Zero-copy guest memory construction - see joos/INIT.md's "Plan:
    // zero-copy vmlinux/initrd loading in VMM construction" and its
    // "End-to-end result" subsection. kernel_bytes/initrd_bytes above stay
    // set regardless, as the fallback path builder.rs takes if this isn't
    // set (or the region construction it drives fails for any reason - see
    // try_build_zero_copy_regions in builder.rs).
    //
    // Opt-in (off by default), not opt-out: measured end to end via
    // bench_boot.sh, this currently makes fc_boot ~2x *worse* (~54ms vs
    // ~24ms), not better - the host-side pre-population added to
    // vstate/memory::mixed() runs before the KVM memory slot exists, so it
    // never actually avoids the per-page EPT-violation cost of the guest's
    // first touch (see INIT.md for the full dmesg-based root cause). Set
    // JOOS_ZERO_COPY=1 to enable it anyway for further experimentation. See
    // JOOS_HUGE_ANON below for the follow-up attempt at the same root cause.
    if std::env::var_os("JOOS_ZERO_COPY").is_some() {
        vm_resources.zero_copy = try_build_zero_copy_layout(&vm_resources);
    }

    // Hugetlbfs-backed anonymous guest memory - see joos/INIT.md's "Plan:
    // hugetlbfs-backed anonymous guest memory (candidate #1, take 2)" and
    // its "Result" subsection. Unlike JOOS_ZERO_COPY above, this changes
    // nothing about how vmlinux/initrd get loaded - load_kernel()/
    // InitrdConfig::from_bytes() still do their normal memcpy, just into
    // hugetlbfs-backed (real 2MB pages, pre-committed at mmap time) rather
    // than plain anonymous (4KB, fault-allocated on demand) memory.
    //
    // On (auto-detected) by default, not opt-in: measured as a real, if
    // modest, win with no observed downside - see INIT.md. Set
    // FIRE_DISABLE_HUGE_PAGES=1 to force the plain-anonymous path anyway
    // (e.g. for A/B benchmarking).
    //
    // HugePageConfig::Hugetlbfs2M backs the *entire* guest DRAM region, not
    // just vmlinux/initrd - easy to assume otherwise, and wrong: confirmed
    // directly (start fire2, watch /proc/meminfo's HugePages_Free drop
    // while it runs) that hugetlbfs pages get consumed lazily as guest
    // memory is actually touched, up to the *whole* configured
    // mem_size_mib, not some smaller fixed amount. `mmap(MAP_HUGETLB)`
    // itself can apparently succeed even when the host doesn't have enough
    // *total* reserved pages to cover that full amount (observed: it
    // didn't fail during a brief boot that only touched ~46MB against a
    // 512MB guest with just 128MB reserved) - but a longer-running guest
    // that touches more of its RAM than the host has reserved would run
    // out mid-flight with no graceful fallback to 4K pages, since a
    // MAP_HUGETLB mapping can't partially degrade like that. So the
    // detection below requires enough *free* hugepages to cover the
    // *entire* configured guest memory, not just "any are available" -
    // anything less is unsafe for a guest that's actually used for real
    // work (this project's whole point), not just a quick boot-and-check.
    if std::env::var_os("FIRE_DISABLE_HUGE_PAGES").is_none() {
        let mem_size_mib = vm_resources.machine_config.mem_size_mib;
        if mem_size_mib % 2 != 0 {
            eprintln!(
                "[joos-fire] huge-pages: mem_size_mib ({mem_size_mib}) isn't a multiple of 2 - \
                 using 4K pages"
            );
        } else {
            let required_pages = mem_size_mib / 2;
            match free_hugepages_2m() {
                Some(free) if free >= required_pages => {
                    vm_resources.machine_config.huge_pages = HugePageConfig::Hugetlbfs2M;
                }
                Some(free) => eprintln!(
                    "[joos-fire] huge-pages: {free} free 2M hugepages, need {required_pages} to \
                     cover the full {mem_size_mib}MiB guest - using 4K pages"
                ),
                None => {} // no hugetlbfs support/reservation on this host - silently use 4K pages
            }
        }
    }

    // Matches --no-seccomp on the stock firecracker launch this replaces.
    let seccomp_filters = get_empty_filters();

    let vmm = build_and_boot_microvm(
        &instance_info,
        &vm_resources,
        &mut event_manager,
        &seccomp_filters,
    )
    .expect("failed to build/boot microVM");

    // Same event loop firecracker's own main.rs runs post-construction -
    // this is what actually keeps devices/vsock functioning, not just the
    // build_and_boot_microvm call above.
    loop {
        event_manager.run().expect("event manager run failed");
        match vmm.lock().unwrap().shutdown_exit_code() {
            Some(FcExitCode::Ok) => break,
            Some(exit_code) => {
                eprintln!("[joos-fire] shutdown with exit code {exit_code:?}");
                std::process::exit(exit_code as i32);
            }
            None => continue,
        }
    }
}
