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

#[unsafe(no_mangle)]
#[unsafe(link_section = ".joos_vmlinux")]
static VMLINUX_SLOT: PageAligned<{ 8 + VMLINUX_MAX }> =
    PageAligned(*include_bytes!(env!("JOOS_VMLINUX_SLOT_PATH")));

#[unsafe(no_mangle)]
#[unsafe(link_section = ".joos_initrd")]
static INITRD_SLOT: PageAligned<{ 8 + INITRD_MAX }> =
    PageAligned(*include_bytes!(env!("JOOS_INITRD_SLOT_PATH")));

#[unsafe(no_mangle)]
#[unsafe(link_section = ".joos_config")]
static CONFIG_SLOT: [u8; 8 + CONFIG_MAX] = *include_bytes!(env!("JOOS_CONFIG_SLOT_PATH"));

/// Extracts the real (unpadded) bytes out of a slot: real content, zero
/// padding, then an 8-byte LE length trailer at the very end (see
/// build.rs's `write_slot` for why the length is a trailer, not a prefix).
fn slot_data(slot: &'static [u8]) -> &'static [u8] {
    let n = slot.len();
    let len = u64::from_le_bytes(slot[n - 8..n].try_into().unwrap()) as usize;
    &slot[..len]
}

/// Minimal ELF64 section-header lookup against this process's own running
/// executable, to find `.joos_vmlinux`/`.joos_initrd`'s *current* file
/// offset - see `joos/INIT.md`'s "zero-copy" plan. Can't be a build-time
/// constant: `joos-fire-patch` can overwrite a section's *content*
/// post-link without moving its *offset*, but the offset itself is only
/// fixed once linking has happened, so build.rs (which runs before
/// linking) can never know it. Hand-rolled (no `object` crate) to avoid
/// adding a dependency to joos-fire's own release build, which already has
/// a real link-time cost to watch (see build.rs's profile comment in
/// joos-fire-patch's Cargo.toml for the related reasoning). Reads only the
/// ELF header + section header table + string table once - not the whole
/// multi-MB file, and not re-opened/re-read per name (an earlier version
/// called a single-section lookup twice; every microsecond here is boot
/// time, so this looks up both names in one pass over one open file
/// instead). Returns `(sh_offset, sh_size)` per name in `names`, in the
/// same order, or `None` on any I/O error or if any name isn't found -
/// callers treat that as "disable zero-copy, fall back to the copy-based
/// path" (see `try_build_zero_copy_layout` below).
fn section_file_offsets<const N: usize>(path: &str, names: [&str; N]) -> Option<[(u64, u64); N]> {
    use std::io::{Read, Seek, SeekFrom};

    fn u16le(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
    }
    fn u32le(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }
    fn u64le(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    let mut f = std::fs::File::open(path).ok()?;

    let mut ehdr = [0u8; 64];
    f.read_exact(&mut ehdr).ok()?;
    if &ehdr[0..4] != b"\x7fELF" {
        return None;
    }

    let e_shoff = u64le(&ehdr, 40);
    let e_shentsize = u16le(&ehdr, 58) as usize;
    let e_shnum = u16le(&ehdr, 60) as usize;
    let e_shstrndx = u16le(&ehdr, 62) as usize;
    if e_shentsize != 64 {
        return None;
    }

    f.seek(SeekFrom::Start(e_shoff)).ok()?;
    let mut shdrs = vec![0u8; e_shnum * e_shentsize];
    f.read_exact(&mut shdrs).ok()?;

    let shstr = &shdrs[e_shstrndx * e_shentsize..][..e_shentsize];
    let shstrtab_off = u64le(shstr, 24);
    let shstrtab_size = u64le(shstr, 32) as usize;
    f.seek(SeekFrom::Start(shstrtab_off)).ok()?;
    let mut shstrtab = vec![0u8; shstrtab_size];
    f.read_exact(&mut shstrtab).ok()?;

    let mut results = [None; N];
    for i in 0..e_shnum {
        let sh = &shdrs[i * e_shentsize..][..e_shentsize];
        let name_off = u32le(sh, 0) as usize;
        let end = shstrtab[name_off..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_off + p)
            .unwrap_or(shstrtab.len());
        let Some(section_name) = shstrtab.get(name_off..end) else {
            continue;
        };
        for (slot, name) in results.iter_mut().zip(names) {
            if section_name == name.as_bytes() {
                *slot = Some((u64le(sh, 24), u64le(sh, 32)));
            }
        }
    }

    let mut out = [(0u64, 0u64); N];
    for (o, r) in out.iter_mut().zip(results) {
        *o = r?;
    }
    Some(out)
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

/// Parses `bytes` (the *actually embedded* vmlinux, `slot_data(&VMLINUX_SLOT.0)`
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
    const SELF_EXE: &str = "/proc/self/exe";

    let [(vmlinux_section_off, vmlinux_section_size), (initrd_section_off, initrd_section_size)] =
        section_file_offsets(SELF_EXE, [".joos_vmlinux", ".joos_initrd"]).or_else(|| {
            eprintln!(
                "[joos-fire] zero-copy: .joos_vmlinux/.joos_initrd section lookup in {SELF_EXE} \
                 failed - falling back"
            );
            None
        })?;

    // >= rather than == : PageAligned<N>'s repr(align(4096)) rounds the
    // struct's *total* size up to a 4096 multiple, so the section can be
    // (and normally is) a little larger than the inner array's exact
    // length - that's just alignment padding at the end, harmless, and
    // never read (slot_data() only reads the first 8+len bytes anyway).
    if vmlinux_section_size < VMLINUX_SLOT.0.len() as u64
        || initrd_section_size < INITRD_SLOT.0.len() as u64
    {
        eprintln!(
            "[joos-fire] zero-copy: section size in {SELF_EXE} is smaller than this process's \
             own slot sizes - falling back"
        );
        return None;
    }

    // Parsed fresh from the actually-embedded bytes every time (not a
    // build-time snapshot - see the module-level comment on VmlinuxLayout
    // for why that was a real bug, caught via a real `make patch-fire2`).
    let vmlinux_bytes = slot_data(&VMLINUX_SLOT.0);
    let layout = parse_vmlinux_layout(vmlinux_bytes).or_else(|| {
        eprintln!("[joos-fire] zero-copy: embedded vmlinux doesn't parse as a valid ELF64 image - falling back");
        None
    })?;

    // No offset adjustment needed here: content starts at offset 0 of each
    // slot (the length trailer lives at the *end* - see write_slot() in
    // build.rs), and the section itself is page-aligned via PageAligned, so
    // vmlinux_section_off/initrd_section_off are already the exact absolute
    // file offsets content starts at.
    let kernel_segments: Vec<(u64, u64, u64, u64)> = layout
        .segments
        .iter()
        .map(|&(off, paddr, filesz, memsz)| (vmlinux_section_off + off, paddr, filesz, memsz))
        .collect();
    let (kernel_entry_addr, kernel_boot_protocol_is_pvh) = match layout.pvh_entry {
        Some(pvh) => (pvh, true),
        None => (layout.e_entry, false),
    };
    let initrd_file_offset = initrd_section_off;
    let initrd_size = slot_data(&INITRD_SLOT.0).len() as u64;

    let mem_size_mib = vm_resources.machine_config.mem_size_mib as u64;
    let lowmem_size = mem_size_mib * 1024 * 1024;
    if initrd_size >= lowmem_size {
        eprintln!("[joos-fire] zero-copy: initrd doesn't fit in configured guest memory - falling back");
        return None;
    }
    let page = GUEST_PAGE_SIZE as u64;
    let initrd_guest_addr = (lowmem_size - initrd_size) & !(page - 1);

    Some(ZeroCopyLayout {
        backing_path: SELF_EXE,
        kernel_segments: Box::leak(kernel_segments.into_boxed_slice()),
        kernel_entry_addr,
        kernel_boot_protocol_is_pvh,
        initrd_file_offset,
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
    vm_resources.kernel_bytes = Some(slot_data(&VMLINUX_SLOT.0));
    vm_resources.initrd_bytes = Some(slot_data(&INITRD_SLOT.0));

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
    // JOOS_ZERO_COPY=1 to enable it anyway for further experimentation
    // (e.g. a huge-page-backed version, tracked as an open discussion in
    // INIT.md, not yet implemented).
    if std::env::var_os("JOOS_ZERO_COPY").is_some() {
        vm_resources.zero_copy = try_build_zero_copy_layout(&vm_resources);
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
