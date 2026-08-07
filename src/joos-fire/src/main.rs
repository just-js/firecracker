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

use vmm::builder::build_and_boot_microvm;
use vmm::logger::{LOGGER, LevelFilter, LoggerConfig};
use vmm::resources::VmResources;
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
#[unsafe(no_mangle)]
#[unsafe(link_section = ".joos_vmlinux")]
static VMLINUX_SLOT: [u8; 8 + VMLINUX_MAX] = *include_bytes!(env!("JOOS_VMLINUX_SLOT_PATH"));

#[unsafe(no_mangle)]
#[unsafe(link_section = ".joos_initrd")]
static INITRD_SLOT: [u8; 8 + INITRD_MAX] = *include_bytes!(env!("JOOS_INITRD_SLOT_PATH"));

#[unsafe(no_mangle)]
#[unsafe(link_section = ".joos_config")]
static CONFIG_SLOT: [u8; 8 + CONFIG_MAX] = *include_bytes!(env!("JOOS_CONFIG_SLOT_PATH"));

/// Extracts the real (unpadded) bytes out of a slot: an 8-byte LE length
/// prefix followed by that many real bytes, then zero padding.
fn slot_data(slot: &'static [u8]) -> &'static [u8] {
    let len = u64::from_le_bytes(slot[0..8].try_into().unwrap()) as usize;
    &slot[8..8 + len]
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
    vm_resources.kernel_bytes = Some(slot_data(&VMLINUX_SLOT));
    vm_resources.initrd_bytes = Some(slot_data(&INITRD_SLOT));

    // Hugetlbfs-backed anonymous guest memory - see joos/INIT.md's "Plan:
    // hugetlbfs-backed anonymous guest memory (candidate #1, take 2)" and
    // its "Result" subsection. load_kernel()/InitrdConfig::from_bytes()
    // still do their normal memcpy, just into hugetlbfs-backed (real 2MB
    // pages, pre-committed at mmap time) rather than plain anonymous (4KB,
    // fault-allocated on demand) memory.
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
