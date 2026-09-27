// A custom firecracker launcher that boots the vmlinux/initrd.cpio/config
// appended to its own binary (see payload()) and calls vmm's VMM-construction
// API in-process, instead of this project's usual wrapper (memfd_create + write
// + fexecve into a stock firecracker binary). Eliminates that wrapper's
// ~10-11ms of memfd writes entirely - see FIRECRACKER.md and BOOT_PROFILE.md in
// the parent joos project for the full reasoning and measurements.
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

// The kernel, initrd and config aren't built into this binary: joos's
// tools/assemble.js appends them to a copy of it, as one extra read-only
// PT_LOAD segment made from the spare program header build.rs reserves.
// The kernel maps it at exec like any other segment, so nothing here opens
// a file. Payload layout, all integers little-endian:
//
//   "JOOSPAY1", u32 count, u32 0
//   count x (u32 kind, u32 0, u64 offset from payload start, u64 len)
//   blobs
const PAYLOAD_MAGIC: &[u8; 8] = b"JOOSPAY1";
const KIND_VMLINUX: u32 = 1;
const KIND_INITRD: u32 = 2;
const KIND_CONFIG: u32 = 3;

unsafe extern "C" {
    // Linker-defined: the ELF header, i.e. this binary's load address.
    static __ehdr_start: u8;
}

/// Returns the payload segment: the PT_LOAD whose first bytes are
/// PAYLOAD_MAGIC. Panics if there is none (a bare, unassembled joos-fire).
fn payload() -> &'static [u8] {
    // SAFETY: getauxval has no preconditions; AT_PHDR/AT_PHNUM describe this
    // executable's program headers, which the kernel always maps.
    let (phdr, phnum) = unsafe {
        (
            libc::getauxval(libc::AT_PHDR) as *const libc::Elf64_Phdr,
            libc::getauxval(libc::AT_PHNUM) as usize,
        )
    };
    // SAFETY: see above.
    let phdrs = unsafe { std::slice::from_raw_parts(phdr, phnum) };
    let base = (&raw const __ehdr_start) as usize;
    for ph in phdrs {
        if ph.p_type != libc::PT_LOAD || ph.p_memsz < 16 {
            continue;
        }
        // SAFETY: a PT_LOAD's [p_vaddr, p_vaddr + p_memsz) is mapped for the
        // life of the process, and nothing in this program writes to it.
        let segment = unsafe {
            std::slice::from_raw_parts(
                (base + ph.p_vaddr as usize) as *const u8,
                ph.p_memsz as usize,
            )
        };
        if segment.starts_with(PAYLOAD_MAGIC) {
            return segment;
        }
    }
    panic!("no payload segment - assemble this binary with joos's tools/assemble.js");
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], off: usize) -> usize {
    usize::try_from(u64::from_le_bytes(b[off..off + 8].try_into().unwrap())).unwrap()
}

/// Returns the blob of `kind` from `payload`. Panics if it's missing.
fn blob(payload: &'static [u8], kind: u32) -> &'static [u8] {
    let count = u32_at(payload, 8) as usize;
    for i in 0..count {
        let entry = 16 + i * 24;
        if u32_at(payload, entry) == kind {
            let (offset, len) = (u64_at(payload, entry + 8), u64_at(payload, entry + 16));
            return &payload[offset..offset + len];
        }
    }
    panic!("payload has no blob of kind {kind}");
}

/// Drops `payload`'s resident pages via MADV_DONTNEED. It's read-only,
/// file-backed, never-written pages of this binary, so this can't lose data -
/// any later access (the slices stay valid) just faults them back in from the
/// file. The segment is page-aligned, so its first page is always released.
/// Best effort: failure only costs RSS.
fn release_pages(payload: &'static [u8]) {
    // SAFETY: sysconf has no preconditions.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
    let start = (payload.as_ptr() as usize).next_multiple_of(page);
    let end = (payload.as_ptr() as usize + payload.len()) / page * page;
    if end > start {
        // SAFETY: [start, end) lies within `payload`, a mapped read-only
        // segment that's never written, so MADV_DONTNEED only drops clean
        // file-backed pages and the kernel refaults identical contents on any
        // later read.
        unsafe { libc::madvise(start as *mut libc::c_void, end - start, libc::MADV_DONTNEED) };
    }
}

/// The host terminal's size as (cols, rows), from stdin, or `None` if stdin
/// isn't a terminal or reports no size.
fn terminal_size() -> Option<(u16, u16)> {
    // SAFETY: TIOCGWINSZ on stdin fills in a winsize we own; the return
    // value is checked.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if rc != 0 || ws.ws_col == 0 || ws.ws_row == 0 {
        return None;
    }
    Some((ws.ws_col, ws.ws_row))
}

/// Writes all of `buf` to `fd`, waiting (poll) while it would block: stdout
/// can be non-blocking, since start_vcpus() sets O_NONBLOCK on stdin and a
/// terminal's stdin/stdout often share one open file description.
fn write_all_fd(fd: libc::c_int, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        // SAFETY: writes from a live slice of the given length.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n > 0 {
            buf = &buf[n as usize..];
            continue;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EAGAIN) => {
                let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                // SAFETY: one valid pollfd.
                unsafe { libc::poll(&mut pfd, 1, -1) };
            }
            Some(libc::EINTR) => {}
            _ => return false,
        }
    }
    true
}

/// joos vsock terminal: relays the host terminal (stdin/stdout) and the data
/// stream (the guest app's pty, through the vsock backend) until the guest
/// closes it. On stdin EOF (e.g. piped input) it only stops reading stdin.
fn relay_terminal(data: std::os::unix::net::UnixStream) {
    use std::os::unix::io::AsRawFd;
    let dfd = data.as_raw_fd();
    let mut buf = vec![0u8; 64 * 1024];
    let mut stdin_open = true;
    loop {
        let mut fds = [
            libc::pollfd { fd: dfd, events: libc::POLLIN, revents: 0 },
            libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: if stdin_open { libc::POLLIN } else { 0 },
                revents: 0,
            },
        ];
        // SAFETY: two valid pollfds.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            continue; // EINTR
        }
        if fds[0].revents != 0 {
            // SAFETY: reads into our own buffer.
            let n = unsafe { libc::read(dfd, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                if !write_all_fd(libc::STDOUT_FILENO, &buf[..n as usize]) {
                    return;
                }
            } else if n == 0 || !is_retry_errno() {
                return; // the guest closed the terminal
            }
        }
        if stdin_open && fds[1].revents != 0 {
            // SAFETY: reads into our own buffer.
            let n = unsafe { libc::read(libc::STDIN_FILENO, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                if !write_all_fd(dfd, &buf[..n as usize]) {
                    return;
                }
            } else if n == 0 || !is_retry_errno() {
                stdin_open = false;
            }
        }
    }
}

fn is_retry_errno() -> bool {
    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EAGAIN) | Some(libc::EINTR)
    )
}

/// joos vsock terminal: sends the host terminal's size as `{u16 cols, u16
/// rows}` (little-endian) now and on every SIGWINCH (blocked in all threads,
/// received here through a signalfd).
fn relay_resize(resize: std::os::unix::net::UnixStream) {
    use std::os::unix::io::AsRawFd;
    let send = |fd| match terminal_size() {
        Some((cols, rows)) => {
            let mut rec = [0u8; 4];
            rec[..2].copy_from_slice(&cols.to_le_bytes());
            rec[2..].copy_from_slice(&rows.to_le_bytes());
            write_all_fd(fd, &rec)
        }
        None => true,
    };
    let fd = resize.as_raw_fd();
    if !send(fd) {
        return;
    }
    // SAFETY: a sigset we own, initialised by sigemptyset; signalfd's result
    // is checked.
    let sfd = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGWINCH);
        libc::signalfd(-1, &set, libc::SFD_CLOEXEC)
    };
    if sfd < 0 {
        return;
    }
    let mut info = [0u8; std::mem::size_of::<libc::signalfd_siginfo>()];
    loop {
        // SAFETY: reads one signalfd_siginfo into our own buffer.
        let n = unsafe { libc::read(sfd, info.as_mut_ptr().cast(), info.len()) };
        if n < 0 && !is_retry_errno() {
            return;
        }
        if n > 0 && !send(fd) {
            return;
        }
    }
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
    // A panic after start_vcpus() put the host terminal into raw mode
    // ("terminal": true) would otherwise leave it there: restore it first,
    // then report the panic as usual.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        vmm::restore_terminal();
        default_hook(info);
    }));

    // Matches the wrapper's unlink() of stale sockets from a previous run -
    // vsock's bind() fails with EADDRINUSE otherwise. No fire.sock/API
    // socket to worry about here since there's no API server in this binary.
    let _ = std::fs::remove_file("./v.sock");

    // Without this, log::warn!/info! (used by e.g. the boot-timer device's
    // Guest-boot-time line) are silent no-ops - firecracker's own main.rs
    // does this via its --level CLI arg, which joos-fire doesn't have.
    LOGGER.init().unwrap_or_else(|e| panic!("failed to init logger: {e}"));
    LOGGER
        .update(LoggerConfig {
            log_path: None,
            level: Some(LevelFilter::Error),
            show_level: None,
            show_log_origin: None,
            module: None,
        })
        .unwrap_or_else(|e| panic!("failed to configure logger level: {e}"));

    let instance_info = InstanceInfo {
        id: "anonymous-instance".to_string(),
        state: VmState::NotStarted,
        vmm_version: "joos-fire".to_string(),
        app_name: "joos-fire".to_string(),
    };

    let mut event_manager =
        EventManager::new().unwrap_or_else(|e| panic!("failed to create EventManager: {e}"));

    let payload = payload();
    let config_json = std::str::from_utf8(blob(payload, KIND_CONFIG))
        .unwrap_or_else(|e| panic!("embedded config JSON is not UTF-8: {e}"));
    let mut vm_resources = VmResources::from_json(config_json, &instance_info, 0, None)
        .unwrap_or_else(|e| panic!("failed to parse embedded config JSON: {e}"));
    // Matches --boot-timer on the stock firecracker launch this replaces.
    vm_resources.boot_timer = true;
    // The whole point: load straight from the embedded bytes above, instead
    // of boot_source.builder's File (which the embedded config's patched
    // boot-source section deliberately points at /dev/null - see
    // tools/assemble.js's pack_config()).
    vm_resources.kernel_bytes = Some(blob(payload, KIND_VMLINUX));
    vm_resources.initrd_bytes = Some(blob(payload, KIND_INITRD));

    // "terminal": true - pass the host terminal's size to the guest as
    // joos_winsize=<cols>x<rows>: the kernel hands unknown, dot-free
    // parameters to init as environment variables, and init.c sets it on
    // the console (see joos doc/TERMINAL.md, step 1).
    if vm_resources.terminal {
        if let Some((cols, rows)) = terminal_size() {
            if let Some(boot_config) = vm_resources.boot_source.builder.as_mut() {
                boot_config
                    .cmdline
                    .insert_str(format!("joos_winsize={cols}x{rows}"))
                    .unwrap_or_else(|e| panic!("kernel command line: {e}"));
            }
        }
    }

    // "terminal": true plus a vsock device: the vsock terminal (joos doc/TERMINAL.md,
    // step 2). init.c sees joos_vterm=1, runs the app on a pty and connects its data and
    // resize channels to us; the serial console only carries kernel messages. SIGWINCH is
    // blocked here, before any vCPU thread exists, so every thread inherits the mask and
    // only relay_resize()'s signalfd receives it.
    let terminal_streams = vm_resources.terminal_streams.take();
    if terminal_streams.is_some() {
        if let Some(boot_config) = vm_resources.boot_source.builder.as_mut() {
            boot_config
                .cmdline
                .insert_str("joos_vterm=1")
                .unwrap_or_else(|e| panic!("kernel command line: {e}"));
        }
        // SAFETY: a sigset we own, initialised by sigemptyset before use.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGWINCH);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        }
    }

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
    .unwrap_or_else(|e| panic!("failed to build/boot microVM: {e}"));

    // vmlinux/initrd are in guest memory now and nothing reads the payload
    // again - drop its pages from our RSS (~5MB packed+lz4, ~13MB packed).
    // After boot, so it's off the guest's critical path.
    release_pages(payload);

    // After boot, so the host terminal is already in raw mode (start_vcpus).
    if let Some(streams) = terminal_streams {
        let vmm::TerminalStreams { data, resize } = streams;
        std::thread::spawn(move || relay_terminal(data));
        std::thread::spawn(move || relay_resize(resize));
    }

    // Same event loop firecracker's own main.rs runs post-construction -
    // this is what actually keeps devices/vsock functioning, not just the
    // build_and_boot_microvm call above.
    loop {
        event_manager.run().unwrap_or_else(|e| panic!("event manager run failed: {e}"));
        match vmm.lock().unwrap().shutdown_exit_code() {
            // Restore the terminal here: exit() skips Vmm's Drop, and on the
            // Ok path other references can keep the Vmm alive past main.
            Some(FcExitCode::Ok) => {
                vmm::restore_terminal();
                break;
            }
            Some(exit_code) => {
                vmm::restore_terminal();
                eprintln!("[joos-fire] shutdown with exit code {exit_code:?}");
                std::process::exit(exit_code as i32);
            }
            None => continue,
        }
    }
}
