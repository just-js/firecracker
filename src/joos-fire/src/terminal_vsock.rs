// Minimal proof-of-concept vsock backend, replacing `VsockUnixBackend`'s AF_UNIX
// translation with a direct host-side fd - a plain stdin fd for this first
// connectivity test (the real terminal-relay design is a later step, see
// joos/doc/TERMINAL.md). Lives entirely in joos-fire, not in the vmm crate:
// `vmm` only had to make two already-fully-implemented, already-correct pieces
// public to allow this (`csm::VsockConnection`/`VsockConnectionBackend`, and
// `VsockPacketRx`/`VsockPacketTx`) - no new vsock-protocol logic added to the
// fork itself, just visibility.
//
// `VsockConnection<S>` implements the full vsock protocol - connection
// handshake, credit-based flow control, shutdown - generically over any
// `S: VsockConnectionBackend + Debug` (= `ReadVolatile + Write + WriteVolatile
// + AsRawFd`, per its own doc comment). `std::fs::File` already gets
// `ReadVolatile`/`WriteVolatile` from vm-memory's own blanket impl, so
// wrapping a raw fd in a `File` (via `from_raw_fd`) is enough to use it
// directly as that `S` - no custom stream type needed, no UDS, no text
// handshake protocol, no separate host-side wrapper process.

use std::fmt::Debug;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use vm_memory::bitmap::BitmapSlice;
use vm_memory::io::{ReadVolatile, WriteVolatile};
use vm_memory::VolatileSlice;
use vm_memory::VolatileMemoryError;
use vmm::devices::virtio::vsock::csm::{VsockConnection, VsockConnectionBackend};
use vmm::devices::virtio::vsock::{VsockBackend, VsockChannel, VsockEpollListener, VsockError, VsockPacketRx, VsockPacketTx};
use vmm_sys_util::epoll::EventSet;

/// Orphan-rule workaround: `VsockConnectionBackend` (defined in `vmm`) and
/// `File` (defined in `std`) are both foreign to this crate, so `impl
/// VsockConnectionBackend for File` isn't allowed here (it was fine when this
/// backend lived inside the vmm crate itself, where the trait was local) - a
/// local newtype makes the impl legal again. Pure delegation to `File`'s own
/// (already correct, vm-memory-provided) `ReadVolatile`/`WriteVolatile` impl.
struct TerminalStream(File);

impl ReadVolatile for TerminalStream {
    fn read_volatile<B: BitmapSlice>(&mut self, buf: &mut VolatileSlice<B>) -> Result<usize, VolatileMemoryError> {
        self.0.read_volatile(buf)
    }
}

impl WriteVolatile for TerminalStream {
    fn write_volatile<B: BitmapSlice>(&mut self, buf: &VolatileSlice<B>) -> Result<usize, VolatileMemoryError> {
        self.0.write_volatile(buf)
    }
}

impl Write for TerminalStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl AsRawFd for TerminalStream {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl VsockConnectionBackend for TerminalStream {}

impl Debug for TerminalStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalStream").field("fd", &self.0.as_raw_fd()).finish()
    }
}

/// `VSOCK_OP_REQUEST` (see `virtio_vsock.h`/`vsock/mod.rs`'s private `defs::uapi`
/// - hardcoded here rather than threading another export through `vmm`, since
/// this is a stable, well-known wire-protocol constant, same spirit as
/// hardcoding `AF_VSOCK`/`VMADDR_CID_HOST` in the plain-C test programs
/// elsewhere in this investigation.
const VSOCK_OP_REQUEST: u16 = 1;

/// A `VsockBackend` managing exactly one guest-initiated connection to a
/// fixed local (host) port. Guest-initiated deliberately, not just as a
/// diagnostic variant - see doc/TERMINAL.md's "Implementation attempt #1" and
/// "Reconsidering connection direction": a *host*-initiated connection races
/// the guest's own boot (the host has no way to know when the guest's
/// `listen()` has actually happened), which this design sidesteps entirely -
/// the host is always ready to accept (this backend exists and is registered
/// from VM construction time onward), and the guest only connects once its
/// own userspace has decided it's ready, so there's no window where either
/// side could be the one not yet listening.
pub struct TerminalVsockBackend {
    /// A `dup`'d fd, distinct from `source_fd`, kept alive purely so
    /// `as_raw_fd()` always has something valid *and uniquely owned* to
    /// return before a connection exists - returning `source_fd` directly
    /// collided with the legacy serial console device's own registration of
    /// that same fd (`Failed to register vsock backend event: file
    /// descriptor has already been registered` - harmless when it happened,
    /// real bug, real fix).
    idle_fd: File,
    source_fd: RawFd,
    local_cid: u64,
    listen_port: u32,
    conn: Option<VsockConnection<TerminalStream>>,
}

impl TerminalVsockBackend {
    /// `fd` is not consumed here - a fresh dup happens once a guest actually
    /// connects, on `listen_port`.
    pub fn new_listening(fd: RawFd, local_cid: u64, listen_port: u32) -> Self {
        Self { idle_fd: dup_as_file(fd), source_fd: fd, local_cid, listen_port, conn: None }
    }

    fn dup_stream(&self) -> TerminalStream {
        TerminalStream(dup_as_file(self.source_fd))
    }
}

fn dup_as_file(fd: RawFd) -> File {
    // SAFETY: `fd` is a valid, open fd for the lifetime of this call (the
    // caller's responsibility), and libc::dup's return value is checked.
    let dup_fd = unsafe { libc::dup(fd) };
    assert!(dup_fd >= 0, "dup() failed for vsock terminal backend fd");
    // SAFETY: `dup_fd` was just returned by a successful `dup()` above, so
    // it's a valid, freshly-owned fd nothing else holds.
    unsafe { File::from_raw_fd(dup_fd) }
}

impl VsockChannel for TerminalVsockBackend {
    fn recv_pkt(&mut self, pkt: &mut VsockPacketRx) -> Result<(), VsockError> {
        match &mut self.conn {
            Some(conn) => conn.recv_pkt(pkt),
            None => Err(VsockError::NoData),
        }
    }

    fn send_pkt(&mut self, pkt: &VsockPacketTx) {
        if self.conn.is_none()
            && pkt.hdr.op() == VSOCK_OP_REQUEST
            && pkt.hdr.dst_port() == self.listen_port
        {
            let stream = self.dup_stream();
            self.conn = Some(VsockConnection::new_peer_init(
                stream,
                self.local_cid,
                pkt.hdr.src_cid(),
                pkt.hdr.dst_port(),
                pkt.hdr.src_port(),
                pkt.hdr.buf_alloc(),
            ));
        }
        if let Some(conn) = &mut self.conn {
            conn.send_pkt(pkt);
        }
    }

    fn has_pending_rx(&self) -> bool {
        self.conn.as_ref().is_some_and(|conn| conn.has_pending_rx())
    }
}

impl AsRawFd for TerminalVsockBackend {
    fn as_raw_fd(&self) -> RawFd {
        match &self.conn {
            Some(conn) => conn.as_raw_fd(),
            None => self.idle_fd.as_raw_fd(),
        }
    }
}

impl VsockEpollListener for TerminalVsockBackend {
    fn get_polled_evset(&self) -> EventSet {
        // No connection yet: nothing to watch for - we're waiting on a TXQ
        // event (the guest's REQUEST packet), not our own fd's readiness.
        // NOTE: this is read once, at device activation - see doc/TERMINAL.md,
        // this backend doesn't yet handle needing a *different* evset once a
        // connection exists (not reached by this diagnostic test either way).
        match &self.conn {
            Some(conn) => conn.get_polled_evset(),
            None => EventSet::empty(),
        }
    }

    fn notify(&mut self, evset: EventSet) {
        if let Some(conn) = &mut self.conn {
            conn.notify(evset);
        }
    }
}

impl VsockBackend for TerminalVsockBackend {}

impl Debug for TerminalVsockBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalVsockBackend").finish()
    }
}
