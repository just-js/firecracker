// joos: host-side setup for the guest's tap, done before the guest runs ("tap" in
// the Firecracker config, from `tap` in a joos image config - see joos
// doc/LO-TAP.md, "Tap setup in joos-fire").
//
// - ephemeral: firecracker's own Tap::open_named (TUNSETIFF) creates a missing
//   tap when this process has CAP_NET_ADMIN - non-persistent, tied to that fd,
//   so it goes away when the VMM exits, however it exits. That happens while
//   VmResources::from_json() builds the net device, so main() decides what to
//   do before that, and addresses the tap and brings it up after the VM is
//   built, before the vCPUs run.
// - persistent: create_persistent_tap() makes the tap before the VM is built.
// - Either way, only when we made the tap: ensure_routing() - NAT for guests
//   through one nftables table, `ip joos`, created if it's missing, and
//   ip_forward.
//
// Then drop_net_admin() removes CAP_NET_ADMIN, whatever the mode, so a guest
// that escapes into the VMM doesn't get it.

use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// struct ifreq: the name, then a 24-byte union (sockaddr or short flags).
const IFREQ_LEN: usize = 40;
const IFNAMSIZ: usize = 16;

fn check(rc: libc::c_long) -> Result<libc::c_long, Error> {
    if rc < 0 { Err(Error::last_os_error()) } else { Ok(rc) }
}

fn ifreq(name: &str) -> Result<[u8; IFREQ_LEN], Error> {
    if name.is_empty() || name.len() >= IFNAMSIZ {
        return Err(Error::new(ErrorKind::InvalidInput, format!("bad interface name {name:?}")));
    }
    let mut req = [0u8; IFREQ_LEN];
    req[..name.len()].copy_from_slice(name.as_bytes());
    Ok(req)
}

fn set_ifreq_addr(req: &mut [u8; IFREQ_LEN], ip: Ipv4Addr) {
    // struct sockaddr_in: family, port, address
    req[IFNAMSIZ..].fill(0);
    req[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    req[IFNAMSIZ + 4..IFNAMSIZ + 8].copy_from_slice(&ip.octets());
}

fn socket(domain: libc::c_int, ty: libc::c_int, proto: libc::c_int) -> Result<OwnedFd, Error> {
    // SAFETY: socket has no preconditions; the result is checked.
    let fd = check(unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC, proto) }.into())?;
    // SAFETY: a new fd we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
}

/// true if a network interface called `name` exists.
pub fn tap_exists(name: &str) -> bool {
    let Ok(name) = std::ffi::CString::new(name) else { return false };
    // SAFETY: a NUL-terminated string.
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}

/// Creates the persistent tap `name`, owned by our uid, with the flags
/// Tap::open_named attaches with.
pub fn create_persistent_tap(name: &str) -> Result<(), Error> {
    // SAFETY: a constant NUL-terminated path; the result is checked.
    let fd = check(unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) }.into())?;
    // SAFETY: a new fd we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
    let mut req = ifreq(name)?;
    let flags = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as i16;
    req[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());
    // SAFETY: TUNSETIFF reads and writes a struct ifreq, which req is; the
    // others take an integer argument.
    unsafe {
        check(libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF as _, req.as_mut_ptr()).into())?;
        check(libc::ioctl(fd.as_raw_fd(), libc::TUNSETOWNER as _, libc::getuid() as libc::c_ulong).into())?;
        check(libc::ioctl(fd.as_raw_fd(), libc::TUNSETPERSIST as _, 1 as libc::c_ulong).into())?;
    }
    Ok(())
}

/// Gives interface `name` the address `ip/prefix_len` and brings it up.
pub fn configure_tap(name: &str, ip: Ipv4Addr, prefix_len: u8) -> Result<(), Error> {
    let s = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    let mut req = ifreq(name)?;
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix_len.min(32))).unwrap_or(0);
    // SAFETY: each ioctl reads (and SIOCGIFFLAGS writes) a struct ifreq, which req is.
    unsafe {
        set_ifreq_addr(&mut req, ip);
        check(libc::ioctl(s.as_raw_fd(), libc::SIOCSIFADDR as _, req.as_mut_ptr()).into())?;
        set_ifreq_addr(&mut req, Ipv4Addr::from(mask));
        check(libc::ioctl(s.as_raw_fd(), libc::SIOCSIFNETMASK as _, req.as_mut_ptr()).into())?;
        req[IFNAMSIZ..].fill(0);
        check(libc::ioctl(s.as_raw_fd(), libc::SIOCGIFFLAGS as _, req.as_mut_ptr()).into())?;
        let flags = i16::from_ne_bytes([req[IFNAMSIZ], req[IFNAMSIZ + 1]]) | libc::IFF_UP as i16;
        req[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());
        check(libc::ioctl(s.as_raw_fd(), libc::SIOCSIFFLAGS as _, req.as_mut_ptr()).into())?;
    }
    Ok(())
}

/// NAT for guests: creates nftables table `ip joos` if it doesn't exist, and
/// turns on ip_forward. The table holds one chain,
///
///   chain postrouting { type nat hook postrouting priority srcnat
///     iifname "tap*" oifname != "tap*" masquerade }
///
/// so it names no tap or uplink and never needs updating: any tap's traffic
/// leaving through a non-tap interface is masqueraded, whatever the uplink.
pub fn ensure_routing() -> Result<(), Error> {
    let nl = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_NETFILTER)?;
    let timeout = libc::timeval { tv_sec: 1, tv_usec: 0 };
    // SAFETY: SO_RCVTIMEO takes a struct timeval, which timeout is.
    check(unsafe {
        libc::setsockopt(
            nl.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    }.into())?;
    if !table_exists(&nl)? {
        create_table(&nl)?;
    }
    enable_ip_forward()
}

fn enable_ip_forward() -> Result<(), Error> {
    const PATH: &str = "/proc/sys/net/ipv4/ip_forward";
    if std::fs::read_to_string(PATH)?.trim() != "1" {
        std::fs::write(PATH, "1")?;
    }
    Ok(())
}

// uapi linux/netfilter/nf_tables.h attribute numbers (not in the libc crate)
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFTA_DATA_VALUE: u16 = 1;
const NF_IP_PRI_NAT_SRC: i32 = 100;

const TABLE: &[u8] = b"joos\0";
const CHAIN: &[u8] = b"postrouting\0";

/// Netlink messages for NETLINK_NETFILTER: nlmsghdr + nfgenmsg + attributes.
#[derive(Default)]
struct Messages {
    buf: Vec<u8>,
    seq: u32,
    acks: usize,
}

impl Messages {
    fn msg(&mut self, ty: libc::c_int, flags: libc::c_int, family: libc::c_int, res_id: u16, attrs: impl FnOnce(&mut Vec<u8>)) {
        let start = self.buf.len();
        self.buf.extend_from_slice(&[0u8; 16]);
        // struct nfgenmsg: family, version (NFNETLINK_V0), be16 res_id
        self.buf.extend_from_slice(&[family as u8, 0]);
        self.buf.extend_from_slice(&res_id.to_be_bytes());
        attrs(&mut self.buf);
        self.seq += 1;
        let len = (self.buf.len() - start) as u32;
        let hdr = &mut self.buf[start..start + 16];
        hdr[0..4].copy_from_slice(&len.to_ne_bytes());
        hdr[4..6].copy_from_slice(&(ty as u16).to_ne_bytes());
        hdr[6..8].copy_from_slice(&((flags | libc::NLM_F_REQUEST) as u16).to_ne_bytes());
        hdr[8..12].copy_from_slice(&self.seq.to_ne_bytes());
        if flags & libc::NLM_F_ACK != 0 {
            self.acks += 1;
        }
    }

    fn nft(&mut self, msg: libc::c_int, flags: libc::c_int, attrs: impl FnOnce(&mut Vec<u8>)) {
        let ty = (libc::NFNL_SUBSYS_NFTABLES << 8) | msg;
        self.msg(ty, flags | libc::NLM_F_ACK, libc::NFPROTO_IPV4, 0, attrs);
    }
}

fn attr(buf: &mut Vec<u8>, ty: u16, data: &[u8]) {
    buf.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(data);
    buf.resize(buf.len().next_multiple_of(4), 0);
}

fn attr_be32(buf: &mut Vec<u8>, ty: u16, v: u32) {
    attr(buf, ty, &v.to_be_bytes());
}

fn nest(buf: &mut Vec<u8>, ty: u16, inner: impl FnOnce(&mut Vec<u8>)) {
    let start = buf.len();
    buf.extend_from_slice(&[0u8; 4]);
    inner(buf);
    let len = (buf.len() - start) as u16;
    buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    buf[start + 2..start + 4].copy_from_slice(&(ty | libc::NLA_F_NESTED as u16).to_ne_bytes());
}

fn expr(buf: &mut Vec<u8>, name: &[u8], data: Option<&dyn Fn(&mut Vec<u8>)>) {
    nest(buf, NFTA_LIST_ELEM, |buf| {
        attr(buf, NFTA_EXPR_NAME, name);
        if let Some(data) = data {
            nest(buf, NFTA_EXPR_DATA, data);
        }
    });
}

/// `meta load <key> => reg 1`, then `cmp <op> reg 1 "tap"`: a 3-byte compare
/// is a prefix match, i.e. "tap*".
fn ifname_is_tap(buf: &mut Vec<u8>, key: libc::c_int, op: libc::c_int) {
    expr(buf, b"meta\0", Some(&|buf: &mut Vec<u8>| {
        attr_be32(buf, NFTA_META_DREG, libc::NFT_REG_1 as u32);
        attr_be32(buf, NFTA_META_KEY, key as u32);
    }));
    expr(buf, b"cmp\0", Some(&|buf: &mut Vec<u8>| {
        attr_be32(buf, NFTA_CMP_SREG, libc::NFT_REG_1 as u32);
        attr_be32(buf, NFTA_CMP_OP, op as u32);
        nest(buf, NFTA_CMP_DATA, |buf| attr(buf, NFTA_DATA_VALUE, b"tap"));
    }));
}

/// Sends `m` and reads replies until every message that asked for an ack
/// has one. Returns whether any non-ack reply came back, or the first error.
fn transact(nl: &OwnedFd, m: &Messages) -> Result<bool, Error> {
    // SAFETY: sends from a live buffer of the given length.
    check(unsafe { libc::send(nl.as_raw_fd(), m.buf.as_ptr().cast(), m.buf.len(), 0) } as libc::c_long)?;
    let mut buf = vec![0u8; 64 * 1024];
    let (mut acks, mut data, mut error) = (0, false, None);
    while acks < m.acks {
        // SAFETY: reads into our own buffer.
        let n = check(unsafe { libc::recv(nl.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) } as libc::c_long)? as usize;
        let mut off = 0;
        while off + 16 <= n {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
            if len < 16 || off + len > n {
                break;
            }
            if ty == libc::NLMSG_ERROR as u16 {
                acks += 1;
                let errno = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                if errno != 0 && error.is_none() {
                    error = Some(Error::from_raw_os_error(-errno));
                }
            } else {
                data = true;
            }
            off += len.next_multiple_of(4);
        }
    }
    match error {
        Some(e) => Err(e),
        None => Ok(data),
    }
}

fn table_exists(nl: &OwnedFd) -> Result<bool, Error> {
    let mut m = Messages::default();
    m.nft(libc::NFT_MSG_GETTABLE, 0, |buf| attr(buf, NFTA_TABLE_NAME, TABLE));
    match transact(nl, &m) {
        Ok(found) => Ok(found),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(e) => Err(e),
    }
}

/// One atomic batch: add table (no-op if it exists), delete it, add it again
/// with its chain and rule. Two VMMs racing to create it end with one copy.
fn create_table(nl: &OwnedFd) -> Result<(), Error> {
    let subsys = libc::NFNL_SUBSYS_NFTABLES as u16;
    let table = |buf: &mut Vec<u8>| attr(buf, NFTA_TABLE_NAME, TABLE);
    let mut m = Messages::default();
    m.msg(libc::NFNL_MSG_BATCH_BEGIN, 0, libc::AF_UNSPEC, subsys, |_| {});
    m.nft(libc::NFT_MSG_NEWTABLE, libc::NLM_F_CREATE, table);
    m.nft(libc::NFT_MSG_DELTABLE, 0, table);
    m.nft(libc::NFT_MSG_NEWTABLE, libc::NLM_F_CREATE, table);
    m.nft(libc::NFT_MSG_NEWCHAIN, libc::NLM_F_CREATE, |buf| {
        attr(buf, NFTA_CHAIN_TABLE, TABLE);
        attr(buf, NFTA_CHAIN_NAME, CHAIN);
        nest(buf, NFTA_CHAIN_HOOK, |buf| {
            attr_be32(buf, NFTA_HOOK_HOOKNUM, libc::NF_INET_POST_ROUTING as u32);
            attr_be32(buf, NFTA_HOOK_PRIORITY, NF_IP_PRI_NAT_SRC as u32);
        });
        attr(buf, NFTA_CHAIN_TYPE, b"nat\0");
    });
    m.nft(libc::NFT_MSG_NEWRULE, libc::NLM_F_CREATE | libc::NLM_F_APPEND, |buf| {
        attr(buf, NFTA_RULE_TABLE, TABLE);
        attr(buf, NFTA_RULE_CHAIN, CHAIN);
        nest(buf, NFTA_RULE_EXPRESSIONS, |buf| {
            ifname_is_tap(buf, libc::NFT_META_IIFNAME, libc::NFT_CMP_EQ);
            ifname_is_tap(buf, libc::NFT_META_OIFNAME, libc::NFT_CMP_NEQ);
            expr(buf, b"masq\0", None);
        });
    });
    m.msg(libc::NFNL_MSG_BATCH_END, 0, libc::AF_UNSPEC, subsys, |_| {});
    transact(nl, &m).map(|_| ())
}

/// Removes CAP_NET_ADMIN from this process's effective, permitted and
/// inheritable sets, for good.
pub fn drop_net_admin() -> Result<(), Error> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const CAP_NET_ADMIN: u32 = 12;
    let mut hdr = Header { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut data = [Data::default(); 2];
    // SAFETY: version 3 capget/capset take a header and two data structs.
    check(unsafe { libc::syscall(libc::SYS_capget, &raw mut hdr, data.as_mut_ptr()) })?;
    let keep = !(1u32 << CAP_NET_ADMIN);
    data[0].effective &= keep;
    data[0].permitted &= keep;
    data[0].inheritable &= keep;
    // SAFETY: as above.
    check(unsafe { libc::syscall(libc::SYS_capset, &raw mut hdr, data.as_ptr()) })?;
    Ok(())
}
