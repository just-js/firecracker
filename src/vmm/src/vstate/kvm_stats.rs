// Copyright 2026 joos authors.
// SPDX-License-Identifier: Apache-2.0

//! joos: KVM's binary statistics (`KVM_GET_STATS_FD`, Linux 5.14+) for the VM
//! and each vCPU, printed when the guest signals boot (boot timer). Only with
//! `JOOS_KVM_STATS=1` in the environment; otherwise nothing is opened. Shows
//! how many exits of each kind a boot took (joos doc/NESTED_BOOT.md).

use std::fs::File;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::FileExt;
use std::sync::Mutex;

// _IO(KVMIO, 0xce)
const KVM_GET_STATS_FD: libc::c_ulong = 0xae_ce;
// struct kvm_stats_header: flags, name_size, num_desc, id_offset, desc_offset,
// data_offset (u32 each)
const HEADER_SIZE: usize = 24;
// struct kvm_stats_desc without its name: flags u32, exponent i16, size u16,
// offset u32, bucket_size u32
const DESC_SIZE: usize = 16;
const KVM_STATS_TYPE_MASK: u32 = 0xf;
const KVM_STATS_TYPE_CUMULATIVE: u32 = 0;
const KVM_STATS_TYPE_INSTANT: u32 = 1;
const KVM_STATS_TYPE_PEAK: u32 = 2;

static STATS: Mutex<Vec<(String, File)>> = Mutex::new(Vec::new());

fn enabled() -> bool {
    std::env::var_os("JOOS_KVM_STATS").is_some_and(|v| v == "1")
}

/// Opens the stats fd of a VM or vCPU fd and keeps it under `label`.
pub fn register(fd: RawFd, label: &str) {
    if !enabled() {
        return;
    }
    // SAFETY: KVM_GET_STATS_FD takes no argument and returns a new fd or -1.
    let r = unsafe { libc::ioctl(fd, KVM_GET_STATS_FD as _) };
    if r < 0 {
        eprintln!(
            "[joos-fire] kvm-stats: KVM_GET_STATS_FD on {label}: {}",
            std::io::Error::last_os_error()
        );
        return;
    }
    // SAFETY: r is a new fd we own.
    let file = unsafe { File::from_raw_fd(r) };
    STATS.lock().unwrap().push((label.to_string(), file));
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn dump_one(label: &str, f: &File) -> std::io::Result<()> {
    let mut h = [0u8; HEADER_SIZE];
    f.read_exact_at(&mut h, 0)?;
    let name_size = u32_at(&h, 4) as usize;
    let num_desc = u32_at(&h, 8) as usize;
    let desc_offset = u32_at(&h, 16) as u64;
    let data_offset = u32_at(&h, 20) as u64;
    let stride = DESC_SIZE + name_size;
    let mut descs = vec![0u8; stride * num_desc];
    f.read_exact_at(&mut descs, desc_offset)?;
    let mut line = format!("[joos-fire] kvm-stats {label}:");
    for i in 0..num_desc {
        let d = &descs[i * stride..(i + 1) * stride];
        let flags = u32_at(d, 0);
        let kind = flags & KVM_STATS_TYPE_MASK;
        let size = u16::from_le_bytes([d[6], d[7]]) as usize;
        let offset = u32_at(d, 8) as u64;
        // histograms are skipped: only single-value counters
        if size != 1
            || !matches!(
                kind,
                KVM_STATS_TYPE_CUMULATIVE | KVM_STATS_TYPE_INSTANT | KVM_STATS_TYPE_PEAK
            )
        {
            continue;
        }
        let mut v = [0u8; 8];
        f.read_exact_at(&mut v, data_offset + offset)?;
        let v = u64::from_le_bytes(v);
        if v == 0 {
            continue;
        }
        let name = &d[DESC_SIZE..];
        let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        line.push_str(&format!(" {}={v}", String::from_utf8_lossy(&name[..end])));
    }
    eprintln!("{line}");
    Ok(())
}

/// Prints every registered stats fd's non-zero single-value counters.
pub fn dump() {
    for (label, f) in STATS.lock().unwrap().iter() {
        if let Err(e) = dump_one(label, f) {
            eprintln!("[joos-fire] kvm-stats {label}: {e}");
        }
    }
}
