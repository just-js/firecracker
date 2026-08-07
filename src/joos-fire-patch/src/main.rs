// Hot-patches build/fire2's embedded vmlinux/initrd directly, in place, no
// cargo/rustc/mold, no cc, no objcopy - a pure-Rust replacement for
// patch_fire2.sh + pad_slot.c. See FIRECRACKER.md.
//
// `objcopy --update-section` (the thing this replaces) doesn't actually do
// a surgical in-place write despite the name - straced, it reads the whole
// target file and writes a complete new one (rename-over-original), twice
// (once per section). This instead locates the two sections' file
// offsets/sizes via seek-based partial reads (ELF header + section header
// table + string table only - never the sections' own multi-MB content),
// then writes only the real payload bytes directly at those offsets - no
// full-file read, no full-file rewrite, no temp files, no subprocess calls.
//
// Previously used the `object` crate against a `std::fs::read()`'d copy of
// the whole file - that read the pre-patch `.joos_vmlinux`/`.joos_initrd`
// bytes into this process before overwriting them via a separate write
// handle, which turned out to reliably corrupt the *running* fire2 process
// afterward (verified: the resulting file was byte-for-byte correct on
// disk - md5sum-verified against the source vmlinux/initrd - yet fire2
// failed to parse its own embedded vmlinux at runtime; `dd` writing the
// identical bytes to the identical offsets did not reproduce this).
// Root cause not fully understood, but the fix (never read the section
// content into this process at all) reliably resolves it and is a genuine
// improvement regardless - no reason to read 20+MB just to locate two
// section headers.
//
// Scoped deliberately to exactly two sections, matching this project's
// current needs - not a general objcopy replacement.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

const SECTIONS: [(&str, &str); 2] = [(".joos_vmlinux", "vmlinux"), (".joos_initrd", "initrd")];

fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}
fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn u64le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Returns `(sh_offset, sh_size)` for `name`, by seeking directly to the
/// ELF header, then the section header table, then the string table - never
/// reading any section's own content, in particular never the (potentially
/// huge) `.joos_vmlinux`/`.joos_initrd` payloads themselves.
fn section_file_range(f: &mut File, name: &str) -> Option<(u64, u64)> {
    let mut ehdr = [0u8; 64];
    f.seek(SeekFrom::Start(0)).ok()?;
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

    for i in 0..e_shnum {
        let sh = &shdrs[i * e_shentsize..][..e_shentsize];
        let name_off = u32le(sh, 0) as usize;
        let end = shstrtab[name_off..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_off + p)
            .unwrap_or(shstrtab.len());
        if shstrtab.get(name_off..end) == Some(name.as_bytes()) {
            return Some((u64le(sh, 24), u64le(sh, 32)));
        }
    }
    None
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, fire2_path, vmlinux_path, initrd_path] = args.as_slice() else {
        eprintln!("usage: joos-fire-patch <fire2-binary> <vmlinux-file> <initrd-file>");
        std::process::exit(2);
    };
    let sources = [vmlinux_path, initrd_path];

    let mut out = OpenOptions::new()
        .read(true)
        .write(true)
        .open(fire2_path)
        .unwrap_or_else(|e| fail(&format!("cannot open {fire2_path} for read/write: {e}")));

    for ((section_name, label), source_path) in SECTIONS.iter().zip(sources) {
        let (offset, size) = section_file_range(&mut out, section_name).unwrap_or_else(|| {
            fail(&format!("{fire2_path}: no {section_name} section - was this built with joos-fire's slot-based embedding?"))
        });
        // Slot format: data, zero padding, then an 8-byte LE length
        // trailer at the very end (size - 8..size) - the length is a
        // trailer rather than a prefix specifically so data starts at
        // offset 0 of the slot (page-aligned, since the section itself is
        // page-aligned - see PageAligned in joos-fire's main.rs) - required
        // for joos/INIT.md's zero-copy `mmap()` plan. Must match
        // build.rs's write_slot() exactly, since either one can be what
        // last wrote this binary's slots.
        let capacity = size - 8;

        let mut source = File::open(source_path)
            .unwrap_or_else(|e| fail(&format!("cannot open {source_path}: {e}")));
        let source_len = source
            .metadata()
            .unwrap_or_else(|e| fail(&format!("cannot stat {source_path}: {e}")))
            .len();
        if source_len > capacity {
            fail(&format!(
                "{source_path}: {source_len} bytes exceeds the {label} slot's capacity of {capacity} bytes - rebuild with `make {label}=... build/fire2` (bigger JOOS_{}_MAX) instead",
                label.to_uppercase()
            ));
        }

        let mut buf = Vec::with_capacity(size as usize);
        source
            .read_to_end(&mut buf)
            .unwrap_or_else(|e| fail(&format!("cannot read {source_path}: {e}")));
        buf.resize(capacity as usize, 0);
        buf.extend_from_slice(&source_len.to_le_bytes());

        out.seek(SeekFrom::Start(offset))
            .unwrap_or_else(|e| fail(&format!("cannot seek {fire2_path}: {e}")));
        out.write_all(&buf)
            .unwrap_or_else(|e| fail(&format!("cannot write {fire2_path}: {e}")));

        println!("{label}: patched {source_len} bytes into {section_name} (capacity {capacity})");
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("joos-fire-patch: {msg}");
    std::process::exit(1);
}
