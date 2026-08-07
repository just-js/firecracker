// Hot-patches build/fire2's embedded vmlinux/initrd directly, in place, no
// cargo/rustc/mold, no cc, no objcopy - a pure-Rust replacement for
// patch_fire2.sh + pad_slot.c. See FIRECRACKER.md.
//
// `objcopy --update-section` (the thing this replaces) doesn't actually do
// a surgical in-place write despite the name - straced, it reads the whole
// target file and writes a complete new one (rename-over-original), twice
// (once per section). This instead reads the target once just to locate
// the two sections' file offsets/sizes, then writes only the real payload
// bytes directly at those offsets - no full-file rewrite, no temp files,
// no subprocess calls at all.
//
// Scoped deliberately to exactly two sections, matching this project's
// current needs - not a general objcopy replacement.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use object::{Object, ObjectSection};

const SECTIONS: [(&str, &str); 2] = [(".joos_vmlinux", "vmlinux"), (".joos_initrd", "initrd")];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, fire2_path, vmlinux_path, initrd_path] = args.as_slice() else {
        eprintln!("usage: joos-fire-patch <fire2-binary> <vmlinux-file> <initrd-file>");
        std::process::exit(2);
    };
    let sources = [vmlinux_path, initrd_path];

    // Read once, purely to locate section offsets/sizes - the object crate
    // needs a byte slice to parse the ELF headers from.
    let fire2_bytes = std::fs::read(fire2_path)
        .unwrap_or_else(|e| fail(&format!("cannot read {fire2_path}: {e}")));
    let elf = object::File::parse(&*fire2_bytes)
        .unwrap_or_else(|e| fail(&format!("cannot parse {fire2_path} as an object file: {e}")));

    let mut out = OpenOptions::new()
        .write(true)
        .open(fire2_path)
        .unwrap_or_else(|e| fail(&format!("cannot open {fire2_path} for writing: {e}")));

    for ((section_name, label), source_path) in SECTIONS.iter().zip(sources) {
        let section = elf.section_by_name(section_name).unwrap_or_else(|| {
            fail(&format!("{fire2_path}: no {section_name} section - was this built with joos-fire's slot-based embedding?"))
        });
        let (offset, size) = section.file_range().unwrap_or_else(|| {
            fail(&format!("{fire2_path}: {section_name} has no file contents (bss?)"))
        });
        let capacity = size - 8; // slot format: 8-byte LE length prefix + data + padding

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
        buf.extend_from_slice(&source_len.to_le_bytes());
        source
            .read_to_end(&mut buf)
            .unwrap_or_else(|e| fail(&format!("cannot read {source_path}: {e}")));
        buf.resize(size as usize, 0);

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
