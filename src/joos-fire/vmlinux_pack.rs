// Repacks a vmlinux ELF down to just the bytes firecracker's loader actually
// reads: the ELF header, the program headers, and each PT_LOAD segment's
// file contents, laid out back to back. Everything else is dropped - the
// kernel's 2MiB-aligned file offsets leave ~5.4MB of zero padding between
// segments, and .symtab/.strtab add another ~1.2MB, none of which is ever
// loaded (17.17MB -> 10.51MB for the current kernel). See doc/VMLINUX_PACK.md
// in the parent joos project.
//
// Zero runtime cost: linux-loader's Elf::load() only reads the ELF header,
// seeks to e_phoff for the program headers, then reads p_filesz bytes from
// each PT_LOAD's p_offset (plus the PT_NOTE, for the PVH entry point) - so
// rewriting p_offset is all it takes. Guest memory ends up byte-identical.
//
// Shared by joos-fire's build.rs and joos-fire-patch (both pull this file in
// via #[path]) so full builds and hot patches always produce the exact same
// slot contents. Deterministic and idempotent: packing an already-packed
// vmlinux returns it unchanged, so either form can be fed to either tool.

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const PT_LOAD: u32 = 1;
// Segment data alignment within the packed file. Only needs to keep the
// loader's copies reasonably aligned - nothing maps this file.
const DATA_ALIGN: usize = 16;

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

fn to_usize(v: u64, what: &str) -> Result<usize, String> {
    usize::try_from(v).map_err(|_| format!("{what} {v:#x} doesn't fit in usize"))
}

/// Returns `vmlinux` repacked as described above, or an error if it isn't a
/// 64-bit little-endian ELF with sane program headers.
pub fn pack_vmlinux(vmlinux: &[u8]) -> Result<Vec<u8>, String> {
    if vmlinux.len() < EHDR_SIZE || &vmlinux[0..4] != b"\x7fELF" {
        return Err("not an ELF file".into());
    }
    if vmlinux[4] != 2 || vmlinux[5] != 1 {
        return Err("not a 64-bit little-endian ELF".into());
    }
    let phoff = to_usize(u64_at(vmlinux, 32), "e_phoff")?;
    let phentsize = usize::from(u16_at(vmlinux, 54));
    let phnum = usize::from(u16_at(vmlinux, 56));
    if phentsize != PHDR_SIZE {
        return Err(format!("unexpected e_phentsize {phentsize}"));
    }
    if phoff
        .checked_add(phnum * PHDR_SIZE)
        .is_none_or(|end| end > vmlinux.len())
    {
        return Err("program headers run past end of file".into());
    }

    // (p_type, p_offset, p_filesz) for every program header, bounds-checked.
    let mut segs = Vec::with_capacity(phnum);
    for i in 0..phnum {
        let ph = &vmlinux[phoff + i * PHDR_SIZE..phoff + (i + 1) * PHDR_SIZE];
        let p_type = u32_at(ph, 0);
        let offset = to_usize(u64_at(ph, 8), "p_offset")?;
        let filesz = to_usize(u64_at(ph, 32), "p_filesz")?;
        if filesz > 0 && offset.checked_add(filesz).is_none_or(|end| end > vmlinux.len()) {
            return Err(format!("program header {i} runs past end of file"));
        }
        segs.push((p_type, offset, filesz));
    }

    let mut out = vec![0u8; EHDR_SIZE + phnum * PHDR_SIZE];
    out[..EHDR_SIZE].copy_from_slice(&vmlinux[..EHDR_SIZE]);
    out[32..40].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes()); // e_phoff
    out[40..48].fill(0); // e_shoff: no section headers
    out[58..64].fill(0); // e_shentsize, e_shnum, e_shstrndx

    // Pass 1: lay out PT_LOAD data. new_offsets[i] is Some once placed.
    let mut new_offsets: Vec<Option<usize>> = vec![None; phnum];
    let place = |out: &mut Vec<u8>, offset: usize, filesz: usize| {
        out.resize(out.len().next_multiple_of(DATA_ALIGN), 0);
        let at = out.len();
        out.extend_from_slice(&vmlinux[offset..offset + filesz]);
        at
    };
    for (i, &(p_type, offset, filesz)) in segs.iter().enumerate() {
        if p_type == PT_LOAD && filesz > 0 {
            new_offsets[i] = Some(place(&mut out, offset, filesz));
        }
    }
    // Pass 2: everything else with file contents (e.g. PT_NOTE) either
    // lives inside a PT_LOAD already placed - remap it relative to that - or
    // gets its own copy appended.
    for (i, &(p_type, offset, filesz)) in segs.iter().enumerate() {
        if p_type == PT_LOAD || filesz == 0 {
            continue;
        }
        let container = segs.iter().zip(&new_offsets).find_map(|(&(t, o, s), &new)| {
            (t == PT_LOAD && s > 0 && offset >= o && offset + filesz <= o + s)
                .then(|| new.unwrap() + (offset - o))
        });
        new_offsets[i] = Some(container.unwrap_or_else(|| place(&mut out, offset, filesz)));
    }

    for (i, new) in new_offsets.iter().enumerate() {
        let ph = EHDR_SIZE + i * PHDR_SIZE;
        let src = phoff + i * PHDR_SIZE;
        out[ph..ph + PHDR_SIZE].copy_from_slice(&vmlinux[src..src + PHDR_SIZE]);
        out[ph + 8..ph + 16].copy_from_slice(&(new.unwrap_or(0) as u64).to_le_bytes());
    }
    Ok(out)
}
