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
// Also holds the optional lz4 slot formats for vmlinux and initrd
// (pack_vmlinux_lz4/pack_initrd_lz4 below), decoded by vmm at boot.
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
        if filesz > 0
            && offset
                .checked_add(filesz)
                .is_none_or(|end| end > vmlinux.len())
        {
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
        let container = segs
            .iter()
            .zip(&new_offsets)
            .find_map(|(&(t, o, s), &new)| {
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

/// Magic prefix of the lz4 slot format below. Must match
/// `KERNEL_LZ4_MAGIC` in vmm's arch/x86_64/mod.rs, which decodes it.
pub const LZ4_MAGIC: [u8; 8] = *b"JOOSLZ4\x01";

/// lz4 HC level used by both build.rs and joos-fire-patch, so hot patches
/// produce the same bytes as full builds. 9 gets ~the same ratio as the max
/// (12) in a third of the time (0.26s vs 0.81s on the current kernel).
pub const LZ4_LEVEL: i32 = 9;

/// Packs `vmlinux` as above, then lz4-compresses each PT_LOAD separately so
/// joos-fire can decompress it straight into guest memory at p_paddr, with
/// no intermediate buffer and no second copy. `compress` is an lz4 *block* compressor
/// (the caller supplies it, so this file stays dependency-free). Layout, all
/// integers little-endian u64:
///
///   LZ4_MAGIC
///   stub_len, stub      - ELF header + program headers with every PT_LOAD's
///                         p_filesz zeroed (linux-loader skips those), plus
///                         any non-PT_LOAD data (the PVH PT_NOTE). Fed to the
///                         normal loader for entry point/PVH detection.
///   nseg                - then per PT_LOAD, in program header order:
///   paddr, filesz, clen, clen bytes of lz4 block data
pub fn pack_vmlinux_lz4(
    vmlinux: &[u8],
    compress: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Result<Vec<u8>, String> {
    // Normalise (and bounds-check) first, so offsets below are trusted.
    let packed = pack_vmlinux(vmlinux)?;
    let phnum = usize::from(u16_at(&packed, 56));
    let phdr = |i: usize| &packed[EHDR_SIZE + i * PHDR_SIZE..EHDR_SIZE + (i + 1) * PHDR_SIZE];

    let mut stub = packed[..EHDR_SIZE + phnum * PHDR_SIZE].to_vec();
    let mut segs = Vec::new();
    for i in 0..phnum {
        let ph = phdr(i);
        let offset = to_usize(u64_at(ph, 8), "p_offset")?;
        let filesz = to_usize(u64_at(ph, 32), "p_filesz")?;
        let at = EHDR_SIZE + i * PHDR_SIZE;
        if u32_at(ph, 0) == PT_LOAD {
            stub[at + 8..at + 16].fill(0); // p_offset
            stub[at + 32..at + 40].fill(0); // p_filesz
            if filesz > 0 {
                segs.push((u64_at(ph, 24), &packed[offset..offset + filesz]));
            }
        } else if filesz > 0 {
            stub.resize(stub.len().next_multiple_of(DATA_ALIGN), 0);
            let new_offset = stub.len() as u64;
            stub.extend_from_slice(&packed[offset..offset + filesz]);
            stub[at + 8..at + 16].copy_from_slice(&new_offset.to_le_bytes());
        }
    }

    let mut out = LZ4_MAGIC.to_vec();
    out.extend_from_slice(&(stub.len() as u64).to_le_bytes());
    out.extend_from_slice(&stub);
    out.extend_from_slice(&(segs.len() as u64).to_le_bytes());
    for (paddr, data) in segs {
        let compressed = compress(data);
        out.extend_from_slice(&paddr.to_le_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
        out.extend_from_slice(&compressed);
    }
    Ok(out)
}

/// Magic prefix of the chunked lz4 initrd format below. Must match
/// `INITRD_LZ4_MAGIC` in vmm's initrd.rs, which decodes it.
pub const INITRD_LZ4_MAGIC: [u8; 8] = *b"JOOSLZI\x01";

/// Uncompressed size of each independently-compressed initrd chunk. lz4's
/// window is only 64KiB so chunking costs next to nothing in ratio, and it
/// leaves room to decode chunks in parallel if the rootfs ever gets big.
pub const INITRD_LZ4_CHUNK: usize = 4 * 1024 * 1024;

/// lz4-compresses an initrd (any blob, really) so joos-fire can decompress
/// it straight into guest memory at its load address. `compress` is an lz4
/// block compressor, as for pack_vmlinux_lz4(). Layout, all integers
/// little-endian u64:
///
///   INITRD_LZ4_MAGIC
///   size                - total uncompressed size
///   nchunk              - then per chunk, in order:
///   raw_len, clen, clen bytes of lz4 block data
pub fn pack_initrd_lz4(initrd: &[u8], compress: &dyn Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let chunks: Vec<&[u8]> = initrd.chunks(INITRD_LZ4_CHUNK).collect();
    let mut out = INITRD_LZ4_MAGIC.to_vec();
    out.extend_from_slice(&(initrd.len() as u64).to_le_bytes());
    out.extend_from_slice(&(chunks.len() as u64).to_le_bytes());
    for chunk in chunks {
        let compressed = compress(chunk);
        out.extend_from_slice(&(chunk.len() as u64).to_le_bytes());
        out.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
        out.extend_from_slice(&compressed);
    }
    out
}
