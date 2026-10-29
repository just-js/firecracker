// joos: creates a missing drive file as an empty ext4 filesystem
// ("create-disk-mib" in the Firecracker config, from `disk: <MiB>` in a joos
// image config), before VmResources::from_json() opens it.
//
// Deliberately minimal: 4 KiB blocks, 32768 blocks per group, 256-byte inodes
// (one per 16 KiB, mke2fs's default), sparse_super backups, and only the
// filetype, extents, large_file and extra_isize features: no journal,
// metadata_csum, flex_bg, 64bit, resize_inode or dir_index. Writes the
// superblocks, group descriptors, bitmaps, the root directory and lost+found;
// everything else (the inode tables included) is the sparse file's zeros.

use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind};
use std::os::unix::fs::FileExt;
use std::path::Path;

const BLOCK: u64 = 4096;
// One block bitmap's worth of blocks; also the limit on inodes per group.
const BLOCKS_PER_GROUP: u64 = BLOCK * 8;
const INODE_SIZE: u64 = 256;
const INODES_PER_BLOCK: u64 = BLOCK / INODE_SIZE;
const BYTES_PER_INODE: u64 = 16384;
const DESC_SIZE: u64 = 32;
const ROOT_INO: u64 = 2;
// lost+found, also the first non-reserved inode (s_first_ino)
const LPF_INO: u64 = 11;
// The root directory and lost+found, one block each, in group 0.
const DATA_BLOCKS: u64 = 2;

const INCOMPAT_FILETYPE: u64 = 0x2;
const INCOMPAT_EXTENTS: u64 = 0x40;
const RO_COMPAT_SPARSE_SUPER: u64 = 0x1;
const RO_COMPAT_LARGE_FILE: u64 = 0x2;
const RO_COMPAT_EXTRA_ISIZE: u64 = 0x40;
const EXTRA_ISIZE: u64 = 32;

/// Writes `val`'s low `len` bytes, little-endian, at `buf[off..]`.
fn put(buf: &mut [u8], off: usize, len: usize, val: u64) {
    debug_assert!(len == 8 || val >> (len * 8) == 0, "{val} doesn't fit in {len} bytes");
    buf[off..off + len].copy_from_slice(&val.to_le_bytes()[..len]);
}

fn set_bits(bitmap: &mut [u8], from: u64, to: u64) {
    for bit in from..to {
        bitmap[usize::try_from(bit / 8).unwrap()] |= 1 << (bit % 8);
    }
}

// sparse_super: groups 0 and 1 and powers of 3, 5 and 7 hold a superblock
// and group descriptor table copy.
fn has_super(group: u64) -> bool {
    let power_of = |base: u64| {
        let mut n = base;
        while n < group {
            n *= base;
        }
        n == group
    };
    group <= 1 || power_of(3) || power_of(5) || power_of(7)
}

#[derive(Debug)]
struct Layout {
    blocks: u64,
    groups: u64,
    inodes_per_group: u64,
    gdt_blocks: u64,
}

impl Layout {
    /// The largest filesystem that fits in `size` bytes. A last group too
    /// small for its own metadata is left out (its blocks stay unused).
    fn new(size: u64) -> Result<Self, Error> {
        let mut blocks = size / BLOCK;
        if blocks > u64::from(u32::MAX) {
            return Err(Error::new(ErrorKind::InvalidInput, "over 16 TiB needs 64bit"));
        }
        loop {
            let groups = blocks.div_ceil(BLOCKS_PER_GROUP).max(1);
            let inodes_per_group = (blocks * BLOCK / BYTES_PER_INODE)
                .div_ceil(groups)
                .next_multiple_of(INODES_PER_BLOCK)
                .clamp(INODES_PER_BLOCK, BLOCKS_PER_GROUP);
            let layout = Layout {
                blocks,
                groups,
                inodes_per_group,
                gdt_blocks: (groups * DESC_SIZE).div_ceil(BLOCK),
            };
            let last = groups - 1;
            let data = if last == 0 { DATA_BLOCKS } else { 0 };
            if layout.group_blocks(last) > layout.overhead(last) + data {
                return Ok(layout);
            }
            if last == 0 {
                return Err(Error::new(ErrorKind::InvalidInput, "too small for a filesystem"));
            }
            blocks = last * BLOCKS_PER_GROUP;
        }
    }

    fn group_blocks(&self, group: u64) -> u64 {
        (self.blocks - group * BLOCKS_PER_GROUP).min(BLOCKS_PER_GROUP)
    }

    /// The group's superblock + descriptor copy, if any (the first blocks of
    /// the group), then its block bitmap, inode bitmap and inode table.
    fn super_blocks(&self, group: u64) -> u64 {
        if has_super(group) { 1 + self.gdt_blocks } else { 0 }
    }

    fn overhead(&self, group: u64) -> u64 {
        self.super_blocks(group) + 2 + self.inodes_per_group / INODES_PER_BLOCK
    }
}

/// Creates `path` (which must not exist) as a `mib` MiB sparse file holding an
/// empty ext4 filesystem. On failure the partial file is removed.
pub fn create(path: &Path, mib: u64) -> Result<(), Error> {
    let size = mib
        .checked_mul(1 << 20)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "size overflows"))?;
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let result = write(&file, size).and_then(|()| file.sync_all());
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

fn write(file: &File, size: u64) -> Result<(), Error> {
    let layout = Layout::new(size)?;
    file.set_len(size)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        & 0xffff_ffff;

    // Group descriptors and bitmaps
    let mut gdt = vec![0u8; usize::try_from(layout.gdt_blocks * BLOCK).unwrap()];
    let mut bitmap = vec![0u8; usize::try_from(BLOCK).unwrap()];
    let (mut free_blocks, mut free_inodes) = (0, 0);
    for group in 0..layout.groups {
        let block_bitmap = group * BLOCKS_PER_GROUP + layout.super_blocks(group);
        let first = group == 0;
        let used_blocks = layout.overhead(group) + if first { DATA_BLOCKS } else { 0 };
        let used_inodes = if first { LPF_INO } else { 0 };
        let group_free_blocks = layout.group_blocks(group) - used_blocks;
        let group_free_inodes = layout.inodes_per_group - used_inodes;
        free_blocks += group_free_blocks;
        free_inodes += group_free_inodes;

        let desc = &mut gdt[usize::try_from(group * DESC_SIZE).unwrap()..];
        put(desc, 0x00, 4, block_bitmap);
        put(desc, 0x04, 4, block_bitmap + 1); // inode bitmap
        put(desc, 0x08, 4, block_bitmap + 2); // inode table
        put(desc, 0x0c, 2, group_free_blocks);
        put(desc, 0x0e, 2, group_free_inodes);
        put(desc, 0x10, 2, if first { 2 } else { 0 }); // directories

        // Bits past the group's end are set, as mke2fs does.
        bitmap.fill(0);
        set_bits(&mut bitmap, 0, used_blocks);
        set_bits(&mut bitmap, layout.group_blocks(group), BLOCKS_PER_GROUP);
        file.write_all_at(&bitmap, block_bitmap * BLOCK)?;
        bitmap.fill(0);
        set_bits(&mut bitmap, 0, used_inodes);
        set_bits(&mut bitmap, layout.inodes_per_group, BLOCK * 8);
        file.write_all_at(&bitmap, (block_bitmap + 1) * BLOCK)?;
    }

    // Superblock and descriptor table, in group 0 and the sparse_super copies
    let mut uuid = [0u8; 16];
    // SAFETY: uuid is a valid, writable 16-byte buffer for the whole call.
    if unsafe { libc::getrandom(uuid.as_mut_ptr().cast(), uuid.len(), 0) } != 16 {
        return Err(Error::last_os_error());
    }
    uuid[6] = (uuid[6] & 0x0f) | 0x40; // version 4
    uuid[8] = (uuid[8] & 0x3f) | 0x80; // RFC 4122 variant
    let mut sb = [0u8; 1024];
    put(&mut sb, 0x00, 4, layout.groups * layout.inodes_per_group);
    put(&mut sb, 0x04, 4, layout.blocks);
    put(&mut sb, 0x0c, 4, free_blocks);
    put(&mut sb, 0x10, 4, free_inodes);
    put(&mut sb, 0x18, 4, 2); // log2(block size) - 10
    put(&mut sb, 0x1c, 4, 2); // log2(cluster size) - 10
    put(&mut sb, 0x20, 4, BLOCKS_PER_GROUP);
    put(&mut sb, 0x24, 4, BLOCKS_PER_GROUP); // clusters per group
    put(&mut sb, 0x28, 4, layout.inodes_per_group);
    put(&mut sb, 0x30, 4, now); // write time
    put(&mut sb, 0x36, 2, 0xffff); // max mount count: no periodic fsck
    put(&mut sb, 0x38, 2, 0xef53); // magic
    put(&mut sb, 0x3a, 2, 1); // state: clean
    put(&mut sb, 0x3c, 2, 1); // errors: continue
    put(&mut sb, 0x40, 4, now); // last check
    put(&mut sb, 0x4c, 4, 1); // revision: dynamic
    put(&mut sb, 0x54, 4, LPF_INO); // first non-reserved inode
    put(&mut sb, 0x58, 2, INODE_SIZE);
    put(&mut sb, 0x60, 4, INCOMPAT_FILETYPE | INCOMPAT_EXTENTS);
    put(
        &mut sb,
        0x64,
        4,
        RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE | RO_COMPAT_EXTRA_ISIZE,
    );
    sb[0x68..0x78].copy_from_slice(&uuid);
    put(&mut sb, 0x108, 4, now); // mkfs time
    put(&mut sb, 0x15c, 2, EXTRA_ISIZE); // min extra inode size
    put(&mut sb, 0x15e, 2, EXTRA_ISIZE); // wanted extra inode size
    put(&mut sb, 0x160, 4, 1); // flags: signed directory hash (x86's char)
    for group in (0..layout.groups).filter(|&g| has_super(g)) {
        let start = group * BLOCKS_PER_GROUP * BLOCK;
        put(&mut sb, 0x5a, 2, group); // this copy's group
        // Group 0's superblock is at byte 1024; the copies start their group.
        file.write_all_at(&sb, if group == 0 { 1024 } else { start })?;
        file.write_all_at(&gdt, start + BLOCK)?;
    }

    // The root directory and lost+found: their inodes (both in the inode
    // table's first block) and one directory block each
    let root_block = layout.overhead(0);
    let lpf_block = root_block + 1;
    let mut inodes = vec![0u8; usize::try_from(BLOCK).unwrap()];
    for (ino, mode, links, block) in
        [(ROOT_INO, 0o40755, 3, root_block), (LPF_INO, 0o40700, 2, lpf_block)]
    {
        let inode = &mut inodes[usize::try_from((ino - 1) * INODE_SIZE).unwrap()..];
        put(inode, 0x00, 2, mode);
        put(inode, 0x04, 4, BLOCK); // size
        put(inode, 0x08, 4, now); // atime
        put(inode, 0x0c, 4, now); // ctime
        put(inode, 0x10, 4, now); // mtime
        put(inode, 0x1a, 2, links);
        put(inode, 0x1c, 4, BLOCK / 512); // 512-byte sectors
        put(inode, 0x28, 4, block); // i_block[0]: a block map, not extents
        put(inode, 0x80, 2, EXTRA_ISIZE);
        put(inode, 0x90, 4, now); // crtime
    }
    file.write_all_at(&inodes, (layout.super_blocks(0) + 2) * BLOCK)?;
    let root = [(ROOT_INO, &b"."[..]), (ROOT_INO, b".."), (LPF_INO, b"lost+found")];
    file.write_all_at(&dir_block(&root), root_block * BLOCK)?;
    let lpf = [(LPF_INO, &b"."[..]), (ROOT_INO, b"..")];
    file.write_all_at(&dir_block(&lpf), lpf_block * BLOCK)
}

/// A directory block holding `entries` (all directories), the last one
/// spanning the rest of the block.
fn dir_block(entries: &[(u64, &[u8])]) -> Vec<u8> {
    let mut block = vec![0u8; usize::try_from(BLOCK).unwrap()];
    let mut off = 0;
    for (i, (ino, name)) in entries.iter().enumerate() {
        let len = if i + 1 == entries.len() {
            block.len() - off
        } else {
            (8 + name.len()).next_multiple_of(4)
        };
        put(&mut block, off, 4, *ino);
        put(&mut block, off + 4, 2, len as u64);
        put(&mut block, off + 6, 1, name.len() as u64);
        put(&mut block, off + 7, 1, 2); // file type: directory
        block[off + 8..off + 8 + name.len()].copy_from_slice(name);
        off += len;
    }
    block
}
