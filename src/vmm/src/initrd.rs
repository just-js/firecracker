// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::unix::fs::MetadataExt;

use vm_memory::bitmap::Bitmap;
use vm_memory::{Bytes, GuestAddress, GuestMemory, ReadVolatile, VolatileMemoryError};

use crate::arch::initrd_load_addr;
use crate::utils::u64_to_usize;
use crate::vmm_config::boot_source::BootConfig;
use crate::vstate::memory::GuestMemoryMmap;

/// Errors associated with initrd loading.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum InitrdError {
    /// Failed to compute the initrd address.
    Address,
    /// Cannot load initrd due to an invalid memory configuration.
    Load,
    /// Cannot image metadata: {0}
    Metadata(std::io::Error),
    /// Cannot copy initrd file fd: {0}
    CloneFd(std::io::Error),
    /// Cannot load initrd due to an invalid image: {0}
    Read(VolatileMemoryError),
    /// Cannot load lz4-compressed initrd: {0}
    Lz4(String),
}

/// Magic prefix of joos-fire's chunked lz4 initrd format. Must match
/// `INITRD_LZ4_MAGIC` in src/joos-fire/vmlinux_pack.rs, whose
/// pack_initrd_lz4() documents the layout.
pub const INITRD_LZ4_MAGIC: [u8; 8] = *b"JOOSLZI\x01";

/// Splits the next `len` bytes off the front of `data`.
fn take<'a>(data: &mut &'a [u8], len: usize) -> Result<&'a [u8], InitrdError> {
    if data.len() < len {
        return Err(InitrdError::Lz4("truncated image".to_string()));
    }
    let (head, tail) = data.split_at(len);
    *data = tail;
    Ok(head)
}

fn take_usize(data: &mut &[u8]) -> Result<usize, InitrdError> {
    Ok(u64_to_usize(u64::from_le_bytes(
        take(data, 8)?.try_into().unwrap(),
    )))
}

/// Type for passing information about the initrd in the guest memory.
#[derive(Debug)]
pub struct InitrdConfig {
    /// Load address of initrd in guest memory
    pub address: GuestAddress,
    /// Size of initrd in guest memory
    pub size: usize,
}

impl InitrdConfig {
    /// Load initrd into guest memory based on the boot config.
    pub fn from_config(
        boot_cfg: &BootConfig,
        vm_memory: &GuestMemoryMmap,
    ) -> Result<Option<Self>, InitrdError> {
        Ok(match &boot_cfg.initrd_file {
            Some(f) => {
                let f = f.try_clone().map_err(InitrdError::CloneFd)?;
                Some(Self::from_file(vm_memory, f)?)
            }
            None => None,
        })
    }

    /// Loads the initrd directly from an in-process byte slice into guest
    /// memory (e.g. an `include_bytes!`'d initrd.cpio in an embedding binary
    /// like `joos-fire`), instead of a `File` - see `from_file` below for
    /// the file-based equivalent this project's stock boot path still uses.
    ///
    /// Data starting with `INITRD_LZ4_MAGIC` is decompressed straight into
    /// guest memory at the load address instead - see `from_lz4_bytes`.
    pub fn from_bytes(vm_memory: &GuestMemoryMmap, data: &[u8]) -> Result<Self, InitrdError> {
        if data.starts_with(&INITRD_LZ4_MAGIC) {
            return Self::from_lz4_bytes(vm_memory, data);
        }
        let size = data.len();
        let Some(address) = initrd_load_addr(vm_memory, size) else {
            return Err(InitrdError::Address);
        };
        vm_memory
            .write_slice(data, GuestAddress(address))
            .map_err(|_| InitrdError::Load)?;

        Ok(InitrdConfig {
            address: GuestAddress(address),
            size,
        })
    }

    /// Decompresses a joos-fire lz4 initrd (`INITRD_LZ4_MAGIC`) chunk by chunk
    /// directly into guest memory at the same address an uncompressed initrd
    /// of that size would get - no intermediate buffer, no second copy.
    fn from_lz4_bytes(vm_memory: &GuestMemoryMmap, data: &[u8]) -> Result<Self, InitrdError> {
        let err = |msg: String| InitrdError::Lz4(msg);
        let mut rest = &data[INITRD_LZ4_MAGIC.len()..];
        let size = take_usize(&mut rest)?;
        let nchunk = take_usize(&mut rest)?;
        let Some(address) = initrd_load_addr(vm_memory, size) else {
            return Err(InitrdError::Address);
        };
        let dest = vm_memory
            .get_slice(GuestAddress(address), size)
            .map_err(|_| InitrdError::Load)?;
        let guard = dest.ptr_guard_mut();
        // SAFETY: get_slice() checked that [address, address + size) is backed
        // by a single guest memory mapping, which stays mapped while `guard`
        // lives. No vCPU has run yet, so nothing else is accessing this memory.
        let buf = unsafe { std::slice::from_raw_parts_mut(guard.as_ptr(), size) };

        let mut pos = 0;
        for _ in 0..nchunk {
            let raw_len = take_usize(&mut rest)?;
            let clen = take_usize(&mut rest)?;
            let chunk = take(&mut rest, clen)?;
            let end = pos + raw_len;
            if end > size {
                return Err(err(format!("chunks exceed declared size {size}")));
            }
            let raw_len_i32 =
                i32::try_from(raw_len).map_err(|_| err(format!("chunk too big: {raw_len}")))?;
            let written =
                lz4::block::decompress_to_buffer(chunk, Some(raw_len_i32), &mut buf[pos..end])
                    .map_err(|e| err(format!("chunk at {pos}: {e}")))?;
            if written != raw_len {
                return Err(err(format!(
                    "chunk at {pos}: decompressed {written} bytes, expected {raw_len}"
                )));
            }
            pos = end;
        }
        if pos != size {
            return Err(err(format!("decompressed {pos} bytes, expected {size}")));
        }
        // What write_slice() would have done, for dirty-page tracking (snapshots).
        dest.bitmap().mark_dirty(0, size);

        Ok(InitrdConfig {
            address: GuestAddress(address),
            size,
        })
    }

    /// Loads the initrd from a file into guest memory.
    pub fn from_file(vm_memory: &GuestMemoryMmap, mut file: File) -> Result<Self, InitrdError> {
        let size = file.metadata().map_err(InitrdError::Metadata)?.size();
        let size = u64_to_usize(size);
        let Some(address) = initrd_load_addr(vm_memory, size) else {
            return Err(InitrdError::Address);
        };
        let mut slice = vm_memory
            .get_slice(GuestAddress(address), size)
            .map_err(|_| InitrdError::Load)?;
        file.read_exact_volatile(&mut slice)
            .map_err(InitrdError::Read)?;

        Ok(InitrdConfig {
            address: GuestAddress(address),
            size,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::arch::GUEST_PAGE_SIZE;
    use crate::test_utils::{single_region_mem, single_region_mem_at};

    fn make_test_bin() -> Vec<u8> {
        let mut fake_bin = Vec::new();
        fake_bin.resize(1_000_000, 0xAA);
        fake_bin
    }

    #[test]
    // Test that loading the initrd is successful on different archs.
    fn test_load_initrd() {
        let image = make_test_bin();

        let mem_size: usize = image.len() * 2 + GUEST_PAGE_SIZE;

        let tempfile = TempFile::new().unwrap();
        let mut tempfile = tempfile.into_file();
        tempfile.write_all(&image).unwrap();

        #[cfg(target_arch = "x86_64")]
        let gm = single_region_mem(mem_size);

        #[cfg(target_arch = "aarch64")]
        let gm = single_region_mem(mem_size + crate::arch::aarch64::layout::FDT_MAX_SIZE);

        // Need to reset the cursor to read initrd properly.
        tempfile.seek(SeekFrom::Start(0)).unwrap();
        let initrd = InitrdConfig::from_file(&gm, tempfile).unwrap();
        assert!(gm.address_in_range(initrd.address));
        assert_eq!(initrd.size, image.len());
    }

    #[test]
    fn test_load_initrd_no_memory() {
        let gm = single_region_mem(79);
        let image = make_test_bin();
        let tempfile = TempFile::new().unwrap();
        let mut tempfile = tempfile.into_file();
        tempfile.write_all(&image).unwrap();

        // Need to reset the cursor to read initrd properly.
        tempfile.seek(SeekFrom::Start(0)).unwrap();
        let res = InitrdConfig::from_file(&gm, tempfile);
        assert!(matches!(res, Err(InitrdError::Address)), "{:?}", res);
    }

    #[test]
    fn test_load_initrd_unaligned() {
        let image = vec![1, 2, 3, 4];
        let tempfile = TempFile::new().unwrap();
        let mut tempfile = tempfile.into_file();
        tempfile.write_all(&image).unwrap();
        let gm = single_region_mem_at(GUEST_PAGE_SIZE as u64 + 1, image.len() * 2);

        // Need to reset the cursor to read initrd properly.
        tempfile.seek(SeekFrom::Start(0)).unwrap();
        let res = InitrdConfig::from_file(&gm, tempfile);
        assert!(matches!(res, Err(InitrdError::Address)), "{:?}", res);
    }
}
