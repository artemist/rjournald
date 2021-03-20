// Binary format described in https://systemd.io/JOURNAL_FILE_FORMAT/

use crate::util::ConstSliceExt;
use anyhow::{anyhow, Context};
use bitflags::bitflags;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Copy, Clone)]
pub struct Header {
    // Don't store the signature
    pub compatible_flags: CompatibleFlags,
    pub incompatible_flags: IncompatibleFlags,
    pub state: State,
    // 7 bytes reserved here, not needed in memory
    pub file_id: [u8; 16],
    pub machine_id: [u8; 16],
    pub boot_id: [u8; 16],
    pub seqnum_id: [u8; 16],
    pub header_size: u64,
    pub arena_size: u64,
    pub data_hash_table_offset: u64,
    pub data_hash_table_size: u64,
    pub field_hash_table_offset: u64,
    pub field_hash_table_size: u64,
    pub tail_object_offset: u64,
    pub n_objects: u64,
    pub n_entries: u64,
    pub tail_entry_seqnum: u64,
    pub head_entry_seqnum: u64,
    pub entry_array_offset: u64,
    pub head_entry_realtime: SystemTime,
    pub tail_entry_realtime: SystemTime,
    pub tail_entry_monotonic: Duration,
    // Fields added in 187
    pub n_data: Option<u64>,
    pub n_fields: Option<u64>,
    // Fields added in 189
    pub n_tags: Option<u64>,
    pub n_entry_arrays: Option<u64>,
    // Fields added in 246
    pub data_hash_chain_depth: Option<u64>,
    pub field_hash_chain_depth: Option<u64>,
}

bitflags! {
pub struct IncompatibleFlags: u32 {
    const COMPRESSED_XZ = 1;
    const COMPRESSED_LZ4 = 2;
    const KEYED_HASH = 4;
    const COMPRESSED_ZSTD = 8;
}
}

bitflags! {
pub struct CompatibleFlags: u32 {
    const SEALED = 1;
}
}

#[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq)]
pub enum State {
    Offline = 0,
    Online = 1,
    Archived = 2,
}

impl Header {
    pub fn from_slice(source: &[u8]) -> anyhow::Result<Self> {
        if &source[0..8] != b"LPKSHHRH" {
            return Err(anyhow!("File does not contain magic number"));
        }
        if source.len() < 100 {
            return Err(anyhow!("Header too short"));
        }

        let header_size = u64::from_le_bytes(*source.const_slice(88));
        if header_size != 208 && header_size != 224 && header_size != 240 && header_size != 256 {
            return Err(anyhow!("Unknown header size {}", header_size));
        }
        if header_size > source.len() as u64 {
            return Err(anyhow!(
                "File reports header of size {} bytes but we were given {} bytes",
                header_size,
                source.len()
            ));
        }

        let compatible_flags =
            CompatibleFlags::from_bits_truncate(u32::from_le_bytes(*source.const_slice(8)));
        let incompatible_flags =
            IncompatibleFlags::from_bits(u32::from_le_bytes(*source.const_slice(12)))
                .ok_or_else(|| anyhow!("Unknown flags in header"))?;
        let state = State::from_u8(source[16]).context(anyhow!("Invalid state in header"))?;
        let file_id = *source.const_slice(24);
        let machine_id = *source.const_slice(40);
        let boot_id = *source.const_slice(56);
        let seqnum_id = *source.const_slice(72);
        // We got header_size earlier
        let arena_size = u64::from_le_bytes(*source.const_slice(96));
        let data_hash_table_offset = u64::from_le_bytes(*source.const_slice(104));
        let data_hash_table_size = u64::from_le_bytes(*source.const_slice(112));
        let field_hash_table_offset = u64::from_le_bytes(*source.const_slice(120));
        let field_hash_table_size = u64::from_le_bytes(*source.const_slice(128));
        let tail_object_offset = u64::from_le_bytes(*source.const_slice(136));
        let n_objects = u64::from_le_bytes(*source.const_slice(144));
        let n_entries = u64::from_le_bytes(*source.const_slice(152));
        let tail_entry_seqnum = u64::from_le_bytes(*source.const_slice(160));
        let head_entry_seqnum = u64::from_le_bytes(*source.const_slice(168));
        let entry_array_offset = u64::from_le_bytes(*source.const_slice(176));
        let head_entry_realtime =
            UNIX_EPOCH + Duration::from_micros(u64::from_le_bytes(*source.const_slice(184)));
        let tail_entry_realtime =
            UNIX_EPOCH + Duration::from_micros(u64::from_le_bytes(*source.const_slice(192)));
        let tail_entry_monotonic =
            Duration::from_micros(u64::from_le_bytes(*source.const_slice(200)));

        let (n_data, n_fields) = if header_size >= 224 {
            (
                Some(u64::from_le_bytes(*source.const_slice(208))),
                Some(u64::from_le_bytes(*source.const_slice(216))),
            )
        } else {
            (None, None)
        };
        let (n_tags, n_entry_arrays) = if header_size >= 240 {
            (
                Some(u64::from_le_bytes(*source.const_slice(224))),
                Some(u64::from_le_bytes(*source.const_slice(232))),
            )
        } else {
            (None, None)
        };
        let (data_hash_chain_depth, field_hash_chain_depth) = if header_size >= 256 {
            (
                Some(u64::from_le_bytes(*source.const_slice(240))),
                Some(u64::from_le_bytes(*source.const_slice(248))),
            )
        } else {
            (None, None)
        };

        Ok(Self {
            compatible_flags,
            incompatible_flags,
            state,
            file_id,
            machine_id,
            boot_id,
            seqnum_id,
            header_size,
            arena_size,
            data_hash_table_offset,
            data_hash_table_size,
            field_hash_table_offset,
            field_hash_table_size,
            tail_object_offset,
            n_objects,
            n_entries,
            tail_entry_seqnum,
            head_entry_seqnum,
            entry_array_offset,
            head_entry_realtime,
            tail_entry_realtime,
            tail_entry_monotonic,
            n_data,
            n_fields,
            n_tags,
            n_entry_arrays,
            data_hash_chain_depth,
            field_hash_chain_depth,
        })
    }

    /// Write back to a slice
    pub fn write_slice(&self, out: &mut [u8]) -> anyhow::Result<()> {
        if self.header_size != 208
            && self.header_size != 224
            && self.header_size != 240
            && self.header_size != 256
        {
            return Err(anyhow!("Unknown header size {}", self.header_size));
        }
        if (out.len() as u64) < self.header_size {
            return Err(anyhow!("Output too short"));
        }

        unimplemented!("TODO or replace this entire function")
    }
}
