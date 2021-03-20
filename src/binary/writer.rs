use super::header::Header;
use memmap::MmapMut;
use nix::unistd::ftruncate;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::Arc;
use std::{os::unix::prelude::AsRawFd, sync::atomic::AtomicU64};

pub struct SharedWriterState {
    pub next_seqnum: AtomicU64,
    pub boot_id: [u8; 16],
    pub machine_id: [u8; 16],
    pub seqnum_id: [u8; 16],
}

struct BinaryWriter {
    shared_state: Arc<SharedWriterState>,
    backing_file: File,
    map: MmapMut,
}

impl BinaryWriter {
    const DEFAULT_FILE_SIZE: i64 = 256 * 1024 * 1024;

    /// Creates a new journal file at the specified location
    /// Will not overwrite an existing file
    pub fn create(
        shared_state: Arc<SharedWriterState>,
        basedir: &Path,
        basename: &Path,
    ) -> anyhow::Result<Self> {
        let full_filename = basedir.join(basename).with_extension("journal");
        let backing_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(full_filename)?;

        // This is safe as the file will not be dropped ujtil after this is run.
        ftruncate(backing_file.as_raw_fd(), Self::DEFAULT_FILE_SIZE)?;

        let map = unsafe { MmapMut::map_mut(&backing_file)? };

        Ok(Self {
            shared_state,
            backing_file,
            map,
        })
    }

    pub fn read_header(&self) -> anyhow::Result<Header> {
        Header::from_slice(&self.map)
    }

    pub fn write_header(&mut self, new_header: &Header) {}
}
