use anyhow::anyhow;
use libc::{c_void, setsockopt};
use nix::ioctl_read_bad;
use std::{mem::size_of, os::unix::prelude::RawFd};

// Systemd uses SIOCINQ but documentation (and the linux kernel) define this as synonymous as
// FIONREAD
ioctl_read_bad!(unsafe_bytes_availaible, libc::FIONREAD, libc::c_int);

pub unsafe fn bytes_availaible(fd: RawFd) -> anyhow::Result<usize> {
    let mut avail: libc::c_int = -1;
    unsafe_bytes_availaible(fd, &mut avail as *mut _)?;
    if avail < 0 {
        Err(anyhow!("Invalid number of bytes"))
    } else {
        Ok(avail as usize)
    }
}

/// Can cause issues if you set options that confuse your socket object or if the socket you refer
/// to with your socket argument no longer exists
pub unsafe fn setsockopt_int(
    socket: RawFd,
    level: i32,
    name: i32,
    value: i32,
) -> anyhow::Result<()> {
    if setsockopt(
        socket,
        level,
        name,
        &value as *const _ as *const c_void,
        size_of::<i32>() as u32,
    ) == 0
    {
        Ok(())
    } else {
        Err(anyhow!("Unable to setsockopt"))
    }
}
