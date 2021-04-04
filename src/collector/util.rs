use anyhow::anyhow;
use nix::ioctl_read_bad;
use std::os::unix::io::AsRawFd;

// Systemd uses SIOCINQ but documentation (and the linux kernel) define this as synonymous as
// FIONREAD
ioctl_read_bad!(unsafe_bytes_availaible, libc::FIONREAD, libc::c_int);

pub fn bytes_availaible<T: AsRawFd>(file: &T) -> anyhow::Result<usize> {
    let fd = file.as_raw_fd();
    let mut avail: libc::c_int = -1;
    unsafe {
        // We know the fd is still availaible as we have a reference to the object for it
        unsafe_bytes_availaible(fd, &mut avail as *mut _)?;
    }
    if avail < 0 {
        Err(anyhow!("Invalid number of bytes"))
    } else {
        Ok(avail as usize)
    }
}
