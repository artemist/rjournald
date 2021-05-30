use anyhow::anyhow;
use libc::{c_void, gid_t, pid_t, setsockopt, uid_t};
use nix::ioctl_read_bad;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{mem::size_of, os::unix::ffi::OsStringExt, os::unix::prelude::RawFd};

pub type Entry = BTreeMap<Cow<'static, str>, Box<[u8]>>;

// Systemd uses SIOCINQ but documentation (and the linux kernel) define this as synonymous as
// FIONREAD
ioctl_read_bad!(unsafe_bytes_availaible, libc::FIONREAD, libc::c_int);

/// Get the number of bytes available for a file descriptor. May be unsound if the file descriptor
/// does not exist
pub unsafe fn bytes_availaible(fd: RawFd) -> anyhow::Result<usize> {
    let mut avail: libc::c_int = -1;
    unsafe_bytes_availaible(fd, &mut avail as *mut _)?;
    if avail < 0 {
        Err(anyhow!("Invalid number of bytes"))
    } else {
        Ok(avail as usize)
    }
}

/// Equivalant of libc::setsockopt but lets you use an i32 directly.
/// May be unsound if you set options that confuse your socket object (such as making it
/// nonblocking) or if you run setsockopt on a socket that does not exist
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

/// Retrieve process data common to all transports given common data
/// Most of this is retrieved from files in /proc. This function never fails
/// as it's expected that a process may exit before we can read this data.
/// You can test this case by running in a terminal
/// `systemd-cat echo 'asdf'`
/// then viewing the raw journal output with
/// `journalctl -o export -xeg asdf`
/// This may log at certain log levels but should not be considered weird
pub async fn retrieve_process_data(entry: &mut Entry, pid: pid_t, uid: uid_t, gid: gid_t) {
    // UID could be the EUID, SUID, or the RUID. I'm not sure what journald does but just doing
    // what we're told sounds like a good start
    entry.insert(
        Cow::Borrowed(&"_PID"),
        pid.to_string().into_bytes().into_boxed_slice(),
    );
    entry.insert(
        Cow::Borrowed(&"_UID"),
        uid.to_string().into_bytes().into_boxed_slice(),
    );
    entry.insert(
        Cow::Borrowed(&"_GID"),
        gid.to_string().into_bytes().into_boxed_slice(),
    );

    // If a process exits before we start grabbing info from /proc we could end up without any
    // information or with information for a different process. There doesn't seem to be a clean
    // way around this
    let base_path = PathBuf::from(&format!("/proc/{}", pid));
    if let Ok(exe) = tokio::fs::read_link(base_path.join(Path::new("exe"))).await {
        entry.insert(
            Cow::Borrowed(&"_EXE"),
            exe.into_os_string().into_vec().into_boxed_slice(),
        );
    }

    if let Ok(mut cmdline) = tokio::fs::read(base_path.join(Path::new("cmdline"))).await {
        // The contents of /proc/*/cmdline always ends with a null byte which we don't want to pass through
        cmdline.truncate(cmdline.len() - 1);
        // For some reason systemd uses spaces to separate. We get null bytes so switch this
        for b in cmdline.iter_mut() {
            if *b == 0 {
                *b = b' ';
            }
        }

        entry.insert(Cow::Borrowed(&"_CMDLINE"), cmdline.into_boxed_slice());
    }

    if let Ok(mut comm) = tokio::fs::read(base_path.join(Path::new("comm"))).await {
        // Remove the trailing \n
        comm.truncate(comm.len() - 1);
        entry.insert(Cow::Borrowed(&"_COMM"), comm.into_boxed_slice());
    }

    if let Ok(status) = tokio::fs::read_to_string(base_path.join("status")).await {
        if let Some(cap) = status
            .lines()
            .filter_map(|line| line.split_once(":\t"))
            .filter(|parts| parts.0 == "CapEff")
            .map(|parts| parts.1.trim_start_matches('0'))
            .map(|trimmed| if trimmed == "" { "0" } else { trimmed })
            .next()
        {
            entry.insert(
                Cow::Borrowed(&"_CAP_EFFECTIVE"),
                String::from(cap).into_bytes().into_boxed_slice(),
            );
        }
    }
}
