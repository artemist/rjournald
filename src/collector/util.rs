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
        Cow::Borrowed("_PID"),
        pid.to_string().into_bytes().into_boxed_slice(),
    );
    entry.insert(
        Cow::Borrowed("_UID"),
        uid.to_string().into_bytes().into_boxed_slice(),
    );
    entry.insert(
        Cow::Borrowed("_GID"),
        gid.to_string().into_bytes().into_boxed_slice(),
    );

    // If a process exits before we start grabbing info from /proc we could end up without any
    // information or with information for a different process. There doesn't seem to be a clean
    // way around this
    let base_path = PathBuf::from(&format!("/proc/{}", pid));
    if let Ok(exe) = tokio::fs::read_link(base_path.join("exe")).await {
        entry.insert(
            Cow::Borrowed("_EXE"),
            exe.into_os_string().into_vec().into_boxed_slice(),
        );
    }

    if let Ok(mut cmdline) = tokio::fs::read(base_path.join("cmdline")).await {
        // The contents of /proc/*/cmdline always ends with a null byte which we don't want to pass through
        cmdline.truncate(cmdline.len() - 1);
        // For some reason systemd uses spaces to separate. We get null bytes so switch this
        for b in &mut cmdline {
            if *b == 0 {
                *b = b' ';
            }
        }

        entry.insert(Cow::Borrowed("_CMDLINE"), cmdline.into_boxed_slice());
    }

    if let Ok(mut comm) = tokio::fs::read(base_path.join("comm")).await {
        // Remove the trailing \n
        comm.truncate(comm.len() - 1);
        entry.insert(Cow::Borrowed("_COMM"), comm.into_boxed_slice());
    }

    if let Ok(cgroup) = tokio::fs::read(base_path.join("cmdline")).await {
        if let Some(cgroup_path) = cgroup
            .rsplit(|b| *b == b'\n')
            .filter(|line| line.starts_with(b"0::"))
            .map(|line| &line[3..])
            .next()
        {
            let parsed = CgroupPath::from_slice(cgroup_path);
            if let Some(system_slice) = parsed.system_slice {
                entry.insert(Cow::Borrowed("_SYSTEMD_SLICE"), system_slice);
            }
            if let Some(system_unit) = parsed.system_unit {
                entry.insert(Cow::Borrowed("_SYSTEMD_UNIT"), system_unit);
            }
            if let Some(user_slice) = parsed.user_slice {
                entry.insert(Cow::Borrowed("_SYSTEMD_USER_SLICE"), user_slice);
            }
            if let Some(user_unit) = parsed.user_unit {
                entry.insert(Cow::Borrowed("_SYSTEMD_USER_UNIT"), user_unit);
            }
        }
    }

    if let Ok(status) = tokio::fs::read_to_string(base_path.join("status")).await {
        if let Some(cap) = status
            .lines()
            .filter_map(|line| line.split_once(":\t"))
            .filter(|parts| parts.0 == "CapEff")
            .map(|parts| parts.1.trim_start_matches('0'))
            .map(|trimmed| if trimmed.is_empty() { "0" } else { trimmed })
            .next()
        {
            entry.insert(
                Cow::Borrowed("_CAP_EFFECTIVE"),
                String::from(cap).into_bytes().into_boxed_slice(),
            );
        }
    }
}

#[derive(PartialEq, Debug, Default)]
pub struct CgroupPath {
    // We have to use slices here since there's no guaratee we get valid unicode
    pub system_slice: Option<Box<[u8]>>,
    pub system_unit: Option<Box<[u8]>>,
    pub user_slice: Option<Box<[u8]>>,
    pub user_unit: Option<Box<[u8]>>,
}

impl CgroupPath {
    pub fn from_slice(original: &[u8]) -> Self {
        let mut new = Self::default();
        for part in original.split(|b| *b == b'/') {
            if part == b"user.slice" {
                continue;
            }
            if part.ends_with(b".slice") && new.system_slice.is_none() {
                new.system_slice = Some(part.to_owned().into_boxed_slice());
            } else if part.ends_with(b".service") && new.system_unit.is_none() {
                new.system_unit = Some(part.to_owned().into_boxed_slice());
            } else if part.ends_with(b".slice") && new.system_unit.is_some() {
                new.user_slice = Some(part.to_owned().into_boxed_slice());
            } else if part.ends_with(b".service") && new.user_slice.is_some() {
                new.user_unit = Some(part.to_owned().into_boxed_slice());
            }
        }
        new
    }
}
