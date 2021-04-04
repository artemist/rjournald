use super::util::{bytes_availaible, setsockopt_int};
use anyhow::{anyhow, Context};
use async_io::Async;
use libc::{gid_t, pid_t, uid_t, SOL_SOCKET, SO_PASSCRED};
use std::os::unix::{
    net::{AncillaryData, SocketAncillary, UnixDatagram},
    prelude::AsRawFd,
};
use std::{
    borrow::Cow, cmp::max, collections::BTreeMap, io::IoSliceMut, os::unix::prelude::FromRawFd,
    path::Path, sync::Arc,
};
use tokio::{fs::File, io::AsyncReadExt, sync::mpsc::Sender, task::spawn_blocking};

type Entry = BTreeMap<Cow<'static, str>, Box<[u8]>>;

pub async fn listen_journald(
    socket_location: Box<Path>,
    submission: Sender<()>,
) -> anyhow::Result<()> {
    // We can't use Tokio for this as we need some special features
    let listener = Arc::new(
        Async::<UnixDatagram>::bind(socket_location).context("Failed to bind to journald path")?,
    );
    let fd = listener.get_ref().as_raw_fd();
    spawn_blocking(move || {
        // We know the fd is still around (and thus this is safe) because we have a reference to
        // listener
        unsafe { setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, 1) }
    })
    .await??;

    loop {
        listener.readable().await?;
        let message = read_message(listener.clone()).await;
    }
}

async fn read_message(listener: Arc<Async<UnixDatagram>>) -> anyhow::Result<Entry> {
    let blocking_fut = spawn_blocking(move || {
        // I have no idea what size this should be but 4096 sounds large enough
        let mut ancillary_buffer = [0u8].repeat(4096).into_boxed_slice();
        let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);

        // We know the fd is still around as we have a ref to the UnixDatagram, so this is safe
        let message_size = unsafe { bytes_availaible(listener.as_raw_fd())? };
        let mut buf = [0u8].repeat(max(16384, message_size));

        // Open a new scope here so our annoying wrappers get dropped
        let (bytes_read, message_truncated) = {
            let mut bufs = [IoSliceMut::new(&mut buf)];
            // We're already in a blocking thread and we know a message is avaiable
            listener
                .get_ref()
                .recv_vectored_with_ancillary(&mut bufs, &mut ancillary)?
        };

        buf.truncate(bytes_read);

        if message_truncated {
            return Err(anyhow!(
                "Message truncated, maybe the kernel was lying about message size"
            ));
        }

        Ok((ancillary_buffer, buf))
    });

    let (mut ancillary_buffer, mut buf) = blocking_fut.await??;

    // We can't pass the original ancillary object out as we would have a dangling reference
    let ancillary = SocketAncillary::new(&mut ancillary_buffer);

    // Everything after this is pretty simple and async so we can do it on the main thread
    let mut credentials = Vec::new();
    let mut fds = Vec::new();
    for maybe_data in ancillary.messages() {
        if let Ok(data) = maybe_data {
            match data {
                AncillaryData::ScmRights(scm_rights) => fds.extend(scm_rights),
                AncillaryData::ScmCredentials(scm_credentials) => {
                    credentials.extend(scm_credentials)
                }
            }
        }
    }

    if credentials.len() != 1 {
        return Err(anyhow!("No credentials provided in message"));
    }

    if fds.len() > 1 {
        return Err(anyhow!(
            "Got more than one file descriptor, unsure what to do"
        ));
    } else if fds.len() == 1 {
        // We should read the message from a memfd. The kernel just sent us this fd so no one
        // else is using it
        let mut file = unsafe { File::from_raw_fd(fds[0]) };
        // Let's drop fds here to make sure we don't accidentally use the fd again
        drop(fds);

        buf.clear();
        file.read_to_end(&mut buf).await?;
    }
    // If we didn't get any fds just use what we received with recv

    let cred = &credentials[0];
    parse_message(&buf, cred.get_pid(), cred.get_uid(), cred.get_gid())
}

fn parse_message(message: &[u8], pid: pid_t, uid: uid_t, gid: gid_t) -> anyhow::Result<Entry> {
    let entry = Entry::new();

    let field_name = Cow::Borrowed("");
    let last_idx = 0usize;
    for (idx, b) in message.iter().enumerate() {
        if b == &b'=' && &field_name == "" {}
    }

    // If a process exits before we start grabbing info from /proc we could end up without any
    // information or with information for a different process. There doesn't seem to be a clean
    // way around this

    todo!("Finish parsing message")
}
