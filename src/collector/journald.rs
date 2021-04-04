use super::util::bytes_availaible;
use anyhow::{anyhow, Context};
use async_io::Async;
use std::os::unix::net::{AncillaryData, SocketAncillary, UnixDatagram};
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

    loop {
        listener.readable().await?;
        let message = read_message(listener.clone()).await;
    }
    unimplemented!("Add journald socket listener")
}

async fn read_message(listener: Arc<Async<UnixDatagram>>) -> anyhow::Result<Entry> {
    spawn_blocking(|| {
        let bytes_read: usize;
        let truncated;
        // I have no idea what size this should be but 4096 sounds large enough
        let mut ancillary_buffer = [0u8; 4096];
        let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
        let message_size = bytes_availaible(&*listener)?;
        let mut buf = [0u8].repeat(max(16384, message_size));

        // Open a new scope here so our annoying wrappers get dropped
        {
            let mut bufs = [IoSliceMut::new(&mut buf)];
            // We're already in a blocking thread and we know a message is avaiable
            let (bytes_read, truncated) = listener
                .get_ref()
                .recv_vectored_with_ancillary(&mut bufs, &mut ancillary)?;
        }

        if truncated {
            return Err(anyhow!(
                "Message truncated, maybe the kernel was lying about message size"
            ));
        }

        Ok(())
    })
    .await?;

    // Everything after this is pretty simple and async so we can do it on the main thread
    let credentials = Vec::new();
    let fds = Vec::new();
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
    todo!()
}

fn parse_message(mesage: Box<[u8]>) -> anyhow::Result<()> {
    todo!("Parse message")
}
