//! Moving bytes between the data channel and the disk.
//!
//! The scaffolding of the RPCs that move bytes -- the background task and the
//! `Progress` stream -- is provided by the SDK through `progress_stream`. What
//! remains here is the only part that belongs to this plugin: pumping bytes
//! between the socket and a file.

use std::path::Path;

use sb_plugin_sdk::tonic::Status;
use sb_plugin_sdk::{ProgressEmitter, connect_data};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

/// Size of the chunks moved at a time.
///
/// Deliberately smaller than the SDK's progress milestone: a larger chunk would
/// skip whole milestones and progress would jump instead of flowing.
pub const CHUNK: usize = 64 * 1024;

/// The SDK's milestone, bound to this name so it can be compared with `CHUNK`.
#[cfg(test)]
use sb_plugin_sdk::progress::MILESTONE as MIB;

/// Connects to the data channel the core created.
///
/// # Errors
/// [`Status::unavailable`] if the socket does not exist or refuses the
/// connection.
pub async fn connect(socket: &str) -> Result<UnixStream, Status> {
    connect_data(Path::new(socket)).await.map_err(|e| {
        Status::unavailable(format!("could not open the data channel `{socket}`: {e}"))
    })
}

/// Reads the data channel until EOF and writes it into `dest`.
///
/// Creates the intermediate directories: a key such as
/// `production/2026/08/x.age` names a hierarchy that need not exist yet.
///
/// # Errors
/// [`Status::unavailable`] if the channel fails, [`Status::internal`] if the
/// file cannot be created or written.
pub async fn channel_to_file(
    socket: &str,
    dest: &Path,
    progress: &mut ProgressEmitter,
) -> Result<(), Status> {
    // Connect first: if the channel is not there, there is no point in leaving
    // behind an empty file that would later look like a zero-byte artifact.
    let mut channel = connect(socket).await?;
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| Status::internal(format!("could not create {}: {e}", parent.display())))?;
    }
    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| Status::internal(format!("could not create {}: {e}", dest.display())))?;

    let mut buffer = vec![0_u8; CHUNK];
    loop {
        let read = channel
            .read(&mut buffer)
            .await
            .map_err(|e| Status::unavailable(format!("failed reading the data channel: {e}")))?;
        if read == 0 {
            break;
        }
        file.write_all(&buffer[..read])
            .await
            .map_err(|e| Status::internal(format!("failed writing {}: {e}", dest.display())))?;
        progress.advance(read).await;
    }
    // Without the explicit flush the file could end up short exactly when the
    // core already believes the transfer finished.
    file.flush()
        .await
        .map_err(|e| Status::internal(format!("failed closing {}: {e}", dest.display())))?;
    Ok(())
}

/// Writes `source` into the data channel and closes it.
///
/// # Errors
/// [`Status::unavailable`] if the channel fails, [`Status::internal`] if the
/// file cannot be read.
pub async fn file_to_channel(
    socket: &str,
    source: &Path,
    progress: &mut ProgressEmitter,
) -> Result<(), Status> {
    let mut file = tokio::fs::File::open(source)
        .await
        .map_err(|e| Status::internal(format!("could not open {}: {e}", source.display())))?;

    let mut channel = connect(socket).await?;
    let mut buffer = vec![0_u8; CHUNK];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|e| Status::internal(format!("failed reading {}: {e}", source.display())))?;
        if read == 0 {
            break;
        }
        write(&mut channel, &buffer[..read]).await?;
        progress.advance(read).await;
    }
    close(&mut channel).await
}

/// Writes a chunk into the data channel.
///
/// # Errors
/// [`Status::unavailable`] if the other end closed.
pub async fn write(channel: &mut UnixStream, chunk: &[u8]) -> Result<(), Status> {
    channel
        .write_all(chunk)
        .await
        .map_err(|e| Status::unavailable(format!("failed writing to the data channel: {e}")))
}

/// Closes the write side of the channel.
///
/// **This is what signals end of stream to the core.** Without this close the
/// core would wait for bytes that are never coming.
///
/// # Errors
/// [`Status::unavailable`] if the close fails.
pub async fn close(channel: &mut UnixStream) -> Result<(), Status> {
    channel
        .shutdown()
        .await
        .map_err(|e| Status::unavailable(format!("failed closing the data channel: {e}")))
}

/// `usize` to `u64` without an `as` that clippy would have to forgive. Only the
/// check below uses it: the byte count is kept by the SDK.
#[cfg(test)]
fn as_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chunk_fits_comfortably_within_a_milestone() {
        // If a chunk were larger than a mebibyte, whole milestones would be
        // skipped and progress would jump instead of flowing.
        assert!(as_u64(CHUNK) < MIB);
    }

    #[tokio::test]
    async fn connecting_to_a_nonexistent_socket_yields_unavailable() {
        let e = connect("/tmp/does-not-exist-sb-plugin-mock.sock")
            .await
            .unwrap_err();
        assert_eq!(e.code(), sb_plugin_sdk::tonic::Code::Unavailable);
    }
}
