//! The data channel: opening it, writing to it and closing it.
//!
//! The artifact's bytes do not travel over gRPC but over a Unix socket created
//! by the core. The three operations needed to use it live here because the
//! upload and the download share them, and because one of them -- [`close`] --
//! is easy to forget and its absence goes unnoticed until a `restore` hangs.

use std::path::Path;

use sb_plugin_sdk::connect_data;
use sb_plugin_sdk::tonic::Status;
use tokio::io::AsyncWriteExt as _;
use tokio::net::UnixStream;

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
/// core would keep waiting for bytes that are never coming and the `restore`
/// would hang until its deadline expired.
///
/// # Errors
/// [`Status::unavailable`] if the close fails.
pub async fn close(channel: &mut UnixStream) -> Result<(), Status> {
    channel
        .shutdown()
        .await
        .map_err(|e| Status::unavailable(format!("failed closing the data channel: {e}")))
}

/// A failure reading the data channel belongs to the other end, not to R2.
#[must_use]
pub fn read_failure(e: &std::io::Error) -> Status {
    Status::unavailable(format!("failed reading the data channel: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connecting_to_a_nonexistent_socket_yields_unavailable() {
        let e = connect("/tmp/does-not-exist-sb-plugin-r2.sock")
            .await
            .unwrap_err();
        assert_eq!(e.code(), sb_plugin_sdk::tonic::Code::Unavailable);
    }

    #[test]
    fn a_channel_failure_is_not_mistaken_for_an_r2_one() {
        // The core uses this code to decide whether the culprit is the storage
        // target or the other end of the socket.
        let e = read_failure(&std::io::Error::other("broken"));
        assert_eq!(e.code(), sb_plugin_sdk::tonic::Code::Unavailable);
    }
}
