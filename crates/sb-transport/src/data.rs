use std::path::{Path, PathBuf};

use tokio::net::UnixStream;

/// The channel the bytes of a backup flow through.
///
/// # Why it carries no TLS
///
/// That is deliberate. Both ends are processes of the same user on the same
/// machine, talking over a socket inside a `0700` directory. Anyone who can
/// read that socket already *is* that user and has direct access to the
/// credentials: encrypting here would not change the threat model and would
/// cost CPU on the hot path, which moves hundreds of gigabytes.
///
/// The control plane *is* encrypted and authenticated, because that is where
/// the secrets travel and because its volume is negligible.
///
/// The socket is removed when the channel is dropped.
pub struct DataChannel {
    /// Bound to the `std` API on purpose: `create` is synchronous and must be
    /// callable before a runtime exists. The listener is registered with the
    /// tokio reactor only inside `accept`.
    listener: std::os::unix::net::UnixListener,
    path: PathBuf,
}

impl DataChannel {
    /// Creates the channel inside `dir`, whose permissions are forced to `0700`.
    ///
    /// If a socket with that name already exists — a plugin that died without
    /// cleaning up — it is removed before binding, instead of failing with
    /// "address in use".
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created, its permissions
    /// cannot be set, or the socket cannot be bound.
    pub fn create(dir: &Path, name: &str) -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;

        let path = dir.join(format!("{name}.sock"));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        Ok(Self { listener, path })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Waits for the plugin to connect.
    ///
    /// **The caller must impose a deadline.** A plugin that never connects
    /// would leave the backup hanging indefinitely, and a backup hanging at
    /// three in the morning is worse than one that fails.
    ///
    /// # Errors
    /// Returns an error if the `accept` fails.
    pub async fn accept(&self) -> std::io::Result<UnixStream> {
        // The descriptor is duplicated so it can be registered with the reactor
        // without consuming the channel's own listener, which outlives the
        // `accept`.
        let dup = self.listener.try_clone()?;
        dup.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(dup)?;
        let (stream, _) = listener.accept().await?;
        Ok(stream)
    }
}

impl Drop for DataChannel {
    fn drop(&mut self) {
        // Best-effort: if it fails, the temporary directory takes the socket
        // with it.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The plugin's side: connects to the channel the core created.
///
/// # Errors
/// Returns an error if the socket does not exist or cannot be opened.
pub async fn connect_data(path: &Path) -> std::io::Result<UnixStream> {
    UnixStream::connect(path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn the_plugin_writes_and_the_core_reads() {
        // The direction of a backup: the source produces, the core consumes.
        let dir = tempfile::tempdir().unwrap();
        let channel = DataChannel::create(dir.path(), "dump").unwrap();
        let path = channel.path().to_path_buf();

        let plugin = tokio::spawn(async move {
            let mut s = connect_data(&path).await.unwrap();
            s.write_all(b"dump bytes").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut stream = channel.accept().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf, b"dump bytes");
        plugin.await.unwrap();
    }

    #[tokio::test]
    async fn the_core_writes_and_the_plugin_reads() {
        // The direction of a restore, and of the upload to the target.
        let dir = tempfile::tempdir().unwrap();
        let channel = DataChannel::create(dir.path(), "put").unwrap();
        let path = channel.path().to_path_buf();

        let plugin = tokio::spawn(async move {
            let mut s = connect_data(&path).await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let mut stream = channel.accept().await.unwrap();
        stream.write_all(b"encrypted artifact").await.unwrap();
        stream.shutdown().await.unwrap();

        assert_eq!(plugin.await.unwrap(), b"encrypted artifact");
    }

    #[tokio::test]
    async fn it_moves_bulk_data_without_corrupting_anything() {
        let dir = tempfile::tempdir().unwrap();
        let channel = DataChannel::create(dir.path(), "large").unwrap();
        let path = channel.path().to_path_buf();
        let expected: Vec<u8> = (0..8_u32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let copy = expected.clone();

        let plugin = tokio::spawn(async move {
            let mut s = connect_data(&path).await.unwrap();
            s.write_all(&copy).await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut stream = channel.accept().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf.len(), expected.len());
        assert_eq!(buf, expected);
        plugin.await.unwrap();
    }

    #[tokio::test]
    async fn a_zero_byte_stream_ends_cleanly() {
        // An empty database still produces a valid artifact.
        let dir = tempfile::tempdir().unwrap();
        let channel = DataChannel::create(dir.path(), "empty").unwrap();
        let path = channel.path().to_path_buf();

        let plugin = tokio::spawn(async move {
            let mut s = connect_data(&path).await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut stream = channel.accept().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();

        assert!(buf.is_empty());
        plugin.await.unwrap();
    }

    #[tokio::test]
    async fn the_writer_closing_shows_up_as_end_of_stream() {
        // This is the signal that tells the core the dump is over. Without it
        // the backup would wait forever.
        let dir = tempfile::tempdir().unwrap();
        let channel = DataChannel::create(dir.path(), "eof").unwrap();
        let path = channel.path().to_path_buf();

        let plugin = tokio::spawn(async move {
            let mut s = connect_data(&path).await.unwrap();
            s.write_all(b"something").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut stream = channel.accept().await.unwrap();
        let mut buf = [0_u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"something");
        // The next read must return 0: end of stream, not a block.
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
        plugin.await.unwrap();
    }

    #[tokio::test]
    async fn two_channels_in_the_same_directory_do_not_collide() {
        // A backup uses two at once: one from the source and one to the target.
        let dir = tempfile::tempdir().unwrap();
        let a = DataChannel::create(dir.path(), "dump").unwrap();
        let b = DataChannel::create(dir.path(), "put").unwrap();
        assert_ne!(a.path(), b.path());

        let path_a = a.path().to_path_buf();
        let path_b = b.path().to_path_buf();

        let t = tokio::spawn(async move {
            let mut sa = connect_data(&path_a).await.unwrap();
            sa.write_all(b"AAA").await.unwrap();
            sa.shutdown().await.unwrap();
            let mut sb = connect_data(&path_b).await.unwrap();
            sb.write_all(b"BBB").await.unwrap();
            sb.shutdown().await.unwrap();
        });

        let mut sa = a.accept().await.unwrap();
        let mut va = Vec::new();
        sa.read_to_end(&mut va).await.unwrap();

        let mut sb = b.accept().await.unwrap();
        let mut vb = Vec::new();
        sb.read_to_end(&mut vb).await.unwrap();

        assert_eq!(va, b"AAA");
        assert_eq!(vb, b"BBB");
        t.await.unwrap();
    }

    #[test]
    fn the_socket_directory_is_private() {
        // The data channel's only defence: nobody else can open it.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let channel = DataChannel::create(dir.path(), "perm").unwrap();
        let mode = std::fs::metadata(channel.path().parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "the directory must be reachable by its owner only"
        );
    }

    #[test]
    fn the_socket_is_removed_when_the_channel_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = {
            let channel = DataChannel::create(dir.path(), "ephemeral").unwrap();
            channel.path().to_path_buf()
        };
        assert!(!path.exists(), "the socket must not outlive the channel");
    }

    #[test]
    fn it_can_be_created_over_an_orphaned_socket() {
        // A plugin that died without cleaning up leaves the socket behind. The
        // next backup must work just the same, not fail with "address in use".
        let dir = tempfile::tempdir().unwrap();
        let first = DataChannel::create(dir.path(), "reuse").unwrap();
        let path = first.path().to_path_buf();
        std::mem::forget(first); // simulates a death without cleanup

        assert!(path.exists(), "the orphaned socket is still there");
        let second = DataChannel::create(dir.path(), "reuse").unwrap();
        assert_eq!(second.path(), path);
    }

    #[tokio::test]
    async fn connecting_to_a_channel_that_does_not_exist_fails() {
        assert!(
            connect_data(std::path::Path::new(
                "/tmp/does-not-exist-shieldbk-data.sock"
            ))
            .await
            .is_err()
        );
    }
}
