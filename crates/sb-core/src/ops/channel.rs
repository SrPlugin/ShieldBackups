//! The mechanics of a transfer with a plugin, in a single place.
//!
//! The three operations —backup, restore and verify— do exactly the same thing
//! four times: create a socket, ask over gRPC for the plugin to connect to it,
//! wait for that connection with a deadline, drain the `Progress` stream and
//! translate the five different ways in which that can break. The only things
//! that change between them are **which RPC** is called and **in what order**.
//!
//! That split is the reason this module exists and that it is not `ops/mod.rs`:
//! `ops/mod.rs` is the map of which operations exist; if it also held the
//! deadlines, the progress tracking and the error translation, the map would be
//! buried under the machinery. Here is the machinery, with a name of its own, and
//! `backup.rs`, `restore.rs` and `verify.rs` are left being what they really
//! are: three different call orders over the same pieces.
//!
//! [`BackupError`] lives here for the same reason: its variants describe the
//! failures of this machinery —the plugin did not answer, it did not connect, it
//! broke halfway— and two of them quote this module's deadlines in their
//! message. It keeps its name because the three operations share it and renaming
//! it to `OperationError` would say nothing more than it already says.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sb_crypto::PipelineError;
use sb_proto::source_client::SourceClient;
use sb_proto::storage_client::StorageClient;
use sb_proto::{DumpRequest, GetRequest, Progress, PutRequest, RestoreRequest};
use sb_transport::DataChannel;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;
use tonic::Streaming;

use crate::model::ManifestError;
use crate::plugin::client::message_from;
use crate::plugin::{PluginClient, PluginError};

/// Deadline for the RPC that opens a transfer to return its headers.
///
/// `Dump`, `Put`, `Get` and `Restore` may take hours to **finish**, but not to
/// answer: the only thing they do before responding is validate the request and
/// spawn their task. A plugin that does not even get that far is not going to
/// move a single byte.
pub(crate) const OPEN_DEADLINE: Duration = Duration::from_secs(60);

/// Deadline for the plugin to connect to the data channel it was offered.
///
/// Without this deadline, a plugin that accepts the RPC and then does not open
/// the socket would leave the `accept` waiting forever: the operation would not
/// fail, it would hang, which is worse because nobody finds out until a restore
/// is needed.
pub(crate) const CONNECT_DEADLINE: Duration = Duration::from_secs(30);

/// Cap on what is accepted as a "small" blob.
///
/// [`download_blob`] loads what it reads into memory, so it needs a ceiling: a
/// broken —or hostile— destination that served a hundred gigabytes under the
/// manifest's key would take the process down. A real manifest is around a
/// kilobyte; a mebibyte leaves plenty of room while still being a ceiling.
const BLOB_LIMIT: u64 = 1024 * 1024;

pub(crate) const OP_DUMP: &str = "dump";
pub(crate) const OP_PUT: &str = "put";
pub(crate) const OP_GET: &str = "get";
pub(crate) const OP_RESTORE: &str = "restore";

/// Everything that can go wrong in an operation with plugins.
///
/// Every variant names the plugin: an operation has two of them alive at once
/// and "the transfer failed" forces you to guess which of the two it was.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// The chosen plugin cannot play the role it is asked for, or the control
    /// channel failed.
    #[error(transparent)]
    Plugin(#[from] PluginError),
    /// The socket the bytes were going to flow through could not be created.
    #[error("could not create the data channel for the plugin \"{plugin}\": {source}")]
    Channel {
        plugin: String,
        source: std::io::Error,
    },
    /// The plugin answered the RPC with an error, before moving anything.
    #[error("the plugin \"{plugin}\" rejected {operation}: {message}")]
    Rpc {
        plugin: String,
        operation: String,
        message: String,
    },
    /// The RPC did not even return headers.
    #[error("the plugin \"{plugin}\" did not answer {operation} in {} s", OPEN_DEADLINE.as_secs())]
    NoResponse { plugin: String, operation: String },
    /// The plugin accepted the RPC but never opened the socket. It is told apart
    /// from `NoResponse` because here the plugin is alive and answering: what
    /// fails is its side of the data channel.
    #[error(
        "the plugin \"{plugin}\" accepted {operation} but did not connect to the data channel in {} s",
        CONNECT_DEADLINE.as_secs()
    )]
    NoConnection { plugin: String, operation: String },
    /// The transfer started and broke halfway. The error arrives through the
    /// `Progress` stream, which is the only path left once the headers have been
    /// sent.
    #[error("the plugin \"{plugin}\" failed during {operation}: {message}")]
    Transfer {
        plugin: String,
        operation: String,
        message: String,
    },
    /// The task tracking the progress crashed. It is not the plugin's fault, but
    /// the operation cannot be taken as good either.
    #[error("lost track of {operation} of the plugin \"{plugin}\": {source}")]
    Tracking {
        plugin: String,
        operation: String,
        source: tokio::task::JoinError,
    },
    /// Compressing, encrypting, decrypting or hashing failed.
    #[error("the encryption pipeline failed: {0}")]
    Pipeline(#[from] PipelineError),
    /// Writing to or reading from the data channel failed on the core's side.
    #[error("I/O error on the data channel with \"{plugin}\": {source}")]
    Io {
        plugin: String,
        source: std::io::Error,
    },
    /// The manifest could not be serialized or could not be parsed.
    #[error("could not read the manifest: {0}")]
    Manifest(#[from] ManifestError),
    /// The manifest describing an artifact is missing or could not be fetched.
    ///
    /// It is kept apart from `Rpc` because the remedy is different and the
    /// message has to say **which key was looked up**: without a manifest there
    /// is nothing to compare against, and whoever reads the error needs to know
    /// whether the manifest was lost or whether the artifact was never called
    /// that.
    #[error(
        "could not read the manifest \"{key}\" from the storage \"{plugin}\": {reason}. \
         Without it there is nothing to check the artifact against"
    )]
    NoManifest {
        plugin: String,
        key: String,
        reason: String,
    },
    /// The blob that was supposed to be small was not.
    #[error(
        "\"{key}\" takes more than {} bytes: it does not look like a manifest",
        BLOB_LIMIT
    )]
    BlobTooLarge { key: String },
}

/// Creates the data channel inside `plugin`'s runtime directory.
///
/// The name carries a counter because the same pair of plugins does several
/// operations in a row and two live channels with the same name would stomp on
/// each other's socket.
pub(crate) fn create_channel(plugin: &PluginClient) -> Result<DataChannel, BackupError> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name = format!("data-{}", NEXT.fetch_add(1, Ordering::Relaxed));
    DataChannel::create(plugin.process().runtime_dir(), &name).map_err(|source| {
        BackupError::Channel {
            plugin: plugin.name().to_string(),
            source,
        }
    })
}

/// Asks the storage to start **reading** from the channel.
pub(crate) async fn start_put(
    storage: &PluginClient,
    key: &str,
    channel: &DataChannel,
) -> Result<JoinHandle<Result<u64, BackupError>>, BackupError> {
    let mut grpc = StorageClient::new(storage.channel());
    let request = PutRequest {
        key: key.to_string(),
        data_socket: path_of(channel),
    };
    let stream = open(storage.name(), OP_PUT, grpc.put(request)).await?;
    Ok(track_progress(storage.name().to_string(), OP_PUT, stream))
}

/// Asks the storage to start **writing** into the channel.
pub(crate) async fn start_get(
    storage: &PluginClient,
    key: &str,
    channel: &DataChannel,
) -> Result<JoinHandle<Result<u64, BackupError>>, BackupError> {
    let mut grpc = StorageClient::new(storage.channel());
    let request = GetRequest {
        key: key.to_string(),
        data_socket: path_of(channel),
    };
    let stream = open(storage.name(), OP_GET, grpc.get(request)).await?;
    Ok(track_progress(storage.name().to_string(), OP_GET, stream))
}

/// Asks the source to start **writing** into the channel.
pub(crate) async fn start_dump(
    source: &PluginClient,
    channel: &DataChannel,
) -> Result<JoinHandle<Result<u64, BackupError>>, BackupError> {
    let mut grpc = SourceClient::new(source.channel());
    let request = DumpRequest {
        data_socket: path_of(channel),
    };
    let stream = open(source.name(), OP_DUMP, grpc.dump(request)).await?;
    Ok(track_progress(source.name().to_string(), OP_DUMP, stream))
}

/// Asks the source to start **reading** from the channel and to swallow whatever
/// comes out.
pub(crate) async fn start_restore(
    source: &PluginClient,
    channel: &DataChannel,
) -> Result<JoinHandle<Result<u64, BackupError>>, BackupError> {
    let mut grpc = SourceClient::new(source.channel());
    let request = RestoreRequest {
        data_socket: path_of(channel),
    };
    let stream = open(source.name(), OP_RESTORE, grpc.restore(request)).await?;
    Ok(track_progress(
        source.name().to_string(),
        OP_RESTORE,
        stream,
    ))
}

fn path_of(channel: &DataChannel) -> String {
    channel.path().to_string_lossy().into_owned()
}

/// The deadline and the error translation of a transfer RPC, in a single place:
/// forgetting the `timeout` once is enough for a mute plugin to leave the
/// operation waiting.
async fn open<F>(plugin: &str, operation: &str, call: F) -> Result<Streaming<Progress>, BackupError>
where
    F: Future<Output = Result<tonic::Response<Streaming<Progress>>, tonic::Status>>,
{
    match tokio::time::timeout(OPEN_DEADLINE, call).await {
        Ok(Ok(response)) => Ok(response.into_inner()),
        Ok(Err(status)) => Err(BackupError::Rpc {
            plugin: plugin.to_string(),
            operation: operation.to_string(),
            message: message_from(&status),
        }),
        Err(_) => Err(BackupError::NoResponse {
            plugin: plugin.to_string(),
            operation: operation.to_string(),
        }),
    }
}

/// Waits for the plugin to open its side of the channel, with a deadline.
///
/// `DataChannel::accept` deliberately imposes none —its documentation says so—
/// and this is the place where one is imposed.
pub(crate) async fn accept(
    channel: &DataChannel,
    plugin: &str,
    operation: &str,
) -> Result<UnixStream, BackupError> {
    match tokio::time::timeout(CONNECT_DEADLINE, channel.accept()).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(source)) => Err(BackupError::Io {
            plugin: plugin.to_string(),
            source,
        }),
        Err(_) => Err(BackupError::NoConnection {
            plugin: plugin.to_string(),
            operation: operation.to_string(),
        }),
    }
}

/// Drains the `Progress` stream in a background task and re-emits it as traces.
///
/// It has to be drained no matter what: the plugin SDK applies backpressure on
/// that stream, so a core that does not read it ends up throttling the plugin
/// that is moving the bytes. And it is also the only path by which an error can
/// arrive once the RPC headers have been sent.
///
/// It returns the bytes the plugin said it moved, which are useful to contrast
/// with what the pipeline counted.
fn track_progress(
    plugin: String,
    operation: &'static str,
    mut stream: Streaming<Progress>,
) -> JoinHandle<Result<u64, BackupError>> {
    tokio::spawn(async move {
        let mut last = 0;
        loop {
            match stream.message().await {
                Ok(Some(progress)) => {
                    last = progress.bytes;
                    tracing::debug!(
                        plugin = %plugin,
                        operation,
                        bytes = progress.bytes,
                        message = %progress.message,
                        "progress"
                    );
                }
                Ok(None) => return Ok(last),
                Err(status) => {
                    return Err(BackupError::Transfer {
                        plugin,
                        operation: operation.to_string(),
                        message: message_from(&status),
                    });
                }
            }
        }
    })
}

/// Waits for the progress task to finish and translates its two ways of
/// failing: the plugin's and the task's own.
pub(crate) async fn wait_for_progress(
    task: JoinHandle<Result<u64, BackupError>>,
    plugin: &str,
    operation: &str,
) -> Result<u64, BackupError> {
    match task.await {
        Ok(result) => result,
        Err(source) => Err(BackupError::Tracking {
            plugin: plugin.to_string(),
            operation: operation.to_string(),
            source,
        }),
    }
}

/// Uploads a small piece of content that is already in memory.
///
/// The manifest uses it. It walks exactly the same steps as the artifact
/// —channel, `Put`, `accept` with a deadline, progress— because a second upload
/// path is a second behaviour to maintain.
pub(crate) async fn upload_blob(
    storage: &PluginClient,
    key: &str,
    contents: &[u8],
) -> Result<(), BackupError> {
    let channel = create_channel(storage)?;
    let upload = start_put(storage, key, &channel).await?;
    let mut sink = accept(&channel, storage.name(), OP_PUT).await?;

    let io_error = |source| BackupError::Io {
        plugin: storage.name().to_string(),
        source,
    };
    sink.write_all(contents).await.map_err(io_error)?;
    // Closing the write side is what the storage sees as end of stream. Without
    // it, it would wait for bytes that are never going to arrive.
    sink.shutdown().await.map_err(io_error)?;

    wait_for_progress(upload, storage.name(), OP_PUT).await?;
    Ok(())
}

/// Downloads into memory a blob that is known to be small.
///
/// The reverse of [`upload_blob`], and **only** for what really is small: the
/// artifact never goes through here, it is read as a stream. Hence the
/// [`BLOB_LIMIT`], which turns "I trust this key to be a manifest" into an error
/// with a name.
pub(crate) async fn download_blob(
    storage: &PluginClient,
    key: &str,
) -> Result<Vec<u8>, BackupError> {
    let channel = create_channel(storage)?;
    let download = start_get(storage, key, &channel).await?;
    let stream = accept(&channel, storage.name(), OP_GET).await?;

    // `take` of one byte more than the cap: if it fills up, there was more.
    let mut contents = Vec::new();
    let read = stream
        .take(BLOB_LIMIT + 1)
        .read_to_end(&mut contents)
        .await
        .map_err(|source| BackupError::Io {
            plugin: storage.name().to_string(),
            source,
        })?;
    if u64::try_from(read).unwrap_or(u64::MAX) > BLOB_LIMIT {
        return Err(BackupError::BlobTooLarge {
            key: key.to_string(),
        });
    }

    wait_for_progress(download, storage.name(), OP_GET).await?;
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The happy path lives in `tests/backup_mock.rs` and in
    /// `tests/full_cycle.rs`, which need two real processes. Here we only check
    /// what an integration test cannot trigger at will: that the errors say what
    /// has to be said.
    #[test]
    fn the_connection_error_names_the_plugin_the_operation_and_the_deadline() {
        // Without the deadline in the message, whoever reads it does not know
        // whether it waited a second or half an hour, and therefore does not know
        // whether the problem is slowness or a plugin that was never going to
        // connect.
        let text = BackupError::NoConnection {
            plugin: "r2".into(),
            operation: OP_PUT.into(),
        }
        .to_string();
        assert!(text.contains("r2"));
        assert!(text.contains("put"));
        assert!(text.contains(&CONNECT_DEADLINE.as_secs().to_string()));
    }

    #[test]
    fn the_transfer_error_tells_which_plugin_is_to_blame() {
        // An operation has two live plugins: "the transfer failed" forces you to
        // guess which one.
        let text = BackupError::Transfer {
            plugin: "postgres".into(),
            operation: OP_DUMP.into(),
            message: "connection refused".into(),
        }
        .to_string();
        assert!(text.contains("postgres"));
        assert!(text.contains("dump"));
        assert!(text.contains("connection refused"));
    }

    #[test]
    fn a_missing_capability_is_propagated_as_is() {
        // `PluginError`'s message is already the right one; wrapping it again
        // would only add noise in front.
        let error = BackupError::from(PluginError::MissingCapability {
            plugin: "storage-only".into(),
            capability: "source".into(),
        });
        assert_eq!(
            error.to_string(),
            "the plugin \"storage-only\" does not know how to act as \"source\""
        );
    }

    #[test]
    fn the_open_error_states_its_own_deadline() {
        let text = BackupError::NoResponse {
            plugin: "s3".into(),
            operation: OP_PUT.into(),
        }
        .to_string();
        assert!(text.contains("s3"));
        assert!(text.contains(&OPEN_DEADLINE.as_secs().to_string()));
    }

    #[test]
    fn the_missing_manifest_error_says_which_key_it_looked_for() {
        // It is the difference between "I cannot find the manifest" —which does
        // not help— and knowing whether it was lost or whether the artifact was
        // never called that.
        let text = BackupError::NoManifest {
            plugin: "r2".into(),
            key: "prod/2026/x.age.manifest.json".into(),
            reason: "NotFound: does not exist".into(),
        }
        .to_string();
        assert!(text.contains("prod/2026/x.age.manifest.json"));
        assert!(text.contains("manifest"));
        assert!(text.contains("r2"));
    }
}
