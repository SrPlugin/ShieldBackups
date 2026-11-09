//! The source: `Dump` streams `pg_dump`'s stdout into the core's data channel,
//! `Restore` streams the channel into `pg_restore`'s stdin.
//!
//! Neither RPC speaks the `PostgreSQL` wire protocol; both are a byte pump with
//! a subprocess on one end and the data channel on the other, plus the rule
//! that decides whose error wins when both ends fail at once (see
//! `run_dump` and `run_restore`).

use std::path::Path;
use std::process::Stdio;

use sb_plugin_sdk::sb_proto::source_server::Source;
use sb_plugin_sdk::sb_proto::{DumpRequest, RestoreRequest};
use sb_plugin_sdk::tonic::{Request, Response, Status};
use sb_plugin_sdk::{ProgressEmitter, ProgressStream, connect_data, progress_stream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::process::{ChildStdin, ChildStdout};

use crate::command::{self, Running};
use crate::config::{Config, State};
use crate::drill::Scratch;

/// Size of the chunks moved between the process and the channel. Deliberately
/// smaller than the SDK's progress milestone: a larger chunk would skip whole
/// milestones and progress would jump instead of flowing.
const CHUNK: usize = 64 * 1024;

pub struct PostgresSource {
    state: State,
    /// Which database a restore lands in: the configured one, except between a
    /// drill's `Provision` and `Teardown`, when it is the scratch one.
    scratch: Scratch,
}

impl PostgresSource {
    #[must_use]
    pub fn new(state: State, scratch: Scratch) -> Self {
        Self { state, scratch }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Source for PostgresSource {
    type DumpStream = ProgressStream;
    type RestoreStream = ProgressStream;

    async fn dump(
        &self,
        request: Request<DumpRequest>,
    ) -> Result<Response<Self::DumpStream>, Status> {
        // The configuration is required here, before touching the channel: if
        // it is missing, the core gets an immediate `failed_precondition`
        // instead of a silent `pg_dump` against wherever the last run left
        // `PGHOST` pointed.
        let config = self.state.resolved()?;
        let socket = request.into_inner().data_socket;
        Ok(progress_stream(move |mut progress| async move {
            let pg_dump_path = config.pg_dump_path.clone();
            let args = command::dump_args(&config);
            run_dump(&pg_dump_path, &args, &socket, &config, &mut progress).await
        }))
    }

    async fn restore(
        &self,
        request: Request<RestoreRequest>,
    ) -> Result<Response<Self::RestoreStream>, Status> {
        // Aimed at the scratch database while a drill is under way. This is the
        // one line that keeps a drill from restoring over what is being backed up.
        let config = self.scratch.applied_to(self.state.resolved()?);
        let socket = request.into_inner().data_socket;
        Ok(progress_stream(move |mut progress| async move {
            let pg_restore_path = config.pg_restore_path.clone();
            let args = command::restore_args(&config);
            run_restore(&pg_restore_path, &args, &socket, &config, &mut progress).await
        }))
    }
}

/// Connects to the data channel the core created.
///
/// # Errors
/// [`Status::unavailable`] if the socket does not exist or refuses the
/// connection.
async fn connect(socket: &str) -> Result<UnixStream, Status> {
    connect_data(Path::new(socket)).await.map_err(|e| {
        Status::unavailable(format!("could not open the data channel `{socket}`: {e}"))
    })
}

/// Runs `program` with `args` as `pg_dump` and streams its stdout into the
/// data channel at `socket`.
///
/// If the command exits non-zero the transfer is still reported as failed
/// **even though bytes already reached the core**: the core cuts the source's
/// channel abruptly on any failure, so a partial artifact never gets mistaken
/// for a complete one.
///
/// A failure to write into the channel (the core went away) kills the command
/// instead of waiting for it to finish writing into a pipe nobody drains
/// anymore.
///
/// # Errors
/// [`Status::unavailable`] if `pg_dump` cannot be started or the channel fails,
/// [`Status::internal`] if `pg_dump` exits non-zero.
pub(crate) async fn run_dump(
    program: &str,
    args: &[String],
    socket: &str,
    config: &Config,
    progress: &mut ProgressEmitter,
) -> Result<(), Status> {
    let mut channel = connect(socket).await?;
    let mut running = Running::spawn(
        "pg_dump",
        program,
        args,
        config,
        Stdio::null(),
        Stdio::piped(),
    )?;
    let stdout = running.stdout();

    let pump_result = child_to_channel(stdout, &mut channel, progress).await;
    if pump_result.is_err() {
        running.kill();
    }
    // Closing is the end-of-stream signal for the core, sent regardless of how
    // the pump ended: a core still waiting for EOF after a failure is a core
    // that hangs instead of seeing the error.
    let _ = channel.shutdown().await;

    let settle_result = running.settle().await;
    match (pump_result, settle_result) {
        (Err(e), _) | (Ok(()), Err(e)) => Err(e),
        (Ok(()), Ok(())) => {
            progress.finish("dump complete").await;
            tracing::info!(host = %config.host, database = %config.database, "dump emitted");
            Ok(())
        }
    }
}

/// Runs `program` with `args` as `pg_restore` and streams the data channel at
/// `socket` into its stdin.
///
/// The command's own failure wins over a pump failure caused by it (a broken
/// pipe once `pg_restore` has already died is not new information), but a
/// pump failure caused by the **channel** (the core went away) is kept even if
/// killing the command in response makes it exit non-zero too: that channel
/// error is the root cause, `pg_restore`'s is the consequence.
///
/// # Errors
/// [`Status::unavailable`] if `pg_restore` cannot be started or the channel
/// fails, [`Status::internal`] if `pg_restore` exits non-zero.
pub(crate) async fn run_restore(
    program: &str,
    args: &[String],
    socket: &str,
    config: &Config,
    progress: &mut ProgressEmitter,
) -> Result<(), Status> {
    let mut channel = connect(socket).await?;
    let mut running = Running::spawn(
        "pg_restore",
        program,
        args,
        config,
        Stdio::piped(),
        Stdio::null(),
    )?;
    let stdin = running.stdin();

    let pump_result = channel_to_child(&mut channel, stdin, progress).await;
    if pump_result.is_err() {
        // Without this, a command that already exited leaves `settle` waiting
        // on a `wait()` that will never resolve on its own -- it already did,
        // but only `kill` makes that observable here if it has not yet.
        running.kill();
    }

    let settle_result = running.settle().await;
    match (pump_result, settle_result) {
        (Err(e), _) | (Ok(()), Err(e)) => Err(e),
        (Ok(()), Ok(())) => {
            progress.finish("restore complete").await;
            tracing::info!(host = %config.host, database = %config.database, "restore applied");
            Ok(())
        }
    }
}

/// Reads `reader` until EOF and writes it into the data channel.
async fn child_to_channel(
    mut reader: ChildStdout,
    channel: &mut UnixStream,
    progress: &mut ProgressEmitter,
) -> Result<(), Status> {
    let mut buffer = vec![0_u8; CHUNK];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|e| Status::internal(format!("failed reading pg_dump's stdout: {e}")))?;
        if read == 0 {
            break;
        }
        channel
            .write_all(&buffer[..read])
            .await
            .map_err(|e| Status::unavailable(format!("failed writing to the data channel: {e}")))?;
        progress.advance(read).await;
    }
    Ok(())
}

/// Reads the data channel until EOF and writes it into `writer`, then closes
/// `writer` so the command sees its own end of input.
async fn channel_to_child(
    channel: &mut UnixStream,
    mut writer: ChildStdin,
    progress: &mut ProgressEmitter,
) -> Result<(), Status> {
    let mut buffer = vec![0_u8; CHUNK];
    loop {
        let read = channel
            .read(&mut buffer)
            .await
            .map_err(|e| Status::unavailable(format!("failed reading the data channel: {e}")))?;
        if read == 0 {
            break;
        }
        if writer.write_all(&buffer[..read]).await.is_err() {
            // The command stopped reading, almost always because it already
            // exited. Its exit status -- fetched by `settle`, not the generic
            // broken pipe seen here -- is the diagnosis worth keeping, so this
            // is not treated as this function's own failure.
            return Ok(());
        }
        progress.advance(read).await;
    }
    // What signals end of input to `pg_restore`.
    let _ = writer.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::future::Future;

    use sb_plugin_sdk::sb_proto::source_server::Source as _;
    use sb_plugin_sdk::sb_proto::{DumpRequest, RestoreRequest, Value, value::Kind};
    use sb_plugin_sdk::tonic::{Code, Request, Status};
    use sb_plugin_sdk::{ProgressEmitter, progress_stream};
    use sb_transport::DataChannel;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::{PostgresSource, run_dump, run_restore};
    use crate::config::{Config, State};
    use crate::drill::Scratch;

    fn config() -> Config {
        let map = HashMap::from([
            (
                "host".to_string(),
                Value {
                    kind: Some(Kind::StringValue("db.internal".into())),
                },
            ),
            (
                "database".to_string(),
                Value {
                    kind: Some(Kind::StringValue("app".into())),
                },
            ),
            (
                "user".to_string(),
                Value {
                    kind: Some(Kind::StringValue("backup".into())),
                },
            ),
        ]);
        Config::from_map(&map).unwrap()
    }

    /// Runs a job that needs a [`ProgressEmitter`] and returns its result, the
    /// way the core consumes the `Progress` stream: to the end, keeping the
    /// error if there was one.
    async fn with_progress<F, Fut>(job: F) -> Result<(), Status>
    where
        F: FnOnce(ProgressEmitter) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), Status>> + Send + 'static,
    {
        let mut receiver = progress_stream(job).into_inner().into_inner();
        let mut result = Ok(());
        while let Some(message) = receiver.recv().await {
            if let Err(e) = message {
                result = Err(e);
            }
        }
        result
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dump_streams_the_commands_stdout_into_the_channel() {
        let sockets = tempfile::tempdir().unwrap();
        let channel = DataChannel::create(sockets.path(), "dump").unwrap();
        let path = channel.path().display().to_string();

        let reader = tokio::spawn(async move {
            let mut s = channel.accept().await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let result = with_progress(move |mut progress| async move {
            run_dump(
                "/bin/sh",
                &["-c".into(), "printf DUMPDATA".into()],
                &path,
                &config(),
                &mut progress,
            )
            .await
        })
        .await;

        result.unwrap();
        assert_eq!(reader.await.unwrap(), b"DUMPDATA");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dump_whose_command_fails_reports_the_error_even_though_bytes_already_flowed() {
        let sockets = tempfile::tempdir().unwrap();
        let channel = DataChannel::create(sockets.path(), "dump").unwrap();
        let path = channel.path().display().to_string();

        let reader = tokio::spawn(async move {
            let mut s = channel.accept().await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let result = with_progress(move |mut progress| async move {
            run_dump(
                "/bin/sh",
                &[
                    "-c".into(),
                    "printf PARTIAL; echo pg_dump-broke >&2; exit 1".into(),
                ],
                &path,
                &config(),
                &mut progress,
            )
            .await
        })
        .await;

        let e = result.unwrap_err();
        assert_eq!(e.code(), Code::Internal);
        assert!(e.message().contains("pg_dump-broke"), "{}", e.message());
        // What was already sent is not un-sent: the core sees it and the error
        // together, which is exactly what a truncated artifact looks like.
        assert_eq!(reader.await.unwrap(), b"PARTIAL");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_restore_streams_the_channel_into_the_commands_stdin() {
        let sockets = tempfile::tempdir().unwrap();
        let channel = DataChannel::create(sockets.path(), "restore").unwrap();
        let path = channel.path().display().to_string();
        let received = sockets.path().join("received.txt");
        let dest = received.display().to_string();

        let writer = tokio::spawn(async move {
            let mut s = channel.accept().await.unwrap();
            s.write_all(b"RESTOREDATA").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let result = with_progress(move |mut progress| async move {
            run_restore(
                "/bin/sh",
                &["-c".into(), format!("cat > {dest}")],
                &path,
                &config(),
                &mut progress,
            )
            .await
        })
        .await;

        result.unwrap();
        writer.await.unwrap();
        assert_eq!(std::fs::read(&received).unwrap(), b"RESTOREDATA");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_restore_whose_command_fails_is_reported_and_does_not_hang() {
        let sockets = tempfile::tempdir().unwrap();
        let channel = DataChannel::create(sockets.path(), "restore").unwrap();
        let path = channel.path().display().to_string();

        let writer = tokio::spawn(async move {
            let mut s = channel.accept().await.unwrap();
            // More than the failing command's stdin buffer will ever read: what
            // is being checked is that the plugin does not wait for an end of
            // stream that a dead `pg_restore` will never ask for.
            let chunk = vec![b'x'; 64 * 1024];
            loop {
                if s.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        let result = with_progress(move |mut progress| async move {
            run_restore(
                "/bin/sh",
                &["-c".into(), "echo pg_restore-broke >&2; exit 1".into()],
                &path,
                &config(),
                &mut progress,
            )
            .await
        })
        .await;

        let e = result.unwrap_err();
        assert_eq!(e.code(), Code::Internal);
        assert!(e.message().contains("pg_restore-broke"), "{}", e.message());
        let _ = writer.await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dump_without_configure_fails_with_failed_precondition() {
        let source = PostgresSource::new(State::default(), Scratch::default());
        let e = source
            .dump(Request::new(DumpRequest {
                data_socket: "/tmp/unused".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::FailedPrecondition);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn restore_without_configure_fails_with_failed_precondition() {
        let source = PostgresSource::new(State::default(), Scratch::default());
        let e = source
            .restore(Request::new(RestoreRequest {
                data_socket: "/tmp/unused".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::FailedPrecondition);
    }
}
