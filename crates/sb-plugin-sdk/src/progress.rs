//! The scaffolding of the RPCs that move bytes.
//!
//! `Dump`, `Restore`, `Put` and `Get` all have the same shape: spawn a task
//! that pumps bytes through the data channel and hand the core back a stream of
//! `Progress` through which the error also travels if something fails. That
//! shape lives here once, so a source or a storage only has to write its own
//! byte-moving logic.

use std::future::Future;

use sb_proto::Progress;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Response, Status};

/// How many moved bytes trigger a `Progress`.
///
/// It is public because the chunk size is chosen by the plugin and only makes
/// sense if it is smaller than this: a bigger chunk would skip whole milestones
/// and progress would jump instead of flowing.
pub const MILESTONE: u64 = 1024 * 1024;

/// How many `Progress` messages fit unconsumed before the task is throttled.
///
/// The backpressure is deliberate: a core that is not reading progress is a
/// core that is not reading the data either, and generating more would not
/// help.
const CAPACITY: usize = 64;

/// The `Progress` stream returned by the data RPCs.
///
/// It is the type declared in `type DumpStream = ProgressStream;` and in its
/// three siblings.
pub type ProgressStream = ReceiverStream<Result<Progress, Status>>;

/// How the work reports how much it has moved.
///
/// It is built by [`progress_stream`] and handed to the work; there is no other
/// way to create one, because an emitter without its stream on the other end
/// would emit to nobody.
pub struct ProgressEmitter {
    tx: tokio::sync::mpsc::Sender<Result<Progress, Status>>,
    bytes: u64,
    milestones: u64,
}

impl ProgressEmitter {
    /// Records `n` moved bytes and emits a `Progress` if a milestone was
    /// crossed.
    ///
    /// It is called for every chunk: it is cheap, because it only emits when
    /// [`MILESTONE`] is crossed.
    pub async fn advance(&mut self, n: usize) {
        self.bytes += as_u64(n);
        let milestones = self.bytes / MILESTONE;
        if milestones > self.milestones {
            self.milestones = milestones;
            self.emit("in progress").await;
        }
    }

    /// Emits the final `Progress` with the total moved.
    ///
    /// The core uses the last `Progress` as the summary of the operation, so
    /// `message` is what the operator will end up seeing.
    pub async fn finish(&mut self, message: &str) {
        self.emit(message).await;
    }

    /// Bytes moved so far.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    async fn emit(&self, message: &str) {
        // A failed send means the core closed the stream; that is not a plugin
        // error and must not abort the transfer in flight.
        let _ = self
            .tx
            .send(Ok(Progress {
                bytes: self.bytes,
                message: message.into(),
            }))
            .await;
    }
}

/// Runs `work` in a task and returns the progress stream that the core
/// consumes.
///
/// It returns the [`Response`] already assembled because that is the only thing
/// a data RPC has to return:
///
/// ```ignore
/// async fn dump(&self, p: Request<DumpRequest>) -> Result<Response<Self::DumpStream>, Status> {
///     let config = self.config.resolved()?;          // before touching anything
///     let socket = p.into_inner().data_socket;
///     Ok(progress_stream(move |mut progress| async move {
///         dump_to(&socket, &config, &mut progress).await // just move bytes
///     }))
/// }
/// ```
///
/// An `Err` from the work reaches the core **through the same stream** it is
/// already listening on, not as a `Status` of the call: by the time the work
/// starts, the RPC response was sent long ago. The errors that can be detected
/// beforehand —missing configuration, an invalid key, an artifact that does not
/// exist— belong outside of here, behind a `?` in the RPC body.
pub fn progress_stream<F, Fut>(work: F) -> Response<ProgressStream>
where
    F: FnOnce(ProgressEmitter) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), Status>> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(CAPACITY);
    let tx_error = tx.clone();
    tokio::spawn(async move {
        let emitter = ProgressEmitter {
            tx,
            bytes: 0,
            milestones: 0,
        };
        if let Err(e) = work(emitter).await {
            tracing::warn!(error = %e, "the transfer failed");
            let _ = tx_error.send(Err(e)).await;
        }
    });
    Response::new(ReceiverStream::new(rx))
}

/// `usize` to `u64` without an `as` that clippy has to forgive. On the
/// platforms this project supports the conversion never saturates.
fn as_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt as _;

    /// Drains the whole stream and returns what arrived.
    async fn collect_all(r: Response<ProgressStream>) -> Vec<Result<Progress, Status>> {
        r.into_inner().collect().await
    }

    #[tokio::test]
    async fn work_that_emits_nothing_closes_the_stream_without_error() {
        let output = collect_all(progress_stream(|_| async { Ok(()) })).await;
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn the_final_progress_carries_the_total_and_the_plugin_message() {
        let output = collect_all(progress_stream(|mut progress| async move {
            progress.advance(1000).await;
            progress.finish("dump completed").await;
            Ok(())
        }))
        .await;

        assert_eq!(
            output.len(),
            1,
            "below one milestone only the final one goes"
        );
        let p = output[0].as_ref().unwrap();
        assert_eq!(p.bytes, 1000);
        assert_eq!(p.message, "dump completed");
    }

    #[tokio::test]
    async fn one_progress_is_emitted_per_milestone_crossed() {
        let output = collect_all(progress_stream(|mut progress| async move {
            let chunk = usize::try_from(MILESTONE).unwrap() / 4;
            for _ in 0..12 {
                progress.advance(chunk).await;
            }
            progress.finish("done").await;
            Ok(())
        }))
        .await;

        // Three milestones crossed plus the final one.
        assert_eq!(output.len(), 4);
        assert_eq!(output[0].as_ref().unwrap().bytes, MILESTONE);
        assert_eq!(output[3].as_ref().unwrap().bytes, MILESTONE * 3);
    }

    #[tokio::test]
    async fn the_work_error_reaches_the_core_through_the_stream() {
        // By the time the work starts, the RPC response has already been sent:
        // the stream is the only path left for the error.
        let output = collect_all(progress_stream(|mut progress| async move {
            progress.advance(10).await;
            Err(Status::unavailable("the data channel went down"))
        }))
        .await;

        let e = output.last().unwrap().as_ref().unwrap_err();
        assert_eq!(e.code(), tonic::Code::Unavailable);
        assert_eq!(e.message(), "the data channel went down");
    }

    #[tokio::test]
    async fn what_was_emitted_before_the_error_is_not_lost() {
        let output = collect_all(progress_stream(|mut progress| async move {
            progress.finish("was going well").await;
            Err(Status::internal("and then it was not"))
        }))
        .await;

        assert_eq!(output.len(), 2);
        assert_eq!(output[0].as_ref().unwrap().message, "was going well");
        assert!(output[1].is_err());
    }

    #[tokio::test]
    async fn the_emitter_keeps_the_byte_count() {
        let output = collect_all(progress_stream(|mut progress| async move {
            progress.advance(3).await;
            progress.advance(4).await;
            assert_eq!(progress.bytes(), 7);
            progress.finish("done").await;
            Ok(())
        }))
        .await;
        assert_eq!(output[0].as_ref().unwrap().bytes, 7);
    }

    #[tokio::test]
    async fn a_core_that_stops_reading_does_not_fail_the_work() {
        // If the core closes the stream, emitting stops reaching anybody, but
        // the transfer in flight is not a plugin error.
        let (notice_tx, notice_rx) = tokio::sync::oneshot::channel();
        let response = progress_stream(|mut progress| async move {
            for _ in 0..(CAPACITY * 4) {
                progress.finish("tick").await;
            }
            let _ = notice_tx.send(());
            Ok(())
        });
        drop(response);
        notice_rx.await.expect("the work must finish anyway");
    }
}
