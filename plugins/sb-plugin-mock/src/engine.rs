//! The engine: it produces deterministic bytes and receives them back.
//!
//! There is no database behind it. `Dump` generates the stream from a seed and
//! `Restore` writes it to disk so that a test can compare it with what the
//! generator produces, with no dependency beyond arithmetic.

use std::path::Path;

use sb_plugin_mock::deterministic_data;
use sb_plugin_sdk::sb_proto::engine_server::Engine;
use sb_plugin_sdk::sb_proto::{DumpRequest, RestoreRequest};
use sb_plugin_sdk::tonic::{Request, Response, Status};
use sb_plugin_sdk::{ProgressEmitter, ProgressStream, progress_stream};

use crate::config::{Config, State};
use crate::stream;

/// Name of the file where `Restore` leaves what it receives.
pub const RESTORE_FILE: &str = "restore.bin";

pub struct MockEngine {
    state: State,
}

impl MockEngine {
    #[must_use]
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Engine for MockEngine {
    type DumpStream = ProgressStream;
    type RestoreStream = ProgressStream;

    async fn dump(
        &self,
        request: Request<DumpRequest>,
    ) -> Result<Response<Self::DumpStream>, Status> {
        // The configuration is required here, before touching the channel: if
        // it is missing, the core gets an immediate `failed_precondition`
        // instead of a silent dump with values nobody asked for.
        let config = self.state.resolved()?;
        let socket = request.into_inner().data_socket;
        Ok(progress_stream(move |mut progress| async move {
            dump(&socket, &config, &mut progress).await
        }))
    }

    async fn restore(
        &self,
        request: Request<RestoreRequest>,
    ) -> Result<Response<Self::RestoreStream>, Status> {
        let config = self.state.resolved()?;
        let socket = request.into_inner().data_socket;
        let dest = config.dir.join(RESTORE_FILE);
        Ok(progress_stream(move |mut progress| async move {
            restore(&socket, &dest, &mut progress).await
        }))
    }
}

/// Writes `size` bytes from the seed into the channel and closes it.
async fn dump(socket: &str, config: &Config, progress: &mut ProgressEmitter) -> Result<(), Status> {
    let mut channel = stream::connect(socket).await?;
    let mut generator = deterministic_data(config.seed, config.size);
    loop {
        let chunk: Vec<u8> = generator.by_ref().take(stream::CHUNK).collect();
        if chunk.is_empty() {
            break;
        }
        stream::write(&mut channel, &chunk).await?;
        progress.advance(chunk.len()).await;
    }
    // Closing is the end-of-stream signal for the core.
    stream::close(&mut channel).await?;
    progress.finish("dump complete").await;
    tracing::info!(seed = config.seed, size = config.size, "dump emitted");
    Ok(())
}

async fn restore(socket: &str, dest: &Path, progress: &mut ProgressEmitter) -> Result<(), Status> {
    stream::channel_to_file(socket, dest, progress).await?;
    progress.finish("restore complete").await;
    tracing::info!(dest = %dest.display(), "restore written");
    Ok(())
}
