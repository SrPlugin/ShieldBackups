//! The storage target: a directory on disk playing the part of a bucket.
//!
//! Each key is a file under `dir`. The interesting part is not storing bytes
//! but reproducing the contract the core expects from a real storage target:
//! hierarchical keys, idempotent deletion and rejection of escaping keys.

use sb_plugin_sdk::sb_proto::storage_server::Storage;
use sb_plugin_sdk::sb_proto::{
    AbortIncompleteRequest, AbortIncompleteResponse, ArtifactMeta, DeleteRequest, DeleteResponse,
    GetRequest, ListRequest, ListResponse, PutRequest,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};
use sb_plugin_sdk::{ProgressStream, progress_stream};

use crate::config::State;
use crate::keys;
use crate::stream;

pub struct MockStorage {
    state: State,
}

impl MockStorage {
    #[must_use]
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Storage for MockStorage {
    type PutStream = ProgressStream;
    type GetStream = ProgressStream;

    async fn put(&self, request: Request<PutRequest>) -> Result<Response<Self::PutStream>, Status> {
        let config = self.state.resolved()?;
        let PutRequest { key, data_socket } = request.into_inner();
        // The key is validated **before** anything is opened: a `..` must fail
        // as an immediate RPC error, not as a mid-stream error once something
        // has already been written outside the directory.
        let dest = keys::path_for(&config.dir, &key)?;
        Ok(progress_stream(move |mut progress| async move {
            stream::channel_to_file(&data_socket, &dest, &mut progress).await?;
            progress.finish("artifact stored").await;
            tracing::info!(key = %key, "artifact stored");
            Ok(())
        }))
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<Self::GetStream>, Status> {
        let config = self.state.resolved()?;
        let GetRequest { key, data_socket } = request.into_inner();
        let source = keys::path_for(&config.dir, &key)?;
        // Absence is also checked beforehand: the core must be able to tell
        // "it is not there" from "it was cut off halfway".
        if !source.is_file() {
            return Err(Status::not_found(format!(
                "the artifact `{key}` does not exist in {}",
                config.dir.display()
            )));
        }
        Ok(progress_stream(move |mut progress| async move {
            stream::file_to_channel(&data_socket, &source, &mut progress).await?;
            progress.finish("artifact delivered").await;
            Ok(())
        }))
    }

    async fn list(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        let config = self.state.resolved()?;
        let prefix = request.into_inner().prefix;
        let found = keys::list(&config.dir, &prefix).map_err(|e| {
            Status::internal(format!("could not walk {}: {e}", config.dir.display()))
        })?;
        Ok(Response::new(ListResponse {
            artifacts: found
                .into_iter()
                .map(|a| ArtifactMeta {
                    key: a.key,
                    size: a.size,
                    modified_at: a.modified_at,
                })
                .collect(),
        }))
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        let config = self.state.resolved()?;
        let key = request.into_inner().key;
        let path = keys::path_for(&config.dir, &key)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            // Deleting what is already gone is the result that was asked for. A
            // retention pass that retries cannot fail for having succeeded.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(key = %key, "deletion of an artifact that was already gone");
            }
            Err(e) => {
                return Err(Status::internal(format!("could not delete `{key}`: {e}")));
            }
        }
        Ok(Response::new(DeleteResponse {}))
    }

    async fn abort_incomplete(
        &self,
        _: Request<AbortIncompleteRequest>,
    ) -> Result<Response<AbortIncompleteResponse>, Status> {
        // Configuration is required just as in the rest of the storage target,
        // even though the answer does not depend on it: a core that skipped
        // `Configure` must find out on the first RPC it makes, not the second.
        let _ = self.state.resolved()?;
        // This storage target writes each artifact in one go: there is no
        // multipart to abort, which is why it is always zero.
        Ok(Response::new(AbortIncompleteResponse { aborted: 0 }))
    }
}
