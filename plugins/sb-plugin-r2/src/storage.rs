//! The R2 storage target.
//!
//! The five RPCs are deliberately thin: each one resolves with a `?` whatever
//! can be known **before** moving a byte -- the configuration, the key, the
//! object's absence -- and delegates the rest to the module that carries the
//! delicate part ([`crate::put`], [`crate::get`], [`crate::admin`]).
//!
//! That division is not aesthetic. Once [`progress_stream`] has answered the
//! RPC, the error can no longer come back as the call's `Status`: only through
//! the progress stream, where the core treats it as a cut transfer. "That
//! artifact does not exist" and "the download was cut off" are different things
//! for whoever is restoring, so the first one is decided up here.
//!
//! Every RPC requires the configuration first, so a core that skipped
//! `Configure` finds out on the first RPC it makes and not on the second.

use sb_plugin_sdk::sb_proto::storage_server::Storage;
use sb_plugin_sdk::sb_proto::{
    AbortIncompleteRequest, AbortIncompleteResponse, ArtifactMeta, DeleteRequest, DeleteResponse,
    GetRequest, ListRequest, ListResponse, PutRequest,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};
use sb_plugin_sdk::{ProgressStream, progress_stream};

use crate::client::State;
use crate::{admin, get, put};

pub struct R2Storage {
    state: State,
}

impl R2Storage {
    #[must_use]
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Storage for R2Storage {
    type PutStream = ProgressStream;
    type GetStream = ProgressStream;

    async fn put(&self, request: Request<PutRequest>) -> Result<Response<Self::PutStream>, Status> {
        // What can be known before moving a byte is resolved here, with a `?`:
        // once the work starts, the RPC's response has already been sent and
        // the error would only have the progress stream to come back through.
        let context = self.state.resolved()?;
        let PutRequest { key, data_socket } = request.into_inner();
        let key = context.config.key(&key);
        // `progress_stream` answers the RPC **before** the work touches the
        // data socket, which is what the protocol requires: the core waits for
        // that response to start up the other end.
        Ok(progress_stream(move |mut progress| async move {
            put::upload(&context, &key, &data_socket, &mut progress).await?;
            progress.finish("artifact stored").await;
            tracing::info!(key = %key, bytes = progress.bytes(), "artifact stored in R2");
            Ok(())
        }))
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<Self::GetStream>, Status> {
        let context = self.state.resolved()?;
        let GetRequest { key, data_socket } = request.into_inner();
        let key = context.config.key(&key);
        // The `GetObject` is requested **before** answering, and only the
        // headers are requested: the body arrives lazily and is poured out
        // afterwards. That way a missing artifact is answered as the call's
        // `not_found`, which is what the core knows how to tell from a
        // mid-stream cut. None of this touches the data socket yet, which is
        // what the protocol forbids doing before answering.
        let body = get::fetch(&context, &key).await?;
        Ok(progress_stream(move |mut progress| async move {
            get::drain(body, &data_socket, &mut progress).await?;
            progress.finish("artifact delivered").await;
            tracing::info!(key = %key, bytes = progress.bytes(), "artifact downloaded from R2");
            Ok(())
        }))
    }

    async fn list(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        let context = self.state.resolved()?;
        let prefix = context.config.key(&request.into_inner().prefix);
        // `admin::list` walks **every** page: a truncated list goes unnoticed
        // and would make `verify --all` bless artifacts it never even looked
        // at.
        let found = admin::list(&context, &prefix).await?;
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
        let context = self.state.resolved()?;
        let key = context.config.key(&request.into_inner().key);
        admin::delete(&context, &key).await?;
        Ok(Response::new(DeleteResponse {}))
    }

    async fn abort_incomplete(
        &self,
        request: Request<AbortIncompleteRequest>,
    ) -> Result<Response<AbortIncompleteResponse>, Status> {
        let context = self.state.resolved()?;
        let prefix = context.config.key(&request.into_inner().prefix);
        let aborted = admin::abort_incomplete(&context, &prefix).await?;
        if aborted > 0 {
            tracing::warn!(
                aborted,
                prefix = %prefix,
                "incomplete multipart uploads removed: they stop being billed now"
            );
        }
        Ok(Response::new(AbortIncompleteResponse { aborted }))
    }
}
