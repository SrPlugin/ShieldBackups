//! Uploading an artifact to R2.
//!
//! It is the plugin's most delicate part, and it is so for two reasons that are
//! invisible until they hurt:
//!
//! 1. **Every part must be the same size except the last.** S3 tolerates
//!    otherwise; R2 does not. [`Chunker`] takes care of that, and it lives
//!    apart and is tested without networking.
//! 2. **A multipart that fails must be aborted.** The parts already uploaded do
//!    not show up in a `ListObjects` -- the object does not exist yet -- but
//!    they take up space and **are billed indefinitely**. That is why, as soon
//!    as an `upload_id` exists, everything else happens inside `upload_parts`
//!    -- private, hence not linked here -- and the only way back goes through
//!    the `match` in [`upload_from`], which aborts on any `Err`. A stray `?`
//!    above that `match` would be exactly the failure this structure prevents.
//!
//! ## Memory
//!
//! Each part is accumulated whole in memory while it uploads, so an upload's
//! memory ceiling is **`part_size` x `concurrency`**. With the default values
//! -- 64 MiB and 4 parts at a time -- that is 256 MiB. Raising either number
//! without thinking contradicts the bounded-memory promise of the rest of the
//! program: multiplying the concurrency by four also multiplies the memory by
//! four, not just the speed.

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart, StorageClass};
use sb_plugin_sdk::ProgressEmitter;
use sb_plugin_sdk::tonic::Status;
use tokio::io::AsyncRead;
use tokio::task::JoinSet;

use crate::channel;
use crate::chunks::Chunker;
use crate::client::{Context, R2Error, translate};
use crate::config::MAX_PARTS;

/// Uploads the artifact arriving over `socket` to the already prefixed `key`.
///
/// It picks between `PutObject` and multipart depending on what fits in one
/// part, and in the second case it guarantees that no failure leaves the upload
/// open.
///
/// # Errors
///
/// [`Status`] with the already scrubbed reason: the AWS SDK's error is never
/// propagated, because it drags along the request that caused it and with it
/// the authorization header.
pub async fn upload(
    context: &Context,
    key: &str,
    socket: &str,
    progress: &mut ProgressEmitter,
) -> Result<(), Status> {
    let data = channel::connect(socket).await?;
    upload_from(context, key, data, progress).await
}

/// The same as [`upload`], but reading from `data` instead of the data channel.
///
/// The separation exists for a concrete reason: **aborting a multipart can only
/// be tested with a source that fails halfway**, and a Unix socket does not
/// know how to fail. Closing it is a clean end of stream, not an error, so
/// through the data channel there is no way to provoke the failure whose
/// handling is the most delicate part of this module. `tests/integration.rs`
/// pushes through here a source that delivers one part and then returns an I/O
/// error, and checks against the server that no upload is left open.
///
/// # Errors
///
/// The same as [`upload`].
pub async fn upload_from<R: AsyncRead + Unpin>(
    context: &Context,
    key: &str,
    data: R,
    progress: &mut ProgressEmitter,
) -> Result<(), Status> {
    let part_size = context.config.part_size;
    let mut chunker = Chunker::new(data, part_size);

    // The first part decides the path. Reading it is mandatory anyway, so it
    // costs nothing.
    let first = chunker
        .next_chunk()
        .await
        .map_err(|e| channel::read_failure(&e))?
        .unwrap_or_default();

    // Small object: one call instead of three, and no multipart that could be
    // left orphaned. Manifests, which are tiny and written on every backup,
    // always come through here.
    if first.len() < part_size {
        return single_shot(context, key, first, progress).await;
    }

    let upload_id = create(context, key).await?;

    // From this line on there is an open upload in R2 that **must not stay
    // open**. Everything that remains lives inside `upload_parts`, whose only
    // way out is this `match`: there is no way to skip the abort without
    // deleting the whole `match`.
    //
    // The part tasks are created here, and not inside, so they can be stopped
    // before aborting.
    let mut tasks = JoinSet::new();
    match upload_parts(
        context, key, &upload_id, first, chunker, &mut tasks, progress,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(e) => {
            // First the parts still in flight are cancelled and waited for;
            // only afterwards is the upload aborted. The other way round, a
            // part reaching R2 after the abort would be orphaned all the same,
            // which is exactly what the abort is there to prevent.
            tasks.shutdown().await;
            abort(context, key, &upload_id).await;
            Err(e)
        }
    }
}

/// The whole object in one go.
async fn single_shot(
    context: &Context,
    key: &str,
    body: Vec<u8>,
    progress: &mut ProgressEmitter,
) -> Result<(), Status> {
    let bytes = body.len();
    context
        .client
        .put_object()
        .bucket(&context.config.bucket)
        .key(key)
        .set_storage_class(storage_class(context))
        .body(ByteStream::from(body))
        .send()
        .await
        .map_err(|e| translate("PutObject", &e))?;
    progress.advance(bytes).await;
    tracing::debug!(key = %key, bytes, "artifact uploaded in a single call");
    Ok(())
}

/// Opens the multipart upload and returns its identifier.
async fn create(context: &Context, key: &str) -> Result<String, Status> {
    let output = context
        .client
        .create_multipart_upload()
        .bucket(&context.config.bucket)
        .key(key)
        .set_storage_class(storage_class(context))
        .send()
        .await
        .map_err(|e| translate("CreateMultipartUpload", &e))?;
    // Without an `upload_id` there is nothing to abort from here: either the
    // upload never came to exist, or it exists and R2 did not tell us its
    // identifier, and in that second case the only possible remedy is
    // `shieldbk storage gc`, which lists the bucket's incomplete uploads. That
    // is why this error can just come out through `?`.
    output.upload_id().map(ToString::to_string).ok_or_else(|| {
        Status::internal("R2 accepted `CreateMultipartUpload` but returned no `upload_id`")
    })
}

/// Uploads every part and closes the multipart.
///
/// **The whole function may fail freely**: its caller aborts the upload on any
/// `Err`, including the one from `CompleteMultipartUpload`.
///
/// It keeps up to `concurrency` parts uploading at a time. The slot is awaited
/// **before** reading the next part, not after: that way there are never more
/// than `concurrency` parts alive in memory at once.
///
/// `tasks` comes from outside so the caller can stop them before aborting, even
/// -- and above all -- when this function exits through an error.
async fn upload_parts<R: AsyncRead + Unpin>(
    context: &Context,
    key: &str,
    upload_id: &str,
    first: Vec<u8>,
    mut chunker: Chunker<R>,
    tasks: &mut JoinSet<Result<UploadedPart, R2Error>>,
    progress: &mut ProgressEmitter,
) -> Result<(), Status> {
    let concurrency = context.config.concurrency.max(1);
    let mut completed: Vec<CompletedPart> = Vec::new();
    let mut pending = Some(first);
    let mut index: u64 = 0;

    loop {
        // The slot first, the read afterwards: the other way round there would
        // be `concurrency` parts in flight plus the one being read.
        while tasks.len() >= concurrency {
            collect_one(tasks, &mut completed, progress).await?;
        }

        let part = match pending.take() {
            Some(p) => p,
            None => match chunker
                .next_chunk()
                .await
                .map_err(|e| channel::read_failure(&e))?
            {
                Some(p) => p,
                None => break,
            },
        };

        index += 1;
        if index > MAX_PARTS {
            // The configuration validates this against `max_object_gb`, but the
            // real artifact may be bigger than anyone expected. Better to stop
            // it here than to let R2 reject part 10 001.
            return Err(Status::out_of_range(format!(
                "the artifact does not fit in the {MAX_PARTS} parts a multipart upload with {} byte parts admits: raise `part_size_mb`",
                context.config.part_size
            )));
        }
        // After the check above the index never goes past 10 000.
        let number = i32::try_from(index).unwrap_or(i32::MAX);

        tasks.spawn(upload_one(
            context.client.clone(),
            context.config.bucket.clone(),
            key.to_string(),
            upload_id.to_string(),
            number,
            part,
        ));
    }

    while !tasks.is_empty() {
        collect_one(tasks, &mut completed, progress).await?;
    }

    // The parts finish in the order R2 answers them, which is not the order
    // they were sent in. `CompleteMultipartUpload` requires the list sorted by
    // part number.
    completed.sort_by_key(CompletedPart::part_number);

    context
        .client
        .complete_multipart_upload()
        .bucket(&context.config.bucket)
        .key(key)
        .upload_id(upload_id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(completed))
                .build(),
        )
        .send()
        .await
        .map_err(|e| translate("CompleteMultipartUpload", &e))?;

    tracing::debug!(
        key = %key,
        parts = index,
        bytes = chunker.total(),
        "artifact uploaded via multipart"
    );
    Ok(())
}

/// What a part leaves behind when it finishes.
struct UploadedPart {
    number: i32,
    /// The `ETag` R2 returned. `CompleteMultipartUpload` requires it back.
    etag: Option<String>,
    bytes: usize,
}

/// Uploads one part. It runs in its own task, hence it takes everything by
/// value; the `Client` clones cheaply because it shares the connection pool.
async fn upload_one(
    client: aws_sdk_s3::Client,
    bucket: String,
    key: String,
    upload_id: String,
    number: i32,
    part: Vec<u8>,
) -> Result<UploadedPart, R2Error> {
    let bytes = part.len();
    let output = client
        .upload_part()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .part_number(number)
        .body(ByteStream::from(part))
        .send()
        .await
        .map_err(|e| translate("UploadPart", &e))?;
    Ok(UploadedPart {
        number,
        etag: output.e_tag().map(ToString::to_string),
        bytes,
    })
}

/// Waits for any part to finish and records it.
///
/// Progress is emitted here and not on reading: what the operator cares about
/// is what is already in R2, not what was read from the socket.
async fn collect_one(
    tasks: &mut JoinSet<Result<UploadedPart, R2Error>>,
    completed: &mut Vec<CompletedPart>,
    progress: &mut ProgressEmitter,
) -> Result<(), Status> {
    let Some(joined) = tasks.join_next().await else {
        return Ok(());
    };
    // The `JoinError`'s reason is summarised instead of printed: its `Display`
    // includes the panic message, which is text foreign to this module.
    let result = joined.map_err(|e| {
        Status::internal(if e.is_panic() {
            "a part's upload panicked"
        } else {
            "a part's upload was cancelled"
        })
    })?;
    let part = result?;
    progress.advance(part.bytes).await;
    completed.push(
        CompletedPart::builder()
            .part_number(part.number)
            .set_e_tag(part.etag)
            .build(),
    );
    Ok(())
}

/// Aborts the multipart upload. It deliberately returns no error: it is called
/// **from a path that already failed**, and the failure the core is going to be
/// told about is the original one, not this one.
///
/// If the abort does not work either, the only thing left is to say so in the
/// log: the parts already uploaded are still there, invisible in a
/// `ListObjects`, and are billed until someone removes them.
async fn abort(context: &Context, key: &str, upload_id: &str) {
    match context
        .client
        .abort_multipart_upload()
        .bucket(&context.config.bucket)
        .key(key)
        .upload_id(upload_id)
        .send()
        .await
    {
        Ok(_) => {
            tracing::warn!(key = %key, "multipart upload aborted after a failure");
        }
        Err(e) => {
            let reason = translate("AbortMultipartUpload", &e);
            tracing::error!(
                key = %key,
                error = %reason,
                "could not abort the multipart upload: the parts already uploaded are left \
                 orphaned, do not show up when listing the bucket and are billed indefinitely. \
                 Run `shieldbk storage gc <target>` to remove them"
            );
        }
    }
}

/// The configured storage class, in the type the SDK expects, or `None` when
/// the header must not be sent. See
/// [`R2StorageClass::header`](crate::config::R2StorageClass::header).
fn storage_class(context: &Context) -> Option<StorageClass> {
    context
        .config
        .storage_class
        .header()
        .map(StorageClass::from)
}
