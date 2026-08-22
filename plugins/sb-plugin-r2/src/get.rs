//! Downloading an artifact from R2 and pouring it into the data channel.
//!
//! The only delicate thing here is what is **not** done: `body.collect()` is
//! never called. That call, the one that shows up in every SDK example, gathers
//! the whole object in memory before returning it. An artifact from this
//! program can weigh hundreds of gigabytes, and the promise of bounded memory
//! would break here and nowhere else. The body is consumed chunk by chunk, as
//! it arrives from the network, and each chunk is written and released.
//!
//! Absence is detected **before** answering the RPC: the core tells "that
//! artifact does not exist" from "the transfer was cut off", and that
//! distinction is lost if the error arrives through the progress stream once
//! the response has already gone out.

use aws_sdk_s3::primitives::ByteStream;
use sb_plugin_sdk::ProgressEmitter;
use sb_plugin_sdk::tonic::Status;

use crate::channel;
use crate::client::{Context, translate};

/// Asks R2 for the object and returns its body **unread**.
///
/// It is called from the RPC's body, not from the background task: that way a
/// missing artifact is answered as an error of the call and not as a mid-stream
/// cut.
///
/// # Errors
///
/// [`Status::not_found`] with the key inside if the object does not exist, and
/// the already scrubbed reason for any other failure against R2.
pub async fn fetch(context: &Context, key: &str) -> Result<ByteStream, Status> {
    let output = context
        .client
        .get_object()
        .bucket(&context.config.bucket)
        .key(key)
        .send()
        .await
        .map_err(|e| {
            let reason = translate("GetObject", &e);
            if reason.is_missing() {
                return Status::not_found(format!(
                    "the artifact `{key}` does not exist in bucket `{}`",
                    context.config.bucket
                ));
            }
            Status::from(reason)
        })?;
    Ok(output.body)
}

/// Pours `body` into the data channel, chunk by chunk, and closes it.
///
/// # Errors
///
/// [`Status::unavailable`] if R2's network or the data channel fails: in either
/// case the artifact did not arrive whole and the core has to find out.
pub async fn drain(
    mut body: ByteStream,
    socket: &str,
    progress: &mut ProgressEmitter,
) -> Result<(), Status> {
    let mut dest = channel::connect(socket).await?;
    // `next()` hands over the next chunk exactly as it arrived from the
    // network. The whole object is never in memory: only the chunk being
    // written.
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| {
            // The body's error belongs to the SDK and could drag along the
            // request that caused it; all that is said is that the download was
            // cut off.
            tracing::debug!(error = %e, "the GetObject body was cut off");
            Status::unavailable("the download from R2 was cut off before finishing")
        })?;
        channel::write(&mut dest, &chunk).await?;
        progress.advance(chunk.len()).await;
    }
    // Closing is the end-of-stream signal for the core. Without it, the
    // `restore` waits for bytes that are not coming.
    channel::close(&mut dest).await
}
