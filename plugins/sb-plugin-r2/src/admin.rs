//! Listing, deleting and cleaning up incomplete uploads.
//!
//! The storage target's three administrative RPCs. What they have in common,
//! and what justifies keeping them together, is that **all three must paginate
//! or lie**: the S3 API cuts responses short and returns a marker to continue.
//!
//! ## Why pagination is not a detail
//!
//! `ListObjectsV2` returns at most 1000 keys per page. A storage target that
//! kept only the first one would not give an error: it would give a **short and
//! silent** list. With it, `verify --all` would say everything is fine after
//! looking at the first thousand artifacts, and a retention pass would delete
//! believing there is nothing else. A truncated list is worse than a failure,
//! because a failure is visible.
//!
//! Same with `ListMultipartUploads`: the uploads left unaborted do not show up
//! when listing the bucket and are billed indefinitely, so a cleanup that only
//! looks at the first page leaves you paying for what it did not see.

use aws_sdk_s3::primitives::{DateTime, DateTimeFormat};
use aws_sdk_s3::types::Object;
use sb_plugin_sdk::tonic::Status;

use crate::client::{Context, translate};
use crate::keys;

/// An artifact as `List` sees it.
pub struct Artifact {
    /// The key **without** the internal prefix: it is the one the core used
    /// when storing it and the only one it can request it back with.
    pub key: String,
    pub size: u64,
    /// Last modification date in **RFC-3339 UTC with second precision**:
    /// `2026-08-21T09:30:00Z`, exactly twenty characters. That is what the
    /// `.proto` requires for `ArtifactMeta.modified_at`. Empty string if R2 did
    /// not return it.
    pub modified_at: String,
}

/// Every artifact under `prefix`, **paginating to the end**.
///
/// The prefix arrives already complete -- with the internal prefix in front --;
/// the keys that come out go without it.
///
/// # Errors
///
/// The already scrubbed reason if R2 fails on any of the pages. A page that
/// fails aborts the whole listing on purpose: returning what had been gathered
/// would be exactly the truncated list this module exists to prevent.
pub async fn list(context: &Context, prefix: &str) -> Result<Vec<Artifact>, Status> {
    let mut found = Vec::new();
    let mut token: Option<String> = None;
    let mut pages = 0_u64;

    loop {
        let page = context
            .client
            .list_objects_v2()
            .bucket(&context.config.bucket)
            .prefix(prefix)
            .set_continuation_token(token.clone())
            .send()
            .await
            .map_err(|e| translate("ListObjectsV2", &e))?;
        pages += 1;

        for object in page.contents() {
            if let Some(artifact) = artifact_from(context, object) {
                found.push(artifact);
            }
        }

        // The next page's marker is the only reliable stopping condition:
        // `is_truncated` is optional in the response and there are
        // S3-compatible servers that do not send it.
        let next = page
            .next_continuation_token()
            .map(ToString::to_string)
            .filter(|t| !t.is_empty());
        match next {
            None => break,
            // A server that repeated the marker would leave this loop asking
            // for the same page forever. It is the same thing the SDK's
            // paginator does with `stop_on_duplicate_token`.
            Some(t) if Some(&t) == token.as_ref() => {
                tracing::warn!(
                    "R2 repeated the continuation marker while listing: the listing is cut off here"
                );
                break;
            }
            Some(t) => token = Some(t),
        }
    }

    tracing::debug!(
        prefix = %prefix,
        pages,
        artifacts = found.len(),
        "listing complete"
    );
    Ok(found)
}

/// Translates an S3 object into an artifact. `None` if it carries no key, which
/// should not happen and gives nothing to return to the core.
fn artifact_from(context: &Context, object: &Object) -> Option<Artifact> {
    let key = object.key()?;
    Some(Artifact {
        key: keys::without_prefix(key, context.config.prefix()),
        // A negative size does not exist in S3; if one arrived, zero is more
        // honest than a huge number from wrapping around.
        size: u64::try_from(object.size().unwrap_or(0)).unwrap_or(0),
        modified_at: object.last_modified().map(timestamp).unwrap_or_default(),
    })
}

/// The date in the format the `.proto` fixes: RFC-3339 UTC **without
/// fractional seconds**.
///
/// Truncating to seconds is not cosmetic. R2 returns milliseconds and the test
/// storage target does not have them, so without truncating the two targets
/// produce strings that **cannot be sorted against each other**: `...:15Z` and
/// `...:15.983Z` compare at character 19, where `Z` is greater than `.`, and
/// the older artifact comes out ahead of the newer one. The integration test
/// against `MinIO` uncovered it, comparing what this plugin returns with what
/// the contract promises.
fn timestamp(instant: &DateTime) -> String {
    DateTime::from_secs(instant.secs())
        .fmt(DateTimeFormat::DateTime)
        .unwrap_or_default()
}

/// Deletes `key`. **It is idempotent**: deleting what is already gone is not an
/// error.
///
/// Retention is retried, and a retry that succeeds -- because the previous pass
/// already deleted half of it -- cannot turn into a failure of the whole
/// operation.
///
/// # Errors
///
/// The already scrubbed reason if R2 fails for something other than the
/// object's absence.
pub async fn delete(context: &Context, key: &str) -> Result<(), Status> {
    match context
        .client
        .delete_object()
        .bucket(&context.config.bucket)
        .key(key)
        .send()
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            let reason = translate("DeleteObject", &e);
            // S3 answers 204 when deleting something that does not exist, but
            // not every compatible server does; one that answers 404 must not
            // make the retention pass fail either.
            if reason.is_missing() {
                tracing::debug!(key = %key, "deletion of an artifact that was already gone");
                return Ok(());
            }
            Err(reason.into())
        }
    }
}

/// Aborts every incomplete multipart upload under `prefix` and returns how many
/// there were. It is what backs `shieldbk storage gc`.
///
/// It paginates with the pair of markers `ListMultipartUploads` uses -- key and
/// `upload_id` -- because one key may have several open uploads and the key
/// alone does not tell them apart.
///
/// The prefix filter is applied by **this code**, not by the server: see the
/// comment inside the loop.
///
/// # Errors
///
/// The already scrubbed reason if the listing or any of the aborts fails.
pub async fn abort_incomplete(context: &Context, prefix: &str) -> Result<u32, Status> {
    let mut aborted = 0_u32;
    // The pair of markers travels together: `upload_id_marker` without its
    // `key_marker` means nothing.
    let mut marker: Option<(String, Option<String>)> = None;

    loop {
        let (key_from, id_from) = match &marker {
            Some((key, id)) => (Some(key.clone()), id.clone()),
            None => (None, None),
        };
        // **No `prefix` in the request, on purpose.** The parameter exists in
        // the API, but not every S3-compatible server implements it: `MinIO`
        // only returns something when the prefix is the object's full name, and
        // with any partial prefix it answers an empty list. Trusting it turns
        // `shieldbk storage gc` into an operation that **says it aborted zero
        // and stays perfectly happy** while the orphaned parts keep being
        // billed. A filter that does not filter is visible; one that returns
        // empty is not.
        //
        // The filtering happens down below, on the key. Fetching the uploads
        // for the whole bucket costs something, but uploads in progress are few
        // by definition: the ones that survive are failures, not normal
        // traffic.
        let page = context
            .client
            .list_multipart_uploads()
            .bucket(&context.config.bucket)
            .set_key_marker(key_from)
            .set_upload_id_marker(id_from)
            .send()
            .await
            .map_err(|e| translate("ListMultipartUploads", &e))?;

        for upload in page.uploads() {
            let (Some(key), Some(id)) = (upload.key(), upload.upload_id()) else {
                continue;
            };
            // What is not under the prefix is not ours. In a shared bucket,
            // aborting somebody else's upload would destroy their backup
            // halfway through.
            if !key.starts_with(prefix) {
                continue;
            }
            context
                .client
                .abort_multipart_upload()
                .bucket(&context.config.bucket)
                .key(key)
                .upload_id(id)
                .send()
                .await
                .map_err(|e| translate("AbortMultipartUpload", &e))?;
            aborted = aborted.saturating_add(1);
            tracing::info!(key = %key, "incomplete multipart upload aborted");
        }

        if page.is_truncated() != Some(true) {
            break;
        }
        let next = page.next_key_marker().map(|key| {
            (
                key.to_string(),
                page.next_upload_id_marker().map(ToString::to_string),
            )
        });
        match next {
            // Truncated but with no marker: there is no way to ask for the next
            // page. It is cut off and said out loud, because there are uploads
            // left unaborted and they keep being billed.
            None => {
                tracing::warn!(
                    "R2 said the listing of incomplete uploads continued but sent no marker: \
                     some may be left unaborted"
                );
                break;
            }
            Some(s) if Some(&s) == marker.as_ref() => {
                tracing::warn!(
                    "R2 repeated the incomplete-uploads marker: the listing is cut off here"
                );
                break;
            }
            Some(s) => marker = Some(s),
        }
    }

    Ok(aborted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_date_comes_out_as_rfc3339_utc_with_second_precision() {
        // 1 771 234 200 = 2026-02-16T09:30:00Z.
        assert_eq!(
            timestamp(&DateTime::from_secs(1_771_234_200)),
            "2026-02-16T09:30:00Z"
        );
    }

    #[test]
    fn the_milliseconds_r2_sends_are_trimmed() {
        // Without trimming it would come out as `2026-02-16T09:30:00.983Z`,
        // which sorts **behind** a `2026-02-16T09:30:00Z` from another target
        // even though it is later: at character 19 `.` is compared against `Z`.
        let with_millis = DateTime::from_secs_and_nanos(1_771_234_200, 983_000_000);
        let trimmed = timestamp(&with_millis);
        assert_eq!(trimmed, "2026-02-16T09:30:00Z");
        assert_eq!(trimmed.len(), 20);
        assert!(trimmed > timestamp(&DateTime::from_secs(1_771_234_199)));
    }
}
