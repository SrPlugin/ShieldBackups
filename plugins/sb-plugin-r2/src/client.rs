//! Construction of the S3 client that talks to Cloudflare R2.
//!
//! R2 exposes the S3 protocol, but **it is not S3**, and there are three
//! adjustments without which the AWS SDK produces requests that R2 rejects.
//! They are all here, in one place, each with the reason it exists: discovering
//! them costs an afternoon of unexplained 400s.

use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Region, RequestChecksumCalculation, ResponseChecksumValidation};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use sb_plugin_sdk::tonic::Status;

use crate::config::R2Config;

/// The region requests are signed with.
///
/// R2 has no regions -- there is a single endpoint per account -- but `SigV4`
/// puts the region into the string it signs, so one has to be supplied.
/// Cloudflare documents `auto` as the one their service expects; any other one
/// makes the signature not add up.
const REGION: &str = "auto";

/// Name the credentials identify themselves with in the SDK's traces. It is not
/// a secret and does not travel in the request.
const PROVIDER: &str = "shieldbk-r2";

/// What can go wrong when talking to R2.
///
/// No variant carries the AWS SDK's error inside: that error drags along the
/// request that caused it -- headers included, and among them the authorization
/// one -- and would end up in a log. From each failure only what is useful to
/// whoever reads it is extracted: the operation, the code R2 returned and the
/// HTTP status.
#[derive(Debug, thiserror::Error)]
pub enum R2Error {
    #[error("R2 answered `{operation}` with HTTP status {status} and code `{code}`")]
    Service {
        operation: &'static str,
        status: u16,
        code: String,
    },
    #[error("could not reach the R2 endpoint while running `{operation}`")]
    Transport { operation: &'static str },
    #[error("`{operation}` timed out against R2")]
    Timeout { operation: &'static str },
    #[error("could not build the `{operation}` request for R2")]
    RequestBuild { operation: &'static str },
    #[error("R2's response to `{operation}` could not be interpreted")]
    ResponseParse { operation: &'static str },
    #[error("`{operation}` failed against R2 for a reason this plugin cannot classify")]
    Unknown { operation: &'static str },
}

impl R2Error {
    /// Whether the failure means "that is not there": an object that does not
    /// exist.
    ///
    /// It is used by the download -- to answer `not_found` with the key -- and
    /// by the deletion, which is idempotent and treats absence as the result
    /// that was asked for.
    ///
    /// `NoSuchBucket` is deliberately excluded: it also comes with a 404, but a
    /// missing bucket is a configuration problem and cannot pass for "that
    /// artifact was already gone".
    #[must_use]
    pub fn is_missing(&self) -> bool {
        matches!(
            self,
            Self::Service {
                status: 404,
                code,
                ..
            } if code != "NoSuchBucket"
        )
    }
}

/// How a failure against R2 reaches the core.
///
/// The message is [`R2Error`]'s, which is already scrubbed; the only thing
/// added is the gRPC code, so that the core knows whether retrying makes sense.
/// A 403 and a 500 from R2 look nothing alike from the other side.
impl From<R2Error> for Status {
    fn from(e: R2Error) -> Self {
        let text = e.to_string();
        match e {
            R2Error::Service { status, .. } => match status {
                401 | 403 => Self::permission_denied(text),
                404 => Self::not_found(text),
                // A 5xx from R2 is the case where retrying is worth something.
                500..=599 => Self::unavailable(text),
                _ => Self::internal(text),
            },
            R2Error::Transport { .. } => Self::unavailable(text),
            R2Error::Timeout { .. } => Self::deadline_exceeded(text),
            _ => Self::internal(text),
        }
    }
}

/// Translates an AWS SDK error into one of ours, keeping only what can be
/// shown.
pub fn translate<E: ProvideErrorMetadata>(operation: &'static str, error: &SdkError<E>) -> R2Error {
    match error {
        SdkError::ServiceError(e) => R2Error::Service {
            operation,
            status: e.raw().status().as_u16(),
            // `code()` is S3's short code -- `NoSuchBucket`, `AccessDenied` --
            // which is text from the service and not from the request.
            code: e.err().code().unwrap_or("unknown").to_string(),
        },
        SdkError::DispatchFailure(_) => R2Error::Transport { operation },
        SdkError::TimeoutError(_) => R2Error::Timeout { operation },
        SdkError::ConstructionFailure(_) => R2Error::RequestBuild { operation },
        SdkError::ResponseError(_) => R2Error::ResponseParse { operation },
        // `SdkError` is `non_exhaustive`: a new SDK variant must not sneak
        // through to the log with its original message.
        _ => R2Error::Unknown { operation },
    }
}

/// The S3 client pointing at R2, with the credentials from the configuration.
///
/// The credentials are passed explicitly and the AWS provider chain is never
/// consulted: a plugin receives its configuration from the core, and letting
/// the process environment -- variables, `~/.aws/credentials`, IMDS --
/// contribute others would make the backup get written into an account nobody
/// asked for.
#[must_use]
pub fn build(config: &R2Config) -> Client {
    let credentials = Credentials::new(
        config.access_key_id(),
        config.secret_access_key(),
        None,
        None,
        PROVIDER,
    );

    let s3 = aws_sdk_s3::Config::builder()
        // Without the `behavior-version-latest` feature, the SDK requires the
        // behavior version to be pinned here instead of inferring it.
        .behavior_version(BehaviorVersion::latest())
        // 1. R2 has no regions, but SigV4 signs including them; `auto` is the
        //    one Cloudflare documents.
        .region(Region::new(REGION))
        .endpoint_url(config.endpoint())
        .credentials_provider(credentials)
        // 2. Path style: R2's endpoint is per account, not per bucket, so the
        //    bucket goes in the path. With virtual style the SDK would put it
        //    in the host -- `bucket.account.r2.cloudflarestorage.com` -- and
        //    that name does not resolve.
        .force_path_style(true)
        // 3. Checksums only when the operation requires them. Recent SDK
        //    versions add an extra checksum by default (CRC32 in
        //    `x-amz-checksum-*`, and with streaming bodies it is sent as a
        //    trailer with `aws-chunked`) that R2 does not always accept: the
        //    failure is an unexplained 400. No integrity is lost: the one that
        //    counts is the SHA-256 the core computes over the encrypted
        //    artifact and stores in the manifest.
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
        .build();

    Client::from_conf(s3)
}

/// The configuration and the client that comes out of it, together.
///
/// It is built once in `Configure` and shared by the `Plugin` service and the
/// storage target: building the client on every RPC would re-create the
/// connection pool and the endpoint resolver for every artifact.
#[derive(Clone)]
pub struct Context {
    pub config: R2Config,
    pub client: Client,
}

/// The context shared between the plugin's services.
pub type State = sb_plugin_sdk::Configured<Context>;

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::operation::head_bucket::HeadBucketError;
    use sb_plugin_sdk::sb_proto::{Value, value::Kind};
    use std::collections::HashMap;

    const SECRET: &str = "secret-key-that-must-not-leak";

    fn values() -> HashMap<String, Value> {
        [
            ("account_id", "abc123"),
            ("bucket", "backups"),
            ("access_key_id", "AKIAEXAMPLE"),
            ("secret_access_key", SECRET),
        ]
        .into_iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                Value {
                    kind: Some(Kind::StringValue(v.to_string())),
                },
            )
        })
        .collect()
    }

    #[test]
    fn the_client_is_built_from_the_cores_configuration() {
        // Building it is already an assertion: without `behavior_version` the
        // SDK panics while assembling the configuration.
        let config = R2Config::from_values(&values()).unwrap();
        let client = build(&config);
        assert_eq!(client.config().signing_name(), "s3");
    }

    #[test]
    fn the_region_is_auto_because_sigv4_demands_one() {
        let config = R2Config::from_values(&values()).unwrap();
        let client = build(&config);
        assert_eq!(client.config().region().map(Region::as_ref), Some(REGION));
    }

    #[test]
    fn checksums_are_only_computed_when_they_are_needed() {
        let config = R2Config::from_values(&values()).unwrap();
        let client = build(&config);
        assert_eq!(
            client.config().request_checksum_calculation(),
            Some(&RequestChecksumCalculation::WhenRequired)
        );
        assert_eq!(
            client.config().response_checksum_validation(),
            Some(&ResponseChecksumValidation::WhenRequired)
        );
    }

    #[test]
    fn an_sdk_error_does_not_drag_its_original_message_along() {
        // A third-party library's error may carry inside the request that
        // caused it, authorization header included. It is translated, not
        // propagated.
        #[derive(Debug)]
        struct Leak(String);
        impl std::fmt::Display for Leak {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "Authorization: AWS4-HMAC-SHA256 {}", self.0)
            }
        }
        impl std::error::Error for Leak {}

        let original: SdkError<HeadBucketError> =
            SdkError::timeout_error(Box::new(Leak(SECRET.to_string())));
        assert!(original.to_string().contains("timeout") || !original.to_string().is_empty());

        let translated = translate("HeadBucket", &original);
        let text = translated.to_string();
        assert!(!text.contains(SECRET), "the secret leaked: {text}");
        assert!(
            text.contains("HeadBucket"),
            "it must say which operation it was"
        );
    }

    #[test]
    fn the_grpc_code_tells_the_retryable_from_the_rest() {
        // The core uses this code to decide whether to retry; a 403 and a 500
        // from R2 look nothing alike from the other side.
        let service = |status| R2Error::Service {
            operation: "PutObject",
            status,
            code: "X".into(),
        };
        assert_eq!(
            Status::from(service(403)).code(),
            sb_plugin_sdk::tonic::Code::PermissionDenied
        );
        assert_eq!(
            Status::from(service(404)).code(),
            sb_plugin_sdk::tonic::Code::NotFound
        );
        assert_eq!(
            Status::from(service(503)).code(),
            sb_plugin_sdk::tonic::Code::Unavailable
        );
        assert_eq!(
            Status::from(service(400)).code(),
            sb_plugin_sdk::tonic::Code::Internal
        );
        assert_eq!(
            Status::from(R2Error::Transport {
                operation: "PutObject"
            })
            .code(),
            sb_plugin_sdk::tonic::Code::Unavailable
        );
        assert_eq!(
            Status::from(R2Error::Timeout {
                operation: "PutObject"
            })
            .code(),
            sb_plugin_sdk::tonic::Code::DeadlineExceeded
        );
    }

    #[test]
    fn an_object_404_means_missing_and_a_bucket_one_does_not() {
        // Idempotent deletion and the download's `not_found` hang on this
        // distinction: a missing bucket cannot pass for "that artifact was
        // already gone".
        let service = |code: &str| R2Error::Service {
            operation: "GetObject",
            status: 404,
            code: code.into(),
        };
        assert!(service("NoSuchKey").is_missing());
        assert!(!service("NoSuchBucket").is_missing());
        assert!(
            !R2Error::Service {
                operation: "GetObject",
                status: 403,
                code: "AccessDenied".into(),
            }
            .is_missing(),
            "a 403 does not say the object does not exist, it says it cannot be looked at"
        );
        assert!(
            !R2Error::Transport {
                operation: "GetObject"
            }
            .is_missing()
        );
    }

    #[test]
    fn the_status_that_travels_to_the_core_keeps_the_scrubbed_message() {
        let e = R2Error::Service {
            operation: "UploadPart",
            status: 403,
            code: "AccessDenied".into(),
        };
        let text = e.to_string();
        let status = Status::from(e);
        assert_eq!(status.message(), text);
        assert!(status.message().contains("UploadPart"));
    }
}
