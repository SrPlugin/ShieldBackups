//! The five RPCs every plugin implements.

use aws_sdk_s3::primitives::ByteStream;
use sb_plugin_sdk::sb_proto::plugin_server::Plugin;
use sb_plugin_sdk::sb_proto::{
    Capability, Check, ConfigureRequest, ConfigureResponse, InfoRequest, InfoResponse,
    PROTOCOL_VERSION, PreflightRequest, PreflightResponse, SchemaRequest, SchemaResponse,
    ShutdownRequest, ShutdownResponse,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};

use crate::client::{Context, State};
use crate::config::{self, R2Config};

/// Name the plugin identifies itself with to the core.
pub const NAME: &str = "r2";

pub struct R2Plugin {
    state: State,
}

impl R2Plugin {
    #[must_use]
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Plugin for R2Plugin {
    async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
        Ok(Response::new(InfoResponse {
            name: NAME.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: PROTOCOL_VERSION,
            // Storage only: R2 keeps artifacts, it cannot dump anything.
            capabilities: vec![Capability::Storage as i32],
        }))
    }

    async fn schema(&self, _: Request<SchemaRequest>) -> Result<Response<SchemaResponse>, Status> {
        Ok(Response::new(SchemaResponse {
            fields: config::schema(),
        }))
    }

    async fn configure(
        &self,
        request: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
        let config = R2Config::from_values(&request.into_inner().config)?;
        // The client is built here and not on every RPC: this is where the core
        // expects the configuration to be validated, and building the
        // connection pool once saves doing it per artifact.
        let client = crate::client::build(&config);
        tracing::info!(
            bucket = %config.bucket,
            endpoint = %config.endpoint(),
            part_size = config.part_size,
            storage_class = config.storage_class.as_str(),
            "r2 plugin configured"
        );
        self.state.store(Context { config, client });
        Ok(Response::new(ConfigureResponse {}))
    }

    async fn preflight(
        &self,
        _: Request<PreflightRequest>,
    ) -> Result<Response<PreflightResponse>, Status> {
        // Preflight does **not** return `failed_precondition` when there is no
        // configuration: it is the diagnostic RPC and `doctor` needs a report
        // that explains what is missing, not an error that interrupts it.
        let Ok(context) = self.state.resolved() else {
            let check = Check {
                name: "configuration".into(),
                ok: false,
                detail: "the plugin has not received its configuration yet".into(),
                remediation: format!(
                    "call Configure with `{}`, `{}` and both keys before Preflight",
                    config::FIELD_ACCOUNT_ID,
                    config::FIELD_BUCKET
                ),
            };
            return Ok(Response::new(PreflightResponse {
                ok: false,
                checks: vec![check],
                server_version: String::new(),
            }));
        };

        // The three in dependency order: without an accessible bucket the other
        // two say nothing new, but they run anyway because `doctor` is there to
        // show **everything** that is wrong at once, not just the first thing.
        let checks = vec![
            check_bucket(&context).await,
            check_write(&context).await,
            check_list(&context).await,
        ];
        Ok(Response::new(PreflightResponse {
            ok: checks.iter().all(|c| c.ok),
            checks,
            server_version: format!("cloudflare-r2 ({})", context.config.endpoint()),
        }))
    }

    async fn shutdown(
        &self,
        _: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        tracing::info!("shutdown requested");
        Ok(Response::new(ShutdownResponse {}))
    }
}

/// The storage target's only real requirement: that the bucket exists and that
/// the token has access.
///
/// `HeadBucket` is the cheapest check that tells apart the three things that
/// could have been typed wrong -- account, bucket and credentials -- and it
/// writes nothing.
async fn check_bucket(context: &Context) -> Check {
    let bucket = &context.config.bucket;
    match context
        .client
        .head_bucket()
        .bucket(bucket)
        .send()
        .await
        .map_err(|e| crate::client::translate("HeadBucket", &e))
    {
        Ok(_) => Check {
            name: "bucket".into(),
            ok: true,
            detail: format!("`{bucket}` reachable at {}", context.config.endpoint()),
            remediation: String::new(),
        },
        Err(e) => Check {
            name: "bucket".into(),
            ok: false,
            detail: e.to_string(),
            remediation: format!(
                "check that the bucket `{bucket}` exists in account `{}` and that the R2 token has read and write permission on it",
                context.config.account_id
            ),
        },
    }
}

/// Prefix under which the preflight writes its probe object.
///
/// It starts with a dot and names itself so that, if a leftover is ever left
/// behind, whoever looks at the bucket knows where it came from and that it can
/// be deleted.
const PREFLIGHT_PREFIX: &str = ".shieldbk-preflight";

/// Content of the probe object. Tiny: what is being checked is the permission,
/// not the bandwidth.
const PREFLIGHT_BODY: &[u8] = b"shieldbk preflight\n";

/// This process's probe object key.
///
/// It carries the PID so that two `doctor` runs at once -- or one on each
/// machine -- do not step on each other's object and delete each other's probe.
fn probe_key(context: &Context) -> String {
    context
        .config
        .key(&format!("{PREFLIGHT_PREFIX}/{}", std::process::id()))
}

/// Checks that it is possible to **actually write**, by uploading a tiny object
/// and deleting it afterwards.
///
/// It is the only reliable check, and that is why it writes instead of asking.
/// A token with `s3:ListBucket` granted and `s3:PutObject` denied answers yes
/// to any passive check; so does a bucket policy requiring SSE-KMS with a key
/// the role cannot reach. Both blow up on the first `PUT`, halfway through the
/// first nightly backup and with the dump already made.
///
/// If the object uploads but cannot be deleted, the check stays **green** with
/// the warning in the detail: what it came to check was checked, and all that
/// is left is a twenty-byte object somebody will have to remove.
async fn check_write(context: &Context) -> Check {
    let key = probe_key(context);
    let bucket = &context.config.bucket;

    if let Err(e) = context
        .client
        .put_object()
        .bucket(bucket)
        .key(&key)
        // No `storage_class`: it goes to the standard class even if the target
        // is configured as `InfrequentAccess`, because that class bills a
        // thirty-day storage minimum and this object lives for seconds. What is
        // being checked is the write permission, and that is the same for both
        // classes.
        .body(ByteStream::from_static(PREFLIGHT_BODY))
        .send()
        .await
        .map_err(|e| crate::client::translate("PutObject", &e))
    {
        return Check {
            name: "write".into(),
            ok: false,
            detail: format!("could not write `{key}`: {e}"),
            remediation: format!(
                "give the R2 token write permission (`PutObject`) on `{bucket}`; if the bucket has a policy requiring encryption with a managed key, check that the token can use it"
            ),
        };
    }

    // Written. From here on the check is already green: whatever is missing is
    // a leftover, not an impediment to making backups.
    match crate::admin::delete(context, &key).await {
        Ok(()) => Check {
            name: "write".into(),
            ok: true,
            detail: format!("probe object written and deleted in `{bucket}`"),
            remediation: String::new(),
        },
        Err(e) => Check {
            name: "write".into(),
            ok: true,
            detail: format!(
                "writing to `{bucket}` worked, which is what was being checked, but the probe object `{key}` could not be deleted and is still there: {}",
                e.message()
            ),
            remediation: format!(
                "delete `{key}` by hand and add the `DeleteObject` permission to the token, which retention needs as well"
            ),
        },
    }
}

/// Checks that the bucket can be listed.
///
/// It asks for a single key: what is being checked is the permission, and
/// fetching a thousand names for that would be wasted work. Without listing
/// there is no `verify --all` and no retention, even though backups keep being
/// written.
async fn check_list(context: &Context) -> Check {
    let bucket = &context.config.bucket;
    match context
        .client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(context.config.key(""))
        .max_keys(1)
        .send()
        .await
        .map_err(|e| crate::client::translate("ListObjectsV2", &e))
    {
        Ok(_) => Check {
            name: "list".into(),
            ok: true,
            detail: format!("`{bucket}` can be listed"),
            remediation: String::new(),
        },
        Err(e) => Check {
            name: "list".into(),
            ok: false,
            detail: e.to_string(),
            remediation: format!(
                "give the R2 token list permission (`ListBucket`) on `{bucket}`: without it there is no `verify --all` and no retention, even though backups keep being written"
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::R2Config;
    use sb_plugin_sdk::sb_proto::{Value, value::Kind};
    use std::collections::HashMap;

    fn context(prefix: &str) -> Context {
        let values: HashMap<String, Value> = [
            ("account_id", "abc123"),
            ("bucket", "backups"),
            ("access_key_id", "AKIAEXAMPLE"),
            ("secret_access_key", "secret"),
            ("prefix", prefix),
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
        .collect();
        let config = R2Config::from_values(&values).unwrap();
        let client = crate::client::build(&config);
        Context { config, client }
    }

    #[test]
    fn the_probe_object_lives_inside_the_configured_prefix() {
        // Writing outside the prefix is writing into somebody else's bucket:
        // the token's permission may be scoped exactly to this prefix, and the
        // preflight would fail for writing where it should not.
        let key = probe_key(&context("team/backups"));
        assert!(
            key.starts_with("team/backups/"),
            "the probe key escaped the prefix: {key}"
        );
        assert!(key.contains(PREFLIGHT_PREFIX));
    }

    #[test]
    fn two_processes_at_once_do_not_step_on_the_probe_object() {
        // The PID is what prevents it; here it is only checked that it is
        // there.
        let key = probe_key(&context(""));
        assert!(
            key.ends_with(&std::process::id().to_string()),
            "the probe key does not carry the PID: {key}"
        );
    }

    #[test]
    fn the_probe_body_is_tiny() {
        // The permission is what is checked, not the bandwidth: a preflight
        // that uploaded megabytes would be run less often than it needs to be.
        assert!(PREFLIGHT_BODY.len() < 128);
        assert!(!PREFLIGHT_BODY.is_empty(), "an empty object proves less");
    }
}
