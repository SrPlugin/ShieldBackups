//! The drill: a scratch directory to restore into, and a few questions to ask it.
//!
//! The mock has no database, so its disposable place is a directory inside the
//! configured `dir`, and the questions are the handful a test needs to make the
//! core's drill take every branch it has:
//!
//! | `check`      | answer                                                        |
//! |--------------|---------------------------------------------------------------|
//! | `restored`   | passes if something non-empty landed in the scratch directory |
//! | `size=N`     | passes if exactly `N` bytes landed there                      |
//! | `error`      | the check cannot be asked at all (an RPC error, not `ok=false`) |
//!
//! Two marker files in `dir` make the other steps fail on demand, because a test
//! cannot reach into the plugin's process to flip a flag:
//! [`FAIL_PROVISION_MARKER`] and [`FAIL_TEARDOWN_MARKER`].
//!
//! Every call is appended to [`CALLS_FILE`], which is how a test proves the
//! teardown ran after a failure: the order of the lines is the order of the RPCs.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use sb_plugin_sdk::sb_proto::drill_server::Drill;
use sb_plugin_sdk::sb_proto::{
    CheckRequest, CheckResponse, ProvisionRequest, ProvisionResponse, TeardownRequest,
    TeardownResponse,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};
use tokio::io::AsyncWriteExt as _;

use crate::config::{Config, State};
use crate::source::RESTORE_FILE;

/// Directory, inside the configured `dir`, restores land in during a drill.
pub const SCRATCH_DIR: &str = "drill-scratch";
/// File, inside `dir`, every drill RPC is appended to, one line each.
pub const CALLS_FILE: &str = "drill-calls.log";
/// While this file exists in `dir`, `Provision` fails.
pub const FAIL_PROVISION_MARKER: &str = "drill-fail-provision";
/// While this file exists in `dir`, `Teardown` fails.
pub const FAIL_TEARDOWN_MARKER: &str = "drill-fail-teardown";

/// Where restores land right now, shared between the source and the drill.
///
/// `None` is the normal state: restores go to the configured `dir`. Only between
/// `Provision` and `Teardown` is it a scratch directory, and that is what keeps a
/// drill from ever writing over what the plugin was configured to back up.
#[derive(Clone, Default)]
pub struct Scratch(Arc<Mutex<Option<PathBuf>>>);

impl Scratch {
    fn get(&self) -> Option<PathBuf> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set(&self, value: Option<PathBuf>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = value;
    }

    /// The file a restore writes to: the scratch directory's during a drill, the
    /// configured `dir`'s otherwise.
    #[must_use]
    pub fn restore_file(&self, config: &Config) -> PathBuf {
        self.get()
            .unwrap_or_else(|| config.dir.clone())
            .join(RESTORE_FILE)
    }
}

pub struct MockDrill {
    state: State,
    scratch: Scratch,
}

impl MockDrill {
    #[must_use]
    pub fn new(state: State, scratch: Scratch) -> Self {
        Self { state, scratch }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Drill for MockDrill {
    async fn provision(
        &self,
        _: Request<ProvisionRequest>,
    ) -> Result<Response<ProvisionResponse>, Status> {
        let config = self.state.resolved()?;
        log(&config, "provision").await;

        if config.dir.join(FAIL_PROVISION_MARKER).exists() {
            return Err(Status::permission_denied(
                "the mock was told to fail the provision",
            ));
        }
        // A second `Provision` without a `Teardown` would orphan the first
        // scratch directory: refused instead of silently replaced.
        if self.scratch.get().is_some() {
            return Err(Status::failed_precondition(
                "a scratch place is already provisioned: Teardown it first",
            ));
        }

        let path = config.dir.join(SCRATCH_DIR);
        tokio::fs::create_dir_all(&path).await.map_err(|source| {
            Status::internal(format!("could not create `{}`: {source}", path.display()))
        })?;
        let description = path.display().to_string();
        self.scratch.set(Some(path));
        Ok(Response::new(ProvisionResponse { description }))
    }

    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let config = self.state.resolved()?;
        let query = request.into_inner().query;
        log(&config, &format!("check {query}")).await;

        let Some(scratch) = self.scratch.get() else {
            return Err(Status::failed_precondition(
                "nothing is provisioned: call Provision, and restore, before Check",
            ));
        };
        let landed = tokio::fs::metadata(scratch.join(RESTORE_FILE))
            .await
            .map(|m| m.len())
            .ok();

        let (ok, detail) = match query.as_str() {
            "restored" => match landed {
                Some(bytes) if bytes > 0 => (true, format!("{bytes} bytes landed")),
                _ => (false, "nothing landed in the scratch directory".to_owned()),
            },
            "error" => return Err(Status::internal("the mock cannot ask that question")),
            other => match other.strip_prefix("size=").map(str::parse::<u64>) {
                Some(Ok(want)) => match landed {
                    Some(got) if got == want => (true, format!("{got} bytes, as expected")),
                    got => (
                        false,
                        format!("expected {want} bytes, found {}", got.unwrap_or(0)),
                    ),
                },
                _ => {
                    return Err(Status::invalid_argument(format!(
                        "the mock does not understand the check `{other}`"
                    )));
                }
            },
        };
        Ok(Response::new(CheckResponse { ok, detail }))
    }

    async fn teardown(
        &self,
        _: Request<TeardownRequest>,
    ) -> Result<Response<TeardownResponse>, Status> {
        // Idempotent: the core calls it whatever happened before, so it also has
        // to work on a plugin that was never configured or never provisioned.
        if let Ok(config) = self.state.resolved() {
            log(&config, "teardown").await;
            if config.dir.join(FAIL_TEARDOWN_MARKER).exists() {
                return Err(Status::internal("the mock was told to fail the teardown"));
            }
        }
        if let Some(path) = self.scratch.get() {
            tokio::fs::remove_dir_all(&path).await.map_err(|source| {
                Status::internal(format!("could not remove `{}`: {source}", path.display()))
            })?;
            self.scratch.set(None);
        }
        Ok(Response::new(TeardownResponse {}))
    }
}

/// Appends one line to [`CALLS_FILE`]. A failure to log is not the drill's
/// failure: the log is there for tests to read, not for the operation to depend on.
async fn log(config: &Config, line: &str) {
    let _ = tokio::fs::create_dir_all(&config.dir).await;
    let Ok(mut file) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(config.dir.join(CALLS_FILE))
        .await
    else {
        return;
    };
    let _ = file.write_all(format!("{line}\n").as_bytes()).await;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sb_plugin_sdk::sb_proto::{Value, value::Kind};
    use sb_plugin_sdk::tonic::Code;

    use super::*;

    fn configured(dir: &std::path::Path) -> (MockDrill, Scratch, Config) {
        let map = HashMap::from([(
            "dir".to_string(),
            Value {
                kind: Some(Kind::StringValue(dir.display().to_string())),
            },
        )]);
        let config = Config::from_map(&map).unwrap();
        let state = State::default();
        state.store(config.clone());
        let scratch = Scratch::default();
        (MockDrill::new(state, scratch.clone()), scratch, config)
    }

    async fn check(drill: &MockDrill, query: &str) -> Result<CheckResponse, Status> {
        drill
            .check(Request::new(CheckRequest {
                query: query.into(),
            }))
            .await
            .map(Response::into_inner)
    }

    #[tokio::test]
    async fn a_restore_during_a_drill_never_lands_where_the_plugin_backs_up_from() {
        // The property the whole feature rests on.
        let dir = tempfile::tempdir().unwrap();
        let (drill, scratch, config) = configured(dir.path());

        assert_eq!(scratch.restore_file(&config), dir.path().join(RESTORE_FILE));
        drill
            .provision(Request::new(ProvisionRequest {}))
            .await
            .unwrap();
        assert_eq!(
            scratch.restore_file(&config),
            dir.path().join(SCRATCH_DIR).join(RESTORE_FILE)
        );
        drill
            .teardown(Request::new(TeardownRequest {}))
            .await
            .unwrap();
        assert_eq!(scratch.restore_file(&config), dir.path().join(RESTORE_FILE));
    }

    #[tokio::test]
    async fn the_checks_answer_by_what_landed() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, scratch, config) = configured(dir.path());
        drill
            .provision(Request::new(ProvisionRequest {}))
            .await
            .unwrap();

        assert!(
            !check(&drill, "restored").await.unwrap().ok,
            "nothing landed yet"
        );
        std::fs::write(scratch.restore_file(&config), b"12345").unwrap();
        assert!(check(&drill, "restored").await.unwrap().ok);
        assert!(check(&drill, "size=5").await.unwrap().ok);
        let wrong = check(&drill, "size=6").await.unwrap();
        assert!(!wrong.ok);
        assert!(wrong.detail.contains("expected 6"), "{}", wrong.detail);
    }

    #[tokio::test]
    async fn a_check_that_cannot_be_asked_is_an_error_and_not_a_negative_answer() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, _, _) = configured(dir.path());
        drill
            .provision(Request::new(ProvisionRequest {}))
            .await
            .unwrap();

        assert_eq!(
            check(&drill, "error").await.unwrap_err().code(),
            Code::Internal
        );
        assert_eq!(
            check(&drill, "what?").await.unwrap_err().code(),
            Code::InvalidArgument
        );
    }

    #[tokio::test]
    async fn checking_before_provisioning_is_a_precondition_failure() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, _, _) = configured(dir.path());
        assert_eq!(
            check(&drill, "restored").await.unwrap_err().code(),
            Code::FailedPrecondition
        );
    }

    #[tokio::test]
    async fn provisioning_twice_is_refused_and_teardown_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, _, _) = configured(dir.path());

        drill
            .provision(Request::new(ProvisionRequest {}))
            .await
            .unwrap();
        let again = drill.provision(Request::new(ProvisionRequest {})).await;
        assert_eq!(again.unwrap_err().code(), Code::FailedPrecondition);

        drill
            .teardown(Request::new(TeardownRequest {}))
            .await
            .unwrap();
        drill
            .teardown(Request::new(TeardownRequest {}))
            .await
            .unwrap();
        assert!(!dir.path().join(SCRATCH_DIR).exists());
    }

    #[tokio::test]
    async fn teardown_works_on_a_plugin_that_was_never_configured() {
        let drill = MockDrill::new(State::default(), Scratch::default());
        drill
            .teardown(Request::new(TeardownRequest {}))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_markers_make_the_steps_fail_on_demand() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, _, _) = configured(dir.path());

        std::fs::write(dir.path().join(FAIL_PROVISION_MARKER), b"").unwrap();
        let failed = drill.provision(Request::new(ProvisionRequest {})).await;
        assert_eq!(failed.unwrap_err().code(), Code::PermissionDenied);

        std::fs::remove_file(dir.path().join(FAIL_PROVISION_MARKER)).unwrap();
        std::fs::write(dir.path().join(FAIL_TEARDOWN_MARKER), b"").unwrap();
        let failed = drill.teardown(Request::new(TeardownRequest {})).await;
        assert_eq!(failed.unwrap_err().code(), Code::Internal);
    }
}
