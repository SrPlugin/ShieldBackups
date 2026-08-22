//! The five RPCs every plugin implements.

use sb_plugin_sdk::sb_proto::plugin_server::Plugin;
use sb_plugin_sdk::sb_proto::{
    Capability, Check, ConfigureRequest, ConfigureResponse, InfoRequest, InfoResponse,
    PROTOCOL_VERSION, PreflightRequest, PreflightResponse, SchemaRequest, SchemaResponse,
    ShutdownRequest, ShutdownResponse,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};

use crate::config::{self, Config, State};

/// Name the plugin identifies itself with to the core.
pub const NAME: &str = "mock";

pub struct MockPlugin {
    state: State,
}

impl MockPlugin {
    #[must_use]
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Plugin for MockPlugin {
    async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
        Ok(Response::new(InfoResponse {
            name: NAME.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: vec![Capability::Source as i32, Capability::Storage as i32],
        }))
    }

    async fn schema(&self, _: Request<SchemaRequest>) -> Result<Response<SchemaResponse>, Status> {
        Ok(Response::new(SchemaResponse {
            fields: config::fields(),
        }))
    }

    async fn configure(
        &self,
        request: Request<ConfigureRequest>,
    ) -> Result<Response<ConfigureResponse>, Status> {
        let config = Config::from_map(&request.into_inner().config)?;
        tracing::info!(
            dir = %config.dir.display(),
            seed = config.seed,
            size = config.size,
            "mock plugin configured"
        );
        self.state.store(config);
        Ok(Response::new(ConfigureResponse {}))
    }

    async fn preflight(
        &self,
        _: Request<PreflightRequest>,
    ) -> Result<Response<PreflightResponse>, Status> {
        // Preflight does **not** return `failed_precondition` when there is no
        // configuration: it is the diagnostic RPC, and `doctor` needs a report
        // that explains what is missing, not an error that interrupts it.
        let check = match self.state.resolved() {
            Ok(config) => check_directory(&config),
            Err(_) => Check {
                name: "configuration".into(),
                ok: false,
                detail: "the plugin has not received its configuration yet".into(),
                remediation: format!(
                    "call Configure with the `{}` field before Preflight",
                    config::FIELD_DIR
                ),
            },
        };
        Ok(Response::new(PreflightResponse {
            ok: check.ok,
            checks: vec![check],
            source_version: NAME.into(),
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

/// The plugin's only real requirement: being able to write into `dir`.
fn check_directory(config: &Config) -> Check {
    let dir = &config.dir;
    if dir.is_dir() {
        return Check {
            name: "directory".into(),
            ok: true,
            detail: format!("{} exists", dir.display()),
            remediation: String::new(),
        };
    }
    match std::fs::create_dir_all(dir) {
        Ok(()) => Check {
            name: "directory".into(),
            ok: true,
            detail: format!("{} created", dir.display()),
            remediation: String::new(),
        },
        Err(e) => Check {
            name: "directory".into(),
            ok: false,
            detail: format!("could not create {}: {e}", dir.display()),
            remediation: format!(
                "create {} by hand or point `{}` at a path this user can write to",
                dir.display(),
                config::FIELD_DIR
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn preflight_creates_the_directory_if_it_is_missing() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("not/created");
        let check = check_directory(&Config {
            dir: dir.clone(),
            seed: 1,
            size: 0,
        });
        assert!(check.ok, "{}", check.detail);
        assert!(dir.is_dir());
    }

    #[test]
    fn preflight_fails_with_a_remedy_if_it_cannot_create_it() {
        // A file occupying the directory's place: it cannot be created.
        let root = tempfile::tempdir().unwrap();
        let blocker = root.path().join("blocker");
        std::fs::write(&blocker, b"i am not a directory").unwrap();
        let check = check_directory(&Config {
            dir: blocker.join("inside"),
            seed: 1,
            size: 0,
        });
        assert!(!check.ok);
        assert!(
            !check.remediation.is_empty(),
            "a failing check without a remedy is useless"
        );
    }

    #[test]
    fn an_existing_directory_passes_without_touching_anything() {
        let root = tempfile::tempdir().unwrap();
        let check = check_directory(&Config {
            dir: PathBuf::from(root.path()),
            seed: 1,
            size: 0,
        });
        assert!(check.ok);
        assert!(check.remediation.is_empty());
    }
}
