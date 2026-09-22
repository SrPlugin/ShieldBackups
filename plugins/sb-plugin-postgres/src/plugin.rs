//! The five RPCs every plugin implements.

use std::process::Stdio;

use sb_plugin_sdk::sb_proto::plugin_server::Plugin;
use sb_plugin_sdk::sb_proto::{
    Capability, Check, ConfigureRequest, ConfigureResponse, InfoRequest, InfoResponse,
    PROTOCOL_VERSION, PreflightRequest, PreflightResponse, SchemaRequest, SchemaResponse,
    ShutdownRequest, ShutdownResponse,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};

use crate::command::{self, Running};
use crate::config::{self, Config, State};

/// Name the plugin identifies itself with to the core.
pub const NAME: &str = "postgres";

pub struct PostgresPlugin {
    state: State,
}

impl PostgresPlugin {
    #[must_use]
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[sb_plugin_sdk::tonic::async_trait]
impl Plugin for PostgresPlugin {
    async fn info(&self, _: Request<InfoRequest>) -> Result<Response<InfoResponse>, Status> {
        Ok(Response::new(InfoResponse {
            name: NAME.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: PROTOCOL_VERSION,
            // Source only: a database is dumped and restored, never stored.
            capabilities: vec![Capability::Source as i32],
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
            host = %config.host,
            port = config.port,
            database = %config.database,
            user = %config.user,
            "postgres plugin configured"
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
        let Ok(config) = self.state.resolved() else {
            let check = Check {
                name: "configuration".into(),
                ok: false,
                detail: "the plugin has not received its configuration yet".into(),
                remediation: format!(
                    "call Configure with `{}`, `{}` and `{}` before Preflight",
                    config::FIELD_HOST,
                    config::FIELD_DATABASE,
                    config::FIELD_USER
                ),
            };
            return Ok(Response::new(PreflightResponse {
                ok: false,
                checks: vec![check],
                source_version: String::new(),
            }));
        };

        // Order matters: without a reachable `pg_dump` the connection check
        // could not run anyway, so the two binaries are checked first and the
        // one real network probe -- the expensive, meaningful one -- last.
        let checks = vec![
            check_binary("pg_dump", &config.pg_dump_path, config::FIELD_PG_DUMP_PATH).await,
            check_binary(
                "pg_restore",
                &config.pg_restore_path,
                config::FIELD_PG_RESTORE_PATH,
            )
            .await,
            check_connection(&config).await,
        ];
        let source_version = checks
            .iter()
            .find(|c| c.name == "pg_dump")
            .map(|c| c.detail.clone())
            .unwrap_or_default();
        Ok(Response::new(PreflightResponse {
            ok: checks.iter().all(|c| c.ok),
            checks,
            source_version,
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

/// Checks that `path` runs at all, with `--version`: the cheapest possible
/// probe, and the one that tells "not installed" apart from "installed but
/// cannot reach the server", which [`check_connection`] covers instead.
async fn check_binary(name: &'static str, path: &str, field: &'static str) -> Check {
    let remediation = format!(
        "install `postgresql-client` (or your distribution's equivalent) so `{name}` is on PATH, \
         or point the target's `{field}` at its binary"
    );
    match tokio::process::Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
    {
        Ok(output) if output.status.success() => Check {
            name: name.into(),
            ok: true,
            detail: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            remediation: String::new(),
        },
        Ok(output) => Check {
            name: name.into(),
            ok: false,
            detail: format!("`{path} --version` exited with {}", output.status),
            remediation,
        },
        Err(e) => Check {
            name: name.into(),
            ok: false,
            detail: format!("could not start `{path}`: {e}"),
            remediation,
        },
    }
}

/// Checks that the target is actually reachable, by running `pg_dump
/// --schema-only` and discarding its output.
///
/// It is the only reliable check: a passive check -- resolving the host, or
/// opening the TCP port -- says nothing about authentication or about
/// whether `database` exists, and both are exactly what fails a nightly
/// backup at three in the morning if left undiagnosed here.
async fn check_connection(config: &Config) -> Check {
    let target = format!(
        "`{}` on {}:{} as `{}`",
        config.database, config.host, config.port, config.user
    );
    let mut args = command::dump_args(config);
    args.push("--schema-only".into());
    let outcome = match Running::spawn(
        "pg_dump",
        &config.pg_dump_path,
        &args,
        config,
        Stdio::null(),
        Stdio::null(),
    ) {
        Ok(running) => running.settle().await,
        Err(e) => Err(e),
    };
    match outcome {
        Ok(()) => Check {
            name: "connection".into(),
            ok: true,
            detail: format!("connected to {target}"),
            remediation: String::new(),
        },
        Err(e) => Check {
            name: "connection".into(),
            ok: false,
            detail: e.message().to_string(),
            remediation: format!(
                "check host, port, database, user and password for {target}, and that the \
                 server accepts connections from this machine"
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt as _;

    use sb_plugin_sdk::sb_proto::plugin_server::Plugin as _;
    use sb_plugin_sdk::sb_proto::{
        Capability, ConfigureRequest, InfoRequest, PreflightRequest, SchemaRequest,
    };
    use sb_plugin_sdk::sb_proto::{Value, value::Kind};
    use sb_plugin_sdk::tonic::{Code, Request};
    use tempfile::TempDir;

    use super::PostgresPlugin;
    use crate::config::{self, State};

    fn text(s: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(s.into())),
        }
    }

    fn valid_map() -> HashMap<String, Value> {
        HashMap::from([
            (config::FIELD_HOST.to_string(), text("db.internal")),
            (config::FIELD_DATABASE.to_string(), text("app")),
            (config::FIELD_USER.to_string(), text("backup")),
        ])
    }

    fn plugin() -> PostgresPlugin {
        PostgresPlugin::new(State::default())
    }

    /// Writes an executable shell script and returns the directory that owns
    /// it and the script's path -- the directory is kept alive by the caller
    /// so the file survives until the test is done with it.
    fn stub(body: &str) -> (TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stub.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Freshly written and chmod'd executables occasionally answer their
        // very first `execve` with `ETXTBSY` on this sandbox's filesystem --
        // some other process (a file-access watcher, not this test) still has
        // it open a moment after `set_permissions` returns. One throwaway
        // `--help` run absorbs that race before the real assertions spawn it.
        let _ = std::process::Command::new(&path).arg("--help").output();
        let text = path.display().to_string();
        (dir, text)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn info_announces_only_the_source_capability() {
        let info = plugin()
            .info(Request::new(InfoRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(info.name, super::NAME);
        assert_eq!(info.capabilities, vec![Capability::Source as i32]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn schema_publishes_exactly_configs_fields() {
        let schema = plugin()
            .schema(Request::new(SchemaRequest {}))
            .await
            .unwrap()
            .into_inner();
        let names: Vec<String> = schema.fields.iter().map(|f| f.name.clone()).collect();
        let expected: Vec<String> = config::fields().into_iter().map(|f| f.name).collect();
        assert_eq!(names, expected);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn configure_with_a_valid_map_is_accepted_and_resolvable() {
        let state = State::default();
        let p = PostgresPlugin::new(state.clone());
        p.configure(Request::new(ConfigureRequest {
            config: valid_map(),
        }))
        .await
        .unwrap();
        assert_eq!(state.resolved().unwrap().host, "db.internal");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn configure_with_an_invalid_map_is_rejected() {
        let p = plugin();
        let mut map = valid_map();
        map.remove(config::FIELD_HOST);
        let e = p
            .configure(Request::new(ConfigureRequest { config: map }))
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn preflight_without_configure_reports_it_instead_of_failing() {
        let pf = plugin()
            .preflight(Request::new(PreflightRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(!pf.ok);
        assert_eq!(pf.checks.len(), 1);
        assert_eq!(pf.checks[0].name, "configuration");
        assert!(!pf.checks[0].remediation.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn preflight_reports_a_binary_that_is_not_on_path() {
        let state = State::default();
        let p = PostgresPlugin::new(state.clone());
        let mut map = valid_map();
        map.insert(
            config::FIELD_PG_DUMP_PATH.to_string(),
            text("/no/such/pg_dump"),
        );
        p.configure(Request::new(ConfigureRequest { config: map }))
            .await
            .unwrap();

        let pf = p
            .preflight(Request::new(PreflightRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(!pf.ok);
        let pg_dump = pf.checks.iter().find(|c| c.name == "pg_dump").unwrap();
        assert!(!pg_dump.ok);
        assert!(!pg_dump.remediation.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn preflight_passes_every_check_when_the_stubs_all_succeed() {
        let (_dump_dir, dump_path) = stub("exit 0");
        let (_restore_dir, restore_path) = stub("exit 0");
        let state = State::default();
        let p = PostgresPlugin::new(state.clone());
        let mut map = valid_map();
        map.insert(config::FIELD_PG_DUMP_PATH.to_string(), text(&dump_path));
        map.insert(
            config::FIELD_PG_RESTORE_PATH.to_string(),
            text(&restore_path),
        );
        p.configure(Request::new(ConfigureRequest { config: map }))
            .await
            .unwrap();

        let pf = p
            .preflight(Request::new(PreflightRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(pf.ok, "{:?}", pf.checks);
        let names: Vec<&str> = pf.checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["pg_dump", "pg_restore", "connection"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn preflight_reports_a_connection_that_the_stub_refuses() {
        let (_dump_dir, dump_path) = stub("echo 'could not connect to server' >&2; exit 1");
        let (_restore_dir, restore_path) = stub("exit 0");
        let state = State::default();
        let p = PostgresPlugin::new(state.clone());
        let mut map = valid_map();
        map.insert(config::FIELD_PG_DUMP_PATH.to_string(), text(&dump_path));
        map.insert(
            config::FIELD_PG_RESTORE_PATH.to_string(),
            text(&restore_path),
        );
        p.configure(Request::new(ConfigureRequest { config: map }))
            .await
            .unwrap();

        let pf = p
            .preflight(Request::new(PreflightRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(!pf.ok);
        let connection = pf.checks.iter().find(|c| c.name == "connection").unwrap();
        assert!(!connection.ok);
        assert!(
            connection.detail.contains("could not connect to server"),
            "{}",
            connection.detail
        );
        assert!(!connection.remediation.is_empty());
    }
}
