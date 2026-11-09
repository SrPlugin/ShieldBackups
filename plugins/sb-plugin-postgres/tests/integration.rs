// The whole file is test code: bringing up containers, assembling the
// configuration and the docker-wrapped `pg_dump`/`pg_restore` are too, and
// there an `unwrap` is exactly what is wanted -- for the test to blow up
// where it failed, with its line number.
#![allow(clippy::unwrap_used)]

//! The `PostgreSQL` plugin, against a real server -- and a real `pg_dump` /
//! `pg_restore`, neither of which is installed on this machine.
//!
//! ## Why everything runs through Docker
//!
//! This plugin is a thin wrapper: it never speaks the `PostgreSQL` wire
//! protocol itself, it shells out to `pg_dump`/`pg_restore`. Testing it for
//! real therefore needs both a server **and** those two client binaries.
//! Neither is installed here, and this file installs neither:
//!
//! * The **server** is `testcontainers_modules::postgres::Postgres`, the same
//!   "real thing in Docker, no local install" pattern `sb-plugin-r2`'s
//!   integration test uses with `MinIO`.
//! * `pg_dump`/`pg_restore` themselves are also never installed. Each test
//!   points the plugin's `pg_dump_path`/`pg_restore_path` at a tiny wrapper
//!   script ([`docker_wrapper`]) that runs `docker run --network host
//!   postgres:11-alpine pg_dump "$@"` instead of a local binary. `--network
//!   host` is what lets that containerized client reach the server container
//!   through the same `127.0.0.1:<mapped-port>` a local binary would use, so
//!   `Config`'s `host`/`port` mean the same thing either way -- this is
//!   exactly the "point `pg_dump_path` at a wrapper" escape hatch
//!   `command.rs` was built to allow, exercised here because it is also what
//!   this environment needs to run the suite at all.
//!
//! Verifying what actually landed in the target database goes through
//! `psql`, run the same way -- **not** a Rust `PostgreSQL` driver, so this
//! crate's only dependencies stay the ones production needs.
//!
//! ## Docker
//!
//! Without Docker there is no server and these tests skip themselves, saying
//! so on stderr.

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use sb_plugin_postgres::config::{self, Config, State};
use sb_plugin_postgres::drill::{PostgresDrill, Scratch};
use sb_plugin_postgres::plugin::PostgresPlugin;
use sb_plugin_postgres::source::PostgresSource;
use sb_plugin_sdk::sb_proto::drill_client::DrillClient;
use sb_plugin_sdk::sb_proto::drill_server::Drill as _;
use sb_plugin_sdk::sb_proto::plugin_client::PluginClient;
use sb_plugin_sdk::sb_proto::plugin_server::Plugin as _;
use sb_plugin_sdk::sb_proto::source_client::SourceClient;
use sb_plugin_sdk::sb_proto::source_server::Source as _;
use sb_plugin_sdk::sb_proto::value::Kind;
use sb_plugin_sdk::sb_proto::{
    CheckRequest, ConfigureRequest, DumpRequest, PreflightRequest, ProvisionRequest,
    RestoreRequest, TeardownRequest, Value,
};
use sb_plugin_sdk::tonic::transport::Channel;
use sb_plugin_sdk::tonic::{Code, Request, Status};
use sb_transport::{Bootstrap, DataChannel, EphemeralPki, Ready, connect_control};
use tempfile::TempDir;
use testcontainers::ContainerAsync;
use testcontainers::runners::AsyncRunner as _;
use testcontainers_modules::postgres::Postgres;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The tag `testcontainers_modules::postgres::Postgres` starts. Pinned here
/// too, for the docker-wrapped `pg_dump`/`pg_restore`: matching versions
/// sidesteps any question of forward/backward compatibility between the
/// server and the client, which is not what these tests are about.
const PG_IMAGE: &str = "postgres:11-alpine";

// ---------------------------------------------------------------------------
// Docker
// ---------------------------------------------------------------------------

/// Whether there is a container daemon testcontainers can talk to.
fn has_docker() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        Command::new("docker")
            .args(["info", "--format", "{{.ServerVersion}}"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

macro_rules! function_name {
    () => {{
        fn f() {}
        let name = std::any::type_name_of_val(&f);
        name.strip_suffix("::f")
            .unwrap_or(name)
            .rsplit("::")
            .find(|segment| !segment.starts_with("{{"))
            .unwrap_or(name)
    }};
}

/// Leaves the test without failing if there is no Docker, saying why.
macro_rules! skip_without_docker {
    () => {
        if !has_docker() {
            eprintln!(
                "SKIPPED {}::{}: no Docker available, so neither the PostgreSQL server nor the \
                 `pg_dump`/`pg_restore` this plugin is tested against can run. Start Docker and \
                 run it again.",
                module_path!(),
                function_name!()
            );
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// The server and the docker-wrapped clients
// ---------------------------------------------------------------------------

struct Server {
    _container: ContainerAsync<Postgres>,
    host: String,
    port: u16,
}

async fn start_postgres(init_sql: Option<&str>) -> Server {
    let mut image = Postgres::default();
    if let Some(sql) = init_sql {
        image = image.with_init_sql(sql.to_string().into_bytes());
    }
    let container = image.start().await.unwrap();
    let host = container.get_host().await.unwrap().to_string();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    Server {
        _container: container,
        host,
        port,
    }
}

/// Writes a wrapper script that runs `binary` (`pg_dump` or `pg_restore`)
/// inside a throwaway `postgres:11-alpine` container instead of a local
/// install, and returns its path.
///
/// `--network host` is what makes `127.0.0.1:<port>` inside the container
/// mean the same host the mapped port is published on: without it, `host`
/// would have to be the *server* container's name on a shared Docker network
/// instead of the address `Config` already carries.
fn docker_wrapper(dir: &TempDir, binary: &str) -> String {
    let path = dir.path().join(binary);
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nexec docker run --rm -i --network host -e PGPASSWORD=\"$PGPASSWORD\" {PG_IMAGE} {binary} \"$@\"\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    path.display().to_string()
}

fn text(value: &str) -> Value {
    Value {
        kind: Some(Kind::StringValue(value.to_string())),
    }
}

/// The configuration the core would send through `Configure`, pointing at
/// `server` through the docker-wrapped clients in `dir`.
fn values(server: &Server, dir: &TempDir) -> HashMap<String, Value> {
    HashMap::from([
        (config::FIELD_HOST.to_string(), text(&server.host)),
        (
            config::FIELD_PORT.to_string(),
            Value {
                kind: Some(Kind::IntValue(i64::from(server.port))),
            },
        ),
        (config::FIELD_DATABASE.to_string(), text("postgres")),
        (config::FIELD_USER.to_string(), text("postgres")),
        (config::FIELD_PASSWORD.to_string(), text("postgres")),
        (
            config::FIELD_PG_DUMP_PATH.to_string(),
            text(&docker_wrapper(dir, "pg_dump")),
        ),
        (
            config::FIELD_PG_RESTORE_PATH.to_string(),
            text(&docker_wrapper(dir, "pg_restore")),
        ),
        // Only a restore drill runs `psql`, and it runs the same containerised way.
        (
            config::FIELD_PSQL_PATH.to_string(),
            text(&docker_wrapper(dir, "psql")),
        ),
    ])
}

/// Runs `sql` against `server`'s `postgres` database through `psql`, itself
/// run the same throwaway-container way as [`docker_wrapper`], and returns
/// its trimmed stdout.
fn psql(server: &Server, sql: &str) -> String {
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            "host",
            "-e",
            "PGPASSWORD=postgres",
            PG_IMAGE,
            "psql",
            "-h",
            &server.host,
            "-p",
            &server.port.to_string(),
            "-U",
            "postgres",
            "-d",
            "postgres",
            // Tuples only, unaligned: the output is parsed by the test, not
            // read by a human.
            "-tAc",
            sql,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "psql failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

// ---------------------------------------------------------------------------
// Dump and restore through the source, with its data channel
// ---------------------------------------------------------------------------

fn service(config: Config) -> PostgresSource {
    let state = State::new("postgres");
    state.store(config);
    PostgresSource::new(state, Scratch::default())
}

fn plugin_service(config: Config) -> PostgresPlugin {
    let state = State::new("postgres");
    state.store(config);
    PostgresPlugin::new(state)
}

async fn drain_stream(stream: sb_plugin_sdk::ProgressStream) -> Result<(), Status> {
    let mut receiver = stream.into_inner();
    while let Some(message) = receiver.recv().await {
        message?;
    }
    Ok(())
}

/// Dumps `source` and returns the artifact's bytes.
async fn dump(source: &PostgresSource, sockets: &Path) -> Result<Vec<u8>, Status> {
    let channel = DataChannel::create(sockets, "dump").unwrap();
    let path = channel.path().display().to_string();
    let stream = source
        .dump(Request::new(DumpRequest { data_socket: path }))
        .await?
        .into_inner();

    let reader = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        buf
    });
    drain_stream(stream).await?;
    Ok(reader.await.unwrap())
}

/// Restores `artifact` into `source`'s target.
async fn restore(source: &PostgresSource, sockets: &Path, artifact: Vec<u8>) -> Result<(), Status> {
    let channel = DataChannel::create(sockets, "restore").unwrap();
    let path = channel.path().display().to_string();
    let stream = source
        .restore(Request::new(RestoreRequest { data_socket: path }))
        .await?
        .into_inner();

    let writer = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        s.write_all(&artifact).await.unwrap();
        s.shutdown().await.unwrap();
    });
    let result = drain_stream(stream).await;
    match result {
        Ok(()) => {
            writer.await.unwrap();
            Ok(())
        }
        Err(e) => {
            writer.abort();
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_dump_and_restore_round_trip_preserves_the_data() {
    skip_without_docker!();
    let source_server = start_postgres(Some(
        "CREATE TABLE widgets (id serial primary key, name text not null); \
         INSERT INTO widgets (name) VALUES ('left-handed screwdriver'), ('glass hammer'), ('sky hook');",
    ))
    .await;
    let target_server = start_postgres(None).await;
    let sockets = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let source_config = Config::from_map(&values(&source_server, &dir)).unwrap();
    let artifact = dump(&service(source_config), sockets.path()).await.unwrap();
    assert!(
        !artifact.is_empty(),
        "a non-empty database dumped to nothing"
    );

    let target_config = Config::from_map(&values(&target_server, &dir)).unwrap();
    restore(&service(target_config), sockets.path(), artifact)
        .await
        .unwrap();

    let count = psql(&target_server, "SELECT count(*) FROM widgets;");
    assert_eq!(
        count, "3",
        "the restored table does not have the three rows seeded into the source"
    );

    let names = psql(&target_server, "SELECT name FROM widgets ORDER BY id;");
    assert_eq!(
        names, "left-handed screwdriver\nglass hammer\nsky hook",
        "the restored rows are not in the order (and therefore not exactly the content) they were inserted in"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_preflight_passes_against_a_reachable_server() {
    skip_without_docker!();
    let server = start_postgres(None).await;
    let dir = tempfile::tempdir().unwrap();
    let config = Config::from_map(&values(&server, &dir)).unwrap();

    let pf = plugin_service(config)
        .preflight(Request::new(PreflightRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(pf.ok, "{:?}", pf.checks);
    let names: Vec<&str> = pf.checks.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["pg_dump", "pg_restore", "connection"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_preflight_reports_a_wrong_password() {
    skip_without_docker!();
    let server = start_postgres(None).await;
    let dir = tempfile::tempdir().unwrap();
    let mut map = values(&server, &dir);
    map.insert(config::FIELD_PASSWORD.to_string(), text("not-the-password"));
    let config = Config::from_map(&map).unwrap();

    let pf = plugin_service(config)
        .preflight(Request::new(PreflightRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(!pf.ok);
    let connection = pf.checks.iter().find(|c| c.name == "connection").unwrap();
    assert!(!connection.ok);
    assert!(!connection.remediation.is_empty());
}

// ---------------------------------------------------------------------------
// The full cycle through the real binary
// ---------------------------------------------------------------------------

struct LivePlugin {
    child: Child,
    channel: Channel,
    ready: Ready,
    _sockets: TempDir,
}

impl LivePlugin {
    async fn start() -> Self {
        let sockets = tempfile::tempdir().unwrap();
        let socket = sockets.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();
        let envelope = Bootstrap::new(vec![1], socket.display().to_string(), pki.server_bundle());

        let mut child = Command::new(env!("CARGO_BIN_EXE_sb-plugin-postgres"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let mut input = child.stdin.take().unwrap();
        writeln!(input, "{}", envelope.to_line().unwrap()).unwrap();
        input.flush().unwrap();
        drop(input);

        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let ready = Ready::from_line(&line).unwrap();

        let channel = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();

        Self {
            child,
            channel,
            ready,
            _sockets: sockets,
        }
    }
}

impl Drop for LivePlugin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_full_cycle_through_the_real_plugin_binary() {
    skip_without_docker!();
    let source_server = start_postgres(Some(
        "CREATE TABLE widgets (id serial primary key, name text not null); \
         INSERT INTO widgets (name) VALUES ('gimbal lock');",
    ))
    .await;
    let target_server = start_postgres(None).await;
    let dir = tempfile::tempdir().unwrap();

    let live = LivePlugin::start().await;
    assert_eq!(live.ready.protocol_version, 1);
    assert_eq!(live.ready.capabilities, vec!["source", "drill"]);
    assert!(live.ready.pid > 0);

    PluginClient::new(live.channel.clone())
        .configure(ConfigureRequest {
            config: values(&source_server, &dir),
        })
        .await
        .unwrap();

    let pf = PluginClient::new(live.channel.clone())
        .preflight(PreflightRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(pf.ok, "{:?}", pf.checks);

    let sockets = tempfile::tempdir().unwrap();
    let mut source = SourceClient::new(live.channel.clone());

    let channel = DataChannel::create(sockets.path(), "dump").unwrap();
    let path = channel.path().display().to_string();
    let mut stream = source
        .dump(DumpRequest { data_socket: path })
        .await
        .unwrap()
        .into_inner();
    let reader = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        buf
    });
    while stream.message().await.unwrap().is_some() {}
    let artifact = reader.await.unwrap();
    assert!(!artifact.is_empty());

    // Reconfigured at the target, exactly as the core would between the
    // backup of one target and the restore of another.
    PluginClient::new(live.channel.clone())
        .configure(ConfigureRequest {
            config: values(&target_server, &dir),
        })
        .await
        .unwrap();

    let channel = DataChannel::create(sockets.path(), "restore").unwrap();
    let path = channel.path().display().to_string();
    let mut stream = source
        .restore(RestoreRequest { data_socket: path })
        .await
        .unwrap()
        .into_inner();
    let copy = artifact.clone();
    let writer = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        s.write_all(&copy).await.unwrap();
        s.shutdown().await.unwrap();
    });
    while stream.message().await.unwrap().is_some() {}
    writer.await.unwrap();

    assert_eq!(
        psql(&target_server, "SELECT name FROM widgets;"),
        "gimbal lock"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dump_before_configure_yields_failed_precondition_over_the_wire() {
    skip_without_docker!();
    let live = LivePlugin::start().await;
    let mut source = SourceClient::new(live.channel.clone());
    let e = source
        .dump(DumpRequest {
            data_socket: "/tmp/never-used".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
}

// ---------------------------------------------------------------------------
// The restore drill, against a real server
// ---------------------------------------------------------------------------

/// How many scratch databases `server` holds right now.
fn scratch_databases(server: &Server) -> String {
    psql(
        server,
        "SELECT count(*) FROM pg_database WHERE datname LIKE 'drill\\_%';",
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_drill_restores_into_a_scratch_database_and_leaves_the_real_one_alone() {
    skip_without_docker!();
    let source_server = start_postgres(Some(
        "CREATE TABLE widgets (id serial primary key, name text not null); \
         INSERT INTO widgets (name) VALUES ('one'), ('two'), ('three');",
    ))
    .await;
    // The server the drill runs on. Its own `postgres` database stands for what
    // the target is configured to back up: it has no `widgets`, and must still
    // have none when the drill is done.
    let drill_server = start_postgres(None).await;
    let sockets = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let artifact = dump(
        &service(Config::from_map(&values(&source_server, &dir)).unwrap()),
        sockets.path(),
    )
    .await
    .unwrap();

    let state = State::new("postgres");
    state.store(Config::from_map(&values(&drill_server, &dir)).unwrap());
    let scratch = Scratch::default();
    let source = PostgresSource::new(state.clone(), scratch.clone());
    let drill = PostgresDrill::new(state, scratch);

    // Provision: one scratch database appears.
    assert_eq!(scratch_databases(&drill_server), "0");
    let provisioned = drill
        .provision(Request::new(ProvisionRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(
        provisioned.description.contains("drill_"),
        "{provisioned:?}"
    );
    assert_eq!(scratch_databases(&drill_server), "1");

    // Restore: through the ordinary source, which now lands in the scratch one.
    restore(&source, sockets.path(), artifact).await.unwrap();
    assert_eq!(
        psql(
            &drill_server,
            "SELECT to_regclass('public.widgets') IS NULL;"
        ),
        "t",
        "the drill restored into the database the target is configured to back up"
    );

    // Check: the three rows are there, and the verdicts say so in words.
    let ask = |query: &str| {
        let request = Request::new(CheckRequest {
            query: query.into(),
        });
        let drill = &drill;
        async move { drill.check(request).await.unwrap().into_inner() }
    };
    let holds = ask("SELECT count(*) = 3 FROM widgets").await;
    assert!(holds.ok, "{}", holds.detail);
    let wrong = ask("SELECT count(*) = 4 FROM widgets").await;
    assert!(!wrong.ok);
    assert!(wrong.detail.contains("`f`"), "{}", wrong.detail);
    let missing = ask("SELECT count(*) > 0 FROM no_such_table").await;
    assert!(!missing.ok);
    assert!(
        missing.detail.contains("does not exist"),
        "{}",
        missing.detail
    );

    // Teardown: the scratch database is gone, and a second one is a no-op.
    drill
        .teardown(Request::new(TeardownRequest {}))
        .await
        .unwrap();
    assert_eq!(scratch_databases(&drill_server), "0");
    drill
        .teardown(Request::new(TeardownRequest {}))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_drill_without_createdb_fails_to_provision_and_says_what_to_grant() {
    skip_without_docker!();
    let server = start_postgres(None).await;
    let dir = tempfile::tempdir().unwrap();
    psql(
        &server,
        "CREATE ROLE limited LOGIN PASSWORD 'limited' NOCREATEDB;",
    );
    let mut map = values(&server, &dir);
    map.insert(config::FIELD_USER.to_string(), text("limited"));
    map.insert(config::FIELD_PASSWORD.to_string(), text("limited"));

    let state = State::new("postgres");
    state.store(Config::from_map(&map).unwrap());
    let drill = PostgresDrill::new(state, Scratch::default());

    let error = drill
        .provision(Request::new(ProvisionRequest {}))
        .await
        .unwrap_err();
    assert!(
        error.message().contains("CREATEDB"),
        "the operator has to be told what to grant: {}",
        error.message()
    );
    assert_eq!(scratch_databases(&server), "0");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_real_binary_serves_the_drill_service() {
    // Registered in the binary and announced, not only implemented: the unit
    // tests above call the service directly and could not tell.
    skip_without_docker!();
    let server = start_postgres(None).await;
    let dir = tempfile::tempdir().unwrap();
    let live = LivePlugin::start().await;
    assert!(
        live.ready.capabilities.contains(&"drill".to_string()),
        "{:?}",
        live.ready.capabilities
    );

    PluginClient::new(live.channel.clone())
        .configure(ConfigureRequest {
            config: values(&server, &dir),
        })
        .await
        .unwrap();

    let mut drill = DrillClient::new(live.channel.clone());
    drill.provision(ProvisionRequest {}).await.unwrap();
    assert_eq!(scratch_databases(&server), "1");
    let answer = drill
        .check(CheckRequest {
            query: "SELECT true".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(answer.ok, "{}", answer.detail);
    drill.teardown(TeardownRequest {}).await.unwrap();
    assert_eq!(scratch_databases(&server), "0");
}
