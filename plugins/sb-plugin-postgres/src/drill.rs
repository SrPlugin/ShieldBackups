//! The drill: a scratch database to restore into, and one question to ask it.
//!
//! ```text
//! Provision   CREATE DATABASE "drill_<secs>_<pid>"        (on `maintenance_database`)
//!   ...       Source.Restore now runs pg_restore against the scratch database
//! Check       psql -c <query> against the scratch database; passes iff it prints `t`
//! Teardown    DROP DATABASE IF EXISTS "drill_<secs>_<pid>"
//! ```
//!
//! # It cannot restore over the real database
//!
//! The scratch name is generated here, and it is the only database this service
//! ever creates, checks or drops. [`Scratch`] is shared with the source, which asks
//! it which database to restore into: while a drill is between `Provision` and
//! `Teardown` that is the scratch one, and the configured `database` -- the one
//! being backed up -- is not reachable by this path at all. There is no field an
//! operator can mistype to aim a drill at production, because the drill never reads
//! one.
//!
//! # What a passing check is
//!
//! The query has to print exactly `t`, which is what a Postgres boolean `true`
//! looks like under `psql --tuples-only --no-align`. `SELECT count(*) > 0 FROM
//! users` is the shape. A query that prints a number, or nothing, or `f`, does not
//! pass: a check that is satisfied by almost anything proves almost nothing, and the
//! answer is a sentence the operator wrote and can read back.
//!
//! A query that **errors** -- the table is not there -- is also a check that did
//! not hold: that is the restore having lost something, which is the very thing
//! being looked for. Only a plugin that cannot ask at all (no `psql`) is an RPC
//! error.
//!
//! # `psql`, and what it needs
//!
//! `psql` is what is run, with the same `PGPASSWORD`-in-the-environment treatment
//! `pg_dump` gets. The role in `user` needs `CREATEDB`. Dropping does not use
//! `WITH (FORCE)`, which needs `PostgreSQL` 13: by `Teardown` every connection of ours
//! has already exited, and a plain drop works on every version.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use sb_plugin_sdk::sb_proto::drill_server::Drill;
use sb_plugin_sdk::sb_proto::{
    CheckRequest, CheckResponse, ProvisionRequest, ProvisionResponse, TeardownRequest,
    TeardownResponse,
};
use sb_plugin_sdk::tonic::{Request, Response, Status};
use tokio::io::AsyncReadExt as _;

use crate::command::{self, Running};
use crate::config::{Config, State};

/// How much of the check's output is read. A check is one boolean; anything past
/// this is not an answer and is not worth holding in memory.
const OUTPUT_CAP: u64 = 64 * 1024;

/// How much of an unexpected output is repeated back in the detail.
const SHOWN_BYTES: usize = 80;

/// The database restores land in right now, shared between the source and the
/// drill.
///
/// `None` is the normal state, and then a restore goes where it always has: into
/// the configured `database`. Only between `Provision` and `Teardown` is it the
/// scratch one.
#[derive(Clone, Default)]
pub struct Scratch(Arc<Mutex<Option<String>>>);

impl Scratch {
    fn get(&self) -> Option<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set(&self, value: Option<String>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = value;
    }

    /// `config`, aimed at the scratch database if a drill is under way.
    #[must_use]
    pub fn applied_to(&self, config: Config) -> Config {
        match self.get() {
            Some(name) => config.with_database(&name),
            None => config,
        }
    }
}

pub struct PostgresDrill {
    state: State,
    scratch: Scratch,
}

impl PostgresDrill {
    #[must_use]
    pub fn new(state: State, scratch: Scratch) -> Self {
        Self { state, scratch }
    }
}

/// A name for the scratch database: unmistakably a drill's, and different for two
/// drills that run at once on the same server.
fn scratch_name() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format!("drill_{seconds}_{}", std::process::id())
}

/// What a `psql` run printed and how it ended.
struct Ran {
    stdout: String,
    outcome: Result<(), Status>,
}

/// Runs `sql` with `psql` against `database` on `config`'s server.
///
/// # Errors
/// [`Status::unavailable`] only if `psql` cannot be started at all. A statement
/// that fails is not an error here: it is in [`Ran::outcome`], because a check
/// treats it as an answer and a provision treats it as a failure.
async fn psql(config: &Config, database: &str, sql: &str) -> Result<Ran, Status> {
    let target = config.with_database(database);
    let args = command::psql_args(&target, sql);
    let mut running = Running::spawn(
        "psql",
        &config.psql_path,
        &args,
        &target,
        std::process::Stdio::null(),
        std::process::Stdio::piped(),
    )?;

    let mut stdout = String::new();
    // A read that fails leaves whatever was read, which `outcome` then
    // contextualises with the exit status; there is nothing better to do with it.
    let _ = running
        .stdout()
        .take(OUTPUT_CAP)
        .read_to_string(&mut stdout)
        .await;
    let outcome = running.settle().await;
    Ok(Ran { stdout, outcome })
}

#[sb_plugin_sdk::tonic::async_trait]
impl Drill for PostgresDrill {
    async fn provision(
        &self,
        _: Request<ProvisionRequest>,
    ) -> Result<Response<ProvisionResponse>, Status> {
        let config = self.state.resolved()?;
        // A second `Provision` without a `Teardown` would orphan the first scratch
        // database: refused instead of silently replaced.
        if let Some(existing) = self.scratch.get() {
            return Err(Status::failed_precondition(format!(
                "the scratch database `{existing}` is already provisioned: Teardown it first"
            )));
        }

        let name = scratch_name();
        // `template0`, the pristine one: a restore target should not inherit
        // whatever somebody installed into `template1`.
        let sql = format!(
            "CREATE DATABASE {} TEMPLATE template0",
            command::quote_identifier(&name)
        );
        psql(&config, &config.maintenance_database, &sql)
            .await?
            .outcome
            .map_err(|e| {
                Status::new(
                    e.code(),
                    format!(
                        "could not create the scratch database `{name}` through `{}`: {}; the role \
                         `{}` needs the CREATEDB privilege",
                        config.maintenance_database,
                        e.message(),
                        config.user
                    ),
                )
            })?;

        // Recorded only once it exists: a failed `CREATE` leaves nothing for
        // `Teardown` to drop, and from here on `Source.Restore` lands in it.
        self.scratch.set(Some(name.clone()));
        tracing::info!(database = %name, host = %config.host, "scratch database created");
        Ok(Response::new(ProvisionResponse {
            description: format!("database `{name}` on {}:{}", config.host, config.port),
        }))
    }

    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let config = self.state.resolved()?;
        let query = request.into_inner().query;
        let Some(scratch) = self.scratch.get() else {
            return Err(Status::failed_precondition(
                "no scratch database is provisioned: call Provision, and restore, before Check",
            ));
        };

        let ran = psql(&config, &scratch, &query).await?;
        let (ok, detail) = match ran.outcome {
            // The query itself failed: a missing table, a syntax error. That is
            // the restore having lost something, or the check being wrong, and
            // either way the answer is "no".
            Err(e) => (false, format!("the check query failed: {}", e.message())),
            Ok(()) => judge(&ran.stdout),
        };
        tracing::info!(database = %scratch, ok, "check answered");
        Ok(Response::new(CheckResponse { ok, detail }))
    }

    async fn teardown(
        &self,
        _: Request<TeardownRequest>,
    ) -> Result<Response<TeardownResponse>, Status> {
        // Idempotent: the core calls it whatever happened before, so with nothing
        // provisioned it has nothing to do and says so by succeeding.
        let Some(name) = self.scratch.get() else {
            return Ok(Response::new(TeardownResponse {}));
        };
        let config = self.state.resolved()?;

        let sql = format!(
            "DROP DATABASE IF EXISTS {}",
            command::quote_identifier(&name)
        );
        psql(&config, &config.maintenance_database, &sql)
            .await?
            .outcome
            .map_err(|e| {
                // Kept recorded: the database is still there, and a retry should
                // know what to drop.
                Status::new(
                    e.code(),
                    format!(
                        "could not drop the scratch database `{name}`: {}",
                        e.message()
                    ),
                )
            })?;

        self.scratch.set(None);
        tracing::info!(database = %name, "scratch database dropped");
        Ok(Response::new(TeardownResponse {}))
    }
}

/// Turns what `psql` printed into the verdict: passes iff it is exactly `t`.
fn judge(stdout: &str) -> (bool, String) {
    let printed = stdout.trim();
    match printed {
        "t" => (true, "the check returned true".to_owned()),
        "" => (
            false,
            "the check returned no rows: it has to return a single boolean".to_owned(),
        ),
        other => (
            false,
            format!(
                "the check returned `{}`, not `t`: it has to return a single boolean",
                shown(other)
            ),
        ),
    }
}

/// The start of `text`, cut on a character boundary so it cannot panic.
fn shown(text: &str) -> String {
    if text.len() <= SHOWN_BYTES {
        return text.to_owned();
    }
    let mut end = SHOWN_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use sb_plugin_sdk::sb_proto::{Value, value::Kind};
    use sb_plugin_sdk::tonic::Code;

    use super::*;

    fn text(s: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(s.into())),
        }
    }

    /// A stand-in for `psql`: records every invocation's statement in `calls`, and
    /// answers by what the statement says. The real thing is tested against a real
    /// server in `tests/integration.rs`; this is what lets the sequencing be
    /// tested without one.
    ///
    /// - a statement containing `FAILME` exits 1 with a message on stderr
    /// - a statement containing `PRINT:<x>` prints `<x>`
    /// - a `CREATE DATABASE` fails while a `fail-create` file exists next to it
    /// - anything else exits 0 and prints nothing
    fn fake_psql(dir: &Path) -> String {
        let path = dir.join("psql");
        let calls = dir.join("calls");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\n\
                 # the statement is the last argument, and the database follows -d\n\
                 for last; do :; done\n\
                 db=''; prev=''\n\
                 for a in \"$@\"; do [ \"$prev\" = -d ] && db=\"$a\"; prev=\"$a\"; done\n\
                 printf '%s | %s\\n' \"$db\" \"$last\" >> {calls}\n\
                 case \"$last\" in\n\
                   CREATE*) [ -e {fail_create} ] && {{ echo 'ERROR: permission denied to create database' >&2; exit 1; }};;\n\
                   *FAILME*) echo 'ERROR: relation does not exist' >&2; exit 1;;\n\
                   *PRINT:*) printf '%s\\n' \"${{last#*PRINT:}}\";;\n\
                 esac\n\
                 exit 0\n",
                calls = calls.display(),
                fail_create = dir.join("fail-create").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path.display().to_string()
    }

    fn calls(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn drill(dir: &Path) -> (PostgresDrill, Scratch) {
        let map = HashMap::from([
            ("host".to_string(), text("db.internal")),
            ("database".to_string(), text("app")),
            ("user".to_string(), text("backup")),
            ("psql_path".to_string(), text(&fake_psql(dir))),
        ]);
        let state = State::default();
        state.store(Config::from_map(&map).unwrap());
        let scratch = Scratch::default();
        (PostgresDrill::new(state, scratch.clone()), scratch)
    }

    async fn provision(drill: &PostgresDrill) -> Result<String, Status> {
        drill
            .provision(Request::new(ProvisionRequest {}))
            .await
            .map(|r| r.into_inner().description)
    }

    async fn check(drill: &PostgresDrill, query: &str) -> Result<CheckResponse, Status> {
        drill
            .check(Request::new(CheckRequest {
                query: query.into(),
            }))
            .await
            .map(Response::into_inner)
    }

    async fn teardown(drill: &PostgresDrill) -> Result<(), Status> {
        drill
            .teardown(Request::new(TeardownRequest {}))
            .await
            .map(|_| ())
    }

    #[tokio::test]
    async fn provision_creates_the_scratch_database_from_the_maintenance_one() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, scratch) = drill(dir.path());

        let description = provision(&drill).await.unwrap();

        let name = scratch.get().unwrap();
        assert!(name.starts_with("drill_"), "{name}");
        assert!(description.contains(&name), "{description}");
        assert!(description.contains("db.internal:5432"), "{description}");
        // Connected to `postgres`, not to `app`: the scratch database cannot be
        // created from itself, and `app` is not touched.
        assert_eq!(
            calls(dir.path()),
            [format!(
                "postgres | CREATE DATABASE \"{name}\" TEMPLATE template0"
            )]
        );
    }

    #[tokio::test]
    async fn a_restore_during_a_drill_aims_at_the_scratch_database_and_never_at_the_real_one() {
        // The property the whole feature rests on.
        let dir = tempfile::tempdir().unwrap();
        let (drill, scratch) = drill(dir.path());
        let configured = drill.state.resolved().unwrap();

        assert_eq!(scratch.applied_to(configured.clone()).database, "app");
        provision(&drill).await.unwrap();
        let during = scratch.applied_to(configured.clone());
        assert_eq!(during.database, scratch.get().unwrap());
        assert_ne!(during.database, "app");
        teardown(&drill).await.unwrap();
        assert_eq!(scratch.applied_to(configured).database, "app");
    }

    #[tokio::test]
    async fn a_provision_that_fails_says_what_privilege_is_missing_and_records_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, scratch) = drill(dir.path());
        std::fs::write(dir.path().join("fail-create"), b"").unwrap();

        let error = provision(&drill).await.unwrap_err();

        assert!(
            error
                .message()
                .contains("permission denied to create database"),
            "psql's own words must reach the operator: {}",
            error.message()
        );
        assert!(
            error.message().contains("CREATEDB"),
            "and so must the remedy: {}",
            error.message()
        );
        assert!(
            scratch.get().is_none(),
            "nothing was created, so nothing is tracked"
        );
    }

    #[tokio::test]
    async fn a_missing_psql_is_unavailable_and_says_where_it_looked() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, scratch) = drill(dir.path());
        let map = HashMap::from([
            ("host".to_string(), text("db.internal")),
            ("database".to_string(), text("app")),
            ("user".to_string(), text("backup")),
            ("psql_path".to_string(), text("/nonexistent/psql")),
        ]);
        drill.state.store(Config::from_map(&map).unwrap());

        let error = provision(&drill).await.unwrap_err();

        assert_eq!(error.code(), Code::Unavailable);
        assert!(
            error.message().contains("/nonexistent/psql"),
            "{}",
            error.message()
        );
        assert!(scratch.get().is_none());
    }

    #[tokio::test]
    async fn the_check_passes_only_when_the_query_prints_exactly_t() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, _) = drill(dir.path());
        provision(&drill).await.unwrap();

        let yes = check(&drill, "PRINT:t").await.unwrap();
        assert!(yes.ok, "{}", yes.detail);

        for (query, expected) in [
            ("PRINT:f", "`f`"),
            ("PRINT:42", "`42`"),
            ("SELECT nothing", "no rows"),
        ] {
            let answer = check(&drill, query).await.unwrap();
            assert!(!answer.ok, "{query} must not pass");
            assert!(
                answer.detail.contains(expected),
                "{query}: {}",
                answer.detail
            );
        }
    }

    #[tokio::test]
    async fn a_query_that_errors_is_a_check_that_did_not_hold_not_an_rpc_error() {
        // The table being gone after a restore is the thing a drill looks for.
        let dir = tempfile::tempdir().unwrap();
        let (drill, _) = drill(dir.path());
        provision(&drill).await.unwrap();

        let answer = check(&drill, "SELECT FAILME").await.unwrap();
        assert!(!answer.ok);
        assert!(
            answer.detail.contains("relation does not exist"),
            "{}",
            answer.detail
        );
    }

    #[tokio::test]
    async fn the_check_runs_against_the_scratch_database() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, scratch) = drill(dir.path());
        provision(&drill).await.unwrap();
        check(&drill, "PRINT:t").await.unwrap();

        let name = scratch.get().unwrap();
        assert_eq!(
            calls(dir.path()).last().unwrap(),
            &format!("{name} | PRINT:t")
        );
    }

    #[tokio::test]
    async fn a_check_before_provisioning_is_a_precondition_failure() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, _) = drill(dir.path());
        assert_eq!(
            check(&drill, "PRINT:t").await.unwrap_err().code(),
            Code::FailedPrecondition
        );
        assert!(calls(dir.path()).is_empty(), "psql must not have been run");
    }

    #[tokio::test]
    async fn teardown_drops_the_scratch_database_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, scratch) = drill(dir.path());

        // With nothing provisioned it does nothing, and does not start psql.
        teardown(&drill).await.unwrap();
        assert!(calls(dir.path()).is_empty());

        provision(&drill).await.unwrap();
        let name = scratch.get().unwrap();
        teardown(&drill).await.unwrap();
        assert!(scratch.get().is_none());
        assert_eq!(
            calls(dir.path()).last().unwrap(),
            &format!("postgres | DROP DATABASE IF EXISTS \"{name}\"")
        );

        let before = calls(dir.path()).len();
        teardown(&drill).await.unwrap();
        assert_eq!(
            calls(dir.path()).len(),
            before,
            "a second teardown is a no-op"
        );
    }

    #[tokio::test]
    async fn provisioning_twice_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (drill, scratch) = drill(dir.path());
        provision(&drill).await.unwrap();
        let first = scratch.get().unwrap();

        let error = provision(&drill).await.unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert_eq!(
            scratch.get().unwrap(),
            first,
            "the first one is still tracked"
        );
    }

    #[test]
    fn two_scratch_names_from_the_same_process_are_valid_identifiers() {
        let name = scratch_name();
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "{name}"
        );
        assert!(name.starts_with("drill_"));
    }

    #[test]
    fn an_unexpected_output_is_repeated_back_cut_to_size_on_a_char_boundary() {
        // 'é' is two bytes: a cut at an odd offset would split it.
        let long = "é".repeat(200);
        let (ok, detail) = judge(&long);
        assert!(!ok);
        assert!(detail.contains("..."), "{detail}");
        assert!(detail.len() < 200, "{detail}");
    }
}
