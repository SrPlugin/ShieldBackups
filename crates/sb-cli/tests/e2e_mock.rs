// Just as in the rest of the workspace's tests: here an `unwrap` is what is
// wanted, for the test to blow up exactly where it failed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The CLI's real cycle against `sb-plugin-mock`.
//!
//! `cli.rs` checks the surface; this checks that the surface is connected to
//! something. The real binary is run, starting real plugins, and the storage
//! target's directory is inspected to see whether the artifact is where the CLI
//! says it left it.
//!
//! Two of these tests are not from the happy path and they are the ones that
//! matter most: the one checking that **without `plugin lock` nothing runs**
//! and the one checking that **a binary altered after the `lock` does not run
//! either**. A plugin receives the database's and the storage's credentials;
//! that this door is shut is the security property that holds the whole
//! architecture up.

mod common;

use common::{Bench, alter, json_of};

use sb_crypto::Identity;

/// A fresh identity and its key file, as `age-keygen` would write them.
fn identity(bench: &Bench) -> (Identity, std::path::PathBuf) {
    let id = Identity::generate();
    let path = bench.path("key.age");
    std::fs::write(
        &path,
        format!(
            "# created: 2026-08-21T00:00:00Z\n# public key: {}\n{}\n",
            id.to_recipient(),
            id.to_secret_string().expose()
        ),
    )
    .unwrap();
    (id, path)
}

/// Leaves the bench ready: mock installed, registered and a config using it.
fn prepared() -> (Bench, std::path::PathBuf, Identity, std::path::PathBuf) {
    let bench = Bench::new();
    bench.install_mock();
    let (id, key) = identity(&bench);
    let config = bench.config_mock(&id.to_recipient().to_string());

    let lock = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();
    assert!(
        lock.status.success(),
        "plugin lock failed: {}",
        String::from_utf8_lossy(&lock.stderr)
    );

    (bench, config, id, key)
}

#[test]
fn the_lock_doctor_backup_verify_cycle_works_end_to_end() {
    let (bench, config, _id, _key) = prepared();
    let config = config.to_string_lossy().into_owned();

    let doctor = bench
        .cmd()
        .args(["--config", &config, "doctor"])
        .output()
        .unwrap();
    assert!(
        doctor.status.success(),
        "doctor failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&doctor.stdout),
        String::from_utf8_lossy(&doctor.stderr)
    );

    let backup = bench
        .cmd()
        .args(["--config", &config, "backup"])
        .output()
        .unwrap();
    assert!(
        backup.status.success(),
        "backup failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&backup.stdout),
        String::from_utf8_lossy(&backup.stderr)
    );

    // The artifact has to really be in the storage target, not just claimed.
    let artifacts: Vec<_> = walk(&bench.data_dir())
        .into_iter()
        .filter(|r| !r.ends_with(".manifest.json"))
        .collect();
    assert_eq!(
        artifacts.len(),
        1,
        "one artifact was expected: {artifacts:?}"
    );

    let verify = bench
        .cmd()
        .args(["--config", &config, "verify", "production"])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "verify failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let text = String::from_utf8_lossy(&verify.stdout).to_string();
    assert!(
        text.contains("1/1"),
        "verify with no artifact must check every artifact of the target: {text}"
    );
}

#[test]
fn without_a_previous_plugin_lock_the_backup_refuses_and_says_how_to_register_it() {
    // The door that holds the architecture up: shieldbk does not run binaries
    // it has not verified, because a plugin is handed the database's
    // credentials.
    let bench = Bench::new();
    bench.install_mock();
    let (id, _key) = identity(&bench);
    let config = bench.config_mock(&id.to_recipient().to_string());

    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "backup"])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(3),
        "an unregistered plugin is a plugin error"
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        text.contains("plugin lock"),
        "the message must say how to register it: {text}"
    );
    assert!(
        text.contains("mock"),
        "and which plugin is the unregistered one: {text}"
    );

    // And above all: nothing can have been left in the storage target.
    assert!(
        walk(&bench.data_dir()).is_empty(),
        "a backup that refused to run cannot have written anything"
    );
}

#[test]
fn if_the_binary_changes_after_the_lock_the_backup_refuses_and_explains_it() {
    let (bench, config, _id, _key) = prepared();
    alter(&bench.plugins_dir().join("sb-plugin-mock"));

    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "backup"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let text = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        text.contains("has changed"),
        "the message must explain that the binary changed: {text}"
    );
    assert!(
        text.contains("sha256"),
        "and show both hashes so it can be checked: {text}"
    );
    assert!(walk(&bench.data_dir()).is_empty());
}

#[test]
fn restore_reproduces_the_data_the_source_had_dumped() {
    // It is the only thing that justifies the project: a backup that does not
    // restore is not a backup.
    let (bench, config, _id, key) = prepared();
    let config = config.to_string_lossy().into_owned();

    let backup = bench
        .cmd()
        .args(["--config", &config, "--format", "json", "backup"])
        .output()
        .unwrap();
    assert!(backup.status.success());
    let json = json_of(&backup.stdout);
    let artifact = json["targets"][0]["artifact_key"].as_str().unwrap();

    let restore = bench
        .cmd()
        .args([
            "--config",
            &config,
            "restore",
            "production",
            artifact,
            "--identity",
            &key.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(
        restore.status.success(),
        "restore failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&restore.stdout),
        String::from_utf8_lossy(&restore.stderr)
    );

    // The mock source leaves what it receives in `restore.bin`, and its dump is
    // deterministic: it can be regenerated here and compared byte for byte.
    let restored = std::fs::read(bench.data_dir().join("restore.bin")).unwrap();
    let expected: Vec<u8> = sb_plugin_mock::deterministic_data(7, 65536).collect();
    assert_eq!(
        restored, expected,
        "the full cycle through the CLI did not reproduce the original data"
    );
}

#[test]
fn doctor_detects_an_invalid_recipient_in_the_configuration() {
    // A typo in the public key gives no error until somebody tries to restore,
    // and then there is nothing to be done. `doctor` turns it into an immediate
    // failure.
    let bench = Bench::new();
    bench.install_mock();
    let config = bench.config_mock("age1this-is-not-a-public-key");
    let lock = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();
    assert!(lock.status.success());

    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "doctor",
        ])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(4),
        "a diagnosis with failures is an operation error"
    );
    let json = json_of(&out.stdout);
    assert_eq!(json["ok"], serde_json::Value::Bool(false));

    let checks = json["targets"][0]["checks"].as_array().unwrap();
    let recipient = checks
        .iter()
        .find(|c| c["name"] == "recipient")
        .expect("doctor has to check the recipient");
    assert_eq!(recipient["ok"], serde_json::Value::Bool(false));
    assert_eq!(
        recipient["origin"], "config",
        "the problem is in the file, not in a plugin"
    );
    assert!(
        !recipient["remedy"].as_str().unwrap_or_default().is_empty(),
        "a check that fails without a remedy is useless"
    );
}

#[test]
fn the_backup_in_json_gives_the_artifacts_key() {
    let (bench, config, _id, _key) = prepared();

    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "-vv",
            "backup",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // With `-vv` there are plenty of logs; none of them can have slipped in
    // here.
    let json = json_of(&out.stdout);
    assert_eq!(json["ok"], serde_json::Value::Bool(true));
    let key = json["targets"][0]["artifact_key"].as_str().unwrap();
    assert!(
        key.starts_with("production/"),
        "the key comes from the target's template: {key}"
    );
    assert!(key.ends_with(".dump.zst.age"), "{key}");
    assert!(
        bench.data_dir().join(key).is_file(),
        "the artifact the JSON names has to exist: {key}"
    );
    assert!(!out.stderr.is_empty(), "with -vv there are logs, on stderr");
}

#[test]
fn storage_gc_talks_to_the_storage_target_and_counts_what_it_aborted() {
    let (bench, config, _id, _key) = prepared();
    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "storage",
            "gc",
            "production",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = json_of(&out.stdout);
    assert_eq!(json["target"], "production");
    // The mock storage target writes each artifact in one go: there is no
    // multipart to abort and that is why it is zero. What is being checked is
    // that the call arrived.
    assert_eq!(json["aborted"], 0);
    assert_eq!(json["prefix"], "production/");
}

#[test]
fn storage_prune_without_retention_days_refuses_with_a_config_error() {
    // Pruning deletes backups; running it on a target that never opted in
    // would be deleting on a guessed default, which is exactly what the
    // config field exists to prevent.
    let (bench, config, _id, _key) = prepared();
    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "storage",
            "prune",
            "production",
        ])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(2),
        "no `retention_days` is a configuration error, not a plugin or operation one"
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        text.contains("retention_days"),
        "the message has to name the missing field: {text}"
    );
}

#[test]
fn storage_prune_deletes_expired_artifacts_and_their_manifests() {
    let bench = Bench::new();
    bench.install_mock();
    let (id, _key) = identity(&bench);
    // `retention_days = 0`: by the time `prune` runs, the artifact `backup`
    // already wrote is older than "now", so it is exactly the case that has
    // to be deleted -- and the only reliable way to test deletion without a
    // clock the test controls.
    let config = bench.config(&format!(
        r#"
[plugins]
dir = {dir:?}
lockfile = {lock:?}

[defaults]
retention_days = 0

[[target]]
name = "production"
source = "mock"
storage = "mock"
recipient = "{recipient}"

[target.source_config]
dir = {data:?}
seed = 7
size = 65536

[target.storage_config]
dir = {data:?}
"#,
        dir = bench.plugins_dir().to_string_lossy(),
        lock = bench.lockfile().to_string_lossy(),
        data = bench.data_dir().to_string_lossy(),
        recipient = id.to_recipient(),
    ));

    let lock = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();
    assert!(lock.status.success());

    let backup = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "backup"])
        .output()
        .unwrap();
    assert!(backup.status.success());
    assert!(
        !walk(&bench.data_dir()).is_empty(),
        "the backup has to have written something before it can be pruned"
    );

    // `modified_at` has one-second resolution (see `sb-core::naming`'s own
    // note on `{timestamp}`), so the cutoff computed a moment later has to
    // land in the next second for the artifact to compare as strictly older.
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "storage",
            "prune",
            "production",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = json_of(&out.stdout);
    assert_eq!(json["deleted"], 1);
    assert_eq!(json["kept"], 0);

    assert!(
        walk(&bench.data_dir()).is_empty(),
        "the expired artifact and its manifest both had to go"
    );
}

/// A bench with the mock installed and registered and a config that adds
/// whatever the caller writes: `defaults` goes under `[defaults]` and `extra`
/// at the end of the file, where it can be another target's table or a whole
/// `[[notify]]` block. No backup has been taken yet.
fn locked_with(defaults: &str, extra: &str) -> (Bench, std::path::PathBuf) {
    let bench = Bench::new();
    bench.install_mock();
    let (id, _key) = identity(&bench);
    let config = bench.config(&format!(
        r#"
[plugins]
dir = {dir:?}
lockfile = {lock:?}

[defaults]
{defaults}

[[target]]
name = "production"
source = "mock"
storage = "mock"
recipient = "{recipient}"

[target.source_config]
dir = {data:?}
seed = 7
size = 65536

[target.storage_config]
dir = {data:?}

{extra}
"#,
        dir = bench.plugins_dir().to_string_lossy(),
        lock = bench.lockfile().to_string_lossy(),
        data = bench.data_dir().to_string_lossy(),
        recipient = id.to_recipient(),
        extra = extra.replace("@NOTIFY@", &bench.path("notify").to_string_lossy()),
    ));
    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "plugin lock failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (bench, config)
}

/// [`locked_with`], plus one backup already taken. `target` lands in the
/// config's tail, so it is where a retention table for the target goes.
fn backed_up_with_retention(defaults: &str, target: &str) -> (Bench, std::path::PathBuf) {
    let (bench, config) = locked_with(defaults, target);
    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "backup"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "backup failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (bench, config)
}

/// The events the mock notifier recorded, one parsed JSON value per line.
fn notifications(bench: &Bench) -> Vec<serde_json::Value> {
    std::fs::read_to_string(bench.path("notify").join("notifications.jsonl"))
        .map(|text| text.lines().map(|l| json_of(l.as_bytes())).collect())
        .unwrap_or_default()
}

/// A `[[notify]]` block for the mock notifier. `@NOTIFY@` stands for the
/// directory it records under, which only exists once the bench does:
/// [`locked_with`] fills it in.
fn notify_mock(on: &str) -> String {
    format!("[[notify]]\nplugin = \"mock\"\non = \"{on}\"\n[notify.config]\ndir = \"@NOTIFY@\"\n")
}

#[test]
fn storage_prune_dry_run_says_what_would_go_and_deletes_nothing() {
    let (bench, config) = backed_up_with_retention("retention_days = 0", "");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let before = walk(&bench.data_dir());

    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "storage",
            "prune",
            "production",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = json_of(&out.stdout);
    assert_eq!(json["dry_run"], serde_json::Value::Bool(true));
    assert_eq!(json["deleted"], 0);
    assert_eq!(json["expired"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        walk(&bench.data_dir()),
        before,
        "a dry run must leave the storage target exactly as it found it"
    );
}

#[test]
fn storage_prune_with_a_gfs_retention_keeps_the_newest_artifact() {
    let (bench, config) =
        backed_up_with_retention("", "[target.retention]\nkeep_daily = 1\nkeep_monthly = 1");

    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "storage",
            "prune",
            "production",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = json_of(&out.stdout);
    assert_eq!(json["policy"]["kind"], "gfs");
    assert_eq!(json["policy"]["keep_daily"], 1);
    assert_eq!(json["deleted"], 0);
    assert_eq!(json["kept"], 1);
    assert!(
        !walk(&bench.data_dir()).is_empty(),
        "the only artifact is the newest of its day and month: it stays"
    );
}

#[test]
fn a_config_naming_both_kinds_of_retention_is_a_config_error() {
    let (bench, config) = backed_up_with_retention("", "");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        text.replacen(
            "[defaults]\n",
            "[defaults]\nretention_days = 5\n[defaults.retention]\nkeep_daily = 1\n",
            1,
        ),
    )
    .unwrap();

    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "storage",
            "prune",
            "production",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        text.contains("retention_days") && text.contains("[defaults]"),
        "the message has to name what conflicts and where: {text}"
    );
}

#[test]
fn a_backup_tells_the_notifier_that_asked_and_the_report_is_the_json_contract() {
    let (bench, config) = locked_with("", &notify_mock("always"));

    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "backup"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let events = notifications(&bench);
    assert_eq!(events.len(), 1, "one command, one notification");
    assert_eq!(events[0]["command"], "backup");
    assert_eq!(events[0]["ok"], serde_json::Value::Bool(true));
    // What the notifier reads is what `--format json` prints.
    assert_eq!(events[0]["report"]["ok"], serde_json::Value::Bool(true));
    assert!(
        events[0]["report"]["targets"][0]["artifact_key"]
            .as_str()
            .is_some_and(|key| key.starts_with("production/")),
        "{}",
        events[0]
    );
}

#[test]
fn a_notifier_that_only_wants_failures_stays_quiet_when_all_went_well() {
    // `on` defaults to `failure`: an alert that fires on every success is one
    // people learn to ignore.
    let (bench, config) = locked_with("", &notify_mock("failure"));

    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "backup"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(notifications(&bench).is_empty());
}

#[test]
fn a_command_that_fails_before_it_has_a_report_is_still_notified() {
    let (bench, config) = locked_with("", &notify_mock("failure"));

    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "verify", "no-such"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unknown target is a config error"
    );

    let events = notifications(&bench);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["command"], "verify");
    assert_eq!(events[0]["ok"], serde_json::Value::Bool(false));
    assert_eq!(events[0]["report"]["class"], "config");
}

#[test]
fn a_notifier_that_cannot_be_reached_never_changes_the_commands_exit_code() {
    // The backup worked; the alerting did not. The exit code tells about the
    // backup, and the alerting failure is said on stderr instead of being lost.
    let (bench, config) = locked_with("", "[[notify]]\nplugin = \"ghost\"\non = \"always\"\n");

    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "backup"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        text.contains("could not notify") && text.contains("ghost"),
        "the failure has to be said, and name the plugin: {text}"
    );
}

#[test]
fn a_notification_never_pollutes_the_json_on_stdout() {
    let (bench, config) = locked_with("", &notify_mock("always"));

    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "backup",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    // `json_of` fails unless stdout is exactly one JSON document.
    assert_eq!(json_of(&out.stdout)["ok"], serde_json::Value::Bool(true));
}

#[test]
fn plugin_docs_shows_the_plugins_schema_and_no_value() {
    let (bench, config, _id, _key) = prepared();
    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "plugin",
            "docs",
            "mock",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    for expected in ["FIELD", "TYPE", "REQ", "SECRET", "dir", "seed", "size"] {
        assert!(text.contains(expected), "`{expected}` is missing:\n{text}");
    }
    assert!(
        !text.contains(&bench.data_dir().to_string_lossy().to_string()),
        "docs describes the schema, never what is configured:\n{text}"
    );
}

#[test]
fn plugin_list_shows_the_status_of_each_binary() {
    let bench = Bench::new();
    bench.install_mock();
    let config = bench.config_mock("age1qqqqqqqqqq");

    let before = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "plugin",
            "list",
        ])
        .output()
        .unwrap();
    assert!(
        before.status.success(),
        "listing does not fail for the lock being absent"
    );
    let json = json_of(&before.stdout);
    assert_eq!(json["plugins"][0]["name"], "mock");
    assert_eq!(json["plugins"][0]["usable"], serde_json::Value::Bool(false));

    bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();

    let after = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "plugin",
            "list",
        ])
        .output()
        .unwrap();
    let json = json_of(&after.stdout);
    assert_eq!(json["plugins"][0]["usable"], serde_json::Value::Bool(true));
}

/// The relative paths of everything under `root`, in a stable order.
fn walk(root: &std::path::Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(relative) = path.strip_prefix(root) {
                found.push(relative.to_string_lossy().into_owned());
            }
        }
    }
    found.sort();
    found
}

#[test]
fn plugin_docs_works_with_a_plugins_only_config() {
    // `docs` asks the plugin which fields it accepts. It is exactly what gets
    // consulted *before* writing the first `[[target]]`, so it cannot require
    // one.
    let bench = Bench::new();
    bench.install_mock();
    let config = bench.config_plugins_only();

    let lock = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();
    assert!(lock.status.success());

    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "plugin",
            "docs",
            "mock",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    for expected in ["FIELD", "dir", "seed", "size"] {
        assert!(text.contains(expected), "`{expected}` is missing:\n{text}");
    }
}

// --- shieldbk drill ---------------------------------------------------------
//
// The mock's disposable place is a directory, and its checks (`size=N`,
// `restored`, `error`) are the ones its own docs list. What these tests prove is
// the CLI around the drill: which artifact it picks, what it prints, which exit
// code it ends with, and -- the property the feature rests on -- that it never
// writes where the backup comes from.

/// A `[target.drill]` block for the mock.
fn drill_block(check: &str) -> String {
    format!("[target.drill]\ncheck = \"{check}\"\n")
}

/// A locked bench whose target has a drill block, with one backup already taken.
fn drillable(check: &str, extra: &str) -> (Bench, std::path::PathBuf) {
    let (bench, config) = locked_with("", &format!("{}\n{extra}", drill_block(check)));
    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "backup"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "backup failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (bench, config)
}

/// Runs `drill production` with the key `locked_with` left in the bench, plus
/// `extra` arguments.
fn drill(bench: &Bench, config: &std::path::Path, extra: &[&str]) -> std::process::Output {
    bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "--format", "json"])
        .args(["drill", "production", "--identity"])
        .arg(bench.path("key.age"))
        .args(extra)
        .output()
        .unwrap()
}

/// The RPCs the mock's drill saw, in order.
fn drill_calls(bench: &Bench) -> Vec<String> {
    std::fs::read_to_string(bench.data_dir().join("drill-calls.log"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_drill_proves_the_latest_backup_restores_without_touching_the_sources_own_data() {
    let (bench, config) = drillable("size=65536", "");

    let out = drill(&bench, &config, &[]);

    assert!(
        out.status.success(),
        "drill failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let json = json_of(&out.stdout);
    assert_eq!(json["command"], "drill");
    assert_eq!(json["ok"], true);
    assert_eq!(json["passed"], true);
    assert_eq!(json["plaintext_bytes"], 65536);
    assert_eq!(json["check"]["ok"], true);
    assert_eq!(json["teardown_ok"], true);
    assert!(
        json["artifact_key"]
            .as_str()
            .is_some_and(|key| key.starts_with("production/")),
        "{json}"
    );

    // The property the feature rests on: a plain `restore` writes `restore.bin`
    // into the source's directory, and a drill must not.
    assert!(
        !bench.data_dir().join("restore.bin").exists(),
        "the drill restored over the source's own data"
    );
    assert!(
        !bench.data_dir().join("drill-scratch").exists(),
        "the scratch place was left behind"
    );
    assert_eq!(
        drill_calls(&bench),
        ["provision", "check size=65536", "teardown"]
    );
}

#[test]
fn a_drill_whose_check_does_not_hold_exits_4_and_says_which_step_failed() {
    let (bench, config) = drillable("size=1", "");

    let out = drill(&bench, &config, &[]);

    assert_eq!(
        out.status.code(),
        Some(4),
        "the code a cron job pages on: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Under `--format json` the failure travels in stdout's single document.
    let json = json_of(&out.stdout);
    assert_eq!(json["ok"], false);
    assert_eq!(json["passed"], false);
    assert_eq!(json["failed_stage"], "check");
    assert_eq!(json["class"], "operation");
    assert!(
        json["failure"].as_str().unwrap().contains("expected 1"),
        "{json}"
    );
    // The restore did work, and the report keeps that.
    assert_eq!(json["plaintext_bytes"], 65536);
    // And the scratch place went away anyway.
    assert_eq!(drill_calls(&bench).last().unwrap(), "teardown");
    assert!(!bench.data_dir().join("drill-scratch").exists());
}

#[test]
fn a_drill_that_cannot_provision_fails_at_provision_and_restores_nothing() {
    let (bench, config) = drillable("restored", "");
    std::fs::write(bench.data_dir().join("drill-fail-provision"), b"").unwrap();

    let out = drill(&bench, &config, &[]);

    assert_eq!(out.status.code(), Some(4));
    let json = json_of(&out.stdout);
    assert_eq!(json["failed_stage"], "provision");
    assert!(json["plaintext_bytes"].is_null(), "nothing was restored");
    assert!(!bench.data_dir().join("restore.bin").exists());
}

#[test]
fn a_target_without_a_drill_block_cannot_be_drilled_and_the_message_says_how() {
    let (bench, config) = backed_up_with_retention("", "");

    let out = drill(&bench, &config, &[]);

    assert_eq!(out.status.code(), Some(2), "it is a configuration error");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.contains("[target.drill]"), "{text}");
    assert!(
        !bench.data_dir().join("drill-calls.log").exists(),
        "nothing was provisioned for a drill that cannot run"
    );
}

#[test]
fn a_drill_of_a_target_with_nothing_backed_up_is_a_failure_and_not_a_pass() {
    // A target whose backups are missing is exactly what a drill is there to
    // flag, so "nothing to restore" cannot come out green.
    let (bench, config) = locked_with("", &drill_block("restored"));

    let out = drill(&bench, &config, &[]);

    assert_eq!(out.status.code(), Some(4));
    let json = json_of(&out.stdout);
    assert!(
        json["error"].as_str().unwrap().contains("no artifacts"),
        "{json}"
    );
}

#[test]
fn a_drill_can_be_aimed_at_a_named_artifact() {
    let (bench, config) = drillable("restored", "");
    let backup = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "--format", "json"])
        .arg("verify")
        .arg("production")
        .output()
        .unwrap();
    let key = json_of(&backup.stdout)["artifacts"][0]["artifact_key"]
        .as_str()
        .unwrap()
        .to_owned();

    let named = drill(&bench, &config, &["--artifact", &key]);
    assert!(
        named.status.success(),
        "{}",
        String::from_utf8_lossy(&named.stdout)
    );
    assert_eq!(json_of(&named.stdout)["artifact_key"], key.as_str());

    // One that is not there fails in the restore, and says so.
    let missing = drill(&bench, &config, &["--artifact", "production/nope.age"]);
    assert_eq!(missing.status.code(), Some(4));
    assert_eq!(json_of(&missing.stdout)["failed_stage"], "restore");
}

#[test]
fn a_drill_is_told_to_the_notifier_under_its_own_name() {
    let (bench, config) = drillable("restored", &notify_mock("always"));

    let out = drill(&bench, &config, &[]);
    assert!(out.status.success());

    let events = notifications(&bench);
    let told = events
        .iter()
        .find(|e| e["command"] == "drill")
        .expect("the drill was not notified");
    assert_eq!(told["ok"], true);
    assert_eq!(told["report"]["passed"], true);
}
