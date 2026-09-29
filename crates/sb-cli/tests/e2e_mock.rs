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

/// A bench with one backup already taken, and a config whose retention is
/// whatever the caller writes: `defaults` goes under `[defaults]` and `target`
/// under the target's own table.
fn backed_up_with_retention(defaults: &str, target: &str) -> (Bench, std::path::PathBuf) {
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

{target}
"#,
        dir = bench.plugins_dir().to_string_lossy(),
        lock = bench.lockfile().to_string_lossy(),
        data = bench.data_dir().to_string_lossy(),
        recipient = id.to_recipient(),
    ));
    for args in [["plugin", "lock"], ["backup", "--format=human"]] {
        let out = bench
            .cmd()
            .args(["--config", &config.to_string_lossy()])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    (bench, config)
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
