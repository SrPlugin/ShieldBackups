// Just as in the rest of the workspace's tests: here an `unwrap` is what is
// wanted, for the test to blow up exactly where it failed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The tests of the CLI's surface: the ones that need no live plugin.
//!
//! They are the fast ones, and they cover what a script calling `shieldbk`
//! needs to be able to take for granted: that there are six commands, that the
//! exit codes tell the kinds of error apart, and that under `--format json`
//! standard output is JSON **no matter what**.

mod common;

use common::{Bench, alter, json_of};

/// A configuration error. A script has to be able to react differently to "the
/// config is wrong" than to "the backup failed".
const EXIT_CONFIG: i32 = 2;

#[test]
fn the_help_shows_the_six_commands() {
    let out = Bench::new().cmd().arg("--help").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    for command in ["backup", "restore", "verify", "doctor", "plugin", "storage"] {
        assert!(
            text.contains(command),
            "the help does not mention `{command}`:\n{text}"
        );
    }
}

#[test]
fn the_version_works() {
    let out = Bench::new().cmd().arg("--version").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        text.contains(env!("CARGO_PKG_VERSION")),
        "`--version` must say the version: {text}"
    );
}

#[test]
fn a_nonexistent_config_gives_code_2_and_names_the_path() {
    let bench = Bench::new();
    let missing = bench.path("does/not/exist/config.toml");
    let out = bench
        .cmd()
        .args(["--config", &missing.to_string_lossy(), "doctor"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(EXIT_CONFIG));
    let text = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        text.contains(&missing.to_string_lossy().to_string()),
        "the error must name the path it looked for: {text}"
    );
}

#[test]
fn an_invalid_toml_gives_code_2_and_says_it_is_toml() {
    let bench = Bench::new();
    let config = bench.config("this is not toml [[[");
    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "doctor"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(EXIT_CONFIG));
    let text = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        text.contains("toml"),
        "the error must say the problem is the TOML: {text}"
    );
}

#[test]
fn a_config_without_targets_gives_code_2_and_says_so() {
    let bench = Bench::new();
    let config = bench.config("[defaults]\ncompression_level = 6\n");
    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "doctor"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(EXIT_CONFIG));
    let text = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        text.contains("target"),
        "the error must say targets are missing: {text}"
    );
}

#[test]
fn in_json_stdout_is_parseable_json_even_when_the_command_fails() {
    // It is what makes the tool usable from a script: `shieldbk --format json
    // backup | jq` has to work on the day the backup fails too.
    let bench = Bench::new();
    let missing = bench.path("does/not/exist/config.toml");
    let out = bench
        .cmd()
        .args([
            "--config",
            &missing.to_string_lossy(),
            "--format",
            "json",
            "doctor",
        ])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(EXIT_CONFIG));
    let json = json_of(&out.stdout);
    assert_eq!(json["ok"], serde_json::Value::Bool(false));
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("config"),
        "the JSON must carry the message: {json}"
    );
}

#[test]
fn in_json_no_log_slips_into_stdout() {
    // Standard output belongs to the result and nothing else may write there.
    // `-vv` raises tracing to `debug`, which is when there really is a volume of
    // log lines to slip through.
    let bench = Bench::new();
    let config = bench.config_mock("age1qqqqqqqqqq");
    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "-vv",
            "doctor",
            "does-not-exist",
        ])
        .output()
        .unwrap();

    assert_ne!(out.status.code(), Some(0));
    let json = json_of(&out.stdout);
    assert_eq!(json["ok"], serde_json::Value::Bool(false));
    assert!(
        !out.stderr.is_empty(),
        "with -vv there have to be logs, and they have to be on stderr"
    );
}

#[test]
fn plugin_lock_registers_the_directorys_binaries_and_writes_the_lockfile() {
    let bench = Bench::new();
    let config = bench.config_mock("age1qqqqqqqqqq");
    std::fs::write(bench.plugins_dir().join("sb-plugin-one"), b"binary one").unwrap();
    std::fs::write(bench.plugins_dir().join("sb-plugin-two"), b"binary two").unwrap();
    // A file that is not a plugin must not end up registered.
    std::fs::write(bench.plugins_dir().join("README.txt"), b"not a plugin").unwrap();

    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lock = std::fs::read_to_string(bench.lockfile()).unwrap();
    assert!(
        lock.contains("one"),
        "the lockfile must register one: {lock}"
    );
    assert!(
        lock.contains("two"),
        "the lockfile must register two: {lock}"
    );
    assert!(
        !lock.contains("README"),
        "a file that is not a plugin is not registered: {lock}"
    );
}

#[test]
fn plugin_verify_passes_after_lock_and_fails_if_the_binary_changes() {
    let bench = Bench::new();
    let config = bench.config_mock("age1qqqqqqqqqq");
    let binary = bench.plugins_dir().join("sb-plugin-one");
    std::fs::write(&binary, b"binary one").unwrap();

    let lock = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();
    assert!(lock.status.success());

    let good = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "verify"])
        .output()
        .unwrap();
    assert!(
        good.status.success(),
        "freshly registered it must verify: {}",
        String::from_utf8_lossy(&good.stderr)
    );

    alter(&binary);

    let bad = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "verify"])
        .output()
        .unwrap();
    assert_eq!(
        bad.status.code(),
        Some(3),
        "an altered binary is a plugin error"
    );
    let text = String::from_utf8_lossy(&bad.stderr).to_string();
    assert!(
        text.contains("one"),
        "the error must name the altered plugin: {text}"
    );
}

#[test]
fn a_nonexistent_target_gives_an_error_that_names_it() {
    let bench = Bench::new();
    let config = bench.config_mock("age1qqqqqqqqqq");
    let out = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "doctor",
            "the-one-not-there",
        ])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(EXIT_CONFIG));
    let text = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        text.contains("the-one-not-there"),
        "the error must name the target that was asked for: {text}"
    );
    assert!(
        text.contains("production"),
        "and help by saying which ones there are: {text}"
    );
}

#[test]
fn the_tilde_in_the_configurations_paths_is_expanded() {
    // The configuration is written by hand and its paths are written the way a
    // person would write them. No shell expands them when they are read from a
    // TOML, and without this expansion `shieldbk` would create a directory
    // literally named `~` inside the working directory: it would not fail, it
    // would do the right thing in the wrong place.
    let bench = Bench::new();
    let config = bench.config(
        r#"
[plugins]
dir = "~/plugins"
lockfile = "~/plugins.lock"

[[target]]
name = "production"
source = "mock"
storage = "mock"
recipient = "age1qqqqqqqqqq"
"#,
    );
    std::fs::write(bench.plugins_dir().join("sb-plugin-one"), b"one").unwrap();

    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        bench.lockfile().is_file(),
        "the lockfile had to end up at `{}`, which is where ~ points",
        bench.lockfile().display()
    );
    assert!(
        !bench.path("~").exists(),
        "a directory literally named `~` cannot have been created"
    );
}

// -- Installing plugins is a step that comes before configuring targets ------
//
// The lockfile only depends on the plugins directory, so the commands that
// manage it have to work with a configuration that does not declare any
// `[[target]]` yet. The ones that do back something up keep requiring them: the
// distinction is exactly what these tests pin down.

#[test]
fn plugin_lock_works_with_a_plugins_only_config() {
    let bench = Bench::new();
    let config = bench.config_plugins_only();
    std::fs::write(bench.plugins_dir().join("sb-plugin-one"), b"binary one").unwrap();
    std::fs::write(bench.plugins_dir().join("sb-plugin-two"), b"binary two").unwrap();

    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "sealing the lockfile needs no target; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lock = std::fs::read_to_string(bench.lockfile()).unwrap();
    assert!(
        lock.contains("one"),
        "the lockfile must register one: {lock}"
    );
    assert!(
        lock.contains("two"),
        "the lockfile must register two: {lock}"
    );
}

#[test]
fn plugin_verify_and_list_work_with_a_plugins_only_config() {
    let bench = Bench::new();
    let config = bench.config_plugins_only();
    std::fs::write(bench.plugins_dir().join("sb-plugin-one"), b"binary one").unwrap();

    let lock = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
        .output()
        .unwrap();
    assert!(lock.status.success());

    let verify = bench
        .cmd()
        .args([
            "--config",
            &config.to_string_lossy(),
            "--format",
            "json",
            "plugin",
            "verify",
        ])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert_eq!(json_of(&verify.stdout)["failed"], 0);

    let list = bench
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
        list.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let json = json_of(&list.stdout);
    assert_eq!(json["plugins"][0]["name"], "one");
    assert_eq!(json["plugins"][0]["status"], "registered");
}

#[test]
fn backup_with_a_plugins_only_config_still_requires_targets() {
    // The opposite would be worse than the problem it fixes: a `backup` that
    // starts, finds nothing to back up and finishes "fine".
    let bench = Bench::new();
    let config = bench.config_plugins_only();

    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "backup"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(EXIT_CONFIG));
    let text = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        text.contains("target"),
        "the error must say targets are missing: {text}"
    );
}

#[test]
fn doctor_with_a_plugins_only_config_still_requires_targets() {
    let bench = Bench::new();
    let config = bench.config_plugins_only();

    let out = bench
        .cmd()
        .args(["--config", &config.to_string_lossy(), "doctor"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(EXIT_CONFIG));
    let text = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        text.contains("target"),
        "the error must say targets are missing: {text}"
    );
}
