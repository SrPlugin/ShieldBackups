// Just as in `sb-core/tests/common/mod.rs`: this is all test code, and there an
// `unwrap` is what is wanted -- for the test to blow up exactly where it
// failed.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// This module is compiled into **each** test binary that declares it, and none
// of them uses all of its helpers.
#![allow(dead_code)]

//! What the CLI tests share: an isolated environment -- its own config, plugins
//! directory and lockfile -- and a convenient way of invoking the binary.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use assert_cmd::Command;

/// A complete test bench: its own `HOME`, its own config, its own plugins.
///
/// The own `HOME` is not a detail: the CLI expands `~` in the plugin and
/// lockfile paths, and a test that left the real `HOME` in place would write
/// into the home directory of whoever runs it.
pub struct Bench {
    pub root: tempfile::TempDir,
}

impl Bench {
    pub fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("plugins")).unwrap();
        std::fs::create_dir_all(root.path().join("data")).unwrap();
        Self { root }
    }

    pub fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    pub fn plugins_dir(&self) -> PathBuf {
        self.path("plugins")
    }

    pub fn data_dir(&self) -> PathBuf {
        self.path("data")
    }

    pub fn lockfile(&self) -> PathBuf {
        self.path("plugins.lock")
    }

    /// Writes the configuration and returns its path.
    pub fn config(&self, content: &str) -> PathBuf {
        let path = self.path("config.toml");
        std::fs::write(&path, content).unwrap();
        path
    }

    /// Minimal configuration with one target on the mock plugin.
    pub fn config_mock(&self, recipient: &str) -> PathBuf {
        self.config(&format!(
            r#"
[plugins]
dir = {dir:?}
lockfile = {lock:?}

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
            dir = self.plugins_dir().to_string_lossy(),
            lock = self.lockfile().to_string_lossy(),
            data = self.data_dir().to_string_lossy(),
        ))
    }

    /// Configuration with **only** the `[plugins]` section: not a single
    /// `[[target]]`.
    ///
    /// It is the one held by somebody who has just installed the plugins and
    /// has not yet decided which databases to back up -- the `Dockerfile`'s
    /// case, which seals the lockfile during the build.
    pub fn config_plugins_only(&self) -> PathBuf {
        self.config(&format!(
            r"
[plugins]
dir = {dir:?}
lockfile = {lock:?}
",
            dir = self.plugins_dir().to_string_lossy(),
            lock = self.lockfile().to_string_lossy(),
        ))
    }

    /// The binary, with the environment already isolated.
    pub fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shieldbk"));
        cmd.env("HOME", self.root.path());
        cmd.env_remove("RUST_LOG");
        cmd
    }

    /// Copies the mock plugin's binary into the plugins directory with the name
    /// the CLI expects to find: `sb-plugin-<name>`.
    pub fn install_mock(&self) -> PathBuf {
        let dest = self.plugins_dir().join("sb-plugin-mock");
        std::fs::copy(mock_path(), &dest).unwrap();
        dest
    }
}

/// Path of the mock plugin's binary.
///
/// `CARGO_BIN_EXE_*` is only defined by cargo for the **own** package's
/// binaries, and the mock lives in another one. It is located next to the test
/// executable and, if it is not built yet, it is built exactly once.
pub fn mock_path() -> PathBuf {
    static MOCK: LazyLock<PathBuf> = LazyLock::new(|| {
        let mut dir = std::env::current_exe().unwrap();
        dir.pop();
        if dir.ends_with("deps") {
            dir.pop();
        }
        let binary = dir.join("sb-plugin-mock");
        if !binary.is_file() {
            let release = dir.file_name() == Some(OsStr::new("release"));
            let mut cargo = std::process::Command::new(env!("CARGO"));
            cargo.args(["build", "-p", "sb-plugin-mock"]);
            if release {
                cargo.arg("--release");
            }
            assert!(
                cargo.status().unwrap().success(),
                "could not build the mock plugin"
            );
        }
        assert!(
            binary.is_file(),
            "the mock plugin's binary was not found at {}",
            binary.display()
        );
        binary
    });

    MOCK.clone()
}

/// Appends a byte to a file: it is the cheapest way of simulating a binary that
/// has changed since it was registered.
pub fn alter(path: &Path) {
    let mut bytes = std::fs::read(path).unwrap();
    bytes.push(0);
    std::fs::write(path, bytes).unwrap();
}

/// Parses standard output as JSON. It fails with the full text if it is not:
/// under `--format json` that is exactly what needs to be seen.
pub fn json_of(stdout: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(stdout);
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON ({e}):\n---\n{text}\n---"))
}
