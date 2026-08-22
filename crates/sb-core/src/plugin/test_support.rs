//! Utilities shared by this module's tests.
//!
//! The process tests and the client tests start the same binary, and locating it
//! has more to it than it seems. It lives here so that there is a single recipe:
//! if tomorrow the place where cargo leaves binaries changes, it changes in one
//! spot.

/// Path of the mock plugin's binary.
///
/// `CARGO_BIN_EXE_*` is only defined by cargo for the binaries of the **own**
/// package, and the mock lives in another one. Since these tests are unit tests
/// —they live in `src/`, not in `tests/`—, their executable is always in
/// `target/<profile>/deps/`, so we go up one level to reach the
/// `target/<profile>/` where cargo leaves the binaries. If the mock is not built
/// yet it is built once, so that this file can be run in isolation with
/// `cargo test -p sb-core process`.
pub(crate) fn mock_path() -> std::path::PathBuf {
    use std::ffi::OsStr;
    use std::path::PathBuf;
    use std::sync::LazyLock;

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
            let status = cargo.status().unwrap();
            assert!(status.success(), "could not build the mock plugin");
        }
        assert!(
            binary.is_file(),
            "the mock plugin binary was not found at {}",
            binary.display()
        );
        binary
    });

    MOCK.clone()
}
