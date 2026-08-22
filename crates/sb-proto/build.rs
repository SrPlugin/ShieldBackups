//! Generates the Rust code for the contract from `plugin.proto`.
//!
//! There is no `unsafe` here: the path to `protoc` is handed to `prost-build`
//! through its API (`Config::protoc_executable`) instead of setting the
//! `PROTOC` environment variable, which under edition 2024 would require
//! `unsafe` and clash with the workspace-wide `unsafe_code = "forbid"`.

const PROTO: &str = "proto/shieldbk/v1/plugin.proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();

    // Use the protoc we vendor as a dependency instead of demanding one
    // installed system-wide. An external PROTOC is respected if whoever is
    // building prefers their own: in that case prost-build discovers it from
    // the environment on its own.
    if std::env::var_os("PROTOC").is_none() {
        config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    }

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_with_config(config, &[PROTO], &["proto"])?;

    println!("cargo:rerun-if-changed={PROTO}");
    Ok(())
}
