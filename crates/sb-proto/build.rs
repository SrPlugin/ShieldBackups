//! Genera el código Rust del contrato a partir de `plugin.proto`.
//!
//! No hay `unsafe` aquí: la ruta de `protoc` se le pasa a `prost-build` por su
//! API (`Config::protoc_executable`) en vez de escribir la variable de entorno
//! `PROTOC`, que en edition 2024 exigiría `unsafe` y chocaría con el
//! `unsafe_code = "forbid"` del workspace.

const PROTO: &str = "proto/shieldbk/v1/plugin.proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();

    // Usa el protoc que traemos como dependencia en vez de exigir uno instalado
    // en el sistema. Respeta un PROTOC externo si quien compila prefiere el
    // suyo: en ese caso prost-build lo descubre solo desde el entorno.
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
