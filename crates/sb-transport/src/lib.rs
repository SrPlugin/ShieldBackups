//! Transporte entre el núcleo y los plugins.
//!
//! Lo usan tanto `sb-core` (lado cliente) como `sb-plugin-sdk` (lado servidor),
//! y por eso vive en su propio crate: un plugin no debe tener que compilar el
//! núcleo entero para poder hablar el protocolo.

pub mod control;
pub mod data;
pub mod handshake;
pub mod pki;

pub use control::{
    ControlError, connect_control, serve_control, serve_control_routes,
    serve_control_routes_con_parada,
};
pub use data::{DataChannel, connect_data};
pub use handshake::{Bootstrap, HANDSHAKE_VERSION, HandshakeError, MAGIC, READY_TIMEOUT_MS, Ready};
pub use pki::{
    CLIENT_NAME, EphemeralPki, PkiError, SERVER_NAME, ServerBundle, server_config_from_bundle,
};
