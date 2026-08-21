//! Transporte entre el núcleo y los plugins.
//!
//! Lo usan tanto `sb-core` (lado cliente) como `sb-plugin-sdk` (lado servidor),
//! y por eso vive en su propio crate: un plugin no debe tener que compilar el
//! núcleo entero para poder hablar el protocolo.

pub mod pki;

pub use pki::{
    CLIENT_NAME, EphemeralPki, PkiError, SERVER_NAME, ServerBundle, server_config_from_bundle,
};
