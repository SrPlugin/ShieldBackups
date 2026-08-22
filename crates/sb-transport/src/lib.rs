//! Transport between the core and the plugins.
//!
//! It is used both by `sb-core` (client side) and by `sb-plugin-sdk` (server
//! side), which is why it lives in its own crate: a plugin should not have to
//! compile the entire core just to speak the protocol.

pub mod control;
pub mod data;
pub mod handshake;
pub mod pki;

pub use control::{
    ControlError, connect_control, serve_control, serve_control_routes,
    serve_control_routes_with_shutdown,
};
pub use data::{DataChannel, connect_data};
pub use handshake::{Bootstrap, HANDSHAKE_VERSION, HandshakeError, MAGIC, READY_TIMEOUT_MS, Ready};
pub use pki::{
    CLIENT_NAME, EphemeralPki, PkiError, SERVER_NAME, ServerBundle, server_config_from_bundle,
};
