//! Lo que necesita un plugin de `ShieldBackups` escrito en Rust.
//!
//! Un plugin completo son unas cien líneas: implementar los traits generados y
//! llamar a [`PluginRuntime::serve`].

pub mod runtime;

pub use runtime::{PluginRuntime, SdkError};

// Reexportados para que un plugin no tenga que declarar sb-proto ni tonic.
pub use sb_proto;
pub use tonic;
