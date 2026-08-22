//! `shieldbk` configuration: the model of the TOML file.
//!
//! The core knows no specific engine and no specific storage. Whatever the user
//! writes inside `engine_config` and `storage_config` travels up to here as an
//! opaque table and is validated later against the schema the corresponding
//! plugin declares over gRPC.

pub mod model;
pub mod secrets;
pub mod validate;

pub use model::{
    Config, ConfigError, ConfigTable, ConfigValue, Defaults, PluginsConfig, SecretRef, Target,
};
pub use secrets::{SecretError, resolve};
pub use validate::{ValidationError, validate_and_convert};
