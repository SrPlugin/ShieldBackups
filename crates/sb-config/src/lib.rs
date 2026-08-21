//! Configuración de `shieldbk`: modelo del fichero TOML.
//!
//! El núcleo no conoce ningún motor ni ningún almacenamiento concretos. Lo que
//! el usuario escriba dentro de `engine_config` y `storage_config` viaja hasta
//! aquí como una tabla opaca y se valida después contra el esquema que el
//! plugin correspondiente declara por gRPC.

pub mod model;

pub use model::{
    Config, ConfigError, ConfigTable, ConfigValue, Defaults, PluginsConfig, SecretRef, Target,
};
