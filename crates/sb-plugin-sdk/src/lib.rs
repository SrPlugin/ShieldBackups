//! What a `ShieldBackups` plugin written in Rust needs.
//!
//! A complete plugin is about a hundred lines: implement the generated traits
//! and call [`PluginRuntime::serve`]. What every plugin shares lives here so
//! that none of them has to rewrite it:
//!
//! - [`PluginRuntime`] starts the process and ends it when the core calls
//!   `Shutdown`, which the SDK intercepts.
//! - [`Configured`] holds the configuration that `Configure` leaves behind and
//!   that the data services read, with the `failed_precondition` already
//!   written.
//! - [`progress_stream`] provides the scaffolding of the RPCs that move bytes.

pub mod configured;
pub mod progress;
pub mod runtime;
mod shutdown;

pub use configured::Configured;
pub use progress::{ProgressEmitter, ProgressStream, progress_stream};
pub use runtime::{PluginRuntime, SdkError};

// Re-exported so a plugin does not have to declare sb-proto or tonic itself.
pub use sb_proto;
pub use tonic;

/// Opens the data channel that the core created for a transfer.
///
/// It is re-exported from `sb-transport` because every plugin that moves bytes
/// needs it, and making them declare the transport crate for a single function
/// would go against the SDK being the only thing a plugin depends on.
pub use sb_transport::connect_data;
