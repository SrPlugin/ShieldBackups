//! Plugins as seen from the core.
//!
//! A shieldbk plugin is not a linked library: it is a **separate process** that
//! is talked to over gRPC on a Unix socket with mTLS. This module is the core's
//! side of that relationship.

pub mod client;
pub mod process;

#[cfg(test)]
mod test_support;

pub use client::{Capability, PluginClient, PluginError};
pub use process::{PluginProcess, PluginProcessError};
