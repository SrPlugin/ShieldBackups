//! The contract between the core and the plugins.
//!
//! This crate holds no logic: only the code generated from
//! `proto/shieldbk/v1/plugin.proto`, which is the source of truth for the
//! protocol.

/// Protocol version implemented by this build.
///
/// It is bumped only for changes an older plugin could not cope with. Adding
/// fields to a message does **not** require bumping it: protobuf tolerates that
/// by design, and that is exactly why protobuf was chosen.
pub const PROTOCOL_VERSION: u32 = 1;

pub mod v1 {
    // The generated code does not follow our style conventions.
    #![allow(clippy::pedantic, clippy::all)]

    tonic::include_proto!("shieldbk.v1");
}

pub use v1::*;
