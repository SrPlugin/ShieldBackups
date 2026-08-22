//! `sb-plugin-r2`: the backup storage target on top of Cloudflare R2.
//!
//! R2 speaks the S3 protocol, which is why the plugin uses the AWS SDK. What is
//! not S3 -- the `auto` region, the account endpoint, the checksums and the
//! uniform part size -- is isolated in [`client`] and [`config`], with the
//! reason written next to it.
//!
//! ## Why this is a library and not just a binary
//!
//! The `sb-plugin-r2` binary is four lines and all the logic lives here. The
//! reason is that the modules must be exercisable **against a real server**:
//! `tests/integration.rs` brings up a `MinIO` in Docker, builds a
//! [`client::Context`] pointing at it and calls [`put::upload`],
//! [`admin::list`] and friends. With the modules private inside the binary,
//! those tests could only talk over gRPC and could not look inside the bucket
//! -- the parts of a half-uploaded multipart, for instance, which is exactly
//! what needs checking.

pub mod admin;
pub mod channel;
pub mod chunks;
pub mod client;
pub mod config;
pub mod get;
pub mod keys;
pub mod plugin;
pub mod put;
pub mod storage;
