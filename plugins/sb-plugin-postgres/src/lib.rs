//! `sb-plugin-postgres`: a source plugin that wraps `pg_dump`/`pg_restore`.
//!
//! It never speaks the `PostgreSQL` wire protocol itself: `Dump` streams the
//! stdout of `pg_dump` into the core's data channel and `Restore` streams the
//! channel into `pg_restore`'s stdin, `--single-transaction` so a truncated
//! restore leaves the database exactly as it found it.

pub mod command;
pub mod config;
pub mod plugin;
pub mod source;
