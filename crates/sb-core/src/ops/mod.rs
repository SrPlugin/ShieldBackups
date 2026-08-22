//! The operations the user asks for: backup, restore, verify and doctor.
//!
//! Each one composes the same three pieces —two live plugins, two data channels
//! and the `sb-crypto` pipeline— and none of those pieces knows about the
//! others. This is where they come together, and therefore where the only thing
//! that fits in none of them lives: **the order in which they talk**.
//!
//! That order is the only thing specific to each operation, and that is why the
//! machinery the three share —creating the channel, issuing the RPC, waiting for
//! the connection with a deadline, draining the progress and translating the
//! failures— lives apart, in [`channel`]: if it lived here, this module would
//! stop being the map of which operations exist.
//!
//! [`doctor`] is the exception and that is why it shares none of the above: it
//! does not move bytes, so it needs no channel, and it **does not abort**, so it
//! does not need the common error either. Its job is to report in one go
//! everything that would stop the other three from working.

pub mod backup;
pub mod channel;
pub mod doctor;
pub mod restore;
pub mod verify;

// The error belongs to the three operations that move bytes, not to one of them:
// the machinery that produces it —deadlines, data channels, progress stream— is
// common and lives in `channel`.
pub use channel::BackupError;
