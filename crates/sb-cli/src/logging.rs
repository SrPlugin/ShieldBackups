//! Tracing, and the one rule that governs it: **it never writes to stdout**.
//!
//! `shieldbk`'s standard output belongs to the result. That is what lets
//! `shieldbk --format json backup | jq '.targets[].artifact_key'` work, and a
//! single log line slipping in there is enough to break it -- not
//! spectacularly, but with a `jq` that fails at three in the morning inside a
//! `cron` that had been working for months. So the subscriber is pinned to
//! stderr here, in one single place, and no other module of the binary builds
//! one.

use tracing_subscriber::EnvFilter;

/// Turns on tracing at the level `verbosity` asks for.
///
/// The scale starts at `warn` because silence is the correct behaviour of a
/// tool that runs unattended: a backup that goes well has nothing to say, and a
/// `cron` that mails a message for every `info` line ends up filtered into the
/// bin together with the warnings that did matter.
///
/// `RUST_LOG`, if it is defined, wins over `-v`: whoever exports it is asking
/// for finer control -- per module -- than fits in a letter counter, and
/// overriding it would be ignoring the more specific of the two requests.
pub fn init(verbosity: u8) {
    let default = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));

    // Failing here can only mean somebody already installed a subscriber, and
    // in a binary that starts once that cannot happen. That it not be a reason
    // to abort does matter: being left without logs is annoying, not being able
    // to make the backup is serious.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}
