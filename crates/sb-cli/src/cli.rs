//! The shape of the command line, and nothing else.
//!
//! Nothing runs here: this file is the single description of what can be typed.
//! Keeping it apart means adding an option does not force reading any
//! implementation, and reading a command's implementation does not force diving
//! through `clap` attributes.

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};

use crate::output::Format;

/// Path of the configuration when `--config` is not passed.
pub const DEFAULT_CONFIG: &str = "~/.shieldbk/config.toml";

#[derive(Debug, Parser)]
#[command(
    name = "shieldbk",
    version,
    about = "End-to-end encrypted database backups",
    long_about = "shieldbk backs up databases through plugins that run as separate processes. The \
                  dump is compressed, encrypted with age and uploaded without ever touching the \
                  local disk.\n\nExit codes: 0 success, 2 configuration error, 3 plugin error, 4 \
                  operation error."
)]
pub struct Cli {
    /// TOML configuration file.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Format of standard output. Logs always go to stderr.
    #[arg(long, global = true, value_enum, default_value = "human")]
    pub format: Format,

    /// How many targets are processed at a time.
    ///
    /// One by default: several simultaneous dumps compete for the same disk and
    /// the same database, and the one that loses out is the server that is
    /// serving users.
    #[arg(long, global = true, value_name = "N", default_value_t = 1)]
    pub jobs: usize,

    /// Raises the trace level: `-v` info, `-vv` debug, `-vvv` trace.
    #[arg(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Back up one target, or all of them if none is named.
    Backup {
        /// Target to back up. Without it, all of them are backed up.
        target: Option<String>,
    },

    /// Restore an artifact onto the target's source.
    Restore {
        /// Target the restore is performed on.
        target: String,
        /// Key of the artifact in the storage target.
        artifact: String,
        /// File holding the age private key (`shieldbk keygen`).
        #[arg(long, value_name = "PATH")]
        identity: PathBuf,
    },

    /// Check that the artifacts are still intact. It does not need the key.
    Verify {
        /// Target whose artifacts are checked.
        target: String,
        /// A specific artifact. Without it, every artifact of the target is
        /// checked.
        artifact: Option<String>,
    },

    /// Diagnose a target -- or all of them -- before a real backup fails.
    Doctor {
        /// Target to diagnose. Without it, all of them are diagnosed.
        target: Option<String>,
    },

    /// Manage the plugins and the lockfile that authorises their binaries.
    Plugin {
        #[command(subcommand)]
        action: PluginAction,
    },

    /// Generate an age key pair: the key every backup is encrypted to.
    ///
    /// Nothing can be backed up without one: the public key goes into the
    /// `recipient` field of a target and every artifact is encrypted to it,
    /// while the private key is the only thing that can restore them.
    ///
    /// Without `--output` the private key is written to standard output in
    /// `age-keygen`'s format, so `shieldbk keygen > key.txt` works. With it,
    /// the file is created with `0600` permissions and an existing one is
    /// never overwritten.
    ///
    /// It needs no configuration file: this is what is run before there is
    /// one.
    Keygen {
        /// File the private key is written to. It is created with `0600` and
        /// an existing file is refused, never overwritten.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },

    /// Maintenance tasks on the storage target.
    Storage {
        #[command(subcommand)]
        action: StorageAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum PluginAction {
    /// List the binaries found and their status in the lockfile.
    List,
    /// Print a plugin's configuration schema. It never prints values.
    Docs {
        /// Plugin name, without the `sb-plugin-` prefix.
        plugin: String,
    },
    /// Check every plugin's hash without starting any of them.
    Verify,
    /// Register the hash of every binary in the directory and write the
    /// lockfile.
    Lock,
}

#[derive(Debug, Subcommand)]
pub enum StorageAction {
    /// Abort the incomplete uploads the storage target keeps charging for.
    Gc {
        /// Target whose storage is cleaned up.
        target: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn the_definition_is_coherent() {
        // clap's `debug_assert` catches the inconsistencies that would only
        // show up at runtime: repeated names, default values that do not match
        // their type, global options in impossible places.
        Cli::command().debug_assert();
    }

    #[test]
    fn all_seven_commands_are_there() {
        let names: Vec<String> = Cli::command()
            .get_subcommands()
            .map(|c| c.get_name().to_owned())
            .collect();
        for expected in [
            "backup", "restore", "verify", "doctor", "plugin", "storage", "keygen",
        ] {
            assert!(
                names.contains(&expected.to_owned()),
                "{expected} is missing"
            );
        }
    }

    #[test]
    fn the_global_options_work_after_the_subcommand() {
        // `shieldbk backup --format json` has to work just like
        // `shieldbk --format json backup`: nobody remembers where each thing
        // goes.
        let cli = Cli::try_parse_from(["shieldbk", "backup", "--format", "json", "-vv"]).unwrap();
        assert_eq!(cli.format, Format::Json);
        assert_eq!(cli.verbose, 2);
        assert!(matches!(cli.command, Command::Backup { target: None }));
    }

    #[test]
    fn jobs_is_one_by_default() {
        // The default value is a decision about operational safety, not a
        // detail: several dumps at once saturate the database server, and
        // whoever wants to take that risk has to ask for it.
        let cli = Cli::try_parse_from(["shieldbk", "backup"]).unwrap();
        assert_eq!(cli.jobs, 1);
    }

    #[test]
    fn restore_requires_the_identity() {
        // Without a private key there is no possible restore, so a plugin
        // cannot even be started without one.
        assert!(Cli::try_parse_from(["shieldbk", "restore", "t", "key"]).is_err());
        let cli =
            Cli::try_parse_from(["shieldbk", "restore", "t", "key", "--identity", "/k"]).unwrap();
        assert!(matches!(cli.command, Command::Restore { .. }));
    }

    #[test]
    fn verify_accepts_an_optional_artifact() {
        let all = Cli::try_parse_from(["shieldbk", "verify", "t"]).unwrap();
        assert!(matches!(
            all.command,
            Command::Verify { artifact: None, .. }
        ));
        let one = Cli::try_parse_from(["shieldbk", "verify", "t", "key"]).unwrap();
        assert!(matches!(
            one.command,
            Command::Verify {
                artifact: Some(_),
                ..
            }
        ));
    }
}
