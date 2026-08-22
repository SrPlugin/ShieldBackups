//! Secret resolution: turns a [`SecretRef`] into its value.
//!
//! # Why it lives here and not in each plugin
//!
//! The core is the only one that touches the secret sources —environment, file,
//! system keyring or external command—. The plugin receives the already resolved
//! value over the authenticated gRPC channel and never knows where it came from.
//! The secret policy thus stays in a single auditable place instead of being
//! reinvented, with different criteria, in every plugin.
//!
//! # The errors do not leak
//!
//! No [`SecretError`] contains the value that was read, nor the output of the
//! command that was run (neither `stdout` nor `stderr`), nor the bytes the
//! keyring returned. An error that leaks the credential it could not parse is
//! worse than useless: it ends up in a log, in a ticket and in a screenshot. The
//! variants below name the *origin* of the secret (a path, a variable, a
//! program), which is what the operator needs in order to fix it, and never its
//! contents.

use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};

use sb_crypto::Secret;
use zeroize::Zeroize as _;

use crate::model::SecretRef;

/// User assumed when the keyring entry does not carry `service/user`.
///
/// Whoever provisions the entry by hand needs to know it:
/// `secret-tool store --label=… service <service> username shieldbk`.
const DEFAULT_USER: &str = "shieldbk";

/// Mask of the group and "others" permissions.
///
/// Any bit set here means somebody who is not the owner can read, write or
/// execute the file.
const OTHERS_PERMISSIONS: u32 = 0o077;

/// Permission bits inside the `st_mode` returned by `stat(2)`.
///
/// [`std::fs::Permissions::mode`] also includes the file type (`0o100000` for a
/// regular file); without this mask the mode shown in the error would not look
/// like the one the operator passed to `chmod`.
const PERMISSION_BITS: u32 = 0o7777;

/// Failure while obtaining a secret's value.
///
/// **No variant contains the secret.** They all name its origin —a path, an
/// environment variable, a program, a keyring entry— because that is what is
/// needed to fix the problem, and none includes the value that was read or the
/// output of a command, which could carry it inside. This holds for `Display` as
/// well as for the derived `Debug`: every field is a string built here, never
/// data coming from the source.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// The referenced environment variable is not defined in the process.
    #[error("the environment variable \"{0}\" is not defined")]
    MissingVariable(String),

    /// The file could not be opened or read.
    ///
    /// `reason` is the operating system's message (for example "No such file or
    /// directory"): it describes the I/O failure, never the contents.
    #[error("could not read the secret from \"{path}\": {reason}")]
    ReadFailed {
        /// Path of the file that was attempted.
        path: String,
        /// Operating system message.
        reason: String,
    },

    /// The file is accessible to the group or to the rest of the world.
    #[error(
        "the secret file \"{path}\" has permissions {mode:04o} and is accessible to the group or \
         to others; fix it with \"chmod 600 {path}\", or use `file_insecure` if an orchestrator \
         mounts it"
    )]
    PermissionsTooOpen {
        /// Path of the rejected file.
        path: String,
        /// Permissions found, in octal.
        mode: u32,
    },

    /// The `command` reference does not even carry the program to run.
    #[error("the \"command\" reference is empty: the program to run is missing")]
    EmptyCommand,

    /// The command could not be launched, or ended with a non-zero code.
    ///
    /// The message names the program —which is already written in the
    /// configuration file— but **not** its output: a command that fails may have
    /// written the secret to `stdout` before failing, or dumped it into `stderr`
    /// next to the diagnosis. The specific reason (exit code or `exec` error) is
    /// logged through `tracing`, where the value does not travel.
    #[error(
        "the command \"{command}\" could not be run or ended with an error; its output is \
         deliberately omitted because it could contain the secret"
    )]
    CommandFailed {
        /// Program that was attempted (`argv[0]`), without its arguments.
        command: String,
    },

    /// The system keyring did not return the entry.
    ///
    /// `reason` is a fixed description chosen here from the keyring's error
    /// variant, not the library's `Display` or `Debug`: some of its variants
    /// carry the raw bytes of the credential inside.
    #[error("could not read the entry \"{entry}\" from the keyring: {reason}")]
    KeyringFailed {
        /// Requested entry, in `service/user` format.
        entry: String,
        /// Description of the failure, with no credential data.
        reason: String,
    },

    /// The value obtained is not valid UTF-8 text.
    ///
    /// It does not say which bytes failed nor at which position: that would
    /// already be a partial leak of the secret.
    #[error("the secret is not valid UTF-8")]
    NotUtf8,
}

/// Obtains a secret's value.
///
/// Only the core calls this. The plugin receives the result over the
/// authenticated channel and never knows where it came from.
///
/// The value comes back wrapped in [`Secret`], which is wiped from memory when
/// destroyed and implements neither `Debug` nor `Display`.
///
/// # Errors
///
/// Returns [`SecretError`] if the source does not exist, cannot be read, has
/// permissions that are too open, or does not contain UTF-8 text. No error
/// includes the secret's value.
pub fn resolve(reference: &SecretRef) -> Result<Secret<String>, SecretError> {
    match reference {
        SecretRef::Env(name) => from_env(name),
        SecretRef::File(path) => from_file(path, PermissionCheck::Enforced),
        SecretRef::FileInsecure(path) => from_file(path, PermissionCheck::Ignored),
        SecretRef::Keyring(entry) => from_keyring(entry),
        SecretRef::Command(argv) => from_command(argv),
    }
}

/// Whether a secret file has to prove restrictive permissions.
#[derive(Clone, Copy)]
enum PermissionCheck {
    /// Any group or others access is rejected.
    Enforced,
    /// Whatever is there is accepted and a warning is issued. See
    /// [`SecretRef::FileInsecure`].
    Ignored,
}

/// Reads the secret from an environment variable of the process.
///
/// The value is **not** trimmed: unlike a file, which an editor closes with a
/// `\n`, an environment variable is worth exactly what the operator exported, and
/// trimming it could silently break a password.
fn from_env(name: &str) -> Result<Secret<String>, SecretError> {
    match std::env::var(name) {
        Ok(value) => Ok(Secret::new(value)),
        Err(std::env::VarError::NotPresent) => Err(SecretError::MissingVariable(name.to_owned())),
        // `VarError::NotUnicode` carries the value inside and prints it in its
        // `Display`. It is discarded here so it never reaches the error message.
        Err(std::env::VarError::NotUnicode(_)) => Err(SecretError::NotUtf8),
    }
}

/// Reads the secret from a file's contents.
///
/// Permissions are checked on the already open descriptor, not on the path:
/// looking with `stat` and opening afterwards leaves a window in which somebody
/// can swap the file between the two operations.
fn from_file(path: &str, check: PermissionCheck) -> Result<Secret<String>, SecretError> {
    let failure = |reason: &std::io::Error| SecretError::ReadFailed {
        path: path.to_owned(),
        reason: reason.to_string(),
    };

    let mut file = std::fs::File::open(path).map_err(|e| failure(&e))?;
    let mode = file
        .metadata()
        .map_err(|e| failure(&e))?
        .permissions()
        .mode()
        & PERMISSION_BITS;

    match check {
        PermissionCheck::Enforced if mode & OTHERS_PERMISSIONS != 0 => {
            return Err(SecretError::PermissionsTooOpen {
                path: path.to_owned(),
                mode,
            });
        }
        PermissionCheck::Enforced => {}
        PermissionCheck::Ignored => tracing::warn!(
            path = %path,
            mode = %format!("{mode:04o}"),
            "secret read without checking permissions (`file_insecure`); \
             prefer `defaultMode: 0400` in the volume that mounts it"
        ),
    }

    let mut bytes = Vec::new();
    let read = file.read_to_end(&mut bytes).map_err(|e| failure(&e));
    let result = read.and_then(|_| {
        std::str::from_utf8(&bytes)
            .map(|text| trim_trailing_newlines(text).to_owned())
            .map_err(|_| SecretError::NotUtf8)
    });
    // The intermediate buffer held the secret in the clear; it is wiped here
    // because `Vec` does not do it when destroyed.
    bytes.zeroize();

    result.map(Secret::new)
}

/// Reads the secret from the system keyring.
///
/// `entry` is `service/user`; without a slash, the service is the whole entry and
/// the user is [`DEFAULT_USER`].
///
/// # Inside a container it does not work
///
/// The keyring is queried through D-Bus's Secret Service, which a container does
/// not have: there is no session bus and no agent to serve it. There `env` or
/// `file` is used —usually `file_insecure` over the secret the orchestrator
/// mounts—. It does not work over SSH without a graphical session, nor from
/// `cron`, for the same reason: the keyring is locked and nobody can unlock it.
fn from_keyring(entry: &str) -> Result<Secret<String>, SecretError> {
    let (service, user) = entry.split_once('/').unwrap_or((entry, DEFAULT_USER));

    let failure = |reason: &str| SecretError::KeyringFailed {
        entry: entry.to_owned(),
        reason: reason.to_owned(),
    };

    let credential =
        keyring::Entry::new(service, user).map_err(|e| failure(&keyring_reason(&e)))?;
    let value = credential
        .get_password()
        .map_err(|e| failure(&keyring_reason(&e)))?;

    Ok(Secret::new(value))
}

/// Translates a keyring error into a description that carries no data inside.
///
/// `keyring`'s `Display` and `Debug` are not used: its `BadEncoding` variant
/// stores the raw bytes of the credential and the derived `Debug` would print
/// them whole.
fn keyring_reason(error: &keyring::Error) -> String {
    let description = match error {
        keyring::Error::NoEntry => "the entry does not exist in the keyring",
        keyring::Error::NoDefaultStore => {
            "no keyring is available; inside a container there is no D-Bus, use `env` or `file`"
        }
        keyring::Error::NoStorageAccess(_) => "the keyring is locked or not accessible",
        keyring::Error::BadEncoding(_) => "the value stored in the keyring is not UTF-8",
        keyring::Error::Ambiguous(_) => "the entry matches more than one credential",
        keyring::Error::Invalid(attribute, _) => {
            return format!("the entry's attribute \"{attribute}\" is not valid");
        }
        _ => "system keyring failure",
    };
    description.to_owned()
}

/// Runs a command and takes its `stdout` as the secret.
///
/// **There is never a shell.** The program and its arguments go separately to
/// [`Command`], so an argument containing `;`, `$(…)` or `&&` is literal text for
/// the program and not another order. Command injection is eliminated by
/// construction, not filtered out by a list of forbidden characters.
///
/// `stdout` and `stderr` are captured —not inherited— so that the secret does not
/// show up in the terminal nor in `shieldbk`'s logs if the command writes it
/// where it should not. `stdin` is closed so that a program that wants to ask
/// something fails instead of hanging while it waits.
fn from_command(argv: &[String]) -> Result<Secret<String>, SecretError> {
    let (program, arguments) = argv.split_first().ok_or(SecretError::EmptyCommand)?;

    let output = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| {
            // The `exec` error (ENOENT, EACCES…) cannot contain the secret: the
            // program did not even get to start. It goes to the log, where it is
            // useful for diagnosis, and not to the error, whose shape is fixed.
            tracing::warn!(program = %program, error = %e, "could not run the secret command");
            SecretError::CommandFailed {
                command: program.clone(),
            }
        })?;

    let mut bytes = output.stdout;
    // `stderr` is not even looked at: the command may have dumped the secret
    // there next to the diagnosis. It is wiped without being read.
    let mut discarded = output.stderr;
    discarded.zeroize();

    let result = if output.status.success() {
        std::str::from_utf8(&bytes)
            .map(|text| trim_trailing_newlines(text).to_owned())
            .map_err(|_| SecretError::NotUtf8)
    } else {
        tracing::warn!(
            program = %program,
            status = %output.status,
            "the secret command ended with an error; its output is discarded without reading it"
        );
        Err(SecretError::CommandFailed {
            command: program.clone(),
        })
    };
    bytes.zeroize();

    result.map(Secret::new)
}

/// Trims the trailing line breaks, and nothing else.
///
/// An editor adds `\n` when saving and `echo` always puts one, so a secret from a
/// file or from a command almost never ends where the user thinks it does. Spaces
/// are respected, including trailing ones: a password may carry them and trimming
/// them would silently corrupt it.
fn trim_trailing_newlines(text: &str) -> &str {
    text.trim_end_matches(['\n', '\r'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Writes a secret file with the given permissions.
    fn secret_file(dir: &std::path::Path, name: &str, contents: &[u8], mode: u32) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents).unwrap();
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn resolves_from_an_existing_environment_variable() {
        // PATH always exists and there is no need to modify the environment,
        // which in edition 2024 would require `unsafe`.
        let r = resolve(&SecretRef::Env("PATH".into())).unwrap();
        assert!(!r.expose().is_empty());
    }

    #[test]
    fn a_missing_variable_gives_an_error_that_names_it() {
        let err = resolve(&SecretRef::Env("SB_DOES_NOT_EXIST_XYZ_123".into()))
            .err()
            .unwrap();
        assert!(err.to_string().contains("SB_DOES_NOT_EXIST_XYZ_123"));
    }

    #[test]
    fn resolves_from_a_file_with_correct_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(dir.path(), "secret", b"from-the-file\n", 0o600);
        let r = resolve(&SecretRef::File(path)).unwrap();
        assert_eq!(
            r.expose(),
            "from-the-file",
            "the trailing line break is trimmed"
        );
    }

    #[test]
    fn trailing_newlines_are_trimmed_but_not_the_inner_spaces() {
        // An editor adds \n when saving; a password may carry spaces.
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(dir.path(), "s", b"with spaces inside  \r\n", 0o600);
        assert_eq!(
            resolve(&SecretRef::File(path)).unwrap().expose(),
            "with spaces inside  "
        );
    }

    #[test]
    fn a_file_readable_by_the_group_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(dir.path(), "s", b"x", 0o640);
        assert!(matches!(
            resolve(&SecretRef::File(path)).err().unwrap(),
            SecretError::PermissionsTooOpen { .. }
        ));
    }

    #[test]
    fn a_world_readable_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(dir.path(), "s", b"x", 0o644);
        let err = resolve(&SecretRef::File(path)).err().unwrap();
        assert!(matches!(err, SecretError::PermissionsTooOpen { .. }));
        assert!(
            err.to_string().contains("chmod"),
            "it must say how to fix it"
        );
    }

    #[test]
    fn a_secret_mounted_by_the_orchestrator_is_accepted_with_the_opt_out() {
        // Docker mounts /run/secrets with 0444 and Kubernetes its own with 0644.
        // Rejecting them without an alternative would rule out the most common
        // use case in a container; relaxing the check by default would be worse.
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(dir.path(), "mounted", b"from-the-orchestrator\n", 0o444);

        assert!(
            resolve(&SecretRef::File(path.clone())).is_err(),
            "without the opt-out it is rejected"
        );
        assert_eq!(
            resolve(&SecretRef::FileInsecure(path)).unwrap().expose(),
            "from-the-orchestrator"
        );
    }

    #[test]
    fn the_opt_out_still_fails_if_the_file_does_not_exist() {
        // It relaxes the permissions, not the existence.
        assert!(resolve(&SecretRef::FileInsecure("/does/not/exist".into())).is_err());
    }

    #[test]
    fn resolves_by_running_a_command() {
        let r = resolve(&SecretRef::Command(vec![
            "/bin/echo".into(),
            "from-the-command".into(),
        ]))
        .unwrap();
        assert_eq!(r.expose(), "from-the-command");
    }

    #[test]
    fn a_command_that_fails_gives_an_error() {
        assert!(matches!(
            resolve(&SecretRef::Command(vec!["/bin/false".into()]))
                .err()
                .unwrap(),
            SecretError::CommandFailed { .. }
        ));
    }

    #[test]
    fn an_empty_command_is_rejected() {
        assert!(matches!(
            resolve(&SecretRef::Command(vec![])).err().unwrap(),
            SecretError::EmptyCommand
        ));
    }

    #[test]
    fn a_nonexistent_command_gives_an_error_and_not_a_panic() {
        assert!(resolve(&SecretRef::Command(vec!["/does/not/exist/command".into()])).is_err());
    }

    #[test]
    fn the_command_does_not_go_through_a_shell() {
        // If there were a shell, this would run two commands or interpret the
        // semicolon. Without a shell, ";" and "echo" are literal arguments of
        // /bin/echo. That is what eliminates injection by construction.
        let r = resolve(&SecretRef::Command(vec![
            "/bin/echo".into(),
            "one; echo two".into(),
        ]))
        .unwrap();
        assert_eq!(r.expose(), "one; echo two");
    }

    #[test]
    fn the_error_never_includes_the_secret_value() {
        // An error that leaks the credential it could not read is worse than
        // useless.
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(dir.path(), "s", b"ULTRASECRET-CONTENTS", 0o644);
        let text = resolve(&SecretRef::File(path)).err().unwrap().to_string();
        assert!(!text.contains("ULTRASECRET"));
    }

    #[test]
    fn the_command_error_does_not_include_its_output() {
        use std::os::unix::fs::PermissionsExt;

        // A command that fails may have written the secret to stdout before
        // failing, or dumped it into stderr.
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("leak.sh");
        std::fs::write(
            &script,
            b"#!/bin/sh\necho SECRET-ON-STDOUT\necho SECRET-ON-STDERR >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();

        let text = resolve(&SecretRef::Command(vec![
            script.to_string_lossy().into_owned(),
        ]))
        .err()
        .unwrap()
        .to_string();
        assert!(!text.contains("SECRET-ON-STDOUT"));
        assert!(!text.contains("SECRET-ON-STDERR"));
    }

    #[test]
    fn a_secret_that_is_not_utf8_gives_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(dir.path(), "binary", &[0xff, 0xfe, 0xfd], 0o600);
        assert!(resolve(&SecretRef::File(path)).is_err());
    }

    #[test]
    fn an_empty_secret_is_accepted_but_it_is_empty() {
        // It is not this layer's job to decide whether an empty password is
        // valid: the plugin will say so when it uses it. Here only what is there
        // is read.
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(dir.path(), "empty", b"", 0o600);
        assert_eq!(resolve(&SecretRef::File(path)).unwrap().expose(), "");
    }
}
