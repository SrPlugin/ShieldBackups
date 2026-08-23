//! `shieldbk keygen`: the key pair everything else hangs from.
//!
//! Without an age key there is no backup: every artifact is encrypted to a
//! public key that the configuration names in `recipient`. Before this command
//! existed the only way to obtain one was installing `age-keygen` separately,
//! which turned "try the tool" into "install another tool first". The crypto
//! was already here; what was missing was the door.
//!
//! Two rules shape this file, and both are about the private key:
//!
//! * **It never enters a [`Report`].** The report is what [`crate::output`]
//!   turns into text or JSON, and JSON goes to CI logs and shell histories. By
//!   writing the key straight to its destination -- the file or standard
//!   output -- and handing back a report that only carries the public half, no
//!   later change to the emitter can leak it.
//! * **The file is born private.** It is created with `0600` in the same
//!   syscall, not `chmod`ed afterwards: between an open `0644` and a later
//!   `chmod` there is a window in which any user on the machine can read the
//!   key, and a key that has been read once is compromised forever.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use sb_crypto::{Identity, Secret};
use time::OffsetDateTime;

use crate::error::CliError;
use crate::output::{Format, Report};

/// Permissions of the key file: readable by its owner and by nobody else.
const PRIVATE_MODE: u32 = 0o600;

/// Generates an age key pair.
///
/// With `output` the private key goes to that file, which is refused if it
/// already exists. Without it, the key goes to standard output in
/// `age-keygen`'s format so that `shieldbk keygen > key.txt` works -- except
/// under `--format json`, where standard output belongs to the document and a
/// private key has no business being in it.
///
/// # Errors
/// Returns [`CliError::Config`] if the destination file already exists --
/// overwriting it would destroy the only copy of a key -- and
/// [`CliError::Operation`] if it cannot be created or written.
pub fn run(format: Format, output: Option<&Path>) -> Result<Report, CliError> {
    let identity = Identity::generate();
    let public_key = identity.to_recipient().to_string();
    let contents = key_file(&identity, &public_key);

    let written = if let Some(path) = output {
        write_privately(path, contents.expose())?;
        Some(path)
    } else {
        // Under `--format json` standard output is the document and nothing
        // else, so the key is simply not disclosed: `advise` says so rather
        // than letting somebody believe it was saved somewhere.
        if matches!(format, Format::Human) {
            print!("{}", contents.expose());
        }
        None
    };

    advise(format, &public_key, written);

    Ok(Report::new(
        String::new(),
        serde_json::json!({
            "public_key": public_key,
            "path": written.map(|p| p.display().to_string()),
        }),
    ))
}

/// The key file, in the exact shape `age-keygen` writes it.
///
/// The shape is not decoration: it is what makes the output interchangeable
/// with an `age-keygen` file, so anything already reading one -- including
/// `shieldbk restore --identity` -- accepts this without knowing which of the
/// two produced it. The public key travels in a comment so that whoever kept
/// only the file can still read off what to put in `recipient`.
///
/// It comes back wrapped in a [`Secret`] because it contains the private key:
/// the wrapper is what stops it from being printed by accident, and it wipes
/// the buffer when the value goes out of scope.
fn key_file(identity: &Identity, public_key: &str) -> Secret<String> {
    Secret::new(format!(
        "# created: {}\n# public key: {public_key}\n{}\n",
        now_utc(),
        identity.to_secret_string().expose(),
    ))
}

/// The current instant as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Composed with `format!` rather than with `time`'s formatting feature, just
/// as `sb-core::naming` does: the accessors are enough and the proc-macro
/// dependency is not worth one line of text.
fn now_utc() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// Creates the file with `0600` from the outset and writes the key into it.
///
/// `create_new` makes the "does it exist?" check and the creation a single
/// atomic operation, so there is no instant in which an existing key file
/// could be truncated. That refusal is the whole point: every backup encrypted
/// to the previous key becomes unreadable the moment it is overwritten, and
/// nothing can undo it.
fn write_privately(path: &Path, contents: &str) -> Result<(), CliError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_MODE)
        .open(path)
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                CliError::config(format!(
                    "`{}` already exists and will not be overwritten: if it holds a key, every \
                     backup encrypted to it would become unreadable. Choose another path or move \
                     that file aside",
                    path.display()
                ))
            } else {
                CliError::operation(format!("could not create `{}`: {source}", path.display()))
            }
        })?;

    // The message says nothing of what was being written: it was a private
    // key, and an error quoting it would leave it in the log.
    file.write_all(contents.as_bytes())
        .and_then(|()| file.flush())
        .map_err(|source| {
            CliError::operation(format!(
                "could not write the key to `{}`: {source}",
                path.display()
            ))
        })
}

/// Says on standard error what the person needs to know, never the key itself.
///
/// Standard error and not standard output, because standard output is either
/// the key being piped into a file or the JSON document: anything else added
/// there would corrupt one or the other.
fn advise(format: Format, public_key: &str, written: Option<&Path>) {
    // The lock is taken once and held to the end: these lines are one message
    // and they must not be interleaved with anything else.
    let mut err = std::io::stderr().lock();

    if let Some(path) = written {
        let _ = writeln!(
            err,
            "the private key was written to `{}` with 0600 permissions.\nThere is no way to \
             recover it: whoever loses that file loses every backup encrypted to it.",
            path.display()
        );
    } else if matches!(format, Format::Json) {
        // Saying it plainly beats letting somebody believe a key they never
        // saw was saved somewhere.
        let _ = writeln!(
            err,
            "the private key was NOT printed: `--format json` never carries it, because that \
             output ends up in CI logs and shell histories. Run without `--format json` to get it \
             on standard output, or pass `--output <path>` to write it to a file."
        );
    }

    let _ = writeln!(err, "# public key: {public_key}");
    let _ = writeln!(
        err,
        "Copy that public key into the `recipient` field of your target."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_has_age_keygens_three_lines_and_the_matching_public_key() {
        let identity = Identity::generate();
        let public_key = identity.to_recipient().to_string();
        let file = key_file(&identity, &public_key);

        let lines: Vec<&str> = file.expose().lines().collect();
        assert_eq!(lines.len(), 3, "created, public key and the key itself");
        assert!(lines[0].starts_with("# created: "));
        assert_eq!(lines[1], format!("# public key: {public_key}"));
        assert!(lines[2].starts_with("AGE-SECRET-KEY-1"));

        // And it reads back as what it claims to be: a file with the right
        // shape but a mismatched key would encrypt backups nobody can open.
        let parsed = Identity::parse(file.expose()).unwrap();
        assert_eq!(parsed.to_recipient().to_string(), public_key);
    }

    #[test]
    fn the_timestamp_is_utc_and_readable() {
        let now = now_utc();
        assert_eq!(now.len(), 20, "YYYY-MM-DDTHH:MM:SSZ");
        assert!(now.ends_with('Z'), "UTC, never the local time zone");
    }

    #[test]
    fn the_key_file_is_created_with_0600_and_not_widened_afterwards() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.txt");
        write_privately(&path, "AGE-SECRET-KEY-1TEST\n").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn an_existing_file_is_refused_as_a_configuration_error_and_survives() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.txt");
        std::fs::write(&path, "the only copy\n").unwrap();

        let error = write_privately(&path, "AGE-SECRET-KEY-1TEST\n").unwrap_err();
        assert_eq!(error.code(), crate::error::EXIT_CONFIG);
        assert!(
            error.to_string().contains("already exists"),
            "the message has to say why it refused: {error}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "the only copy\n");
    }

    #[test]
    fn the_report_carries_the_public_key_and_never_the_private_one() {
        // The rule this whole file exists to keep: whatever the emitter does
        // with a report, it cannot leak a key it was never given.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.txt");
        let report = run(Format::Json, Some(&path)).unwrap();

        let document = serde_json::to_string(&report.json).unwrap();
        assert!(
            !document.contains("AGE-SECRET-KEY-1"),
            "the private key must not be in the report: {document}"
        );
        assert!(report.human.is_empty(), "nor in the human text");

        let content = std::fs::read_to_string(&path).unwrap();
        let identity = Identity::parse(&content).unwrap();
        assert_eq!(
            report.json["public_key"],
            identity.to_recipient().to_string()
        );
        assert_eq!(report.json["path"], path.display().to_string());
    }

    #[test]
    fn without_a_destination_the_report_says_there_is_no_path() {
        // A script has to be able to tell "it was saved" from "it went by on
        // standard output" without guessing.
        let report = run(Format::Json, None).unwrap();
        assert!(report.json["path"].is_null());
        assert!(
            report.json["public_key"]
                .as_str()
                .is_some_and(|k| k.starts_with("age1"))
        );
    }
}
