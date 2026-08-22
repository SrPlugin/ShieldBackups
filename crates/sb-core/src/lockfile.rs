//! Plugin lockfile: integrity verification of the binaries that `shieldbk` is
//! about to execute.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Version of the lockfile format. It is bumped only on changes that an older
/// reader could not safely interpret.
pub const LOCKFILE_VERSION: u32 = 1;

/// Size of the chunk fed to the hasher. Neither the binary nor a full buffer is
/// loaded into memory.
const CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum LockfileError {
    #[error("could not read \"{path}\": {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not write \"{path}\": {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "the plugin \"{name}\" is not registered in the lockfile. shieldbk does not run binaries \
         it has not verified. Check that \"{path}\" is the binary you expect and register it with \
         `shieldbk plugin lock {name}`"
    )]
    NotRegistered { name: String, path: PathBuf },
    #[error(
        "the binary of plugin \"{name}\" ({path}) has changed since it was registered: the \
         lockfile expected sha256 {expected} and the file has {found}. If the change is expected \
         (you updated the plugin), register it again with `shieldbk plugin lock {name}`. If you \
         were not expecting it, do NOT run it: the binary receives the credentials of your \
         database and of your storage"
    )]
    HashMismatch {
        name: String,
        path: PathBuf,
        expected: String,
        found: String,
    },
    #[error("the lockfile is not valid: {0}")]
    InvalidToml(String),
}

/// Lowercase hexadecimal SHA-256 of a file's contents.
///
/// It reads in a streaming fashion, in 64 KiB chunks: a compiled Rust binary can
/// weigh tens of megabytes and this runs before **every** plugin startup, so the
/// file is never loaded whole into memory.
///
/// # Errors
/// Returns [`LockfileError::Read`] if the file does not exist or cannot be
/// read.
pub fn file_hash(path: &Path) -> Result<String, LockfileError> {
    let mut file = std::fs::File::open(path).map_err(|source| LockfileError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; CHUNK];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| LockfileError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(to_hex(&hasher.finalize()))
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    sha256: String,
}

/// The document exactly as it is serialized to TOML. Kept apart from
/// [`Lockfile`] so that the format version is not part of the in-memory state.
#[derive(Debug, Serialize, Deserialize)]
struct Document {
    version: u32,
    #[serde(default)]
    plugins: BTreeMap<String, Entry>,
}

/// Record of the plugin binaries this system has approved, with the SHA-256 of
/// each one.
///
/// A plugin receives the credentials of the database and of the object storage:
/// running a binary whose contents have not been verified means running
/// arbitrary code with access to those secrets. Before starting a plugin,
/// `shieldbk` recomputes the binary's hash and compares it with the registered
/// one. The idea is the same as Terraform's provider lockfile.
///
/// # What it protects and what it does not
///
/// It protects against the binary **changing** since it was registered: a silent
/// update, a substitution on the `PATH`, a compromise of the server that
/// rewrites the file.
///
/// It does **not** protect against a plugin that is malicious from the very
/// first moment. That is impossible by construction: a plugin needs the
/// credentials to do its job, so registering the wrong binary means having given
/// the secrets to the wrong binary. Trusting the plugin's origin is a decision
/// of whoever registers it; the lockfile only guarantees that it is still the
/// same one.
///
/// The entries are kept in a [`BTreeMap`]: the stable ordering makes the
/// generated TOML deterministic and its diffs readable, because this file is
/// reviewed by hand and kept under version control.
#[derive(Debug, Default, Clone)]
pub struct Lockfile {
    plugins: BTreeMap<String, Entry>,
}

impl Lockfile {
    /// Registers (or re-registers) a plugin's binary with the hash it has right
    /// now.
    ///
    /// Re-registering is the normal operation after updating a plugin: the
    /// previous hash is replaced.
    ///
    /// # Errors
    /// Returns [`LockfileError::Read`] if the binary cannot be read.
    pub fn register(&mut self, name: &str, path: &Path) -> Result<(), LockfileError> {
        let sha256 = file_hash(path)?;
        self.plugins.insert(name.to_owned(), Entry { sha256 });
        Ok(())
    }

    /// Checks that the binary at `path` is still the one registered under
    /// `name`.
    ///
    /// # Errors
    /// - [`LockfileError::NotRegistered`] if the plugin is not in the lockfile.
    /// - [`LockfileError::HashMismatch`] if the binary has changed.
    /// - [`LockfileError::Read`] if the binary cannot be read.
    pub fn verify(&self, name: &str, path: &Path) -> Result<(), LockfileError> {
        let Some(entry) = self.plugins.get(name) else {
            return Err(LockfileError::NotRegistered {
                name: name.to_owned(),
                path: path.to_path_buf(),
            });
        };
        let found = file_hash(path)?;
        if found == entry.sha256 {
            Ok(())
        } else {
            Err(LockfileError::HashMismatch {
                name: name.to_owned(),
                path: path.to_path_buf(),
                expected: entry.sha256.clone(),
                found,
            })
        }
    }

    /// Names of the registered plugins, in stable alphabetical order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.plugins.keys().cloned().collect()
    }

    /// Serializes the lockfile to TOML. The output depends only on the content,
    /// not on the order in which the plugins were registered.
    ///
    /// # Errors
    /// Returns [`LockfileError::InvalidToml`] if serialization fails.
    pub fn to_toml(&self) -> Result<String, LockfileError> {
        let document = Document {
            version: LOCKFILE_VERSION,
            plugins: self.plugins.clone(),
        };
        toml::to_string(&document).map_err(|e| LockfileError::InvalidToml(e.to_string()))
    }

    /// Parses the TOML contents of a lockfile.
    ///
    /// # Errors
    /// Returns [`LockfileError::InvalidToml`] if the text is not valid TOML,
    /// does not have the expected shape, or comes from a newer version of the
    /// format.
    pub fn from_toml(text: &str) -> Result<Self, LockfileError> {
        let document: Document =
            toml::from_str(text).map_err(|e| LockfileError::InvalidToml(e.to_string()))?;
        if document.version > LOCKFILE_VERSION {
            return Err(LockfileError::InvalidToml(format!(
                "lockfile of version {}, this version of shieldbk supports up to {LOCKFILE_VERSION}",
                document.version
            )));
        }
        Ok(Self {
            plugins: document.plugins,
        })
    }

    /// Loads the lockfile from disk.
    ///
    /// If the file does not exist it returns an empty lockfile: the first time
    /// somebody uses `shieldbk` nothing is registered yet, and that is not a
    /// configuration error. The difference shows up on the first
    /// [`verify`](Self::verify), with a message that says what to do.
    ///
    /// # Errors
    /// Returns [`LockfileError::Read`] if the file exists but cannot be read, or
    /// [`LockfileError::InvalidToml`] if its contents are not valid.
    pub fn load(path: &Path) -> Result<Self, LockfileError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_toml(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(LockfileError::Read {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Writes the lockfile to disk.
    ///
    /// # Errors
    /// Returns [`LockfileError::Write`] if the file cannot be written or
    /// [`LockfileError::InvalidToml`] if serialization fails.
    pub fn save(&self, path: &Path) -> Result<(), LockfileError> {
        let text = self.to_toml()?;
        std::fs::write(path, text).map_err(|source| LockfileError::Write {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn fake_binary(dir: &std::path::Path, name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents).unwrap();
        path
    }

    #[test]
    fn computes_the_hash_of_a_binary() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_binary(dir.path(), "sb-plugin-x", b"contents");
        let hash = file_hash(&path).unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, file_hash(&path).unwrap());
    }

    #[test]
    fn the_hash_matches_the_known_sha256() {
        // Checks against an external value, not just against itself: a
        // consistent but incorrect hash would pass the previous test just fine.
        let dir = tempfile::tempdir().unwrap();
        let path = fake_binary(dir.path(), "sb-plugin-x", b"abc");
        assert_eq!(
            file_hash(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_hash_of_an_empty_file_is_the_known_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_binary(dir.path(), "empty", b"");
        assert_eq!(
            file_hash(&path).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hashing_a_nonexistent_file_is_an_error() {
        assert!(file_hash(std::path::Path::new("/does/not/exist")).is_err());
    }

    #[test]
    fn accepts_a_binary_whose_hash_matches() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_binary(dir.path(), "sb-plugin-x", b"contents");
        let mut lock = Lockfile::default();
        lock.register("x", &path).unwrap();
        assert!(lock.verify("x", &path).is_ok());
    }

    #[test]
    fn rejects_a_modified_binary() {
        // The case that justifies the whole module.
        let dir = tempfile::tempdir().unwrap();
        let path = fake_binary(dir.path(), "sb-plugin-x", b"original");
        let mut lock = Lockfile::default();
        lock.register("x", &path).unwrap();

        fake_binary(dir.path(), "sb-plugin-x", b"MODIFIED");

        let err = lock.verify("x", &path).unwrap_err();
        assert!(matches!(err, LockfileError::HashMismatch { .. }));
    }

    #[test]
    fn detects_a_single_byte_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_binary(dir.path(), "p", &vec![7_u8; 100_000]);
        let mut lock = Lockfile::default();
        lock.register("p", &path).unwrap();

        let mut data = vec![7_u8; 100_000];
        data[50_000] = 8;
        fake_binary(dir.path(), "p", &data);

        assert!(lock.verify("p", &path).is_err());
    }

    #[test]
    fn rejects_a_plugin_that_is_not_in_the_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_binary(dir.path(), "sb-plugin-y", b"c");
        let lock = Lockfile::default();
        assert!(matches!(
            lock.verify("y", &path).unwrap_err(),
            LockfileError::NotRegistered { .. }
        ));
    }

    #[test]
    fn registering_again_updates_the_hash() {
        // Updating a plugin is legitimate; re-registering it must be possible.
        let dir = tempfile::tempdir().unwrap();
        let path = fake_binary(dir.path(), "p", b"v1");
        let mut lock = Lockfile::default();
        lock.register("p", &path).unwrap();
        fake_binary(dir.path(), "p", b"v2");
        assert!(lock.verify("p", &path).is_err());
        lock.register("p", &path).unwrap();
        assert!(lock.verify("p", &path).is_ok());
    }

    #[test]
    fn round_trip_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_binary(dir.path(), "sb-plugin-x", b"c");
        let mut lock = Lockfile::default();
        lock.register("x", &path).unwrap();

        let text = lock.to_toml().unwrap();
        let back = Lockfile::from_toml(&text).unwrap();
        assert!(back.verify("x", &path).is_ok());
    }

    #[test]
    fn the_generated_toml_is_deterministic() {
        // The lockfile is reviewed by hand and kept under version control: its
        // diffs must be readable, not reshuffled on every write.
        let dir = tempfile::tempdir().unwrap();
        let a = fake_binary(dir.path(), "a", b"1");
        let b = fake_binary(dir.path(), "b", b"2");
        let c = fake_binary(dir.path(), "c", b"3");

        let mut one = Lockfile::default();
        one.register("zeta", &c).unwrap();
        one.register("alpha", &a).unwrap();
        one.register("mu", &b).unwrap();

        let mut two = Lockfile::default();
        two.register("alpha", &a).unwrap();
        two.register("mu", &b).unwrap();
        two.register("zeta", &c).unwrap();

        assert_eq!(one.to_toml().unwrap(), two.to_toml().unwrap());
    }

    #[test]
    fn a_corrupt_toml_is_an_error_and_not_a_panic() {
        assert!(matches!(
            Lockfile::from_toml("this is not toml [[[").unwrap_err(),
            LockfileError::InvalidToml(_)
        ));
    }

    #[test]
    fn a_missing_lockfile_is_treated_as_empty() {
        // The first time somebody uses shieldbk the file does not exist. The
        // difference shows up on the first `verify`, with a message that says
        // what to do, not with a file-not-found error.
        let dir = tempfile::tempdir().unwrap();
        let lock = Lockfile::load(&dir.path().join("does-not-exist.lock")).unwrap();
        assert!(matches!(
            lock.verify("x", std::path::Path::new("/bin/true"))
                .unwrap_err(),
            LockfileError::NotRegistered { .. }
        ));
    }

    #[test]
    fn save_and_load_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = fake_binary(dir.path(), "p", b"x");
        let lock_path = dir.path().join("plugins.lock");

        let mut lock = Lockfile::default();
        lock.register("p", &bin_path).unwrap();
        lock.save(&lock_path).unwrap();

        assert!(
            Lockfile::load(&lock_path)
                .unwrap()
                .verify("p", &bin_path)
                .is_ok()
        );
    }

    #[test]
    fn the_error_message_says_what_to_do() {
        // An error that only says "does not match" leaves the user in the dark
        // at three in the morning. It must say what happened and how to go on.
        let dir = tempfile::tempdir().unwrap();
        let path = fake_binary(dir.path(), "sb-plugin-x", b"a");
        let mut lock = Lockfile::default();
        lock.register("x", &path).unwrap();
        fake_binary(dir.path(), "sb-plugin-x", b"b");

        let text = lock.verify("x", &path).unwrap_err().to_string();
        assert!(
            text.contains("plugin lock"),
            "it must say how to re-register it"
        );
        assert!(text.contains('x'), "it must name the plugin");
    }

    #[test]
    fn the_not_registered_error_also_says_what_to_do() {
        let lock = Lockfile::default();
        let text = lock
            .verify("ghost", std::path::Path::new("/bin/true"))
            .unwrap_err()
            .to_string();
        assert!(text.contains("plugin lock"));
        assert!(text.contains("ghost"));
    }

    #[test]
    fn lists_the_registered_plugins() {
        let dir = tempfile::tempdir().unwrap();
        let a = fake_binary(dir.path(), "a", b"1");
        let mut lock = Lockfile::default();
        lock.register("two", &a).unwrap();
        lock.register("one", &a).unwrap();
        let names = lock.names();
        assert_eq!(names, vec!["one", "two"], "in stable order");
    }
}
