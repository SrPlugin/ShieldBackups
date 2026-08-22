//! Artifact keys: from a core key to a path inside the storage target.
//!
//! A key arrives over the network from the core and ends up being a filesystem
//! path. That is exactly the place where one extra `..` stops being a detail
//! and becomes a write outside the target's directory, so the translation lives
//! in its own module and is tested on its own.

use std::path::{Component, Path, PathBuf};

use sb_plugin_sdk::tonic::Status;
use time::OffsetDateTime;

/// A stored artifact, as `List` sees it.
pub struct Artifact {
    pub key: String,
    pub size: u64,
    /// Last modification date in **RFC-3339 UTC**, as the `.proto` requires for
    /// `ArtifactMeta.modified_at`: `2026-08-21T09:30:00Z`. Empty string if the
    /// filesystem does not expose the date.
    pub modified_at: String,
}

/// Translates a key into a path inside `dir`.
///
/// Only keys made of normal components separated by `/` are accepted: that lets
/// `production/2026/08/21/x.age` through and rejects `../outside`,
/// `/etc/passwd` and `./a`, which are not keys but attempts to escape.
///
/// # Errors
/// [`Status::invalid_argument`] if the key is empty or contains any component
/// that is not a name.
pub fn path_for(dir: &Path, key: &str) -> Result<PathBuf, Status> {
    if key.is_empty() {
        return Err(Status::invalid_argument("the key cannot be empty"));
    }
    let relative = Path::new(key);
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(Status::invalid_argument(format!(
            "the key `{key}` escapes the storage target's directory: only relative paths without `.` or `..` are accepted"
        )));
    }
    Ok(dir.join(relative))
}

/// Walks `dir` and returns the artifacts whose key starts with `prefix`.
///
/// A directory that does not exist yet is an empty storage target, not an
/// error: listing a repository before the first backup must return zero
/// artifacts.
///
/// The result is sorted by key: a test storage target that returned the keys in
/// filesystem order would make a core test pass on one machine and fail on
/// another.
///
/// # Errors
/// Returns the I/O error if the directory exists but cannot be walked.
pub fn list(dir: &Path, prefix: &str) -> std::io::Result<Vec<Artifact>> {
    let mut found = Vec::new();
    if !dir.exists() {
        return Ok(found);
    }
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in std::fs::read_dir(&current)? {
            let entry = entry?;
            let path = entry.path();
            let meta = entry.metadata()?;
            if meta.is_dir() {
                pending.push(path);
                continue;
            }
            let Some(key) = key_for(dir, &path) else {
                continue;
            };
            if !key.starts_with(prefix) {
                continue;
            }
            found.push(Artifact {
                key,
                size: meta.len(),
                modified_at: modified_at(&meta),
            });
        }
    }
    found.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(found)
}

/// A file's key: its path relative to `dir`, with `/` as the separator.
fn key_for(dir: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(dir).ok()?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(n) => parts.push(n.to_str()?.to_string()),
            // A name that is not UTF-8, or an odd path, has no key to offer the
            // core; it is left out of the listing.
            _ => return None,
        }
    }
    Some(parts.join("/"))
}

/// The modification date in the only format the `.proto` accepts for
/// `ArtifactMeta.modified_at`: RFC-3339 with the time in UTC.
///
/// This storage target used to return the epoch in seconds. It was stable, but
/// the R2 plugin returns RFC-3339, and two targets that answer with
/// incomparable things silently break any date comparison across targets. The
/// format is now fixed by the contract and is merely honoured here.
///
/// A file whose date the system does not expose -- or that falls outside the
/// range of representable dates, which only happens with a broken clock --
/// yields an empty string: that is what the contract asks for "I don't know",
/// and it is preferable to inventing an instant that would later decide what
/// gets deleted.
fn modified_at(meta: &std::fs::Metadata) -> String {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
        .map_or_else(String::new, rfc3339)
}

/// `2026-08-21T09:30:00Z`.
///
/// Composed with `format!` over the accessors rather than with `time`'s
/// `formatting` feature, which would drag in proc-macros just for this. Without
/// fractional seconds, which is what the `.proto` fixes: a precision that one
/// target has and another does not would again make dates incomparable --
/// `...:15Z` sorts **after** `...:15.983Z`, because `Z` is greater than `.`.
fn rfc3339(date: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        date.year(),
        u8::from(date.month()),
        date.day(),
        date.hour(),
        date.minute(),
        date.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_plugin_sdk::tonic::Code;

    #[test]
    fn a_simple_key_lands_inside_the_directory() {
        let r = path_for(Path::new("/target"), "backup.age").unwrap();
        assert_eq!(r, PathBuf::from("/target/backup.age"));
    }

    #[test]
    fn a_key_with_slashes_keeps_the_hierarchy() {
        let r = path_for(Path::new("/target"), "production/2026/08/21/x.age").unwrap();
        assert_eq!(r, PathBuf::from("/target/production/2026/08/21/x.age"));
    }

    #[test]
    fn a_key_with_dot_dot_is_rejected() {
        for key in ["../outside", "a/../../outside", ".."] {
            let e = path_for(Path::new("/target"), key).unwrap_err();
            assert_eq!(e.code(), Code::InvalidArgument, "key {key}");
        }
    }

    #[test]
    fn an_absolute_key_is_rejected() {
        let e = path_for(Path::new("/target"), "/etc/passwd").unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument);
    }

    #[test]
    fn an_empty_key_is_rejected() {
        assert_eq!(
            path_for(Path::new("/target"), "").unwrap_err().code(),
            Code::InvalidArgument
        );
    }

    #[test]
    fn listing_a_nonexistent_directory_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let empty = list(&dir.path().join("never-created"), "").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn listing_walks_the_subdirectories_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::fs::write(dir.path().join("a/b/two.age"), b"xx").unwrap();
        std::fs::write(dir.path().join("one.age"), b"y").unwrap();

        let all = list(dir.path(), "").unwrap();
        let keys: Vec<&str> = all.iter().map(|a| a.key.as_str()).collect();
        assert_eq!(keys, vec!["a/b/two.age", "one.age"]);
        assert_eq!(all[0].size, 2);

        let filtered = list(dir.path(), "a/").unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].key, "a/b/two.age");
    }

    #[test]
    fn the_date_of_a_known_instant_is_rfc3339_in_utc() {
        // 1 771 234 200 = 2026-02-16T09:30:00Z. A fixed instant, not `now()`:
        // that way the test checks the format **and** the conversion, and does
        // not change its result depending on when it runs or in which time zone.
        let date = OffsetDateTime::from_unix_timestamp(1_771_234_200).unwrap();
        assert_eq!(rfc3339(date), "2026-02-16T09:30:00Z");
    }

    #[test]
    fn the_listing_returns_the_date_in_rfc3339_and_not_as_an_epoch() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("one.age"), b"y").unwrap();

        let all = list(dir.path(), "").unwrap();
        let date = &all[0].modified_at;

        // The exact shape the `.proto` fixes: `2026-08-21T09:30:00Z`. The shape
        // is checked rather than a concrete value because the date comes from
        // the filesystem.
        assert_eq!(
            date.len(),
            20,
            "`{date}` is not the length of an RFC-3339 UTC"
        );
        assert!(date.ends_with('Z'), "`{date}` does not end in Z");
        assert_eq!(&date[4..5], "-");
        assert_eq!(&date[7..8], "-");
        assert_eq!(&date[10..11], "T");
        assert_eq!(&date[13..14], ":");
        assert_eq!(&date[16..17], ":");
        // The decimal epoch is what this storage target used to return: if it
        // came back, the string would be all digits.
        assert!(
            !date.chars().all(|c| c.is_ascii_digit()),
            "`{date}` is still the epoch in seconds"
        );
        // And it can be read back as a date, which is what the core would do.
        let year: i32 = date[..4].parse().unwrap();
        assert!(year >= 2024, "`{date}` does not look like a real date");
    }
}
