//! The bucket's internal prefix: adding it and removing it.
//!
//! [`R2Config::key`](crate::config::R2Config::key) prepends the prefix to the
//! key the core sends. This module does the return trip, which is the one
//! `List` uses: the user never wrote the prefix when asking for the backup, and
//! seeing it show up in the results would make the key we hand back useless for
//! requesting that same artifact.
//!
//! It lives apart and without networking because the case that matters -- the
//! partial match -- is not visible by reading the code and only shows up with
//! certain prefix names.

/// Removes `prefix` from the beginning of `key`.
///
/// The prefix is compared **by whole segment**: `team` is not a prefix of
/// `team2/x.age`, even though it is one as text. Trimming it blindly would
/// yield `2/x.age`, a key that does not exist and that the core would try to
/// download.
///
/// A key that is not under the prefix is returned unchanged: in a shared bucket
/// there are objects that do not belong to this shieldbk, and mutilating them
/// would be worse than leaving them alone.
#[must_use]
pub fn without_prefix(key: &str, prefix: &str) -> String {
    // Slashes at the edges are noise: `R2Config` already strips them when
    // normalising, but this function is also called by the tests and the
    // preflight with whatever they happen to have.
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        return key.to_string();
    }
    // The chained `strip_prefix('/')` is the segment check: without it, `team`
    // would eat the beginning of `team2/x.age`. If there is no slash behind it,
    // the key is not inside the prefix and is returned intact.
    key.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(key)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_removes_the_prefix_from_the_returned_keys() {
        // The user configured a prefix; they must not see it in the results,
        // because they did not write it when asking for the backup.
        assert_eq!(
            without_prefix("team/backups/x.age", "team/backups"),
            "x.age"
        );
    }

    #[test]
    fn with_no_configured_prefix_the_key_does_not_change() {
        assert_eq!(without_prefix("x.age", ""), "x.age");
    }

    #[test]
    fn a_key_that_does_not_start_with_the_prefix_is_left_alone() {
        // Objects foreign to this shieldbk that share the bucket.
        assert_eq!(without_prefix("other/x.age", "team"), "other/x.age");
    }

    #[test]
    fn a_trailing_slash_in_the_prefix_does_not_get_in_the_way() {
        assert_eq!(without_prefix("team/x.age", "team/"), "x.age");
    }

    #[test]
    fn a_partially_matching_prefix_is_not_trimmed() {
        // `team2/x` is not inside `team`: trimming it would give `2/x`.
        assert_eq!(without_prefix("team2/x.age", "team"), "team2/x.age");
    }

    #[test]
    fn the_round_trip_through_the_prefix_is_stable() {
        // key() adds the prefix, without_prefix() removes it: they must cancel.
        for original in ["x.age", "a/b/c.age", "..odd.age", ".hidden"] {
            let full = format!("team/backups/{original}");
            assert_eq!(without_prefix(&full, "team/backups"), original);
        }
    }
}
