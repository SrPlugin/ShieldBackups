//! Expansion of `~` in the paths that come from the configuration.
//!
//! The configuration file is written by hand and shared between machines, so
//! its paths are written the way a person would write them:
//! `~/.shieldbk/plugins`. The shell expands that tilde when the argument goes
//! through it, but a path read from a TOML goes through no shell, and without
//! this `shieldbk` would look for the plugins in a directory literally named
//! `~`, created inside the working directory. The failure would not be an
//! error but something worse: it would work, in the wrong place.

use std::path::PathBuf;

/// Turns a configuration path into a system path.
///
/// Only bare `~` and `~/...` are expanded: the `~user` form would require
/// querying the system's user database and is left as is, which is what most
/// tools do and what avoids pretending to understand something that is not
/// understood.
///
/// If `HOME` is not defined the path is returned intact: it is preferable for
/// it to fail later naming the literal path -- which is what was looked for --
/// than to invent a home directory.
#[must_use]
pub fn expand(path: &str) -> PathBuf {
    let Some(home) = std::env::var_os("HOME") else {
        return PathBuf::from(path);
    };

    if path == "~" {
        return PathBuf::from(home);
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `HOME` is not touched here: changing the process environment is `unsafe`
    // as of edition 2024 and the workspace forbids it. These checks lean on the
    // real `HOME` -- always defined under cargo -- and it is the tests in
    // `tests/` that check the expansion with a fake home, because there the
    // binary is a child process and its environment can be set.

    #[test]
    fn an_absolute_path_is_left_alone() {
        assert_eq!(expand("/opt/plugins"), PathBuf::from("/opt/plugins"));
    }

    #[test]
    fn a_relative_path_is_left_alone() {
        assert_eq!(expand("plugins/local"), PathBuf::from("plugins/local"));
    }

    #[test]
    fn the_tilde_expands_to_the_home() {
        let Some(home) = std::env::var_os("HOME") else {
            return;
        };
        assert_eq!(
            expand("~/.shieldbk/plugins"),
            PathBuf::from(&home).join(".shieldbk/plugins")
        );
        assert_eq!(expand("~"), PathBuf::from(&home));
    }

    #[test]
    fn a_tilde_in_the_middle_of_a_path_means_nothing() {
        // Only the prefix is special: `/data/~/x` is a directory named that
        // way, not anybody's home.
        assert_eq!(expand("/data/~/x"), PathBuf::from("/data/~/x"));
        assert_eq!(expand("~other/x"), PathBuf::from("~other/x"));
    }
}
