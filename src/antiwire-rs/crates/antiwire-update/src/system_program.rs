//! Finds the Linux system tools the updater runs: the package managers,
//! `systemctl` and `systemd-run`.
//!
//! A privileged process names the program it runs by absolute path in a system
//! directory, because `PATH` is not to be trusted. These tools live in one of
//! the directories below, depending on the distribution and on whether `/usr`
//! is merged; only root can write any of them.

use std::path::{Path, PathBuf};

const SYSTEM_DIRS: [&str; 4] = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"];

/// `name` in the system directories, or `None` when it is not installed.
#[must_use]
pub(crate) fn system_program(name: &str) -> Option<PathBuf> {
    SYSTEM_DIRS
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
}

/// [`system_program`], or a `NotFound` error naming `name`.
///
/// # Errors
///
/// When `name` is in none of the system directories.
pub(crate) fn require_system_program(name: &str) -> std::io::Result<PathBuf> {
    system_program(name).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{name} is not installed in a system directory"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_that_is_not_installed_is_not_found() {
        assert_eq!(system_program("antiwire-no-such-program"), None);
        let error = require_system_program("antiwire-no-such-program").expect_err("absent");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[cfg(unix)]
    #[test]
    fn finds_a_system_tool_by_absolute_path() {
        let shell = system_program("sh").expect("every Unix has sh");
        assert!(shell.is_absolute());
        assert!(SYSTEM_DIRS.iter().any(|dir| shell.starts_with(dir)));
    }
}
