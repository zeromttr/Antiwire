//! Where versions are installed and where updates are staged.
//!
//! ```text
//! {install}/versions/{version}/daemon/antiwire-daemon[.exe]
//! {install}/versions/{version}/ui/antiwire.exe    Windows client
//! {install}/versions/{version}/ui/Antiwire.app    macOS client bundle
//! {install}/current -> versions/{version}  Windows junction the Start Menu shortcut uses
//! {data}/updates/incoming/{version}/     partial download, discarded on failure
//! {data}/updates/verified/{version}/     signature and hashes checked
//! {data}/updates/db-backup/{version}/    database copy taken before the swap
//! {data}/updates/installed/              Linux: the installed version's package, for rollback
//! {data}/install-state.json              current, previous, pending
//! ```
//!
//! Linux has no version trees: the package manager owns the installed files.

use std::path::{Path, PathBuf};

use semver::Version;

const DAEMON_EXE: &str = if cfg!(windows) {
    "antiwire-daemon.exe"
} else {
    "antiwire-daemon"
};
const CLIENT_EXE: &str = if cfg!(windows) {
    "antiwire.exe"
} else if cfg!(target_os = "macos") {
    "Antiwire.app"
} else {
    "antiwire"
};

/// Paths for one installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePaths {
    data_dir: PathBuf,
    install_root: PathBuf,
}

impl UpdatePaths {
    #[must_use]
    pub fn new(data_dir: impl Into<PathBuf>, install_root: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            install_root: install_root.into(),
        }
    }

    /// Paths for a daemon running from `{install}/versions/{version}/daemon/`.
    ///
    /// `None` when `daemon_exe` is not in that layout: a development build, an
    /// install from before versioned trees, or a package-managed binary.
    #[must_use]
    pub fn from_daemon_exe(data_dir: impl Into<PathBuf>, daemon_exe: &Path) -> Option<Self> {
        let daemon_dir = daemon_exe.parent()?;
        if daemon_dir.file_name()? != "daemon" {
            return None;
        }
        let version_dir = daemon_dir.parent()?;
        Version::parse(version_dir.file_name()?.to_str()?).ok()?;
        let versions = version_dir.parent()?;
        if versions.file_name()? != "versions" {
            return None;
        }
        Some(Self::new(data_dir, versions.parent()?))
    }

    /// Paths for a package-managed Linux install. There are no version trees,
    /// so the install root is the data directory itself: nothing that names a
    /// tree can point outside it.
    #[must_use]
    pub fn for_package(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        Self::new(data_dir.clone(), data_dir)
    }

    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    #[must_use]
    pub fn install_root(&self) -> &Path {
        &self.install_root
    }

    #[must_use]
    pub fn install_state(&self) -> PathBuf {
        self.data_dir.join("install-state.json")
    }

    #[must_use]
    pub fn incoming(&self, version: &Version) -> PathBuf {
        self.updates_dir()
            .join("incoming")
            .join(version.to_string())
    }

    #[must_use]
    pub fn verified(&self, version: &Version) -> PathBuf {
        self.updates_dir()
            .join("verified")
            .join(version.to_string())
    }

    #[must_use]
    pub fn db_backup(&self, version: &Version) -> PathBuf {
        self.updates_dir()
            .join("db-backup")
            .join(version.to_string())
    }

    #[must_use]
    pub fn versions_dir(&self) -> PathBuf {
        self.install_root.join("versions")
    }

    /// Junction to the current version's tree. The Start Menu shortcut and the
    /// uninstall icon go through it, so a swap repoints it rather than editing them.
    #[must_use]
    pub fn current_link(&self) -> PathBuf {
        self.install_root.join("current")
    }

    #[must_use]
    pub fn version_root(&self, version: &Version) -> PathBuf {
        self.versions_dir().join(version.to_string())
    }

    #[must_use]
    pub fn daemon_exe(&self, version: &Version) -> PathBuf {
        self.version_root(version).join("daemon").join(DAEMON_EXE)
    }

    /// The client executable, or on macOS the `Antiwire.app` bundle directory.
    #[must_use]
    pub fn client_exe(&self, version: &Version) -> PathBuf {
        self.version_root(version).join("ui").join(CLIENT_EXE)
    }

    /// Linux: holds the package of the version installed now, so the next
    /// update can roll back to it without downloading it again.
    #[must_use]
    pub fn installed_packages(&self) -> PathBuf {
        self.updates_dir().join("installed")
    }

    fn updates_dir(&self) -> PathBuf {
        self.data_dir.join("updates")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_install_root_from_versioned_daemon() {
        let exe = Path::new("/opt/aw/versions/1.2.3/daemon").join(DAEMON_EXE);
        let paths = UpdatePaths::from_daemon_exe("/data", &exe).expect("versioned layout");
        assert_eq!(paths.install_root(), Path::new("/opt/aw"));
        assert_eq!(paths.daemon_exe(&Version::new(1, 2, 3)), exe);
    }

    #[test]
    fn rejects_unversioned_daemon() {
        let exe = Path::new("/opt/aw/Daemon").join(DAEMON_EXE);
        assert!(UpdatePaths::from_daemon_exe("/data", &exe).is_none());
    }

    #[test]
    fn rejects_non_semver_directory() {
        let exe = Path::new("/opt/aw/versions/latest/daemon").join(DAEMON_EXE);
        assert!(UpdatePaths::from_daemon_exe("/data", &exe).is_none());
    }
}
