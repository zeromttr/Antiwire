//! Atomic publication helpers for local IPC credentials.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use antiwire_proto::IPC_CLIENT_GROUP;
use atomic_write_file::OpenOptions;

/// Who can read the published IPC token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenAccess {
    /// Administrators and members of [`IPC_CLIENT_GROUP`].
    ClientGroup,
    /// Administrators only, because [`IPC_CLIENT_GROUP`] does not exist.
    AdminsOnly,
    /// A debug build's per-user directory, left as the directory makes it.
    DeveloperProfile,
}

/// Whether the IPC token has to carry its own access control.
///
/// A release daemon keeps its credentials in the machine-wide data directory, which
/// every local account can list. A debug build keeps them under the developer's own
/// profile instead (see `ipc_directory`), where an elevated daemon and the unelevated
/// client of the same developer both have to reach them.
pub(crate) const fn restrict_ipc_token() -> bool {
    !cfg!(debug_assertions)
}

/// Publishes the IPC token so that only administrators and [`IPC_CLIENT_GROUP`] can read it.
///
/// The token unlocks the daemon's whole API, so it must not be readable by every local
/// account. The file is restricted while it is still empty, before the token is written
/// into it, and then renamed into place: the token is never readable by anyone else,
/// even briefly, and a file someone else created at the final path is replaced rather
/// than written through.
pub(crate) fn write_token(path: &Path, token: &[u8]) -> io::Result<TokenAccess> {
    if !restrict_ipc_token() {
        write_shared_credential(path, token)?;
        return Ok(TokenAccess::DeveloperProfile);
    }
    write_restricted_token(path, token)
}

fn write_restricted_token(path: &Path, token: &[u8]) -> io::Result<TokenAccess> {
    antiwire_secrets::write_private_file(path, token, restrict_token_file)
}

#[cfg(windows)]
fn restrict_token_file(staging: &Path, _file: &fs::File) -> io::Result<TokenAccess> {
    use antiwire_secrets::GroupAccess;

    Ok(
        match antiwire_secrets::restrict_to_admins_and_group(staging, IPC_CLIENT_GROUP)? {
            GroupAccess::Granted => TokenAccess::ClientGroup,
            GroupAccess::GroupMissing => TokenAccess::AdminsOnly,
        },
    )
}

/// The file is created `0600`; with the group present it becomes `0640` and group-owned.
#[cfg(unix)]
fn restrict_token_file(_staging: &Path, file: &fs::File) -> io::Result<TokenAccess> {
    use std::os::unix::fs::PermissionsExt as _;

    let Some(gid) = antiwire_secrets::group_id(IPC_CLIENT_GROUP)? else {
        return Ok(TokenAccess::AdminsOnly);
    };
    std::os::unix::fs::fchown(file, None, Some(gid))?;
    file.set_permissions(fs::Permissions::from_mode(0o640))?;
    Ok(TokenAccess::ClientGroup)
}

/// Publishes a credential that every local client may read.
///
/// This writes `ipc.crt`, the daemon's public TLS certificate, which is not secret. In a
/// debug build it also writes `ipc.token`, which then lives under the developer's own
/// profile; see [`restrict_ipc_token`]. Unix uses `0644` so the unprivileged client can
/// read what the root daemon wrote.
pub(crate) fn write_shared_credential(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    let mut options = OpenOptions::new();
    #[cfg(not(unix))]
    let options = OpenOptions::new();
    #[cfg(unix)]
    {
        use atomic_write_file::unix::OpenOptionsExt as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        options
            .mode(0o644)
            .preserve_mode(false)
            .preserve_owner(false);
    }

    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.commit()
}

#[cfg(test)]
mod restricted_token_tests {
    use super::*;

    #[test]
    fn replaces_the_token_and_leaves_no_staging_file() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("ipc.token");
        fs::write(&path, b"old token").expect("old token");

        write_restricted_token(&path, b"new token").expect("publish");

        assert_eq!(fs::read(&path).expect("read back"), b"new token");
        assert_eq!(fs::read_dir(directory.path()).expect("list").count(), 1);
    }

    /// The installer has not run here, so the client group is missing and the token is
    /// left to administrators: nothing inherited from the directory may survive.
    #[cfg(windows)]
    #[test]
    fn without_the_client_group_the_token_drops_inherited_access() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("ipc.token");

        let access = write_restricted_token(&path, b"token").expect("publish");
        if access != TokenAccess::AdminsOnly {
            // The client group exists on this machine; the group case is covered
            // by antiwire-secrets.
            return;
        }
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(format!("(Get-Acl -LiteralPath '{}').Sddl", path.display()))
            .output()
            .expect("powershell");
        let sddl = String::from_utf8_lossy(&output.stdout);
        assert!(sddl.contains("D:P"), "inheritance must be cut, got {sddl}");
        assert!(
            !sddl.contains(";BU)"),
            "Users must not keep access, got {sddl}"
        );
    }

    /// Needs the client group to exist, as the installer leaves it.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires the Antiwire Users local group"]
    fn live_the_client_group_can_read_the_token() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("ipc.token");

        let access = write_restricted_token(&path, b"token").expect("publish");
        assert_eq!(access, TokenAccess::ClientGroup);

        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(format!("(Get-Acl -LiteralPath '{}').Sddl", path.display()))
            .output()
            .expect("powershell");
        let sddl = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        println!("token DACL {sddl}");
        assert!(sddl.contains("D:P"), "inheritance must be cut, got {sddl}");
        assert!(
            !sddl.contains(";BU)"),
            "Users must not keep access, got {sddl}"
        );
        // A locally created group has a machine-domain SID; the only such ACE is the group's.
        assert!(
            sddl.contains(";;FR;;;S-1-5-21-"),
            "the client group must be granted read, got {sddl}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn without_the_client_group_the_token_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("ipc.token");
        let access = write_restricted_token(&path, b"token").expect("publish");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        match access {
            TokenAccess::AdminsOnly => assert_eq!(mode, 0o600),
            TokenAccess::ClientGroup => assert_eq!(mode, 0o640),
            TokenAccess::DeveloperProfile => unreachable!("always restricted"),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn published_credentials_are_readable_by_packaged_clients() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("ipc.token");

        write_shared_credential(&path, b"token").expect("publish token");

        let mode = std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
    }
}
