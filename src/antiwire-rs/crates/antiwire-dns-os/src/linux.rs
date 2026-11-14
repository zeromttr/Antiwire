//! Linux resolver capture, loopback redirection, and restoration.

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{AppliedRedirect, RedirectCoverage};

const RESOLV_CONF: &str = "/etc/resolv.conf";

#[derive(Debug, Serialize, Deserialize)]
struct ResolverState {
    contents: String,
}

/// Read the current resolver contents.
///
/// Returns `None` on any read failure instead of an empty-contents snapshot:
/// restoring that would truncate `/etc/resolv.conf`, and a snapshot must never
/// claim to be valid when it was not actually captured.
pub fn capture_state() -> Option<String> {
    match fs::read_to_string(RESOLV_CONF) {
        Ok(contents) => serde_json::to_string(&ResolverState { contents }).ok(),
        Err(error) => {
            warn!(%error, path = RESOLV_CONF, "failed to capture Linux resolver state");
            None
        }
    }
}

pub fn redirect(redirect_v6: bool) -> bool {
    let mut contents = String::from(
        "# Managed temporarily by Antiwire; original contents are restored on shutdown.\n\
         nameserver 127.0.0.1\n",
    );
    if redirect_v6 {
        contents.push_str("nameserver ::1\n");
    }
    write_resolver(Path::new(RESOLV_CONF), &contents)
}

/// Redirect and return the snapshot that restore must reverse.
pub fn redirect_capturing(redirect_v6: bool, prior_saved_json: &str) -> Option<AppliedRedirect> {
    let plan = plan_redirect(redirect_v6, prior_saved_json)?;
    apply_redirect(redirect_v6, &plan)
}

/// The snapshot to persist before [`apply_redirect`] changes anything.
///
/// `/etc/resolv.conf` is one file for the whole host, so a prior snapshot
/// already holds its original and is the plan as it stands. Reading the file
/// again would only capture the redirect itself.
pub fn plan_redirect(_redirect_v6: bool, prior_saved_json: &str) -> Option<String> {
    if prior_saved_json.trim().is_empty() {
        capture_state()
    } else {
        Some(prior_saved_json.to_owned())
    }
}

/// Redirect to loopback; returns the snapshot restore must reverse, which is `plan`.
///
/// There is one resolver file for the whole host, so a redirect that lands
/// is always complete. A plan restore could not write back is refused before
/// anything changes.
pub fn apply_redirect(redirect_v6: bool, plan: &str) -> Option<AppliedRedirect> {
    if serde_json::from_str::<ResolverState>(plan).is_err() {
        warn!("Linux resolver redirect plan is invalid; resolv.conf left unchanged");
        return None;
    }
    crate::common::apply_redirect(
        redirect_v6,
        plan,
        |redirect_v6, _plan| redirect(redirect_v6).then_some(RedirectCoverage::Complete),
        flush_cache,
    )
}

pub fn restore(saved_state_json: &str) -> bool {
    restore_file(Path::new(RESOLV_CONF), saved_state_json)
}

/// Writes the saved contents back to `path`, unless it already holds them.
///
/// A file that already holds the original needs no write. That also lets a
/// redirect that never landed settle where the file cannot be replaced, such
/// as a bind-mounted `resolv.conf`, instead of staying owed forever.
fn restore_file(path: &Path, saved_state_json: &str) -> bool {
    let Ok(state) = serde_json::from_str::<ResolverState>(saved_state_json) else {
        warn!("saved Linux resolver state is invalid; refusing to overwrite resolv.conf");
        return false;
    };
    if fs::read_to_string(path).is_ok_and(|current| current == state.contents) {
        return true;
    }
    write_resolver(path, &state.contents)
}

pub fn flush_cache() {
    let _ = Command::new("resolvectl").arg("flush-caches").status();
}

fn write_resolver(path: &Path, contents: &str) -> bool {
    match replace_resolver(path, contents) {
        Ok(()) => true,
        Err(error) => {
            warn!(%error, path = %path.display(), "failed to update Linux resolver configuration");
            false
        }
    }
}

fn replace_resolver(path: &Path, contents: &str) -> io::Result<()> {
    // Follow /etc/resolv.conf symlinks (systemd-resolved/NetworkManager), replacing
    // the target rather than severing the link. A bind mount cannot be renamed;
    // refuse that update instead of truncating the live resolver file.
    let target = fs::canonicalize(path)?;
    let metadata = fs::metadata(&target)?;
    if !metadata.is_file() {
        return Err(io::Error::other(
            "resolver configuration is not a regular file",
        ));
    }
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::other("resolver has no parent"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(contents.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let temp_meta = temp.as_file().metadata()?;
        if temp_meta.uid() != metadata.uid() || temp_meta.gid() != metadata.gid() {
            // SAFETY: the fd belongs to the live temporary file; uid/gid come
            // from the original resolver file and are preserved on replacement.
            #[allow(unsafe_code)]
            if unsafe { libc::fchown(temp.as_file().as_raw_fd(), metadata.uid(), metadata.gid()) }
                != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
    }
    temp.as_file().set_permissions(metadata.permissions())?;
    temp.as_file().sync_all()?;
    temp.persist(&target).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_replacement_preserves_contents_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, "nameserver 192.0.2.1\n").unwrap();
        assert!(write_resolver(&path, "nameserver 127.0.0.1\n"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "nameserver 127.0.0.1\n");
        assert!(!write_resolver(dir.path(), "bad"));
        assert!(!write_resolver(&dir.path().join("missing"), "bad"));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn resolver_replacement_follows_symlink_and_preserves_metadata() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("resolv.conf");
        fs::write(&target, "original").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        let original = fs::metadata(&target).unwrap();
        symlink(&target, &link).unwrap();
        assert!(write_resolver(&link, "updated"));
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(&target).unwrap(), "updated");
        let replaced = fs::metadata(&target).unwrap();
        assert_eq!(replaced.mode(), original.mode());
        assert_eq!(
            (replaced.uid(), replaced.gid()),
            (original.uid(), original.gid())
        );
    }

    fn saved(contents: &str) -> String {
        serde_json::to_string(&ResolverState {
            contents: contents.to_owned(),
        })
        .expect("encode state")
    }

    #[test]
    fn restore_writes_the_original_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(
            &path,
            "nameserver 127.0.0.1
",
        )
        .unwrap();
        assert!(restore_file(
            &path,
            &saved(
                "nameserver 192.0.2.1
"
            )
        ));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "nameserver 192.0.2.1
"
        );
        assert!(!restore_file(&path, "not json"));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "nameserver 192.0.2.1
"
        );
    }

    /// A file that already holds the original counts as restored without a
    /// write, so a redirect that never landed can settle even where the file
    /// cannot be replaced. A file that cannot be read is still written, and a
    /// failed write is still a failed restore.
    #[test]
    fn restore_needs_no_write_when_the_original_is_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(
            &path,
            "nameserver 192.0.2.1
",
        )
        .unwrap();
        assert!(restore_file(
            &path,
            &saved(
                "nameserver 192.0.2.1
"
            )
        ));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(!restore_file(
            dir.path(),
            &saved(
                "nameserver 192.0.2.1
"
            )
        ));
    }

    #[test]
    fn a_prior_snapshot_is_the_plan_without_reading_the_file() {
        let prior = saved(
            "nameserver 192.0.2.1
",
        );
        assert_eq!(plan_redirect(true, &prior).as_deref(), Some(prior.as_str()));
    }

    #[test]
    fn an_invalid_plan_changes_nothing() {
        assert_eq!(apply_redirect(false, "not json"), None);
    }

    #[test]
    fn resolver_state_round_trips() {
        let original = "search example.test\nnameserver 192.0.2.1\n";
        let encoded = serde_json::to_string(&ResolverState {
            contents: original.to_owned(),
        })
        .expect("encode state");
        let decoded: ResolverState = serde_json::from_str(&encoded).expect("decode state");
        assert_eq!(decoded.contents, original);
    }
}
