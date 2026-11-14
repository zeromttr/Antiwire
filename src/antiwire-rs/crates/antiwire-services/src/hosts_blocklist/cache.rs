//! The blocklist cache files on disk, and building a blocklist from them.

use std::path::{Path, PathBuf};

use antiwire_policy::{
    is_builtin_list_id, BlocklistBuilder, HostsParser, HostsParserMode, SyncTarget,
    SYSTEM_HOSTS_LIST_ID,
};
use tracing::{info, warn};

/// Where `target`'s cache lives in `dir`.
pub(super) fn cache_path(dir: &Path, target: &SyncTarget) -> PathBuf {
    dir.join(target.cache_filename())
}

/// What [`load_cache_into_builder`] found on disk.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CacheLoad {
    /// The cache was loaded and added this many domains.
    Loaded(usize),
    /// No cache file exists yet.
    Missing,
    /// A cache file exists but could not be read, or is not UTF-8 text.
    Unusable,
}

/// Adds the cached list at `path` to `builder`. The target's pinned names are
/// added, and names it refuses are skipped.
pub(super) fn load_cache_into_builder(
    path: &Path,
    target: &SyncTarget,
    builder: &mut BlocklistBuilder,
) -> CacheLoad {
    let list_name = target.name();
    if !path.exists() {
        return CacheLoad::Missing;
    }
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) => {
            warn!(
                path = ?path,
                error = %error,
                "failed to read blocklist cache; it will be downloaded again"
            );
            return CacheLoad::Unusable;
        }
    };
    let mut count = 0;
    for line in content.lines() {
        let domain = line.trim();
        if !domain.is_empty() && target.accepts(domain) {
            count += usize::from(builder.add_from_list(list_name, domain));
        }
    }
    for domain in target.pinned_names() {
        count += usize::from(builder.add_from_list(list_name, domain));
    }
    CacheLoad::Loaded(count)
}

/// Deletes managed cache files in `dir` that are not in `keep`.
pub(super) fn prune_orphan_cache_files(dir: &Path, keep: &[PathBuf]) {
    if !dir.exists() {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            warn!(error = %error, "failed to enumerate blocklist cache directory");
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("txt") {
            continue;
        }
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name.ends_with(".tmp") {
            continue;
        }
        let managed =
            name.starts_with("custom_") || is_builtin_list_id(name.trim_end_matches(".txt"));
        if !managed || keep.iter().any(|k| k == &path) {
            continue;
        }
        if let Err(error) = std::fs::remove_file(&path) {
            warn!(path = ?path, error = %error, "failed to prune orphaned blocklist cache");
        } else {
            info!(path = ?path, "pruned orphaned blocklist cache");
        }
        remove_cache_sidecars(&path);
    }
}

/// Removes the hash sidecars beside the cache at `path`.
pub(super) fn remove_cache_sidecars(path: &Path) {
    let Some(stem) = path.file_stem() else {
        return;
    };
    let parent = path.parent().unwrap_or(Path::new("."));
    for suffix in [".sha256", ".hash-checked"] {
        let sidecar = parent.join(format!("{}{suffix}", stem.to_string_lossy()));
        if sidecar.exists() {
            let _ = std::fs::remove_file(sidecar);
        }
    }
}

/// Adds the host's own hosts-file entries to `builder`.
pub(super) fn parse_system_hosts(builder: &mut BlocklistBuilder) {
    let path = if cfg!(windows) {
        PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
    } else {
        PathBuf::from("/etc/hosts")
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) => {
            warn!(path = ?path, error = %error, "failed to read system hosts file");
            return;
        }
    };

    let mut count = 0;
    HostsParser::for_each_domain(&content, HostsParserMode::RequireHostsAddress, |domain| {
        count += usize::from(builder.add_from_list(SYSTEM_HOSTS_LIST_ID, &domain));
    });
    info!(count, "parsed system hosts entries into blocklist");
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_policy::resolve_sync_targets;

    #[test]
    fn abused_tlds_cache_adds_pinned_names_and_skips_core_zones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("hagezi_abused_tlds.txt");
        std::fs::write(&path, "lol\ncom\n").expect("write cache");
        let target = resolve_sync_targets(true, "hagezi_abused_tlds", "")
            .pop()
            .expect("target");

        let mut builder = BlocklistBuilder::new(16);
        // lol from the file, then christmas, mov and zip pinned; com skipped.
        assert_eq!(
            load_cache_into_builder(&path, &target, &mut builder),
            CacheLoad::Loaded(4)
        );
    }

    #[test]
    fn missing_and_unreadable_caches_are_told_apart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("hagezi_light.txt");
        let target = resolve_sync_targets(true, "hagezi_light", "")
            .pop()
            .expect("target");
        let mut builder = BlocklistBuilder::new(16);

        assert_eq!(
            load_cache_into_builder(&path, &target, &mut builder),
            CacheLoad::Missing
        );
        std::fs::write(&path, [0xff, 0xfe, b'\n']).expect("write invalid cache");
        assert_eq!(
            load_cache_into_builder(&path, &target, &mut builder),
            CacheLoad::Unusable
        );
    }

    #[test]
    fn pruning_keeps_selected_and_unmanaged_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in [
            "hagezi_light.txt",
            "hagezi_pro.txt",
            "custom_1.txt",
            "notes.txt",
        ] {
            std::fs::write(dir.path().join(name), "x").expect("write");
        }
        std::fs::write(dir.path().join("hagezi_pro.sha256"), "x").expect("sidecar");

        prune_orphan_cache_files(dir.path(), &[dir.path().join("hagezi_light.txt")]);

        assert!(dir.path().join("hagezi_light.txt").exists());
        assert!(dir.path().join("notes.txt").exists(), "not a managed cache");
        assert!(!dir.path().join("hagezi_pro.txt").exists());
        assert!(!dir.path().join("hagezi_pro.sha256").exists());
        assert!(!dir.path().join("custom_1.txt").exists());
    }
}
