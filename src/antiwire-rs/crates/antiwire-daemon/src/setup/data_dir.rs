//! Where the daemon keeps its database, logs and crash log: chosen from
//! `--data-dir`, `ANTIWIRE_DATA_DIR` or a per-build default, read early,
//! before the command line is parsed, and published to child processes.

use std::path::{Path, PathBuf};

use directories::ProjectDirs;

/// Where the daemon keeps its database and logs when neither `--data-dir`
/// nor `ANTIWIRE_DATA_DIR` says.
pub(crate) fn default_data_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        ProjectDirs::from("com", "Antiwire", "Antiwire")
            .map(|directories| directories.data_local_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".antiwire"))
    } else if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\Antiwire")
    } else {
        PathBuf::from("/var/lib/antiwire")
    }
}

/// The data directory, read from the raw arguments before clap has parsed
/// them, so the crash log and the log file land beside the database.
///
/// The order is clap's: `--data-dir`, then `ANTIWIRE_DATA_DIR`, then the
/// default. The boot heal task, for one, passes only `--data-dir`.
pub(crate) fn early_data_dir() -> PathBuf {
    data_dir_arg(std::env::args_os().skip(1))
        .or_else(|| std::env::var_os("ANTIWIRE_DATA_DIR").map(PathBuf::from))
        .unwrap_or_else(default_data_dir)
}

/// The value of `--data-dir VALUE` or `--data-dir=VALUE` in `args`.
fn data_dir_arg(args: impl IntoIterator<Item = std::ffi::OsString>) -> Option<PathBuf> {
    const FLAG: &str = "--data-dir";
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == FLAG {
            return args.next().map(PathBuf::from);
        }
        let bytes = arg.as_encoded_bytes();
        if let Some(value) = bytes
            .strip_prefix(FLAG.as_bytes())
            .and_then(|rest| rest.strip_prefix(b"="))
        {
            #[allow(unsafe_code)]
            // SAFETY: `value` is `arg`'s encoded bytes after an ASCII prefix,
            // so it starts on a boundary and runs to the end of `arg`.
            let value = unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(value) };
            return Some(PathBuf::from(value));
        }
    }
    None
}

/// Publishes the resolved data directory as `ANTIWIRE_DATA_DIR`, for code in
/// this process that reads it (the macOS pf token) and for the children it
/// spawns, such as the reaper.
///
/// Call once, from `crate::run`, after parsing and before any thread exists: the
/// session-end window, the service dispatcher and the async runtime all come
/// later. Changing the environment while other threads may read it is not
/// thread-safe on Unix.
pub(crate) fn publish_data_dir(data_dir: &Path) {
    std::env::set_var("ANTIWIRE_DATA_DIR", data_dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<std::ffi::OsString> {
        list.iter().map(std::ffi::OsString::from).collect()
    }

    /// The regression this guards: logs went to the environment's or the
    /// default directory while `--data-dir` put the database elsewhere.
    #[test]
    fn the_data_dir_flag_is_read_before_parsing_in_both_forms() {
        assert_eq!(
            data_dir_arg(args(&["--heal-host-state", "--data-dir", r"D:\aw data\"])),
            Some(PathBuf::from(r"D:\aw data\"))
        );
        assert_eq!(
            data_dir_arg(args(&["--data-dir=/srv/antiwire", "--foreground"])),
            Some(PathBuf::from("/srv/antiwire"))
        );
        assert_eq!(data_dir_arg(args(&["--foreground"])), None);
        assert_eq!(data_dir_arg(args(&["--data-dir"])), None);
        assert_eq!(
            data_dir_arg(args(&["--data-directory=x"])),
            None,
            "only the exact flag counts"
        );
    }
}
