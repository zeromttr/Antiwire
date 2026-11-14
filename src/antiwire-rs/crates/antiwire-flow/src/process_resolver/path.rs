//! Path normalization helpers for process identity resolution.

use antiwire_policy::BASENAME_FALLBACK_PATH;

use crate::sanitize;

/// Returns true when `path` looks like a bare executable name without directory separators.
pub fn is_basename_only(path: &str) -> bool {
    !path.is_empty() && !path.contains('\\') && !path.contains('/')
}

/// Returns true when `path` contains directory separators (DOS or NT).
pub fn has_path_separators(path: &str) -> bool {
    path.contains('\\') || path.contains('/')
}

/// Returns true when `path` ends with `suffix`, compared case-insensitively for ASCII.
///
/// Compares raw bytes rather than `&str` slices: an executable path containing
/// multi-byte characters can put `path.len() - suffix.len()` in the middle of a
/// character, and slicing a `&str` there panics.
#[cfg(any(windows, test))]
pub fn path_ends_with_ignore_ascii_case(path: &str, suffix: &str) -> bool {
    let (path, suffix) = (path.as_bytes(), suffix.as_bytes());
    path.len() >= suffix.len() && path[path.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// Returns true when `path` is exactly the `file` image in the Windows system
/// directory: `<SystemRoot>\System32\<file>` or `<SystemRoot>\SysWOW64\<file>`.
///
/// This is the one canonical-image check shared by the svchost and rundll32
/// hosts and by the system-service classifier. It is strict on purpose: the
/// comparison is ASCII case-insensitive (Windows paths are), but nothing else is
/// normalized. A `\\?\` device prefix, forward slashes, a different parent, a
/// subdirectory, or a `..` segment all fail, so only the spelling of the real
/// host verifies. The system root is read once per process, so a mid-run
/// environment change cannot flip verdicts.
#[cfg(any(windows, test))]
pub fn is_system_host_binary(path: &str, file: &str) -> bool {
    is_system_host_binary_under(path, file, system_root())
}

#[cfg(any(windows, test))]
fn is_system_host_binary_under(path: &str, file: &str, root: &str) -> bool {
    ["System32", "SysWOW64"]
        .iter()
        .any(|dir| path.eq_ignore_ascii_case(&format!(r"{root}\{dir}\{file}")))
}

/// Windows system root, read once. Trailing separators are removed and forward
/// slashes become backslashes, so `C:\Windows\` and `C:/Windows` both name
/// the same directory as `C:\Windows`.
#[cfg(any(windows, test))]
fn system_root() -> &'static str {
    static ROOT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| normalize_system_root(&std::env::var("SystemRoot").unwrap_or_default()))
}

#[cfg(any(windows, test))]
fn normalize_system_root(raw: &str) -> String {
    let raw = if raw.is_empty() { r"C:\Windows" } else { raw };
    raw.trim_end_matches(['\\', '/']).replace('/', "\\")
}

/// The name a saved application should have, when an earlier build saved it with an `.exe`
/// suffix this platform's programs do not carry. `None` when the name is right as it is.
///
/// Version 0.1.0 added the suffix on every platform, so its Linux and macOS databases hold
/// `curl.exe` for `/usr/bin/curl` and `unknown.exe` for a process that could not be
/// identified. Those two shapes are the ones recognised: a name that is the path's file name
/// plus the suffix, and the unknown placeholder. A program whose own name ends in `.exe`, as
/// one run under Wine does, has that in its path too and is left alone, and so is a name
/// saved without a path, which nothing here can check. On Windows the suffix belongs.
pub fn name_without_stray_suffix<'a>(app_name: &'a str, app_path: &str) -> Option<&'a str> {
    if cfg!(windows) {
        return None;
    }
    let stem = app_name.strip_suffix(".exe")?;
    let stray = if is_unknown_placeholder(app_path) {
        stem == antiwire_policy::UNKNOWN_APP_NAME
    } else {
        !is_synthetic_path(app_path) && executable_name(app_path) == stem
    };
    stray.then_some(stem)
}

/// Extracts the file name component from an executable path.
pub fn executable_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_owned()
}

/// Returns true when `path` is an absolute executable location acceptable from
/// untrusted metadata (`FlowMeta`), rather than a path-shaped display string.
///
/// Producers today are kernel ETW and `sysinfo`, but `FlowMeta` is
/// `Deserialize`-able and part of the collector contract. Anything that later
/// feeds metadata from an IPC or plugin boundary must not be able to claim a
/// relative name, a synthetic identity, or a string carrying control
/// characters. Paths that fail this check are ignored in favour of live
/// resolution.
pub fn is_trusted_process_path(path: &str) -> bool {
    if path.is_empty()
        || path.chars().count() > sanitize::MAX_PATH_CHARS
        || sanitize::has_control_chars(path)
    {
        return false;
    }
    is_absolute_path(path)
}

/// Windows executable paths are absolute when they name a DOS drive, a UNC or
/// device namespace, or an NT device path (`\Device\...`, `\??\...`).
#[cfg(windows)]
fn is_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let nt_device = path
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\Device\"));
    let nt_alias = path
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\??\"));
    let unc_or_device = path.starts_with(r"\\");
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    nt_device || nt_alias || unc_or_device || drive_absolute
}

/// On Unix an obtainable executable path is always rooted.
#[cfg(not(windows))]
fn is_absolute_path(path: &str) -> bool {
    path.starts_with('/')
}

/// Gives a Windows process name its `.exe` suffix when the source left it off, so one
/// program has one name whichever source reported it.
#[cfg(windows)]
pub fn normalize_process_name(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    if name
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("exe"))
    {
        return name.to_owned();
    }
    format!("{name}.exe")
}

/// Off Windows a process name is already whole: programs there have no suffix to add.
#[cfg(not(windows))]
pub fn normalize_process_name(name: &str) -> String {
    name.to_owned()
}

/// Placeholder path used when a process name is known but the executable path is inaccessible.
pub fn placeholder_path() -> &'static str {
    BASENAME_FALLBACK_PATH
}

/// Returns true when `path` is an NT device path whose DOS conversion can fail
/// when the drive map does not (yet) know the volume.
///
/// Such paths must never become their own application identity: the same file
/// can report as `C:\...` a moment later, which would fork a second row for
/// one binary. Callers keep the name-keyed placeholder instead and retry the
/// conversion while the process is alive.
pub fn is_nt_device_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let nt_device = bytes.len() >= 8 && bytes[..8].eq_ignore_ascii_case(b"\\Device\\");
    let nt_alias = bytes.len() >= 4 && bytes[..4].eq_ignore_ascii_case(b"\\??\\");
    nt_device || nt_alias
}

/// Returns true when `path` is the basename fallback for a process whose name
/// is known but whose executable path was unreachable.
///
/// Unlike the unknown placeholders (each its own identity) and `System` (a
/// genuine identity), this placeholder is recoverable: a later sighting of the
/// same process instance carrying a real path may upgrade it.
pub fn is_recoverable_placeholder(path: &str) -> bool {
    let path = path.trim();
    BASENAME_FALLBACK_PATH.eq_ignore_ascii_case(path)
        // The label older daemons stored before `Path unavailable`.
        || "System / Elevated Process".eq_ignore_ascii_case(path)
}

/// Returns true when `path` is a stand-in rather than a real executable location.
///
/// These say only that resolution failed, so they must not displace a real path
/// already on record for the application — that would read as a relocation.
pub fn is_synthetic_path(path: &str) -> bool {
    antiwire_policy::is_synthetic_placeholder(path)
}

/// Returns true when `path` stands in for an unattributable process.
///
/// Unlike the basename fallback (`Path unavailable`, which carries a
/// real name and must keep joining that application's row), each unknown reason
/// is its own identity: no-owner, exited, and access-denied rows must not merge.
pub fn is_unknown_placeholder(path: &str) -> bool {
    antiwire_policy::is_unknown_placeholder(path)
}

/// Converts an NT device path (`\Device\HarddiskVolume3\...`) to a DOS path when possible.
#[cfg(windows)]
pub fn nt_path_to_dos_path(nt_path: &str) -> String {
    super::windows::nt_path_to_dos_path(nt_path)
}

/// Non-Windows builds pass paths through unchanged.
#[cfg(not(windows))]
pub fn nt_path_to_dos_path(path: &str) -> String {
    path.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_ends_with_ignore_ascii_case_matches_exe_suffix() {
        assert!(path_ends_with_ignore_ascii_case(
            r"C:\Windows\System32\svchost.exe",
            "svchost.exe"
        ));
        assert!(path_ends_with_ignore_ascii_case(
            r"C:\Windows\System32\SVCHOST.EXE",
            "svchost.exe"
        ));
        assert!(!path_ends_with_ignore_ascii_case(
            r"C:\Windows\System32\curl.exe",
            "svchost.exe"
        ));
    }

    #[test]
    fn path_ends_with_ignore_ascii_case_handles_multibyte_paths() {
        // Five three-byte characters: 15 bytes, with a boundary at every third
        // byte, so `15 - "svchost.exe".len()` (4) falls inside a character.
        let path = "€€€€€";
        assert_eq!(path.len(), 15);
        assert!(!path.is_char_boundary(path.len() - "svchost.exe".len()));
        assert!(!path_ends_with_ignore_ascii_case(path, "svchost.exe"));

        assert!(path_ends_with_ignore_ascii_case(
            "€svchost.exe",
            "svchost.exe"
        ));
    }

    #[test]
    fn recoverable_placeholder_is_only_the_basename_fallback() {
        assert!(is_recoverable_placeholder("Path unavailable"));
        assert!(is_recoverable_placeholder("  PATH UNAVAILABLE  "));
        assert!(is_recoverable_placeholder("System / Elevated Process"));
        assert!(is_recoverable_placeholder("  system / elevated process  "));
        assert!(!is_recoverable_placeholder("System"));
        assert!(!is_recoverable_placeholder("Unknown (Exited)"));
        assert!(!is_recoverable_placeholder("Unknown (No Owner)"));
        assert!(!is_recoverable_placeholder("Unknown (Access Denied)"));
        assert!(!is_recoverable_placeholder(r"C:\apps\real.exe"));
    }

    #[test]
    fn nt_device_paths_are_detected_without_slicing() {
        assert!(is_nt_device_path(r"\Device\HarddiskVolume3\Windows\a.exe"));
        assert!(is_nt_device_path(r"\device\HarddiskVolume3\Windows\a.exe"));
        assert!(is_nt_device_path(r"\??\C:\Windows\a.exe"));
        assert!(!is_nt_device_path(r"C:\Windows\a.exe"));
        assert!(!is_nt_device_path(r"\\?\C:\Windows\a.exe"));
        assert!(!is_nt_device_path(r"\\server\share\a.exe"));
        assert!(!is_nt_device_path(""));
        // Byte-level prefix comparison must not panic on multibyte input.
        assert!(!is_nt_device_path("€€€€€€€€€€€€€"));
    }
    #[test]
    fn basename_only_detects_short_names() {
        assert!(is_basename_only("svchost.exe"));
        assert!(!is_basename_only(r"C:\Windows\System32\svchost.exe"));
    }

    #[test]
    fn executable_name_handles_both_path_separator_styles() {
        assert_eq!(
            executable_name(r"C:\Windows\System32\svchost.exe"),
            "svchost.exe"
        );
        assert_eq!(executable_name("/usr/bin/curl"), "curl");
    }

    #[test]
    fn trusted_process_paths_reject_synthetics_and_control_characters() {
        assert!(!is_trusted_process_path(""));
        assert!(!is_trusted_process_path("chrome.exe"));
        assert!(!is_trusted_process_path("System / Elevated Process"));
        assert!(!is_trusted_process_path("Unknown (No Owner)"));
        assert!(!is_trusted_process_path("Unknown (Exited)"));
        assert!(!is_trusted_process_path("Unknown (Access Denied)"));
        assert!(!is_trusted_process_path("evil\u{0}.exe"));
        assert!(!is_trusted_process_path("evil\npath\\tool.exe"));
        assert!(!is_trusted_process_path(
            &"a".repeat(sanitize::MAX_PATH_CHARS + 1)
        ));
    }

    #[test]
    fn unknown_placeholders_are_distinct_from_other_synthetics() {
        for path in [
            "Unknown (No Owner)",
            "Unknown (Exited)",
            "Unknown (Access Denied)",
        ] {
            assert!(is_synthetic_path(path));
            assert!(is_unknown_placeholder(path));
        }
        assert!(!is_unknown_placeholder("System / Elevated Process"));
        assert!(!is_unknown_placeholder("System"));
        assert!(!is_unknown_placeholder(r"C:\apps\real.exe"));
    }

    #[cfg(windows)]
    #[test]
    fn trusted_windows_process_paths_require_an_absolute_form() {
        assert!(is_trusted_process_path(r"C:\Windows\System32\svchost.exe"));
        assert!(is_trusted_process_path(r"c:/windows/system32/svchost.exe"));
        assert!(is_trusted_process_path(
            r"\Device\HarddiskVolume3\Windows\svchost.exe"
        ));
        assert!(is_trusted_process_path(r"\??\C:\Windows\svchost.exe"));
        assert!(is_trusted_process_path(r"\\?\C:\Windows\svchost.exe"));
        assert!(is_trusted_process_path(r"\\server\share\tool.exe"));
        assert!(!is_trusted_process_path(r"\Windows\System32\svchost.exe"));
        assert!(!is_trusted_process_path(r"Windows\System32\svchost.exe"));
        assert!(!is_trusted_process_path(r"C:relative\tool.exe"));
    }

    #[test]
    fn system_host_binary_accepts_only_the_exact_system_image() {
        let root = r"C:\Windows";
        assert!(is_system_host_binary_under(
            r"C:\Windows\System32\svchost.exe",
            "svchost.exe",
            root
        ));
        assert!(is_system_host_binary_under(
            r"c:\windows\syswow64\SVCHOST.EXE",
            "svchost.exe",
            root
        ));
        assert!(is_system_host_binary_under(
            r"D:\WinSys\System32\rundll32.exe",
            "rundll32.exe",
            r"D:\WinSys"
        ));
        for path in [
            r"C:\Users\me\AppData\Local\Temp\svchost.exe",
            r"C:\Windows\System32\drivers\svchost.exe",
            r"C:\Windows\System32\..\Temp\svchost.exe",
            r"C:\Windows\System32\rundll32.exe",
            r"C:\Windows\System32\svchost.exe.exe",
            r"\\?\C:\Windows\System32\svchost.exe",
            r"C:/Windows/System32/svchost.exe",
            r"C:\Windows\System32\\svchost.exe",
            r"D:\Windows\System32\svchost.exe",
            "svchost.exe",
        ] {
            assert!(
                !is_system_host_binary_under(path, "svchost.exe", root),
                "{path} must not verify as the system svchost"
            );
        }
    }

    #[test]
    fn system_root_is_normalized_before_comparison() {
        assert_eq!(normalize_system_root(r"C:\Windows"), r"C:\Windows");
        assert_eq!(normalize_system_root(r"C:\Windows\"), r"C:\Windows");
        assert_eq!(normalize_system_root("C:/Windows/"), r"C:\Windows");
        assert_eq!(normalize_system_root(""), r"C:\Windows");
        assert!(is_system_host_binary_under(
            r"C:\Windows\System32\svchost.exe",
            "svchost.exe",
            &normalize_system_root("C:/Windows/")
        ));
    }

    #[test]
    fn system_host_binary_matches_the_live_system_root() {
        let root = normalize_system_root(&std::env::var("SystemRoot").unwrap_or_default());
        assert!(is_system_host_binary(
            &format!(r"{root}\System32\svchost.exe"),
            "svchost.exe"
        ));
        assert!(!is_system_host_binary(
            &format!(r"{root}\System32\svchost.exe.bak"),
            "svchost.exe"
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn trusted_unix_process_paths_require_a_root() {
        assert!(is_trusted_process_path("/usr/bin/curl"));
        assert!(!is_trusted_process_path("usr/bin/curl"));
    }
}
