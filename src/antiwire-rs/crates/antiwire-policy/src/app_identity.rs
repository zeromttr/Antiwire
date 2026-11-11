//! Stable identity keys for applications across in-place updates.
//!
//! An application's executable path changes on every version bump
//! (`...\GitHubDesktop\app-3.6.5\GitHubDesktop.exe` to
//! `...\GitHubDesktop\app-3.6.6\GitHubDesktop.exe`). Treating each exact path as
//! a different application splinters connection history, per-app totals, and
//! firewall rules. The functions here derive a *version family* key from a path:
//! the path with version-like components erased.
//!
//! Identity is still rooted in the full install path, so a copy under Desktop,
//! `%TEMP%`, or a second install root stays its own family. Only paths that are
//! identical apart from version-shaped segments collapse.
//!
//! The store uses [`stable_identity`] for application rows and the rule engine
//! uses [`app_rule_identity`] to match a rule created for one version against
//! the next.

/// Placeholder path used when a process name is known but its location is not.
///
/// Unlike the unknown placeholders (each its own identity) and `System` (a
/// genuine identity), this placeholder is recoverable: a later sighting of the
/// same process instance carrying a real path may upgrade it.
pub const BASENAME_FALLBACK_PATH: &str = "Path unavailable";

/// Path stand-ins for processes with no reachable executable on disk.
const SYNTHETIC_PATHS: [&str; 6] = [
    BASENAME_FALLBACK_PATH,
    "System / Elevated Process", // Older daemon records and clients.
    "Unknown (No Owner)",
    "Unknown (Exited)",
    "Unknown (Access Denied)",
    "System",
];

/// Stand-ins that describe a failed resolution rather than a known program.
///
/// Each reason is its own identity: no-owner, exited, and access-denied rows
/// must not merge.
const UNKNOWN_PATHS: [&str; 3] = [
    "Unknown (No Owner)",
    "Unknown (Exited)",
    "Unknown (Access Denied)",
];

/// Replacement written in place of a version token.
const VERSION_TOKEN: &str = "{v}";

/// Mask for the digits, dots, and `v` prefix a version token may contain.
const VERSION_MASK: u8 = 0b0000_0001;
/// Mask for ASCII alphanumerics and dots, which end a version token.
const IDENTITY_MASK: u8 = 0b0000_0010;

/// Per-byte membership used by the token scanner.
///
/// A table lookup keeps the scan branch-light on a function that runs for every
/// sighting and every rule-match fallback.
const BYTE_FLAGS: [u8; 256] = build_byte_flags();

const fn build_byte_flags() -> [u8; 256] {
    let mut flags = [0_u8; 256];
    let mut value = 0_u8;
    loop {
        let index = value as usize;
        if value.is_ascii_digit() || value == b'v' || value == b'V' {
            flags[index] |= VERSION_MASK;
        }
        if value.is_ascii_alphanumeric() || value == b'.' {
            flags[index] |= IDENTITY_MASK;
        }
        if value == u8::MAX {
            break;
        }
        value += 1;
    }
    flags
}

/// The path conventions a normalization run follows.
///
/// Rules are gated on this so a Linux-only layout cannot rewrite a macOS path
/// (and vice versa), and so tests can exercise each flavor on any host.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Platform {
    Windows,
    MacOs,
    Linux,
}

/// The platform this build runs on.
fn current_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Linux
    }
}

/// Returns true when `path` is a stand-in rather than a real executable location.
#[must_use]
pub fn is_synthetic_placeholder(path: &str) -> bool {
    let path = path.trim();
    SYNTHETIC_PATHS
        .iter()
        .any(|synthetic| synthetic.eq_ignore_ascii_case(path))
}

/// Returns true when `path` stands in for a specific failed resolution.
#[must_use]
pub fn is_unknown_placeholder(path: &str) -> bool {
    let path = path.trim();
    UNKNOWN_PATHS
        .iter()
        .any(|unknown| unknown.eq_ignore_ascii_case(path))
}

/// Stable identity used to decide whether two sightings are the same application.
///
/// Non-authoritative paths are name-keyed so a fallback sighting joins the real
/// application's row. Authoritative paths are keyed by their version family.
#[must_use]
pub fn stable_identity(app_name: &str, app_path: &str, authoritative: bool) -> String {
    stable_identity_with(app_name, app_path, authoritative, current_platform())
}

/// Key used to match an APPLICATION rule target against a live executable path.
///
/// ASCII case-folded on every platform so the key matches
/// [`crate::normalize_rule`], which lowercases app targets before indexing.
#[must_use]
pub fn app_rule_identity(path: &str) -> String {
    normalize_versioned_path(path).to_ascii_lowercase()
}

/// Normalizes an executable path by erasing version-shaped segments.
///
/// Components keep their literal spelling so unrelated install roots stay
/// distinct; only version tokens (`app-3.6.6`, `v1.2`, `120.0.6099.109`) are
/// replaced with `{v}`. A rule only runs on the platform whose layouts it
/// describes. Windows paths additionally fold case and separators.
#[must_use]
pub fn normalize_versioned_path(path: &str) -> String {
    normalize_versioned_path_with(path, current_platform())
}

fn stable_identity_with(
    app_name: &str,
    app_path: &str,
    authoritative: bool,
    platform: Platform,
) -> String {
    let path = app_path.trim();
    if authoritative && !path.is_empty() {
        return format!("p:{}", normalize_versioned_path_with(path, platform));
    }
    format!("n:{}", app_name.trim().to_lowercase())
}

fn normalize_versioned_path_with(path: &str, platform: Platform) -> String {
    let windows = platform == Platform::Windows;
    let mut normalized = path.trim().to_owned();
    if windows {
        normalized = strip_extended_prefix(&normalized).replace('\\', "/");
    }

    let (root, body) = split_root(&normalized, windows);

    let mut components: Vec<String> = body
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .map(str::to_owned)
        .collect();
    apply_platform_sequence_rules(&mut components, platform);
    let joined = components
        .iter()
        .map(|component| replace_version_tokens(component))
        .collect::<Vec<_>>()
        .join("/");

    let result = match root.as_str() {
        "" => joined,
        "//" => format!("//{joined}"),
        "/" => format!("/{joined}"),
        drive => format!("{drive}/{joined}"),
    };
    if windows {
        result.to_lowercase()
    } else {
        result
    }
}

/// Splits the volume/root marker from the path body.
///
/// Keeping the marker literal prevents `C:x` from collapsing into `x` and a UNC
/// path from collapsing into a relative one.
fn split_root(path: &str, windows: bool) -> (String, &str) {
    if windows && is_drive_prefix(path) {
        let (drive, body) = path.split_at(2);
        return (drive.to_ascii_lowercase(), body.trim_start_matches('/'));
    }
    if let Some(rest) = path.strip_prefix("//") {
        return ("//".to_owned(), rest);
    }
    if let Some(rest) = path.strip_prefix('/') {
        return ("/".to_owned(), rest);
    }
    (String::new(), path)
}

fn is_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Removes the Win32 extended-length prefix so `\\?\C:\x` matches `C:\x`.
fn strip_extended_prefix(path: &str) -> &str {
    for prefix in [r"\\?\", r"\??\", "//?/", "/??/"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            return rest;
        }
    }
    path
}

/// Applies the platform-specific version-folder shapes.
///
/// Each rule runs only on the platform whose layouts it describes, so a
/// Linux-only pattern cannot rewrite a macOS path (and vice versa). The
/// anchored rules never match a path that merely contains a number.
fn apply_platform_sequence_rules(components: &mut [String], platform: Platform) {
    match platform {
        Platform::Windows => apply_windows_rules(components),
        Platform::MacOs => apply_macos_rules(components),
        Platform::Linux => apply_linux_rules(components),
    }
    if platform != Platform::Windows {
        // Homebrew and Linuxbrew both use `Cellar`; Nix runs on macOS and Linux.
        apply_homebrew_rules(components);
        apply_nix_rules(components);
    }
    // Browser tooling caches and vendor release directories exist on every OS.
    apply_playwright_rules(components);
    apply_vendor_release_rules(components);
}

/// Windows-only release layouts.
fn apply_windows_rules(components: &mut [String]) {
    // Microsoft Office installs into `root/Office<major>` (`Office16`).
    for component in components.iter_mut() {
        if is_office_version_dir(component) {
            component.truncate("Office".len());
            component.push_str(VERSION_TOKEN);
        }
    }
}

/// macOS-only release layouts.
fn apply_macos_rules(components: &mut [String]) {
    // Frameworks: `Versions/A`, `Versions/B`, and the `Versions/Current`
    // symlink are generations of the same framework.
    for index in 0..components.len().saturating_sub(1) {
        if components[index].eq_ignore_ascii_case("Versions") {
            let next = &components[index + 1];
            let generation = next.len() == 1 && next.as_bytes()[0].is_ascii_uppercase();
            if generation || next.eq_ignore_ascii_case("Current") {
                VERSION_TOKEN.clone_into(&mut components[index + 1]);
            }
        }
    }

    // App Translocation: a quarantined app runs from a fresh random directory
    // each launch (`.../T/AppTranslocation/<uuid>/...`), which would otherwise
    // fork an application row every time it starts.
    for index in 0..components.len().saturating_sub(1) {
        if components[index].eq_ignore_ascii_case("AppTranslocation") {
            VERSION_TOKEN.clone_into(&mut components[index + 1]);
        }
    }
}

/// Linux-only release layouts.
fn apply_linux_rules(components: &mut [String]) {
    // Snap: `/snap/<package>/<revision>/...`, where the revision is a
    // monotonic integer or the `current` symlink.
    for index in 0..components.len().saturating_sub(2) {
        if components[index].eq_ignore_ascii_case("snap") {
            let revision = &components[index + 2];
            if revision.eq_ignore_ascii_case("current")
                || (!revision.is_empty() && revision.bytes().all(|b| b.is_ascii_digit()))
            {
                VERSION_TOKEN.clone_into(&mut components[index + 2]);
            }
        }
    }

    // Flatpak: `.../flatpak/<app|runtime>/<app-id>/<arch>/<branch>/<commit>/`.
    // The commit (or its `active` symlink) is the deployed build; the branch is
    // a release channel and stays literal so stable and beta stay separate.
    for index in 0..components.len().saturating_sub(5) {
        let deployment = components[index].eq_ignore_ascii_case("flatpak")
            && (components[index + 1].eq_ignore_ascii_case("app")
                || components[index + 1].eq_ignore_ascii_case("runtime"));
        if deployment {
            let commit = &components[index + 5];
            if commit.eq_ignore_ascii_case("active") || is_hex_commit(commit) {
                VERSION_TOKEN.clone_into(&mut components[index + 5]);
            }
        }
    }

    // AppImage: a running image is mounted at `/tmp/.mount_<name><random>/`, so
    // the mount point changes every launch. The random suffix cannot be split
    // from the name; the inner path and executable disambiguate.
    for component in components.iter_mut() {
        if is_appimage_mount(component) {
            VERSION_TOKEN.clone_into(component);
        }
    }
}

/// Homebrew and Linuxbrew: `Cellar/<formula>/<version>/`, where the version may
/// carry a revision suffix (`1.2.3_2`) that the generic token rule leaves
/// behind and would otherwise split the family on every rebuild.
fn apply_homebrew_rules(components: &mut [String]) {
    for index in 0..components.len().saturating_sub(2) {
        if components[index].eq_ignore_ascii_case("Cellar") {
            VERSION_TOKEN.clone_into(&mut components[index + 2]);
        }
    }
}

/// Nix: `/nix/store/<hash>-<package>-<version>/`. The store hash changes on
/// every update, so it is erased while the package path is kept.
fn apply_nix_rules(components: &mut [String]) {
    for index in 1..components.len().saturating_sub(1) {
        if components[index].eq_ignore_ascii_case("store")
            && components[index - 1].eq_ignore_ascii_case("nix")
        {
            let replaced = nix_store_package(&components[index + 1])
                .map(|package| format!("{VERSION_TOKEN}-{package}"));
            if let Some(replaced) = replaced {
                components[index + 1] = replaced;
            }
        }
    }
}

/// Playwright browsers: `~/.cache/ms-playwright/<browser>-<build>/...` uses a
/// bare integer build number with no dotted token.
fn apply_playwright_rules(components: &mut [String]) {
    for index in 0..components.len().saturating_sub(1) {
        if components[index].eq_ignore_ascii_case("ms-playwright") {
            let replaced = playwright_browser(&components[index + 1])
                .map(|browser| format!("{browser}-{VERSION_TOKEN}"));
            if let Some(replaced) = replaced {
                components[index + 1] = replaced;
            }
        }
    }
}

/// Vendor release directories that end in a bare year (`Adobe Photoshop 2024`).
fn apply_vendor_release_rules(components: &mut [String]) {
    for component in components.iter_mut() {
        if let Some(separator) = trailing_year_separator(component) {
            component.truncate(separator + 1);
            component.push_str(VERSION_TOKEN);
        }
    }
}

fn is_hex_commit(value: &str) -> bool {
    value.len() >= 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Returns the package part after a Nix store hash: `<hash>-sample-1.2.3`
/// yields `sample-1.2.3`.
fn nix_store_package(value: &str) -> Option<&str> {
    if value.len() < 34 {
        return None;
    }
    let hash = value.get(..32)?;
    if !hash
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return None;
    }
    let package = value.get(32..)?.strip_prefix('-')?;
    (!package.is_empty()).then_some(package)
}

/// Returns the browser name of a Playwright build directory:
/// `chromium-1091` yields `chromium`, `chromium_headless_shell-1091` yields
/// `chromium_headless_shell`.
fn playwright_browser(value: &str) -> Option<&str> {
    let (name, build) = value.rsplit_once('-')?;
    let usable_name = name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    let numeric_build = !build.is_empty() && build.bytes().all(|byte| byte.is_ascii_digit());
    (usable_name && numeric_build).then_some(name)
}

/// Returns true for an `AppImage` mount point `.../.mount_<name><random>`.
fn is_appimage_mount(value: &str) -> bool {
    value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(".mount_"))
}

/// Returns the index of the separator before a trailing release year
/// (`Adobe Photoshop 2024` -> the space, `App-2024` -> the dash).
fn trailing_year_separator(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    if bytes.len() < 6 {
        return None;
    }
    let year_start = bytes.len() - 4;
    let separator = year_start - 1;
    if separator == 0 || !matches!(bytes[separator], b' ' | b'-' | b'_') {
        return None;
    }
    if !bytes[year_start..].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let year = value[year_start..].parse::<u32>().ok()?;
    (1900..=2099).contains(&year).then_some(separator)
}

/// Returns true for `Office<digits>` release directories (`Office16`).
fn is_office_version_dir(value: &str) -> bool {
    let Some(prefix) = value.get(..6) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case("Office") {
        return false;
    }
    let rest = &value[6..];
    !rest.is_empty() && rest.len() <= 3 && rest.bytes().all(|byte| byte.is_ascii_digit())
}

/// Replaces every version token in one path component with [`VERSION_TOKEN`].
fn replace_version_tokens(component: &str) -> String {
    let bytes = component.as_bytes();
    if !bytes.iter().any(u8::is_ascii_digit) {
        return component.to_owned();
    }

    let mut out = String::with_capacity(component.len());
    let mut copied_to = 0;
    let mut index = 0;
    while index < bytes.len() {
        let starts_token = BYTE_FLAGS[bytes[index] as usize] & VERSION_MASK != 0
            && starts_version_token(bytes, index);
        if starts_token {
            if let Some(end) = version_token_end(bytes, index) {
                out.push_str(&component[copied_to..index]);
                out.push_str(VERSION_TOKEN);
                copied_to = end;
                index = end;
                continue;
            }
        }
        index += utf8_char_len(bytes[index]);
    }

    if copied_to == 0 {
        return component.to_owned();
    }
    out.push_str(&component[copied_to..]);
    out
}

/// Returns true when a version token may start at `index`.
///
/// The token must follow a delimiter, a byte that is neither alphanumeric nor a
/// dot. As an exception it may be glued to an alphabetic run that itself starts
/// at a boundary, so `go1.21.5` normalizes to `go{v}` while a dotted package
/// name such as `dc5c6510.2032887045529` (digits before the run) stays literal.
fn starts_version_token(bytes: &[u8], index: usize) -> bool {
    let Some(previous) = index.checked_sub(1).map(|position| bytes[position]) else {
        return true;
    };
    if BYTE_FLAGS[previous as usize] & IDENTITY_MASK == 0 {
        return true;
    }
    if !previous.is_ascii_alphabetic() {
        return false;
    }

    let mut cursor = index - 1;
    while cursor > 0 && bytes[cursor].is_ascii_alphabetic() {
        cursor -= 1;
    }
    if bytes[cursor].is_ascii_alphabetic() {
        // The run reached the component start.
        true
    } else {
        BYTE_FLAGS[bytes[cursor] as usize] & IDENTITY_MASK == 0
    }
}

/// Returns the exclusive end of a version token starting at `start`, if any.
///
/// A token is `[vV]?digit+(.digit+)+`. Its numeric run may be glued to an
/// alphabetic prefix (`go1.21.5`), and it must end at a component boundary,
/// before a non-identity byte, or before an extension dot (`App-1.2.3.exe`).
fn version_token_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    if matches!(bytes.get(index), Some(b'v' | b'V')) {
        index += 1;
    }
    if !bytes.get(index)?.is_ascii_digit() {
        return None;
    }
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }

    let mut has_dot = false;
    loop {
        let dotted =
            index + 1 < bytes.len() && bytes[index] == b'.' && bytes[index + 1].is_ascii_digit();
        if !dotted {
            break;
        }
        has_dot = true;
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
    }
    if !has_dot {
        return None;
    }

    let delimited = index == bytes.len()
        || bytes[index] == b'.'
        || BYTE_FLAGS[bytes[index] as usize] & IDENTITY_MASK == 0;
    delimited.then_some(index)
}

fn utf8_char_len(byte: u8) -> usize {
    match byte {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(path: &str) -> String {
        normalize_versioned_path_with(path, Platform::Windows)
    }

    fn mac(path: &str) -> String {
        normalize_versioned_path_with(path, Platform::MacOs)
    }

    fn linux(path: &str) -> String {
        normalize_versioned_path_with(path, Platform::Linux)
    }

    #[test]
    fn github_desktop_version_bump_is_one_family() {
        assert_eq!(
            win(r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.5\GitHubDesktop.exe"),
            win(r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.6\GitHubDesktop.exe")
        );
    }

    #[test]
    fn a_copy_outside_the_install_root_stays_separate() {
        let installed = win(r"C:\Users\me\AppData\Local\GitHubDesktop\app-3.6.6\GitHubDesktop.exe");
        let desktop = win(r"C:\Users\me\Desktop\GitHubDesktop.exe");
        assert_ne!(installed, desktop);
        assert_ne!(
            installed,
            win(r"D:\GitHubDesktop\app-3.6.6\GitHubDesktop.exe")
        );
    }

    #[test]
    fn dotted_versions_normalize_with_and_without_a_v_prefix() {
        assert_eq!(win(r"C:\apps\v1.2\app.exe"), win(r"C:\apps\v1.3\app.exe"));
        assert_eq!(win(r"C:\apps\v1.2\app.exe"), win(r"C:\apps\1.9\app.exe"));
        assert_eq!(
            win(r"C:\Program Files\Google\Chrome\Application\120.0.6099.109\chrome.exe"),
            win(r"C:\Program Files\Google\Chrome\Application\121.0.0.0\chrome.exe")
        );
    }

    #[test]
    fn versioned_file_names_normalize_before_the_extension() {
        assert_eq!(
            win(r"C:\tools\App-1.2.3.exe"),
            win(r"C:\tools\App-1.2.4.exe")
        );
        assert_eq!(
            linux("/opt/App-1.2.3.AppImage"),
            linux("/opt/App-1.2.4.AppImage")
        );
    }

    #[test]
    fn windows_store_package_versions_normalize() {
        assert_eq!(
            win(
                r"C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2210.0.0_x64__8wekyb3d8bbwe\Calculator.exe"
            ),
            win(
                r"C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2211.0.0_x64__8wekyb3d8bbwe\Calculator.exe"
            )
        );
    }

    #[test]
    fn windows_store_package_names_containing_dots_stay_literal() {
        // `PackageFullName` is `<PackageName>_<Version>_<Arch>_<ResourceId>_<PublisherId>`.
        // The dotted PackageName and the publisher hash must survive, or two
        // different packages could merge.
        let older = win(
            r"C:\Program Files\WindowsApps\Sample.Publisher.1234567890123_4.5.6.0_x64__0abc1def2ghi3\SampleApp.exe",
        );
        let newer = win(
            r"C:\Program Files\WindowsApps\Sample.Publisher.1234567890123_4.7.0.0_x64__0abc1def2ghi3\SampleApp.exe",
        );
        assert_eq!(older, newer);
        assert_eq!(
            older,
            "c:/program files/windowsapps/sample.publisher.1234567890123_{v}_x64__0abc1def2ghi3/sampleapp.exe"
        );

        let other_package = win(
            r"C:\Program Files\WindowsApps\Sample.Publisher.9999999999999_4.5.6.0_x64__0abc1def2ghi3\SampleApp.exe",
        );
        assert_ne!(older, other_package);
        let other_publisher = win(
            r"C:\Program Files\WindowsApps\Sample.Publisher.1234567890123_4.5.6.0_x64__9xyz8wvu7tsr6\SampleApp.exe",
        );
        assert_ne!(older, other_publisher);
    }

    #[test]
    fn non_version_numbers_are_preserved() {
        assert_ne!(win(r"C:\data\2024\tool.exe"), win(r"C:\data\2025\tool.exe"));
        assert_ne!(win(r"C:\apps\3\tool.exe"), win(r"C:\apps\4\tool.exe"));
        // A bare four-digit suffix outside the year range is not a release.
        assert_ne!(
            win(r"C:\data\report-8080\tool.exe"),
            win(r"C:\data\report-9090\tool.exe")
        );
        assert_eq!(win(r"C:\data\2024\tool.exe"), r"c:/data/2024/tool.exe");
    }

    #[test]
    fn windows_folds_case_and_separators_but_unix_preserves_case() {
        assert_eq!(win(r"C:\Apps\Tool.EXE"), win(r"c:/apps/tool.exe"));
        assert_ne!(linux("/opt/Tool/App.exe"), linux("/opt/tool/app.exe"));
    }

    #[test]
    fn extended_length_prefixes_match_the_dos_spelling() {
        assert_eq!(
            win(r"\\?\C:\x\app-1.0\app.exe"),
            win(r"C:\x\app-2.0\app.exe")
        );
        assert_eq!(win(r"\??\C:\x\app.exe"), win(r"C:\x\app.exe"));
    }

    #[test]
    fn macos_framework_generations_normalize() {
        let a =
            mac("/Applications/Foo.app/Contents/Frameworks/Foo.framework/Versions/A/Helpers/foo");
        let b =
            mac("/Applications/Foo.app/Contents/Frameworks/Foo.framework/Versions/B/Helpers/foo");
        let current = mac(
            "/Applications/Foo.app/Contents/Frameworks/Foo.framework/Versions/Current/Helpers/foo",
        );
        assert_eq!(a, b);
        assert_eq!(a, current);
        // A literal directory that merely contains the word is untouched.
        assert_eq!(mac("/opt/Versions/tool"), "/opt/Versions/tool");
    }

    #[test]
    fn snap_revisions_collapse_with_current() {
        let revision = linux("/snap/firefox/4051/usr/lib/firefox/firefox");
        let next = linux("/snap/firefox/4090/usr/lib/firefox/firefox");
        let current = linux("/snap/firefox/current/usr/lib/firefox/firefox");
        assert_eq!(revision, next);
        assert_eq!(revision, current);
        assert_ne!(
            revision,
            linux("/snap/chromium/4051/usr/lib/firefox/firefox")
        );
    }

    #[test]
    fn flatpak_commits_collapse_but_branches_stay_separate() {
        let first = linux(
            "/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/8a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef/files/bin/firefox",
        );
        let second = linux(
            "/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100/files/bin/firefox",
        );
        let active = linux(
            "/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/active/files/bin/firefox",
        );
        assert_eq!(first, second);
        assert_eq!(first, active);
        assert_ne!(
            first,
            linux(
                "/var/lib/flatpak/app/org.mozilla.firefox/x86_64/beta/8a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef/files/bin/firefox",
            )
        );
    }

    #[test]
    fn macos_app_translocation_ignores_the_random_directory() {
        let first = mac(
            "/private/var/folders/1a/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/T/AppTranslocation/11111111-2222-3333-4444-555555555555/d/Sample.app/Contents/MacOS/Sample",
        );
        let second = mac(
            "/private/var/folders/1a/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/T/AppTranslocation/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/d/Sample.app/Contents/MacOS/Sample",
        );
        assert_eq!(first, second);
        assert_ne!(
            first,
            mac(
                "/private/var/folders/1a/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/T/AppTranslocation/11111111-2222-3333-4444-555555555555/d/Other.app/Contents/MacOS/Other",
            )
        );
    }

    #[test]
    fn homebrew_cellar_revisions_collapse() {
        let revision = mac("/opt/homebrew/Cellar/sample/1.2.3_2/bin/sample");
        let next = mac("/opt/homebrew/Cellar/sample/1.2.4_1/bin/sample");
        assert_eq!(revision, next);
        assert_eq!(
            linux("/home/linuxbrew/.linuxbrew/Cellar/sample/1.2.4_1/bin/sample"),
            "/home/linuxbrew/.linuxbrew/Cellar/sample/{v}/bin/sample"
        );
        assert_ne!(
            revision,
            mac("/opt/homebrew/Cellar/other/1.2.4_1/bin/sample")
        );
        assert_ne!(
            revision,
            mac("/opt/homebrew/Cellar/sample/1.2.4_1/bin/other")
        );
    }

    #[test]
    fn nix_store_hashes_are_erased_but_the_package_stays_literal() {
        let first = linux("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sample-1.2.3/bin/sample");
        let second = linux("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-sample-1.3.0/bin/sample");
        assert_eq!(first, second);
        assert_eq!(first, "/nix/store/{v}-sample-{v}/bin/sample");
        assert_ne!(
            first,
            linux("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-other-1.2.3/bin/sample")
        );
    }

    #[test]
    fn appimage_mounts_merge_by_inner_path() {
        let first = linux("/tmp/.mount_SampleApp1a2b3c/usr/bin/sample");
        let second = linux("/tmp/.mount_SampleApp9z8y7x/usr/bin/sample");
        assert_eq!(first, second);
        assert_eq!(first, "/tmp/{v}/usr/bin/sample");
        assert_ne!(first, linux("/tmp/.mount_SampleApp1a2b3c/usr/bin/other"));
    }

    #[test]
    fn playwright_browser_builds_collapse() {
        let first = linux("/home/me/.cache/ms-playwright/chromium-1091/chrome-linux/chrome");
        let second = linux("/home/me/.cache/ms-playwright/chromium-1124/chrome-linux/chrome");
        assert_eq!(first, second);
        assert_ne!(
            first,
            linux("/home/me/.cache/ms-playwright/firefox-1400/chrome-linux/chrome")
        );
        assert_eq!(
            linux("/home/me/.cache/ms-playwright/chromium_headless_shell-1091/chrome-linux/headless_shell"),
            linux("/home/me/.cache/ms-playwright/chromium_headless_shell-1124/chrome-linux/headless_shell")
        );
    }

    #[test]
    fn vendor_release_years_collapse() {
        assert_eq!(
            win(r"C:\Program Files\Adobe\Adobe Photoshop 2024\Photoshop.exe"),
            win(r"C:\Program Files\Adobe\Adobe Photoshop 2025\Photoshop.exe")
        );
        assert_eq!(
            mac("/Applications/Adobe Photoshop 2024/Photoshop"),
            "/Applications/Adobe Photoshop {v}/Photoshop"
        );
        assert_eq!(linux("/opt/MyApp-2019/app"), linux("/opt/MyApp-2020/app"));
    }

    #[test]
    fn platform_rules_do_not_leak_across_flavors() {
        // macOS framework generations only collapse on macOS.
        assert_eq!(
            linux("/Applications/Foo.app/Contents/Frameworks/Foo.framework/Versions/A/foo"),
            "/Applications/Foo.app/Contents/Frameworks/Foo.framework/Versions/A/foo"
        );
        // Snap revisions only collapse on Linux.
        assert_eq!(
            mac("/snap/sample/1234/usr/bin/sample"),
            "/snap/sample/1234/usr/bin/sample"
        );
        // AppImage mounts only collapse on Linux.
        assert_eq!(
            mac("/tmp/.mount_SampleApp1a2b3c/usr/bin/sample"),
            "/tmp/.mount_SampleApp1a2b3c/usr/bin/sample"
        );
        // The Office layout only collapses on Windows.
        assert_eq!(
            linux("/opt/Microsoft Office/root/Office16/WINWORD"),
            "/opt/Microsoft Office/root/Office16/WINWORD"
        );
        // Homebrew and Nix both run on macOS and Linux, not on Windows.
        assert_eq!(
            mac("/opt/homebrew/Cellar/sample/1.2.3_2/bin/sample"),
            mac("/opt/homebrew/Cellar/sample/1.2.4_1/bin/sample")
        );
        assert_eq!(
            win(r"C:\tools\Cellar\sample\1.2.3_2\sample.exe"),
            r"c:/tools/cellar/sample/{v}_2/sample.exe"
        );
        assert_eq!(
            linux("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sample-1.2.3/bin/sample"),
            linux("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-sample-1.3.0/bin/sample")
        );
        // A Windows path with a literal `nix/store` directory keeps its hash.
        assert_ne!(
            win(r"C:\nix\store\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sample-1.2.3\sample.exe"),
            win(r"C:\nix\store\bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-sample-1.3.0\sample.exe")
        );
        // Browser tooling caches exist on every platform.
        assert_eq!(
            mac("/Users/me/Library/Caches/ms-playwright/chromium-1091/chrome"),
            mac("/Users/me/Library/Caches/ms-playwright/chromium-1124/chrome")
        );
        assert_eq!(
            win(r"C:\Users\me\AppData\Local\ms-playwright\chromium-1091\chrome.exe"),
            win(r"C:\Users\me\AppData\Local\ms-playwright\chromium-1124\chrome.exe")
        );
    }

    #[test]
    fn office_release_directories_collapse() {
        assert_eq!(
            win(r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
            win(r"C:\Program Files\Microsoft Office\root\Office15\WINWORD.EXE")
        );
        // A directory that merely starts with the word stays literal.
        assert_eq!(
            win(r"C:\apps\OfficeSuite\tool.exe"),
            r"c:/apps/officesuite/tool.exe"
        );
    }

    #[test]
    fn malformed_and_partial_versions_are_left_alone() {
        // A trailing letter is not a version boundary.
        assert_eq!(win(r"C:\x\1.2.3a\tool.exe"), r"c:/x/1.2.3a/tool.exe");
        // A single-component dotted run is still a version.
        assert_eq!(win(r"C:\x\1.2\tool.exe"), r"c:/x/{v}/tool.exe");
    }

    #[test]
    fn glued_dotted_versions_normalize_behind_an_alphabetic_prefix() {
        assert_eq!(
            win(r"C:\tools\go1.21.5\bin\go.exe"),
            win(r"C:\tools\go1.22.0\bin\go.exe")
        );
        assert_eq!(
            linux("/usr/local/go1.21.5/bin/go"),
            "/usr/local/go{v}/bin/go"
        );
        assert_eq!(linux("/usr/bin/python3.11"), linux("/usr/bin/python3.12"));
        assert_eq!(linux("/usr/bin/python3.11"), "/usr/bin/python{v}");
    }

    #[test]
    fn multibyte_components_do_not_break_the_scanner() {
        assert_eq!(linux("/opt/中文/tool.exe"), "/opt/中文/tool.exe");
        assert_eq!(linux("/opt/中文/v1.2/tool.exe"), "/opt/中文/{v}/tool.exe");
    }

    #[test]
    fn synthetic_placeholders_are_classified() {
        assert!(is_synthetic_placeholder("System / Elevated Process"));
        assert!(is_synthetic_placeholder("  system / elevated process  "));
        assert!(is_synthetic_placeholder("Unknown (Exited)"));
        assert!(is_unknown_placeholder("Unknown (Exited)"));
        assert!(!is_unknown_placeholder("System / Elevated Process"));
        assert!(!is_unknown_placeholder("System"));
        assert!(!is_synthetic_placeholder(r"C:\apps\real.exe"));
    }

    #[test]
    fn name_and_path_identities_can_never_collide() {
        let path_key = stable_identity_with("app.exe", r"C:\apps\app.exe", true, Platform::Windows);
        let name_key =
            stable_identity_with(r"C:\apps\app.exe", "app.exe", false, Platform::Windows);
        assert!(path_key.starts_with("p:"));
        assert!(name_key.starts_with("n:"));
        assert_ne!(path_key, name_key);
    }

    #[test]
    fn rule_identity_is_ascii_case_folded() {
        assert_eq!(
            app_rule_identity(r"C:\PROGRAM FILES\Vendor\App-3.6.5\App.exe"),
            app_rule_identity(r"C:\Program Files\Vendor\App-3.6.6\App.exe")
        );
    }
}
