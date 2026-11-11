//! Sanitization for strings that cross the process trust boundary.
//!
//! Executable paths, process names, DNS names, and blocklist labels can all be
//! chosen by another process. They are interpolated into user-facing
//! notifications, SIEM payloads, tracing fields, and `SQLite` rows, so control
//! characters are stripped and length is capped before any of those uses.
//! Stripping rather than escaping keeps a forged newline from splitting one
//! record into two, which is the log-injection failure mode this guards.
//! Unicode format controls are retained here so an executable path remains an
//! exact identity; display boundaries use `antiwire_policy::display_text`.

/// Maximum characters retained for an executable path.
pub(crate) const MAX_PATH_CHARS: usize = 4096;
/// Maximum characters retained for a process or application display name.
pub(crate) const MAX_NAME_CHARS: usize = 256;
/// Maximum characters retained for a DNS name (RFC 1035 wire limit).
pub(crate) const MAX_DOMAIN_CHARS: usize = 253;
/// Maximum characters retained for a single blocklist label.
pub(crate) const MAX_LABEL_CHARS: usize = 128;
/// Maximum characters retained for a composed notification message.
pub(crate) const MAX_MESSAGE_CHARS: usize = 1024;

/// Returns a copy of `value` with control characters removed and at most
/// `max_chars` characters retained. Character-based so multi-byte input can
/// never split a code point.
pub(crate) fn text(value: &str, max_chars: usize) -> String {
    let mut clean = String::with_capacity(value.len().min(max_chars));
    let mut kept = 0usize;
    for character in value.chars() {
        if kept >= max_chars {
            break;
        }
        if !character.is_control() {
            clean.push(character);
            kept += 1;
        }
    }
    clean
}

/// Trims and sanitizes `value` to `max_chars`, the form used for stored fields.
pub(crate) fn trimmed(value: &str, max_chars: usize) -> String {
    text(value.trim(), max_chars)
}

/// Returns true when `value` contains a control character.
pub(crate) fn has_control_chars(value: &str) -> bool {
    value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_control_characters() {
        assert_eq!(
            text("chrome.exe\nINFO forged", 100),
            "chrome.exeINFO forged"
        );
        assert_eq!(text("evil\u{0}.example", 100), "evil.example");
        assert_eq!(text("tab\there", 100), "tabhere");
    }

    #[test]
    fn caps_by_characters_not_bytes() {
        let value = "中中中中中";
        assert_eq!(text(value, 3), "中中中");
        assert_eq!(text(value, 99).chars().count(), 5);
    }

    #[test]
    fn preserves_ordinary_text() {
        assert_eq!(
            text(r"C:\Program Files\app.exe", 4096),
            r"C:\Program Files\app.exe"
        );
        assert_eq!(trimmed("  example.com  ", 253), "example.com");
    }

    #[test]
    fn preserves_unicode_format_controls_in_raw_paths() {
        let path = "C:\\程序\\应用\u{202E}.exe";
        assert_eq!(trimmed(path, MAX_PATH_CHARS), path);
    }
}
