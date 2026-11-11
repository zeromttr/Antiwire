//! Formatting for untrusted text that is about to cross a display boundary.
//!
//! This module deliberately does not participate in policy identity or path
//! matching. Callers must retain the original value for those operations and
//! use this only for a copied title, message, or log field.

/// Formats untrusted text for a log or user-facing display.
///
/// C0/C1 control characters are omitted, matching the daemon's existing
/// notification sanitization. Unicode format controls are represented by an
/// ASCII escape so bidirectional overrides and zero-width characters cannot
/// hide or reorder the text a reader sees. The returned string is capped by
/// its rendered character count.
pub fn display_text(value: &str, max_chars: usize) -> String {
    let mut rendered = String::with_capacity(value.len().min(max_chars));
    let mut rendered_chars = 0usize;

    for character in value.chars() {
        if character.is_control() {
            continue;
        }

        if is_unicode_format_control(character) {
            let escape = format!(r"\u{{{:04X}}}", u32::from(character));
            let escape_chars = escape.chars().count();
            if rendered_chars + escape_chars > max_chars {
                break;
            }
            rendered.push_str(&escape);
            rendered_chars += escape_chars;
        } else {
            if rendered_chars >= max_chars {
                break;
            }
            rendered.push(character);
            rendered_chars += 1;
        }
    }

    rendered
}

/// Returns true for Unicode `Cf` format controls, including the bidi and
/// zero-width controls that are commonly used to make a path misleading.
fn is_unicode_format_control(character: char) -> bool {
    matches!(
        u32::from(character),
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_bidirectional_and_zero_width_format_controls() {
        assert_eq!(
            display_text("report\u{202E}exe\u{200B}.old", 100),
            r"report\u{202E}exe\u{200B}.old"
        );
        assert_eq!(
            display_text("safe\u{2066}name\u{2069}", 100),
            r"safe\u{2066}name\u{2069}"
        );
    }

    #[test]
    fn strips_controls_and_caps_rendered_output() {
        assert_eq!(display_text("line\n\ttext", 100), "linetext");
        assert_eq!(display_text("ab\u{202E}cd", 10), r"ab\u{202E}");
    }

    #[test]
    fn leaves_ordinary_unicode_paths_unchanged() {
        assert_eq!(display_text(r"C:\程序\应用.exe", 4096), r"C:\程序\应用.exe");
    }
}
