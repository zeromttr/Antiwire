//! Names the DLL entry point a `rundll32.exe` instance runs.
//!
//! The label is read from the process command line, so each hosted
//! `module.dll,EntryPoint` gets its own identity rather than one shared
//! `rundll32.exe` row.

use crate::process_resolver::path::{executable_name, path_ends_with_ignore_ascii_case};
use crate::process_resolver::windows::process_command_line;
use crate::sanitize;

/// Labels the instance with this PID by the module its command line calls, or
/// `None` when the command line cannot be read (exited, protected) or carries
/// no DLL call.
pub(super) fn hosted_module(pid: u32) -> Option<String> {
    process_command_line(pid).as_deref().and_then(module_label)
}

/// Maximum characters in a hosted-module label. A longer command line
/// keeps the plain identity rather than forking a truncated one that could
/// collide with a different hosted module.
const LABEL_MAX_CHARS: usize = 128;

/// Extracts the hosted-module label (`module.dll,EntryPoint`) from a rundll32
/// command line, or `None` when the command line carries no DLL call.
///
/// rundll32's syntax is `rundll32 <dll>,<entry> [args]`; the DLL token may be
/// quoted and directories may themselves contain commas, so the split prefers
/// the last `.dll,` boundary over the first comma. The entry point is cut at
/// the first whitespace (anything after it is call arguments, not identity).
/// Labels containing control characters, the `::` identity separator, or
/// characters illegal in Windows file names are rejected: such a command line
/// keeps the plain `rundll32.exe` identity instead of forging a confusing one.
fn module_label(command_line: &str) -> Option<String> {
    let mut tokens = split_command_line(command_line);
    if tokens.len() < 2 {
        return None;
    }
    let spec = tokens.remove(1);
    let spec = spec.trim().trim_matches('"').trim();
    if spec.is_empty() {
        return None;
    }
    // Byte-safe: the pattern is pure ASCII and `to_ascii_lowercase` preserves
    // byte length, so indices found in `lower` are valid for `spec`.
    let lower = spec.to_ascii_lowercase();
    let (dll_part, entry_part) = match lower.rfind(".dll,") {
        Some(index) => {
            let dll_part = spec.get(..index + 4)?;
            let entry_part = spec.get(index + 5..)?;
            (dll_part, entry_part)
        }
        None => {
            if path_ends_with_ignore_ascii_case(spec, ".dll") {
                (spec, "")
            } else if spec.contains(',') {
                // Extensionless module name; validated below.
                let (candidate, entry) = spec.split_once(',')?;
                (candidate, entry)
            } else {
                return None;
            }
        }
    };
    let dll_base = {
        let base = executable_name(dll_part);
        if base.is_empty() {
            return None;
        }
        if path_ends_with_ignore_ascii_case(&base, ".dll") {
            base
        } else if base.contains('.') {
            // Some other extension: not a loadable module token.
            return None;
        } else {
            // Extensionless names (`rundll32 dsquery,OpenQueryWindow`) resolve
            // through the loader search order; normalize like process names.
            format!("{base}.dll")
        }
    };
    let entry = entry_part.split_whitespace().next().unwrap_or_default();
    let label = if entry.is_empty() {
        dll_base
    } else {
        format!("{dll_base},{entry}")
    };
    if !label_usable(&label) {
        return None;
    }
    Some(label)
}

/// Returns true when `label` is safe to embed in an application identity.
///
/// The label flows into `SQLite` rows, SIEM payloads, and notifications, which
/// already sanitize; the extra rules here protect the `exe::label` convention
/// itself (`:` would blur the separator) and keep display names to a single
/// line of printable text.
fn label_usable(label: &str) -> bool {
    !label.is_empty()
        && label.chars().count() <= LABEL_MAX_CHARS
        && !sanitize::has_control_chars(label)
        && !label.contains([':', '/', '\\', '"', '<', '>', '|', '?', '*'])
}

/// Splits a Windows command line into tokens, honouring double quotes.
///
/// This is a deliberately small subset of `CommandLineToArgvW`: quotes toggle
/// grouping and are stripped, while backslashes are kept verbatim rather than
/// implementing the backslash-quote escaping rules. A command line exotic
/// enough to need those rules simply fails to parse downstream and keeps the
/// plain identity, which is always safe.
fn split_command_line(command_line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut has_content = false;
    let mut in_quotes = false;
    for character in command_line.chars() {
        match character {
            '"' => {
                in_quotes = !in_quotes;
                has_content = true;
            }
            character if character.is_whitespace() && !in_quotes => {
                if has_content {
                    tokens.push(std::mem::take(&mut current));
                    has_content = false;
                }
            }
            _ => {
                current.push(character);
                has_content = true;
            }
        }
    }
    if has_content {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_parses_the_documented_invocation_shape() {
        assert_eq!(
            module_label(
                r"C:\Windows\System32\rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL appwiz.cpl"
            )
            .as_deref(),
            Some("shell32.dll,Control_RunDLL")
        );
    }

    #[test]
    fn label_handles_quoted_exe_and_dll_tokens() {
        assert_eq!(
            module_label(
                r#""C:\Windows\System32\rundll32.exe" "C:\Program Files\Vendor\plug in.dll",StartW ""#
            )
            .as_deref(),
            Some("plug in.dll,StartW")
        );
    }

    #[test]
    fn label_accepts_bare_dll_names_and_ordinals() {
        // Extensionless names resolve through the loader search order and are
        // normalized the same way process names gain `.exe`.
        assert_eq!(
            module_label("rundll32.exe dsquery,OpenQueryWindow").as_deref(),
            Some("dsquery.dll,OpenQueryWindow")
        );
        // Bare names without an entry point are not DLL calls.
        assert_eq!(module_label("rundll32.exe dsquery"), None);
        assert_eq!(
            module_label(r"C:\Windows\System32\rundll32.exe a.dll,#24").as_deref(),
            Some("a.dll,#24")
        );
    }

    #[test]
    fn label_without_entry_keeps_the_module_only() {
        assert_eq!(
            module_label(r"C:\Windows\System32\rundll32.exe C:\x\mod.dll").as_deref(),
            Some("mod.dll")
        );
    }

    #[test]
    fn label_prefers_the_dll_boundary_over_commas_in_directories() {
        assert_eq!(
            module_label(
                r"C:\Windows\System32\rundll32.exe C:\we,ird\dir\host.dll,Entry arg1,arg2"
            )
            .as_deref(),
            Some("host.dll,Entry")
        );
    }

    #[test]
    fn label_rejects_non_dll_first_arguments() {
        assert_eq!(module_label("rundll32.exe"), None);
        assert_eq!(module_label("rundll32.exe -sta"), None);
        assert_eq!(module_label("rundll32.exe ,Entry"), None);
        assert_eq!(module_label(""), None);
    }

    #[test]
    fn label_rejects_separator_and_control_characters() {
        // A label containing `::` would blur the `exe::label` identity shape.
        assert_eq!(module_label("rundll32.exe a.dll,Ev::il"), None);
        assert_eq!(module_label("rundll32.exe a.dll,Ev\x01il"), None);
        assert_eq!(
            module_label("rundll32.exe a.dll,Ev il").as_deref(),
            Some("a.dll,Ev")
        );
        // Relative directories collapse to the basename; only the module and
        // entry point survive, so no traversal can reach the label.
        assert_eq!(
            module_label("rundll32.exe ..\\evil.dll,Entry").as_deref(),
            Some("evil.dll,Entry")
        );
        // An entry point smuggling a separator is rejected instead.
        assert_eq!(module_label("rundll32.exe a.dll,..\\evil"), None);
        // `?` and `*` are illegal in Windows file names; a label smuggling
        // them is rejected rather than forging a confusing identity.
        assert_eq!(module_label("rundll32.exe a.dll,Ev?il"), None);
        assert_eq!(module_label("rundll32.exe a.dll,Ev*il"), None);
    }

    #[test]
    fn label_rejects_overlong_command_lines_instead_of_truncating() {
        let long_entry = "E".repeat(LABEL_MAX_CHARS);
        assert_eq!(
            module_label(&format!("rundll32.exe a.dll,{long_entry}")),
            None
        );
    }

    #[test]
    fn label_handles_multibyte_module_paths() {
        assert_eq!(
            module_label("rundll32.exe C:\\\u{4e2d}\u{6587}\\mod.dll,Entry").as_deref(),
            Some("mod.dll,Entry")
        );
    }
}
