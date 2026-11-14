//! Building Windows command lines that parse back to the intended arguments.
//!
//! A child process receives one command-line string, which its C runtime or
//! `CommandLineToArgvW` splits back into arguments. The splitting rules are
//! not "quote it if it has a space": tabs also separate arguments, an empty
//! argument vanishes unless it is quoted, an embedded quote must be escaped,
//! and backslashes are literal except in a run that ends at a quote, where a
//! trailing backslash would escape the closing quote. This module applies
//! those rules to UTF-16 units, so a non-Unicode `OsStr` survives as it is.

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

const QUOTE: u16 = b'"' as u16;
const BACKSLASH: u16 = b'\\' as u16;

/// Appends `arg` to `line`, quoted so it parses back to exactly `arg`.
///
/// Every argument is quoted, which is always valid, and is the only form
/// that keeps an empty argument. Use it for every argument after the
/// program name.
pub fn push_quoted_arg(line: &mut Vec<u16>, arg: &OsStr) {
    line.push(QUOTE);
    let mut backslashes = 0usize;
    for unit in arg.encode_wide() {
        match unit {
            BACKSLASH => backslashes += 1,
            QUOTE => {
                // The run before a quote is doubled, plus one to escape it.
                line.extend(std::iter::repeat_n(BACKSLASH, backslashes * 2 + 1));
                line.push(QUOTE);
                backslashes = 0;
            }
            _ => {
                line.extend(std::iter::repeat_n(BACKSLASH, backslashes));
                line.push(unit);
                backslashes = 0;
            }
        }
    }
    // A run before the closing quote is doubled so it cannot escape it.
    line.extend(std::iter::repeat_n(BACKSLASH, backslashes * 2));
    line.push(QUOTE);
}

/// `arg` quoted as [`push_quoted_arg`] quotes it.
#[must_use]
pub fn quote_arg(arg: &OsStr) -> OsString {
    let mut line = Vec::new();
    push_quoted_arg(&mut line, arg);
    OsString::from_wide(&line)
}

/// A full command line: `program`, then each of `args`, all quoted.
///
/// The program name follows simpler rules than the arguments: it ends at
/// its closing quote, and backslashes in it are never escapes. A Windows
/// path cannot contain a quote, so quoting it as it is is enough.
#[must_use]
pub fn command_line(program: &OsStr, args: &[OsString]) -> Vec<u16> {
    let mut line = Vec::new();
    line.push(QUOTE);
    line.extend(program.encode_wide());
    line.push(QUOTE);
    for arg in args {
        line.push(u16::from(b' '));
        push_quoted_arg(&mut line, arg);
    }
    line
}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)]

    use super::*;

    fn quoted(arg: &str) -> String {
        quote_arg(OsStr::new(arg)).to_string_lossy().into_owned()
    }

    /// Splits `line` with the parser child processes use.
    fn parse(line: &[u16]) -> Vec<OsString> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::UI::Shell::CommandLineToArgvW;

        let wide: Vec<u16> = line.iter().copied().chain([0]).collect();
        let mut count = 0i32;
        // SAFETY: `wide` is NUL-terminated and outlives the call. The returned
        // array holds `count` NUL-terminated strings and is freed once, below.
        unsafe {
            let argv = CommandLineToArgvW(PCWSTR(wide.as_ptr()), &raw mut count);
            assert!(!argv.is_null(), "CommandLineToArgvW failed");
            let parsed = (0..usize::try_from(count).expect("count"))
                .map(|index| OsString::from_wide((*argv.add(index)).as_wide()))
                .collect();
            let _ = LocalFree(Some(HLOCAL(argv.cast())));
            parsed
        }
    }

    #[test]
    fn quotes_paths_without_special_characters() {
        assert_eq!(
            quoted(r"C:\Program Files\antiwire.exe"),
            r#""C:\Program Files\antiwire.exe""#
        );
    }

    #[test]
    fn trailing_backslash_is_doubled_before_the_closing_quote() {
        assert_eq!(quoted(r"C:\data\"), r#""C:\data\\""#);
    }

    #[test]
    fn embedded_quote_is_escaped_and_cannot_break_out() {
        assert_eq!(quoted(r#"a"b"#), r#""a\"b""#);
    }

    #[test]
    fn backslash_before_a_quote_is_doubled_and_the_quote_escaped() {
        assert_eq!(quoted(r#"a\"b"#), r#""a\\\"b""#);
    }

    #[test]
    fn an_empty_argument_is_kept() {
        assert_eq!(quoted(""), r#""""#);
    }

    /// The parser the child uses must hand back every argument as it was,
    /// including the ones a space check alone would fuse or drop.
    #[test]
    fn every_argument_round_trips_through_command_line_to_argv() {
        let program = OsStr::new(r"C:\Program Files\Antiwire\antiwire-daemon.exe");
        let args: Vec<OsString> = [
            "--no-service",
            "",
            "with space",
            "with\ttab",
            r"C:\data\",
            r"C:\data dir\",
            r#"a"b"#,
            r#"a\"b"#,
            r"\\server\share\",
            "trailing\\\\",
            "ünïcödé",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();

        let parsed = parse(&command_line(program, &args));

        assert_eq!(parsed[0], program);
        assert_eq!(&parsed[1..], args.as_slice());
    }

    /// An `OsString` that is not valid UTF-16 is passed through unit for unit.
    #[test]
    fn unpaired_surrogates_round_trip() {
        let lone = OsString::from_wide(&[u16::from(b'x'), 0xD800, u16::from(b'y')]);
        let program = OsStr::new(r"C:\a.exe");
        let parsed = parse(&command_line(program, std::slice::from_ref(&lone)));
        assert_eq!(parsed[1], lone);
    }
}
