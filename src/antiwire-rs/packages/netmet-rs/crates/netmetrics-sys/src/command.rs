//! Runs a system tool the way a privileged process must: by absolute path, with no inherited
//! environment, bounded in time and output, and with its exit status checked.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Longest one command may run. The tools run here (`nft`, `pfctl`) make a few kernel calls.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
/// How often [`run_command`] checks whether the child has exited.
const COMMAND_POLL: Duration = Duration::from_millis(10);
/// Most bytes read from each output of one command. What is read here is a few hundred lines.
const COMMAND_OUTPUT_LIMIT: u64 = 1 << 20;

/// What a command that succeeded printed.
#[derive(Debug, Default)]
pub struct CommandOutput {
    /// Its standard output.
    pub stdout: String,
    /// Its standard error, where some tools print what a caller needs (`pfctl -E` its token).
    pub stderr: String,
}

/// Runs `program` with `args`, writes `input` to its standard input, and returns what it printed.
///
/// `program` must be an absolute path: a privileged process does not look a program up on
/// `PATH`. The child gets an empty environment, so nothing inherited changes what it does or
/// prints. It is killed if it is still running after ten seconds, and at most 1 MiB of each
/// output is read; past that the pipe is closed, and the tool fails when it writes more.
///
/// # Errors
///
/// Returns an error when `program` is not absolute or cannot start, when it times out, when
/// its input cannot be written, or when it exits unsuccessfully. The last error carries what
/// it printed on standard error.
pub fn run_command(
    program: &Path,
    args: &[&str],
    input: Option<&str>,
) -> Result<CommandOutput, String> {
    let command = format!("{} {}", program.display(), args.join(" "));
    if !program.is_absolute() {
        return Err(format!("{command}: not an absolute path"));
    }
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{command} could not start: {error}"))?;
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
    thread::scope(|scope| {
        // Both outputs are read while the child runs, so it never waits on a full pipe.
        let stdout = thread::Builder::new().spawn_scoped(scope, move || read_limited(stdout));
        let stderr = thread::Builder::new().spawn_scoped(scope, move || read_limited(stderr));
        // The input is a few hundred bytes, well inside a pipe's buffer, so this write does
        // not wait on the child. Dropping the handle ends the child's input.
        let written = match (child.stdin.take(), input) {
            (Some(mut stdin), Some(input)) => stdin.write_all(input.as_bytes()),
            _ => Ok(()),
        };
        let status = wait_until(&mut child, Instant::now() + COMMAND_TIMEOUT);
        // A reader that could not start dropped its pipe, so the child did not wait on it.
        let collect = |reader: std::io::Result<thread::ScopedJoinHandle<'_, String>>| {
            reader.ok().and_then(|reader| reader.join().ok())
        };
        let (stdout, stderr) = (collect(stdout), collect(stderr));
        let status = status.map_err(|error| format!("{command}: {error}"))?;
        if !status.success() {
            let stderr = stderr.unwrap_or_default();
            return Err(format!("{command} failed ({status}): {}", stderr.trim()));
        }
        written.map_err(|error| format!("{command}: writing its input failed: {error}"))?;
        Ok(CommandOutput {
            stdout: stdout.ok_or_else(|| format!("{command}: its output could not be read"))?,
            stderr: stderr.unwrap_or_default(),
        })
    })
}

/// Waits for `child` to exit, and kills and reaps it once `deadline` passes.
fn wait_until(child: &mut Child, deadline: Instant) -> Result<ExitStatus, String> {
    let failure = loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(COMMAND_POLL),
            Ok(None) => break "timed out".to_owned(),
            Err(error) => break error.to_string(),
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    Err(failure)
}

/// Reads at most [`COMMAND_OUTPUT_LIMIT`] bytes from `pipe`.
fn read_limited(pipe: Option<impl Read>) -> String {
    let mut bytes = Vec::new();
    if let Some(pipe) = pipe {
        // What arrived before a read error is kept; the exit status decides the outcome.
        let _ = pipe.take(COMMAND_OUTPUT_LIMIT).read_to_end(&mut bytes);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_read_up_to_its_limit() {
        assert_eq!(read_limited(Some(&b"lo0\n"[..])), "lo0\n");
        assert_eq!(read_limited(None::<&[u8]>), "");
        let endless = read_limited(Some(std::io::repeat(b'x')));
        assert_eq!(u64::try_from(endless.len()), Ok(COMMAND_OUTPUT_LIMIT));
    }

    #[test]
    fn a_program_named_without_its_path_is_refused() {
        let error = run_command(Path::new("nft"), &["list", "ruleset"], None)
            .expect_err("a bare name must not be run");
        assert!(error.contains("not an absolute path"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn an_unsuccessful_exit_is_an_error_and_a_successful_one_returns_the_output() {
        assert!(run_command(Path::new("/usr/bin/false"), &[], None).is_err());
        let output = run_command(Path::new("/bin/cat"), &[], Some("lo0\n")).expect("cat");
        assert_eq!(output.stdout, "lo0\n");
    }

    #[cfg(unix)]
    #[test]
    fn a_child_still_running_at_the_deadline_is_killed() {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("start sleep");
        let started = Instant::now();
        let error = wait_until(&mut child, Instant::now() + Duration::from_millis(50))
            .expect_err("sleep outlasts the deadline");
        assert_eq!(error, "timed out");
        assert!(started.elapsed() < Duration::from_secs(10));
        // Killed and reaped: the status is already collected, and it is not a success.
        assert!(matches!(child.try_wait(), Ok(Some(status)) if !status.success()));
    }
}
