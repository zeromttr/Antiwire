//! Bounded child processes for DNS recovery. PowerShell waits for a stdin gate
//! until it belongs to our kill-on-close job, so netsh children cannot escape it.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::CREATE_NO_WINDOW;

pub(super) const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;

struct ChildJob(HANDLE);

impl ChildJob {
    fn new() -> io::Result<Self> {
        // SAFETY: unnamed job with default security; the returned handle is owned here.
        let job =
            Self(unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(io::Error::other)?);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: limits is initialized and sized for the requested information class.
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                u32::try_from(std::mem::size_of_val(&limits)).expect("job limits size fits u32"),
            )
        }
        .map_err(io::Error::other)?;
        Ok(job)
    }
}

impl Drop for ChildJob {
    fn drop(&mut self) {
        // SAFETY: we own this handle. Closing the last job handle terminates
        // every remaining child, including netsh launched by PowerShell.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

pub(super) fn status(command: &mut Command) -> io::Result<std::process::ExitStatus> {
    run(command, COMMAND_TIMEOUT, false).map(|output| output.status)
}

pub(super) fn powershell(script: &str) -> io::Result<Output> {
    powershell_with_timeout(script, COMMAND_TIMEOUT)
}

fn powershell_with_timeout(script: &str, timeout: Duration) -> io::Result<Output> {
    let gated = format!("$null = [Console]::ReadLine(); & {{ {script} }}");
    run(
        Command::new("powershell").args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &gated,
        ]),
        timeout,
        true,
    )
}

fn run(command: &mut Command, timeout: Duration, gated: bool) -> io::Result<Output> {
    let deadline = Instant::now() + timeout;
    let job = ChildJob::new()?;
    // A file avoids pipe deadlocks and descendants retaining a pipe's write end.
    let mut stdout = tempfile::tempfile()?;
    let mut child = command
        .creation_flags(CREATE_NO_WINDOW.0)
        .stdin(if gated { Stdio::piped() } else { Stdio::null() })
        .stdout(stdout.try_clone()?)
        .stderr(Stdio::null())
        .spawn()?;
    // SAFETY: both handles are live; the job remains owned until after the wait.
    if let Err(error) = unsafe { AssignProcessToJobObject(job.0, HANDLE(child.as_raw_handle())) } {
        // A very short standalone command may already have exited. PowerShell
        // cannot execute the script yet because the stdin gate is still closed.
        if !matches!(child.try_wait(), Ok(Some(_))) {
            let _ = child.kill();
            return Err(io::Error::other(error));
        }
    }
    if gated {
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing PowerShell stdin gate"))?
            .write_all(b"\n")?;
    }
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            // Dropping job kills the entire tree; never wait without a deadline.
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS command timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(job);
    if stdout.metadata()?.len() > MAX_OUTPUT_BYTES {
        return Err(io::Error::other("DNS command output exceeds size limit"));
    }
    stdout.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    stdout.take(MAX_OUTPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(io::Error::other("DNS command output exceeds size limit"));
    }
    Ok(Output {
        status,
        stdout: bytes,
        stderr: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_output_and_unsuccessful_status_are_preserved() {
        let output = powershell("Write-Output 'captured'; exit 7").unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "captured");
    }

    #[test]
    fn timeout_terminates_powershell_descendants_too() {
        use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{
            OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
        };

        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("child.pid");
        let escaped = pid_file.to_string_lossy().replace('\'', "''");
        let script = format!(
            "$child = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 60' -PassThru -WindowStyle Hidden; \
             [System.IO.File]::WriteAllText('{escaped}', [string]$child.Id); Start-Sleep -Seconds 60"
        );
        // Long enough for a loaded CI runner to start both PowerShells and record
        // the child before the timeout fires; 4 s was not.
        let error = powershell_with_timeout(&script, Duration::from_secs(15)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let pid = std::fs::read_to_string(pid_file)
            .expect("child started")
            .parse()
            .unwrap();
        // SAFETY: requesting only synchronization access to the recorded child PID.
        match unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) } {
            Ok(handle) => {
                // SAFETY: handle is live and owned here; bounded wait for job teardown.
                let result = unsafe { WaitForSingleObject(handle, 1000) };
                // SAFETY: close the handle once after the wait.
                let _ = unsafe { CloseHandle(handle) };
                assert_eq!(result, WAIT_OBJECT_0, "descendant survived the timeout");
            }
            Err(error) => assert_eq!(
                error.code(),
                windows::core::HRESULT::from_win32(ERROR_INVALID_PARAMETER.0)
            ),
        }
    }

    #[test]
    fn hung_child_is_bounded() {
        let started = Instant::now();
        let error = run(
            Command::new("powershell").args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 30",
            ]),
            Duration::from_millis(100),
            false,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
