//! Process executable names and creation times read from procfs.

use netmetrics_core::ProcessIdentity;
use std::fs;
use std::path::Path;

#[cfg(test)]
mod tests;

pub(super) fn read_process_identity(proc_root: &Path, pid: u32) -> Option<ProcessIdentity> {
    let root = proc_root.join(pid.to_string());
    let executable = fs::read_link(root.join("exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = fs::read_to_string(root.join("comm"))
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .or_else(|| {
            Path::new(&executable)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })?;
    // An unreadable stat means an unknown creation time (zero), never the
    // observation time: stamping "now" as the process start would both poison
    // PID-reuse validation downstream and let a later re-read displace the
    // real value in the process table.
    let start_ts = fs::read_to_string(root.join("stat"))
        .ok()
        .and_then(|stat| parse_proc_start_ticks(&stat))
        .and_then(|ticks| proc_start_epoch_ms(proc_root, ticks))
        .unwrap_or(0);
    Some(ProcessIdentity {
        executable,
        name,
        start_ts,
    })
}

fn parse_proc_start_ticks(stat: &str) -> Option<u64> {
    let end_name = stat.rfind(')')?;
    // Field 22 is starttime. After the closing ')' the first token is field 3.
    stat[end_name + 1..]
        .split_ascii_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
}

fn proc_start_epoch_ms(proc_root: &Path, start_ticks: u64) -> Option<u64> {
    let boot_seconds = fs::read_to_string(proc_root.join("stat"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .parse::<u64>()
        .ok()?;
    // SAFETY: sysconf with _SC_CLK_TCK has no pointer arguments or side effects.
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let ticks_per_second = u64::try_from(ticks_per_second)
        .ok()
        .filter(|value| *value > 0)?;
    Some(
        boot_seconds
            .saturating_mul(1000)
            .saturating_add(start_ticks.saturating_mul(1000) / ticks_per_second),
    )
}
