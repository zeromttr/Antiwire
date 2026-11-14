//! Process executable names and creation times read from procfs.

use netmetrics_core::ProcessIdentity;
use std::fs;
use std::path::Path;

#[cfg(test)]
mod tests;

/// What `/proc` says about a process, with the value that tells it from every other
/// process that has had, or will have, its PID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProcessReading {
    pub identity: ProcessIdentity,
    /// `proc_pid_stat(5)` field 22, `starttime`: when the process started, in clock ticks
    /// since boot. It is fixed for the life of the process.
    ///
    /// `identity.start_ts` is not. It adds the boot time, `btime` in `proc_stat(5)`, which the
    /// kernel works out from the wall clock each time the file is read (`getboottime64`
    /// in `kernel/time/timekeeping.c`). After the clock has been set, the same process
    /// reads a different `start_ts`, so whether two readings are of one process is
    /// decided on this value.
    pub start_ticks: Option<u64>,
}

pub(super) fn read_process(proc_root: &Path, pid: u32) -> Option<ProcessReading> {
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
    let start_ticks = fs::read_to_string(root.join("stat"))
        .ok()
        .and_then(|stat| parse_proc_start_ticks(&stat));
    Some(ProcessReading {
        identity: ProcessIdentity {
            executable,
            name,
            start_ts: start_ticks
                .and_then(|ticks| proc_start_epoch_ms(proc_root, ticks))
                .unwrap_or(0),
        },
        start_ticks,
    })
}

/// What an exit record says about a process `/proc` no longer describes: its name and
/// start time, without the executable path that only `/proc/<pid>/exe` held.
#[cfg(feature = "ebpf")]
pub(super) fn exited_process(
    proc_root: &Path,
    name: &str,
    start_boottime_ns: u64,
) -> Option<ProcessReading> {
    if name.is_empty() {
        return None;
    }
    let start_ticks = boottime_ticks(start_boottime_ns);
    Some(ProcessReading {
        identity: ProcessIdentity {
            executable: String::new(),
            name: name.to_owned(),
            start_ts: start_ticks
                .and_then(|ticks| proc_start_epoch_ms(proc_root, ticks))
                .unwrap_or(0),
        },
        start_ticks,
    })
}

/// A start time in nanoseconds since boot, in the clock ticks `proc_pid_stat(5)` reports
/// `starttime` in. The kernel makes this conversion itself, from the same nanosecond
/// value (`nsec_to_clock_t` in `do_task_stat`, `fs/proc/array.c`), dropping the fraction
/// of a tick; where a tick is not a whole number of nanoseconds it rounds another way,
/// and the answer here is `None`.
#[cfg(feature = "ebpf")]
pub(super) fn boottime_ticks(start_boottime_ns: u64) -> Option<u64> {
    const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;
    let ticks_per_second = clock_ticks_per_second()?;
    NANOSECONDS_PER_SECOND
        .is_multiple_of(ticks_per_second)
        .then(|| start_boottime_ns / (NANOSECONDS_PER_SECOND / ticks_per_second))
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
    let ticks_per_second = clock_ticks_per_second()?;
    Some(
        boot_seconds
            .saturating_mul(1000)
            .saturating_add(start_ticks.saturating_mul(1000) / ticks_per_second),
    )
}

/// The clock ticks in a second that proc(5) counts times in.
fn clock_ticks_per_second() -> Option<u64> {
    // SAFETY: sysconf with _SC_CLK_TCK has no pointer arguments or side effects.
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(ticks_per_second)
        .ok()
        .filter(|value| *value > 0)
}
