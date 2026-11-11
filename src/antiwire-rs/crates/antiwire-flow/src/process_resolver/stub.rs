//! Non-Windows live process lookup via sysinfo.

use std::sync::OnceLock;

use parking_lot::Mutex;
use sysinfo::{Pid, ProcessesToUpdate, System};

use super::path::normalize_process_name;
use super::ResolvedIdentity;

fn system() -> &'static Mutex<System> {
    static SYSTEM: OnceLock<Mutex<System>> = OnceLock::new();
    SYSTEM.get_or_init(|| Mutex::new(System::new()))
}

/// Passes each process already running before collection started to `seed`.
///
/// Returns how many processes were enumerated and how many produced a usable
/// identity, so startup logs can prove the rundown ran.
pub fn running_processes(mut seed: impl FnMut(u32, &ResolvedIdentity)) -> super::BootstrapStats {
    let mut stats = super::BootstrapStats::default();
    let mut system = system().lock();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let pids: Vec<u32> = system
        .processes()
        .keys()
        .map(|pid| pid.as_u32())
        .filter(|pid| *pid > 4)
        .collect();

    for pid in pids {
        stats.enumerated += 1;
        let sys_pid = Pid::from_u32(pid);
        let Some(process) = system.process(sys_pid) else {
            continue;
        };
        let raw_name = process.name().to_string_lossy();
        let name = normalize_process_name(&raw_name);
        let path = process
            .exe()
            .map(|exe| exe.to_string_lossy().into_owned())
            .unwrap_or_default();
        if path.is_empty() {
            continue;
        }
        seed(
            pid,
            &ResolvedIdentity {
                path,
                name,
                start_ts: sysinfo_start_ts(process),
            },
        );
        stats.seeded += 1;
    }
    stats
}

/// Resolves a live process identity using sysinfo.
pub fn live_lookup(pid: u32) -> Result<ResolvedIdentity, super::ProcessLookupError> {
    let mut system = system().lock();
    let sys_pid = Pid::from_u32(pid);
    system.refresh_processes(ProcessesToUpdate::Some(&[sys_pid]), true);
    let Some(process) = system.process(sys_pid) else {
        return Err(super::ProcessLookupError::NotFound);
    };

    let raw_name = process.name().to_string_lossy();
    let name = normalize_process_name(&raw_name);
    let path = process
        .exe()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    if path.is_empty() {
        return Err(super::ProcessLookupError::NotFound);
    }
    Ok(ResolvedIdentity {
        path,
        name,
        start_ts: sysinfo_start_ts(process),
    })
}

/// `sysinfo` reports creation time in whole seconds; the contract stores Unix
/// epoch milliseconds.
fn sysinfo_start_ts(process: &sysinfo::Process) -> u64 {
    process.start_time().saturating_mul(1_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_lookup_reports_a_start_timestamp() {
        let lookup = live_lookup(std::process::id()).expect("own process resolves");
        assert!(!lookup.path.is_empty());
        assert!(lookup.start_ts > 0);
    }
}
