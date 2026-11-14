//! Windows live process lookup and NT device path conversion.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use antiwire_tuning::PROCESS_DEVICE_MAP_REBUILD_MS;
use parking_lot::Mutex;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, FILETIME, HANDLE, WIN32_ERROR};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::path::{executable_name, normalize_process_name};
use super::ResolvedIdentity;

/// NT device name to drive letter, e.g. `\Device\HarddiskVolume3` to `C:`.
type DeviceMap = HashMap<String, String>;

/// The shortest interval between rebuilds forced by a path the map does not
/// know, so a burst of unmappable paths queries the drive letters once.
const DEVICE_MAP_MISS_REBUILD: Duration = Duration::from_secs(1);

#[derive(Default)]
struct DeviceMapState {
    map: Arc<DeviceMap>,
    built_at: Option<Instant>,
}

fn device_map_state() -> &'static Mutex<DeviceMapState> {
    static STATE: OnceLock<Mutex<DeviceMapState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(DeviceMapState::default()))
}

const ERROR_ACCESS_DENIED: WIN32_ERROR = WIN32_ERROR(5);
const ERROR_INSUFFICIENT_BUFFER: WIN32_ERROR = WIN32_ERROR(122);

/// Resolves a live process identity using `QueryFullProcessImageNameW`.
pub fn live_lookup(pid: u32) -> Result<ResolvedIdentity, super::ProcessLookupError> {
    let handle = open_process(pid)?;
    let _guard = ProcessHandleGuard(handle);
    #[cfg(test)]
    crate::test_support::native_probe("process");
    let path = query_full_image_path(handle)?;
    let name = normalize_process_name(&executable_name(&path));
    Ok(ResolvedIdentity {
        path,
        name,
        start_ts: process_start_ts(handle),
    })
}

/// Reads a process's full command line via `NtQueryInformationProcess`.
///
/// Only `PROCESS_QUERY_LIMITED_INFORMATION` is needed on modern Windows, the
/// same rights [`live_lookup`] already holds. Any failure (exited, protected,
/// or unsupported OS) returns `None`; callers keep the plain identity, so a
/// failure here can never make attribution worse than it is today.
#[expect(
    unsafe_code,
    reason = "FFI call to NtQueryInformationProcess for the process command line"
)]
pub fn process_command_line(pid: u32) -> Option<String> {
    use windows::Wdk::System::Threading::{
        NtQueryInformationProcess, ProcessCommandLineInformation,
    };
    use windows::Win32::Foundation::{STATUS_INFO_LENGTH_MISMATCH, UNICODE_STRING};

    /// Absolute ceiling for one command-line read; the OS caps command lines
    /// at 32 KiB, so anything beyond this is a corrupt length.
    const MAX_COMMAND_LINE_BYTES: usize = 131_072;

    let handle = open_process(pid).ok()?;
    let _guard = ProcessHandleGuard(handle);

    let mut capacity_bytes = 2048usize;
    for _ in 0..4 {
        // u64 backing guarantees the 8-byte alignment `UNICODE_STRING` needs;
        // a u16 buffer would only align to 2.
        let mut buffer = vec![0u64; capacity_bytes.div_ceil(8)];
        let capacity_u32 = u32::try_from(buffer.len() * 8).ok()?;
        let mut return_len = 0u32;
        // SAFETY: `buffer` is alive for the call and `return_len` is a valid
        // out pointer; the handle was opened with query rights above.
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                ProcessCommandLineInformation,
                buffer.as_mut_ptr().cast::<std::ffi::c_void>(),
                capacity_u32,
                &raw mut return_len,
            )
        };
        if status != STATUS_INFO_LENGTH_MISMATCH && !status.is_ok() {
            // Exited, protected, or otherwise unreadable: terminal.
            return None;
        }
        if !status.is_ok() {
            // `STATUS_INFO_LENGTH_MISMATCH` carries the required size.
            let needed = return_len as usize;
            if needed > capacity_bytes && needed <= MAX_COMMAND_LINE_BYTES {
                capacity_bytes = needed + 64;
                continue;
            }
            return None;
        }
        // SAFETY: the u64 backing is correctly aligned; copy the struct out
        // rather than borrowing the unaligned-capable buffer.
        let info: UNICODE_STRING =
            unsafe { std::ptr::read(buffer.as_ptr().cast::<UNICODE_STRING>()) };
        let len_bytes = usize::from(info.Length);
        if len_bytes == 0 || len_bytes % 2 != 0 || info.Buffer.is_null() {
            return None;
        }
        // `Length` alone bounds only the size, not the location: verify the
        // string lies inside the buffer ntdll wrote into before dereferencing
        // it. A pointer outside the allocation must never be read, even from
        // a trusted source.
        let buffer_start = buffer.as_ptr() as usize;
        let buffer_len = buffer.len().checked_mul(8)?;
        let string_start = info.Buffer.0 as usize;
        let string_end = string_start.checked_add(len_bytes)?;
        let buffer_end = buffer_start.checked_add(buffer_len)?;
        if string_start < buffer_start
            || string_end > buffer_end
            || !string_start.is_multiple_of(std::mem::align_of::<u16>())
        {
            return None;
        }
        // SAFETY: the (Buffer, Length) range was validated to sit inside
        // `buffer`, which is alive; `Length` is even so it holds whole UTF-16
        // units.
        let units = unsafe { std::slice::from_raw_parts(info.Buffer.0, len_bytes / 2) };
        let command_line = String::from_utf16_lossy(units);
        return (!command_line.trim().is_empty()).then_some(command_line);
    }
    None
}

/// Enumerates running process IDs via `CreateToolhelp32Snapshot`.
#[expect(
    unsafe_code,
    clippy::borrow_as_ptr,
    reason = "FFI calls into the Win32 toolhelp snapshot API take a raw entry pointer"
)]
pub fn enumerate_process_ids() -> Vec<u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    // SAFETY: the flags request a process snapshot with no pointer arguments. A
    // failed or invalid handle is rejected by the match below, so only a valid
    // snapshot reaches the iteration calls.
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(handle) if !handle.is_invalid() => handle,
        _ => return Vec::new(),
    };

    let mut pids = Vec::new();
    // SAFETY: `PROCESSENTRY32W` is plain old data (integers, handles and a UTF-16
    // array), so the all-zero bit pattern is a valid value. `dwSize` is then set
    // to the struct size, as the toolhelp API requires.
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(0),
        ..unsafe { std::mem::zeroed() }
    };

    // SAFETY: `snapshot` is the valid handle checked above, and `entry` is a live
    // local whose `dwSize` is set, so the API may write a full entry into it.
    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();
    while has_entry {
        if entry.th32ProcessID > 0 {
            pids.push(entry.th32ProcessID);
        }
        // SAFETY: same invariants as `Process32FirstW`: the snapshot is still open
        // and `entry` is a live, correctly sized local.
        has_entry = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
    }

    // SAFETY: `snapshot` is a valid handle opened in this function and is not used
    // after this call, so it is closed exactly once.
    unsafe {
        let _ = CloseHandle(snapshot);
    }
    pids
}

/// Passes each process already running before the ETW session started to
/// `seed`.
///
/// Returns how many processes were enumerated and how many produced a usable
/// identity. Skips are normal (protected processes deny the query, PIDs 0/4
/// have no image); the counts exist so startup logs can prove the rundown ran.
pub fn running_processes(mut seed: impl FnMut(u32, &ResolvedIdentity)) -> super::BootstrapStats {
    let mut stats = super::BootstrapStats::default();
    for pid in enumerate_process_ids() {
        if pid <= 4 {
            continue;
        }
        stats.enumerated += 1;
        let Ok(identity) = live_lookup(pid) else {
            continue;
        };
        if identity.path.is_empty() {
            continue;
        }
        seed(pid, &identity);
        stats.seeded += 1;
    }
    stats
}

#[expect(unsafe_code, reason = "FFI call to OpenProcess and GetLastError")]
fn open_process(pid: u32) -> Result<HANDLE, super::ProcessLookupError> {
    // SAFETY: `OpenProcess` is called with a valid PID and limited query rights.
    match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) if !handle.is_invalid() => Ok(handle),
        _ => {
            // SAFETY: `GetLastError` takes no arguments and only reads the calling
            // thread's last-error value, which the failed `OpenProcess` just set.
            let error = unsafe { GetLastError() };
            if error == ERROR_ACCESS_DENIED {
                Err(super::ProcessLookupError::AccessDenied)
            } else {
                Err(super::ProcessLookupError::NotFound)
            }
        }
    }
}

#[expect(
    unsafe_code,
    clippy::borrow_as_ptr,
    reason = "FFI calls to QueryFullProcessImageNameW and GetLastError take raw pointers"
)]
fn query_full_image_path(handle: HANDLE) -> Result<String, super::ProcessLookupError> {
    let mut capacity = 1024u32;
    loop {
        let mut buffer = vec![0u16; capacity as usize];
        let mut size = capacity;
        // SAFETY: `handle` comes from `open_process` with query rights and is alive for
        // the call. `buffer` holds `capacity` UTF-16 units, and `size` starts at that
        // same count, the most the API is allowed to write.
        let ok = unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
        };
        if ok.is_ok() && size > 0 {
            return Ok(String::from_utf16_lossy(&buffer[..size as usize]));
        }

        // SAFETY: `GetLastError` takes no arguments and only reads the calling
        // thread's last-error value, which the failed query just set.
        let error = unsafe { GetLastError() };
        if error != ERROR_INSUFFICIENT_BUFFER || capacity >= 32_768 {
            if error == ERROR_ACCESS_DENIED {
                return Err(super::ProcessLookupError::AccessDenied);
            }
            return Err(super::ProcessLookupError::NotFound);
        }
        capacity = capacity.saturating_mul(2);
    }
}

/// Reads the process creation time, in Unix epoch milliseconds.
///
/// This is the value `FlowMeta.process.start_ts` carries, so a cached or
/// tracked identity can be validated against a lifecycle event even when that
/// event arrived on a different path. Zero means the query failed and no
/// validation is possible.
#[expect(unsafe_code, reason = "FFI call to GetProcessTimes")]
fn process_start_ts(handle: HANDLE) -> u64 {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `handle` was opened with `PROCESS_QUERY_LIMITED_INFORMATION`, which
    // `GetProcessTimes` requires, and all four outputs are valid.
    if unsafe {
        GetProcessTimes(
            handle,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    }
    .is_err()
    {
        return 0;
    }
    filetime_to_unix_ms(creation)
}

/// Converts a Win32 `FILETIME` (100 ns ticks since 1601) to Unix epoch milliseconds.
fn filetime_to_unix_ms(filetime: FILETIME) -> u64 {
    const WINDOWS_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    let ticks = (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime);
    ticks.saturating_sub(WINDOWS_EPOCH_100NS) / 10_000
}

struct ProcessHandleGuard(HANDLE);

impl Drop for ProcessHandleGuard {
    #[expect(unsafe_code, reason = "FFI call to CloseHandle")]
    fn drop(&mut self) {
        // SAFETY: `CloseHandle` is only called on a handle opened by this module.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Converts an NT device path to a DOS path when a drive mapping is known.
pub fn nt_path_to_dos_path(nt_path: &str) -> String {
    if nt_path.is_empty() {
        return String::new();
    }
    if let Some(dos_path) = object_alias_to_dos_path(nt_path) {
        return dos_path;
    }
    if !has_prefix_ignore_ascii_case(nt_path, r"\Device\") {
        return nt_path.to_owned();
    }

    let map = device_map(Rebuild::WhenStale);
    if let Some(dos_path) = try_map_device(&map, nt_path) {
        return dos_path;
    }

    // A volume mounted since the last rebuild is not in the map yet.
    let map = device_map(Rebuild::AfterMiss);
    try_map_device(&map, nt_path).unwrap_or_else(|| nt_path.to_owned())
}

/// Converts a path in the object manager's `\??\` alias directory, which names
/// DOS devices directly: `\??\C:\dir` is `C:\dir` and `\??\UNC\server\share`
/// is `\\server\share`. Any other alias, such as a volume GUID, is left alone.
fn object_alias_to_dos_path(path: &str) -> Option<String> {
    if !has_prefix_ignore_ascii_case(path, r"\??\") {
        return None;
    }
    let rest = &path[4..];
    if has_prefix_ignore_ascii_case(rest, r"UNC\") {
        return Some(format!(r"\\{}", &rest[4..]));
    }
    let bytes = rest.as_bytes();
    let drive = bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes.get(2), None | Some(b'\\'));
    drive.then(|| rest.to_owned())
}

fn has_prefix_ignore_ascii_case(path: &str, prefix: &str) -> bool {
    path.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn try_map_device(map: &DeviceMap, nt_path: &str) -> Option<String> {
    let bytes = nt_path.as_bytes();
    // The map is unordered, so a shorter device that is also a prefix of the
    // path could win the iteration and shadow the real one. Pick the longest
    // matching device deterministically.
    let mut best: Option<(&str, &str)> = None;
    for (device, drive) in map {
        if bytes.len() < device.len() {
            continue;
        }
        let prefix_matches = bytes
            .get(..device.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(device.as_bytes()));
        if !prefix_matches
            || (bytes.len() != device.len() && !matches!(bytes.get(device.len()), Some(b'\\')))
        {
            continue;
        }
        if best.is_none_or(|(best_device, _)| device.len() > best_device.len()) {
            best = Some((device, drive));
        }
    }
    let (device, drive) = best?;
    Some(format!("{drive}{}", nt_path.get(device.len()..)?))
}

/// When [`device_map`] queries the drive letters again.
#[derive(Clone, Copy)]
enum Rebuild {
    /// Once the map is older than the regular rebuild interval.
    WhenStale,
    /// After a lookup missed: soon, but at most once per
    /// [`DEVICE_MAP_MISS_REBUILD`].
    AfterMiss,
}

/// Returns the current device map, rebuilding it first when `rebuild` asks.
#[expect(unsafe_code, reason = "FFI call to QueryDosDeviceW")]
fn device_map(rebuild: Rebuild) -> Arc<DeviceMap> {
    let mut state = device_map_state().lock();
    let max_age = match rebuild {
        Rebuild::WhenStale => Duration::from_millis(PROCESS_DEVICE_MAP_REBUILD_MS),
        Rebuild::AfterMiss => DEVICE_MAP_MISS_REBUILD,
    };
    if state
        .built_at
        .is_some_and(|built_at| built_at.elapsed() < max_age)
    {
        return Arc::clone(&state.map);
    }

    let mut map = HashMap::new();
    let mut target = [0u16; 300];
    for letter in b'A'..=b'Z' {
        let device_name = format!("{}:", letter as char);
        let mut device_name_wide: Vec<u16> = device_name.encode_utf16().chain([0]).collect();
        // SAFETY: `device_name_wide` is NUL-terminated and `target` is large enough for sizing.
        let result = unsafe {
            QueryDosDeviceW(
                windows::core::PCWSTR(device_name_wide.as_mut_ptr()),
                Some(&mut target),
            )
        };
        if result != 0 {
            let end = target
                .iter()
                .position(|&ch| ch == 0)
                .unwrap_or(target.len());
            let device = String::from_utf16_lossy(&target[..end]);
            if !device.is_empty() {
                register_device(&mut map, device, device_name);
            }
        }
    }

    state.map = Arc::new(map);
    state.built_at = Some(Instant::now());
    Arc::clone(&state.map)
}

/// Records `device -> drive`, keeping the first (canonically lowest) drive letter.
///
/// A device can be reachable through more than one drive letter: a mounted
/// volume also assigned a letter, or a `subst` alias. Overwriting on every
/// letter let a later, higher letter replace the canonical one and changed the
/// path string that feeds path-based policy. First mapping wins.
fn register_device(map: &mut HashMap<String, String>, device: String, drive: String) {
    map.entry(device).or_insert(drive);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_process_command_line_is_readable() {
        // The test process can always open itself with limited-query rights,
        // so this exercises the real `NtQueryInformationProcess` path without
        // elevation or live fixtures.
        let command_line =
            process_command_line(std::process::id()).expect("own command line resolves");
        assert_ne!(command_line.trim(), "");
    }

    #[test]
    fn exited_process_command_line_is_none() {
        // PID 0 can never be opened: the failure must surface as `None`, never
        // a panic, so callers keep the plain identity.
        assert_eq!(process_command_line(0), None);
    }

    #[test]
    fn nt_path_conversion_passes_through_non_device_paths() {
        assert_eq!(
            nt_path_to_dos_path(r"C:\already\dos\path.exe"),
            r"C:\already\dos\path.exe"
        );
        assert_eq!(nt_path_to_dos_path(""), "");
    }

    #[test]
    fn nt_path_conversion_maps_system_drive_device() {
        let map = device_map(Rebuild::AfterMiss);
        let Some((device, drive)) = map.iter().next() else {
            return;
        };
        let nt_path = format!("{device}\\Windows\\System32\\svchost.exe");
        let dos_path = nt_path_to_dos_path(&nt_path);
        assert_eq!(dos_path, format!("{drive}\\Windows\\System32\\svchost.exe"));
    }

    #[test]
    fn object_alias_paths_convert_to_dos_paths() {
        assert_eq!(
            nt_path_to_dos_path(r"\??\C:\Program Files\app.exe"),
            r"C:\Program Files\app.exe"
        );
        assert_eq!(
            nt_path_to_dos_path(r"\??\unc\server\share\tool.exe"),
            r"\\server\share\tool.exe"
        );
        let volume = r"\??\Volume{00000000-0000-0000-0000-000000000000}\tool.exe";
        assert_eq!(nt_path_to_dos_path(volume), volume);
    }

    #[test]
    fn unmappable_nt_path_is_kept_verbatim() {
        let path = nt_path_to_dos_path(r"\Device\AntiwireBogusVolume\dir\tool.exe");
        assert_eq!(path, r"\Device\AntiwireBogusVolume\dir\tool.exe");
    }

    #[test]
    fn try_map_device_handles_multibyte_nt_paths() {
        let mut map = HashMap::new();
        map.insert(r"\Device\HarddiskVolume3".to_owned(), "C:".to_owned());
        // The device name is 23 bytes; every boundary in these thirteen
        // three-byte characters is a multiple of three, so the old prefix slice
        // at byte 23 split a character.
        let nt_path = "€€€€€€€€€€€€€";
        assert_eq!(nt_path.len(), 39);
        assert!(!nt_path.is_char_boundary(23));
        assert!(try_map_device(&map, nt_path).is_none());
    }

    #[test]
    fn device_registration_keeps_the_first_drive_letter() {
        let mut map = HashMap::new();
        register_device(
            &mut map,
            r"\Device\HarddiskVolume3".to_owned(),
            "C:".to_owned(),
        );
        register_device(
            &mut map,
            r"\Device\HarddiskVolume3".to_owned(),
            "Z:".to_owned(),
        );
        assert_eq!(
            map.get(r"\Device\HarddiskVolume3").map(String::as_str),
            Some("C:")
        );
    }

    #[test]
    fn try_map_device_prefers_the_longest_matching_device() {
        let mut map = HashMap::new();
        map.insert(r"\Device\A".to_owned(), "C:".to_owned());
        map.insert(r"\Device\A\B".to_owned(), "D:".to_owned());
        assert_eq!(
            try_map_device(&map, r"\Device\A\B\tool.exe"),
            Some(r"D:\tool.exe".to_owned())
        );
    }
}
