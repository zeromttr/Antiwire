//! The Windows Filtering Platform calls behind the DNS block.
//!
//! All of it is the user-mode management API, which needs no driver:
//! <https://learn.microsoft.com/windows/win32/api/fwpmu/>. Every object is added in a
//! dynamic session, so Windows deletes it when the session ends, which is when the engine
//! handle is closed or this process ends, however it ends
//! (<https://learn.microsoft.com/windows/win32/fwp/object-management>).
//!
//! Adding objects needs Administrator: by default only the Administrators group has
//! `FWPM_ACTRL_ADD` (<https://learn.microsoft.com/windows/win32/fwp/access-control>).

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::{iter, ptr, slice};

use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_DATA_TYPE,
    FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_NONE_SET, FWP_MATCH_TYPE, FWP_UINT8, FWP_UINT16, FWP_UINT32,
    FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0, FWPM_ACTION0_0, FWPM_CONDITION_ALE_APP_ID,
    FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER0,
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterGetById0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::{GUID, PCWSTR, PWSTR};

use super::{Family, FilterSpec};

const ERROR_SUCCESS: u32 = 0;
/// `E_ACCESSDENIED`, which the engine's RPC layer can report in place of the Win32 code.
const E_ACCESSDENIED: u32 = 0x8007_0005;

/// The sublayer the filters live in. Its weight orders it among other sublayers, which does
/// not change the outcome: a block in any sublayer is final
/// (<https://learn.microsoft.com/windows/win32/fwp/filter-arbitration>).
const SUBLAYER_WEIGHT: u16 = 0x8000;
/// Weight ranges inside the sublayer: a permit is evaluated before a block, so the first
/// match for an exempt program is its permit.
/// <https://learn.microsoft.com/windows/win32/fwp/filter-weight-assignment>
const PERMIT_WEIGHT_RANGE: u8 = 15;
const BLOCK_WEIGHT_RANGE: u8 = 14;

/// `text` as the NUL-terminated UTF-16 a `PWSTR` points to.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(iter::once(0)).collect()
}

/// Says which call failed, and with what.
fn failure(call: &str, status: u32) -> String {
    let hint = if status == ERROR_ACCESS_DENIED.0 || status == E_ACCESSDENIED {
        " (access denied: adding filters needs Administrator)"
    } else {
        ""
    };
    format!("{call} failed with status {status:#010x}{hint}")
}

fn check(call: &str, status: u32) -> Result<(), String> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(failure(call, status))
    }
}

/// Frees what a WFP function allocated.
/// <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0>
///
/// # Safety
///
/// `pointer` must come from a WFP function documented to be freed with `FwpmFreeMemory0`,
/// and must not have been freed before.
unsafe fn free(mut pointer: *mut c_void) {
    // SAFETY: the caller guarantees `pointer` is such an allocation; the call takes the
    // address of the pointer, which is this live local.
    unsafe { FwpmFreeMemory0(&raw mut pointer) };
}

/// The id WFP knows the program at `path` by, which is what
/// `FWPM_CONDITION_ALE_APP_ID` matches.
/// <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0>
///
/// # Errors
///
/// When the path holds a NUL, or WFP cannot name the file, such as when it does not exist.
pub(super) fn app_id(path: &Path) -> Result<Vec<u8>, String> {
    let name: Vec<u16> = path.as_os_str().encode_wide().collect();
    if name.contains(&0) {
        return Err(format!("{} holds a NUL character", path.display()));
    }
    let name: Vec<u16> = name.into_iter().chain(iter::once(0)).collect();
    let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
    // SAFETY: `name` is NUL-terminated and lives past the call, and `blob` is a valid place
    // for the pointer the function returns.
    let status = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(name.as_ptr()), &raw mut blob) };
    if status != ERROR_SUCCESS || blob.is_null() {
        return Err(format!(
            "{}: {}",
            path.display(),
            failure("FwpmGetAppIdFromFileName0", status)
        ));
    }
    // SAFETY: the call succeeded, so `blob` points to a blob WFP allocated, which stays
    // valid until it is freed below.
    let FWP_BYTE_BLOB { size, data } = unsafe { *blob };
    let bytes = match usize::try_from(size) {
        Ok(size) if !data.is_null() => {
            // SAFETY: a blob WFP returns holds `size` readable bytes at `data`.
            unsafe { slice::from_raw_parts(data, size) }.to_vec()
        }
        _ => Vec::new(),
    };
    // SAFETY: `blob` came from `FwpmGetAppIdFromFileName0`, whose documentation names
    // `FwpmFreeMemory0`, and this is the one place that frees it.
    unsafe { free(blob.cast()) };
    if bytes.is_empty() {
        return Err(format!("{}: WFP returned an empty id", path.display()));
    }
    Ok(bytes)
}

/// A dynamic session with the filter engine. Closing it deletes what it added.
pub(super) struct Engine {
    handle: HANDLE,
}

impl Engine {
    /// Opens a dynamic session.
    /// <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0>
    ///
    /// # Errors
    ///
    /// When the Base Filtering Engine cannot be reached.
    pub(super) fn open() -> Result<Self, String> {
        let mut name = wide("netmetrics DNS block");
        let session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR::null(),
            },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..FWPM_SESSION0::default()
        };
        let mut handle = HANDLE::default();
        // SAFETY: the server name must be null, which it is. `session` and the name it
        // points to live past the call, and `handle` is a valid place for the result.
        let status = unsafe {
            FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                Some(&raw const session),
                &raw mut handle,
            )
        };
        check("FwpmEngineOpen0", status)?;
        Ok(Self { handle })
    }

    /// Adds a sublayer and `filters` to it, all or none, and returns the filters' ids.
    ///
    /// They are added in one transaction, so the blocks never apply without the permits.
    ///
    /// # Errors
    ///
    /// When any call fails. The transaction is aborted then, and nothing was added.
    pub(super) fn add(&self, filters: &[FilterSpec<'_>]) -> Result<Vec<u64>, String> {
        // SAFETY: `handle` is this session's open handle. Flags 0 begin a read/write
        // transaction.
        check("FwpmTransactionBegin0", unsafe {
            FwpmTransactionBegin0(self.handle, 0)
        })?;
        let added = self.add_all(filters).and_then(|ids| {
            // SAFETY: `handle` is open, and the transaction begun above is in progress.
            check("FwpmTransactionCommit0", unsafe {
                FwpmTransactionCommit0(self.handle)
            })?;
            Ok(ids)
        });
        if added.is_err() {
            // SAFETY: `handle` is open. Aborting when the transaction has already ended
            // only returns an error, which changes nothing here: the first one is reported.
            let _ = unsafe { FwpmTransactionAbort0(self.handle) };
        }
        added
    }

    fn add_all(&self, filters: &[FilterSpec<'_>]) -> Result<Vec<u64>, String> {
        let sublayer = GUID::new().map_err(|error| format!("no GUID for the sublayer: {error}"))?;
        self.add_sublayer(sublayer)?;
        filters
            .iter()
            .map(|filter| self.add_filter(sublayer, filter))
            .collect()
    }

    /// <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayeradd0>
    fn add_sublayer(&self, key: GUID) -> Result<(), String> {
        let mut name = wide("netmetrics DNS block");
        let mut description = wide("Refuses DNS that bypasses the local resolver");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR(description.as_mut_ptr()),
            },
            weight: SUBLAYER_WEIGHT,
            ..FWPM_SUBLAYER0::default()
        };
        // SAFETY: `handle` is open. `sublayer` and the strings it points to live past the
        // call, and a null security descriptor asks for the default one.
        let status = unsafe {
            FwpmSubLayerAdd0(
                self.handle,
                &raw const sublayer,
                PSECURITY_DESCRIPTOR::default(),
            )
        };
        check("FwpmSubLayerAdd0", status)
    }

    /// <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0>
    ///
    /// The conditions and their data types are those listed for the layer under
    /// <https://learn.microsoft.com/windows/win32/fwp/filtering-condition-identifiers->.
    /// Every condition is on a different field, so all of them must hold.
    fn add_filter(&self, sublayer: GUID, spec: &FilterSpec<'_>) -> Result<u64, String> {
        // The blob only points into `spec`, which WFP reads and does not write.
        let mut app = match spec.permitted_app {
            Some(id) => Some(FWP_BYTE_BLOB {
                size: u32::try_from(id.len())
                    .map_err(|_| "an application id is too long".to_owned())?,
                data: id.as_ptr().cast_mut(),
            }),
            None => None,
        };
        let mut conditions = vec![
            condition(
                FWPM_CONDITION_IP_PROTOCOL,
                FWP_MATCH_EQUAL,
                FWP_UINT8,
                FWP_CONDITION_VALUE0_0 {
                    uint8: spec.protocol,
                },
            ),
            condition(
                FWPM_CONDITION_IP_REMOTE_PORT,
                FWP_MATCH_EQUAL,
                FWP_UINT16,
                FWP_CONDITION_VALUE0_0 { uint16: spec.port },
            ),
        ];
        conditions.push(match &mut app {
            Some(app) => condition(
                FWPM_CONDITION_ALE_APP_ID,
                FWP_MATCH_EQUAL,
                FWP_BYTE_BLOB_TYPE,
                FWP_CONDITION_VALUE0_0 {
                    byteBlob: ptr::from_mut(app),
                },
            ),
            // The block leaves loopback alone: that is where the resolver listens.
            None => condition(
                FWPM_CONDITION_FLAGS,
                FWP_MATCH_FLAGS_NONE_SET,
                FWP_UINT32,
                FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            ),
        });
        let (mut name, action, weight) = if spec.permitted_app.is_some() {
            (
                wide("netmetrics: DNS from an exempt program"),
                FWP_ACTION_PERMIT,
                PERMIT_WEIGHT_RANGE,
            )
        } else {
            (
                wide("netmetrics: DNS that bypasses the resolver"),
                FWP_ACTION_BLOCK,
                BLOCK_WEIGHT_RANGE,
            )
        };
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_mut_ptr()),
                description: PWSTR::null(),
            },
            layerKey: match spec.family {
                Family::V4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                Family::V6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            },
            subLayerKey: sublayer,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: weight },
            },
            numFilterConditions: u32::try_from(conditions.len())
                .map_err(|_| "too many filter conditions".to_owned())?,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: action,
                Anonymous: FWPM_ACTION0_0::default(),
            },
            ..FWPM_FILTER0::default()
        };
        let mut id = 0_u64;
        // SAFETY: `handle` is open. `filter` points to `name`, `conditions` and, through
        // them, `app` and the id bytes in `spec`, which all live past the call; WFP copies
        // what it needs before returning. A null security descriptor asks for the default
        // one, and `id` is a valid place for the result.
        let status = unsafe {
            FwpmFilterAdd0(
                self.handle,
                &raw const filter,
                PSECURITY_DESCRIPTOR::default(),
                Some(&raw mut id),
            )
        };
        check("FwpmFilterAdd0", status)?;
        Ok(id)
    }

    /// Whether the filter `id`, which [`add`](Self::add) returned, is still there.
    /// <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbyid0>
    ///
    /// # Errors
    ///
    /// When it is gone, or the engine cannot say, as after it restarted.
    pub(super) fn filter_is_there(&self, id: u64) -> Result<(), String> {
        let mut filter: *mut FWPM_FILTER0 = ptr::null_mut();
        // SAFETY: `handle` is this session's handle, and `filter` is a valid place for the
        // pointer the function returns.
        let status = unsafe { FwpmFilterGetById0(self.handle, id, &raw mut filter) };
        check("FwpmFilterGetById0", status)?;
        if !filter.is_null() {
            // SAFETY: the call succeeded, so `filter` is WFP's allocation, which its
            // documentation says to free with `FwpmFreeMemory0`. Nothing else frees it.
            unsafe { free(filter.cast()) };
        }
        Ok(())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: `handle` came from `FwpmEngineOpen0` and is closed only here. Closing
        // ends the dynamic session, which deletes its sublayer and filters.
        let _ = unsafe { FwpmEngineClose0(self.handle) };
    }
}

fn condition(
    field: GUID,
    match_type: FWP_MATCH_TYPE,
    data_type: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: match_type,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: data_type,
            Anonymous: value,
        },
    }
}
