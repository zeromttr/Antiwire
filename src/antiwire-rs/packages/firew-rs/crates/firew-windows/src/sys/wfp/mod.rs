//! WFP FFI. Call only from the dedicated WFP worker thread.

use data_encoding::BASE32_NOPAD;
use firew_core::{Direction, Error, ErrorKind, Protocol, Rule};
use firew_sys::{BackendConfig, PartMarkers};
use ipnet::IpNet;
use sha2::{Digest, Sha256};
use windows::core::HSTRING;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0,
    FwpmFilterDeleteByKey0, FwpmProviderAdd0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_ACTION0_0,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER0_0, FWPM_FILTER_FLAGS,
    FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_PROVIDER0,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SESSION0, FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT,
    FWP_BYTE_BLOB,
};

mod conditions;
mod listing;
#[cfg(test)]
mod tests;

use conditions::{
    empty_weight, expected_conditions, map_filter_action, AppIdBlob, FilterShape, PinnedConditions,
};

fn pwstr(h: &HSTRING) -> windows_core::PWSTR {
    windows_core::PWSTR(h.as_ptr().cast_mut())
}

const ERROR_SUCCESS: u32 = 0;
const ERROR_ACCESS_DENIED: u32 = 5;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
const FWP_E_OBJECT_EXISTS: u32 = 0x8032_0009;
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_000A;
const FWP_E_ACCESS_DENIED: u32 = 0x8032_0022;
const FWPM_SESSION_FLAG_DYNAMIC_VALUE: u32 = 0x0000_0001;

/// Returns the IPv6 layer booleans to use when `remote_addresses` is empty.
pub(crate) fn layers_for_empty_remote(protocol: Protocol) -> &'static [bool] {
    match protocol {
        Protocol::IcmpV4 => &[false],
        Protocol::IcmpV6 => &[true],
        _ => &[false, true],
    }
}

/// Open WFP engine handle with managed provider and sublayer.
pub(crate) struct WfpEngine {
    handle: HANDLE,
    provider_key: windows_core::GUID,
    sublayer_key: windows_core::GUID,
}

impl WfpEngine {
    /// Opens a WFP engine session and registers managed objects.
    ///
    /// # Safety
    ///
    /// Must be called once on the WFP worker thread before any other WFP API in this module.
    pub(crate) fn open(config: &BackendConfig) -> Result<Self, Error> {
        // SAFETY: all pointers refer to initialized stack values for the duration
        // of the call, and the returned handle is closed by `Drop`.
        unsafe {
            let session = FWPM_SESSION0 {
                flags: if config.memory_mode {
                    FWPM_SESSION_FLAG_DYNAMIC_VALUE
                } else {
                    0
                },
                ..FWPM_SESSION0::default()
            };
            let mut engine_handle = HANDLE::default();
            let status = FwpmEngineOpen0(
                None,
                10,
                None,
                Some(&raw const session),
                &raw mut engine_handle,
            );
            if status != ERROR_SUCCESS {
                let kind = if is_access_denied(status) {
                    ErrorKind::PermissionDenied
                } else {
                    ErrorKind::BackendUnavailable
                };
                return Err(Error::new(
                    kind,
                    format!("FwpmEngineOpen0 status {status:#x}"),
                ));
            }

            let namespace = config.managed_namespace();
            let provider_key = guid_from_seed(&format!("firew-rs-provider:{}", namespace.as_str()));
            let sublayer_key = guid_from_seed(&format!("firew-rs-sublayer:{}", namespace.as_str()));

            let engine = Self {
                handle: engine_handle,
                provider_key,
                sublayer_key,
            };
            engine.ensure_provider(config)?;
            engine.ensure_sublayer(config)?;
            Ok(engine)
        }
    }

    pub(crate) fn add_filters_for_rule(
        &self,
        config: &BackendConfig,
        rule: &Rule,
    ) -> Result<Vec<u64>, Error> {
        if rule.package_sid().is_some() {
            return Err(Error::new(
                ErrorKind::UnsupportedMatcher,
                "package SID rules are not supported on WFP backend",
            )
            .with_logical_key(rule.logical_key()));
        }

        let app_id = AppIdBlob::from_rule(rule)?;
        let encoded_rule = encode_rule_payload(rule)?;
        let slots = filter_slots(rule);
        let namespace = config.managed_namespace();
        let mut markers = PartMarkers::new("WFP", rule.logical_key(), &namespace, slots.len())?;
        let mut ids = Vec::with_capacity(slots.len());
        let result = slots.iter().try_for_each(|slot| {
            let marker = markers.encode_next()?;
            ids.push(self.add_filter(
                config,
                rule,
                &encoded_rule,
                app_id.as_ptr(),
                slot,
                &marker,
            )?);
            Ok::<(), Error>(())
        });

        if let Err(error) = result {
            for id in &ids {
                let _ = self.delete_filter_by_id(*id);
            }
            return Err(error);
        }

        Ok(ids)
    }

    pub(crate) fn delete_filter_by_id(&self, filter_id: u64) -> Result<(), Error> {
        // SAFETY: `self.handle` is an open engine handle and `filter_id` was
        // returned by WFP for that engine.
        unsafe {
            let status = FwpmFilterDeleteById0(self.handle, filter_id);
            if status == FWP_E_FILTER_NOT_FOUND {
                return Ok(());
            }
            check_status(status, "FwpmFilterDeleteById0")?;
        }
        Ok(())
    }

    pub(crate) fn transaction_begin(&self) -> Result<(), Error> {
        // SAFETY: `self.handle` is an open WFP engine handle owned by this object.
        unsafe {
            let status = FwpmTransactionBegin0(self.handle, 0);
            check_status(status, "FwpmTransactionBegin0")?;
        }
        Ok(())
    }

    pub(crate) fn transaction_commit(&self) -> Result<(), Error> {
        // SAFETY: `self.handle` has an active transaction started by this engine.
        unsafe {
            let status = FwpmTransactionCommit0(self.handle);
            check_status(status, "FwpmTransactionCommit0")?;
        }
        Ok(())
    }

    pub(crate) fn transaction_abort(&self) -> Result<(), Error> {
        // SAFETY: `self.handle` is an open engine handle; abort status is checked
        // so the caller never reports a rollback that failed natively.
        unsafe {
            let status = FwpmTransactionAbort0(self.handle);
            if status == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::RollbackFailed,
                    format!("WFP FwpmTransactionAbort0 failed with status {status:#x}"),
                ))
            }
        }
    }

    fn ensure_provider(&self, config: &BackendConfig) -> Result<(), Error> {
        let display = HSTRING::from(format!("firew-rs ({})", config.name_prefix));
        let description = HSTRING::from("firew-rs managed WFP provider");
        let provider = FWPM_PROVIDER0 {
            providerKey: self.provider_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: pwstr(&display),
                description: pwstr(&description),
            },
            flags: if config.memory_mode {
                0
            } else {
                FWPM_PROVIDER_FLAG_PERSISTENT
            },
            ..FWPM_PROVIDER0::default()
        };
        // SAFETY: all pointer fields reference live stack values and HSTRING
        // buffers for the duration of `FwpmProviderAdd0`.
        unsafe {
            let status = FwpmProviderAdd0(self.handle, &raw const provider, None);
            if status == ERROR_SUCCESS || status_is_exists(status) {
                Ok(())
            } else {
                check_status(status, "FwpmProviderAdd0")
            }
        }
    }

    fn ensure_sublayer(&self, config: &BackendConfig) -> Result<(), Error> {
        let display = HSTRING::from(format!("firew-rs ({})", config.name_prefix));
        let description = HSTRING::from("firew-rs managed WFP sublayer");
        let mut provider_key = self.provider_key;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: self.sublayer_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: pwstr(&display),
                description: pwstr(&description),
            },
            flags: if config.memory_mode {
                0
            } else {
                FWPM_SUBLAYER_FLAG_PERSISTENT
            },
            providerKey: &raw mut provider_key,
            weight: 0x8000,
            ..FWPM_SUBLAYER0::default()
        };
        // SAFETY: all pointer fields reference live stack values and HSTRING
        // buffers for the duration of `FwpmSubLayerAdd0`.
        unsafe {
            let status = FwpmSubLayerAdd0(self.handle, &raw const sublayer, None);
            if status == ERROR_SUCCESS || status_is_exists(status) {
                Ok(())
            } else {
                check_status(status, "FwpmSubLayerAdd0")
            }
        }
    }

    fn add_filter(
        &self,
        config: &BackendConfig,
        rule: &Rule,
        encoded_rule: &str,
        app_id: *mut FWP_BYTE_BLOB,
        slot: &FilterSlot<'_>,
        marker: &str,
    ) -> Result<u64, Error> {
        let wfp_dir = slot.direction;
        let layer = slot.layer();
        let display_name = HSTRING::from(format!("{marker} {encoded_rule}"));
        let description = HSTRING::from(
            rule.label()
                .map_or_else(|| format!("firew-rs {wfp_dir:?}"), ToOwned::to_owned),
        );
        let filter_key = guid_from_seed(&format!(
            "firew-rs-filter:{}:{:?}:{}:{}:{}",
            marker, wfp_dir, slot.net_idx, slot.layer_idx, slot.is_v6
        ));

        let mut pinned = PinnedConditions::default();
        let conditions = pinned.build_for_rule(rule, slot.remote, slot.is_v6, app_id);

        let action_type = map_filter_action(rule.action());
        let mut provider_key = self.provider_key;
        let filter = FWPM_FILTER0 {
            filterKey: filter_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: pwstr(&display_name),
                description: pwstr(&description),
            },
            flags: if config.memory_mode {
                FWPM_FILTER_FLAGS(0)
            } else {
                FWPM_FILTER_FLAG_PERSISTENT
            },
            providerKey: &raw mut provider_key,
            layerKey: layer,
            subLayerKey: self.sublayer_key,
            weight: empty_weight(),
            numFilterConditions: u32::try_from(conditions.len())
                .map_err(|_| Error::new(ErrorKind::Internal, "too many WFP filter conditions"))?,
            filterCondition: conditions.as_ptr().cast_mut(),
            action: FWPM_ACTION0 {
                r#type: action_type,
                Anonymous: FWPM_ACTION0_0::default(),
            },
            Anonymous: FWPM_FILTER0_0::default(),
            ..FWPM_FILTER0::default()
        };

        let mut filter_id = 0u64;
        // SAFETY: the filter and condition pointers remain valid through the call;
        // WFP copies their contents before returning.
        unsafe {
            let mut status = FwpmFilterAdd0(
                self.handle,
                &raw const filter,
                None,
                Some(&raw mut filter_id),
            );
            if status_is_exists(status) {
                let _ = FwpmFilterDeleteByKey0(self.handle, &raw const filter_key);
                status = FwpmFilterAdd0(
                    self.handle,
                    &raw const filter,
                    None,
                    Some(&raw mut filter_id),
                );
            }
            check_status(status, "FwpmFilterAdd0")?;
        }
        Ok(filter_id)
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: this object uniquely owns the open engine handle and closes
            // it exactly once during destruction.
            unsafe {
                let _ = FwpmEngineClose0(self.handle);
            }
        }
    }
}

/// The shape [`WfpEngine::add_filters_for_rule`] gives `rule`'s filter number
/// `part`, or `None` when the rule has no such filter.
///
/// `app_id` is the application's id, used when the rule names one.
fn expected_filter_shape(rule: &Rule, part: usize, app_id: Vec<u8>) -> Option<FilterShape> {
    let slot = *filter_slots(rule).get(part)?;
    let app_id = rule.application_path().map(|_| app_id);
    Some(FilterShape::new(
        slot.layer(),
        map_filter_action(rule.action()),
        expected_conditions(rule, slot.remote, slot.is_v6, app_id),
    ))
}

fn encode_rule_payload(rule: &Rule) -> Result<String, Error> {
    let json = serde_json::to_vec(rule).map_err(|source| {
        Error::new(ErrorKind::Internal, "failed to serialize WFP rule metadata")
            .with_logical_key(rule.logical_key())
            .with_source(source)
    })?;
    Ok(BASE32_NOPAD.encode(&json))
}

#[derive(Debug, Clone, Copy)]
enum WfpDirection {
    Outbound,
    Inbound,
}

/// One native filter of a rule: its direction, remote address (or none, for
/// an address-less rule's per-family filter), and family, plus the indices its
/// filter key is derived from.
#[derive(Clone, Copy)]
struct FilterSlot<'a> {
    direction: WfpDirection,
    remote: Option<&'a IpNet>,
    net_idx: usize,
    layer_idx: usize,
    is_v6: bool,
}

impl FilterSlot<'_> {
    fn layer(&self) -> windows_core::GUID {
        layer_for_direction(self.direction, self.is_v6)
    }
}

/// Every filter `rule` installs, in part order: per direction, one filter per
/// remote address, or one per address family when there are none.
fn filter_slots(rule: &Rule) -> Vec<FilterSlot<'_>> {
    let mut slots = Vec::new();
    for &direction in wfp_directions(rule.direction()) {
        if rule.remote_addresses().is_empty() {
            for (layer_idx, &is_v6) in layers_for_empty_remote(rule.protocol()).iter().enumerate() {
                slots.push(FilterSlot {
                    direction,
                    remote: None,
                    net_idx: 0,
                    layer_idx,
                    is_v6,
                });
            }
        } else {
            for (net_idx, remote) in rule.remote_addresses().iter().enumerate() {
                slots.push(FilterSlot {
                    direction,
                    remote: Some(remote),
                    net_idx,
                    layer_idx: 0,
                    is_v6: remote.addr().is_ipv6(),
                });
            }
        }
    }
    slots
}

fn wfp_directions(direction: Direction) -> &'static [WfpDirection] {
    match direction {
        Direction::Outbound => &[WfpDirection::Outbound],
        Direction::Inbound => &[WfpDirection::Inbound],
        Direction::Both => &[WfpDirection::Outbound, WfpDirection::Inbound],
    }
}

fn layer_for_direction(wfp_dir: WfpDirection, is_v6: bool) -> windows_core::GUID {
    match (wfp_dir, is_v6) {
        (WfpDirection::Outbound, false) => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        (WfpDirection::Outbound, true) => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        (WfpDirection::Inbound, false) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        (WfpDirection::Inbound, true) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

fn guid_from_seed(seed: &str) -> windows_core::GUID {
    let digest = Sha256::digest(seed.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    windows_core::GUID::from_u128(u128::from_be_bytes(bytes))
}

fn status_is_exists(status: u32) -> bool {
    status == FWP_E_OBJECT_EXISTS || status == FWP_E_ALREADY_EXISTS
}

fn is_access_denied(status: u32) -> bool {
    status == ERROR_ACCESS_DENIED || status == FWP_E_ACCESS_DENIED
}

fn check_status(status: u32, op: &str) -> Result<(), Error> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else if is_access_denied(status) {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("WFP {op} failed with access denied ({status:#x})"),
        ))
    } else {
        Err(Error::new(
            ErrorKind::Internal,
            format!("WFP {op} failed with status {status:#x}"),
        ))
    }
}
