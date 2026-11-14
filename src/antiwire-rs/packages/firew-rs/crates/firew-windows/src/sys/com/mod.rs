//! `INetFw` COM FFI. Call only from the dedicated `INetFw` worker thread.

use std::collections::HashMap;

use firew_core::{cartesian_exceeds_limits, Direction, Error, ErrorKind, Rule, RuleKey};
use firew_sys::{ManagedMarker, ManagedNamespace};
use windows::core::{Interface, BSTR, HRESULT};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, E_ACCESSDENIED, E_INVALIDARG,
};
use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwPolicy2, INetFwRule, INetFwRules};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IDispatch, CLSCTX_INPROC_SERVER,
    COINIT_MULTITHREADED,
};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::VARIANT;

use crate::naming::native_display_name;

mod decode;
mod encode;
#[cfg(test)]
mod tests;

use decode::decode_rule;

const SET_MODE_TOKEN: &str = "[set]";

struct ComApartment;

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: `ComApartment` is created only after successful initialization
        // on this worker thread and is dropped on that same thread.
        unsafe { CoUninitialize() };
    }
}

/// COM session owning the `INetFw` rules collection.
pub(crate) struct ComInetFwSession {
    rules: INetFwRules,
    _apartment: ComApartment,
}

/// Managed rows recovered from native state, plus rows that drifted.
pub(crate) struct EnumeratedRules {
    pub(crate) rows: Vec<InetFwNativeRow>,
    /// Names of rules in our group whose ownership marker or attributes drifted.
    pub(crate) drifted: Vec<String>,
    /// Native rule names of drifted rows whose logical key is still known from their marker.
    pub(crate) drifted_by_key: HashMap<RuleKey, Vec<String>>,
}

pub(crate) struct InetFwNativeRow {
    pub(crate) marker: ManagedMarker,
    pub(crate) name: String,
    pub(crate) rule: Rule,
}

impl ComInetFwSession {
    /// Initializes COM and opens the `INetFw` rules collection.
    ///
    /// # Safety
    ///
    /// Must be called once on the `INetFw` worker thread before any other COM API in this module.
    pub(crate) fn open() -> Result<Self, Error> {
        // SAFETY: all COM values remain confined to the dedicated worker thread,
        // and `ComApartment` balances successful initialization on that thread.
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .map_err(|source| {
                    Error::new(
                        ErrorKind::BackendUnavailable,
                        "failed to initialize the COM apartment",
                    )
                    .with_source(source)
                })?;
            let apartment = ComApartment;
            let policy: INetFwPolicy2 = CoCreateInstance(
                &windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2,
                None,
                CLSCTX_INPROC_SERVER,
            )
            .map_err(|e| {
                Error::new(
                    ErrorKind::BackendUnavailable,
                    format!("CoCreateInstance: {e}"),
                )
            })?;
            let rules = policy
                .Rules()
                .map_err(|e| Error::new(ErrorKind::BackendUnavailable, format!("Rules(): {e}")))?;
            Ok(Self {
                rules,
                _apartment: apartment,
            })
        }
    }

    /// Updates an existing owned rule in place when present in our group, or adds a new one.
    pub(crate) fn upsert_rule(
        &self,
        rule: &Rule,
        direction: Direction,
        native_name: &str,
        marker: &str,
        native_group: &str,
    ) -> Result<(), Error> {
        let bstr_name = BSTR::from(native_name);
        let expected_group = BSTR::from(native_group);
        // SAFETY: `self.rules` is a valid COM interface confined to this worker thread.
        unsafe {
            if let Ok(existing) = self.rules.Item(&bstr_name) {
                if existing.Grouping().ok().as_ref() == Some(&expected_group) {
                    return Self::apply_rule_properties(
                        &existing,
                        rule,
                        direction,
                        native_name,
                        marker,
                        native_group,
                    );
                }
            }
        }
        let fw_rule = Self::build_rule(rule, direction, native_name, marker, native_group)?;
        self.add_rule(&fw_rule, rule.logical_key())
    }

    /// Adds a rule to the native rules collection.
    pub(crate) fn add_rule(
        &self,
        fw_rule: &INetFwRule,
        logical_key: &RuleKey,
    ) -> Result<(), Error> {
        // SAFETY: `fw_rule` and the rules collection are valid COM interfaces
        // confined to the initialized worker apartment.
        unsafe {
            self.rules
                .Add(fw_rule)
                .map_err(|e| map_com_mutation_err(&e, "Rules.Add", logical_key))?;
        }
        Ok(())
    }

    /// Removes a rule by its display name after verifying that it belongs to `expected_group`.
    pub(crate) fn remove_rule(
        &self,
        display_name: &str,
        expected_group: &str,
        logical_key: &RuleKey,
    ) -> Result<(), Error> {
        let bstr_name = BSTR::from(display_name);
        let bstr_group = BSTR::from(expected_group);
        // SAFETY: the rules collection is a valid COM interface confined to the
        // initialized worker apartment and the BSTRs live for the call.
        unsafe {
            match self.rules.Item(&bstr_name) {
                Err(e) if e.code() == ERROR_FILE_NOT_FOUND.to_hresult() => return Ok(()),
                Err(_) => {
                    // `Item(name)` may not resolve duplicate or legacy names directly;
                    // verify ownership via the enumerator before calling `Remove(name)`.
                    if !self.has_rule_in_group(display_name, &bstr_group)? {
                        return Ok(());
                    }
                }
                Ok(existing) => {
                    let group = existing
                        .Grouping()
                        .map_err(|e| map_com_mutation_err(&e, "Rule.Grouping", logical_key))?;
                    if group != bstr_group {
                        // Never delete a rule belonging to another namespace/group.
                        return Ok(());
                    }
                }
            }
            match self.rules.Remove(&bstr_name) {
                Err(e) if e.code() == ERROR_FILE_NOT_FOUND.to_hresult() => Ok(()),
                result => result.map_err(|e| map_com_mutation_err(&e, "Rules.Remove", logical_key)),
            }
        }
    }

    /// Removes a rule whose group ownership was already verified during enumeration.
    pub(crate) fn remove_verified_rule(
        &self,
        display_name: &str,
        logical_key: &RuleKey,
    ) -> Result<(), Error> {
        let bstr_name = BSTR::from(display_name);
        // SAFETY: the rules collection is a valid COM interface confined to the
        // initialized worker apartment and the BSTR lives for the call.
        unsafe {
            match self.rules.Remove(&bstr_name) {
                Err(e) if e.code() == ERROR_FILE_NOT_FOUND.to_hresult() => Ok(()),
                result => result.map_err(|e| map_com_mutation_err(&e, "Rules.Remove", logical_key)),
            }
        }
    }

    fn has_rule_in_group(&self, display_name: &str, expected_group: &BSTR) -> Result<bool, Error> {
        // SAFETY: COM is initialized on this worker thread and all COM objects stay confined here.
        unsafe {
            let unknown = self.rules._NewEnum().map_err(com_enumeration_error)?;
            let enumerator: IEnumVARIANT = unknown.cast().map_err(com_enumeration_error)?;
            let expected_name = BSTR::from(display_name);
            loop {
                let mut values = [VARIANT::default()];
                let mut fetched = 0u32;
                enumerator
                    .Next(&mut values, &raw mut fetched)
                    .ok()
                    .map_err(com_enumeration_error)?;
                if fetched == 0 {
                    return Ok(false);
                }
                let dispatch = IDispatch::try_from(&values[0]).map_err(com_enumeration_error)?;
                let native: INetFwRule = dispatch.cast().map_err(com_enumeration_error)?;
                if native.Grouping().map_err(com_enumeration_error)? == *expected_group
                    && native.Name().map_err(com_enumeration_error)? == expected_name
                {
                    return Ok(true);
                }
            }
        }
    }

    pub(crate) fn enumerate(
        &self,
        namespace: &ManagedNamespace,
        native_group: &str,
    ) -> Result<EnumeratedRules, Error> {
        // SAFETY: COM is initialized for this worker thread; all returned
        // interfaces and variants remain thread-confined and `VARIANT` clears itself.
        unsafe {
            let unknown = self.rules._NewEnum().map_err(com_enumeration_error)?;
            let enumerator: IEnumVARIANT = unknown.cast().map_err(com_enumeration_error)?;
            let expected_group = BSTR::from(native_group);
            let mut rows = Vec::new();
            let mut drifted = Vec::new();
            let mut drifted_by_key: HashMap<RuleKey, Vec<String>> = HashMap::new();
            loop {
                let mut values = [VARIANT::default()];
                let mut fetched = 0u32;
                enumerator
                    .Next(&mut values, &raw mut fetched)
                    .ok()
                    .map_err(com_enumeration_error)?;
                if fetched == 0 {
                    break;
                }
                let dispatch = IDispatch::try_from(&values[0]).map_err(com_enumeration_error)?;
                let native: INetFwRule = dispatch.cast().map_err(com_enumeration_error)?;
                if native.Grouping().map_err(com_enumeration_error)? != expected_group {
                    continue;
                }
                let mut name = native.Name().map_err(com_enumeration_error)?.to_string();
                let description = native
                    .Description()
                    .map_err(com_enumeration_error)?
                    .to_string();

                let Ok(marker) = ManagedMarker::parse(&description, namespace)
                    .or_else(|_| ManagedMarker::parse(&name, namespace))
                else {
                    drifted.push(name);
                    continue;
                };

                // Deliberately migrate legacy names in place while holding the
                // group-verified COM object so future removals never use bare names.
                let canonical_name =
                    native_display_name(namespace, &marker.key, marker.part, marker.total);
                if name != canonical_name
                    && native.SetName(&BSTR::from(canonical_name.as_str())).is_ok()
                {
                    name = canonical_name;
                }

                let Ok(rule) = decode_rule(&native, &description, &marker.key) else {
                    drifted_by_key
                        .entry(marker.key)
                        .or_default()
                        .push(name.clone());
                    drifted.push(name);
                    continue;
                };
                rows.push(InetFwNativeRow { marker, name, rule });
            }
            Ok(EnumeratedRules {
                rows,
                drifted,
                drifted_by_key,
            })
        }
    }
}

const HRESULT_RPC_S_INVALID_BOUND: HRESULT = HRESULT(0x8007_06C6_u32.cast_signed());

fn map_com_mutation_err(err: &windows_core::Error, op: &str, logical_key: &RuleKey) -> Error {
    let code = err.code();
    let kind = if code == E_ACCESSDENIED || code == ERROR_ACCESS_DENIED.to_hresult() {
        ErrorKind::PermissionDenied
    } else if code == HRESULT_RPC_S_INVALID_BOUND {
        ErrorKind::LimitExceeded
    } else if code == E_INVALIDARG {
        ErrorKind::InvalidRule
    } else {
        ErrorKind::Internal
    };
    Error::new(kind, format!("{op}: {err}"))
        .with_logical_key(logical_key)
        .with_source(err.clone())
}

pub(crate) fn description_has_set_token(description: &str) -> bool {
    description.split_whitespace().nth(1) == Some(SET_MODE_TOKEN)
}

pub(crate) fn needs_set_mode(
    explicit_set: bool,
    direction: Direction,
    remote_len: usize,
    local_len: usize,
    remote_ports_len: usize,
    local_ports_len: usize,
) -> bool {
    remote_len != 0
        && (explicit_set
            || cartesian_exceeds_limits(
                direction,
                remote_len,
                local_len,
                remote_ports_len,
                local_ports_len,
            ))
}

fn com_enumeration_error(source: windows_core::Error) -> Error {
    Error::new(
        ErrorKind::CorruptNativeState,
        "failed to enumerate or decode managed INetFw state",
    )
    .with_source(source)
}
