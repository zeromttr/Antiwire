//! Filter conditions and the native buffers they point into.

use std::net::IpAddr;
use std::ptr;

use firew_core::{Action, Error, ErrorKind, Rule};
use ipnet::IpNet;
use windows::core::HSTRING;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FWPM_CONDITION_ALE_APP_ID,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE,
    FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_DATA_TYPE, FWP_EMPTY, FWP_MATCH_EQUAL, FWP_MATCH_RANGE,
    FWP_MATCH_TYPE, FWP_RANGE0, FWP_RANGE_TYPE, FWP_UINT16, FWP_UINT32, FWP_UINT8,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0,
    FWP_VALUE0_0,
};

use super::ERROR_SUCCESS;

pub(super) struct AppIdBlob {
    blob: *mut FWP_BYTE_BLOB,
}

impl AppIdBlob {
    pub(super) fn from_rule(rule: &Rule) -> Result<Self, Error> {
        let Some(path) = rule.application_path() else {
            return Ok(Self {
                blob: ptr::null_mut(),
            });
        };
        Self::from_path(path).map_err(|status| {
            Error::new(
                ErrorKind::InvalidRule,
                format!("FwpmGetAppIdFromFileName0 status {status:#x}"),
            )
            .with_logical_key(rule.logical_key())
        })
    }

    /// The id WFP derives from `path`, or the failing status, such as when
    /// the file does not exist.
    pub(super) fn from_path(path: &std::path::Path) -> Result<Self, u32> {
        let path_h = HSTRING::from(path.as_os_str().to_string_lossy().as_ref());
        let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
        // SAFETY: COM-style WFP allocation receives a valid output pointer;
        // ownership is retained in `AppIdBlob` and freed once on drop.
        let status = unsafe { FwpmGetAppIdFromFileName0(&path_h, &raw mut blob) };
        if status == ERROR_SUCCESS {
            Ok(Self { blob })
        } else {
            Err(status)
        }
    }

    pub(super) fn as_ptr(&self) -> *mut FWP_BYTE_BLOB {
        self.blob
    }

    /// The id's bytes, empty when there is no id.
    pub(super) fn bytes(&self) -> Vec<u8> {
        // SAFETY: a non-null `blob` is WFP's allocation, alive until drop.
        unsafe { self.blob.as_ref().map(|blob| blob_bytes(blob)) }.unwrap_or_default()
    }
}

/// Copies out the bytes a blob points to.
///
/// # Safety
///
/// `blob.data` must be null or point to `blob.size` readable bytes.
unsafe fn blob_bytes(blob: &FWP_BYTE_BLOB) -> Vec<u8> {
    if blob.data.is_null() {
        Vec::new()
    } else {
        // SAFETY: guaranteed by the caller.
        unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) }.to_vec()
    }
}

impl Drop for AppIdBlob {
    fn drop(&mut self) {
        if !self.blob.is_null() {
            // SAFETY: `blob` came from `FwpmGetAppIdFromFileName0` and is freed
            // once through the matching WFP allocator.
            unsafe {
                let mut ptr = self.blob.cast::<core::ffi::c_void>();
                FwpmFreeMemory0(&raw mut ptr);
            }
            self.blob = ptr::null_mut();
        }
    }
}

#[derive(Default)]
pub(super) struct PinnedConditions {
    v4_mask: Option<Box<FWP_V4_ADDR_AND_MASK>>,
    v6_mask: Option<Box<FWP_V6_ADDR_AND_MASK>>,
    range: Option<Box<FWP_RANGE0>>,
}

impl PinnedConditions {
    pub(super) fn build_for_rule(
        &mut self,
        rule: &Rule,
        remote: Option<&IpNet>,
        is_v6: bool,
        app_id: *mut FWP_BYTE_BLOB,
    ) -> Vec<FWPM_FILTER_CONDITION0> {
        let mut conditions = Vec::with_capacity(4);

        if let Some(net) = remote {
            if is_v6 {
                if let IpAddr::V6(addr) = net.network() {
                    let mut v6 = Box::new(FWP_V6_ADDR_AND_MASK {
                        addr: addr.octets(),
                        prefixLength: net.prefix_len(),
                    });
                    let ptr = &raw mut *v6;
                    self.v6_mask = Some(v6);
                    conditions.push(condition(
                        FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        FWP_V6_ADDR_MASK,
                        FWP_CONDITION_VALUE0_0 { v6AddrMask: ptr },
                    ));
                }
            } else if let IpAddr::V4(addr) = net.network() {
                let mask = v4_mask(net.prefix_len());
                let mut v4 = Box::new(FWP_V4_ADDR_AND_MASK {
                    addr: u32::from_be_bytes(addr.octets()),
                    mask,
                });
                let ptr = &raw mut *v4;
                self.v4_mask = Some(v4);
                conditions.push(condition(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_V4_ADDR_MASK,
                    FWP_CONDITION_VALUE0_0 { v4AddrMask: ptr },
                ));
            }
        }

        if let Some(proto) = rule.protocol().number() {
            conditions.push(condition(
                FWPM_CONDITION_IP_PROTOCOL,
                FWP_UINT8,
                FWP_CONDITION_VALUE0_0 { uint8: proto },
            ));
        }

        if let Some(port) = rule.remote_ports().first() {
            if port.is_single() {
                conditions.push(condition(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 {
                        uint16: port.start(),
                    },
                ));
            } else {
                let mut range = Box::new(FWP_RANGE0 {
                    valueLow: FWP_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_VALUE0_0 {
                            uint16: port.start(),
                        },
                    },
                    valueHigh: FWP_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_VALUE0_0 { uint16: port.end() },
                    },
                });
                let ptr = &raw mut *range;
                self.range = Some(range);
                conditions.push(condition(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_RANGE_TYPE,
                    FWP_CONDITION_VALUE0_0 { rangeValue: ptr },
                ));
            }
        }

        if !app_id.is_null() {
            conditions.push(condition(
                FWPM_CONDITION_ALE_APP_ID,
                FWP_BYTE_BLOB_TYPE,
                FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
            ));
        }

        conditions
    }
}

pub(super) fn condition(
    field_key: windows_core::GUID,
    value_type: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: match_type_for(value_type),
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: value_type,
            Anonymous: value,
        },
    }
}

/// WFP accepts a range value only with `FWP_MATCH_RANGE`; every other value
/// this backend builds, including address masks, is an equality match.
pub(super) fn match_type_for(value_type: FWP_DATA_TYPE) -> FWP_MATCH_TYPE {
    if value_type == FWP_RANGE_TYPE {
        FWP_MATCH_RANGE
    } else {
        FWP_MATCH_EQUAL
    }
}

pub(super) fn map_filter_action(action: Action) -> FWP_ACTION_TYPE {
    match action {
        Action::Allow => FWP_ACTION_PERMIT,
        Action::Block | Action::Reject => FWP_ACTION_BLOCK,
    }
}

fn v4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        0xffff_ffff
    } else {
        (!0u32) << (32 - prefix_len)
    }
}

/// A filter condition as WFP lists it, reduced to the kinds this backend writes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ListedCondition {
    RemoteV4 {
        addr: u32,
        mask: u32,
    },
    RemoteV6 {
        addr: [u8; 16],
        prefix: u8,
    },
    Protocol(u8),
    RemotePort(u16),
    RemotePortRange(u16, u16),
    AppId(Vec<u8>),
    /// A field, match type, or value this backend never writes.
    Foreign,
}

/// What one filter enforces: its layer, its action, and its conditions in a
/// fixed order. The rule encoded in a filter's name is only a claim; this is
/// what WFP actually applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FilterShape {
    pub(super) layer: windows_core::GUID,
    pub(super) action: FWP_ACTION_TYPE,
    pub(super) conditions: Vec<ListedCondition>,
}

impl FilterShape {
    pub(super) fn new(
        layer: windows_core::GUID,
        action: FWP_ACTION_TYPE,
        mut conditions: Vec<ListedCondition>,
    ) -> Self {
        conditions.sort();
        Self {
            layer,
            action,
            conditions,
        }
    }

    /// Reads the shape of a filter WFP listed.
    ///
    /// # Safety
    ///
    /// `filter` must come from `FwpmFilterEnum0`, with its condition array and
    /// every pointer inside it still valid.
    pub(super) unsafe fn of_listed(filter: &FWPM_FILTER0) -> Self {
        let count = filter.numFilterConditions as usize;
        let conditions = if filter.filterCondition.is_null() || count == 0 {
            Vec::new()
        } else {
            // SAFETY: WFP lists `numFilterConditions` conditions at `filterCondition`.
            unsafe { std::slice::from_raw_parts(filter.filterCondition, count) }
                .iter()
                // SAFETY: each condition's pointers belong to the same listing.
                .map(|condition| unsafe { listed_condition(condition) })
                .collect()
        };
        Self::new(filter.layerKey, filter.action.r#type, conditions)
    }

    /// Drops the bytes of app-id conditions, for when the expected id cannot
    /// be computed because the application no longer exists at its path.
    pub(super) fn without_app_id_bytes(mut self) -> Self {
        for condition in &mut self.conditions {
            if let ListedCondition::AppId(bytes) = condition {
                bytes.clear();
            }
        }
        self.conditions.sort();
        self
    }
}

/// # Safety
///
/// `condition` must come from a live `FwpmFilterEnum0` listing.
unsafe fn listed_condition(condition: &FWPM_FILTER_CONDITION0) -> ListedCondition {
    let value = &condition.conditionValue;
    let field = condition.fieldKey;
    let equal = condition.matchType == FWP_MATCH_EQUAL;
    // SAFETY: the union member read is the one `value.r#type` names, and its
    // pointer is checked for null before it is dereferenced.
    unsafe {
        if field == FWPM_CONDITION_IP_REMOTE_ADDRESS && equal {
            if value.r#type == FWP_V4_ADDR_MASK && !value.Anonymous.v4AddrMask.is_null() {
                let mask = &*value.Anonymous.v4AddrMask;
                return ListedCondition::RemoteV4 {
                    addr: mask.addr,
                    mask: mask.mask,
                };
            }
            if value.r#type == FWP_UINT32 {
                return ListedCondition::RemoteV4 {
                    addr: value.Anonymous.uint32,
                    mask: u32::MAX,
                };
            }
            if value.r#type == FWP_V6_ADDR_MASK && !value.Anonymous.v6AddrMask.is_null() {
                let mask = &*value.Anonymous.v6AddrMask;
                return ListedCondition::RemoteV6 {
                    addr: mask.addr,
                    prefix: mask.prefixLength,
                };
            }
            if value.r#type == FWP_BYTE_ARRAY16_TYPE && !value.Anonymous.byteArray16.is_null() {
                return ListedCondition::RemoteV6 {
                    addr: (*value.Anonymous.byteArray16).byteArray16,
                    prefix: 128,
                };
            }
        }
        if field == FWPM_CONDITION_IP_PROTOCOL && equal && value.r#type == FWP_UINT8 {
            return ListedCondition::Protocol(value.Anonymous.uint8);
        }
        if field == FWPM_CONDITION_IP_REMOTE_PORT {
            if equal && value.r#type == FWP_UINT16 {
                return ListedCondition::RemotePort(value.Anonymous.uint16);
            }
            if condition.matchType == FWP_MATCH_RANGE
                && value.r#type == FWP_RANGE_TYPE
                && !value.Anonymous.rangeValue.is_null()
            {
                let range = &*value.Anonymous.rangeValue;
                if range.valueLow.r#type == FWP_UINT16 && range.valueHigh.r#type == FWP_UINT16 {
                    return ListedCondition::RemotePortRange(
                        range.valueLow.Anonymous.uint16,
                        range.valueHigh.Anonymous.uint16,
                    );
                }
            }
        }
        if field == FWPM_CONDITION_ALE_APP_ID
            && equal
            && value.r#type == FWP_BYTE_BLOB_TYPE
            && !value.Anonymous.byteBlob.is_null()
        {
            return ListedCondition::AppId(blob_bytes(&*value.Anonymous.byteBlob));
        }
    }
    ListedCondition::Foreign
}

/// The conditions [`PinnedConditions::build_for_rule`] writes for `rule` on
/// the filter matching `remote`, read back the way a listing reads them.
/// `app_id` is the application's id when the rule names one.
pub(super) fn expected_conditions(
    rule: &Rule,
    remote: Option<&IpNet>,
    is_v6: bool,
    app_id: Option<Vec<u8>>,
) -> Vec<ListedCondition> {
    let mut app_id = app_id;
    let mut blob = app_id.as_mut().map(|bytes| FWP_BYTE_BLOB {
        size: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        data: bytes.as_mut_ptr(),
    });
    let blob_ptr = blob.as_mut().map_or(ptr::null_mut(), ptr::from_mut);
    let mut pinned = PinnedConditions::default();
    let conditions = pinned.build_for_rule(rule, remote, is_v6, blob_ptr);
    conditions
        .iter()
        // SAFETY: every condition points into `pinned` or `app_id`, both alive.
        .map(|condition| unsafe { listed_condition(condition) })
        .collect()
}

/// The application id WFP derives from `path`, or `None` when it cannot,
/// such as when the file no longer exists.
pub(super) fn app_id_bytes(path: &std::path::Path) -> Option<Vec<u8>> {
    AppIdBlob::from_path(path).ok().map(|blob| blob.bytes())
}

pub(super) fn empty_weight() -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_EMPTY,
        Anonymous: FWP_VALUE0_0::default(),
    }
}
