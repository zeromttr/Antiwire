//! Enumerating this namespace's sublayer and grouping its filters into rules.

use std::collections::{BTreeMap, HashMap};
use std::ptr;

use data_encoding::BASE32_NOPAD;
use firew_core::{Error, ErrorKind, Rule, RuleKey};
use firew_sys::{ManagedMarker, ManagedNamespace};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FWPM_FILTER0,
};

use super::conditions::{app_id_bytes, FilterShape};
use super::{check_status, expected_filter_shape, WfpEngine, ERROR_SUCCESS};

pub(crate) struct EnumeratedWfpState {
    pub(crate) rules: HashMap<RuleKey, Rule>,
    pub(crate) filter_ids: HashMap<RuleKey, Vec<u64>>,
    pub(crate) orphan_ids: HashMap<RuleKey, Vec<u64>>,
    /// Filters in this namespace's sublayer whose names carry no marker. The
    /// sublayer is derived from the namespace, so they are still ours to clear.
    pub(crate) unkeyed_orphan_ids: Vec<u64>,
    pub(crate) drifted: Vec<String>,
}

impl WfpEngine {
    pub(crate) fn enumerate_managed(
        &self,
        namespace: &ManagedNamespace,
    ) -> Result<EnumeratedWfpState, Error> {
        Ok(group_filters(
            self.list_sublayer_filters()?,
            namespace,
            app_id_bytes,
        ))
    }

    /// Every filter in this namespace's sublayer, copied out of WFP's buffers.
    fn list_sublayer_filters(&self) -> Result<Vec<ListedFilter>, Error> {
        // SAFETY: `self.handle` is an open WFP engine handle on this worker thread,
        // `enum_handle` is destroyed before returning, and `entries` buffers are freed
        // with `FwpmFreeMemory0` after their filters are copied out.
        unsafe {
            let mut enum_handle = HANDLE::default();
            let status = FwpmFilterCreateEnumHandle0(self.handle, None, &raw mut enum_handle);
            check_status(status, "FwpmFilterCreateEnumHandle0")?;

            let mut listed = Vec::new();
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = ptr::null_mut();
                let mut num_entries = 0u32;
                let enum_status = FwpmFilterEnum0(
                    self.handle,
                    enum_handle,
                    256,
                    &raw mut entries,
                    &raw mut num_entries,
                );
                if enum_status != ERROR_SUCCESS {
                    let _ = FwpmFilterDestroyEnumHandle0(self.handle, enum_handle);
                    return Err(Error::new(
                        ErrorKind::CorruptNativeState,
                        format!("WFP FwpmFilterEnum0 failed with status {enum_status:#x}"),
                    ));
                }
                if num_entries == 0 || entries.is_null() {
                    if !entries.is_null() {
                        let mut mem = entries.cast::<core::ffi::c_void>();
                        FwpmFreeMemory0(&raw mut mem);
                    }
                    break;
                }

                let slice = std::slice::from_raw_parts(entries, num_entries as usize);
                for &filter_ptr in slice {
                    if filter_ptr.is_null() {
                        continue;
                    }
                    let filter = &*filter_ptr;
                    if filter.subLayerKey != self.sublayer_key {
                        continue;
                    }
                    let name = if filter.displayData.name.is_null() {
                        String::new()
                    } else {
                        filter.displayData.name.to_string().unwrap_or_default()
                    };
                    listed.push(ListedFilter {
                        filter_id: filter.filterId,
                        rule: decode_wfp_filter(&name),
                        // SAFETY: `filter` and its conditions belong to this
                        // listing, freed only after the loop.
                        shape: FilterShape::of_listed(filter),
                        name,
                    });
                }

                let mut mem = entries.cast::<core::ffi::c_void>();
                FwpmFreeMemory0(&raw mut mem);
            }

            let _ = FwpmFilterDestroyEnumHandle0(self.handle, enum_handle);
            Ok(listed)
        }
    }
}
/// The rule a filter's display name encodes. Only a claim: [`group_filters`]
/// checks it against the filter's actual shape.
fn decode_wfp_filter(display_name: &str) -> Option<Rule> {
    let encoded = display_name.split_whitespace().nth(1)?;
    let bytes = BASE32_NOPAD.decode(encoded.as_bytes()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// One filter in this namespace's sublayer, with the rule its name encodes
/// when that name decodes, and what the filter actually enforces.
pub(super) struct ListedFilter {
    pub(super) filter_id: u64,
    pub(super) name: String,
    pub(super) rule: Option<Rule>,
    pub(super) shape: FilterShape,
}

/// Sorts listed filters into complete rules and drift. The sublayer is this
/// namespace's own, so a filter without a marker is still ours to clear.
///
/// A filter counts toward its rule only when its layer, action, and
/// conditions are the ones the encoded rule installs for that part. A filter
/// edited natively keeps its name, and the name alone would report the rule
/// as intact while the filter enforces something else.
///
/// `app_id` computes an application's WFP id from its path.
pub(super) fn group_filters(
    listed: Vec<ListedFilter>,
    namespace: &ManagedNamespace,
    app_id: impl Fn(&std::path::Path) -> Option<Vec<u8>>,
) -> EnumeratedWfpState {
    struct MarkedFilter {
        filter_id: u64,
        name: String,
        marker: ManagedMarker,
        rule: Rule,
    }

    let mut drifted = Vec::new();
    let mut orphan_ids: HashMap<RuleKey, Vec<u64>> = HashMap::new();
    let mut unkeyed_orphan_ids: Vec<u64> = Vec::new();
    let mut grouped: BTreeMap<RuleKey, Vec<MarkedFilter>> = BTreeMap::new();
    for filter in listed {
        let Ok(marker) = ManagedMarker::parse(&filter.name, namespace) else {
            unkeyed_orphan_ids.push(filter.filter_id);
            drifted.push(format!("wfp:{}", filter.filter_id));
            continue;
        };
        let rule = filter
            .rule
            .filter(|rule| shape_matches(rule, &marker, filter.shape, &app_id));
        let Some(rule) = rule else {
            orphan_ids
                .entry(marker.key)
                .or_default()
                .push(filter.filter_id);
            drifted.push(filter.name);
            continue;
        };
        grouped
            .entry(marker.key.clone())
            .or_default()
            .push(MarkedFilter {
                filter_id: filter.filter_id,
                name: filter.name,
                marker,
                rule,
            });
    }

    let mut rules = HashMap::with_capacity(grouped.len());
    let mut filter_ids = HashMap::with_capacity(grouped.len());
    for (key, mut parts) in grouped {
        let complete = firew_sys::complete_parts(&mut parts, |row| &row.marker).is_some()
            && parts.iter().all(|row| row.rule == parts[0].rule);
        if !complete {
            for row in parts {
                orphan_ids
                    .entry(key.clone())
                    .or_default()
                    .push(row.filter_id);
                drifted.push(row.name);
            }
            continue;
        }
        rules.insert(key.clone(), parts[0].rule.clone());
        filter_ids.insert(key, parts.into_iter().map(|row| row.filter_id).collect());
    }

    EnumeratedWfpState {
        rules,
        filter_ids,
        orphan_ids,
        unkeyed_orphan_ids,
        drifted,
    }
}

/// Whether `shape` is what `rule` installs as its part `marker.part` of
/// `marker.total`.
fn shape_matches(
    rule: &Rule,
    marker: &ManagedMarker,
    shape: FilterShape,
    app_id: &impl Fn(&std::path::Path) -> Option<Vec<u8>>,
) -> bool {
    let known_id = rule.application_path().and_then(app_id);
    // An id that cannot be computed now, such as for an application removed
    // since, cannot be compared byte for byte; only its presence is checked.
    let id_unknown = rule.application_path().is_some() && known_id.is_none();
    let part = usize::from(marker.part);
    let Some(expected) = expected_filter_shape(rule, part, known_id.unwrap_or_default()) else {
        return false;
    };
    if id_unknown {
        expected.without_app_id_bytes() == shape.without_app_id_bytes()
    } else {
        expected == shape
    }
}
