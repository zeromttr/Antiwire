//! Linux backend auto-detection.

use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, Ordering};

use firew_sys::BackendPreference;
use nftables::batch::Batch;
#[cfg(target_os = "linux")]
use nftables::helper;
use nftables::schema::{NfListObject, Table};
use nftables::types::NfFamily;

static PROBE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generates a unique, unhooked scratch table name for one operational probe.
///
/// Using a per-call token (process ID + monotonic counter) ensures concurrent
/// probes never collide and a preexisting table is never touched or deleted.
#[must_use]
pub fn unique_probe_table_name() -> String {
    let pid = std::process::id();
    let seq = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("__firew_probe_{pid}_{seq}__")
}

/// Builds a single atomic batch that creates and immediately deletes an
/// unhooked scratch table.
///
/// Because the table has no chains, no hooks, and no rules, it never intercepts
/// or drops packets, and because creation and deletion happen in the same
/// netlink transaction, no kernel object outlives the probe call.
#[must_use]
pub fn build_probe_batch(table_name: &str) -> Batch<'static> {
    let mut batch = Batch::new();
    batch.add(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: Cow::Owned(table_name.to_owned()),
        ..Default::default()
    }));
    batch.delete(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: Cow::Owned(table_name.to_owned()),
        ..Default::default()
    }));
    batch
}

/// Detects whether nftables can apply rules on this host.
pub fn nftables_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        nftables_operational()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn nftables_operational() -> bool {
    let table_name = unique_probe_table_name();
    let batch = build_probe_batch(&table_name);
    if helper::apply_ruleset(&batch.to_nftables()).is_ok() {
        return true;
    }

    // Fallback for older kernels/binaries that disallow add+delete in one batch:
    // create the unique unhooked table (no chains/hooks/rules) and delete it.
    let mut create = Batch::new();
    create.add(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: Cow::Owned(table_name.clone()),
        ..Default::default()
    }));
    if helper::apply_ruleset(&create.to_nftables()).is_err() {
        return false;
    }
    let mut cleanup = Batch::new();
    cleanup.delete(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: Cow::Owned(table_name),
        ..Default::default()
    }));
    helper::apply_ruleset(&cleanup.to_nftables()).is_ok()
}

/// Probes `iptables` command availability.
pub fn iptables_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        iptables::new(false).is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Selects backend based on preference and availability.
///
/// # Errors
///
/// Returns [`firew_core::ErrorKind::BackendUnavailable`] when the requested backend
/// is not available or the preference is invalid for Linux.
pub fn select_backend(preference: BackendPreference) -> Result<BackendKind, firew_core::Error> {
    use firew_core::{Error, ErrorKind};

    match preference {
        BackendPreference::Nftables => {
            if nftables_available() {
                Ok(BackendKind::Nftables)
            } else {
                Err(Error::new(
                    ErrorKind::BackendUnavailable,
                    "nftables not available",
                ))
            }
        }
        BackendPreference::Iptables => {
            if iptables_available() {
                Ok(BackendKind::Iptables)
            } else {
                Err(Error::new(
                    ErrorKind::BackendUnavailable,
                    "iptables not available",
                ))
            }
        }
        BackendPreference::Auto => {
            if nftables_available() {
                Ok(BackendKind::Nftables)
            } else if iptables_available() {
                Ok(BackendKind::Iptables)
            } else {
                Err(Error::new(
                    ErrorKind::BackendUnavailable,
                    "no linux firewall backend available",
                ))
            }
        }
        _ => Err(Error::new(
            ErrorKind::BackendUnavailable,
            "invalid backend preference for linux",
        )),
    }
}

/// Linux backend implementation kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    /// nftables via `nftables-rs` (`nft -j`).
    Nftables,
    /// iptables via `iptables` command wrapper.
    Iptables,
}

#[cfg(test)]
mod tests {
    use super::*;
    use nftables::schema::NfObject;

    #[test]
    fn probe_batch_uses_unique_unhooked_table_without_rules_or_chains() {
        let name_a = unique_probe_table_name();
        let name_b = unique_probe_table_name();
        assert_ne!(name_a, name_b);

        let ruleset = build_probe_batch(&name_a).to_nftables();
        for obj in ruleset.objects.iter() {
            match obj {
                NfObject::CmdObject(_) => {}
                NfObject::ListObject(list_obj) => {
                    panic!("unexpected list object in probe batch: {list_obj:?}");
                }
            }
        }
        let json = serde_json::to_string(&ruleset).expect("serialize probe batch");
        assert!(
            !json.contains("drop"),
            "probe batch must not contain a drop rule"
        );
        assert!(
            !json.contains("hook"),
            "probe batch must not contain a hooked chain"
        );
        assert!(json.contains(&name_a));
    }
}
