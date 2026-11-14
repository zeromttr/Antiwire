//! macOS PF backend via `pfctl`.

use std::borrow::Cow;
use std::collections::BTreeMap;

use firew_core::{Error, ErrorKind, Protocol, Rule, RuleKey};
use firew_sys::{
    unsupported_matcher, Backend, BackendConfig, BackendPreference, DriftTracker, HealthSnapshot,
    NativeRuleRef, RuleFilter,
};
use pfctl::{AnchorChange, AnchorKind, PfCtl};

use crate::pf_rules::{build_filter_rules, map_pf_err_kind};
use crate::pf_table::AnchorListing;

/// macOS PF anchor backend.
pub struct MacOsBackend {
    config: BackendConfig,
    anchor: String,
    /// Legacy sub-anchor flushed on open/sync so upgrades leave no stale rules behind.
    legacy_set_anchor: String,
    /// Whether the `pfctl` binary is usable; probed once at open.
    pfctl_available: bool,
    pf: PfCtl,
    rules: BTreeMap<RuleKey, Rule>,
    /// Anchor lines the last listing could not rebuild into `rules`, written
    /// back on every load so an anchor rewrite never deletes them.
    unrecognized: Vec<(Option<RuleKey>, String)>,
    drift: DriftTracker,
    /// Whether `rules` and `unrecognized` hold everything in the anchor.
    /// Always true with `pfctl`, which lists the anchor. Without it the anchor
    /// cannot be read, so this owner must not rewrite it until it has written
    /// or cleared the anchor itself: a rewrite from an empty map would delete
    /// persistent rules an earlier owner installed.
    anchor_known: bool,
    transaction_open: bool,
    transaction_snapshot: Option<PfSnapshot>,
}

/// What an aborted or failed transaction restores.
struct PfSnapshot {
    rules: BTreeMap<RuleKey, Rule>,
    unrecognized: Vec<(Option<RuleKey>, String)>,
    anchor_known: bool,
}

impl MacOsBackend {
    /// Opens the managed PF anchor, ensuring the PF packet filter is enabled.
    ///
    /// # Errors
    ///
    /// Returns an error when `/dev/pf` cannot be accessed, PF is disabled and
    /// cannot be enabled, or the managed anchor cannot be initialized.
    pub fn open(config: &BackendConfig) -> Result<Self, Error> {
        if !matches!(
            config.prefer_backend,
            BackendPreference::Auto | BackendPreference::Pf
        ) {
            return Err(Error::new(
                ErrorKind::BackendUnavailable,
                "invalid backend preference for macos",
            ));
        }

        let anchor = format!("firew_rs/{}", config.managed_namespace().as_str());
        let legacy_set_anchor = format!("{anchor}_sets");
        let mut pf = PfCtl::new().map_err(|e| map_pf_err_kind(&e, ErrorKind::PermissionDenied))?;

        // Ensure PF is enabled so installed rules actually enforce packet filtering (#14).
        if let Err(enable_err) = pf.try_enable() {
            return Err(map_pf_err_kind(&enable_err, ErrorKind::BackendUnavailable));
        }

        pf.try_add_anchor(&anchor, AnchorKind::Filter)
            .map_err(|e| map_pf_err_kind(&e, ErrorKind::Internal))?;
        let _ = pf.try_add_anchor(&legacy_set_anchor, AnchorKind::Filter);

        let pfctl_available = crate::pf_table::is_available();
        let mut backend = Self {
            config: config.clone(),
            anchor,
            legacy_set_anchor,
            pfctl_available,
            pf,
            rules: BTreeMap::new(),
            unrecognized: Vec::new(),
            drift: DriftTracker::new(),
            anchor_known: pfctl_available,
            transaction_open: false,
            transaction_snapshot: None,
        };
        backend.refresh_from_native()?;
        Ok(backend)
    }

    fn ensure_pf_enabled(&mut self) -> Result<(), Error> {
        self.pf
            .try_enable()
            .map_err(|e| map_pf_err_kind(&e, ErrorKind::BackendUnavailable))
    }

    /// Lists the managed anchor, with the legacy set anchor folded in.
    fn read_listing(&self) -> Result<AnchorListing, Error> {
        let namespace = self.config.managed_namespace();
        let mut listing = crate::pf_table::query_anchor_rules(&self.anchor, &namespace)?;
        if let Ok(legacy) = crate::pf_table::query_anchor_rules(&self.legacy_set_anchor, &namespace)
        {
            for (k, r) in legacy.rules {
                listing.rules.entry(k).or_insert(r);
            }
            listing.drifted.extend(legacy.drifted);
            // The legacy anchor is emptied on every load; carry its unparsed
            // lines into the main anchor rather than dropping them.
            listing.unrecognized.extend(legacy.unrecognized);
        }
        Ok(listing)
    }

    /// Whether reads go to the anchor. A transaction reads its own staged
    /// view, and without `pfctl` the anchor cannot be listed.
    fn reads_anchor(&self) -> bool {
        !self.transaction_open && self.pfctl_available
    }

    fn refresh_from_native(&mut self) -> Result<(), Error> {
        if !self.reads_anchor() {
            return Ok(());
        }
        let listing = self.read_listing()?;
        self.rules = listing.rules;
        self.unrecognized = listing.unrecognized;

        self.drift.observe(listing.drifted);
        Ok(())
    }

    /// The rules a read reports: a fresh anchor listing, or this process's
    /// view while a transaction is open or `pfctl` is unavailable. Failing to
    /// list the anchor is an error, never a cue to answer from memory.
    fn visible_rules(&self) -> Result<Cow<'_, BTreeMap<RuleKey, Rule>>, Error> {
        if !self.reads_anchor() {
            return Ok(Cow::Borrowed(&self.rules));
        }
        let namespace = self.config.managed_namespace();
        Ok(Cow::Owned(
            crate::pf_table::query_anchor_rules(&self.anchor, &namespace)?.rules,
        ))
    }

    fn native_ref(&self, key: RuleKey) -> NativeRuleRef {
        NativeRuleRef::new("pf", self.config.display_name(&key), key)
    }

    /// Commits all rules (both Cartesian and Set) atomically into `self.anchor`,
    /// refusing when the anchor holds rules this owner cannot see.
    fn sync_anchor(&mut self) -> Result<(), Error> {
        if !self.anchor_known {
            return Err(Error::new(
                ErrorKind::BackendUnavailable,
                format!(
                    "pfctl is unavailable, so the rules already in PF anchor {} cannot be read \
                     and rewriting it would delete them; remove all rules to take the anchor over",
                    self.anchor
                ),
            ));
        }
        self.write_anchor()
    }

    /// Replaces the anchor with `rules` and the lines kept from the last listing.
    fn write_anchor(&mut self) -> Result<(), Error> {
        self.ensure_pf_enabled()?;
        let namespace = self.config.managed_namespace();
        if self.pfctl_available {
            let mut ruleset = crate::pf_table::render_full_anchor(&self.rules, &namespace)?;
            // Loading replaces the whole anchor. Lines that did not parse are
            // written back unchanged, except those of a key this owner now
            // holds a valid rule for, which the new rendering supersedes.
            for (key, line) in &self.unrecognized {
                if key.as_ref().is_some_and(|key| self.rules.contains_key(key)) {
                    continue;
                }
                ruleset.push_str(line);
                ruleset.push('\n');
            }
            crate::pf_table::load_anchor(&self.anchor, &ruleset)?;
            let _ = crate::pf_table::load_anchor(&self.legacy_set_anchor, "");
            Ok(())
        } else {
            let filter_rules = build_filter_rules(&self.rules, &namespace)?;
            let mut change = AnchorChange::new();
            change.set_filter_rules(filter_rules);
            self.pf
                .set_rules(&self.anchor, change)
                .map_err(|e| map_pf_err_kind(&e, ErrorKind::Internal))?;
            // The anchor now holds exactly `rules`.
            self.anchor_known = true;
            Ok(())
        }
    }

    fn snapshot(&self) -> PfSnapshot {
        PfSnapshot {
            rules: self.rules.clone(),
            unrecognized: self.unrecognized.clone(),
            anchor_known: self.anchor_known,
        }
    }

    fn restore(&mut self, snapshot: PfSnapshot) {
        self.rules = snapshot.rules;
        self.unrecognized = snapshot.unrecognized;
        self.anchor_known = snapshot.anchor_known;
    }
}

impl Backend for MacOsBackend {
    fn open(config: &BackendConfig) -> Result<Self, Error> {
        Self::open(config)
    }

    fn name(&self) -> &'static str {
        "pf"
    }

    fn supports_transactions(&self) -> bool {
        true
    }

    fn max_address_set_entries(&self) -> Option<usize> {
        self.pfctl_available
            .then_some(crate::pf_table::MAX_TABLE_ENTRIES)
    }

    fn validate_rule(&self, rule: &Rule) -> Result<(), Error> {
        firew_sys::validate_native_rule(self, "PF", rule)?;
        firew_sys::reject_application_matchers("PF", "pf", rule)?;
        if matches!(rule.protocol(), Protocol::Other(_)) {
            return unsupported(rule, "custom protocol numbers");
        }
        Ok(())
    }

    fn add_rule(&mut self, rule: &Rule) -> Result<NativeRuleRef, Error> {
        self.validate_rule(rule)?;
        // Every edit rewrites the whole anchor from `self.rules`, so it must
        // start from a listing that worked, never from a stale or empty map.
        self.refresh_from_native()?;

        let key = rule.logical_key().clone();
        if self.rules.contains_key(&key) {
            return Err(firew_sys::duplicate_rule(key));
        }

        self.rules.insert(key.clone(), rule.clone());
        if !self.transaction_open {
            if let Err(error) = self.sync_anchor() {
                self.rules.remove(&key);
                return Err(error);
            }
        }
        Ok(self.native_ref(key))
    }

    fn update_rule(&mut self, id: &NativeRuleRef, rule: &Rule) -> Result<NativeRuleRef, Error> {
        self.validate_rule(rule)?;
        // Every edit rewrites the whole anchor from `self.rules`, so it must
        // start from a listing that worked, never from a stale or empty map.
        self.refresh_from_native()?;

        let key = id.logical_key().clone();
        if &key != rule.logical_key() {
            return Err(firew_sys::key_mismatch(rule));
        }
        let previous = self
            .rules
            .get(&key)
            .cloned()
            .ok_or_else(|| firew_sys::rule_not_found(&key))?;
        self.rules.insert(key.clone(), rule.clone());
        if !self.transaction_open {
            if let Err(error) = self.sync_anchor() {
                self.rules.insert(key, previous);
                return Err(error);
            }
        }
        Ok(self.native_ref(key))
    }

    fn remove_rule(&mut self, id: &NativeRuleRef) -> Result<(), Error> {
        self.refresh_from_native()?;
        let key = id.logical_key();
        let has_fragments = self
            .unrecognized
            .iter()
            .any(|(line_key, _)| line_key.as_ref() == Some(key));
        if !self.rules.contains_key(key) && !has_fragments {
            return Err(firew_sys::rule_not_found(key));
        }
        let previous = self.snapshot();
        self.rules.remove(key);
        // Lines of this key that did not parse are kept on every rewrite, so
        // they have to go explicitly or they stay in the anchor.
        self.unrecognized
            .retain(|(line_key, _)| line_key.as_ref() != Some(key));
        if !self.transaction_open {
            if let Err(error) = self.sync_anchor() {
                self.restore(previous);
                return Err(error);
            }
        }
        Ok(())
    }

    fn get_rule(&self, id: &NativeRuleRef) -> Result<Rule, Error> {
        self.visible_rules()?
            .get(id.logical_key())
            .cloned()
            .ok_or_else(|| firew_sys::rule_not_found(id.logical_key()))
    }

    fn list_rules(&self, filter: &RuleFilter) -> Result<Vec<(NativeRuleRef, Rule)>, Error> {
        Ok(self
            .visible_rules()?
            .iter()
            .filter(|(key, rule)| filter.matches(key, rule))
            .map(|(key, rule)| (self.native_ref(key.clone()), rule.clone()))
            .collect())
    }

    fn begin_transaction(&mut self) -> Result<(), Error> {
        if self.transaction_open {
            return Err(Error::new(
                ErrorKind::TransactionFailed,
                "transaction already open",
            ));
        }
        self.refresh_from_native()?;
        self.transaction_snapshot = Some(self.snapshot());
        self.transaction_open = true;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Error> {
        if self.transaction_open {
            if let Err(error) = self.sync_anchor() {
                if let Some(snapshot) = self.transaction_snapshot.take() {
                    self.restore(snapshot);
                }
                self.transaction_open = false;
                return Err(error);
            }
            self.transaction_open = false;
            self.transaction_snapshot = None;
        }
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Error> {
        if self.transaction_open {
            if let Some(snapshot) = self.transaction_snapshot.take() {
                self.restore(snapshot);
            }
            self.transaction_open = false;
        }
        Ok(())
    }

    fn health_probe(&self, expected_keys: &[RuleKey]) -> Result<HealthSnapshot, Error> {
        if self.reads_anchor() {
            let output = std::process::Command::new("pfctl")
                .args(["-s", "info"])
                .stdin(std::process::Stdio::null())
                .output();
            if let Ok(out) = output {
                let text = String::from_utf8_lossy(&out.stdout);
                if text.contains("Status: Disabled") {
                    return Ok(HealthSnapshot::from_present(
                        std::iter::empty(),
                        expected_keys,
                    ));
                }
            }
        }
        Ok(HealthSnapshot::from_present(
            self.visible_rules()?.keys(),
            expected_keys,
        ))
    }

    fn remove_all_managed(&mut self) -> Result<(), Error> {
        self.rules.clear();
        self.unrecognized.clear();
        self.drift.clear();
        // Emptying the anchor is the one rewrite that needs no listing: it is
        // meant to delete whatever is there. `write_anchor` records that the
        // anchor is known; a transaction records it now and restores the old
        // value if it aborts.
        if self.transaction_open {
            self.anchor_known = true;
            Ok(())
        } else {
            self.write_anchor()
        }
    }

    fn take_drift(&mut self) -> Result<Vec<String>, Error> {
        self.refresh_from_native()?;
        Ok(self.drift.take())
    }

    fn incomplete_keys(&self) -> Result<Vec<RuleKey>, Error> {
        let fresh;
        let (rules, unrecognized) = if self.reads_anchor() {
            fresh = self.read_listing()?;
            (&fresh.rules, &fresh.unrecognized)
        } else {
            (&self.rules, &self.unrecognized)
        };
        let keys: std::collections::BTreeSet<RuleKey> = unrecognized
            .iter()
            .filter_map(|(key, _)| key.clone())
            .filter(|key| !rules.contains_key(key))
            .collect();
        Ok(keys.into_iter().collect())
    }
}

fn unsupported(rule: &Rule, field: &str) -> Result<(), Error> {
    Err(unsupported_matcher("PF", "pf", rule, field))
}
