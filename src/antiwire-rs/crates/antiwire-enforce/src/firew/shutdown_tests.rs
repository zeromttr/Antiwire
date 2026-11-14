use std::sync::atomic::{AtomicUsize, Ordering};

use antiwire_policy::{EnforcementOp, RuleDirection, Verdict};

use super::*;
use crate::EnforcementClient;

/// Uses its own native namespace and removes it even if an assertion panics.
/// The observer reads native state independently of the filter's tracking.
pub(super) struct NativeRules {
    observer: Firewall,
}

impl NativeRules {
    pub(super) fn seed() -> (Self, FirewFilter) {
        static NEXT_NAMESPACE: AtomicUsize = AtomicUsize::new(0);
        let prefix = format!(
            "antiwire-stop-test-{}-{}",
            std::process::id(),
            NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed)
        );
        let open = || {
            Firewall::builder()
                .name_prefix(&prefix)
                .memory_mode(false)
                .build()
                .expect("open isolated native firewall")
        };
        let rules = Self { observer: open() };
        let mut filter = FirewFilter::new();
        filter.firewall = Some(open());
        filter
            .apply(EnforcementOp::AddIpRule {
                rule_id: 1,
                ip: "192.0.2.1".to_owned(),
                verdict: Verdict::Block,
                direction: RuleDirection::Outbound,
            })
            .expect("install persistent IP block");
        filter
            .apply(EnforcementOp::AddDohBlock {
                doh_ips: vec!["192.0.2.2".to_owned()],
                port: 443,
            })
            .expect("install resolver-dependent blocks");
        assert_eq!(rules.keys().len(), 3);
        (rules, filter)
    }

    pub(super) fn keys(&self) -> Vec<String> {
        let mut keys: Vec<_> = self
            .observer
            .list_rules(&RuleFilter::new())
            .expect("read native rules")
            .into_iter()
            .map(|(id, _)| id.key().as_str().to_owned())
            .collect();
        keys.sort();
        keys
    }
}

impl Drop for NativeRules {
    fn drop(&mut self) {
        if let Err(error) = self.observer.remove_all_rules() {
            eprintln!("could not clean up isolated shutdown-test rules: {error}");
            assert!(std::thread::panicking(), "native test cleanup failed");
        }
    }
}

fn cleanup_failure() -> EnforceError {
    firew_rs::Error::new(
        ErrorKind::BackendUnavailable,
        "injected DoH cleanup failure",
    )
    .into()
}

fn assert_cleanup_failure(result: Result<()>) {
    let EnforceError::Firewall(error) = result.expect_err("cleanup failure must reach the caller")
    else {
        panic!("expected the injected firewall error");
    };
    assert_eq!(error.kind(), ErrorKind::BackendUnavailable);
    assert_eq!(error.message(), "injected DoH cleanup failure");
}

#[test]
fn stopping_an_inactive_filter_is_idempotent() {
    let mut filter = FirewFilter::new();
    filter
        .close(|_| panic!("an inactive filter has nothing to clean up"))
        .expect("already closed");
    filter.stop_keeping_rules().expect("already stopped");
    filter.stop().expect("already stopped");
    assert!(!filter.is_enforcing());
}

#[test]
#[ignore = "requires administrator and native firewall access"]
fn live_failed_cleanup_preserves_rules_on_drop() {
    for partial_cleanup in [false, true] {
        let (rules, mut filter) = NativeRules::seed();
        let mut expected = rules.keys();
        // Inject at the cleanup boundary used by stop_keeping_rules. Exercise
        // both failure before mutation and failure after removing one DoH rule.
        let result = filter.close(|firewall| {
            if partial_cleanup {
                let (id, _) = firewall
                    .list_rules(&RuleFilter::new())?
                    .into_iter()
                    .find(|(id, _)| id.key().as_str().starts_with(DOH_KEY_PREFIX))
                    .expect("DoH rule");
                firewall.remove_rule(&id)?;
                expected.retain(|key| key != id.key().as_str());
            }
            Err(cleanup_failure())
        });
        assert_cleanup_failure(result);
        let detached = !filter.is_enforcing();
        let tracking_cleared = filter.installed.is_empty()
            && filter.doh_rule_keys.is_empty()
            && filter.country_rule_keys.is_empty();
        drop(filter);

        assert_eq!(rules.keys(), expected, "drop must preserve remaining rules");
        assert!(detached, "failed cleanup must still detach the backend");
        assert!(
            tracking_cleared,
            "a detached filter must forget its tracking"
        );
    }
}

/// Injects a failure into the real filter's persistent close path. Ordinary
/// stop and Drop still use the real implementation, including native cleanup.
struct FailingCleanupFilter(FirewFilter);

impl FirewallFilter for FailingCleanupFilter {
    fn start(&mut self) -> Result<()> {
        self.0.start()
    }

    fn stop(&mut self) -> Result<()> {
        self.0.stop()
    }

    fn stop_keeping_rules(&mut self) -> Result<()> {
        self.0.close(|_| Err(cleanup_failure()))
    }

    fn is_enforcing(&self) -> bool {
        self.0.is_enforcing()
    }

    fn apply(&mut self, op: EnforcementOp) -> Result<()> {
        self.0.apply(op)
    }
}

#[test]
#[ignore = "requires administrator and native firewall access"]
fn live_failed_cleanup_preserves_rules_on_worker_shutdown() {
    let (rules, filter) = NativeRules::seed();
    let expected = rules.keys();
    let client = EnforcementClient::with_filter(FailingCleanupFilter(filter)).expect("worker");

    assert_cleanup_failure(client.stop_keeping_rules());
    drop(client);

    assert_eq!(
        rules.keys(),
        expected,
        "worker shutdown must preserve rules"
    );
}

#[test]
#[ignore = "requires administrator and native firewall access"]
fn live_persistent_stop_removes_only_resolver_dependent_rules() {
    let (rules, mut filter) = NativeRules::seed();
    let expected: Vec<_> = rules
        .keys()
        .into_iter()
        .filter(|key| !key.starts_with(DOH_KEY_PREFIX))
        .collect();
    // Also find DoH rules recovered from a previous process, which this
    // filter did not install or track.
    filter.installed.clear();
    filter.doh_rule_keys.clear();
    let client = EnforcementClient::with_filter(filter).expect("worker");

    client.stop_keeping_rules().expect("persistent stop");
    assert!(!client.is_enforcing().expect("state"));
    client
        .stop_keeping_rules()
        .expect("repeated persistent stop");
    client.stop().expect("ordinary stop after persistent stop");
    drop(client);

    assert_eq!(rules.keys(), expected);
}

#[test]
#[ignore = "requires administrator and native firewall access"]
fn live_ordinary_stop_and_drop_still_remove_all_rules() {
    for explicit_stop in [false, true] {
        let (rules, mut filter) = NativeRules::seed();
        if explicit_stop {
            filter.stop().expect("ordinary stop");
            assert!(!filter.is_enforcing());
        }
        drop(filter);
        assert_eq!(rules.keys(), [] as [String; 0]);
    }
}
