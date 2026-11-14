//! Offline Windows rule naming and namespace isolation contract tests.

use firew_core::{ErrorKind, RuleKey};
use firew_sys::{Backend, BackendConfig, BackendPreference, ManagedMarker};
use firew_windows::{legacy_display_name, native_display_name, native_group_name, WindowsBackend};

#[test]
fn native_display_names_isolate_distinct_namespaces_sharing_the_same_key() {
    let key = RuleKey::try_from("shared-key").expect("key");
    let first = BackendConfig::new("manager-a").managed_namespace();
    let second = BackendConfig::new("manager-b").managed_namespace();
    let mut with_app = BackendConfig::new("manager-a");
    with_app.application_name = "daemon".to_owned();
    let third = with_app.managed_namespace();

    let name_a = native_display_name(&first, &key, 0, 2);
    let name_b = native_display_name(&second, &key, 0, 2);
    let name_c = native_display_name(&third, &key, 0, 2);

    assert_ne!(name_a, name_b);
    assert_ne!(name_a, name_c);
    assert_ne!(name_b, name_c);
    assert!(name_a.contains(first.as_str()));
    assert!(name_a.ends_with("shared-key [1/2]"));
    assert_ne!(name_a, legacy_display_name(&key, 0, 2));
}

#[test]
fn native_group_and_marker_correlate_to_the_same_namespace() {
    let mut config = BackendConfig::new("firew");
    config.application_name = "daemon".to_owned();
    let ns = config.managed_namespace();
    let key = RuleKey::try_from("rule-7").expect("key");

    let group = native_group_name(&ns);
    assert_eq!(group, format!("firew-rs:{}", ns.as_str()));

    let marker = ManagedMarker {
        key: key.clone(),
        part: 0,
        total: 1,
    }
    .encode(&ns)
    .expect("marker");
    let description = format!("{marker} [set] human label");
    let parsed = ManagedMarker::parse(&description, &ns).expect("parse marker");
    assert_eq!(parsed.key, key);
    assert_eq!(parsed.part, 0);
    assert_eq!(parsed.total, 1);
}

#[test]
fn rejects_foreign_backend_preferences_on_windows() {
    for foreign in [
        BackendPreference::Nftables,
        BackendPreference::Iptables,
        BackendPreference::Pf,
    ] {
        let mut config = BackendConfig::new("firew");
        config.prefer_backend = foreign;
        let Err(err) = WindowsBackend::open(&config) else {
            panic!("foreign preference {foreign:?} must be rejected");
        };
        assert_eq!(err.kind(), ErrorKind::BackendUnavailable);
    }
}
