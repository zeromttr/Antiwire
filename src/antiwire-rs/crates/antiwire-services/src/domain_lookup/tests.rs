use super::{lookup_name, DomainLookupService};
use crate::lookup_fakes::LookupHarness;

#[test]
fn the_inferred_marker_is_not_part_of_the_name() {
    assert_eq!(lookup_name("cdn.example.com (inferred)"), "cdn.example.com");
    assert_eq!(lookup_name(" cdn.example.com "), "cdn.example.com");
    assert_eq!(lookup_name("cdn.example.com"), "cdn.example.com");
}

#[tokio::test]
async fn a_registration_is_saved_only_when_the_setting_is_on() {
    for save_domain_lookups in [false, true] {
        let h = LookupHarness::new(0.0);
        h.configure("", save_domain_lookups);
        let lookups = DomainLookupService::new(&h.context, &h.clients);

        let found = lookups
            .registration("example.com (inferred)")
            .await
            .expect("record");

        assert_eq!(found.record.domain, "example.com");
        let saved = h
            .context
            .store
            .get_domain_lookup("example.com")
            .expect("read");
        assert_eq!(saved.is_some(), save_domain_lookups);
        if let Some(saved) = saved {
            assert_eq!(saved.source, "rdap");
            assert_eq!(saved.fetched_at, found.fetched_at);
        }
    }
}

#[tokio::test]
async fn a_lookup_that_finds_nothing_saves_nothing() {
    let h = LookupHarness::new(0.0);
    h.configure("", true);
    let lookups = DomainLookupService::new(&h.context, &h.clients);

    assert!(matches!(
        lookups.registration("unregistered.example").await,
        Err(antiwire_lookup::Error::NotFound(_))
    ));
    assert!(h
        .context
        .store
        .get_domain_lookup("unregistered.example")
        .expect("read")
        .is_none());
}
