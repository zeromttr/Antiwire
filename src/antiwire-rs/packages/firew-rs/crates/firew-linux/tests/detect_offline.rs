//! Offline tests for Linux backend preference validation and probe safety.

use firew_core::ErrorKind;
use firew_sys::BackendPreference;

#[test]
fn invalid_preference_for_linux_returns_error() {
    for foreign in [
        BackendPreference::InetFw,
        BackendPreference::Wfp,
        BackendPreference::Pf,
    ] {
        let err = firew_linux::detect::select_backend(foreign)
            .unwrap_firew_err()
            .kind();
        assert_eq!(err, ErrorKind::BackendUnavailable);
    }
}

#[test]
fn probe_table_names_are_unique_and_unhooked() {
    let a = firew_linux::detect::unique_probe_table_name();
    let b = firew_linux::detect::unique_probe_table_name();
    assert_ne!(a, b);
    let _batch = firew_linux::detect::build_probe_batch(&a);
}

trait UnwrapFirewErr {
    fn unwrap_firew_err(self) -> firew_core::Error;
}

impl<T> UnwrapFirewErr for Result<T, firew_core::Error> {
    fn unwrap_firew_err(self) -> firew_core::Error {
        match self {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        }
    }
}
