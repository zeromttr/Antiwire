//! Backends compiled for a target they cannot run on.

/// Implements [`Backend`](crate::Backend) for a type that has no native firewall to drive.
///
/// `open` maps the configuration to the error explaining why the backend is
/// unavailable. Every other operation fails with `BackendUnavailable` and
/// `reason`. Listing every method here, instead of giving the trait defaults,
/// keeps a real backend from compiling with an operation left out.
///
/// ```ignore
/// firew_sys::unavailable_backend!(LinuxBackend, name = "linux-stub", reason = "stub", open = |_| {
///     Error::new(ErrorKind::BackendUnavailable, "linux backend unavailable on this target")
/// });
/// ```
#[macro_export]
macro_rules! unavailable_backend {
    ($ty:ty, name = $name:literal, reason = $reason:literal, open = $open:expr $(,)?) => {
        impl $crate::Backend for $ty {
            fn open(
                config: &$crate::BackendConfig,
            ) -> ::core::result::Result<Self, $crate::__private::Error> {
                let open: fn(&$crate::BackendConfig) -> $crate::__private::Error = $open;
                Err(open(config))
            }

            fn name(&self) -> &'static str {
                $name
            }

            fn supports_transactions(&self) -> bool {
                false
            }

            fn add_rule(
                &mut self,
                _rule: &$crate::__private::Rule,
            ) -> ::core::result::Result<$crate::NativeRuleRef, $crate::__private::Error> {
                Err($crate::__private::unavailable($reason))
            }

            fn update_rule(
                &mut self,
                _id: &$crate::NativeRuleRef,
                _rule: &$crate::__private::Rule,
            ) -> ::core::result::Result<$crate::NativeRuleRef, $crate::__private::Error> {
                Err($crate::__private::unavailable($reason))
            }

            fn remove_rule(
                &mut self,
                _id: &$crate::NativeRuleRef,
            ) -> ::core::result::Result<(), $crate::__private::Error> {
                Err($crate::__private::unavailable($reason))
            }

            fn get_rule(
                &self,
                _id: &$crate::NativeRuleRef,
            ) -> ::core::result::Result<$crate::__private::Rule, $crate::__private::Error> {
                Err($crate::__private::unavailable($reason))
            }

            fn list_rules(
                &self,
                _filter: &$crate::RuleFilter,
            ) -> ::core::result::Result<
                ::std::vec::Vec<($crate::NativeRuleRef, $crate::__private::Rule)>,
                $crate::__private::Error,
            > {
                Err($crate::__private::unavailable($reason))
            }

            fn begin_transaction(
                &mut self,
            ) -> ::core::result::Result<(), $crate::__private::Error> {
                Err($crate::__private::unavailable($reason))
            }

            fn commit_transaction(
                &mut self,
            ) -> ::core::result::Result<(), $crate::__private::Error> {
                Err($crate::__private::unavailable($reason))
            }

            fn abort_transaction(
                &mut self,
            ) -> ::core::result::Result<(), $crate::__private::Error> {
                Err($crate::__private::unavailable($reason))
            }

            fn health_probe(
                &self,
                _expected: &[$crate::__private::RuleKey],
            ) -> ::core::result::Result<$crate::HealthSnapshot, $crate::__private::Error> {
                Err($crate::__private::unavailable($reason))
            }

            fn remove_all_managed(
                &mut self,
            ) -> ::core::result::Result<(), $crate::__private::Error> {
                Err($crate::__private::unavailable($reason))
            }
        }
    };
}

/// Items [`unavailable_backend!`] expands to; not part of the API.
#[doc(hidden)]
pub mod __private {
    pub use firew_core::{Action, Direction, Error, PortRange, Protocol, Rule, RuleKey};
    pub use ipnet::IpNet;

    use firew_core::ErrorKind;

    /// `BackendUnavailable` with `reason`.
    #[must_use]
    pub fn unavailable(reason: &'static str) -> Error {
        Error::new(ErrorKind::BackendUnavailable, reason)
    }
}

#[cfg(test)]
mod tests {
    use firew_core::{Error, ErrorKind};

    use crate::{Backend, BackendConfig, RuleFilter};

    struct Unavailable;

    crate::unavailable_backend!(
        Unavailable,
        name = "test-stub",
        reason = "stub",
        open = |_| { Error::new(ErrorKind::BackendUnavailable, "not here") }
    );

    #[test]
    fn open_and_every_operation_report_unavailable() {
        let Err(error) = Unavailable::open(&BackendConfig::new("stub-test")) else {
            panic!("stub opened");
        };
        assert_eq!(error.kind(), ErrorKind::BackendUnavailable);
        let mut backend = Unavailable;
        assert_eq!(backend.name(), "test-stub");
        assert!(!backend.supports_transactions());
        let error = backend.list_rules(&RuleFilter::new()).expect_err("list");
        assert_eq!(error.kind(), ErrorKind::BackendUnavailable);
        let error = backend.begin_transaction().expect_err("begin");
        assert_eq!(error.kind(), ErrorKind::BackendUnavailable);
    }
}
