//! Wrappers that pick one native backend at open time.

/// Expands, inside an `impl Backend` block, to every method except `open`,
/// each forwarding to the backend stored in `self.$field`.
///
/// Methods with trait defaults are forwarded too, so a wrapper never answers
/// with a default where the backend it selected overrides it.
#[macro_export]
macro_rules! forward_backend {
    ($field:ident) => {
        fn name(&self) -> &'static str {
            self.$field.name()
        }

        fn supports_transactions(&self) -> bool {
            self.$field.supports_transactions()
        }

        fn max_address_set_entries(&self) -> ::core::option::Option<usize> {
            self.$field.max_address_set_entries()
        }

        fn supports_ipv6(&self) -> bool {
            self.$field.supports_ipv6()
        }

        fn validate_rule(
            &self,
            rule: &$crate::__private::Rule,
        ) -> ::core::result::Result<(), $crate::__private::Error> {
            self.$field.validate_rule(rule)
        }

        fn add_rule(
            &mut self,
            rule: &$crate::__private::Rule,
        ) -> ::core::result::Result<$crate::NativeRuleRef, $crate::__private::Error> {
            self.$field.add_rule(rule)
        }

        fn update_rule(
            &mut self,
            id: &$crate::NativeRuleRef,
            rule: &$crate::__private::Rule,
        ) -> ::core::result::Result<$crate::NativeRuleRef, $crate::__private::Error> {
            self.$field.update_rule(id, rule)
        }

        fn remove_rule(
            &mut self,
            id: &$crate::NativeRuleRef,
        ) -> ::core::result::Result<(), $crate::__private::Error> {
            self.$field.remove_rule(id)
        }

        fn get_rule(
            &self,
            id: &$crate::NativeRuleRef,
        ) -> ::core::result::Result<$crate::__private::Rule, $crate::__private::Error> {
            self.$field.get_rule(id)
        }

        fn list_rules(
            &self,
            filter: &$crate::RuleFilter,
        ) -> ::core::result::Result<
            ::std::vec::Vec<($crate::NativeRuleRef, $crate::__private::Rule)>,
            $crate::__private::Error,
        > {
            self.$field.list_rules(filter)
        }

        fn begin_transaction(&mut self) -> ::core::result::Result<(), $crate::__private::Error> {
            self.$field.begin_transaction()
        }

        fn commit_transaction(&mut self) -> ::core::result::Result<(), $crate::__private::Error> {
            self.$field.commit_transaction()
        }

        fn abort_transaction(&mut self) -> ::core::result::Result<(), $crate::__private::Error> {
            self.$field.abort_transaction()
        }

        fn health_probe(
            &self,
            expected_keys: &[$crate::__private::RuleKey],
        ) -> ::core::result::Result<$crate::HealthSnapshot, $crate::__private::Error> {
            self.$field.health_probe(expected_keys)
        }

        fn remove_all_managed(&mut self) -> ::core::result::Result<(), $crate::__private::Error> {
            self.$field.remove_all_managed()
        }

        fn take_drift(
            &mut self,
        ) -> ::core::result::Result<::std::vec::Vec<::std::string::String>, $crate::__private::Error>
        {
            self.$field.take_drift()
        }

        fn incomplete_keys(
            &self,
        ) -> ::core::result::Result<
            ::std::vec::Vec<$crate::__private::RuleKey>,
            $crate::__private::Error,
        > {
            self.$field.incomplete_keys()
        }
    };
}

#[cfg(test)]
mod tests {
    use firew_core::Error;

    use crate::mock::MockBackend;
    use crate::{Backend, BackendConfig, RuleFilter};

    struct Wrapper {
        inner: Box<dyn Backend>,
    }

    impl Backend for Wrapper {
        fn open(config: &BackendConfig) -> Result<Self, Error> {
            Ok(Self {
                inner: Box::new(MockBackend::open(config)?),
            })
        }

        crate::forward_backend!(inner);
    }

    #[test]
    fn forwards_to_the_selected_backend() {
        let config = BackendConfig::new("forward-test");
        let wrapper = Wrapper::open(&config).expect("open");
        let direct = MockBackend::open(&config).expect("open");
        assert_eq!(wrapper.name(), direct.name());
        assert_eq!(
            wrapper.supports_transactions(),
            direct.supports_transactions()
        );
        assert!(wrapper
            .list_rules(&RuleFilter::new())
            .expect("list")
            .is_empty());
    }
}
