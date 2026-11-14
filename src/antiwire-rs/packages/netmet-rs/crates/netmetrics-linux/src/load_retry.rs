//! Whether a retry loads the eBPF object again after a load failed.

use netmetrics_sys::BackendError;

/// The last failed load that would fail the same way again, and the object it failed with.
///
/// `Object` says which object a load used, and two loads used the same one when they compare
/// equal. An object nothing can say that of is always loaded again.
#[derive(Debug)]
pub(crate) struct LoadRetry<Object> {
    repeats: Option<(Object, BackendError)>,
}

impl<Object> Default for LoadRetry<Object> {
    fn default() -> Self {
        Self { repeats: None }
    }
}

impl<Object: PartialEq> LoadRetry<Object> {
    /// What loading `object` would fail with again, when its last load failed in a way that
    /// repeats with the same object. `None` means it is worth loading.
    pub(crate) fn repeated_failure(&self, object: Option<&Object>) -> Option<BackendError> {
        let (failed, error) = self.repeats.as_ref()?;
        (object? == failed).then(|| error.clone())
    }

    /// A load of `object` failed with `error`. Unless the cause `passes`, a load of the same
    /// object fails the same way.
    pub(crate) fn failed(&mut self, object: Option<Object>, error: &BackendError, passes: bool) {
        self.repeats = object
            .filter(|_| !passes)
            .map(|object| (object, error.clone()));
    }

    /// A load succeeded, so whatever failed before is no longer known to repeat.
    pub(crate) fn succeeded(&mut self) {
        self.repeats = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmetrics_sys::BackendErrorKind;

    fn rejected() -> BackendError {
        BackendError::new(
            BackendErrorKind::Unavailable,
            "aya-loader",
            "the verifier rejected a program",
        )
    }

    #[test]
    fn an_object_is_loaded_until_a_load_of_it_fails() {
        let retry = LoadRetry::<u32>::default();
        assert_eq!(retry.repeated_failure(Some(&1)), None);
        assert_eq!(retry.repeated_failure(None), None);
    }

    #[test]
    fn a_failure_that_repeats_is_not_loaded_again_until_the_object_changes() {
        let mut retry = LoadRetry::default();
        retry.failed(Some(1), &rejected(), false);
        assert_eq!(retry.repeated_failure(Some(&1)), Some(rejected()));
        assert_eq!(
            retry.repeated_failure(Some(&2)),
            None,
            "a replaced object is loaded"
        );
        assert_eq!(
            retry.repeated_failure(None),
            None,
            "an object that cannot be told apart is loaded"
        );
    }

    #[test]
    fn a_failure_that_passes_is_loaded_again() {
        let mut retry = LoadRetry::default();
        retry.failed(Some(1), &rejected(), false);
        retry.failed(Some(1), &rejected(), true);
        assert_eq!(retry.repeated_failure(Some(&1)), None);
    }

    #[test]
    fn a_failure_of_an_object_that_cannot_be_told_apart_is_loaded_again() {
        let mut retry = LoadRetry::<u32>::default();
        retry.failed(None, &rejected(), false);
        assert_eq!(retry.repeated_failure(None), None);
        assert_eq!(retry.repeated_failure(Some(&1)), None);
    }

    #[test]
    fn a_success_forgets_the_failure() {
        let mut retry = LoadRetry::default();
        retry.failed(Some(1), &rejected(), false);
        retry.succeeded();
        assert_eq!(retry.repeated_failure(Some(&1)), None);
    }
}
