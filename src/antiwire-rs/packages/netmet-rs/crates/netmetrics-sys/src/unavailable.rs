//! Backends compiled for a target they cannot run on.

/// Defines a unit-struct [`Backend`](crate::Backend) that fails to run with
/// [`BackendErrorKind::Unsupported`](crate::BackendErrorKind::Unsupported).
///
/// Platform crates use it so a feature enabled for another target still
/// builds, and the collector reports the platform as unsupported instead of
/// failing to compile.
#[macro_export]
macro_rules! unavailable_backend {
    ($(#[$meta:meta])* $vis:vis struct $name:ident, name = $backend:literal, detail = $detail:literal $(,)?) => {
        $(#[$meta])*
        #[derive(Debug, Default)]
        $vis struct $name;

        impl $crate::Backend for $name {
            fn name(&self) -> &'static str {
                $backend
            }

            fn run(
                &mut self,
                _config: &$crate::BackendConfig,
                _sink: $crate::EventSink,
                _stop: $crate::StopFlag,
            ) -> ::core::result::Result<(), $crate::BackendError> {
                Err($crate::BackendError::new(
                    $crate::BackendErrorKind::Unsupported,
                    $backend,
                    $detail,
                ))
            }
        }
    };
}
