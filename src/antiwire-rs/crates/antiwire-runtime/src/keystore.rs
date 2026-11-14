//! The key store that protects the database, per platform.

use antiwire_platform::DataPaths;

/// The key store for the database in `data_paths`. The runtime and the
/// orphaned-state revert both open the database through it.
pub(crate) fn platform_keystore(data_paths: &DataPaths) -> impl antiwire_secrets::KeyStore + use<> {
    #[cfg(windows)]
    {
        antiwire_secrets::WindowsDpapiKeyProvider::new(data_paths.db_key())
    }

    #[cfg(not(windows))]
    {
        antiwire_secrets::UnixSecureFileKeyProvider::new(data_paths.db_key())
    }
}
