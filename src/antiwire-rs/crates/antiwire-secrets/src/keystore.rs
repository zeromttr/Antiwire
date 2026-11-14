use std::fs;
use std::path::Path;

use crate::error::KeyStoreError;
use crate::secret::SecretBytes;

/// Length of the database encryption key in bytes (AES-256).
pub const DB_KEY_LEN: usize = 32;

/// Persists and loads database encryption keys from platform-specific secure storage.
pub trait KeyStore {
    /// Loads the key, returning `None` when no key has been created.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform store cannot be read or contains an invalid key.
    fn load_key(&self) -> Result<Option<SecretBytes>, KeyStoreError>;

    /// Persists a database key.
    ///
    /// # Errors
    ///
    /// Returns an error when the key has the wrong length or cannot be persisted securely.
    fn save_key(&self, key: &[u8]) -> Result<(), KeyStoreError>;
}

/// Creates the directory that will hold `key_path`, if it has one.
pub(crate) fn ensure_parent_dir(key_path: &Path) -> Result<(), KeyStoreError> {
    let Some(parent) = key_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|source| KeyStoreError::Write {
        path: parent.display().to_string(),
        source,
    })
}

pub(crate) fn validate_key_length(key: &[u8]) -> Result<(), KeyStoreError> {
    if key.len() == DB_KEY_LEN {
        Ok(())
    } else {
        Err(KeyStoreError::InvalidKeyLength)
    }
}
