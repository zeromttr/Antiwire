use std::fs;
use std::io::{ErrorKind, Read};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::error::KeyStoreError;
use crate::keystore::{ensure_parent_dir, validate_key_length, KeyStore, DB_KEY_LEN};
use crate::secret::SecretBytes;

/// Stores the database key as a plaintext file with `0600` permissions.
pub struct UnixSecureFileKeyProvider {
    key_path: PathBuf,
}

impl UnixSecureFileKeyProvider {
    pub fn new(key_path: impl Into<PathBuf>) -> Self {
        Self {
            key_path: key_path.into(),
        }
    }
}

impl KeyStore for UnixSecureFileKeyProvider {
    fn load_key(&self) -> Result<Option<SecretBytes>, KeyStoreError> {
        #[cfg(unix)]
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);

        let mut file = match options.open(&self.key_path) {
            Ok(file) => file,
            Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(if source.kind() == ErrorKind::PermissionDenied {
                    KeyStoreError::AccessDenied {
                        path: self.key_path.display().to_string(),
                    }
                } else {
                    KeyStoreError::Read {
                        path: self.key_path.display().to_string(),
                        source,
                    }
                });
            }
        };

        let metadata = file.metadata().map_err(|source| KeyStoreError::Read {
            path: self.key_path.display().to_string(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(KeyStoreError::Read {
                path: self.key_path.display().to_string(),
                source: std::io::Error::new(
                    ErrorKind::InvalidData,
                    "key path is not a regular file",
                ),
            });
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(KeyStoreError::InsecurePermissions);
        }

        let mut key = Zeroizing::new(vec![0_u8; DB_KEY_LEN]);
        file.read_exact(key.as_mut_slice())
            .map_err(|source| KeyStoreError::Read {
                path: self.key_path.display().to_string(),
                source,
            })?;
        let mut trailing = [0_u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|source| KeyStoreError::Read {
                path: self.key_path.display().to_string(),
                source,
            })?
            != 0
        {
            return Err(KeyStoreError::InvalidKeyLength);
        }
        validate_key_length(&key)?;

        Ok(Some(SecretBytes::new(std::mem::take(&mut *key))))
    }

    fn save_key(&self, key: &[u8]) -> Result<(), KeyStoreError> {
        validate_key_length(key)?;
        ensure_parent_dir(&self.key_path)?;

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&self.key_path)
                .map_err(|source| {
                    if source.kind() == ErrorKind::PermissionDenied {
                        KeyStoreError::AccessDenied {
                            path: self.key_path.display().to_string(),
                        }
                    } else {
                        KeyStoreError::Write {
                            path: self.key_path.display().to_string(),
                            source,
                        }
                    }
                })?;

            let metadata = file.metadata().map_err(|source| KeyStoreError::Write {
                path: self.key_path.display().to_string(),
                source,
            })?;
            if !metadata.is_file() {
                return Err(KeyStoreError::Write {
                    path: self.key_path.display().to_string(),
                    source: std::io::Error::new(
                        ErrorKind::InvalidData,
                        "key path is not a regular file",
                    ),
                });
            }

            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|source| KeyStoreError::Write {
                    path: self.key_path.display().to_string(),
                    source,
                })?;
            file.set_len(0).map_err(|source| KeyStoreError::Write {
                path: self.key_path.display().to_string(),
                source,
            })?;
            file.write_all(key).map_err(|source| KeyStoreError::Write {
                path: self.key_path.display().to_string(),
                source,
            })?;
            file.sync_all().map_err(|source| KeyStoreError::Write {
                path: self.key_path.display().to_string(),
                source,
            })?;
        }

        #[cfg(not(unix))]
        {
            fs::write(&self.key_path, key).map_err(|source| KeyStoreError::Write {
                path: self.key_path.display().to_string(),
                source,
            })?;
        }

        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn unix_secure_file_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("dbkey.bin");
        let provider = UnixSecureFileKeyProvider::new(&key_path);
        let key = [0x42_u8; DB_KEY_LEN];

        assert!(provider.load_key().expect("load").is_none());

        provider.save_key(&key).expect("save");

        let metadata = fs::metadata(&key_path).expect("metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        let loaded = provider
            .load_key()
            .expect("load")
            .expect("key should exist");
        assert_eq!(loaded.expose_secret(), &key);
    }

    #[test]
    fn rejects_trailing_key_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("dbkey.bin");
        fs::write(&key_path, [0x42_u8; DB_KEY_LEN + 1]).expect("write");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("permissions");

        let provider = UnixSecureFileKeyProvider::new(&key_path);
        assert!(matches!(
            provider.load_key(),
            Err(KeyStoreError::InvalidKeyLength)
        ));
    }

    #[test]
    fn refuses_symlink_key_paths() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.bin");
        let link = dir.path().join("dbkey.bin");
        fs::write(&target, [0x42_u8; DB_KEY_LEN]).expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("permissions");
        symlink(&target, &link).expect("symlink");

        let provider = UnixSecureFileKeyProvider::new(&link);
        assert!(provider.load_key().is_err());
        assert!(provider.save_key(&[7; DB_KEY_LEN]).is_err());
        assert_eq!(
            fs::read(target).expect("unchanged target"),
            [0x42; DB_KEY_LEN]
        );
    }
}
