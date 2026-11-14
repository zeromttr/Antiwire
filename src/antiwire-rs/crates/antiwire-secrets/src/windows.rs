#![allow(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
};
use zeroize::Zeroizing;

use crate::acl::restrict_to_owner_and_admins;
use crate::error::KeyStoreError;
use crate::keystore::{ensure_parent_dir, validate_key_length, KeyStore};
use crate::secret::SecretBytes;

/// Stores the database key encrypted with DPAPI (`LocalMachine` scope).
pub struct WindowsDpapiKeyProvider {
    key_path: PathBuf,
}

impl WindowsDpapiKeyProvider {
    pub fn new(key_path: impl Into<PathBuf>) -> Self {
        Self {
            key_path: key_path.into(),
        }
    }

    /// Cuts the key file's inherited ACL down to `SYSTEM`, Administrators, and its owner.
    fn restrict(&self) -> Result<(), KeyStoreError> {
        restrict_to_owner_and_admins(&self.key_path).map_err(|source| KeyStoreError::Acl {
            path: self.key_path.display().to_string(),
            source,
        })
    }

    fn read_error(&self, source: std::io::Error) -> KeyStoreError {
        if source.kind() == std::io::ErrorKind::PermissionDenied {
            KeyStoreError::AccessDenied {
                path: self.key_path.display().to_string(),
            }
        } else {
            KeyStoreError::Read {
                path: self.key_path.display().to_string(),
                source,
            }
        }
    }

    fn write_error(&self, source: std::io::Error) -> KeyStoreError {
        if source.kind() == std::io::ErrorKind::PermissionDenied {
            KeyStoreError::AccessDenied {
                path: self.key_path.display().to_string(),
            }
        } else {
            KeyStoreError::Write {
                path: self.key_path.display().to_string(),
                source,
            }
        }
    }

    fn protect(key: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(key.len())
                .map_err(|_| KeyStoreError::Dpapi("key is too large for DPAPI".to_owned()))?,
            pbData: key.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        // SAFETY: `input` references `key` for the duration of the call. On success, DPAPI returns
        // a valid output allocation that is copied before being released with `LocalFree`.
        unsafe {
            CryptProtectData(
                &raw const input,
                PCWSTR::null(),
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                &raw mut output,
            )
            .map_err(|err| KeyStoreError::Dpapi(err.to_string()))?;

            let protected =
                std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
            Ok(protected)
        }
    }

    fn unprotect(encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(encrypted.len()).map_err(|_| {
                KeyStoreError::Dpapi("encrypted key is too large for DPAPI".to_owned())
            })?,
            pbData: encrypted.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        // SAFETY: `input` references `encrypted` for the duration of the call. On success, DPAPI
        // returns a valid output allocation that is copied before being released with `LocalFree`.
        unsafe {
            CryptUnprotectData(&raw const input, None, None, None, None, 0, &raw mut output)
                .map_err(|err| KeyStoreError::Dpapi(err.to_string()))?;

            let mut decrypted = Zeroizing::new(
                std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec(),
            );
            std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
            let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
            Ok(std::mem::take(&mut decrypted))
        }
    }
}

impl KeyStore for WindowsDpapiKeyProvider {
    fn load_key(&self) -> Result<Option<SecretBytes>, KeyStoreError> {
        if !self.key_path.exists() {
            return Ok(None);
        }

        // Re-applied on every load, which is what repairs a key file written by a build
        // that predates this — every existing install has one, sitting in a directory
        // whose inherited ACL grants BUILTIN\Users read. Failing rather than warning
        // matches the unix provider, which refuses a key file that is not 0600 instead of
        // using it anyway.
        self.restrict()?;

        let encrypted = fs::read(&self.key_path).map_err(|source| self.read_error(source))?;

        let mut key = Self::unprotect(&encrypted)?;
        validate_key_length(&key)?;
        Ok(Some(SecretBytes::new(std::mem::take(&mut *key))))
    }

    fn save_key(&self, key: &[u8]) -> Result<(), KeyStoreError> {
        use std::io::Write as _;

        validate_key_length(key)?;
        ensure_parent_dir(&self.key_path)?;

        let encrypted = Self::protect(key)?;

        // Created empty, restricted, and only then written: the protected key never
        // exists in a file carrying the data directory's inherited ACL. That ordering
        // matters more here than it looks, because `CryptProtectData` is called with
        // CRYPTPROTECT_LOCAL_MACHINE — any process that can read this file can decrypt
        // it, so the ACL is the whole of the protection.
        let mut file =
            fs::File::create(&self.key_path).map_err(|source| self.write_error(source))?;
        self.restrict()?;
        file.write_all(&encrypted)
            .map_err(|source| self.write_error(source))?;
        file.sync_all().map_err(|source| self.write_error(source))
    }
}
