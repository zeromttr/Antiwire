//! The signed release manifest published with every GitHub release.
//!
//! `manifest.json` is plain JSON; `manifest.json.sig` is a raw 64-byte ed25519
//! signature over those exact bytes. Verify the signature before parsing.

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::UpdateError;

/// Longest release notes shown in the client's confirm dialog.
pub(crate) const MAX_NOTES_CHARS: usize = 2000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: Version,
    /// One short paragraph, shown in the client's confirm dialog.
    pub notes: String,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    pub role: FileRole,
    /// [`current_platform`] value the file is built for, e.g. `windows-x86_64`.
    pub platform: String,
    /// Release asset name. A bare file name: no separators, no `..`.
    pub name: String,
    /// Lowercase hex SHA-256 of the asset.
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileRole {
    Daemon,
    Client,
}

/// `{os}-{arch}` for this build, matching [`ManifestFile::platform`].
#[must_use]
pub fn current_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Checks `signature` over `manifest_bytes`, then parses and validates them.
///
/// # Errors
///
/// [`UpdateError::BadSignature`] when the signature does not verify (checked
/// before anything is parsed), [`UpdateError::BadManifest`] when the JSON is
/// invalid, a file name is not a bare name, a hash is not 64 lowercase hex
/// characters, or a role appears twice for one platform.
pub fn verify(
    manifest_bytes: &[u8],
    signature: &[u8],
    key: &ed25519_dalek::VerifyingKey,
) -> Result<Manifest, UpdateError> {
    verify_signature(manifest_bytes, signature, key)?;
    let manifest: Manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| UpdateError::BadManifest(error.to_string()))?;
    manifest.validate()?;
    Ok(manifest)
}

/// Checks a raw 64-byte ed25519 `signature` over `bytes`. Shared by every
/// signed manifest, and run before any of them is parsed.
pub(crate) fn verify_signature(
    bytes: &[u8],
    signature: &[u8],
    key: &ed25519_dalek::VerifyingKey,
) -> Result<(), UpdateError> {
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| UpdateError::BadSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature);
    key.verify_strict(bytes, &signature)
        .map_err(|_| UpdateError::BadSignature)
}

impl Manifest {
    /// The daemon and client files for `platform`.
    ///
    /// # Errors
    ///
    /// [`UpdateError::BadManifest`] when either role is missing.
    pub fn files_for(&self, platform: &str) -> Result<PlatformFiles<'_>, UpdateError> {
        let find = |role: FileRole| {
            self.files
                .iter()
                .find(|file| file.platform == platform && file.role == role)
                .ok_or_else(|| {
                    UpdateError::BadManifest(format!(
                        "the release has no {} file for {platform}",
                        role_name(role)
                    ))
                })
        };
        Ok(PlatformFiles {
            daemon: find(FileRole::Daemon)?,
            client: find(FileRole::Client)?,
        })
    }

    fn validate(&self) -> Result<(), UpdateError> {
        if self.notes.chars().count() > MAX_NOTES_CHARS {
            return Err(UpdateError::BadManifest(format!(
                "the notes are longer than {MAX_NOTES_CHARS} characters"
            )));
        }
        for (index, file) in self.files.iter().enumerate() {
            if !is_bare_name(&file.name) {
                return Err(UpdateError::BadManifest(format!(
                    "{:?} is not a bare file name",
                    file.name
                )));
            }
            if !is_sha256_hex(&file.sha256) {
                return Err(UpdateError::BadManifest(format!(
                    "the hash of {} is not 64 lowercase hex characters",
                    file.name
                )));
            }
            if self.files[..index]
                .iter()
                .any(|other| other.role == file.role && other.platform == file.platform)
            {
                return Err(UpdateError::BadManifest(format!(
                    "the {} file for {} is listed more than once",
                    role_name(file.role),
                    file.platform
                )));
            }
        }
        Ok(())
    }
}

/// The two files one platform needs.
#[derive(Debug, Clone, Copy)]
pub struct PlatformFiles<'a> {
    pub daemon: &'a ManifestFile,
    pub client: &'a ManifestFile,
}

fn role_name(role: FileRole) -> &'static str {
    match role {
        FileRole::Daemon => "daemon",
        FileRole::Client => "client",
    }
}

/// A single path component that cannot escape the download directory. `.` and
/// `..` are rejected by the leading-dot rule.
pub(crate) fn is_bare_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && !name.contains(['/', '\\', ':'])
        && !name.chars().any(char::is_control)
}

pub(crate) fn is_sha256_hex(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use serde_json::{json, Value};

    use super::*;

    const HASH: &str = "ab00000000000000000000000000000000000000000000000000000000000001";

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn public_key() -> VerifyingKey {
        signing_key().verifying_key()
    }

    fn sign(bytes: &[u8]) -> Vec<u8> {
        signing_key().sign(bytes).to_bytes().to_vec()
    }

    fn file(role: &str, name: &str, sha256: &str) -> Value {
        json!({
            "role": role,
            "platform": "windows-x86_64",
            "name": name,
            "sha256": sha256,
            "size": 10
        })
    }

    fn good_files() -> Value {
        json!([
            file("daemon", "antiwire-daemon.exe", HASH),
            file("client", "antiwire.exe", HASH)
        ])
    }

    fn manifest_bytes(files: &Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": "0.3.0",
            "notes": "Fixes a crash.",
            "files": files
        }))
        .expect("manifest json")
    }

    #[test]
    fn accepts_signed_manifest_and_finds_platform_files() {
        let bytes = manifest_bytes(&good_files());
        let manifest = verify(&bytes, &sign(&bytes), &public_key()).expect("valid");
        assert_eq!(manifest.version, Version::new(0, 3, 0));
        let files = manifest.files_for("windows-x86_64").expect("files");
        assert_eq!(files.daemon.name, "antiwire-daemon.exe");
        assert_eq!(files.client.name, "antiwire.exe");
    }

    #[test]
    fn rejects_tampered_manifest() {
        let bytes = manifest_bytes(&good_files());
        let signature = sign(&bytes);
        let mut tampered = bytes.clone();
        let index = tampered.len() - 3;
        tampered[index] ^= 1;
        assert!(matches!(
            verify(&tampered, &signature, &public_key()),
            Err(UpdateError::BadSignature)
        ));
    }

    #[test]
    fn rejects_signature_from_another_key() {
        let bytes = manifest_bytes(&good_files());
        let other = SigningKey::from_bytes(&[8; 32]);
        let signature = other.sign(&bytes).to_bytes().to_vec();
        assert!(matches!(
            verify(&bytes, &signature, &public_key()),
            Err(UpdateError::BadSignature)
        ));
    }

    #[test]
    fn rejects_63_byte_signature() {
        let bytes = manifest_bytes(&good_files());
        let mut signature = sign(&bytes);
        signature.pop();
        assert!(matches!(
            verify(&bytes, &signature, &public_key()),
            Err(UpdateError::BadSignature)
        ));
    }

    #[test]
    fn rejects_path_traversal_in_name() {
        let bytes = manifest_bytes(&json!([
            file("daemon", "../x", HASH),
            file("client", "antiwire.exe", HASH)
        ]));
        assert!(matches!(
            verify(&bytes, &sign(&bytes), &public_key()),
            Err(UpdateError::BadManifest(_))
        ));
    }

    #[test]
    fn rejects_uppercase_hash() {
        let bytes = manifest_bytes(&json!([
            file("daemon", "antiwire-daemon.exe", &HASH.to_uppercase()),
            file("client", "antiwire.exe", HASH)
        ]));
        assert!(matches!(
            verify(&bytes, &sign(&bytes), &public_key()),
            Err(UpdateError::BadManifest(_))
        ));
    }

    #[test]
    fn rejects_duplicate_role_for_one_platform() {
        let bytes = manifest_bytes(&json!([
            file("daemon", "antiwire-daemon.exe", HASH),
            file("daemon", "other.exe", HASH),
            file("client", "antiwire.exe", HASH)
        ]));
        assert!(matches!(
            verify(&bytes, &sign(&bytes), &public_key()),
            Err(UpdateError::BadManifest(_))
        ));
    }

    #[test]
    fn rejects_unknown_field() {
        let bytes = serde_json::to_vec(&json!({
            "version": "0.3.0",
            "notes": "Fixes a crash.",
            "files": good_files(),
            "extra": true
        }))
        .expect("manifest json");
        assert!(matches!(
            verify(&bytes, &sign(&bytes), &public_key()),
            Err(UpdateError::BadManifest(_))
        ));
    }

    #[test]
    fn files_for_names_the_missing_role() {
        let bytes = manifest_bytes(&json!([file("daemon", "antiwire-daemon.exe", HASH)]));
        let manifest = verify(&bytes, &sign(&bytes), &public_key()).expect("valid");
        match manifest.files_for("windows-x86_64") {
            Err(UpdateError::BadManifest(message)) => assert!(message.contains("client")),
            other => panic!("expected a missing client error, got {other:?}"),
        }
    }
}
