//! Linux updates: the signed package manifest and the plan the helper follows.
//!
//! On Linux the daemon is installed by a `.deb` or `.rpm`, and the package
//! manager owns its files. An update installs the next release's package with
//! that package manager instead of swapping version trees, so Linux has its own
//! signed manifest, `manifest-linux.json`, listing one package per platform and
//! format. It is a separate file because `manifest.json` rejects unknown fields
//! and roles: adding packages to it would make every Windows and macOS daemon
//! already installed refuse the manifest and stop seeing updates.
//!
//! The daemon downloads the new package and the running version's package (kept
//! for rollback), writes a [`PackagePlan`] beside them, and starts the helper.
//! The helper ([`crate::package_apply`]) reads the plan, never the network.

use std::path::Path;

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::manifest::{is_bare_name, is_sha256_hex, verify_signature, MAX_NOTES_CHARS};
use crate::UpdateError;

/// The two package formats a release publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageFormat {
    Deb,
    Rpm,
}

impl PackageFormat {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Deb => "deb",
            Self::Rpm => "rpm",
        }
    }
}

impl std::fmt::Display for PackageFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

/// `manifest-linux.json`, published with every release that has Linux builds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    pub version: Version,
    /// One short paragraph, shown in the client's confirm dialog.
    pub notes: String,
    pub packages: Vec<PackageFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    /// [`crate::manifest::current_platform`] value, e.g. `linux-x86_64`.
    pub platform: String,
    pub format: PackageFormat,
    /// Release asset name. A bare file name: no separators, no `..`.
    pub name: String,
    /// Lowercase hex SHA-256 of the asset.
    pub sha256: String,
    pub size: u64,
}

/// Checks `signature` over `manifest_bytes`, then parses and validates them.
///
/// # Errors
///
/// [`UpdateError::BadSignature`] when the signature does not verify (checked
/// before anything is parsed), [`UpdateError::BadManifest`] when the JSON is
/// invalid, a name is not a bare file name, a hash is malformed, or a platform
/// lists one format twice.
pub fn verify(
    manifest_bytes: &[u8],
    signature: &[u8],
    key: &ed25519_dalek::VerifyingKey,
) -> Result<PackageManifest, UpdateError> {
    verify_signature(manifest_bytes, signature, key)?;
    let manifest: PackageManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| UpdateError::BadManifest(error.to_string()))?;
    manifest.validate()?;
    Ok(manifest)
}

impl PackageManifest {
    /// The package for `platform` in `format`.
    ///
    /// # Errors
    ///
    /// [`UpdateError::BadManifest`] when the release has none.
    pub fn package_for(
        &self,
        platform: &str,
        format: PackageFormat,
    ) -> Result<&PackageFile, UpdateError> {
        self.packages
            .iter()
            .find(|package| package.platform == platform && package.format == format)
            .ok_or_else(|| {
                UpdateError::BadManifest(format!("the release has no .{format} for {platform}"))
            })
    }

    /// Whether the release has any package for `platform`, used when the
    /// install's format is unknown and the update is only reported.
    #[must_use]
    pub fn has_platform(&self, platform: &str) -> bool {
        self.packages
            .iter()
            .any(|package| package.platform == platform)
    }

    fn validate(&self) -> Result<(), UpdateError> {
        if self.notes.chars().count() > MAX_NOTES_CHARS {
            return Err(UpdateError::BadManifest(format!(
                "the notes are longer than {MAX_NOTES_CHARS} characters"
            )));
        }
        for (index, package) in self.packages.iter().enumerate() {
            if !is_bare_name(&package.name) {
                return Err(UpdateError::BadManifest(format!(
                    "{:?} is not a bare file name",
                    package.name
                )));
            }
            if !is_sha256_hex(&package.sha256) {
                return Err(UpdateError::BadManifest(format!(
                    "the hash of {} is not 64 lowercase hex characters",
                    package.name
                )));
            }
            if self.packages[..index]
                .iter()
                .any(|other| other.platform == package.platform && other.format == package.format)
            {
                return Err(UpdateError::BadManifest(format!(
                    "the .{} for {} is listed more than once",
                    package.format, package.platform
                )));
            }
        }
        Ok(())
    }
}

/// Name of the plan file in the version's `verified` directory.
pub const PLAN_FILE: &str = "package-update.json";

/// What the helper installs, written by the daemon beside the verified files.
///
/// The files are named relative to the directory holding the plan. The data
/// directory is writable only by root, as on the other platforms, so the
/// helper trusts the plan and the hashes the daemon already checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePlan {
    pub format: PackageFormat,
    /// The new release's package.
    pub package: String,
    /// The running version's package, reinstalled if the new one fails. `None`
    /// when it could not be obtained; the install then has no rollback.
    pub rollback: Option<String>,
}

impl PackagePlan {
    /// Reads the plan in `dir`.
    ///
    /// # Errors
    ///
    /// When the file is missing or invalid, or names a path outside `dir`.
    pub fn load(dir: &Path) -> Result<Self, UpdateError> {
        let path = dir.join(PLAN_FILE);
        let bytes = std::fs::read(&path).map_err(|error| UpdateError::io("read", &path, error))?;
        let plan: Self = serde_json::from_slice(&bytes)
            .map_err(|error| UpdateError::BadManifest(format!("{PLAN_FILE}: {error}")))?;
        let names = std::iter::once(&plan.package).chain(plan.rollback.as_ref());
        for name in names {
            if !is_bare_name(name) {
                return Err(UpdateError::BadManifest(format!(
                    "{PLAN_FILE} names {name:?}, which is not a bare file name"
                )));
            }
        }
        Ok(plan)
    }

    /// Writes the plan into `dir`.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn store(&self, dir: &Path) -> Result<(), UpdateError> {
        let path = dir.join(PLAN_FILE);
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| {
            UpdateError::io(
                "serialize",
                &path,
                std::io::Error::new(std::io::ErrorKind::InvalidData, error),
            )
        })?;
        std::fs::write(&path, bytes).map_err(|error| UpdateError::io("write", &path, error))
    }
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

    fn package(platform: &str, format: &str, name: &str) -> Value {
        json!({
            "platform": platform,
            "format": format,
            "name": name,
            "sha256": HASH,
            "size": 10
        })
    }

    fn manifest_bytes(packages: &Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": "0.3.0",
            "notes": "Faster start-up.",
            "packages": packages
        }))
        .expect("json")
    }

    fn good() -> Vec<u8> {
        manifest_bytes(&json!([
            package("linux-x86_64", "deb", "antiwire_0.3.0_amd64.deb"),
            package("linux-x86_64", "rpm", "antiwire-0.3.0-1.x86_64.rpm"),
            package("linux-aarch64", "deb", "antiwire_0.3.0_arm64.deb"),
        ]))
    }

    #[test]
    fn verifies_and_finds_each_format() {
        let bytes = good();
        let manifest = verify(&bytes, &sign(&bytes), &public_key()).expect("valid");
        assert_eq!(manifest.version, Version::new(0, 3, 0));
        let deb = manifest
            .package_for("linux-x86_64", PackageFormat::Deb)
            .expect("deb");
        assert_eq!(deb.name, "antiwire_0.3.0_amd64.deb");
        let rpm = manifest
            .package_for("linux-x86_64", PackageFormat::Rpm)
            .expect("rpm");
        assert_eq!(rpm.name, "antiwire-0.3.0-1.x86_64.rpm");
        assert!(manifest
            .package_for("linux-aarch64", PackageFormat::Rpm)
            .is_err());
        assert!(manifest.has_platform("linux-aarch64"));
        assert!(!manifest.has_platform("linux-riscv64"));
    }

    #[test]
    fn rejects_a_bad_signature_before_parsing() {
        let bytes = b"not json".to_vec();
        let mut signature = sign(&bytes);
        signature[0] ^= 1;
        assert!(matches!(
            verify(&bytes, &signature, &public_key()),
            Err(UpdateError::BadSignature)
        ));
    }

    #[test]
    fn rejects_the_tree_manifest() {
        // A manifest.json must never be mistaken for the package manifest.
        let bytes = serde_json::to_vec(&json!({
            "version": "0.3.0",
            "notes": "x",
            "files": []
        }))
        .expect("json");
        assert!(matches!(
            verify(&bytes, &sign(&bytes), &public_key()),
            Err(UpdateError::BadManifest(_))
        ));
    }

    #[test]
    fn rejects_a_path_in_a_name() {
        let bytes = manifest_bytes(&json!([package("linux-x86_64", "deb", "../evil.deb")]));
        assert!(matches!(
            verify(&bytes, &sign(&bytes), &public_key()),
            Err(UpdateError::BadManifest(_))
        ));
    }

    #[test]
    fn rejects_a_format_listed_twice() {
        let bytes = manifest_bytes(&json!([
            package("linux-x86_64", "deb", "a.deb"),
            package("linux-x86_64", "deb", "b.deb"),
        ]));
        assert!(matches!(
            verify(&bytes, &sign(&bytes), &public_key()),
            Err(UpdateError::BadManifest(_))
        ));
    }

    #[test]
    fn plan_round_trips_and_refuses_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = PackagePlan {
            format: PackageFormat::Rpm,
            package: "antiwire-0.3.0-1.x86_64.rpm".to_owned(),
            rollback: Some("antiwire-0.2.0-1.x86_64.rpm".to_owned()),
        };
        plan.store(dir.path()).expect("store");
        assert_eq!(PackagePlan::load(dir.path()).expect("load"), plan);

        let escaping = PackagePlan {
            rollback: Some("../../etc/passwd".to_owned()),
            ..plan
        };
        escaping.store(dir.path()).expect("store");
        assert!(PackagePlan::load(dir.path()).is_err());
    }
}
