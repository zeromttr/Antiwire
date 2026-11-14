//! The Rust verifier accepts what `scripts/release-manifest.mjs` publishes.
//!
//! `fixtures/` was written by that script with the test-only seed of 32 `0x07`
//! bytes, the same key the unit tests sign with. Regenerate it with:
//!
//! ```text
//! ANTIWIRE_UPDATE_SIGNING_KEY=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc= \
//!   node scripts/release-manifest.mjs build --version 0.2.0 --notes-file notes.md \
//!   --out src/antiwire-rs/crates/antiwire-update/tests/fixtures --platform windows-x86_64 \
//!   --daemon antiwire-daemon-0.2.0-windows-x86_64.exe --client antiwire-0.2.0-windows-x86_64.exe
//! ```
//!
//! where the two files hold `daemon bytes` and `client bytes`.
//!
//! `manifest-linux.json` comes from the script's `packages` command, with the same seed:
//!
//! ```text
//! ANTIWIRE_UPDATE_SIGNING_KEY=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc= //!   node scripts/release-manifest.mjs packages --version 0.2.0 --notes-file notes.md //!   --out src/antiwire-rs/crates/antiwire-update/tests/fixtures --platform linux-x86_64 //!   --deb antiwire_0.2.0_amd64.deb --rpm antiwire-0.2.0-1.x86_64.rpm
//! ```
//!
//! where the two packages hold `deb bytes` and `rpm bytes!`.

use antiwire_update::manifest::{self, FileRole};
use antiwire_update::package::{self, PackageFormat};
use ed25519_dalek::SigningKey;
use semver::Version;

const MANIFEST: &[u8] = include_bytes!("fixtures/manifest.json");
const SIGNATURE: &[u8] = include_bytes!("fixtures/manifest.json.sig");
const PACKAGE_MANIFEST: &[u8] = include_bytes!("fixtures/manifest-linux.json");
const PACKAGE_SIGNATURE: &[u8] = include_bytes!("fixtures/manifest-linux.json.sig");

#[test]
fn script_manifest_verifies_and_parses() {
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let manifest = manifest::verify(MANIFEST, SIGNATURE, &key).expect("script output verifies");

    assert_eq!(manifest.version, Version::new(0, 2, 0));
    let files = manifest.files_for("windows-x86_64").expect("both roles");
    assert_eq!(files.daemon.role, FileRole::Daemon);
    assert_eq!(
        files.daemon.name,
        "antiwire-daemon-0.2.0-windows-x86_64.exe"
    );
    assert_eq!(files.client.size, 12);
}

#[test]
fn script_manifest_rejects_another_key() {
    let other = SigningKey::from_bytes(&[8; 32]).verifying_key();
    assert!(manifest::verify(MANIFEST, SIGNATURE, &other).is_err());
}

#[test]
fn script_package_manifest_verifies_and_parses() {
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let manifest =
        package::verify(PACKAGE_MANIFEST, PACKAGE_SIGNATURE, &key).expect("script output verifies");

    assert_eq!(manifest.version, Version::new(0, 2, 0));
    let deb = manifest
        .package_for("linux-x86_64", PackageFormat::Deb)
        .expect("deb");
    assert_eq!(deb.name, "antiwire_0.2.0_amd64.deb");
    assert_eq!(deb.size, 9);
    let rpm = manifest
        .package_for("linux-x86_64", PackageFormat::Rpm)
        .expect("rpm");
    assert_eq!(rpm.size, 10);
}

#[test]
fn the_two_manifests_cannot_be_swapped() {
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    // Each is signed, but neither parses as the other, so an old daemon reading
    // manifest.json is never handed packages, and a Linux daemon never trees.
    assert!(manifest::verify(PACKAGE_MANIFEST, PACKAGE_SIGNATURE, &key).is_err());
    assert!(package::verify(MANIFEST, SIGNATURE, &key).is_err());
}
