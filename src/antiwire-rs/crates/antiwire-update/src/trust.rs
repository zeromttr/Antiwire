//! Where releases come from and the key that signs them.
//!
//! Releases are the GitHub Releases of the project's repository, published and
//! signed by CI. The repository is compiled in from `[workspace.package]
//! repository` in `src/antiwire-rs/Cargo.toml`, and every URL is built from it,
//! so neither the UI, a settings file, nor the manifest can point the daemon
//! at another host. The public key is compiled in from the release build's
//! environment; a build without it (every local and test build) reports
//! updates as unsupported.

use ed25519_dalek::VerifyingKey;
use semver::Version;

use crate::Channel;

/// The project's repository, `https://github.com/{owner}/{name}`, from
/// `[workspace.package] repository`. Its `/releases` hosts every release.
pub const REPOSITORY_URL: &str = env!("CARGO_PKG_REPOSITORY");

/// Name of the signed manifest asset in each release.
pub const MANIFEST_ASSET: &str = "manifest.json";

/// Name of the signed Linux package manifest asset (see [`crate::package`]).
pub const PACKAGE_MANIFEST_ASSET: &str = "manifest-linux.json";

/// The compiled-in release feed.
#[derive(Debug, Clone)]
pub struct Trust {
    releases_url: String,
    pub public_key: VerifyingKey,
}

impl Trust {
    /// The feed baked into this build, if any.
    ///
    /// `ANTIWIRE_UPDATE_PUBLIC_KEY` (32 bytes, standard base64) is read at
    /// compile time. Missing or malformed gives `None`.
    #[must_use]
    pub fn compiled() -> Option<Self> {
        Self::new(
            format!("{REPOSITORY_URL}/releases"),
            option_env!("ANTIWIRE_UPDATE_PUBLIC_KEY")?,
        )
    }

    /// A feed rooted at `releases_url` (a GitHub `/releases` URL, or a test
    /// server laid out the same way). `None` unless the URL is HTTPS and the key
    /// decodes to a valid ed25519 point.
    #[must_use]
    pub fn new(releases_url: impl Into<String>, public_key_base64: &str) -> Option<Self> {
        let releases_url = releases_url.into();
        if !releases_url.starts_with("https://") {
            return None;
        }
        let bytes = data_encoding::BASE64
            .decode(public_key_base64.trim().as_bytes())
            .ok()?;
        let bytes: [u8; 32] = bytes.try_into().ok()?;
        Some(Self {
            releases_url: releases_url.trim_end_matches('/').to_owned(),
            public_key: VerifyingKey::from_bytes(&bytes).ok()?,
        })
    }

    /// `asset` of the newest release in `channel`'s feed.
    ///
    /// The stable feed is GitHub's `latest` redirect, which goes to the newest
    /// non-prerelease, non-draft release and is what daemons from before
    /// channels read. The other feeds are fixed `channel-{name}` releases,
    /// whose manifests CI replaces with those of the channel's newest release.
    #[must_use]
    pub fn feed_url(&self, channel: Channel, asset: &str) -> String {
        match channel {
            Channel::Stable => format!("{}/latest/download/{asset}", self.releases_url),
            other => format!("{}/download/channel-{other}/{asset}", self.releases_url),
        }
    }

    /// The newest release's manifest. GitHub redirects `latest` to the newest
    /// non-prerelease, non-draft release.
    #[must_use]
    pub fn latest_manifest_url(&self) -> String {
        self.feed_url(Channel::Stable, MANIFEST_ASSET)
    }

    /// The detached ed25519 signature over the latest manifest's bytes.
    #[must_use]
    pub fn latest_signature_url(&self) -> String {
        format!("{}.sig", self.latest_manifest_url())
    }

    /// The newest release's Linux package manifest.
    #[must_use]
    pub fn latest_package_manifest_url(&self) -> String {
        self.feed_url(Channel::Stable, PACKAGE_MANIFEST_ASSET)
    }

    /// The Linux package manifest of a specific release, used to find the
    /// running version's package for rollback.
    #[must_use]
    pub fn package_manifest_url(&self, version: &Version) -> String {
        self.asset_url(version, PACKAGE_MANIFEST_ASSET)
    }

    /// The detached signature beside any manifest URL.
    #[must_use]
    pub fn signature_url(manifest_url: &str) -> String {
        format!("{manifest_url}.sig")
    }

    /// An asset of a specific release. Asset names come from the verified
    /// manifest; the host and path never do.
    #[must_use]
    pub fn asset_url(&self, version: &Version, name: &str) -> String {
        format!("{}/download/v{version}/{name}", self.releases_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    const RELEASES: &str = "https://github.com/example/antiwire/releases";

    fn is_git_suffixed(name: &str) -> bool {
        std::path::Path::new(name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("git"))
    }

    #[test]
    fn the_compiled_in_repository_is_a_plain_github_url() {
        let path = REPOSITORY_URL
            .strip_prefix("https://github.com/")
            .expect("a GitHub URL");
        let parts: Vec<&str> = path.split('/').collect();
        assert_eq!(parts.len(), 2, "owner/name, not {REPOSITORY_URL}");
        assert!(parts
            .iter()
            .all(|part| !part.is_empty() && !is_git_suffixed(part)));
    }

    #[test]
    fn rejects_plain_http() {
        assert!(Trust::new("http://example.com/releases", KEY).is_none());
    }

    #[test]
    fn rejects_short_key() {
        assert!(Trust::new(RELEASES, "AAAA").is_none());
    }

    #[test]
    fn builds_github_release_urls() {
        let trust = Trust::new(RELEASES, KEY).expect("valid feed");
        assert_eq!(
            trust.latest_signature_url(),
            "https://github.com/example/antiwire/releases/latest/download/manifest.json.sig"
        );
        assert_eq!(
            trust.asset_url(&Version::new(0, 2, 0), "antiwire-daemon.exe"),
            "https://github.com/example/antiwire/releases/download/v0.2.0/antiwire-daemon.exe"
        );
    }

    #[test]
    fn builds_package_manifest_urls() {
        let trust = Trust::new(RELEASES, KEY).expect("valid feed");
        assert_eq!(
            Trust::signature_url(&trust.latest_package_manifest_url()),
            "https://github.com/example/antiwire/releases/latest/download/manifest-linux.json.sig"
        );
        assert_eq!(
            trust.package_manifest_url(&Version::new(0, 2, 0)),
            "https://github.com/example/antiwire/releases/download/v0.2.0/manifest-linux.json"
        );
    }

    #[test]
    fn each_channel_has_its_own_feed() {
        let trust = Trust::new(RELEASES, KEY).expect("valid feed");
        assert_eq!(
            trust.feed_url(Channel::Stable, MANIFEST_ASSET),
            trust.latest_manifest_url()
        );
        assert_eq!(
            trust.feed_url(Channel::Beta, MANIFEST_ASSET),
            "https://github.com/example/antiwire/releases/download/channel-beta/manifest.json"
        );
        assert_eq!(
            trust.feed_url(Channel::Nightly, PACKAGE_MANIFEST_ASSET),
            "https://github.com/example/antiwire/releases/download/channel-nightly/manifest-linux.json"
        );
    }
}
