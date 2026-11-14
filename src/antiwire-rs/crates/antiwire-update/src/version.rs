//! The single product version shared by the daemon, the helper, and the client.

use semver::Version;

/// The product version this binary was built as. The workspace version is the
/// source; CI checks that the client's `package.json` and the packaging workflow agree.
pub const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// [`PRODUCT_VERSION`] parsed.
///
/// # Panics
///
/// Never in practice: Cargo rejects a package version that is not semver.
#[must_use]
pub fn product_version() -> Version {
    Version::parse(PRODUCT_VERSION).expect("Cargo package versions are semver")
}
