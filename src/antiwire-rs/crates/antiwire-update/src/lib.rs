//! Signed release feed, staging, and the install swap.
//!
//! Design: `tasks/update-plan.md`. The daemon checks the manifest on its own and
//! reports what it found ([`service`]). Nothing is downloaded or installed until
//! the client calls `InstallUpdate`. The swap itself runs in a one-shot helper
//! process started from the new version's tree ([`apply`]), so stopping the
//! daemon service does not stop the swap. On Linux the package manager owns
//! the install, and an update installs the next release's package instead
//! ([`package`]).

pub mod apply;
pub mod channel;
pub mod error;
pub mod launcher;
pub mod manifest;
pub mod package;
pub mod package_apply;
pub mod package_install;
pub mod paths;
pub mod service;
pub mod service_control;
pub mod state;
pub mod status;
pub mod trust;
pub mod version;

pub use channel::Channel;
pub use error::UpdateError;
pub use paths::UpdatePaths;
pub use service::{recover_interrupted_install, UpdateService, UpdateSupport};
pub use status::{UpdateState, UpdateStatus};
pub use version::PRODUCT_VERSION;
