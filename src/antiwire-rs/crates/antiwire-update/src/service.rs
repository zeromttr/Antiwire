//! The daemon-side updater: checks the feed, reports status, and stages an
//! install when the client asks for one.
//!
//! Checking runs on a timer and fetches only the manifest and its signature.
//! [`UpdateService::request_install`] is the only path that downloads release
//! files or starts the helper, and the gRPC `InstallUpdate` handler is its only
//! caller.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use antiwire_downloader::{DownloadClient, DownloadConfig, DownloadError};
use data_encoding::HEXLOWER;
use parking_lot::Mutex;
use semver::Version;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::apply::{remove_dir_if_present, remove_file_if_present};
use crate::channel::Channel;
use crate::launcher::HelperLauncher;
use crate::manifest::{self, Manifest, ManifestFile};
use crate::package::{self, PackageFile, PackageFormat, PackageManifest, PackagePlan};
use crate::package_install;
use crate::state::{new_request_id, ApplyPhase, InstallState, PendingInstall};
use crate::status::{AvailableRelease, UpdateState, UpdateStatus};
use crate::trust::{Trust, MANIFEST_ASSET, PACKAGE_MANIFEST_ASSET};
use crate::version::product_version;
use crate::{UpdateError, UpdatePaths};

/// How often the daemon re-reads the manifest.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// A manual check this soon after the last one returns that result instead of
/// asking GitHub again.
const MANUAL_CHECK_COOLDOWN: Duration = Duration::from_secs(5);

/// Delay before the first check, so it does not compete with start-up.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(2 * 60);

/// How long after launching the helper this daemon waits to be stopped by it
/// before treating the install as abandoned. Longer than the helper's stop
/// budget (`service_control::STOP_TIMEOUT`).
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(3 * 60);

/// Largest manifest or signature the daemon will read.
const MANIFEST_MAX_BYTES: u64 = 64 * 1024;

/// Whether this daemon can update itself, decided once at start-up.
#[derive(Debug, Clone)]
pub enum UpdateSupport {
    /// Windows and macOS: versioned install trees the helper swaps between.
    Supported { paths: UpdatePaths, trust: Trust },
    /// Linux: the package manager installed this daemon from a package in
    /// `format`, and an update installs the next release's package
    /// ([`crate::package`]).
    Package {
        paths: UpdatePaths,
        trust: Trust,
        format: PackageFormat,
    },
    /// Checks still run when a feed is known, so the client can say a newer
    /// version exists, but installs are refused with this reason.
    Unsupported {
        reason: String,
        trust: Option<Trust>,
    },
}

/// The facts [`decide`] needs about the running daemon.
struct Environment {
    release_build: bool,
    is_service: bool,
    platform_supported: bool,
}

impl UpdateSupport {
    /// Decides support for the running daemon.
    ///
    /// On Windows and macOS, supported only when all hold: a release build,
    /// running as the platform service (`is_service`), a compiled-in
    /// [`Trust`], and `daemon_exe` in the versioned layout
    /// ([`UpdatePaths::from_daemon_exe`]). On Linux the last requirement is
    /// instead that a `.deb` or `.rpm` owns `daemon_exe`.
    #[must_use]
    pub fn detect(data_dir: &Path, daemon_exe: &Path, is_service: bool) -> Self {
        let environment = Environment {
            release_build: !cfg!(debug_assertions),
            is_service,
            platform_supported: cfg!(any(windows, target_os = "macos", target_os = "linux")),
        };
        if cfg!(target_os = "linux") {
            // Asking the package database is skipped where it cannot matter.
            let format = (environment.release_build && environment.is_service)
                .then(|| package_install::owner_format(daemon_exe))
                .flatten();
            return decide_package(&environment, Trust::compiled(), data_dir, format);
        }
        let layout = UpdatePaths::from_daemon_exe(data_dir, daemon_exe);
        let recorded = layout.as_ref().is_some_and(recorded_as_current);
        decide(&environment, Trust::compiled(), layout, recorded)
    }
}

/// Picks the first failing requirement, or [`UpdateSupport::Supported`] when
/// none fails. Pure, so each reason can be tested without touching the build.
fn decide(
    environment: &Environment,
    trust: Option<Trust>,
    layout: Option<UpdatePaths>,
    recorded: bool,
) -> UpdateSupport {
    let checks = [
        (environment.release_build, "this is a development build"),
        (
            environment.is_service,
            "Antiwire is not running as a service",
        ),
        (
            environment.platform_supported,
            "updates are only installed on Windows, macOS, and Linux",
        ),
        (trust.is_some(), "this build has no release signing key"),
        (
            layout.is_some(),
            "Antiwire was not installed in the versioned layout",
        ),
        (
            recorded,
            "the install state does not record this version as installed",
        ),
    ];
    let blocker = checks
        .iter()
        .find_map(|&(passed, reason)| (!passed).then_some(reason));
    match (blocker, trust, layout) {
        (None, Some(trust), Some(paths)) => UpdateSupport::Supported { paths, trust },
        (blocker, trust, _) => UpdateSupport::Unsupported {
            reason: blocker
                .unwrap_or("Antiwire cannot update itself")
                .to_owned(),
            trust,
        },
    }
}

/// [`decide`] for a Linux install, where the package manager owns the files.
fn decide_package(
    environment: &Environment,
    trust: Option<Trust>,
    data_dir: &Path,
    format: Option<PackageFormat>,
) -> UpdateSupport {
    let checks = [
        (environment.release_build, "this is a development build"),
        (
            environment.is_service,
            "Antiwire is not running as a service",
        ),
        (trust.is_some(), "this build has no release signing key"),
        (
            format.is_some(),
            "Antiwire was not installed from its .deb or .rpm package; \
             update it the way it was installed",
        ),
    ];
    let blocker = checks
        .iter()
        .find_map(|&(passed, reason)| (!passed).then_some(reason));
    match (blocker, trust, format) {
        (None, Some(trust), Some(format)) => UpdateSupport::Package {
            paths: UpdatePaths::for_package(data_dir),
            trust,
            format,
        },
        (blocker, trust, _) => UpdateSupport::Unsupported {
            reason: blocker
                .unwrap_or("Antiwire cannot update itself")
                .to_owned(),
            trust,
        },
    }
}

fn recorded_as_current(paths: &UpdatePaths) -> bool {
    match InstallState::load(&paths.install_state()) {
        Ok(state) => state.current.as_ref() == Some(&product_version()),
        Err(error) => {
            warn!(error = %error, "install state could not be read");
            false
        }
    }
}

/// Shared by the gRPC handlers and the background checker.
/// Reads the update channel the user chose, at each check.
pub type ChannelSource = Arc<dyn Fn() -> Channel + Send + Sync>;

pub struct UpdateService {
    support: UpdateSupport,
    launcher: Arc<dyn HelperLauncher>,
    download: DownloadClient,
    channel: ChannelSource,
    inner: Mutex<Inner>,
    /// Held for the whole of a check, so a manual check and the timer never
    /// run at once and a second click waits for the first result.
    check_lock: tokio::sync::Mutex<()>,
}

/// A verified release newer than the running version, from whichever
/// manifest this platform reads.
#[derive(Debug, Clone)]
enum Release {
    Tree(Manifest),
    Package(PackageManifest),
}

impl Release {
    fn version(&self) -> &Version {
        match self {
            Self::Tree(manifest) => &manifest.version,
            Self::Package(manifest) => &manifest.version,
        }
    }

    fn notes(&self) -> &str {
        match self {
            Self::Tree(manifest) => &manifest.notes,
            Self::Package(manifest) => &manifest.notes,
        }
    }
}

/// Which manifest the checker reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestKind {
    Tree,
    /// `None` when the install's format is unknown: a newer release is then
    /// reported, but cannot be installed.
    Packages(Option<PackageFormat>),
}

/// A release file the daemon downloads: a tree file or a package.
struct Asset<'a> {
    name: &'a str,
    sha256: &'a str,
    size: u64,
}

impl<'a> From<&'a ManifestFile> for Asset<'a> {
    fn from(file: &'a ManifestFile) -> Self {
        Self {
            name: &file.name,
            sha256: &file.sha256,
            size: file.size,
        }
    }
}

impl<'a> From<&'a PackageFile> for Asset<'a> {
    fn from(file: &'a PackageFile) -> Self {
        Self {
            name: &file.name,
            sha256: &file.sha256,
            size: file.size,
        }
    }
}

/// Mutable state, guarded by the service's mutex.
#[derive(Default)]
struct Inner {
    /// A verified release naming a version newer than the running one.
    available: Option<Release>,
    /// At least one check has succeeded, so "no newer version" is known.
    checked: bool,
    /// An install has been accepted and has not failed yet.
    installing: bool,
    /// Cached from the install state so `status` never reads the file.
    last_error: Option<String>,
    /// The channel `available` and `checked` were found on. A result from
    /// another channel is not shown or installed.
    checked_channel: Option<Channel>,
    /// When the last check finished, successfully or not.
    last_checked: Option<SystemTime>,
    /// Why the last check could not read the feeds, until one succeeds.
    check_error: Option<String>,
}

impl UpdateService {
    /// A service that always uses the stable channel.
    #[must_use]
    pub fn new(support: UpdateSupport, launcher: Arc<dyn HelperLauncher>) -> Arc<Self> {
        Self::with_channel(support, launcher, Arc::new(|| Channel::Stable))
    }

    /// A service that reads the update channel from `channel` at each check.
    #[must_use]
    pub fn with_channel(
        support: UpdateSupport,
        launcher: Arc<dyn HelperLauncher>,
        channel: ChannelSource,
    ) -> Arc<Self> {
        let mut inner = Inner::default();
        if let UpdateSupport::Supported { paths, .. } | UpdateSupport::Package { paths, .. } =
            &support
        {
            recover_install_state(paths, launcher.as_ref(), &mut inner);
        }
        Arc::new(Self {
            support,
            launcher,
            download: DownloadClient::public_only(),
            channel,
            inner: Mutex::new(inner),
            check_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Starts the periodic manifest check. The first check runs shortly after
    /// start-up; the task ends when `shutdown` is cancelled.
    pub fn spawn_checker(self: &Arc<Self>, shutdown: CancellationToken) {
        let service = Arc::clone(self);
        tokio::spawn(async move { service.run_checks(shutdown).await });
    }

    /// The current status. Never blocks on the network.
    ///
    /// Until the user's current channel has been checked, no release is shown:
    /// one found on the previous channel may not belong to this one.
    #[must_use]
    pub fn status(&self) -> UpdateStatus {
        let channel = (self.channel)();
        let inner = self.inner.lock();
        let fresh = inner.checked_channel == Some(channel);
        let available =
            inner
                .available
                .as_ref()
                .filter(|_| fresh)
                .map(|release| AvailableRelease {
                    version: release.version().clone(),
                    notes: release.notes().to_owned(),
                });
        let (state, detail) = match &self.support {
            UpdateSupport::Unsupported { reason, .. } => (UpdateState::Unsupported, reason.clone()),
            UpdateSupport::Supported { .. } | UpdateSupport::Package { .. } => {
                if inner.installing {
                    (UpdateState::Installing, String::new())
                } else if let Some(error) = &inner.last_error {
                    (UpdateState::Failed, error.clone())
                } else if available.is_some() {
                    (UpdateState::Available, String::new())
                } else if inner.checked && fresh {
                    (UpdateState::UpToDate, String::new())
                } else {
                    (UpdateState::Unknown, String::new())
                }
            }
        };
        UpdateStatus {
            state,
            current_version: product_version(),
            available,
            detail,
            channel,
            last_checked: inner.last_checked,
            check_error: inner.check_error.clone().unwrap_or_default(),
        }
    }

    /// Checks the feeds now, as when the user clicks Check for updates, and
    /// returns the resulting status.
    ///
    /// A click soon after the last check on the same channel returns that
    /// result rather than asking GitHub again. A build with no release feed
    /// returns its status unchanged.
    pub async fn check_now(&self) -> UpdateStatus {
        if let Some(trust) = self.trust().cloned() {
            let _checking = self.check_lock.lock().await;
            let channel = (self.channel)();
            let recent = {
                let inner = self.inner.lock();
                inner.checked_channel == Some(channel)
                    && inner.last_checked.is_some_and(|at| {
                        at.elapsed()
                            .is_ok_and(|elapsed| elapsed < MANUAL_CHECK_COOLDOWN)
                    })
            };
            if !recent {
                self.check(&trust).await;
            }
        }
        self.status()
    }

    /// Starts installing `version`, which must equal the available release.
    ///
    /// Returns as soon as the request is accepted. Download, verification, and
    /// the helper launch continue in a background task that reports through
    /// [`Self::status`].
    ///
    /// # Errors
    ///
    /// [`UpdateError::Unsupported`], [`UpdateError::VersionMismatch`], or
    /// [`UpdateError::AlreadyInstalling`].
    pub fn request_install(self: &Arc<Self>, version: &str) -> Result<(), UpdateError> {
        let (paths, trust) = match &self.support {
            UpdateSupport::Supported { paths, trust }
            | UpdateSupport::Package { paths, trust, .. } => (paths.clone(), trust.clone()),
            UpdateSupport::Unsupported { reason, .. } => {
                return Err(UpdateError::Unsupported(reason.clone()));
            }
        };

        let channel = (self.channel)();
        let release = {
            let mut inner = self.inner.lock();
            let requested = Version::parse(version).ok();
            let fresh = inner.checked_channel == Some(channel);
            let release = match (&inner.available, requested) {
                (Some(available), Some(requested))
                    if fresh && *available.version() == requested =>
                {
                    available.clone()
                }
                _ => {
                    return Err(UpdateError::VersionMismatch {
                        requested: version.to_owned(),
                    });
                }
            };
            if inner.installing {
                return Err(UpdateError::AlreadyInstalling);
            }
            inner.installing = true;
            release
        };

        if let Err(error) = update_install_state(&paths.install_state(), |state| {
            state.last_error = None;
        }) {
            self.inner.lock().installing = false;
            return Err(error);
        }
        self.inner.lock().last_error = None;

        let service = Arc::clone(self);
        tokio::spawn(async move {
            service.run_install(paths, trust, release).await;
        });
        Ok(())
    }

    fn trust(&self) -> Option<&Trust> {
        match &self.support {
            UpdateSupport::Supported { trust, .. } | UpdateSupport::Package { trust, .. } => {
                Some(trust)
            }
            UpdateSupport::Unsupported { trust, .. } => trust.as_ref(),
        }
    }

    fn manifest_kind(&self) -> ManifestKind {
        match &self.support {
            UpdateSupport::Package { format, .. } => ManifestKind::Packages(Some(*format)),
            UpdateSupport::Unsupported { .. } if cfg!(target_os = "linux") => {
                ManifestKind::Packages(None)
            }
            UpdateSupport::Supported { .. } | UpdateSupport::Unsupported { .. } => {
                ManifestKind::Tree
            }
        }
    }

    async fn run_checks(&self, shutdown: CancellationToken) {
        let Some(trust) = self.trust().cloned() else {
            return;
        };
        let mut delay = FIRST_CHECK_DELAY;
        loop {
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = shutdown.cancelled() => return,
            }
            tokio::select! {
                () = self.check_locked(&trust) => {}
                () = shutdown.cancelled() => return,
            }
            delay = CHECK_INTERVAL;
        }
    }

    async fn check_locked(&self, trust: &Trust) {
        let _checking = self.check_lock.lock().await;
        self.check(trust).await;
    }

    /// Reads every feed the user's channel covers and keeps the newest release
    /// offered. The caller holds `check_lock`.
    async fn check(&self, trust: &Trust) {
        let channel = (self.channel)();
        let platform = manifest::current_platform();
        let running = product_version();
        let mut results = Vec::new();
        for feed in channel.feeds() {
            let result = self.check_feed(trust, feed, &platform, &running).await;
            if let Err(error) = &result {
                warn!(%feed, error = %error, "update feed could not be read");
            }
            results.push((feed, result));
        }
        let outcome = combine_feeds(channel, results);

        let mut inner = self.inner.lock();
        inner.last_checked = Some(SystemTime::now());
        inner.check_error = outcome.error;
        if outcome.read {
            inner.checked = true;
            inner.checked_channel = Some(channel);
            inner.available = outcome.offered;
        }
    }

    /// The release `feed` offers this daemon, if any.
    async fn check_feed(
        &self,
        trust: &Trust,
        feed: Channel,
        platform: &str,
        running: &Version,
    ) -> Result<Option<Release>, UpdateError> {
        let result = match self.manifest_kind() {
            ManifestKind::Tree => self
                .fetch_manifest(trust, &trust.feed_url(feed, MANIFEST_ASSET))
                .await
                .map(|manifest| offered_release(manifest, platform, running).map(Release::Tree)),
            ManifestKind::Packages(format) => self
                .fetch_package_manifest(trust, &trust.feed_url(feed, PACKAGE_MANIFEST_ASSET))
                .await
                .map(|manifest| {
                    offered_package(manifest, platform, format, running).map(Release::Package)
                }),
        };
        empty_until_published(feed, result)
    }

    /// The manifest at `url`, checked against its signature.
    async fn fetch_manifest(&self, trust: &Trust, url: &str) -> Result<Manifest, UpdateError> {
        let config = DownloadConfig {
            max_bytes: MANIFEST_MAX_BYTES,
            ..DownloadConfig::default()
        };
        let bytes = self
            .download
            .fetch_bytes(url, &config)
            .await
            .map_err(manifest_download_error)?;
        let signature = self
            .download
            .fetch_bytes(&Trust::signature_url(url), &config)
            .await
            .map_err(manifest_download_error)?;
        manifest::verify(&bytes, &signature, &trust.public_key)
    }

    /// The Linux package manifest at `url`, checked against its signature.
    async fn fetch_package_manifest(
        &self,
        trust: &Trust,
        url: &str,
    ) -> Result<PackageManifest, UpdateError> {
        let config = DownloadConfig {
            max_bytes: MANIFEST_MAX_BYTES,
            ..DownloadConfig::default()
        };
        let bytes = self
            .download
            .fetch_bytes(url, &config)
            .await
            .map_err(manifest_download_error)?;
        let signature = self
            .download
            .fetch_bytes(&Trust::signature_url(url), &config)
            .await
            .map_err(manifest_download_error)?;
        package::verify(&bytes, &signature, &trust.public_key)
    }

    async fn run_install(self: Arc<Self>, paths: UpdatePaths, trust: Trust, release: Release) {
        let version = release.version().clone();
        let installed = match (&release, &self.support) {
            (Release::Tree(manifest), UpdateSupport::Supported { .. }) => {
                self.install(&paths, &trust, manifest).await
            }
            (Release::Package(manifest), UpdateSupport::Package { format, .. }) => {
                self.install_package(&paths, &trust, manifest, *format)
                    .await
            }
            _ => Err(UpdateError::BadManifest(
                "the release does not match how Antiwire was installed".to_owned(),
            )),
        };
        match installed {
            Ok(()) => {
                info!(version = %version, "update handed to the apply helper");
                // The helper stops this daemon within its stop budget. Still
                // being alive well after that means it never took over.
                tokio::time::sleep(HANDOFF_TIMEOUT).await;
                self.reconcile_after_handoff(&paths);
            }
            Err(error) => {
                warn!(version = %version, error = %error, "update install failed");
                if let Err(cleanup) = remove_dir_if_present(&paths.incoming(&version)) {
                    warn!(error = %cleanup, "partial update could not be removed");
                }
                self.record_failure(&paths, &error);
                self.inner.lock().installing = false;
            }
        }
    }

    async fn install(
        &self,
        paths: &UpdatePaths,
        trust: &Trust,
        manifest: &Manifest,
    ) -> Result<(), UpdateError> {
        let version = &manifest.version;
        let files = manifest.files_for(&manifest::current_platform())?;
        let incoming = paths.incoming(version);
        remove_dir_if_present(&incoming)?;
        self.download_asset(trust, version, files.daemon.into(), &incoming)
            .await?;
        self.download_asset(trust, version, files.client.into(), &incoming)
            .await?;

        let verified = paths.verified(version);
        replace_dir(&incoming, &verified)?;
        stage_and_launch(paths, manifest, &verified, self.launcher.as_ref())
    }

    /// Downloads the new release's package and the running version's package,
    /// writes the [`PackagePlan`], and starts the helper.
    async fn install_package(
        &self,
        paths: &UpdatePaths,
        trust: &Trust,
        manifest: &PackageManifest,
        format: PackageFormat,
    ) -> Result<(), UpdateError> {
        let version = &manifest.version;
        let platform = manifest::current_platform();
        let package = manifest.package_for(&platform, format)?;
        let incoming = paths.incoming(version);
        remove_dir_if_present(&incoming)?;
        std::fs::create_dir_all(&incoming)
            .map_err(|error| UpdateError::io("create", &incoming, error))?;
        self.download_asset(trust, version, package.into(), &incoming)
            .await?;

        // Without it a failed install cannot go back, but the user asked for the
        // update and the new package is verified, so the install goes ahead.
        let rollback = match self
            .rollback_package(paths, trust, &platform, format, &incoming)
            .await
        {
            Ok(name) if name != package.name => Some(name),
            Ok(_) => None,
            Err(error) => {
                warn!(error = %error, "no package of the running version; the update has no rollback");
                None
            }
        };
        PackagePlan {
            format,
            package: package.name.clone(),
            rollback,
        }
        .store(&incoming)?;

        let verified = paths.verified(version);
        replace_dir(&incoming, &verified)?;
        stage_package_and_launch(paths, version, self.launcher.as_ref())
    }

    /// Puts the running version's package in `dir`: the copy kept by the last
    /// update when it still matches, or a download from the running version's
    /// release. Returns its file name.
    async fn rollback_package(
        &self,
        paths: &UpdatePaths,
        trust: &Trust,
        platform: &str,
        format: PackageFormat,
        dir: &Path,
    ) -> Result<String, UpdateError> {
        let running = product_version();
        let manifest = self
            .fetch_package_manifest(trust, &trust.package_manifest_url(&running))
            .await?;
        if manifest.version != running {
            return Err(UpdateError::BadManifest(format!(
                "the {running} release's package manifest names {}",
                manifest.version
            )));
        }
        let file = manifest.package_for(platform, format)?;
        let kept = paths.installed_packages().join(&file.name);
        let destination = dir.join(&file.name);
        if kept_package_matches(&kept, file) {
            std::fs::copy(&kept, &destination)
                .map_err(|error| UpdateError::io("copy", &kept, error))?;
        } else {
            self.download_asset(trust, &running, file.into(), dir)
                .await?;
        }
        Ok(file.name.clone())
    }

    async fn download_asset(
        &self,
        trust: &Trust,
        version: &Version,
        file: Asset<'_>,
        incoming: &Path,
    ) -> Result<(), UpdateError> {
        let digest: [u8; 32] = HEXLOWER
            .decode(file.sha256.as_bytes())
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| {
                UpdateError::BadManifest(format!("the hash of {} is malformed", file.name))
            })?;
        let destination = incoming.join(file.name);
        let config = DownloadConfig {
            max_bytes: file.size,
            ..DownloadConfig::default()
        };
        self.download
            .download_verified_file(
                &trust.asset_url(version, file.name),
                &destination,
                &config,
                &digest,
            )
            .await
            .map_err(|error| match error {
                DownloadError::HashMismatch => UpdateError::HashMismatch {
                    name: file.name.to_owned(),
                },
                other => UpdateError::Download(other.to_string()),
            })?;

        let actual = std::fs::metadata(&destination)
            .map_err(|error| UpdateError::io("read", &destination, error))?
            .len();
        if actual != file.size {
            return Err(UpdateError::Download(format!(
                "{} is {actual} bytes, the manifest says {}",
                file.name, file.size
            )));
        }
        Ok(())
    }

    /// Ends `Installing` when the helper did not take the request: it refused
    /// it, or exited before stopping this daemon. A request the helper accepted
    /// (`Swapping`) is left to the helper.
    fn reconcile_after_handoff(&self, paths: &UpdatePaths) {
        let path = paths.install_state();
        let mut state = match InstallState::load(&path) {
            Ok(state) => state,
            Err(error) => {
                warn!(error = %error, "install state could not be read");
                return;
            }
        };
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.phase == ApplyPhase::Swapping)
        {
            return;
        }
        if state.pending.take().is_some() {
            state.last_error = Some(
                "the update helper did not start the install; press Install to try again"
                    .to_owned(),
            );
            if let Err(error) = state.store(&path) {
                warn!(error = %error, "install state could not be cleared");
            }
        }
        let mut inner = self.inner.lock();
        inner.last_error.clone_from(&state.last_error);
        inner.installing = false;
    }

    fn record_failure(&self, paths: &UpdatePaths, error: &UpdateError) {
        let message = error.to_string();
        self.inner.lock().last_error = Some(message.clone());
        if let Err(write) = update_install_state(&paths.install_state(), |state| {
            state.last_error = Some(message);
        }) {
            warn!(error = %write, "install failure could not be recorded");
        }
    }
}

/// The release to offer: newer than `running` and built for `platform`. A
/// release without a build for this machine (an Intel Mac when only arm64 was
/// published, say) is not offered, rather than failing after the user clicks.
fn offered_release(manifest: Manifest, platform: &str, running: &Version) -> Option<Manifest> {
    if manifest.files_for(platform).is_err() {
        info!(version = %manifest.version, %platform, "release has no build for this platform");
        return None;
    }
    (manifest.version > *running).then_some(manifest)
}

/// The error a manifest download reports. A 404 is [`UpdateError::NotPublished`],
/// so a feed with nothing on it yet can be told from one that cannot be read.
fn manifest_download_error(error: DownloadError) -> UpdateError {
    match error {
        DownloadError::Http(http) if http.status().map(|status| status.as_u16()) == Some(404) => {
            UpdateError::NotPublished
        }
        other => UpdateError::Download(other.to_string()),
    }
}

/// A feed with nothing published yet offers no release; it is not a failed
/// check. Before the first beta or nightly the `channel-*` release does not
/// exist, and a user who picked that channel should see "up to date", not an
/// error.
fn empty_until_published(
    feed: Channel,
    result: Result<Option<Release>, UpdateError>,
) -> Result<Option<Release>, UpdateError> {
    match result {
        Err(UpdateError::NotPublished) => {
            info!(%feed, "nothing is published on this update feed yet");
            Ok(None)
        }
        other => other,
    }
}

/// What one check found across the feeds of a channel.
#[derive(Debug, PartialEq, Eq)]
struct FeedOutcome {
    /// At least one feed was read. When none was, the last result is kept.
    read: bool,
    /// The newest release the channel accepts, when a feed was read.
    offered: Option<Release>,
    /// Shown to the user: every feed failed, or the channel's own feed did.
    /// A more stable feed failing alone is only logged.
    error: Option<String>,
}

impl PartialEq for Release {
    fn eq(&self, other: &Self) -> bool {
        self.version() == other.version()
    }
}

impl Eq for Release {}

fn combine_feeds(
    channel: Channel,
    results: Vec<(Channel, Result<Option<Release>, UpdateError>)>,
) -> FeedOutcome {
    let mut newest: Option<Release> = None;
    let mut read_any = false;
    let mut own_feed_error = None;
    let mut errors = Vec::new();
    for (feed, result) in results {
        match result {
            Ok(release) => {
                read_any = true;
                let accepted = release.filter(|release| channel.accepts(release.version()));
                if let Some(release) = accepted {
                    if newest
                        .as_ref()
                        .is_none_or(|best| release.version() > best.version())
                    {
                        newest = Some(release);
                    }
                }
            }
            Err(error) => {
                let message = format!("the {feed} feed could not be read: {error}");
                if feed == channel {
                    own_feed_error = Some(message.clone());
                }
                errors.push(message);
            }
        }
    }
    let error = if read_any {
        own_feed_error
    } else {
        (!errors.is_empty()).then(|| errors.join("; "))
    };
    FeedOutcome {
        read: read_any,
        offered: newest,
        error,
    }
}

/// The Linux release to offer: newer than `running`, with a package for
/// `platform` in `format`, or in any format when the install's is unknown.
fn offered_package(
    manifest: PackageManifest,
    platform: &str,
    format: Option<PackageFormat>,
    running: &Version,
) -> Option<PackageManifest> {
    let built = match format {
        Some(format) => manifest.package_for(platform, format).is_ok(),
        None => manifest.has_platform(platform),
    };
    if !built {
        info!(version = %manifest.version, %platform, "release has no package for this platform");
        return None;
    }
    (manifest.version > *running).then_some(manifest)
}

/// Whether the package kept by the last update is the one `file` describes.
fn kept_package_matches(kept: &Path, file: &PackageFile) -> bool {
    std::fs::metadata(kept).is_ok_and(|metadata| metadata.is_file() && metadata.len() == file.size)
        && sha256_hex(kept).is_ok_and(|hash| hash == file.sha256)
}

/// Finishes or abandons an install that the previous daemon left behind.
fn recover_install_state(paths: &UpdatePaths, launcher: &dyn HelperLauncher, inner: &mut Inner) {
    let path = paths.install_state();
    let mut state = match InstallState::load(&path) {
        Ok(state) => state,
        Err(error) => {
            warn!(error = %error, "install state could not be read");
            inner.last_error = Some(error.to_string());
            return;
        }
    };
    inner.last_error.clone_from(&state.last_error);

    match state.pending.as_ref().map(|pending| pending.phase) {
        Some(ApplyPhase::Swapping) => {
            // The helper takes its own lock and exits when an apply is still
            // running, so starting it without checking is safe.
            match std::env::current_exe() {
                Ok(exe) => {
                    if let Err(error) = launcher.launch_recover(&exe, paths.data_dir()) {
                        warn!(error = %error, "could not start the update recovery helper");
                    }
                }
                Err(error) => warn!(error = %error, "could not find the daemon executable"),
            }
        }
        Some(ApplyPhase::Requested) => {
            let message =
                "the daemon stopped before the update started; press Install to try again"
                    .to_owned();
            state.pending = None;
            state.last_error = Some(message.clone());
            inner.last_error = Some(message);
            if let Err(error) = state.store(&path) {
                warn!(error = %error, "install state could not be cleared");
            }
        }
        None => {}
    }
}

/// Copies the verified files into the version tree, records the request, and
/// starts the helper from the new tree.
///
/// Nothing is recorded or launched unless both copies hash to the manifest.
pub(crate) fn stage_and_launch(
    paths: &UpdatePaths,
    manifest: &Manifest,
    verified: &Path,
    launcher: &dyn HelperLauncher,
) -> Result<(), UpdateError> {
    let version = &manifest.version;
    let files = manifest.files_for(&manifest::current_platform())?;
    let daemon_exe = paths.daemon_exe(version);
    let client_exe = paths.client_exe(version);

    let copied = copy_verified(
        &verified.join(&files.daemon.name),
        &daemon_exe,
        files.daemon,
    )
    .and_then(|()| {
        stage_client(
            &verified.join(&files.client.name),
            &client_exe,
            files.client,
        )
    });
    if let Err(error) = copied {
        remove_file_if_exists(&daemon_exe);
        remove_path_if_exists(&client_exe);
        return Err(error);
    }

    let request_id = new_request_id();
    update_install_state(&paths.install_state(), |state| {
        state.pending = Some(PendingInstall {
            version: version.clone(),
            request_id: request_id.clone(),
            phase: ApplyPhase::Requested,
        });
    })?;

    if let Err(error) = launcher.launch_apply(&daemon_exe, paths.data_dir(), version, &request_id) {
        if let Err(clear) = update_install_state(&paths.install_state(), |state| {
            state.pending = None;
        }) {
            warn!(error = %clear, "pending install could not be cleared");
        }
        return Err(UpdateError::io("start", &daemon_exe, error));
    }
    Ok(())
}

/// Records the request for the verified package and starts the helper from
/// this daemon's own executable, which the package manager owns. Unlike a
/// tree install there is nothing to copy: the helper installs the package.
fn stage_package_and_launch(
    paths: &UpdatePaths,
    version: &Version,
    launcher: &dyn HelperLauncher,
) -> Result<(), UpdateError> {
    let daemon_exe = std::env::current_exe()
        .map_err(|error| UpdateError::io("locate", "the daemon executable", error))?;
    stage_package_request(paths, version, &daemon_exe, launcher)
}

fn stage_package_request(
    paths: &UpdatePaths,
    version: &Version,
    daemon_exe: &Path,
    launcher: &dyn HelperLauncher,
) -> Result<(), UpdateError> {
    let request_id = new_request_id();
    update_install_state(&paths.install_state(), |state| {
        // A package install writes no install state of its own, so the running
        // version is what a rollback returns to.
        state.current = Some(product_version());
        state.pending = Some(PendingInstall {
            version: version.clone(),
            request_id: request_id.clone(),
            phase: ApplyPhase::Requested,
        });
    })?;

    if let Err(error) = launcher.launch_apply(daemon_exe, paths.data_dir(), version, &request_id) {
        if let Err(clear) = update_install_state(&paths.install_state(), |state| {
            state.pending = None;
        }) {
            warn!(error = %clear, "pending install could not be cleared");
        }
        return Err(UpdateError::io("start", daemon_exe, error));
    }
    Ok(())
}

fn copy_verified(
    source: &Path,
    destination: &Path,
    file: &ManifestFile,
) -> Result<(), UpdateError> {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| UpdateError::io("create", parent, error))?;
    }
    std::fs::copy(source, destination).map_err(|error| UpdateError::io("copy", source, error))?;
    if sha256_hex(destination)? != file.sha256 {
        remove_file_if_exists(destination);
        return Err(UpdateError::HashMismatch {
            name: file.name.clone(),
        });
    }
    Ok(())
}

/// Puts the client into the version tree: on Windows the Electron app
/// directory unpacked from its zip, on macOS the `Antiwire.app` bundle
/// unpacked from its zip, elsewhere a copy of the executable.
fn stage_client(source: &Path, destination: &Path, file: &ManifestFile) -> Result<(), UpdateError> {
    #[cfg(target_os = "macos")]
    {
        unpack_app_bundle(source, destination, file)
    }
    #[cfg(windows)]
    {
        unpack_app_directory(source, destination, file)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        copy_verified(source, destination, file)
    }
}

/// Unpacks the client zip (the contents of electron-builder's `win-unpacked`
/// directory, `antiwire.exe` at its root) into the directory holding
/// `destination`. The Electron client is a directory of runtime files, not one
/// executable, so it cannot be copied like the daemon.
///
/// Uses the `tar` that ships with Windows (bsdtar), which reads zip and refuses
/// absolute and `..` member paths. It unpacks into a sibling directory first, so
/// a failed unpack never leaves a half-written client in place.
#[cfg(windows)]
fn unpack_app_directory(
    archive: &Path,
    destination: &Path,
    file: &ManifestFile,
) -> Result<(), UpdateError> {
    // The archive was hashed on download; hash again so nothing swapped it
    // inside the data directory since.
    if sha256_hex(archive)? != file.sha256 {
        return Err(UpdateError::HashMismatch {
            name: file.name.clone(),
        });
    }
    let target = destination
        .parent()
        .ok_or_else(|| UpdateError::BadManifest("the client has no install directory".into()))?;
    let staging = target.with_extension("unpacking");
    remove_path_if_exists(&staging);
    std::fs::create_dir_all(&staging)
        .map_err(|error| UpdateError::io("create", &staging, error))?;
    let tar = std::env::var_os("SystemRoot")
        .map_or_else(
            || std::path::PathBuf::from(r"C:\Windows"),
            std::path::PathBuf::from,
        )
        .join("System32")
        .join("tar.exe");
    let status = std::process::Command::new(&tar)
        .arg("-x")
        .arg("-f")
        .arg(archive)
        .arg("-C")
        .arg(&staging)
        .status()
        .map_err(|error| UpdateError::io("unpack", archive, error));
    let executable = destination
        .file_name()
        .map_or_else(|| staging.clone(), |name| staging.join(name));
    match status {
        Ok(status) if status.success() && executable.is_file() => {}
        Ok(_) => {
            remove_path_if_exists(&staging);
            return Err(UpdateError::BadManifest(format!(
                "{} does not unpack to {}",
                file.name,
                destination.display()
            )));
        }
        Err(error) => {
            remove_path_if_exists(&staging);
            return Err(error);
        }
    }
    replace_dir(&staging, target)
}

/// Unpacks the client zip (made with `ditto -c -k --keepParent Antiwire.app`)
/// so `destination` is the bundle. `ditto` keeps the bundle's symlinks,
/// permissions, and code signature intact, which a plain copy does not.
#[cfg(target_os = "macos")]
fn unpack_app_bundle(
    archive: &Path,
    destination: &Path,
    file: &ManifestFile,
) -> Result<(), UpdateError> {
    // The archive was hashed on download; hash again so nothing swapped it
    // inside the data directory since.
    if sha256_hex(archive)? != file.sha256 {
        return Err(UpdateError::HashMismatch {
            name: file.name.clone(),
        });
    }
    let parent = destination
        .parent()
        .ok_or_else(|| UpdateError::BadManifest("the client has no install directory".into()))?;
    remove_path_if_exists(destination);
    std::fs::create_dir_all(parent).map_err(|error| UpdateError::io("create", parent, error))?;
    let status = std::process::Command::new("/usr/bin/ditto")
        .arg("-x")
        .arg("-k")
        .arg(archive)
        .arg(parent)
        .status()
        .map_err(|error| UpdateError::io("unpack", archive, error))?;
    if !status.success() || !destination.join("Contents").is_dir() {
        return Err(UpdateError::BadManifest(format!(
            "{} does not unpack to {}",
            file.name,
            destination.display()
        )));
    }
    Ok(())
}

fn sha256_hex(path: &Path) -> Result<String, UpdateError> {
    let mut file = File::open(path).map_err(|error| UpdateError::io("open", path, error))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|error| UpdateError::io("read", path, error))?;
    Ok(HEXLOWER.encode(&hasher.finalize()))
}

fn update_install_state(
    path: &Path,
    change: impl FnOnce(&mut InstallState),
) -> Result<(), UpdateError> {
    let mut state = InstallState::load(path)?;
    change(&mut state);
    state.store(path)
}

fn replace_dir(from: &Path, to: &Path) -> Result<(), UpdateError> {
    remove_dir_if_present(to)?;
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| UpdateError::io("create", parent, error))?;
    }
    std::fs::rename(from, to).map_err(|error| UpdateError::io("move", from, error))
}

/// Removes a file or a directory tree, such as an unpacked app bundle.
fn remove_path_if_exists(path: &Path) {
    if path.is_dir() {
        if let Err(error) = remove_dir_if_present(path) {
            warn!(error = %error, "could not remove a directory");
        }
    } else {
        remove_file_if_exists(path);
    }
}

fn remove_file_if_exists(path: &Path) {
    if let Err(error) = remove_file_if_present(path) {
        warn!(error = %error, "could not remove a file");
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::manifest::FileRole;

    /// Public key of the signing key used in `manifest` tests. Any valid point works.
    const KEY: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    const RELEASES: &str = "https://github.com/example/antiwire/releases";

    #[derive(Default)]
    struct RecordingLauncher {
        applies: Mutex<Vec<(PathBuf, PathBuf, Version, String)>>,
        recovers: Mutex<usize>,
        fail: bool,
    }

    impl HelperLauncher for RecordingLauncher {
        fn launch_apply(
            &self,
            daemon_exe: &Path,
            data_dir: &Path,
            version: &Version,
            request_id: &str,
        ) -> std::io::Result<()> {
            self.applies.lock().push((
                daemon_exe.to_path_buf(),
                data_dir.to_path_buf(),
                version.clone(),
                request_id.to_owned(),
            ));
            if self.fail {
                Err(std::io::Error::other("refused"))
            } else {
                Ok(())
            }
        }

        fn launch_recover(&self, _daemon_exe: &Path, _data_dir: &Path) -> std::io::Result<()> {
            *self.recovers.lock() += 1;
            Ok(())
        }
    }

    fn test_trust() -> Trust {
        Trust::new(RELEASES, KEY).expect("test feed")
    }

    fn temp_paths() -> (tempfile::TempDir, UpdatePaths) {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = UpdatePaths::new(dir.path().join("data"), dir.path().join("install"));
        std::fs::create_dir_all(paths.data_dir()).expect("data dir");
        (dir, paths)
    }

    fn hex(bytes: &[u8]) -> String {
        HEXLOWER.encode(&Sha256::digest(bytes))
    }

    fn manifest_for(version: &Version, daemon: &[u8], client: &[u8]) -> Manifest {
        let platform = manifest::current_platform();
        Manifest {
            version: version.clone(),
            notes: "Fixes a crash.".to_owned(),
            files: vec![
                ManifestFile {
                    role: FileRole::Daemon,
                    platform: platform.clone(),
                    name: "antiwire-daemon.exe".to_owned(),
                    sha256: hex(daemon),
                    size: daemon.len() as u64,
                },
                ManifestFile {
                    role: FileRole::Client,
                    platform,
                    name: "antiwire.exe".to_owned(),
                    sha256: hex(client),
                    size: client.len() as u64,
                },
            ],
        }
    }

    /// The client as a release ships it: on Windows a zip of the app directory
    /// made with the system `tar`, on macOS a zip of the `Antiwire.app` bundle
    /// made as the release does, with `ditto`, elsewhere the executable.
    fn client_payload(executable: &[u8]) -> Vec<u8> {
        #[cfg(windows)]
        {
            let dir = tempfile::tempdir().expect("app dir");
            let app = dir.path().join("win-unpacked");
            std::fs::create_dir_all(app.join("resources")).expect("app");
            std::fs::write(app.join("antiwire.exe"), executable).expect("app executable");
            std::fs::write(app.join("resources").join("app.asar"), b"asar").expect("app archive");
            let archive = dir.path().join("antiwire.zip");
            let status = std::process::Command::new("tar")
                .arg("-a")
                .arg("-c")
                .arg("-f")
                .arg(&archive)
                .arg("-C")
                .arg(&app)
                .arg(".")
                .status()
                .expect("tar");
            assert!(status.success(), "tar could not zip the app directory");
            std::fs::read(archive).expect("app archive")
        }
        #[cfg(target_os = "macos")]
        {
            let dir = tempfile::tempdir().expect("bundle dir");
            let bundle = dir.path().join("Antiwire.app");
            let macos = bundle.join("Contents").join("MacOS");
            std::fs::create_dir_all(&macos).expect("bundle");
            std::fs::write(macos.join("Antiwire"), executable).expect("bundle executable");
            let archive = dir.path().join("Antiwire.zip");
            let status = std::process::Command::new("/usr/bin/ditto")
                .args(["-c", "-k", "--keepParent"])
                .arg(&bundle)
                .arg(&archive)
                .status()
                .expect("ditto");
            assert!(status.success(), "ditto could not zip the bundle");
            std::fs::read(archive).expect("bundle archive")
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            executable.to_vec()
        }
    }

    fn write_verified(
        paths: &UpdatePaths,
        version: &Version,
        daemon: &[u8],
        client: &[u8],
    ) -> PathBuf {
        let verified = paths.verified(version);
        std::fs::create_dir_all(&verified).expect("verified dir");
        std::fs::write(verified.join("antiwire-daemon.exe"), daemon).expect("daemon");
        std::fs::write(verified.join("antiwire.exe"), client).expect("client");
        verified
    }

    fn supported(paths: &UpdatePaths) -> UpdateSupport {
        UpdateSupport::Supported {
            paths: paths.clone(),
            trust: test_trust(),
        }
    }

    fn environment(release_build: bool, is_service: bool, platform_supported: bool) -> Environment {
        Environment {
            release_build,
            is_service,
            platform_supported,
        }
    }

    fn reason_of(support: UpdateSupport) -> String {
        match support {
            UpdateSupport::Unsupported { reason, .. } => reason,
            UpdateSupport::Supported { .. } | UpdateSupport::Package { .. } => {
                panic!("expected unsupported")
            }
        }
    }

    fn layout() -> UpdatePaths {
        UpdatePaths::new("/data", "/install")
    }

    #[test]
    fn supported_only_when_every_requirement_holds() {
        let support = decide(
            &environment(true, true, true),
            Some(test_trust()),
            Some(layout()),
            true,
        );
        assert!(matches!(support, UpdateSupport::Supported { .. }));
    }

    #[test]
    fn development_build_reason() {
        let support = decide(
            &environment(false, true, true),
            Some(test_trust()),
            Some(layout()),
            true,
        );
        assert_eq!(reason_of(support), "this is a development build");
    }

    #[test]
    fn not_service_reason() {
        let support = decide(
            &environment(true, false, true),
            Some(test_trust()),
            Some(layout()),
            true,
        );
        assert_eq!(reason_of(support), "Antiwire is not running as a service");
    }

    #[test]
    fn unsupported_platform_reason() {
        let support = decide(
            &environment(true, true, false),
            Some(test_trust()),
            Some(layout()),
            true,
        );
        assert_eq!(
            reason_of(support),
            "updates are only installed on Windows, macOS, and Linux"
        );
    }

    #[test]
    fn a_package_install_is_supported() {
        let support = decide_package(
            &environment(true, true, true),
            Some(test_trust()),
            Path::new("/var/lib/antiwire"),
            Some(PackageFormat::Rpm),
        );
        match support {
            UpdateSupport::Package { paths, format, .. } => {
                assert_eq!(format, PackageFormat::Rpm);
                assert_eq!(paths.data_dir(), Path::new("/var/lib/antiwire"));
            }
            _ => panic!("expected a package install"),
        }
    }

    #[test]
    fn an_unpackaged_linux_install_says_how_to_update() {
        let support = decide_package(
            &environment(true, true, true),
            Some(test_trust()),
            Path::new("/var/lib/antiwire"),
            None,
        );
        assert!(reason_of(support).contains(".deb or .rpm"));
    }

    #[test]
    fn a_package_install_still_needs_a_release_build_and_a_key() {
        let development = decide_package(
            &environment(false, true, true),
            Some(test_trust()),
            Path::new("/var/lib/antiwire"),
            Some(PackageFormat::Deb),
        );
        assert_eq!(reason_of(development), "this is a development build");
        let unsigned = decide_package(
            &environment(true, true, true),
            None,
            Path::new("/var/lib/antiwire"),
            Some(PackageFormat::Deb),
        );
        assert_eq!(reason_of(unsigned), "this build has no release signing key");
    }

    fn package_manifest(version: Version, formats: &[PackageFormat]) -> PackageManifest {
        PackageManifest {
            version,
            notes: "Fixes a crash.".to_owned(),
            packages: formats
                .iter()
                .map(|format| PackageFile {
                    platform: "linux-x86_64".to_owned(),
                    format: *format,
                    name: format!("antiwire.{format}"),
                    sha256: hex(b"package"),
                    size: 7,
                })
                .collect(),
        }
    }

    #[test]
    fn offers_packages_in_the_installed_format() {
        let running = Version::new(0, 2, 0);
        let deb_only = package_manifest(Version::new(0, 3, 0), &[PackageFormat::Deb]);
        let offered =
            |format| offered_package(deb_only.clone(), "linux-x86_64", format, &running).is_some();
        assert!(offered(Some(PackageFormat::Deb)));
        assert!(!offered(Some(PackageFormat::Rpm)));
        // A tarball install is told about the release, in any format.
        assert!(offered(None));
        assert!(offered_package(deb_only.clone(), "linux-aarch64", None, &running).is_none());
        assert!(offered_package(deb_only, "linux-x86_64", None, &Version::new(0, 3, 0)).is_none());
    }

    #[test]
    fn package_request_records_the_running_version_and_launches() {
        let (_dir, paths) = temp_paths();
        let launcher = RecordingLauncher::default();
        let exe = Path::new("/usr/bin/antiwire-daemon");
        stage_package_request(&paths, &Version::new(9, 0, 0), exe, &launcher).expect("staged");

        let state = InstallState::load(&paths.install_state()).expect("state");
        assert_eq!(state.current, Some(product_version()));
        let pending = state.pending.expect("pending");
        assert_eq!(pending.phase, ApplyPhase::Requested);
        let applies = launcher.applies.lock();
        assert_eq!(applies.len(), 1);
        assert_eq!(applies[0].0, exe);
        assert_eq!(applies[0].3, pending.request_id);
    }

    #[test]
    fn failed_package_launch_clears_pending() {
        let (_dir, paths) = temp_paths();
        let launcher = RecordingLauncher {
            fail: true,
            ..RecordingLauncher::default()
        };
        let exe = Path::new("/usr/bin/antiwire-daemon");
        assert!(stage_package_request(&paths, &Version::new(9, 0, 0), exe, &launcher).is_err());
        let state = InstallState::load(&paths.install_state()).expect("state");
        assert_eq!(state.pending, None);
    }

    #[test]
    fn a_kept_package_is_reused_only_when_it_matches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kept = dir.path().join("antiwire.deb");
        std::fs::write(&kept, b"package").expect("kept");
        let file = &package_manifest(Version::new(0, 2, 0), &[PackageFormat::Deb]).packages[0];
        assert!(kept_package_matches(&kept, file));
        std::fs::write(&kept, b"tampered").expect("kept");
        assert!(!kept_package_matches(&kept, file));
        assert!(!kept_package_matches(&dir.path().join("missing.deb"), file));
    }

    #[test]
    fn no_signing_key_reason() {
        let support = decide(&environment(true, true, true), None, Some(layout()), true);
        assert_eq!(reason_of(support), "this build has no release signing key");
    }

    #[test]
    fn unversioned_layout_reason() {
        let support = decide(
            &environment(true, true, true),
            Some(test_trust()),
            None,
            false,
        );
        assert_eq!(
            reason_of(support),
            "Antiwire was not installed in the versioned layout"
        );
    }

    #[test]
    fn unrecorded_install_reason() {
        let support = decide(
            &environment(true, true, true),
            Some(test_trust()),
            Some(layout()),
            false,
        );
        assert_eq!(
            reason_of(support),
            "the install state does not record this version as installed"
        );
    }

    #[test]
    fn unsupported_keeps_trust_for_checks() {
        let support = decide(
            &environment(false, true, true),
            Some(test_trust()),
            Some(layout()),
            true,
        );
        assert!(matches!(
            support,
            UpdateSupport::Unsupported { trust: Some(_), .. }
        ));
    }

    #[test]
    fn stage_writes_version_tree_and_requests_launch() {
        let (_dir, paths) = temp_paths();
        let version = Version::new(0, 3, 0);
        let daemon = b"new daemon";
        let client = client_payload(b"new client");
        let verified = write_verified(&paths, &version, daemon, &client);
        let manifest = manifest_for(&version, daemon, &client);
        let launcher = RecordingLauncher::default();

        stage_and_launch(&paths, &manifest, &verified, &launcher).expect("stage");

        assert_eq!(
            std::fs::read(paths.daemon_exe(&version)).expect("daemon copy"),
            daemon
        );
        // On macOS the bundle is unpacked, so its executable holds the content.
        let staged_client = if cfg!(target_os = "macos") {
            paths
                .client_exe(&version)
                .join("Contents")
                .join("MacOS")
                .join("Antiwire")
        } else {
            paths.client_exe(&version)
        };
        assert_eq!(
            std::fs::read(staged_client).expect("client copy"),
            b"new client"
        );
        // On Windows the whole Electron app directory arrives, not only the executable.
        if cfg!(windows) {
            let ui = paths.client_exe(&version);
            let asar = ui
                .parent()
                .expect("ui dir")
                .join("resources")
                .join("app.asar");
            assert!(asar.is_file(), "{} missing", asar.display());
        }
        let pending = InstallState::load(&paths.install_state())
            .expect("state")
            .pending
            .expect("pending");
        assert_eq!(pending.phase, ApplyPhase::Requested);
        assert_eq!(pending.version, version);
        let applies = launcher.applies.lock();
        assert_eq!(applies.len(), 1);
        assert_eq!(applies[0].0, paths.daemon_exe(&version));
        assert_eq!(applies[0].3, pending.request_id);
    }

    #[test]
    fn hash_mismatch_writes_nothing_and_launches_nothing() {
        let (_dir, paths) = temp_paths();
        let version = Version::new(0, 3, 0);
        let verified = write_verified(&paths, &version, b"tampered", b"new client");
        let manifest = manifest_for(&version, b"new daemon", b"new client");
        let launcher = RecordingLauncher::default();

        let error = stage_and_launch(&paths, &manifest, &verified, &launcher)
            .expect_err("mismatch must fail");

        assert!(matches!(error, UpdateError::HashMismatch { .. }));
        assert!(!paths.daemon_exe(&version).exists());
        assert!(!paths.install_state().exists());
        assert!(launcher.applies.lock().is_empty());
    }

    #[test]
    fn failed_launch_clears_pending() {
        let (_dir, paths) = temp_paths();
        let version = Version::new(0, 3, 0);
        let verified = write_verified(&paths, &version, b"new daemon", b"new client");
        let manifest = manifest_for(&version, b"new daemon", b"new client");
        let launcher = RecordingLauncher {
            fail: true,
            ..RecordingLauncher::default()
        };

        assert!(stage_and_launch(&paths, &manifest, &verified, &launcher).is_err());
        let state = InstallState::load(&paths.install_state()).expect("state");
        assert_eq!(state.pending, None);
    }

    #[test]
    fn recovery_relaunches_swapping_install() {
        let (_dir, paths) = temp_paths();
        InstallState {
            pending: Some(PendingInstall {
                version: Version::new(0, 3, 0),
                request_id: "id".to_owned(),
                phase: ApplyPhase::Swapping,
            }),
            ..InstallState::default()
        }
        .store(&paths.install_state())
        .expect("store");

        let launcher = Arc::new(RecordingLauncher::default());
        let _service = UpdateService::new(supported(&paths), launcher.clone());

        assert_eq!(*launcher.recovers.lock(), 1);
    }

    #[test]
    fn requested_install_is_dropped_on_start() {
        let (_dir, paths) = temp_paths();
        InstallState {
            pending: Some(PendingInstall {
                version: Version::new(0, 3, 0),
                request_id: "id".to_owned(),
                phase: ApplyPhase::Requested,
            }),
            ..InstallState::default()
        }
        .store(&paths.install_state())
        .expect("store");

        let launcher = Arc::new(RecordingLauncher::default());
        let service = UpdateService::new(supported(&paths), launcher.clone());

        assert_eq!(*launcher.recovers.lock(), 0);
        assert!(service.status().detail.contains("press Install"));
        let state = InstallState::load(&paths.install_state()).expect("state");
        assert_eq!(state.pending, None);
    }

    #[test]
    fn request_refused_when_unsupported() {
        let service = UpdateService::new(
            UpdateSupport::Unsupported {
                reason: "this is a development build".to_owned(),
                trust: None,
            },
            Arc::new(RecordingLauncher::default()),
        );
        assert!(matches!(
            service.request_install("0.3.0"),
            Err(UpdateError::Unsupported(_))
        ));
    }

    #[test]
    fn request_refused_for_other_version() {
        let (_dir, paths) = temp_paths();
        let service = UpdateService::new(supported(&paths), Arc::new(RecordingLauncher::default()));
        service.inner.lock().available = Some(Release::Tree(manifest_for(
            &Version::new(0, 3, 0),
            b"a",
            b"b",
        )));

        assert!(matches!(
            service.request_install("0.4.0"),
            Err(UpdateError::VersionMismatch { .. })
        ));
        assert!(matches!(
            service.request_install("not a version"),
            Err(UpdateError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn request_refused_while_installing() {
        let (_dir, paths) = temp_paths();
        let service = UpdateService::new(supported(&paths), Arc::new(RecordingLauncher::default()));
        {
            let mut inner = service.inner.lock();
            inner.available = Some(Release::Tree(manifest_for(
                &Version::new(0, 3, 0),
                b"a",
                b"b",
            )));
            inner.checked_channel = Some(Channel::Stable);
            inner.installing = true;
        }

        assert!(matches!(
            service.request_install("0.3.0"),
            Err(UpdateError::AlreadyInstalling)
        ));
    }

    fn tree_release(version: &str) -> Release {
        Release::Tree(manifest_for(
            &Version::parse(version).expect("version"),
            b"a",
            b"b",
        ))
    }

    #[test]
    fn the_newest_release_the_channel_accepts_wins() {
        let outcome = combine_feeds(
            Channel::Nightly,
            vec![
                (Channel::Stable, Ok(Some(tree_release("0.3.0")))),
                (Channel::Beta, Ok(Some(tree_release("0.3.0-beta.2")))),
                (
                    Channel::Nightly,
                    Ok(Some(tree_release("0.3.1-nightly.20261102.4"))),
                ),
            ],
        );
        let offered = outcome.offered.expect("a release");
        assert_eq!(offered.version().to_string(), "0.3.1-nightly.20261102.4");
        assert_eq!(outcome.error, None);

        // A beta user is offered the stable release once it is newer than the last beta.
        let outcome = combine_feeds(
            Channel::Beta,
            vec![
                (Channel::Stable, Ok(Some(tree_release("0.3.0")))),
                (Channel::Beta, Ok(Some(tree_release("0.3.0-beta.2")))),
            ],
        );
        let offered = outcome.offered.expect("a release");
        assert_eq!(offered.version().to_string(), "0.3.0");
    }

    #[test]
    fn a_feed_never_offers_a_release_from_a_less_stable_channel() {
        // The beta feed is CI's, but a nightly slipped into it is still refused.
        let outcome = combine_feeds(
            Channel::Beta,
            vec![
                (Channel::Stable, Ok(None)),
                (
                    Channel::Beta,
                    Ok(Some(tree_release("0.4.0-nightly.20261102.1"))),
                ),
            ],
        );
        assert!(outcome.read);
        assert_eq!(outcome.offered, None);
    }

    #[test]
    fn feed_failures_are_reported_only_when_they_matter() {
        let failed = || Err(UpdateError::Download("404".to_owned()));

        // A more stable feed failing alone is only logged.
        let outcome = combine_feeds(
            Channel::Beta,
            vec![(Channel::Stable, failed()), (Channel::Beta, Ok(None))],
        );
        assert!(outcome.read);
        assert_eq!(outcome.offered, None);
        assert_eq!(outcome.error, None);

        // The channel's own feed failing is shown, but the others still count.
        let outcome = combine_feeds(
            Channel::Nightly,
            vec![
                (Channel::Stable, Ok(Some(tree_release("0.3.0")))),
                (Channel::Beta, Ok(None)),
                (Channel::Nightly, failed()),
            ],
        );
        assert!(outcome.read && outcome.offered.is_some());
        assert!(outcome
            .error
            .is_some_and(|error| error.contains("nightly feed")));

        // Every feed failing keeps the last result and says why.
        let outcome = combine_feeds(Channel::Stable, vec![(Channel::Stable, failed())]);
        assert!(!outcome.read);
        assert!(outcome
            .error
            .is_some_and(|error| error.contains("stable feed")));
    }

    #[test]
    fn a_feed_with_nothing_published_offers_nothing_without_an_error() {
        assert!(matches!(
            empty_until_published(Channel::Nightly, Err(UpdateError::NotPublished)),
            Ok(None)
        ));
        assert!(matches!(
            empty_until_published(
                Channel::Beta,
                Err(UpdateError::Download("connection reset".to_owned()))
            ),
            Err(UpdateError::Download(_))
        ));
        assert!(matches!(
            empty_until_published(Channel::Stable, Ok(Some(tree_release("0.3.0")))),
            Ok(Some(_))
        ));
    }

    #[test]
    fn switching_channel_hides_the_previous_result_until_the_next_check() {
        let (_dir, paths) = temp_paths();
        let chosen = Arc::new(Mutex::new(Channel::Stable));
        let source = Arc::clone(&chosen);
        let service = UpdateService::with_channel(
            supported(&paths),
            Arc::new(RecordingLauncher::default()),
            Arc::new(move || *source.lock()),
        );
        {
            let mut inner = service.inner.lock();
            inner.checked = true;
            inner.checked_channel = Some(Channel::Stable);
            inner.available = Some(tree_release("0.3.0"));
        }
        let status = service.status();
        assert_eq!(status.state, UpdateState::Available);
        assert_eq!(status.channel, Channel::Stable);

        *chosen.lock() = Channel::Beta;
        let status = service.status();
        assert_eq!(status.state, UpdateState::Unknown);
        assert_eq!(status.available, None);
        assert_eq!(status.channel, Channel::Beta);
        assert!(matches!(
            service.request_install("0.3.0"),
            Err(UpdateError::VersionMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn a_manual_check_without_a_feed_returns_the_status() {
        let service = UpdateService::new(
            UpdateSupport::Unsupported {
                reason: "this build has no release signing key".to_owned(),
                trust: None,
            },
            Arc::new(RecordingLauncher::default()),
        );
        let status = service.check_now().await;
        assert_eq!(status.state, UpdateState::Unsupported);
        assert_eq!(status.last_checked, None);
        assert_eq!(status.check_error, "");
    }

    #[test]
    fn status_reports_unsupported_reason() {
        let service = UpdateService::new(
            UpdateSupport::Unsupported {
                reason: "this is a development build".to_owned(),
                trust: None,
            },
            Arc::new(RecordingLauncher::default()),
        );
        let status = service.status();
        assert_eq!(status.state, UpdateState::Unsupported);
        assert_eq!(status.detail, "this is a development build");
    }

    #[test]
    fn status_moves_from_unknown_to_available_and_installing() {
        let (_dir, paths) = temp_paths();
        let service = UpdateService::new(supported(&paths), Arc::new(RecordingLauncher::default()));
        assert_eq!(service.status().state, UpdateState::Unknown);

        {
            let mut inner = service.inner.lock();
            inner.checked = true;
            inner.checked_channel = Some(Channel::Stable);
        }
        assert_eq!(service.status().state, UpdateState::UpToDate);

        service.inner.lock().available = Some(Release::Tree(manifest_for(
            &Version::new(0, 3, 0),
            b"a",
            b"b",
        )));
        let status = service.status();
        assert_eq!(status.state, UpdateState::Available);
        assert_eq!(
            status.available.map(|release| release.version),
            Some(Version::new(0, 3, 0))
        );

        service.inner.lock().installing = true;
        assert_eq!(service.status().state, UpdateState::Installing);
    }

    #[test]
    fn offers_only_newer_releases_built_for_this_platform() {
        let manifest = manifest_for(&Version::new(0, 3, 0), b"a", b"b");
        let platform = manifest.files[0].platform.clone();

        assert!(offered_release(manifest.clone(), &platform, &Version::new(0, 2, 0)).is_some());
        assert!(offered_release(manifest.clone(), &platform, &Version::new(0, 3, 0)).is_none());
        assert!(offered_release(manifest, "macos-x86_64-other", &Version::new(0, 2, 0)).is_none());
    }

    fn store_pending(paths: &UpdatePaths, phase: ApplyPhase) {
        InstallState {
            pending: Some(PendingInstall {
                version: Version::new(0, 3, 0),
                request_id: "id".to_owned(),
                phase,
            }),
            ..InstallState::default()
        }
        .store(&paths.install_state())
        .expect("store");
    }

    #[test]
    fn unclaimed_request_ends_installing_with_an_error() {
        let (_dir, paths) = temp_paths();
        let service = UpdateService::new(supported(&paths), Arc::new(RecordingLauncher::default()));
        store_pending(&paths, ApplyPhase::Requested);
        service.inner.lock().installing = true;

        service.reconcile_after_handoff(&paths);

        let status = service.status();
        assert_eq!(status.state, UpdateState::Failed);
        assert!(status.detail.contains("did not start the install"));
        let state = InstallState::load(&paths.install_state()).expect("state");
        assert_eq!(state.pending, None);
    }

    #[test]
    fn swap_in_progress_is_left_to_the_helper() {
        let (_dir, paths) = temp_paths();
        let service = UpdateService::new(supported(&paths), Arc::new(RecordingLauncher::default()));
        store_pending(&paths, ApplyPhase::Swapping);
        service.inner.lock().installing = true;

        service.reconcile_after_handoff(&paths);

        assert_eq!(service.status().state, UpdateState::Installing);
        let state = InstallState::load(&paths.install_state()).expect("state");
        assert!(state.pending.is_some());
    }
}
