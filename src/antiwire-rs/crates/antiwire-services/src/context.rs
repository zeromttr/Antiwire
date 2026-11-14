//! What every background service is built from.

use std::sync::Arc;

use antiwire_events::AlertPublisher;
use antiwire_platform::DataPaths;
use antiwire_store::Store;
use tokio_util::sync::CancellationToken;

use crate::settings_feed::SettingsFeed;

/// The shared dependencies of the background services.
///
/// The runtime builds one and hands it to each service, so the daemon and
/// the tests wire services the same way.
#[derive(Clone)]
pub struct ServiceContext {
    pub store: Arc<Store>,
    pub settings: SettingsFeed,
    pub alerts: AlertPublisher,
    pub data_paths: DataPaths,
    /// Cancelled once, by the runtime, when the daemon shuts down. Every
    /// service stops its work when it is.
    pub shutdown: CancellationToken,
}
