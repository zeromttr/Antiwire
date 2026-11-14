//! The saved daemon settings, published to every service that acts on them.

use std::sync::Arc;

use antiwire_store::{DaemonSetting, Store, StoreError};
use parking_lot::Mutex;
use time::OffsetDateTime;
use tokio::sync::watch;

/// The saved settings, and the one way services change them.
///
/// A change is saved and then published here, so every service decides from
/// the same snapshot instead of each re-reading the store or polling it.
#[derive(Clone)]
pub struct SettingsFeed {
    store: Arc<Store>,
    sender: Arc<watch::Sender<Arc<DaemonSetting>>>,
    /// Held across each save and its publish, so publishes happen in the
    /// order the saves did.
    publish: Arc<Mutex<()>>,
}

impl SettingsFeed {
    /// A feed over the settings saved in `store`. Blocking.
    ///
    /// # Errors
    ///
    /// A store failure reading the settings.
    pub fn load(store: Arc<Store>) -> Result<Self, StoreError> {
        let settings = store.get_settings()?;
        let (sender, _) = watch::channel(Arc::new(settings));
        Ok(Self {
            store,
            sender: Arc::new(sender),
            publish: Arc::new(Mutex::new(())),
        })
    }

    /// The settings as last saved.
    #[must_use]
    pub fn current(&self) -> Arc<DaemonSetting> {
        Arc::clone(&self.sender.borrow())
    }

    /// Notified with every saved change.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Arc<DaemonSetting>> {
        self.sender.subscribe()
    }

    /// Saves the row `merge` derives from the saved one and publishes it.
    /// `merge` may refuse the change. Returns the row as it was and as it
    /// was saved. Blocking.
    ///
    /// # Errors
    ///
    /// What `merge` returned, or a store failure; nothing is published.
    pub fn modify(
        &self,
        merge: impl FnOnce(&DaemonSetting) -> Result<DaemonSetting, StoreError>,
    ) -> Result<(DaemonSetting, DaemonSetting), StoreError> {
        let _publish = self.publish.lock();
        let (previous, updated) = self.store.modify_settings(merge)?;
        self.sender.send_replace(Arc::new(updated.clone()));
        Ok((previous, updated))
    }

    /// Records that the hosts blocklists synced at `at`. Blocking.
    ///
    /// # Errors
    ///
    /// A store failure; nothing is published.
    pub fn record_hosts_blocklist_sync(&self, at: OffsetDateTime) -> Result<(), StoreError> {
        let _publish = self.publish.lock();
        self.store.set_hosts_blocklist_last_updated(at)?;
        self.sender
            .send_modify(|settings| Arc::make_mut(settings).hosts_blocklist_last_updated = at);
        Ok(())
    }

    /// Records that the `GeoIP` database synced at `at`. Blocking.
    ///
    /// # Errors
    ///
    /// A store failure; nothing is published.
    pub fn record_geoip_sync(&self, at: OffsetDateTime) -> Result<(), StoreError> {
        let _publish = self.publish.lock();
        self.store.set_geoip_database_last_updated(at)?;
        self.sender
            .send_modify(|settings| Arc::make_mut(settings).geoip_database_last_updated = at);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn feed() -> (tempfile::NamedTempFile, Arc<Store>, SettingsFeed) {
        let file = tempfile::NamedTempFile::new().expect("temp");
        let store = Arc::new(Store::open(file.path()).expect("open"));
        let feed = SettingsFeed::load(Arc::clone(&store)).expect("feed");
        (file, store, feed)
    }

    #[test]
    fn a_change_is_saved_then_published() {
        let (_file, store, feed) = feed();
        let mut changes = feed.subscribe();

        let (previous, updated) = feed
            .modify(|saved| {
                Ok(DaemonSetting {
                    geoip_enabled: !saved.geoip_enabled,
                    ..saved.clone()
                })
            })
            .expect("modify");

        assert_ne!(previous.geoip_enabled, updated.geoip_enabled);
        assert!(changes.has_changed().expect("feed alive"));
        assert_eq!(feed.current().geoip_enabled, updated.geoip_enabled);
        assert_eq!(
            store.get_settings().expect("settings").geoip_enabled,
            updated.geoip_enabled
        );
        changes.mark_unchanged();
    }

    #[test]
    fn sync_records_are_saved_and_published_without_touching_other_columns() {
        let (_file, store, feed) = feed();
        let at = datetime!(2026-01-02 03:04:05 UTC);

        feed.record_hosts_blocklist_sync(at).expect("hosts");
        feed.record_geoip_sync(at).expect("geoip");

        assert_eq!(feed.current().hosts_blocklist_last_updated, at);
        assert_eq!(feed.current().geoip_database_last_updated, at);
        let saved = store.get_settings().expect("settings");
        assert_eq!(saved.hosts_blocklist_last_updated, at);
        assert_eq!(saved.geoip_database_last_updated, at);
    }
}
