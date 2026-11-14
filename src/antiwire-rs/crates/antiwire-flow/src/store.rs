use antiwire_store::{
    ConnectionDomainUpgrade, ConnectionLogAttribution, DnsCacheEntry, NewConnectionLog, Store,
};
use time::OffsetDateTime;

use crate::error::Result;

/// Persistence surface for batched flow writes.
pub trait FlowStore: Send + Sync {
    /// Persists a batch of connection-log deltas.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing store rejects the write.
    fn insert_batch(&self, logs: &[NewConnectionLog]) -> Result<()>;

    /// Moves an existing provisional row to its resolved application.
    ///
    /// # Errors
    ///
    /// Returns an error when the backing store rejects the update.
    fn reattribute(&self, attribution: &ConnectionLogAttribution) -> Result<()>;
}

/// Adapts [`Store::insert_connection_logs`] (per-connection triple upsert) to [`FlowStore`].
pub struct StoreFlowAdapter {
    store: std::sync::Arc<Store>,
}

impl StoreFlowAdapter {
    pub fn new(store: std::sync::Arc<Store>) -> Self {
        Self { store }
    }
}

impl FlowStore for StoreFlowAdapter {
    fn insert_batch(&self, logs: &[NewConnectionLog]) -> Result<()> {
        self.store.insert_connection_logs(logs).map_err(Into::into)
    }

    fn reattribute(&self, attribution: &ConnectionLogAttribution) -> Result<()> {
        self.store
            .reattribute_connection_log(attribution)
            .map_err(Into::into)
    }
}

/// What the flow processor reads and writes about domains: the DNS answer
/// cache, domain sightings, and late domain upgrades of logged connections.
pub trait DomainStore: Send + Sync {
    /// The cached DNS answer for an address.
    ///
    /// # Errors
    ///
    /// When the store cannot be read.
    fn get_dns_cache(&self, id: &str) -> antiwire_store::Result<Option<DnsCacheEntry>>;

    /// Saves DNS answers observed since the last flush.
    ///
    /// # Errors
    ///
    /// When the store rejects the write.
    fn upsert_dns_cache_batch(&self, entries: &[DnsCacheEntry]) -> antiwire_store::Result<()>;

    /// Records that `domain` was seen, returning whether it was new.
    ///
    /// # Errors
    ///
    /// When the store rejects the write.
    fn record_domain_sighting(
        &self,
        domain: &str,
        seen_at: OffsetDateTime,
    ) -> antiwire_store::Result<bool>;

    /// Confirms the domains of logged connections, returning which rows
    /// were updated.
    ///
    /// # Errors
    ///
    /// When the store rejects the update.
    fn upgrade_connection_domains(
        &self,
        upgrades: &[ConnectionDomainUpgrade],
    ) -> antiwire_store::Result<Vec<bool>>;
}

impl DomainStore for Store {
    fn get_dns_cache(&self, id: &str) -> antiwire_store::Result<Option<DnsCacheEntry>> {
        Store::get_dns_cache(self, id)
    }

    fn upsert_dns_cache_batch(&self, entries: &[DnsCacheEntry]) -> antiwire_store::Result<()> {
        Store::upsert_dns_cache_batch(self, entries)
    }

    fn record_domain_sighting(
        &self,
        domain: &str,
        seen_at: OffsetDateTime,
    ) -> antiwire_store::Result<bool> {
        Store::record_domain_sighting(self, domain, seen_at)
    }

    fn upgrade_connection_domains(
        &self,
        upgrades: &[ConnectionDomainUpgrade],
    ) -> antiwire_store::Result<Vec<bool>> {
        Store::upgrade_connection_domains(self, upgrades)
    }
}

impl<F> FlowStore for F
where
    F: Fn(&[NewConnectionLog]) -> Result<()> + Send + Sync,
{
    fn insert_batch(&self, logs: &[NewConnectionLog]) -> Result<()> {
        self(logs)
    }

    /// A closure sink keeps no provisional rows, so there is nothing to move.
    fn reattribute(&self, _attribution: &ConnectionLogAttribution) -> Result<()> {
        Ok(())
    }
}
