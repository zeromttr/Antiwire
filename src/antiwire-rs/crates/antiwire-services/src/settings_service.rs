//! Saving the daemon settings and putting them into effect.

use std::sync::Arc;

use antiwire_dns::{
    apply_dns_settings_change, doh_block_targets, DnsDependencies, DnsInterceptorSlot,
};
use antiwire_platform::{SiemConfig, SiemExporter};
use antiwire_store::{DaemonSetting, StoreError};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::doh::DohBlocker;
use crate::geo_database::GeoDatabaseService;
use crate::hosts_blocklist::HostsBlocklistService;
use crate::settings_feed::SettingsFeed;

/// Why a settings update was refused or failed. Nothing was saved.
#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    /// The settings are not valid. Nothing was saved.
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Store(StoreError),
    #[error("settings save did not finish: {0}")]
    Interrupted(String),
}

/// A saved settings update.
#[derive(Debug, Clone)]
pub struct SettingsUpdate {
    pub settings: DaemonSetting,
    /// Each part that could not be put into effect, naming the part and why.
    pub not_applied: Vec<String>,
}

/// What the settings service applies changes to.
pub struct SettingsServiceParts {
    pub settings: SettingsFeed,
    pub doh: Arc<DohBlocker>,
    pub dns: DnsDependencies,
    pub dns_interceptor: Arc<DnsInterceptorSlot>,
    pub hosts_blocklist: Arc<HostsBlocklistService>,
    pub geo_database: Arc<GeoDatabaseService>,
    pub siem: SiemExporter,
}

/// Saves settings changes and puts them into effect, one change at a time.
pub struct SettingsService {
    apply: Arc<SettingsServiceParts>,
    /// Held from saving a change until it is fully applied, so a later
    /// change cannot save after this one and then be overtaken applying.
    gate: Arc<Mutex<()>>,
}

impl SettingsService {
    #[must_use]
    pub fn new(parts: SettingsServiceParts) -> Self {
        Self {
            apply: Arc::new(parts),
            gate: Arc::new(Mutex::new(())),
        }
    }

    /// The settings as last saved.
    #[must_use]
    pub fn current(&self) -> Arc<DaemonSetting> {
        self.apply.settings.current()
    }

    /// Saves the settings `merge` derives from the saved ones, then puts the
    /// change into effect.
    ///
    /// Waits up to [`antiwire_tuning::SETTINGS_APPLY_DEADLINE`] for that.
    /// What is still running then carries on in the background, still ahead
    /// of any later update, and is reported in `not_applied` as not done yet.
    ///
    /// # Errors
    ///
    /// [`SettingsError::Invalid`] for settings the daemon cannot put into
    /// effect, or a store failure. Nothing is saved then.
    pub async fn update<F>(&self, merge: F) -> Result<SettingsUpdate, SettingsError>
    where
        F: FnOnce(&DaemonSetting) -> DaemonSetting + Send + 'static,
    {
        let gate = Arc::clone(&self.gate).lock_owned().await;
        let feed = self.apply.settings.clone();
        let (previous, updated) = tokio::task::spawn_blocking(move || {
            feed.modify(|saved| {
                let merged = merge(saved);
                validate(&merged).map_err(StoreError::InvalidInput)?;
                Ok(merged)
            })
        })
        .await
        .map_err(|error| SettingsError::Interrupted(error.to_string()))?
        .map_err(|error| match error {
            StoreError::InvalidInput(problem) => SettingsError::Invalid(problem),
            other => SettingsError::Store(other),
        })?;

        let mut applying = tokio::spawn(apply(
            Arc::clone(&self.apply),
            previous,
            updated.clone(),
            gate,
        ));
        let not_applied =
            match tokio::time::timeout(antiwire_tuning::SETTINGS_APPLY_DEADLINE, &mut applying)
                .await
            {
                Ok(Ok(not_applied)) => not_applied,
                Ok(Err(error)) => vec![format!("Applying the settings stopped: {error}")],
                Err(_) => vec![
                    "Some settings are still being put into effect in the background".to_owned(),
                ],
            };
        Ok(SettingsUpdate {
            settings: updated,
            not_applied,
        })
    }
}

/// Why the daemon cannot put `settings` into effect, checked before saving.
fn validate(settings: &DaemonSetting) -> Result<(), String> {
    if !antiwire_dns::is_known_dns_protocol(&settings.dns_protocol) {
        return Err(format!("unknown DNS protocol: {}", settings.dns_protocol));
    }
    antiwire_dns::check_upstream_settings(settings).map_err(|error| error.to_string())?;
    let max_age = settings.dns_new_domain_max_age_days;
    if !antiwire_dns::is_supported_new_domain_max_age(max_age) {
        return Err(format!(
            "new domain age must be one of {:?} days, not {max_age}",
            antiwire_dns::NEW_DOMAIN_MAX_AGE_DAYS
        ));
    }
    Ok(())
}

/// Puts the change from `previous` to `updated` into effect, in order, and
/// returns what could not be. Releases `gate` when done.
async fn apply(
    parts: Arc<SettingsServiceParts>,
    previous: DaemonSetting,
    updated: DaemonSetting,
    gate: OwnedMutexGuard<()>,
) -> Vec<String> {
    let mut not_applied = Vec::new();
    if let Some(sink) = &parts.dns.block_sink {
        sink.update_runtime_settings(
            updated.log_daemon_connections,
            updated.notify_threat_detected,
        );
    }

    let doh_changed = doh_blocking_changed(&previous, &updated);
    if doh_changed && updated.doh_blocking_enabled {
        // Spare both resolvers until the switch below completes, so neither
        // the old nor the new upstream is cut off mid-change.
        if let Err(error) = reconcile_doh(&parts.doh, Some(previous.clone())).await {
            not_applied.push(format!("DNS-over-HTTPS blocking: {error}"));
        }
    }
    if let Err(error) =
        apply_dns_settings_change(&parts.dns_interceptor, &parts.dns, &previous, &updated).await
    {
        tracing::warn!(%error, "dns settings apply failed");
        not_applied.push(format!("DNS: {error}"));
    }
    if doh_changed {
        if let Err(error) = reconcile_doh(&parts.doh, None).await {
            not_applied.push(format!("DNS-over-HTTPS blocking: {error}"));
        }
    }
    if let Err(error) = parts
        .hosts_blocklist
        .on_settings_changed(&previous, &updated)
        .await
    {
        tracing::warn!(%error, "hosts blocklist rebuild after a settings change failed");
        not_applied.push(format!("Blocklists: {error}"));
    }
    parts.geo_database.on_settings_changed(&previous, &updated);
    if let Err(error) = apply_siem_config(&parts.siem, &updated).await {
        tracing::warn!(%error, "siem settings apply failed");
        not_applied.push(format!("SIEM forwarding: {error}"));
    }
    drop(gate);
    not_applied
}

/// Brings the `DoH` block in line with the saved settings, also sparing the
/// resolver of `still_in_use` while a switch away from it completes.
async fn reconcile_doh(
    doh: &Arc<DohBlocker>,
    still_in_use: Option<DaemonSetting>,
) -> Result<(), String> {
    let doh = Arc::clone(doh);
    tokio::task::spawn_blocking(move || doh.reconcile(still_in_use.as_ref().as_slice()))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| {
            tracing::warn!(%error, "DoH blocking apply failed");
            error.to_string()
        })
}

/// Hands `settings` to the SIEM exporter. The update waits for the worker to
/// finish its current export, which can take seconds.
async fn apply_siem_config(siem: &SiemExporter, settings: &DaemonSetting) -> std::io::Result<()> {
    let siem = siem.clone();
    let config = SiemConfig::from_settings(settings);
    tokio::task::spawn_blocking(move || siem.update_config(config))
        .await
        .unwrap_or_else(|error| Err(std::io::Error::other(error.to_string())))
}

/// Whether the `DoH` block for `next` differs from the one installed for `prev`.
fn doh_blocking_changed(prev: &DaemonSetting, next: &DaemonSetting) -> bool {
    prev.doh_blocking_enabled != next.doh_blocking_enabled
        || (next.doh_blocking_enabled && doh_block_targets(&[prev]) != doh_block_targets(&[next]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(enabled: bool, provider: &str) -> DaemonSetting {
        DaemonSetting {
            doh_blocking_enabled: enabled,
            dns_protocol: "doh".to_owned(),
            doh_provider: provider.to_owned(),
            ..DaemonSetting::default()
        }
    }

    #[test]
    fn the_doh_block_follows_the_toggle_and_the_upstream() {
        let on = settings(true, "cloudflare");
        assert!(!doh_blocking_changed(&on, &on.clone()));
        assert!(doh_blocking_changed(&on, &settings(false, "cloudflare")));
        assert!(doh_blocking_changed(&settings(false, "cloudflare"), &on));
        assert!(doh_blocking_changed(&on, &settings(true, "google")));
        // Off on both sides: a provider change installs nothing.
        assert!(!doh_blocking_changed(
            &settings(false, "cloudflare"),
            &settings(false, "google")
        ));
    }

    #[test]
    fn settings_the_daemon_cannot_use_are_refused() {
        assert!(validate(&DaemonSetting::default()).is_ok());
        assert!(validate(&DaemonSetting {
            dns_protocol: "carrier-pigeon".to_owned(),
            ..DaemonSetting::default()
        })
        .is_err());
        assert!(validate(&DaemonSetting {
            dns_new_domain_max_age_days: 3,
            ..DaemonSetting::default()
        })
        .is_err());
    }

    #[test]
    fn a_custom_upstream_the_resolver_cannot_dial_is_refused() {
        let custom = |url: &str| DaemonSetting {
            dns_protocol: "doh".to_owned(),
            doh_provider: "custom".to_owned(),
            doh_custom_url: url.to_owned(),
            ..DaemonSetting::default()
        };
        let error = validate(&custom("https://dns.example.test/dns-query"))
            .expect_err("an unknown upstream hostname cannot be dialled");
        assert!(error.contains("dns.example.test"), "{error}");
        assert!(validate(&custom("https://192.0.2.53/dns-query")).is_ok());
        assert!(validate(&custom("https://dns.quad9.net/dns-query")).is_ok());
    }
}
