//! Firewall builder.

use std::time::Duration;

use firew_sys::{BackendConfig, BackendPreference};

/// Configures a [`super::Firewall`] instance.
#[derive(Clone, Debug)]
pub struct FirewallBuilder {
    name_prefix: String,
    application_name: String,
    memory_mode: bool,
    prefer_backend: BackendPreference,
    dns_timeout: Duration,
    dns_refresh_interval: Duration,
    max_address_set_entries: Option<usize>,
}

impl FirewallBuilder {
    /// Creates a builder with the given manager prefix.
    #[must_use]
    pub fn new(name_prefix: impl Into<String>) -> Self {
        Self {
            name_prefix: name_prefix.into(),
            application_name: String::new(),
            memory_mode: false,
            prefer_backend: BackendPreference::Auto,
            dns_timeout: Duration::from_secs(5),
            dns_refresh_interval: Duration::from_secs(60),
            max_address_set_entries: None,
        }
    }

    /// Sets the manager name prefix isolating managed rules.
    #[must_use]
    pub fn name_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.name_prefix = prefix.into();
        self
    }

    /// Sets the application name appended to Windows rule display names.
    #[must_use]
    pub fn application_name(mut self, name: impl Into<String>) -> Self {
        self.application_name = name.into();
        self
    }

    /// Enables memory-mode lifecycle tracking and cleanup on close.
    #[must_use]
    pub fn memory_mode(mut self, enabled: bool) -> Self {
        self.memory_mode = enabled;
        self
    }

    /// Overrides backend auto-detection.
    #[must_use]
    pub fn prefer_backend(mut self, preference: BackendPreference) -> Self {
        self.prefer_backend = preference;
        self
    }

    /// Sets the deadline for initial domain resolution.
    #[must_use]
    pub fn dns_timeout(mut self, timeout: Duration) -> Self {
        self.dns_timeout = timeout;
        self
    }

    /// Sets the interval between background domain refresh attempts.
    #[must_use]
    pub fn dns_refresh_interval(mut self, interval: Duration) -> Self {
        self.dns_refresh_interval = interval;
        self
    }

    /// Overrides the backend's native address-set ceiling.
    ///
    /// Only meaningful for backends that collapse many remote addresses into
    /// one native object. Use it to tune the Windows ceiling once measured.
    #[must_use]
    pub fn max_address_set_entries(mut self, limit: usize) -> Self {
        self.max_address_set_entries = Some(limit);
        self
    }

    /// Builds a [`super::Firewall`].
    ///
    /// # Errors
    /// Returns an error when the platform backend cannot be opened.
    pub fn build(self) -> Result<super::Firewall, firew_core::Error> {
        let config = BackendConfig {
            name_prefix: self.name_prefix,
            application_name: self.application_name,
            memory_mode: self.memory_mode,
            prefer_backend: self.prefer_backend,
            max_address_set_entries: self.max_address_set_entries,
        };
        super::Firewall::open(config, self.dns_timeout, self.dns_refresh_interval)
    }
}
