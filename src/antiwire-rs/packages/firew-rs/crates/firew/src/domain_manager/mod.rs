//! Domain name resolution for ephemeral firewall rules.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender, SyncSender};
use std::sync::{Arc, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use firew_core::{
    cartesian_exceeds_limits, AddressSetMode, Error, ErrorKind, Protocol, Rule, RuleKey,
};
use ipnet::IpNet;
use parking_lot::Mutex;

use crate::firewall::FirewallState;

mod resolver;
#[cfg(test)]
mod tests;

use resolver::{resolve_with_custom, restore_entry, run_resolver};

pub(crate) type ResolvedNetworks = Arc<[IpNet]>;
pub(crate) type CustomDnsResolver = Arc<dyn Fn(&str) -> Result<Vec<IpNet>, Error> + Send + Sync>;
type RefreshErrors = Arc<Mutex<VecDeque<Error>>>;

#[derive(Default)]
struct DomainBookkeeping {
    registrations: HashMap<RuleKey, Rule>,
    resolutions: HashMap<RuleKey, ResolvedNetworks>,
}

type SharedBookkeeping = Arc<Mutex<DomainBookkeeping>>;

const MAX_REFRESH_ERRORS: usize = 64;
const MAX_CONCURRENT_LOOKUPS: usize = 8;

/// Address-family filter for domain resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FamilySupport {
    pub(crate) allow_v4: bool,
    pub(crate) allow_v6: bool,
}

impl Default for FamilySupport {
    fn default() -> Self {
        Self {
            allow_v4: true,
            allow_v6: true,
        }
    }
}

impl FamilySupport {
    pub(crate) fn for_rule(rule: &Rule, backend_supports_ipv6: bool) -> Self {
        let mut allow_v4 = true;
        let mut allow_v6 = backend_supports_ipv6;
        match rule.protocol() {
            Protocol::IcmpV4 => allow_v6 = false,
            Protocol::IcmpV6 => allow_v4 = false,
            _ => {}
        }
        if !rule.local_addresses().is_empty() {
            let local_has_v4 = rule.local_addresses().iter().any(|n| n.addr().is_ipv4());
            let local_has_v6 = rule.local_addresses().iter().any(|n| n.addr().is_ipv6());
            allow_v4 &= local_has_v4;
            allow_v6 &= local_has_v6;
        }
        Self { allow_v4, allow_v6 }
    }

    pub(crate) fn filter(self, networks: &[IpNet]) -> Vec<IpNet> {
        networks
            .iter()
            .copied()
            .filter(|net| {
                (net.addr().is_ipv4() && self.allow_v4) || (net.addr().is_ipv6() && self.allow_v6)
            })
            .collect()
    }
}

enum DomainCommand {
    Register(Rule),
    Unregister(RuleKey),
    Replace(HashMap<RuleKey, Rule>),
    Resolve {
        domains: Vec<String>,
        family: FamilySupport,
        reply: SyncSender<Result<Vec<IpNet>, Error>>,
    },
    Shutdown,
}

struct DomainSetManagerInner {
    command_tx: Sender<DomainCommand>,
    bookkeeping: SharedBookkeeping,
    refresh_errors: RefreshErrors,
    stopped: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

/// Background resolver maintaining domain-to-address mappings.
#[derive(Clone)]
pub struct DomainSetManager {
    inner: Arc<DomainSetManagerInner>,
}

pub(crate) struct DomainCheckpoint {
    registrations: HashMap<RuleKey, Rule>,
    resolutions: HashMap<RuleKey, ResolvedNetworks>,
}

impl DomainSetManager {
    /// Creates and starts the resolver thread.
    ///
    /// The thread retains the last valid address set when a periodic refresh fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the refresh worker cannot be started.
    pub fn new(
        refresh_interval: Duration,
        state: Weak<Mutex<FirewallState>>,
    ) -> Result<Self, Error> {
        let bookkeeping = Arc::new(Mutex::new(DomainBookkeeping::default()));
        let refresh_errors = Arc::new(Mutex::new(VecDeque::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let (command_tx, command_rx) = mpsc::channel();
        let bookkeeping_clone = bookkeeping.clone();
        let error_clone = refresh_errors.clone();
        let stopped_clone = stopped.clone();
        let worker = thread::Builder::new()
            .name("firew-rs-domain-resolver".to_owned())
            .spawn(move || {
                run_resolver(
                    &command_rx,
                    &bookkeeping_clone,
                    &error_clone,
                    &stopped_clone,
                    &state,
                    refresh_interval,
                );
            })
            .map_err(|source| {
                Error::new(
                    ErrorKind::DnsResolutionFailed,
                    "failed to start domain refresh worker",
                )
                .with_source(source)
            })?;
        Ok(Self {
            inner: Arc::new(DomainSetManagerInner {
                command_tx,
                bookkeeping,
                refresh_errors,
                stopped,
                worker: Mutex::new(Some(worker)),
            }),
        })
    }

    pub(crate) fn resolve_initial_for_family(
        &self,
        rule: &Rule,
        timeout: Duration,
        family: FamilySupport,
        override_resolver: Option<&CustomDnsResolver>,
    ) -> Result<ResolvedNetworks, Error> {
        if rule.remote_domains().is_empty() {
            return Ok(Arc::from([]));
        }
        if self.inner.stopped.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::DnsResolutionFailed,
                "domain resolver worker is stopped",
            )
            .with_logical_key(rule.logical_key()));
        }

        let networks = if let Some(resolver) = override_resolver {
            resolve_with_custom(rule.remote_domains(), family, resolver)
                .map_err(|e| e.with_logical_key(rule.logical_key()))?
        } else {
            self.resolve_on_worker(rule, timeout, family)?
        };
        if networks.is_empty() {
            return Err(Error::new(
                ErrorKind::DnsResolutionFailed,
                "DNS resolution returned no compatible addresses",
            )
            .with_logical_key(rule.logical_key()));
        }
        Ok(networks.into())
    }

    /// Resolves through the worker, which runs each lookup on its own thread so
    /// a slow resolver costs this caller its timeout and nothing more.
    fn resolve_on_worker(
        &self,
        rule: &Rule,
        timeout: Duration,
        family: FamilySupport,
    ) -> Result<Vec<IpNet>, Error> {
        let domains = rule.remote_domains().to_vec();
        let (tx, rx) = mpsc::sync_channel(1);
        self.inner
            .command_tx
            .send(DomainCommand::Resolve {
                domains,
                family,
                reply: tx,
            })
            .map_err(|source| {
                Error::new(
                    ErrorKind::DnsResolutionFailed,
                    "domain resolver worker is unavailable",
                )
                .with_logical_key(rule.logical_key())
                .with_source(source)
            })?;

        rx.recv_timeout(timeout).map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => Error::new(
                ErrorKind::DnsResolutionTimeout,
                "initial DNS resolution timed out",
            )
            .with_logical_key(rule.logical_key()),
            mpsc::RecvTimeoutError::Disconnected => Error::new(
                ErrorKind::DnsResolutionFailed,
                "initial DNS resolver stopped unexpectedly",
            )
            .with_logical_key(rule.logical_key()),
        })?
    }

    pub(crate) fn register_resolved(
        &self,
        rule: &Rule,
        networks: ResolvedNetworks,
    ) -> Result<(), Error> {
        let key = rule.logical_key().clone();
        let (previous_resolution, previous_registration) = {
            let mut bookkeeping = self.inner.bookkeeping.lock();
            let previous_resolution = bookkeeping.resolutions.insert(key.clone(), networks);
            let previous_registration = bookkeeping.registrations.insert(key.clone(), rule.clone());
            (previous_resolution, previous_registration)
        };
        if let Err(source) = self
            .inner
            .command_tx
            .send(DomainCommand::Register(rule.clone()))
        {
            let mut bookkeeping = self.inner.bookkeeping.lock();
            restore_entry(
                &mut bookkeeping.resolutions,
                key.clone(),
                previous_resolution,
            );
            restore_entry(&mut bookkeeping.registrations, key, previous_registration);
            return Err(Error::new(
                ErrorKind::DnsResolutionFailed,
                "domain refresh worker is unavailable",
            )
            .with_logical_key(rule.logical_key())
            .with_source(source));
        }
        Ok(())
    }

    /// Unregisters a domain-backed rule.
    pub fn unregister(&self, logical_key: &RuleKey) {
        let mut bookkeeping = self.inner.bookkeeping.lock();
        bookkeeping.registrations.remove(logical_key);
        bookkeeping.resolutions.remove(logical_key);
        drop(bookkeeping);
        let _ = self
            .inner
            .command_tx
            .send(DomainCommand::Unregister(logical_key.clone()));
    }

    /// Replaces all registered domain rules and prunes any absent keys.
    pub(crate) fn retain_only(&self, keep_keys: &std::collections::HashSet<RuleKey>) {
        let replacement = {
            let mut bookkeeping = self.inner.bookkeeping.lock();
            bookkeeping
                .registrations
                .retain(|k, _| keep_keys.contains(k));
            bookkeeping.resolutions.retain(|k, _| keep_keys.contains(k));
            bookkeeping.registrations.clone()
        };
        let _ = self
            .inner
            .command_tx
            .send(DomainCommand::Replace(replacement));
    }

    pub(crate) fn resolved_for(&self, key: &RuleKey) -> Option<ResolvedNetworks> {
        self.inner.bookkeeping.lock().resolutions.get(key).cloned()
    }

    pub(crate) fn registered_rule(&self, key: &RuleKey) -> Option<Rule> {
        self.inner
            .bookkeeping
            .lock()
            .registrations
            .get(key)
            .cloned()
    }

    pub(crate) fn checkpoint(&self) -> DomainCheckpoint {
        let bookkeeping = self.inner.bookkeeping.lock();
        DomainCheckpoint {
            registrations: bookkeeping.registrations.clone(),
            resolutions: bookkeeping.resolutions.clone(),
        }
    }

    pub(crate) fn restore(&self, checkpoint: &DomainCheckpoint) {
        let mut bookkeeping = self.inner.bookkeeping.lock();
        bookkeeping
            .registrations
            .clone_from(&checkpoint.registrations);
        bookkeeping.resolutions.clone_from(&checkpoint.resolutions);
        drop(bookkeeping);
        let _ = self
            .inner
            .command_tx
            .send(DomainCommand::Replace(checkpoint.registrations.clone()));
    }

    /// Signals the background resolver worker to stop and joins it within a bounded deadline.
    pub(crate) fn shutdown(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        let _ = self.inner.command_tx.send(DomainCommand::Shutdown);
        if let Some(worker) = self.inner.worker.lock().take() {
            let _ = worker.join();
        }
    }

    #[cfg(test)]
    pub(crate) fn is_registered(&self, logical_key: &RuleKey) -> bool {
        self.inner
            .bookkeeping
            .lock()
            .registrations
            .contains_key(logical_key)
    }

    pub(crate) fn expand_resolved(
        rule: &Rule,
        resolved: &[IpNet],
        max_set_entries: Option<usize>,
    ) -> Result<Rule, Error> {
        expand_with_networks(rule, resolved, max_set_entries)
    }

    /// The address rule installed natively for `rule`: the rule itself when it
    /// names no domains, otherwise its expansion with the current resolution.
    /// `None` when a domain rule has no usable resolution.
    pub(crate) fn expected_native(
        &self,
        rule: &Rule,
        max_set_entries: Option<usize>,
    ) -> Option<Rule> {
        if rule.remote_domains().is_empty() {
            return Some(rule.clone());
        }
        let resolved = self.resolved_for(rule.logical_key())?;
        expand_with_networks(rule, &resolved, max_set_entries).ok()
    }

    pub(crate) fn take_refresh_errors(&self) -> Vec<Error> {
        self.inner.refresh_errors.lock().drain(..).collect()
    }
}

pub(crate) fn expand_with_networks(
    rule: &Rule,
    resolved: &[IpNet],
    max_set_entries: Option<usize>,
) -> Result<Rule, Error> {
    let mut builder = rule
        .to_builder()
        .without_remote_addresses()
        .without_remote_domains();

    let mut combined: Vec<IpNet> = rule
        .remote_addresses()
        .iter()
        .chain(resolved.iter())
        .map(IpNet::trunc)
        .collect();
    combined.sort_unstable();
    combined.dedup();

    let cartesian_exceeds = cartesian_exceeds_limits(
        rule.direction(),
        combined.len(),
        rule.local_addresses().len(),
        rule.remote_ports().len(),
        rule.local_ports().len(),
    );

    let use_set = rule.address_set_mode() == AddressSetMode::Set
        || (cartesian_exceeds && max_set_entries.is_some());

    if use_set {
        builder = builder.remote_address_set(combined);
    } else {
        for address in combined {
            builder = builder.remote_address(address);
        }
    }
    builder.build()
}

impl Drop for DomainSetManagerInner {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _ = self.command_tx.send(DomainCommand::Shutdown);
        if let Some(worker) = self.worker.lock().take() {
            let _ = worker.join();
        }
    }
}
