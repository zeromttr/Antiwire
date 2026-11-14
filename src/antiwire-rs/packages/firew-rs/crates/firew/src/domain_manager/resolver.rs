//! The resolver worker: queued commands, background refresh passes, and lookups.

use std::collections::{BTreeSet, HashMap};
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use firew_core::{Error, ErrorKind, Rule, RuleKey};
use ipnet::IpNet;
use parking_lot::Mutex;

use crate::firewall::FirewallState;

use super::{
    expand_with_networks, CustomDnsResolver, DomainCommand, FamilySupport, RefreshErrors,
    ResolvedNetworks, SharedBookkeeping, MAX_CONCURRENT_LOOKUPS, MAX_REFRESH_ERRORS,
};

pub(super) fn run_resolver(
    rx: &Receiver<DomainCommand>,
    bookkeeping: &SharedBookkeeping,
    refresh_errors: &RefreshErrors,
    stopped: &Arc<AtomicBool>,
    state: &Weak<Mutex<FirewallState>>,
    refresh_interval: Duration,
) {
    let mut registry: HashMap<RuleKey, Rule> = HashMap::new();
    let active_lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut next_refresh = Instant::now() + refresh_interval;
    // The refresh pass runs on its own thread so this loop keeps serving
    // commands: an initial lookup for `add_rule` must not wait behind every
    // registered domain being re-resolved, and shutdown must not wait for it.
    let mut refresh_pass: Option<JoinHandle<()>> = None;

    loop {
        if stopped.load(Ordering::Acquire) {
            return;
        }
        let now = Instant::now();
        let wait = next_refresh.saturating_duration_since(now);
        match rx.recv_timeout(wait) {
            Ok(command) => {
                if apply_command(command, &mut registry, &active_lookups) {
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }

        while let Ok(command) = rx.try_recv() {
            if apply_command(command, &mut registry, &active_lookups) {
                return;
            }
        }

        if stopped.load(Ordering::Acquire) {
            return;
        }
        if Instant::now() < next_refresh {
            continue;
        }
        next_refresh = Instant::now() + refresh_interval;

        if state.strong_count() == 0 {
            return;
        }
        if refresh_pass
            .as_ref()
            .is_some_and(|pass| !pass.is_finished())
        {
            // The previous pass is still resolving; skip this tick.
            continue;
        }
        if registry.is_empty() {
            continue;
        }
        let snapshot: Vec<(RuleKey, Rule)> = registry
            .iter()
            .map(|(key, rule)| (key.clone(), rule.clone()))
            .collect();
        let pass_bookkeeping = bookkeeping.clone();
        let pass_errors = refresh_errors.clone();
        let pass_stopped = stopped.clone();
        let pass_state = state.clone();
        refresh_pass = match thread::Builder::new()
            .name("firew-rs-dns-refresh".to_owned())
            .spawn(move || {
                run_refresh_pass(
                    &snapshot,
                    &pass_bookkeeping,
                    &pass_errors,
                    &pass_stopped,
                    &pass_state,
                );
            }) {
            Ok(pass) => Some(pass),
            Err(source) => {
                record_refresh_error(
                    refresh_errors,
                    Error::new(ErrorKind::Internal, "failed to start DNS refresh pass")
                        .with_source(source),
                );
                None
            }
        };
    }
}

/// Re-resolves every registered domain rule once and installs changed results.
fn run_refresh_pass(
    snapshot: &[(RuleKey, Rule)],
    bookkeeping: &SharedBookkeeping,
    refresh_errors: &RefreshErrors,
    stopped: &AtomicBool,
    state: &Weak<Mutex<FirewallState>>,
) {
    let Some(upgraded_state) = state.upgrade() else {
        return;
    };
    let (backend_supports_ipv6, max_set_entries, override_resolver) = {
        let guard = upgraded_state.lock();
        if guard.closed {
            return;
        }
        (
            guard.backend.supports_ipv6(),
            guard.backend.max_address_set_entries(),
            guard.dns_resolver.clone(),
        )
    };
    drop(upgraded_state);

    for (key, rule) in snapshot {
        if stopped.load(Ordering::Acquire) {
            return;
        }
        // The resolution this lookup would replace. If anything installs a
        // newer one while the lookup runs, this result is stale and dropped.
        let baseline = bookkeeping.lock().resolutions.get(key).cloned();
        let family = FamilySupport::for_rule(rule, backend_supports_ipv6);
        let resolution_result = if let Some(ref resolver) = override_resolver {
            resolve_with_custom(rule.remote_domains(), family, resolver)
        } else {
            resolve_domains(rule.remote_domains(), family)
        };
        match resolution_result {
            Ok(networks) if !networks.is_empty() => {
                let should_apply = {
                    let bookkeeping = bookkeeping.lock();
                    bookkeeping.registrations.get(key) == Some(rule)
                        && same_resolution(bookkeeping.resolutions.get(key), baseline.as_ref())
                        && baseline
                            .as_ref()
                            .is_none_or(|current| current.as_ref() != networks)
                };
                if !should_apply {
                    continue;
                }
                if let Err(error) = apply_refresh(
                    state,
                    bookkeeping,
                    stopped,
                    rule,
                    &networks,
                    baseline.as_ref(),
                    max_set_entries,
                ) {
                    record_refresh_error(refresh_errors, error);
                }
            }
            Ok(_) => record_refresh_error(
                refresh_errors,
                Error::new(
                    ErrorKind::DnsResolutionFailed,
                    "DNS refresh returned no compatible addresses",
                )
                .with_logical_key(rule.logical_key()),
            ),
            Err(error) => {
                record_refresh_error(refresh_errors, error.with_logical_key(rule.logical_key()));
            }
        }
    }
}

/// Whether two resolution snapshots are the same installed value, not merely
/// equal addresses: every install stores a fresh `Arc`.
fn same_resolution(left: Option<&ResolvedNetworks>, right: Option<&ResolvedNetworks>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        _ => false,
    }
}

pub(super) fn resolve_with_custom(
    domains: &[String],
    family: FamilySupport,
    resolver: &CustomDnsResolver,
) -> Result<Vec<IpNet>, Error> {
    let mut combined = BTreeSet::new();
    for domain in domains {
        for net in resolver(domain)? {
            combined.insert(net.trunc());
        }
    }
    let raw: Vec<IpNet> = combined.into_iter().collect();
    Ok(family.filter(&raw))
}

fn record_refresh_error(errors: &RefreshErrors, error: Error) {
    let mut errors = errors.lock();
    if errors.len() == MAX_REFRESH_ERRORS {
        errors.pop_front();
    }
    errors.push_back(error);
}

pub(super) fn restore_entry<K: Eq + std::hash::Hash, V>(
    entries: &mut HashMap<K, V>,
    key: K,
    previous: Option<V>,
) {
    if let Some(previous) = previous {
        entries.insert(key, previous);
    } else {
        entries.remove(&key);
    }
}

fn apply_refresh(
    state: &Weak<Mutex<FirewallState>>,
    bookkeeping: &SharedBookkeeping,
    stopped: &AtomicBool,
    rule: &Rule,
    networks: &[IpNet],
    baseline: Option<&ResolvedNetworks>,
    max_set_entries: Option<usize>,
) -> Result<(), Error> {
    let state = state.upgrade().ok_or_else(|| {
        Error::new(
            ErrorKind::DnsResolutionFailed,
            "firewall owner ended during DNS refresh",
        )
        .with_logical_key(rule.logical_key())
    })?;
    let mut state = state.lock();
    if state.closed || stopped.load(Ordering::Acquire) {
        return Ok(());
    }
    {
        // Re-check under the firewall lock, which every writer of desired state
        // holds: the rule must still be registered, and no newer resolution may
        // have been installed while the lookup ran. The logical rule alone is
        // not enough, because re-resolving an unchanged rule leaves it equal.
        let bookkeeping = bookkeeping.lock();
        if bookkeeping.registrations.get(rule.logical_key()) != Some(rule)
            || !same_resolution(bookkeeping.resolutions.get(rule.logical_key()), baseline)
        {
            return Ok(());
        }
    }
    let native = state
        .native_rules
        .get(rule.logical_key())
        .cloned()
        .ok_or_else(|| {
            Error::new(
                ErrorKind::RuleNotFound,
                "domain-backed native rule is missing during refresh",
            )
            .with_logical_key(rule.logical_key())
        })?;
    let expanded = expand_with_networks(rule, networks, max_set_entries)?;
    state.backend.validate_rule(&expanded)?;

    let new_native = if state.backend.supports_transactions() {
        state.backend.begin_transaction()?;
        let updated = match state.backend.update_rule(&native, &expanded) {
            Ok(updated) => updated,
            Err(error) => {
                let _ = state.backend.abort_transaction();
                return Err(error);
            }
        };
        if let Err(error) = state.backend.commit_transaction() {
            let _ = state.backend.abort_transaction();
            return Err(error);
        }
        updated
    } else {
        state.backend.update_rule(&native, &expanded)?
    };
    state
        .native_rules
        .insert(rule.logical_key().clone(), new_native);
    let still_registered = bookkeeping.lock().registrations.get(rule.logical_key()) == Some(rule);
    if still_registered {
        bookkeeping
            .lock()
            .resolutions
            .insert(rule.logical_key().clone(), networks.to_vec().into());
    }
    Ok(())
}

fn apply_command(
    command: DomainCommand,
    registry: &mut HashMap<RuleKey, Rule>,
    active_lookups: &Arc<std::sync::atomic::AtomicUsize>,
) -> bool {
    match command {
        DomainCommand::Register(rule) => {
            registry.insert(rule.logical_key().clone(), rule);
            false
        }
        DomainCommand::Unregister(key) => {
            // `unregister` already cleared the bookkeeping when it queued this.
            // Touching it here would delete a newer resolution registered for
            // the same key after the command was queued.
            registry.remove(&key);
            false
        }
        DomainCommand::Replace(replacement) => {
            *registry = replacement;
            false
        }
        DomainCommand::Resolve {
            domains,
            family,
            reply,
        } => {
            let current = active_lookups.fetch_add(1, Ordering::AcqRel);
            if current >= MAX_CONCURRENT_LOOKUPS {
                active_lookups.fetch_sub(1, Ordering::AcqRel);
                let _ = reply.try_send(Err(Error::new(
                    ErrorKind::LimitExceeded,
                    "too many concurrent DNS resolution requests",
                )));
                return false;
            }
            let counter = active_lookups.clone();
            if thread::Builder::new()
                .name("firew-rs-dns-lookup".to_owned())
                .spawn(move || {
                    let result = resolve_domains(&domains, family);
                    counter.fetch_sub(1, Ordering::AcqRel);
                    let _ = reply.try_send(result);
                })
                .is_err()
            {
                active_lookups.fetch_sub(1, Ordering::AcqRel);
            }
            false
        }
        DomainCommand::Shutdown => true,
    }
}

pub(super) fn resolve_domains(
    domains: &[String],
    family: FamilySupport,
) -> Result<Vec<IpNet>, Error> {
    let mut networks = BTreeSet::new();
    for domain in domains {
        let addresses = (domain.as_str(), 0).to_socket_addrs().map_err(|source| {
            Error::new(
                ErrorKind::DnsResolutionFailed,
                format!("failed to resolve domain {domain}"),
            )
            .with_source(source)
        })?;
        networks.extend(addresses.map(|address| IpNet::from(address.ip())));
    }
    let all: Vec<IpNet> = networks.into_iter().collect();
    Ok(family.filter(&all))
}
