//! macOS network-service DNS capture, loopback redirection, and restoration.

use std::process::Command;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{AppliedRedirect, RedirectCoverage};

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const LOOPBACK_V4: &str = "127.0.0.1";
const LOOPBACK_V6: &str = "::1";

#[derive(Debug, Serialize, Deserialize)]
struct NetworkServiceDns {
    service: String,
    servers: Vec<String>,
}

pub fn capture_state() -> Option<String> {
    capture_services(network_services()?, dns_servers)
}

fn capture_services(
    services: Vec<String>,
    mut read_dns: impl FnMut(&str) -> Option<Vec<String>>,
) -> Option<String> {
    if services.is_empty() {
        warn!("no enabled macOS network services; refusing DNS redirect");
        return None;
    }
    let entries = services
        .into_iter()
        .map(|service| {
            Some(NetworkServiceDns {
                servers: read_dns(&service)?,
                service,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    serde_json::to_string(&entries).ok()
}

/// Points each enabled service `plan` records, and no other, at loopback.
/// Returns whether every one it tried changed, or `None` when none did.
fn redirect_planned(redirect_v6: bool, plan: &str) -> Option<RedirectCoverage> {
    redirect_services(redirect_v6, plan, network_services, set_dns_servers)
}

/// [`redirect_planned`] over a service list and a DNS writer a test can fake.
///
/// A service that appeared after the plan was captured has no original on
/// disk, so it is left alone until a later plan records one. A plan that does
/// not parse changes nothing. Some services changing while others fail is a
/// partial redirect, which the caller retries.
fn redirect_services(
    redirect_v6: bool,
    plan: &str,
    list_services: impl FnOnce() -> Option<Vec<String>>,
    mut set_dns: impl FnMut(&str, &[&str]) -> bool,
) -> Option<RedirectCoverage> {
    let Ok(planned) = serde_json::from_str::<Vec<NetworkServiceDns>>(plan) else {
        warn!("macOS DNS redirect plan is invalid; no network service was redirected");
        return None;
    };
    let services = list_services()?;
    let mut servers = vec![LOOPBACK_V4];
    if redirect_v6 {
        servers.push(LOOPBACK_V6);
    }
    let mut changed = 0u32;
    let mut failed = 0u32;
    for service in services {
        if planned.iter().any(|entry| entry.service == service) {
            if set_dns(&service, &servers) {
                changed += 1;
            } else {
                failed += 1;
            }
        }
    }
    if changed == 0 {
        return None;
    }
    if failed == 0 {
        return Some(RedirectCoverage::Complete);
    }
    warn!(
        changed,
        failed, "some macOS network services could not be redirected; they are retried"
    );
    Some(RedirectCoverage::Partial)
}

/// Redirect and return the snapshot that restore must reverse.
pub fn redirect_capturing(redirect_v6: bool, prior_saved_json: &str) -> Option<AppliedRedirect> {
    crate::common::redirect_capturing(
        redirect_v6,
        prior_saved_json,
        capture_state,
        add_new_services,
        redirect_planned,
        flush_cache,
    )
}

/// The snapshot to persist before [`apply_redirect`] changes anything.
pub fn plan_redirect(_redirect_v6: bool, prior_saved_json: &str) -> Option<String> {
    crate::common::plan_redirect(prior_saved_json, capture_state, add_new_services)
}

/// Redirects the services `plan` records, and only those, to loopback.
/// Returns the snapshot restore must reverse, which is `plan`, and whether
/// every service it tried changed.
pub fn apply_redirect(redirect_v6: bool, plan: &str) -> Option<AppliedRedirect> {
    crate::common::apply_redirect(redirect_v6, plan, redirect_planned, flush_cache)
}

/// `prior` with the services in `current` it does not describe, for a
/// redirect that reuses a recovered snapshot.
///
/// A service already on loopback is skipped: with no original recorded for
/// it, loopback is all a restore could write back, so restore's sweep resets
/// it to automatic instead. That holds for an empty `prior` too, which older
/// versions saved when they could not read the DNS settings. A `prior` that
/// does not parse is returned unchanged.
fn add_new_services(prior: &str, current: &str) -> String {
    let (Ok(mut merged), Ok(current)) = (
        serde_json::from_str::<Vec<NetworkServiceDns>>(prior),
        serde_json::from_str::<Vec<NetworkServiceDns>>(current),
    ) else {
        return prior.to_owned();
    };
    let before = merged.len();
    for entry in current {
        let described = merged
            .iter()
            .any(|recorded| recorded.service == entry.service);
        if !described && !points_at_loopback(&entry.servers) {
            merged.push(entry);
        }
    }
    if merged.len() == before {
        return prior.to_owned();
    }
    serde_json::to_string(&merged).unwrap_or_else(|_| prior.to_owned())
}

pub fn restore(saved_state_json: &str) -> bool {
    restore_using(
        saved_state_json,
        network_services,
        dns_servers,
        set_dns_servers,
    )
}

/// Restores each service the snapshot describes, then resets every other
/// enabled service still pointing at this resolver to automatic (DHCP) DNS.
///
/// A service can be on loopback with no usable original: one added while the
/// redirect was being applied, one whose entry holds something other than
/// addresses, or any service under the `[]` older versions saved when they
/// could not read the DNS settings. Its original is unknown, so it is reset to
/// automatic, but only while it still points at this resolver's loopback
/// address. A setting the user has changed since is left alone, and so is a
/// service the snapshot restored, whose original may be a loopback resolver
/// the user runs.
///
/// `false` when any write fails, or when the services cannot be listed or
/// read for the sweep, so the redirect stays owed and the restore is retried.
fn restore_using(
    saved_state_json: &str,
    list_services: impl FnOnce() -> Option<Vec<String>>,
    mut read_dns: impl FnMut(&str) -> Option<Vec<String>>,
    mut set_dns: impl FnMut(&str, &[&str]) -> bool,
) -> bool {
    let Ok(entries) = serde_json::from_str::<Vec<NetworkServiceDns>>(saved_state_json) else {
        warn!("saved macOS DNS state is invalid; refusing to change network services");
        return false;
    };
    let mut restored = true;
    let mut handled = Vec::new();
    let mut unknown = Vec::new();
    for entry in &entries {
        if entry.service.trim().is_empty() {
            continue;
        }
        handled.push(entry.service.clone());
        if entry
            .servers
            .iter()
            .any(|ip| ip.parse::<std::net::IpAddr>().is_err())
        {
            unknown.push(entry.service.clone());
            continue;
        }
        let servers = if entry.servers.is_empty() {
            vec!["Empty"]
        } else {
            entry.servers.iter().map(String::as_str).collect()
        };
        restored &= set_dns(&entry.service, &servers);
    }
    let Some(services) = list_services() else {
        warn!(
            "could not list macOS network services; services left on loopback DNS were not reset"
        );
        return false;
    };
    unknown.extend(
        services
            .into_iter()
            .filter(|service| !handled.contains(service)),
    );
    for service in unknown {
        match read_dns(&service) {
            Some(servers) if points_at_loopback(&servers) => {
                warn!(%service, "original DNS unknown; resetting the redirected service to automatic");
                restored &= set_dns(&service, &["Empty"]);
            }
            Some(_) => {}
            None => restored = false,
        }
    }
    restored
}

/// Whether `servers` is the redirect this resolver installs.
fn points_at_loopback(servers: &[String]) -> bool {
    !servers.is_empty()
        && servers.iter().all(|server| {
            server
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        })
}

pub fn flush_cache() {
    let _ = Command::new("/usr/bin/dscacheutil")
        .arg("-flushcache")
        .status();
    let _ = Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .status();
}

fn network_services() -> Option<Vec<String>> {
    let Ok(output) = Command::new(NETWORKSETUP)
        .arg("-listallnetworkservices")
        .output()
    else {
        warn!("networksetup could not list macOS network services");
        return None;
    };
    if !output.status.success() {
        warn!("networksetup failed to list macOS network services");
        return None;
    }
    Some(parse_network_services(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn parse_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty() && !line.starts_with("An asterisk") && !line.starts_with('*')
        })
        .map(str::to_owned)
        .collect()
}

fn dns_servers(service: &str) -> Option<Vec<String>> {
    let Ok(output) = Command::new(NETWORKSETUP)
        .args(["-getdnsservers", service])
        .output()
    else {
        warn!(%service, "networksetup could not capture DNS servers");
        return None;
    };
    let result = parse_dns_servers(
        output.status.success(),
        &String::from_utf8_lossy(&output.stdout),
    );
    if result.is_none() {
        warn!(%service, "networksetup returned no reliable DNS snapshot");
    }
    result
}

fn parse_dns_servers(success: bool, stdout: &str) -> Option<Vec<String>> {
    if !success {
        return None;
    }
    let stdout = stdout.trim();
    if stdout.starts_with("There aren't any DNS Servers set on ") && stdout.lines().count() == 1 {
        return Some(Vec::new());
    }
    if stdout.is_empty() {
        return None;
    }
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| ip.to_string())
        })
        .collect()
}

fn set_dns_servers(service: &str, servers: &[&str]) -> bool {
    let status = Command::new(NETWORKSETUP)
        .arg("-setdnsservers")
        .arg(service)
        .args(servers)
        .status();
    match status {
        Ok(status) if status.success() => true,
        Ok(status) => {
            warn!(%status, %service, "networksetup failed to update DNS servers");
            false
        }
        Err(error) => {
            warn!(%error, %service, "networksetup could not update DNS servers");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeat_redirect_records_services_added_since() {
        let prior = r#"[{"service":"Wi-Fi","servers":["192.0.2.1"]}]"#;
        let current = r#"[{"service":"Wi-Fi","servers":["127.0.0.1"]},{"service":"VPN","servers":["198.51.100.1"]},{"service":"Stale","servers":["127.0.0.1"]}]"#;
        let merged: Vec<NetworkServiceDns> =
            serde_json::from_str(&add_new_services(prior, current)).expect("snapshot");
        let described: Vec<(&str, &[String])> = merged
            .iter()
            .map(|entry| (entry.service.as_str(), entry.servers.as_slice()))
            .collect();
        assert_eq!(
            described,
            [
                ("Wi-Fi", &["192.0.2.1".to_owned()][..]),
                ("VPN", &["198.51.100.1".to_owned()][..]),
            ]
        );
        assert_eq!(add_new_services("not json", current), "not json");
        assert_eq!(add_new_services(prior, prior), prior, "nothing new to add");
    }

    /// An older version's `[]` gains the services it could not read: they
    /// are redirected and later restored, and a service already on loopback
    /// is left for restore's sweep.
    #[test]
    fn an_empty_prior_gains_the_services_not_on_loopback() {
        let current = r#"[{"service":"Wi-Fi","servers":["127.0.0.1"]},{"service":"VPN","servers":["198.51.100.1"]}]"#;
        let merged: Vec<NetworkServiceDns> =
            serde_json::from_str(&add_new_services("[]", current)).expect("snapshot");
        let services: Vec<&str> = merged.iter().map(|entry| entry.service.as_str()).collect();
        assert_eq!(services, ["VPN"]);
    }

    /// Runs `redirect_services` against fake services, returning the result
    /// and every service it changed.
    fn redirect_fake(
        plan: &str,
        enabled: Option<&[&str]>,
    ) -> (Option<RedirectCoverage>, Vec<(String, Vec<String>)>) {
        let mut writes = Vec::new();
        let redirected = redirect_services(
            true,
            plan,
            || enabled.map(|names| names.iter().map(|name| (*name).to_owned()).collect()),
            |service, servers| {
                writes.push((
                    service.to_owned(),
                    servers.iter().map(|s| (*s).to_owned()).collect(),
                ));
                true
            },
        );
        (redirected, writes)
    }

    /// The regression this guards: the redirect pointed every enabled service
    /// at loopback whatever the plan held, so a VPN connected after the plan
    /// was captured, or one a failed capture never saw, was redirected with
    /// no original on disk.
    #[test]
    fn a_redirect_changes_only_the_services_its_plan_records() {
        let plan =
            r#"[{"service":"Wi-Fi","servers":["192.0.2.1"]},{"service":"Gone","servers":[]}]"#;
        let (redirected, writes) = redirect_fake(plan, Some(&["Wi-Fi", "VPN"]));
        assert_eq!(redirected, Some(RedirectCoverage::Complete));
        assert_eq!(
            writes,
            vec![(
                "Wi-Fi".to_owned(),
                vec!["127.0.0.1".to_owned(), "::1".to_owned()]
            )]
        );
    }

    #[test]
    fn a_redirect_without_a_valid_plan_or_service_list_changes_nothing() {
        assert_eq!(redirect_fake("not json", Some(&["Wi-Fi"])), (None, vec![]));
        assert_eq!(redirect_fake("[]", Some(&["Wi-Fi"])), (None, vec![]));
        let plan = r#"[{"service":"Wi-Fi","servers":[]}]"#;
        assert_eq!(redirect_fake(plan, None), (None, vec![]));
    }

    /// The regression this guards: one service redirected was reported as
    /// success, so the services that failed were never tried again.
    #[test]
    fn a_redirect_that_misses_a_service_is_partial() {
        let plan = r#"[{"service":"Wi-Fi","servers":[]},{"service":"VPN","servers":[]}]"#;
        let list = || Some(vec!["Wi-Fi".to_owned(), "VPN".to_owned()]);
        assert_eq!(
            redirect_services(false, plan, list, |service, _| service == "Wi-Fi"),
            Some(RedirectCoverage::Partial)
        );
        assert_eq!(redirect_services(false, plan, list, |_, _| false), None);
    }

    #[test]
    fn capture_failure_is_distinct_from_automatic_dns() {
        assert_eq!(
            parse_dns_servers(false, "There aren't any DNS Servers set on Wi-Fi."),
            None
        );
        assert_eq!(parse_dns_servers(true, ""), None);
        assert_eq!(parse_dns_servers(true, "unexpected error"), None);
        assert_eq!(
            parse_dns_servers(true, "There aren't any DNS Servers set on Wi-Fi.\n"),
            Some(vec![])
        );
        assert_eq!(
            parse_dns_servers(true, "8.8.8.8\n2001:4860:4860::8888\n"),
            Some(vec!["8.8.8.8".into(), "2001:4860:4860::8888".into()])
        );
        assert!(capture_services(vec![], |_| panic!("no services")).is_none());
        assert!(
            capture_services(vec!["Wi-Fi".into(), "LAN".into()], |service| {
                if service == "Wi-Fi" {
                    Some(vec!["8.8.8.8".into()])
                } else {
                    None
                }
            })
            .is_none()
        );
        let captured = capture_services(vec!["Wi-Fi".into()], |_| Some(vec![])).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<NetworkServiceDns>>(&captured).unwrap()[0].servers,
            Vec::<String>::new()
        );
    }

    #[test]
    fn invalid_restore_is_rejected_before_running_networksetup() {
        assert!(!restore("not json"));
    }

    /// Runs `restore_using` against fake services, returning the result and
    /// every DNS change it made.
    fn restore_fake(
        saved: &str,
        current: &[(&str, &[&str])],
    ) -> (bool, Vec<(String, Vec<String>)>) {
        let mut changes = Vec::new();
        let restored = restore_using(
            saved,
            || Some(current.iter().map(|(name, _)| (*name).to_owned()).collect()),
            |service| {
                current
                    .iter()
                    .find(|(name, _)| *name == service)
                    .map(|(_, servers)| servers.iter().map(|s| (*s).to_owned()).collect())
            },
            |service, servers| {
                changes.push((
                    service.to_owned(),
                    servers.iter().map(|s| (*s).to_owned()).collect(),
                ));
                true
            },
        );
        (restored, changes)
    }

    /// The regression this guards: an empty snapshot from an older version was
    /// restored as a no-op, leaving every service pointed at the dead resolver.
    #[test]
    fn an_empty_snapshot_resets_only_services_still_redirected() {
        let (restored, changes) = restore_fake(
            "[]",
            &[
                ("Wi-Fi", &["127.0.0.1", "::1"]),
                ("LAN", &["192.0.2.53"]),
                ("USB", &[]),
            ],
        );
        assert!(restored);
        assert_eq!(
            changes,
            vec![("Wi-Fi".to_owned(), vec!["Empty".to_owned()])]
        );
    }

    #[test]
    fn known_entries_restore_and_unreadable_ones_fall_back() {
        let (restored, changes) = restore_fake(
            r#"[{"service":"Wi-Fi","servers":["8.8.8.8"]},{"service":"LAN","servers":["invalid"]}]"#,
            &[("Wi-Fi", &["127.0.0.1"]), ("LAN", &["127.0.0.1"])],
        );
        assert!(restored);
        assert_eq!(
            changes,
            vec![
                ("Wi-Fi".to_owned(), vec!["8.8.8.8".to_owned()]),
                ("LAN".to_owned(), vec!["Empty".to_owned()]),
            ]
        );
    }

    /// A service on loopback that the snapshot does not record, such as one
    /// added while the redirect was applied, is reset rather than left on a
    /// resolver that is going away. One the user changed since is left alone.
    #[test]
    fn a_restore_resets_unrecorded_services_still_redirected() {
        let (restored, changes) = restore_fake(
            r#"[{"service":"Wi-Fi","servers":["192.0.2.1"]}]"#,
            &[
                ("Wi-Fi", &["127.0.0.1"]),
                ("VPN", &["127.0.0.1", "::1"]),
                ("LAN", &["198.51.100.1"]),
            ],
        );
        assert!(restored);
        assert_eq!(
            changes,
            vec![
                ("Wi-Fi".to_owned(), vec!["192.0.2.1".to_owned()]),
                ("VPN".to_owned(), vec!["Empty".to_owned()]),
            ]
        );
    }

    /// A recorded loopback original is a resolver the user runs: restore
    /// writes it back and the sweep does not reset it.
    #[test]
    fn a_recorded_loopback_original_is_kept() {
        let (restored, changes) = restore_fake(
            r#"[{"service":"Wi-Fi","servers":["127.0.0.1"]}]"#,
            &[("Wi-Fi", &["127.0.0.1"])],
        );
        assert!(restored);
        assert_eq!(
            changes,
            vec![("Wi-Fi".to_owned(), vec!["127.0.0.1".to_owned()])]
        );
    }

    #[test]
    fn a_restore_that_cannot_list_services_is_not_confirmed() {
        let mut changes = Vec::new();
        let restored = restore_using(
            r#"[{"service":"Wi-Fi","servers":["192.0.2.1"]}]"#,
            || None,
            |_| panic!("nothing to read without a service list"),
            |service, _| {
                changes.push(service.to_owned());
                true
            },
        );
        assert!(!restored, "unrecorded services may still be on loopback");
        assert_eq!(changes, ["Wi-Fi"], "recorded services are still restored");
    }

    #[test]
    fn an_unreadable_service_keeps_the_recovery_state() {
        let restored = restore_using(
            "[]",
            || Some(vec!["Wi-Fi".to_owned()]),
            |_| None,
            |_, _| panic!("a service whose DNS cannot be read is not changed"),
        );
        assert!(!restored);
    }

    #[test]
    fn service_parser_skips_header_and_disabled_services() {
        let output = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\nUSB LAN\n";
        assert_eq!(parse_network_services(output), ["Wi-Fi", "USB LAN"]);
    }
}
