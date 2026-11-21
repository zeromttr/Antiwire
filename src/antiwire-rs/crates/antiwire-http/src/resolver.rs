//! A DNS resolver that only returns addresses the destination policy allows.

use std::fmt;
use std::net::SocketAddr;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::destination::Destinations;

/// Error returned by [`PolicyResolver`] when a hostname or its resolved
/// addresses are refused by the active [`Destinations`] policy.
#[derive(Debug)]
pub(crate) struct PolicyRefused(pub(crate) String);

impl fmt::Display for PolicyRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PolicyRefused {}

/// Whether `host` is a local-only name that `destinations` must refuse before
/// invoking the OS resolver.
///
/// Refusing `localhost` / `*.localhost` (RFC 6761) unless loopback is allowed,
/// and refusing single-label names and `*.local` (RFC 6762 mDNS) under
/// [`Destinations::Public`], prevents a public request or redirect from
/// triggering LLMNR, mDNS, `NetBIOS`, or corporate DNS search-suffix lookups.
pub(crate) fn is_refused_hostname(host: &str, destinations: Destinations) -> bool {
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() {
        return true;
    }
    let last_label = trimmed.rsplit('.').next().unwrap_or("");
    if last_label.eq_ignore_ascii_case("localhost")
        && destinations != Destinations::PublicPrivateAndLoopback
    {
        return true;
    }
    if destinations == Destinations::Public {
        return !trimmed.contains('.') || last_label.eq_ignore_ascii_case("local");
    }
    false
}

/// Resolves through the system resolver, then drops every address the policy
/// refuses.
///
/// Checking here rather than on the URL covers a public name that resolves to
/// a private address, each redirect hop, and a name whose answer changes
/// between checks: the addresses checked are the ones the connection uses.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PolicyResolver {
    destinations: Destinations,
}

impl PolicyResolver {
    pub(crate) const fn new(destinations: Destinations) -> Self {
        Self { destinations }
    }
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let destinations = self.destinations;
        Box::pin(async move {
            if is_refused_hostname(&host, destinations) {
                return Err(Box::new(PolicyRefused(format!(
                    "{host} is not a host this client may resolve"
                ))) as _);
            }
            // The port is replaced by the URL's own when the connection is made.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed = allowed_addresses(resolved, destinations);
            if allowed.is_empty() {
                return Err(Box::new(PolicyRefused(format!(
                    "{host} resolves only to addresses this client may not reach"
                ))) as _);
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

fn allowed_addresses(
    resolved: impl Iterator<Item = SocketAddr>,
    destinations: Destinations,
) -> Vec<SocketAddr> {
    resolved
        .filter(|address| destinations.allows(address.ip()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addresses(list: &[&str]) -> Vec<SocketAddr> {
        list.iter()
            .map(|address| format!("{address}:0").parse().expect("address"))
            .collect()
    }

    #[test]
    fn keeps_only_allowed_answers() {
        let answers = addresses(&["10.0.0.7", "93.184.216.34", "169.254.169.254"]);
        assert_eq!(
            allowed_addresses(answers.clone().into_iter(), Destinations::Public),
            addresses(&["93.184.216.34"])
        );
        assert_eq!(
            allowed_addresses(answers.into_iter(), Destinations::PublicAndPrivate),
            addresses(&["10.0.0.7", "93.184.216.34"])
        );
    }

    #[test]
    fn refuses_local_only_hostnames_according_to_policy() {
        for host in [
            "localhost",
            "LOCALHOST.",
            "api.localhost",
            "wpad",
            "nas.local",
            "local.",
        ] {
            assert!(is_refused_hostname(host, Destinations::Public), "{host}");
        }
        assert!(!is_refused_hostname("example.com", Destinations::Public));

        assert!(is_refused_hostname(
            "localhost",
            Destinations::PublicAndPrivate
        ));
        assert!(is_refused_hostname(
            "sub.localhost",
            Destinations::PublicAndPrivate
        ));
        assert!(!is_refused_hostname(
            "nas.local",
            Destinations::PublicAndPrivate
        ));
        assert!(!is_refused_hostname(
            "pihole",
            Destinations::PublicAndPrivate
        ));

        assert!(!is_refused_hostname(
            "localhost",
            Destinations::PublicPrivateAndLoopback
        ));
        assert!(!is_refused_hostname(
            "sub.localhost",
            Destinations::PublicPrivateAndLoopback
        ));
    }

    #[tokio::test]
    async fn localhost_is_refused_unless_loopback_is_allowed() {
        let Err(refused) = PolicyResolver::new(Destinations::Public)
            .resolve("localhost".parse().expect("name"))
            .await
        else {
            panic!("localhost must be refused under Public");
        };
        assert!(refused.is::<PolicyRefused>(), "{refused}");

        let Err(refused_private) = PolicyResolver::new(Destinations::PublicAndPrivate)
            .resolve("localhost".parse().expect("name"))
            .await
        else {
            panic!("localhost must be refused under PublicAndPrivate");
        };
        assert!(refused_private.is::<PolicyRefused>(), "{refused_private}");

        let Ok(allowed) = PolicyResolver::new(Destinations::PublicPrivateAndLoopback)
            .resolve("localhost".parse().expect("name"))
            .await
        else {
            panic!("localhost must resolve under PublicPrivateAndLoopback");
        };
        assert!(allowed
            .into_iter()
            .all(|address| address.ip().is_loopback()));
    }
}
