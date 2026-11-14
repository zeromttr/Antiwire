//! A DNS resolver that only returns addresses the destination policy allows.

use std::net::SocketAddr;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::destination::Destinations;

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
            // The port is replaced by the URL's own when the connection is made.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed = allowed_addresses(resolved, destinations);
            if allowed.is_empty() {
                return Err(
                    format!("{host} resolves only to addresses this client may not reach").into(),
                );
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

    #[tokio::test]
    async fn localhost_is_refused_unless_loopback_is_allowed() {
        let refused = PolicyResolver::new(Destinations::Public)
            .resolve("localhost".parse().expect("name"))
            .await;
        assert!(refused.is_err());

        let allowed = PolicyResolver::new(Destinations::PublicPrivateAndLoopback)
            .resolve("localhost".parse().expect("name"))
            .await
            .expect("resolves");
        assert!(allowed
            .into_iter()
            .all(|address| address.ip().is_loopback()));
    }
}
