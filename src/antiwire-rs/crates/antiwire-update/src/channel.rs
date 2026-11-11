//! Update channels: which releases a daemon is offered.
//!
//! Every release belongs to one channel, read from its version: no prerelease
//! is stable, `-beta.N` or `-rc.N` is beta, and `-nightly.…` is nightly. A
//! daemon on a channel is offered the newest release from that channel or any
//! more stable one, so a beta user still gets a stable release that is newer
//! than the last beta. Nothing is ever offered that is older than the running
//! version, so moving to a more stable channel takes effect at the next
//! release newer than the one installed.
//!
//! Each channel has its own feed: the stable one is GitHub's `latest` release,
//! which skips prereleases, and the others are fixed `channel-{name}` releases
//! whose manifests CI replaces with the newest release of that channel.

use semver::Version;

/// One update channel, ordered from most to least stable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Channel {
    #[default]
    Stable,
    Beta,
    Nightly,
}

impl Channel {
    /// Every channel, most stable first.
    pub const ALL: [Self; 3] = [Self::Stable, Self::Beta, Self::Nightly];

    /// The name stored in settings and shown in feed URLs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Nightly => "nightly",
        }
    }

    /// The channel `name` stands for. `None` for anything else, which callers
    /// treat as stable.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|channel| channel.name().eq_ignore_ascii_case(name.trim()))
    }

    /// The channel `name` stands for, or stable when it names none.
    #[must_use]
    pub fn parse_or_stable(name: &str) -> Self {
        Self::parse(name).unwrap_or_default()
    }

    /// The feeds a daemon on this channel reads: its own and every more
    /// stable one.
    pub fn feeds(self) -> impl Iterator<Item = Self> {
        Self::ALL.into_iter().filter(move |feed| *feed <= self)
    }

    /// The channel a release belongs to, from its version. `None` for a
    /// prerelease label no channel publishes.
    #[must_use]
    pub fn of_version(version: &Version) -> Option<Self> {
        if version.pre.is_empty() {
            return Some(Self::Stable);
        }
        match version.pre.as_str().split('.').next() {
            Some("beta" | "rc") => Some(Self::Beta),
            Some("nightly") => Some(Self::Nightly),
            _ => None,
        }
    }

    /// Whether a daemon on this channel may be offered `version`.
    #[must_use]
    pub fn accepts(self, version: &Version) -> bool {
        Self::of_version(version).is_some_and(|channel| channel <= self)
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &str) -> Version {
        Version::parse(text).expect("version")
    }

    #[test]
    fn parses_names_and_falls_back_to_stable() {
        assert_eq!(Channel::parse("beta"), Some(Channel::Beta));
        assert_eq!(Channel::parse(" Nightly "), Some(Channel::Nightly));
        assert_eq!(Channel::parse("canary"), None);
        assert_eq!(Channel::parse_or_stable(""), Channel::Stable);
        for channel in Channel::ALL {
            assert_eq!(Channel::parse(channel.name()), Some(channel));
        }
    }

    #[test]
    fn each_channel_reads_its_own_feed_and_the_more_stable_ones() {
        let feeds = |channel: Channel| channel.feeds().collect::<Vec<_>>();
        assert_eq!(feeds(Channel::Stable), [Channel::Stable]);
        assert_eq!(feeds(Channel::Beta), [Channel::Stable, Channel::Beta]);
        assert_eq!(feeds(Channel::Nightly), Channel::ALL);
    }

    #[test]
    fn reads_the_channel_from_the_version() {
        assert_eq!(
            Channel::of_version(&version("0.3.0")),
            Some(Channel::Stable)
        );
        assert_eq!(
            Channel::of_version(&version("0.3.0-beta.2")),
            Some(Channel::Beta)
        );
        assert_eq!(
            Channel::of_version(&version("0.3.0-rc.1")),
            Some(Channel::Beta)
        );
        assert_eq!(
            Channel::of_version(&version("0.3.1-nightly.20261102.4")),
            Some(Channel::Nightly)
        );
        assert_eq!(Channel::of_version(&version("0.3.0-alpha.1")), None);
    }

    #[test]
    fn a_channel_accepts_its_releases_and_more_stable_ones() {
        let nightly = version("0.3.1-nightly.20261102.4");
        let beta = version("0.3.0-beta.2");
        let stable = version("0.3.0");
        assert!(Channel::Stable.accepts(&stable));
        assert!(!Channel::Stable.accepts(&beta));
        assert!(Channel::Beta.accepts(&beta));
        assert!(!Channel::Beta.accepts(&nightly));
        assert!(Channel::Nightly.accepts(&nightly));
        assert!(Channel::Nightly.accepts(&stable));
    }

    #[test]
    fn versions_order_across_channels() {
        // A nightly is numbered after the release it follows, and a stable
        // release beats its own betas.
        assert!(version("0.3.0") > version("0.3.0-rc.1"));
        assert!(version("0.3.0-rc.1") > version("0.3.0-beta.9"));
        assert!(version("0.3.1-nightly.20261102.4") > version("0.3.0"));
        assert!(version("0.3.1-nightly.20261103.1") > version("0.3.1-nightly.20261102.9"));
    }
}
