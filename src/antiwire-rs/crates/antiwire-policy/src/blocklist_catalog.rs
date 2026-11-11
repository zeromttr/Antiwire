//! Built-in community blocklist IDs and download URLs (C# `HostsParser.ListUrls` parity).

use ahash::AHashSet;
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::blocklist_display::custom_blocklist_display_name;
use crate::hosts::HostsParserMode;

/// One downloadable blocklist target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncTarget {
    name: String,
    urls: Vec<String>,
    hash_urls: Vec<String>,
    cache_filename: String,
    parser_mode: HostsParserMode,
    pinned_names: &'static [&'static str],
}

impl SyncTarget {
    fn new(
        name: String,
        urls: Vec<String>,
        cache_filename: String,
        parser_mode: HostsParserMode,
    ) -> Option<Self> {
        (!urls.is_empty()).then_some(Self {
            name,
            urls,
            hash_urls: Vec::new(),
            cache_filename,
            parser_mode,
            pinned_names: &[],
        })
    }

    const fn with_pinned_names(mut self, names: &'static [&'static str]) -> Self {
        self.pinned_names = names;
        self
    }

    /// Names this list always blocks, whether or not the download has them.
    #[must_use]
    pub const fn pinned_names(&self) -> &'static [&'static str] {
        self.pinned_names
    }

    /// False for a whole zone too widely used to block, such as `com`, which
    /// a single-label list must never take down even if its source lists it.
    #[must_use]
    pub fn accepts(&self, domain: &str) -> bool {
        !(matches!(self.parser_mode, HostsParserMode::AllowSingleLabelNames)
            && NEVER_BLOCK_ZONES
                .iter()
                .any(|zone| zone.eq_ignore_ascii_case(domain)))
    }

    fn with_hash_urls(mut self, hash_urls: Vec<String>) -> Self {
        self.hash_urls = hash_urls;
        self
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    #[must_use]
    pub fn hash_urls(&self) -> &[String] {
        &self.hash_urls
    }

    #[must_use]
    pub fn cache_filename(&self) -> &str {
        &self.cache_filename
    }

    #[must_use]
    pub(crate) const fn built_in_ip_prefix(&self) -> bool {
        matches!(self.parser_mode, HostsParserMode::RequireHostsAddress)
    }

    #[must_use]
    pub const fn parser_mode(&self) -> HostsParserMode {
        self.parser_mode
    }
}

/// Catalog id reported when the OS hosts file contributed the blocking entry.
pub const SYSTEM_HOSTS_LIST_ID: &str = "system_hosts";

const HAGEZI_ABUSED_TLDS_ID: &str = "hagezi_abused_tlds";

/// TLDs the abused-TLD list always blocks, even when the upstream list omits them.
const ABUSED_TLDS_PINNED: &[&str] = &["christmas", "mov", "zip"];

/// Zones a single-label list may never block.
const NEVER_BLOCK_ZONES: &[&str] = &["com", "net", "org", "edu", "gov", "mil", "int", "arpa"];

const HOSTS_MODE: HostsParserMode = HostsParserMode::RequireHostsAddress;

const BUILTIN_LIST_URLS: &[(&str, &[&str], &[&str], HostsParserMode)] = &[
    (
        "hagezi_light",
        &[
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/light.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    (
        "hagezi_multi",
        &[
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/multi.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    (
        "hagezi_pro",
        &[
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/pro.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    (
        "hagezi_pro_mini",
        &[
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.mini.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/pro.mini.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    (
        "hagezi_pro_plus_plus",
        &[
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/pro.plus.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    (
        "hagezi_pro_plus_plus_mini",
        &[
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.mini.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.mini.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/pro.plus.mini.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    (
        "hagezi_ultimate",
        &[
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/ultimate.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    (
        "hagezi_ultimate_mini",
        &[
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.mini.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.mini.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/ultimate.mini.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    (
        "hagezi_tif",
        &[
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/tif.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    (
        "hagezi_bypass",
        &[
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh-vpn-proxy-bypass.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/doh-vpn-proxy-bypass.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    (
        "hagezi_dyn",
        &[
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/dyndns.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    // URLhaus (abuse.ch) malware hosts, with popular domains filtered out by
    // the malware-filter project to keep false positives down.
    (
        "urlhaus",
        &[
            "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
            "https://curbengh.github.io/malware-filter/urlhaus-filter-hosts.txt",
            "https://malware-filter.pages.dev/urlhaus-filter-hosts.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    // Phishing Army publishes bare domains, one per line.
    (
        "phishing_army",
        &["https://phishing.army/download/phishing_army_blocklist.txt"],
        &[],
        HostsParserMode::AllowBareDomains,
    ),
    (
        "stevenblack-uni",
        &[
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "https://cdn.jsdelivr.net/gh/StevenBlack/hosts@master/hosts",
        ],
        &[],
        HOSTS_MODE,
    ),
    (
        "someonewhocares",
        &["https://someonewhocares.org/hosts/hosts"],
        &[],
        HOSTS_MODE,
    ),
    // HaGeZi's Most Abused TLDs (`||zip^` lines), fetched straight from
    // HaGeZi; ABUSED_TLDS_PINNED is added and NEVER_BLOCK_ZONES dropped on load.
    (
        HAGEZI_ABUSED_TLDS_ID,
        &[
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds-adblock.txt",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock.txt",
            "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/spam-tlds-adblock.txt",
        ],
        &[],
        HostsParserMode::AllowSingleLabelNames,
    ),
    (
        "1hosts_lite",
        &[
            "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt",
            "https://cdn.jsdelivr.net/gh/badmojr/1Hosts@master/Lite/hosts.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
    (
        "1host_xtra",
        &[
            // Over jsDelivr's 20 MB file limit, so GitHub Pages is the mirror.
            "https://raw.githubusercontent.com/badmojr/1Hosts/master/Xtra/hosts.txt",
            "https://badmojr.github.io/1Hosts/Xtra/hosts.txt",
        ],
        &[],
        HOSTS_MODE,
    ),
];

fn lookup_builtin(
    id: &str,
) -> Option<(
    &'static [&'static str],
    &'static [&'static str],
    HostsParserMode,
)> {
    BUILTIN_LIST_URLS
        .iter()
        .find(|(key, _, _, _)| key.eq_ignore_ascii_case(id))
        .map(|(_, urls, hash_urls, mode)| (*urls, *hash_urls, *mode))
}

/// Returns true when `id` is a known built-in list name.
#[must_use]
pub fn is_builtin_list_id(id: &str) -> bool {
    lookup_builtin(id).is_some()
}

fn split_selected_lists(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn split_custom_urls(raw: &str) -> Vec<String> {
    raw.split(';')
        .map(str::trim)
        .filter_map(parse_http_url)
        .collect()
}

fn parse_http_url(value: &str) -> Option<String> {
    let parsed = Url::parse(value).ok()?;
    matches!(parsed.scheme(), "http" | "https")
        .then(|| parsed.to_string())
        .filter(|_| parsed.host().is_some())
}

/// Resolves configured list IDs and custom URLs into download targets.
#[must_use]
pub fn resolve_sync_targets(
    enabled: bool,
    selected_lists: &str,
    custom_urls: &str,
) -> Vec<SyncTarget> {
    if !enabled {
        return Vec::new();
    }

    let mut targets = Vec::new();

    for list in split_selected_lists(selected_lists) {
        let Some((urls, hash_urls, mode)) = lookup_builtin(&list) else {
            continue;
        };
        let name = list.to_ascii_lowercase();
        let Some(mut target) = SyncTarget::new(
            name.clone(),
            urls.iter().map(|url| (*url).to_owned()).collect(),
            format!("{name}.txt"),
            mode,
        ) else {
            continue;
        };
        if !hash_urls.is_empty() {
            target = target.with_hash_urls(hash_urls.iter().map(|url| (*url).to_owned()).collect());
        }
        if name == HAGEZI_ABUSED_TLDS_ID {
            target = target.with_pinned_names(ABUSED_TLDS_PINNED);
        }
        targets.push(target);
    }

    for (index, url) in split_custom_urls(custom_urls).into_iter().enumerate() {
        let filename = custom_cache_filename(&url);
        let name = custom_blocklist_display_name(&url, index + 1);
        if let Some(target) =
            SyncTarget::new(name, vec![url], filename, HostsParserMode::AllowBareDomains)
        {
            targets.push(target);
        }
    }

    targets
}

/// Cache filename for a user-supplied URL (`custom_{first-16-sha256-hex-chars}.txt`).
#[must_use]
fn custom_cache_filename(url: &str) -> String {
    let digest = Sha256::digest(url.as_bytes());
    let prefix = HEXLOWER.encode(&digest[..8]);
    format!("custom_{prefix}.txt")
}

/// Rough domain-count estimate for Binary Fuse builder sizing.
#[must_use]
pub fn estimate_blocklist_size(targets: &[SyncTarget]) -> usize {
    let mut estimate = 8192;
    for target in targets {
        estimate += if target.built_in_ip_prefix() {
            antiwire_tuning::HOSTS_PER_LIST_SIZE_ESTIMATE as usize
        } else {
            antiwire_tuning::HOSTS_PER_CUSTOM_LIST_SIZE_ESTIMATE as usize
        };
    }
    estimate.clamp(8192, 5_000_000)
}

/// Hostnames that must resolve while the blocklist boot gate is armed (every
/// catalog mirror host plus hosts from saved custom list URLs).
#[must_use]
pub fn blocklist_sync_allow_hosts(enabled: bool, custom_urls: &str) -> AHashSet<String> {
    let mut hosts = AHashSet::new();
    if !enabled {
        return hosts;
    }

    for (_, urls, hash_urls, _) in BUILTIN_LIST_URLS {
        for url in urls.iter().chain(hash_urls.iter()) {
            if let Some(host) = host_from_http_url(url) {
                hosts.insert(host);
            }
        }
    }

    for url in split_custom_urls(custom_urls) {
        if let Some(host) = host_from_http_url(&url) {
            hosts.insert(host);
        }
    }

    hosts
}

fn host_from_http_url(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let Host::Domain(host) = parsed.host()? else {
        return None;
    };
    (!host.eq_ignore_ascii_case("localhost")).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Live check: every built-in mirror must still resolve and serve its list.
    ///
    /// Ignored by default because it needs real network access and depends on
    /// third-party availability. Run it explicitly when a catalog change lands
    /// or a sync failure points at a moved list:
    ///
    /// ```text
    /// cargo test -p antiwire-policy --lib blocklist_catalog -- --ignored --nocapture
    /// ```
    ///
    /// Redirects count as healthy (the final hop must return 200); response
    /// bodies are dropped after the headers so the check does not download
    /// every multi-megabyte list.
    #[tokio::test]
    #[ignore = "live network test; run explicitly to verify catalog mirrors"]
    async fn every_builtin_list_url_still_serves_200() {
        // The production download rules, so a mirror that only works by
        // breaking them (plain HTTP after HTTPS, a local redirect) fails here too.
        let client = antiwire_http::HttpClient::builder("antiwire-blocklist-catalog-check")
            .https_only(false)
            .max_redirects(10)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("http client");

        let mut failures = Vec::new();
        let mut checked = 0_usize;
        for (name, urls, hash_urls, _) in BUILTIN_LIST_URLS {
            assert!(!urls.is_empty(), "{name} has no download URLs configured");
            for url in urls.iter().chain(hash_urls.iter()) {
                checked += 1;
                let request = match client.get(url) {
                    Ok(request) => request,
                    Err(error) => {
                        failures.push(format!("{name}: {url} -> {error}"));
                        continue;
                    }
                };
                match request.send().await {
                    Ok(response) => {
                        let status = response.status();
                        if status != antiwire_http::reqwest::StatusCode::OK {
                            failures.push(format!("{name}: {url} -> HTTP {status}"));
                        }
                    }
                    Err(error) => failures.push(format!("{name}: {url} -> {error}")),
                }
                println!("checked {url}");
            }
        }

        assert!(checked > 0, "catalog is empty; nothing was verified");
        assert!(
            failures.is_empty(),
            "{} blocklist mirror(s) no longer resolve or return 200:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    #[test]
    fn resolves_hagezi_light() {
        let targets = resolve_sync_targets(true, "hagezi_light", "");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "hagezi_light");
        assert!(targets[0]
            .urls()
            .first()
            .expect("built-in mirror")
            .contains("hagezi"));
        assert_eq!(targets[0].urls.len(), 3);
        assert_eq!(
            targets[0].parser_mode(),
            HostsParserMode::RequireHostsAddress
        );
        assert!(targets[0].hash_urls().is_empty());
    }

    #[test]
    fn custom_url_is_included() {
        let targets = resolve_sync_targets(true, "", "https://example.test/hosts.txt");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].parser_mode(), HostsParserMode::AllowBareDomains);
        assert_eq!(
            targets[0].urls,
            vec!["https://example.test/hosts.txt".to_owned()]
        );
        assert_eq!(targets[0].name(), "Custom List - 1");
        assert_eq!(targets[0].cache_filename, "custom_4a32a26d0a4d8d32.txt");
    }

    #[test]
    fn custom_urls_use_extracted_or_indexed_display_names() {
        let targets = resolve_sync_targets(
            true,
            "",
            "https://example.test/hosts.txt;https://badmojr.github.io/1Hosts/Lite/dnsmasq.conf",
        );
        assert_eq!(targets[0].name(), "Custom List - 1");
        assert_eq!(targets[1].name(), "1Hosts - Lite");
    }

    #[test]
    fn sync_target_rejects_an_empty_mirror_list() {
        assert!(SyncTarget::new(
            "empty".to_owned(),
            Vec::new(),
            "empty.txt".to_owned(),
            HostsParserMode::AllowBareDomains,
        )
        .is_none());
    }

    #[test]
    fn custom_urls_are_parsed_before_use() {
        let targets = resolve_sync_targets(
            true,
            "",
            "HTTPS://EXAMPLE.TEST/list;ftp://example.test/list;not a url",
        );

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].urls(), ["https://example.test/list"]);
    }

    #[test]
    fn resolves_hagezi_abused_tlds() {
        let targets = resolve_sync_targets(true, HAGEZI_ABUSED_TLDS_ID, "");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, HAGEZI_ABUSED_TLDS_ID);
        assert_eq!(
            targets[0].parser_mode(),
            HostsParserMode::AllowSingleLabelNames
        );
        assert!(!targets[0].built_in_ip_prefix());
        assert_eq!(targets[0].urls().len(), 3);
        assert!(targets[0]
            .urls()
            .iter()
            .all(|url| url.contains("hagezi") && url.ends_with("/spam-tlds-adblock.txt")));
        assert!(targets[0].hash_urls().is_empty());
        assert_eq!(targets[0].pinned_names(), ["christmas", "mov", "zip"]);
    }

    #[test]
    fn single_label_lists_never_block_core_zones() {
        let tlds = &resolve_sync_targets(true, HAGEZI_ABUSED_TLDS_ID, "")[0];
        assert!(tlds.accepts("zip"));
        assert!(!tlds.accepts("com"));
        assert!(!tlds.accepts("ORG"));
        let hosts = &resolve_sync_targets(true, "hagezi_light", "")[0];
        assert!(hosts.pinned_names().is_empty());
        assert!(hosts.accepts("com"));
    }

    #[test]
    fn resolves_threat_feeds() {
        let targets = resolve_sync_targets(true, "urlhaus,phishing_army", "");
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].name(), "urlhaus");
        assert_eq!(targets[0].cache_filename(), "urlhaus.txt");
        assert_eq!(
            targets[0].parser_mode(),
            HostsParserMode::RequireHostsAddress
        );
        assert!(targets[0].urls().len() > 1);
        assert_eq!(targets[1].name(), "phishing_army");
        assert_eq!(targets[1].parser_mode(), HostsParserMode::AllowBareDomains);
        assert!(targets[1].urls()[0].starts_with("https://phishing.army/"));
    }

    #[test]
    fn unknown_builtin_id_is_skipped() {
        let targets = resolve_sync_targets(true, "not_a_real_list", "");
        assert!(targets.is_empty());
    }

    #[test]
    fn disabled_returns_empty() {
        let targets = resolve_sync_targets(false, "hagezi_light", "");
        assert!(targets.is_empty());
    }

    #[test]
    fn sync_allow_hosts_includes_catalog_and_custom() {
        let hosts = blocklist_sync_allow_hosts(true, "https://lists.example.test/ads.txt");
        assert!(hosts.contains("cdn.jsdelivr.net"));
        assert!(hosts.contains("raw.githubusercontent.com"));
        assert!(hosts.contains("gitlab.com"));
        assert!(hosts.contains("someonewhocares.org"));
        assert!(hosts.contains("lists.example.test"));
        assert!(!hosts.contains("evil.tracker.test"));
    }

    #[test]
    fn sync_allow_hosts_empty_when_disabled() {
        let hosts = blocklist_sync_allow_hosts(false, "https://lists.example.test/ads.txt");
        assert!(hosts.is_empty());
    }

    #[test]
    fn host_from_url_strips_port_and_userinfo() {
        assert_eq!(
            host_from_http_url("https://user:pass@cdn.example.test:8443/path"),
            Some("cdn.example.test".to_owned())
        );
        assert_eq!(host_from_http_url("https://1.2.3.4/hosts.txt"), None);
        assert_eq!(host_from_http_url("https://[2001:db8::1]/hosts.txt"), None);
        assert_eq!(host_from_http_url("not a url"), None);
    }
}
