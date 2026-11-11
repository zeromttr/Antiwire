//! User-facing names for custom blocklist URLs.

use url::Url;

/// User-facing name for a custom blocklist URL.
///
/// Path tokens that look like a project and variant become `"1Hosts - Lite"`.
/// When nothing reliable remains, the fallback is `"Custom List - {index}"`
/// using the 1-based position among custom URLs.
#[must_use]
pub(crate) fn custom_blocklist_display_name(url: &str, custom_index: usize) -> String {
    extract_custom_blocklist_name(url).unwrap_or_else(|| format!("Custom List - {custom_index}"))
}

fn extract_custom_blocklist_name(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let mut tokens = Vec::new();

    if let Some(segments) = parsed.path_segments() {
        let segments: Vec<&str> = segments.filter(|segment| !segment.is_empty()).collect();
        let skip = path_prefix_skip(&parsed, &segments);
        for segment in segments.iter().skip(skip) {
            for part in segment.split(['@', '+']) {
                push_path_tokens(&mut tokens, part);
            }
        }
    }

    tokens.retain(|token| !is_generic_token(token));
    drop_leading_username(&mut tokens);

    if tokens.is_empty() {
        if let Some(host) = parsed.host_str() {
            if !host_is_forging_platform(host) && !host_is_unreliable(host) {
                for label in host.split('.') {
                    if !is_generic_token(label) && !is_generic_host_label(label) {
                        tokens.push(label.to_owned());
                    }
                }
            }
        }
    }

    match tokens.as_slice() {
        [] => None,
        [solo] if is_weak_solo_token(solo) => None,
        [solo] => Some(solo.clone()),
        rest => Some(format_display_tokens(rest)),
    }
}

fn path_prefix_skip(parsed: &Url, segments: &[&str]) -> usize {
    let host = parsed.host_str().unwrap_or("");
    if host.contains("jsdelivr")
        && segments
            .first()
            .is_some_and(|first| first.eq_ignore_ascii_case("gh"))
    {
        return 2.min(segments.len());
    }
    0
}

fn push_path_tokens(tokens: &mut Vec<String>, raw: &str) {
    let stripped = strip_filename_extension(raw);
    if stripped.is_empty() {
        return;
    }
    for token in stripped.split(['-', '_', '.']) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        tokens.push(token.to_owned());
    }
}

fn strip_filename_extension(segment: &str) -> &str {
    const EXTENSIONS: &[&str] = &["txt", "conf", "list", "gz", "zip", "json", "csv", "hosts"];
    let Some((stem, ext)) = segment.rsplit_once('.') else {
        return segment;
    };
    if EXTENSIONS
        .iter()
        .any(|known| ext.eq_ignore_ascii_case(known))
    {
        stem
    } else {
        segment
    }
}

fn drop_leading_username(tokens: &mut Vec<String>) {
    if tokens.len() < 2 {
        return;
    }
    let first = &tokens[0];
    if first.len() >= 2
        && first
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && first.bytes().any(|byte| byte.is_ascii_lowercase())
        && !is_variant_token(first)
    {
        tokens.remove(0);
    }
}

fn host_is_forging_platform(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host.ends_with(".github.io")
        || host == "github.io"
        || host.ends_with(".githubusercontent.com")
        || host.contains("jsdelivr")
        || host.ends_with(".gitlab.io")
}

fn host_is_unreliable(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    matches!(
        parsed_host_kind(&host),
        HostKind::Reserved | HostKind::Address
    )
}

fn parsed_host_kind(host: &str) -> HostKind {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return HostKind::Address;
    }
    let tld = host.rsplit('.').next().unwrap_or(host);
    if host == "localhost"
        || host == "example"
        || host.starts_with("example.")
        || matches!(tld, "example" | "test" | "invalid" | "localhost")
    {
        return HostKind::Reserved;
    }
    HostKind::Named
}

enum HostKind {
    Named,
    Reserved,
    Address,
}

fn is_generic_host_label(label: &str) -> bool {
    matches!(
        label.to_ascii_lowercase().as_str(),
        "com"
            | "org"
            | "net"
            | "io"
            | "www"
            | "raw"
            | "cdn"
            | "github"
            | "gitlab"
            | "test"
            | "local"
            | "example"
            | "invalid"
            | "localhost"
    )
}

fn is_generic_token(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "hosts"
            | "host"
            | "list"
            | "lists"
            | "blocklist"
            | "blocklists"
            | "adblock"
            | "ads"
            | "dns"
            | "dnsmasq"
            | "conf"
            | "txt"
            | "raw"
            | "latest"
            | "master"
            | "main"
            | "blob"
            | "tree"
            | "release"
            | "releases"
            | "cdn"
            | "jsdelivr"
            | "github"
            | "gitlab"
            | "githubusercontent"
            | "pages"
            | "www"
            | "index"
            | "download"
            | "files"
            | "file"
            | "mirror"
            | "mirrors"
            | "gh"
            | "git"
            | "refs"
            | "heads"
            | "media"
            | "static"
            | "assets"
            | "public"
            | "src"
            | "dist"
            | "data"
            | "domains"
            | "domain"
            | "names"
            | "etc"
            | "formats"
            | "format"
    )
}

fn is_variant_token(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "lite" | "light" | "pro" | "mini" | "plus" | "xtra" | "ultimate" | "tif" | "bypass" | "uni"
    )
}

fn is_weak_solo_token(token: &str) -> bool {
    is_variant_token(token) || is_generic_token(token)
}

fn format_display_tokens(tokens: &[String]) -> String {
    if tokens.len() >= 2 && is_variant_token(&tokens[tokens.len() - 1]) {
        let product = tokens[..tokens.len() - 1].join(" ");
        format!("{product} - {}", tokens[tokens.len() - 1])
    } else {
        tokens.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::custom_blocklist_display_name;

    #[test]
    fn extracts_project_and_variant_from_url() {
        assert_eq!(
            custom_blocklist_display_name("https://badmojr.github.io/1Hosts/Lite/dnsmasq.conf", 1),
            "1Hosts - Lite"
        );
        assert_eq!(
            custom_blocklist_display_name(
                "https://cdn.jsdelivr.net/gh/badmojr/1Hosts@master/Lite/hosts.txt",
                1
            ),
            "1Hosts - Lite"
        );
        assert_eq!(
            custom_blocklist_display_name(
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                2
            ),
            "StevenBlack"
        );
    }

    #[test]
    fn falls_back_to_indexed_label() {
        assert_eq!(
            custom_blocklist_display_name("https://example.test/hosts.txt", 1),
            "Custom List - 1"
        );
        assert_eq!(
            custom_blocklist_display_name("https://example.test/list.txt", 3),
            "Custom List - 3"
        );
    }
}
