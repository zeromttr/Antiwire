//! Configured-upstream parsing into dialable endpoints.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use hickory_resolver::config::{ConnectionConfig, NameServerConfig};
use url::Url;

use crate::listener::{dns_listen_addr, dns_listen_addr_v6};
use crate::settings::DnsProtocol;
use crate::{DnsError, Result};

use super::super::providers::{bootstrap_ipv4_for_host, tls_name_for_address};

/// Parses each configured upstream, collecting the failures of the ones that
/// did not yield any dialable endpoint.
pub(super) fn collect_upstream_endpoints(
    protocol: DnsProtocol,
    upstreams: &[String],
) -> Result<(Vec<UpstreamEndpoint>, Vec<String>)> {
    let mut collected = Vec::new();
    let mut errors = Vec::new();

    for (index, upstream) in upstreams.iter().enumerate() {
        match parse_upstream_endpoints(upstream, protocol) {
            Ok(endpoints) => collected.extend(endpoints),
            Err(error) => errors.push(format!("upstream {}: {error}", index + 1)),
        }
    }

    if collected.is_empty() {
        let detail = if errors.is_empty() {
            "no upstream servers configured".to_owned()
        } else {
            errors.join("; ")
        };
        return Err(DnsError::Config(format!(
            "failed to build upstream resolver: {detail}"
        )));
    }

    Ok((collected, errors))
}

/// One dialable upstream endpoint in flat form.
///
/// 0.26's `NameServerConfig` keeps the port, protocol, and server name behind a
/// `Vec<ConnectionConfig>`, which the parsing pipeline and the health registry's
/// endpoint labels would both have to pick apart again. Parsing produces this
/// instead and converts to a `NameServerConfig` only at pool construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UpstreamEndpoint {
    pub(super) socket_addr: SocketAddr,
    pub(super) protocol: DnsProtocol,
    pub(super) tls_dns_name: Option<String>,
    pub(super) http_endpoint: Option<String>,
}

impl UpstreamEndpoint {
    /// `address:port`, plus the TLS name, for logs; never the URL path.
    pub(super) fn label(&self) -> String {
        let mut label = format!("{}:{}", self.socket_addr.ip(), self.socket_addr.port());
        if let Some(tls) = &self.tls_dns_name {
            label.push('/');
            label.push_str(tls);
        }
        label
    }

    /// Server name for the TLS handshake on encrypted transports.
    ///
    /// 0.26 makes this mandatory where 0.25 had it optional. Falling back to the
    /// IP literal keeps 0.25's behaviour of attempting the connection and
    /// failing at the handshake, rather than rejecting the whole upstream set at
    /// configuration time.
    fn server_name(&self) -> Arc<str> {
        match &self.tls_dns_name {
            Some(name) => Arc::from(name.as_str()),
            None => Arc::from(self.socket_addr.ip().to_string()),
        }
    }

    fn http_path(&self) -> Option<Arc<str>> {
        self.http_endpoint
            .as_deref()
            .filter(|path| !path.is_empty())
            .map(Arc::from)
    }

    /// A plain UDP server is also given a TCP connection on the same port.
    /// Hickory asks over UDP first and uses TCP only to repeat a query whose
    /// UDP answer came back truncated (RFC 7766 §5). With UDP alone it has
    /// nothing to retry on and reports the truncated answer as an error, so
    /// a name with a large answer could never resolve.
    pub(super) fn to_name_server_config(&self) -> NameServerConfig {
        let mut connection = match self.protocol {
            DnsProtocol::Udp => ConnectionConfig::udp(),
            DnsProtocol::Tcp => ConnectionConfig::tcp(),
            DnsProtocol::Tls => ConnectionConfig::tls(self.server_name()),
            DnsProtocol::Quic => ConnectionConfig::quic(self.server_name()),
            DnsProtocol::Https => ConnectionConfig::https(self.server_name(), self.http_path()),
            DnsProtocol::H3 => ConnectionConfig::h3(self.server_name(), self.http_path()),
        };
        connection.port = self.socket_addr.port();
        let mut connections = vec![connection];
        if self.protocol == DnsProtocol::Udp {
            let mut truncation_retry = ConnectionConfig::tcp();
            truncation_retry.port = self.socket_addr.port();
            connections.push(truncation_retry);
        }
        NameServerConfig::new(self.socket_addr.ip(), true, connections)
    }
}

/// Parses one upstream entry into dialable endpoints (may expand hostnames to bootstrap IPs).
///
/// An entry that leads back to this resolver is refused. Another resolver on this host is a
/// valid upstream, on any other loopback address or port.
pub(super) fn parse_upstream_endpoints(
    input: &str,
    protocol: DnsProtocol,
) -> Result<Vec<UpstreamEndpoint>> {
    let endpoints = parse_endpoints(input, protocol)?;
    match endpoints
        .iter()
        .find(|endpoint| reaches_this_resolver(endpoint.socket_addr))
    {
        Some(own) => Err(DnsError::Config(format!(
            "upstream {} is this resolver's own address, so it would answer its own queries",
            own.socket_addr
        ))),
        None => Ok(endpoints),
    }
}

/// Whether a query sent to `address` comes back to this resolver: one of the two sockets it
/// listens on, or the unspecified address with their port, which an operating system
/// delivers to this host.
fn reaches_this_resolver(address: SocketAddr) -> bool {
    let listeners = [dns_listen_addr(), dns_listen_addr_v6()];
    listeners.contains(&address)
        || (address.ip().is_unspecified()
            && listeners
                .iter()
                .any(|listener| listener.port() == address.port()))
}

fn parse_endpoints(input: &str, protocol: DnsProtocol) -> Result<Vec<UpstreamEndpoint>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.contains("://") {
        return parse_url_upstream(trimmed, protocol);
    }

    if trimmed.contains('/') {
        return parse_url_upstream(&format!("https://{trimmed}"), protocol);
    }

    if let Ok(addr) = SocketAddr::from_str(trimmed) {
        let tls = tls_dns_name_for_addr(protocol, addr);
        return Ok(vec![endpoint_for_socket(addr, protocol, tls, None)]);
    }

    // A bare IPv6 literal has colons but no port; it takes the default below.
    let bare_ip = IpAddr::from_str(trimmed).is_ok();
    if let Some((host, port)) = trimmed.split_once(':').filter(|_| !bare_ip) {
        let port = port
            .parse::<u16>()
            .map_err(|error| DnsError::Config(format!("invalid upstream port: {error}")))?;
        let tls_hint = tls_name_for_hostname(protocol, host);
        return expand_host_endpoints(host, port, protocol, None, tls_hint);
    }

    let default_port = default_port_for(protocol);
    expand_host_endpoints(trimmed, default_port, protocol, None, None)
}

fn parse_url_upstream(input: &str, protocol: DnsProtocol) -> Result<Vec<UpstreamEndpoint>> {
    let url = Url::parse(input)
        .map_err(|error| DnsError::Config(format!("invalid upstream URL: {error}")))?;

    let scheme = url.scheme();
    let host = url
        .host_str()
        .ok_or_else(|| DnsError::Config("upstream URL missing host".to_owned()))?;
    // `url` serializes IPv6 hosts bracketed ("[2001:db8::1]"); every parser
    // below — `IpAddr::from_str`, the bootstrap table, TLS naming — wants the
    // bare address.
    let host = host.trim_start_matches('[').trim_end_matches(']');

    if scheme == "http" {
        return Err(DnsError::Config(
            "plain http:// DNS upstreams are not supported; use https://".to_owned(),
        ));
    }
    let (upstream_protocol, default_port) = protocol_from_scheme(scheme, protocol);
    let port = url.port().unwrap_or(default_port);
    let path = url.path();
    let http_endpoint = match scheme {
        "https" if path.is_empty() || path == "/" => Some("/dns-query".to_owned()),
        "https" => Some(path.to_owned()),
        _ => None,
    };

    let tls_hint = if IpAddr::from_str(host).is_ok() {
        tls_name_for_address(host).map(std::borrow::ToOwned::to_owned)
    } else {
        Some(host.to_owned())
    };

    expand_host_endpoints(host, port, upstream_protocol, http_endpoint, tls_hint)
}

fn expand_host_endpoints(
    host: &str,
    port: u16,
    protocol: DnsProtocol,
    http_endpoint: Option<String>,
    tls_hint: Option<String>,
) -> Result<Vec<UpstreamEndpoint>> {
    let hostname_tls = tls_hint.or_else(|| tls_name_for_hostname(protocol, host));

    if let Ok(ip) = IpAddr::from_str(host) {
        let tls =
            hostname_tls.or_else(|| tls_name_for_address(host).map(std::borrow::ToOwned::to_owned));
        return Ok(vec![endpoint_for_socket(
            SocketAddr::new(ip, port),
            protocol,
            tls,
            http_endpoint,
        )]);
    }

    let bootstrap = bootstrap_ipv4_for_host(host);
    let ips: Vec<String> = if let Some(ips) = bootstrap {
        ips
    } else {
        vec![host.to_owned()]
    };

    let mut endpoints = Vec::new();
    let mut last_error = None;

    for ip_str in ips {
        let ip = if let Ok(ip) = IpAddr::from_str(&ip_str) {
            ip
        } else if let Ok(addr) = SocketAddr::from_str(&ip_str) {
            addr.ip()
        } else {
            // System DNS points at this resolver once it runs, so it cannot
            // look up its own upstream: only known resolver hosts and IP
            // addresses can be dialled.
            last_error = Some(DnsError::Config(format!(
                "upstream host {host} is not a known resolver; use its IP address instead"
            )));
            continue;
        };

        // IPv6 endpoints are kept like any other: hickory dials them, and the
        // health registry sinks unreachable ones instead of this parser
        // silently discarding reachability.
        let tls = hostname_tls
            .clone()
            .or_else(|| tls_name_for_address(&ip_str).map(std::borrow::ToOwned::to_owned));
        endpoints.push(endpoint_for_socket(
            SocketAddr::new(ip, port),
            protocol,
            tls,
            http_endpoint.clone(),
        ));
    }

    if endpoints.is_empty() {
        return Err(last_error.unwrap_or_else(|| {
            DnsError::Config(format!("no dialable upstream endpoints for host {host}"))
        }));
    }

    Ok(endpoints)
}

fn tls_dns_name_for_addr(protocol: DnsProtocol, addr: SocketAddr) -> Option<String> {
    match protocol {
        DnsProtocol::Tls | DnsProtocol::Https | DnsProtocol::H3 | DnsProtocol::Quic => {
            tls_name_for_address(&addr.ip().to_string()).map(std::borrow::ToOwned::to_owned)
        }
        DnsProtocol::Udp | DnsProtocol::Tcp => None,
    }
}

fn tls_name_for_hostname(protocol: DnsProtocol, host: &str) -> Option<String> {
    if IpAddr::from_str(host).is_ok() {
        return None;
    }
    match protocol {
        DnsProtocol::Tls | DnsProtocol::Https | DnsProtocol::H3 | DnsProtocol::Quic => {
            Some(host.to_owned())
        }
        DnsProtocol::Udp | DnsProtocol::Tcp => None,
    }
}

fn endpoint_for_socket(
    socket_addr: SocketAddr,
    protocol: DnsProtocol,
    tls_dns_name: Option<String>,
    http_endpoint: Option<String>,
) -> UpstreamEndpoint {
    UpstreamEndpoint {
        socket_addr,
        protocol,
        tls_dns_name,
        http_endpoint,
    }
}

fn protocol_from_scheme(scheme: &str, settings_protocol: DnsProtocol) -> (DnsProtocol, u16) {
    match scheme {
        "https" => match settings_protocol {
            DnsProtocol::H3 => (DnsProtocol::H3, 443),
            _ => (DnsProtocol::Https, 443),
        },
        "quic" => (DnsProtocol::Quic, 853),
        "tls" | "dot" => (DnsProtocol::Tls, 853),
        _ => (settings_protocol, default_port_for(settings_protocol)),
    }
}

fn default_port_for(protocol: DnsProtocol) -> u16 {
    match protocol {
        DnsProtocol::Udp | DnsProtocol::Tcp => 53,
        DnsProtocol::Tls | DnsProtocol::Quic => 853,
        DnsProtocol::Https | DnsProtocol::H3 => 443,
    }
}
