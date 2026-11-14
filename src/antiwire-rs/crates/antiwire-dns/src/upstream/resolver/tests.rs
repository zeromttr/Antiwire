//! Tests for the upstream resolver module tree.

mod backpressure;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::net::{DnsError as HickoryDnsError, NetError};

use antiwire_tuning::{
    DNS_TRANSPORT_RETRY_ATTEMPTS, DNS_TRANSPORT_TIMEOUT, DOH_FORWARD_TIMEOUT, DOH_HEDGE_DELAY,
};

use super::endpoint::parse_upstream_endpoints;
use super::error_kind::{empty_answer_for_error, is_benign_empty_answer, upstream_error_kind};
use super::*;
use crate::settings::DnsProtocol;
use crate::upstream::providers;

fn query(id: u16, name: &str) -> Message {
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii(name).expect("query name"),
        RecordType::A,
    ));
    query
}

/// Builds a handle whose tiers are the given UDP servers, in order.
fn tiered(groups: &[&[SocketAddr]]) -> UpstreamDns {
    let groups: Vec<Vec<_>> = groups
        .iter()
        .map(|servers| {
            servers
                .iter()
                .flat_map(|server| {
                    parse_upstream_endpoints(&server.to_string(), DnsProtocol::Udp)
                        .expect("udp endpoint")
                })
                .collect()
        })
        .collect();
    let tiers: Vec<&[_]> = groups.iter().map(Vec::as_slice).collect();
    build_from_tiers(DnsProtocol::Udp, &tiers, Vec::new()).expect("tiered upstream")
}

/// A UDP socket that is bound but never answers.
async fn silent_udp() -> (tokio::net::UdpSocket, SocketAddr) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("silent bind");
    let addr = socket.local_addr().expect("silent address");
    (socket, addr)
}

/// A UDP server that answers only while `responding` is set, and remembers
/// the last query it received.
struct SwitchableUdp {
    addr: SocketAddr,
    responding: Arc<AtomicBool>,
    last_query: Arc<parking_lot::Mutex<Option<Message>>>,
    _task: tokio::task::JoinHandle<()>,
}

impl SwitchableUdp {
    async fn start(responding: bool) -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("switchable bind");
        let addr = socket.local_addr().expect("switchable address");
        let flag = Arc::new(AtomicBool::new(responding));
        let last_query = Arc::new(parking_lot::Mutex::new(None));
        let task = {
            let flag = Arc::clone(&flag);
            let last_query = Arc::clone(&last_query);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                        continue;
                    };
                    let Ok(request) = Message::from_vec(&buf[..len]) else {
                        continue;
                    };
                    *last_query.lock() = Some(request.clone());
                    if !flag.load(Ordering::Relaxed) {
                        continue;
                    }
                    let mut response = Message::response(request.metadata.id, OpCode::Query);
                    response.metadata.recursion_available = true;
                    if let Some(question) = request.queries.first() {
                        response.add_query(question.clone());
                        response.add_answer(hickory_proto::rr::Record::from_rdata(
                            question.name().clone(),
                            30,
                            hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                                std::net::Ipv4Addr::new(192, 0, 2, 5),
                            )),
                        ));
                    }
                    if let Ok(wire) = crate::messages::encode_message(&response) {
                        let _ = socket.send_to(&wire, peer).await;
                    }
                }
            })
        };
        Self {
            addr,
            responding: flag,
            last_query,
            _task: task,
        }
    }
}

async fn wait_until(limit: Duration, condition: impl Fn() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < limit {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    condition()
}

#[test]
fn tiers_follow_transport_boundaries_in_configured_order() {
    let dot = build_upstream_dns(
        DnsProtocol::Tls,
        &crate::upstream::resolve_upstream_urls(DnsProtocol::Tls, "cloudflare", ""),
    )
    .expect("dot upstream");
    let labels: Vec<&str> = dot.tiers.iter().map(|tier| tier.label.as_ref()).collect();
    assert_eq!(
        labels.len(),
        2,
        "port-853 primary plus its DoH fallback: {labels:?}"
    );
    assert!(labels[0].starts_with("DoT "));
    assert!(labels[1].starts_with("DoH "));

    let doh = build_upstream_dns(
        DnsProtocol::Https,
        &providers::resolve_upstream_urls(DnsProtocol::Https, "cloudflare", ""),
    )
    .expect("doh upstream");
    assert_eq!(doh.tiers.len(), 1, "one transport is one tier");
}

#[test]
fn transport_options_race_two_servers_per_tier() {
    let opts = resolver_opts_from_tuning();
    assert_eq!(opts.timeout, DNS_TRANSPORT_TIMEOUT);
    assert_eq!(opts.attempts, DNS_TRANSPORT_RETRY_ATTEMPTS);
    assert_eq!(opts.num_concurrent_reqs, 2);
    assert_eq!(opts.max_active_requests, MAX_IN_FLIGHT_PER_TIER);
}

#[tokio::test]
async fn a_silent_server_does_not_delay_its_tier_partner() {
    let (_silent, silent_addr) = silent_udp().await;
    let live = SwitchableUdp::start(true).await;
    let upstream = tiered(&[&[silent_addr, live.addr]]);

    for id in 0..5 {
        let started = Instant::now();
        let answer = upstream
            .exchange(&query(id, &format!("race{id}.test.")), None)
            .await
            .expect("the live server answers");
        assert_eq!(answer.message.answers.len(), 1);
        assert!(
            started.elapsed() < DNS_TRANSPORT_TIMEOUT,
            "both servers are queried at once, so the silent one costs nothing"
        );
    }
}

#[tokio::test]
async fn a_tier_goes_down_after_the_failure_threshold() {
    let (_silent, silent_addr) = silent_udp().await;
    let upstream = tiered(&[&[silent_addr]]);

    for id in 0..u16::try_from(antiwire_tuning::DOH_ENDPOINT_FAILURE_THRESHOLD).expect("small") {
        assert!(
            !upstream.endpoints_degraded(),
            "not down before the threshold"
        );
        assert!(upstream
            .exchange(&query(id, "down.test."), None)
            .await
            .is_err());
    }
    assert!(upstream.endpoints_degraded());
}

#[tokio::test]
async fn one_recovery_attempt_runs_while_every_tier_is_down() {
    let (_silent, silent_addr) = silent_udp().await;
    let upstream = Arc::new(tiered(&[&[silent_addr]]));
    upstream.mark_all_endpoints_failed();

    let owner = {
        let upstream = Arc::clone(&upstream);
        tokio::spawn(async move { upstream.exchange(&query(1, "owner.test."), None).await })
    };
    assert!(
        wait_until(Duration::from_secs(1), || upstream
            .recovery_occupied_for_test())
        .await,
        "the first exchange owns the recovery attempt"
    );

    let started = Instant::now();
    assert!(upstream
        .exchange(&query(2, "bystander.test."), None)
        .await
        .is_err());
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "others fail fast instead of waiting on a down tier"
    );
    assert!(owner.await.expect("owner task").is_err());
    assert!(
        upstream.endpoints_degraded(),
        "a failed recovery keeps the tier down"
    );
}

/// Port 853 blocked with a `DoH` fallback: the fallback answers every query
/// before the primary fails, so the primary is only learned from the attempts
/// that keep running after losing.
#[tokio::test]
async fn a_primary_that_always_loses_to_its_fallback_goes_down() {
    let (_blocked, blocked_addr) = silent_udp().await;
    let fallback = SwitchableUdp::start(true).await;
    let upstream = tiered(&[&[blocked_addr], &[fallback.addr]]);

    for id in 0..3 {
        let started = Instant::now();
        upstream
            .exchange(&query(id, &format!("hedged{id}.test.")), None)
            .await
            .expect("the fallback answers");
        assert!(
            started.elapsed() >= DOH_HEDGE_DELAY,
            "the primary gets its head start"
        );
    }
    assert!(
        wait_until(DOH_FORWARD_TIMEOUT * 2, || upstream.tiers[0]
            .health
            .is_down())
        .await,
        "the losing primary attempts still record their failures"
    );

    // The first query after that may own the primary's recovery attempt and
    // pay one hedge delay; the rest go straight to the fallback. That
    // recovery holds the primary out for at least its transport timeout plus
    // the recovery interval, so the queries below are never offered to it and
    // pay no hedge delay. This checks admission rather than wall-clock
    // latency, which a loaded CI runner can stretch past the hedge delay.
    let _ = upstream.exchange(&query(10, "owner.test."), None).await;
    for id in 11..16 {
        assert!(
            upstream.tiers[0].health.skips_now(),
            "a down primary no longer delays queries"
        );
        upstream
            .exchange(&query(id, &format!("direct{id}.test.")), None)
            .await
            .expect("the fallback answers");
    }
}

#[tokio::test]
async fn a_recovered_primary_takes_traffic_again() {
    let primary = SwitchableUdp::start(false).await;
    let fallback = SwitchableUdp::start(true).await;
    let upstream = tiered(&[&[primary.addr], &[fallback.addr]]);
    upstream.tiers[0].health.force_down();

    // The recovery attempt fails while the primary is silent...
    let _ = upstream.exchange(&query(1, "still-down.test."), None).await;
    assert!(
        wait_until(DOH_FORWARD_TIMEOUT * 2, || !upstream.tiers[0]
            .health
            .is_recovering())
        .await
    );
    assert!(upstream.tiers[0].health.is_down());

    // ...and the next one, an interval later, finds it answering.
    primary.responding.store(true, Ordering::Relaxed);
    tokio::time::sleep(antiwire_tuning::DNS_UPSTREAM_RECOVERY_INTERVAL).await;
    upstream
        .exchange(&query(2, "recovered.test."), None)
        .await
        .expect("answer");
    assert!(
        wait_until(Duration::from_secs(1), || !upstream.tiers[0]
            .health
            .is_down())
        .await,
        "a successful recovery attempt brings the tier back"
    );
}

#[tokio::test]
async fn a_cut_short_exchange_still_counts_one_failure() {
    let (_silent, silent_addr) = silent_udp().await;
    let upstream = tiered(&[&[silent_addr]]);

    let result = upstream
        .exchange(&query(1, "short.test."), Some(Duration::from_millis(80)))
        .await;
    assert!(matches!(result, Err(NetError::Timeout)));
    assert!(
        wait_until(DOH_FORWARD_TIMEOUT * 2, || {
            upstream.tiers[0].health.consecutive_failures() == 1
        })
        .await,
        "the attempt outlives the caller and records its own failure"
    );
    assert!(
        !upstream.endpoints_degraded(),
        "one failure is below the threshold"
    );
}

#[tokio::test]
async fn a_clients_tcp_keepalive_option_is_not_forwarded() {
    let server = SwitchableUdp::start(true).await;
    let upstream = tiered(&[&[server.addr]]);
    let mut request = query(1, "keepalive.test.");
    let mut edns = Edns::new();
    edns.options_mut().insert(EdnsOption::Unknown(
        u16::from(EdnsCode::Keepalive),
        Vec::new(),
    ));
    edns.options_mut()
        .insert(EdnsOption::Subnet("192.168.1.0/24".parse().unwrap()));
    edns.options_mut().insert(EdnsOption::Unknown(
        u16::from(EdnsCode::Padding),
        vec![0; 32],
    ));
    request.set_edns(edns);

    upstream.exchange(&request, None).await.expect("answer");
    let forwarded = server
        .last_query
        .lock()
        .clone()
        .expect("query reached the server");
    assert!(forwarded
        .edns
        .as_ref()
        .and_then(|edns| edns.option(EdnsCode::Keepalive))
        .is_none());
    for code in [EdnsCode::Subnet, EdnsCode::Padding] {
        assert!(forwarded
            .edns
            .as_ref()
            .and_then(|edns| edns.option(code))
            .is_none());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cold_start_gate_opens_one_connection_for_a_burst() {
    let (addr, accepted) = spawn_counting_tcp_upstream().await;
    let upstream =
        Arc::new(build_upstream_dns(DnsProtocol::Tcp, &[addr.to_string()]).expect("tcp upstream"));

    let tasks: Vec<_> = (0..32u16)
        .map(|id| {
            let upstream = Arc::clone(&upstream);
            tokio::spawn(async move {
                upstream
                    .exchange(&query(id, &format!("cold{id}.test.")), None)
                    .await
                    .is_ok()
            })
        })
        .collect();
    for task in tasks {
        assert!(
            task.await.expect("exchange task"),
            "every query is answered"
        );
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

/// Why the cold-start gate exists: without it, Hickory 0.26.3 opens one
/// connection per request that arrives before the first connection is up. If
/// this starts failing, Hickory coalesces cold connects and the gate can go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hickory_opens_a_connection_per_concurrent_cold_query() {
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
    use hickory_resolver::{NameServerPool, PoolContext, TlsConfig};

    let (addr, accepted) = spawn_counting_tcp_upstream().await;
    let endpoints = parse_upstream_endpoints(&addr.to_string(), DnsProtocol::Tcp).expect("parse");
    let opts = resolver_opts_from_tuning();
    let request_options = request_options_from_resolver_opts(&opts);
    let context = Arc::new(PoolContext::new(opts, TlsConfig::new().expect("tls")));
    let pool = Arc::new(NameServerPool::from_config(
        [endpoints[0].to_name_server_config()],
        context,
        TokioRuntimeProvider::new(),
    ));

    let tasks: Vec<_> = (0..32u16)
        .map(|id| {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move {
                let request = hickory_proto::op::DnsRequest::new(
                    query(id, &format!("cold{id}.test.")),
                    request_options,
                );
                pool.send(request).first_answer().await.is_ok()
            })
        })
        .collect();
    for task in tasks {
        assert!(task.await.expect("query task"));
    }
    assert!(
        accepted.load(Ordering::SeqCst) > 1,
        "Hickory now coalesces cold connects; the cold-start gate is no longer needed"
    );
}

/// A server that truncates every UDP answer. Over TCP on the same port it
/// answers in full, or truncates there too.
struct TruncatingUdp {
    addr: SocketAddr,
    udp_queries: Arc<AtomicUsize>,
    tcp_queries: Arc<AtomicUsize>,
}

impl TruncatingUdp {
    /// The answer to `request`, or with `truncated` only its TC bit.
    fn reply(request: &Message, truncated: bool) -> Vec<u8> {
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.metadata.recursion_available = true;
        response.metadata.truncation = truncated;
        response.queries.clone_from(&request.queries);
        if let (false, Some(question)) = (truncated, request.queries.first()) {
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                question.name().clone(),
                30,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                    192, 0, 2, 9,
                ))),
            ));
        }
        crate::messages::encode_message(&response).expect("encode")
    }

    async fn start(tcp_truncates: bool) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // One port for both transports, as a real server has. The UDP port a
        // free TCP port shares is almost always free too.
        let (tcp, udp) = loop {
            let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("tcp bind");
            let addr = tcp.local_addr().expect("tcp address");
            if let Ok(udp) = tokio::net::UdpSocket::bind(addr).await {
                break (tcp, udp);
            }
        };
        let addr = tcp.local_addr().expect("address");
        let udp_queries = Arc::new(AtomicUsize::new(0));
        let tcp_queries = Arc::new(AtomicUsize::new(0));

        let counter = Arc::clone(&udp_queries);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                let Ok(request) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = udp.send_to(&Self::reply(&request, true), peer).await;
            }
        });
        let counter = Arc::clone(&tcp_queries);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    loop {
                        let mut len = [0u8; 2];
                        if stream.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut wire = vec![0u8; usize::from(u16::from_be_bytes(len))];
                        if stream.read_exact(&mut wire).await.is_err() {
                            return;
                        }
                        let Ok(request) = Message::from_vec(&wire) else {
                            return;
                        };
                        counter.fetch_add(1, Ordering::SeqCst);
                        let bytes = Self::reply(&request, tcp_truncates);
                        let len = u16::try_from(bytes.len()).expect("frame");
                        if stream.write_all(&len.to_be_bytes()).await.is_err()
                            || stream.write_all(&bytes).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        Self {
            addr,
            udp_queries,
            tcp_queries,
        }
    }
}

/// The regression this guards: a plain UDP upstream had no TCP connection to
/// retry on, so every truncated answer came back as an error and the name
/// could not resolve.
#[tokio::test]
async fn a_truncated_udp_answer_is_asked_again_over_tcp() {
    let server = TruncatingUdp::start(false).await;
    let upstream = build_upstream_dns(DnsProtocol::Udp, &[server.addr.to_string()]).expect("udp");

    let answer = upstream
        .exchange(&query(1, "large.test."), None)
        .await
        .expect("the TCP retry answers");
    assert_eq!(answer.message.answers.len(), 1);
    assert!(!answer.message.metadata.truncation);
    assert_eq!(server.udp_queries.load(Ordering::SeqCst), 1);
    assert_eq!(server.tcp_queries.load(Ordering::SeqCst), 1);
    assert_eq!(upstream.tiers[0].health.consecutive_failures(), 0);
}

/// A server that truncates over TCP as well did answer, so its tier stays up
/// however many names fail that way.
#[tokio::test]
async fn truncated_answers_do_not_take_a_tier_down() {
    let server = TruncatingUdp::start(true).await;
    let upstream = build_upstream_dns(DnsProtocol::Udp, &[server.addr.to_string()]).expect("udp");

    let attempts = u16::try_from(antiwire_tuning::DOH_ENDPOINT_FAILURE_THRESHOLD).expect("small");
    for id in 0..=attempts {
        let error = upstream
            .exchange(&query(id, &format!("large{id}.test.")), None)
            .await
            .err()
            .expect("truncated on both transports");
        assert!(matches!(error, NetError::Truncated), "{error}");
    }
    assert!(!upstream.endpoints_degraded());
    assert_eq!(upstream.tiers[0].health.consecutive_failures(), 0);
}

#[test]
fn error_kinds_come_from_typed_errors() {
    assert_eq!(upstream_error_kind(&NetError::Timeout), "timeout");
    assert_eq!(
        upstream_error_kind(&NetError::from(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        ))),
        "connection_closed"
    );
    assert_eq!(
        upstream_error_kind(&NetError::Dns(HickoryDnsError::ResponseCode(
            hickory_proto::op::ResponseCode::Refused
        ))),
        "dns"
    );
    assert_eq!(upstream_error_kind(&NetError::Truncated), "truncated");
}

#[test]
fn only_nxdomain_and_nodata_become_answers() {
    let servfail = NetError::from(hickory_resolver::net::NoRecords::new(
        Query::query(Name::from_ascii("x.example.").expect("name"), RecordType::A),
        hickory_proto::op::ResponseCode::ServFail,
    ));
    assert!(!is_benign_empty_answer(&servfail));
    assert!(is_benign_empty_answer(&no_records_error(
        hickory_proto::op::ResponseCode::NXDomain,
        None,
        None,
    )));
    assert!(is_benign_empty_answer(&no_records_error(
        hickory_proto::op::ResponseCode::NoError,
        None,
        None,
    )));
}

#[test]
fn ipv6_upstreams_are_kept_on_every_parse_path() {
    let url = parse_upstream_endpoints(
        "https://[2606:4700:4700::1111]/dns-query",
        DnsProtocol::Https,
    )
    .expect("parse");
    assert_eq!(url.len(), 1);
    assert_eq!(
        url[0].socket_addr,
        "[2606:4700:4700::1111]:443".parse().expect("v6 addr")
    );

    let socket =
        parse_upstream_endpoints("[2606:4700:4700::1111]:853", DnsProtocol::Tls).expect("parse");
    assert_eq!(socket.len(), 1);
    assert_eq!(
        socket[0].socket_addr,
        "[2606:4700:4700::1111]:853".parse().expect("v6 addr")
    );
}

/// The resolver forwarding to its own socket would answer each query by asking itself.
/// Another resolver on this host, on a different loopback address or port, is a valid
/// upstream.
#[test]
fn an_upstream_that_is_this_resolver_is_refused() {
    for (own, protocol) in [
        ("127.0.0.1", DnsProtocol::Udp),
        ("127.0.0.1:53", DnsProtocol::Tcp),
        ("[::1]:53", DnsProtocol::Udp),
        ("0.0.0.0:53", DnsProtocol::Udp),
        ("https://127.0.0.1:53/dns-query", DnsProtocol::Https),
    ] {
        let error = parse_upstream_endpoints(own, protocol).expect_err(own);
        assert!(error.to_string().contains("own address"), "{own}: {error}");
    }
    for (local, protocol) in [
        ("127.0.0.53", DnsProtocol::Udp),
        ("127.0.0.1:5353", DnsProtocol::Udp),
        ("https://127.0.0.1/dns-query", DnsProtocol::Https),
        ("https://127.0.0.1:8443/dns-query", DnsProtocol::Https),
    ] {
        assert_eq!(
            parse_upstream_endpoints(local, protocol)
                .expect(local)
                .len(),
            1
        );
    }
}

/// A bare IPv6 literal has no port to split off; it gets the transport's
/// default port, as a bare IPv4 literal does.
#[test]
fn bare_ipv6_upstream_uses_the_default_port() {
    for (protocol, port) in [(DnsProtocol::Tls, 853), (DnsProtocol::Udp, 53)] {
        let endpoints =
            parse_upstream_endpoints("2606:4700:4700::1111", protocol).expect("bare ipv6");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints[0].socket_addr,
            SocketAddr::new("2606:4700:4700::1111".parse().expect("v6"), port)
        );
    }
}

#[test]
fn partially_invalid_upstreams_build_with_warnings() {
    let upstream = build_upstream_dns(
        DnsProtocol::Udp,
        &[
            "127.0.0.1:5353".to_owned(),
            "definitely not an upstream".to_owned(),
        ],
    )
    .expect("one valid endpoint is enough to serve");

    let warnings = upstream.config_warnings();
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0].contains("definitely not an upstream"),
        "the warning names the skipped upstream"
    );

    // All-valid and all-invalid configurations keep their old behavior.
    let all_valid =
        build_upstream_dns(DnsProtocol::Udp, &["127.0.0.1:5353".to_owned()]).expect("valid");
    assert_eq!(all_valid.config_warnings(), [] as [String; 0]);
    assert!(build_upstream_dns(DnsProtocol::Udp, &["also bad".to_owned()]).is_err());
}

#[test]
fn invalid_upstream_diagnostics_do_not_echo_credentials_or_tokens() {
    let sensitive = "https://user:password@[invalid?token=secret".to_owned();
    let error = build_upstream_dns(DnsProtocol::Https, &[sensitive])
        .err()
        .expect("invalid upstream must fail")
        .to_string();

    assert!(!error.contains("password"));
    assert!(!error.contains("secret"));
}

#[test]
fn endpoint_labels_do_not_expose_custom_paths() {
    let endpoints =
        parse_upstream_endpoints("https://1.1.1.1/private/token-value", DnsProtocol::Https)
            .expect("valid upstream");

    let label = endpoints[0].label();
    assert!(!label.contains("private"));
    assert!(!label.contains("token-value"));
}

#[tokio::test]
async fn single_endpoint_exchange_has_the_forward_deadline() {
    // Keep a real UDP port open but never read or answer. This avoids an
    // immediate ICMP refusal and exercises the single-candidate branch.
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("blackhole bind");
    let endpoint = blackhole.local_addr().expect("blackhole address");
    let upstream =
        build_upstream_dns(DnsProtocol::Udp, &[endpoint.to_string()]).expect("single upstream");
    let mut query = Message::new(1, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        hickory_proto::rr::Name::from_ascii("timeout.test.").expect("query name"),
        hickory_proto::rr::RecordType::A,
    ));

    let result = tokio::time::timeout(
        DOH_FORWARD_TIMEOUT + Duration::from_secs(1),
        upstream.exchange(&query, None),
    )
    .await
    .expect("upstream's own deadline must fire");
    assert!(result.is_err());
}

#[tokio::test]
async fn exchange_honors_a_shorter_caller_budget() {
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("blackhole bind");
    let endpoint = blackhole.local_addr().expect("blackhole address");
    let upstream =
        build_upstream_dns(DnsProtocol::Udp, &[endpoint.to_string()]).expect("single upstream");
    let mut query = Message::new(1, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        hickory_proto::rr::Name::from_ascii("short-budget.test.").expect("query name"),
        hickory_proto::rr::RecordType::A,
    ));

    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_millis(500),
        upstream.exchange(&query, Some(Duration::from_millis(80))),
    )
    .await
    .expect("caller budget must fire before the outer wait");
    assert!(result.is_err());
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "a 80ms budget must not wait the full forward timeout"
    );
    assert!(
        !upstream.endpoints_degraded(),
        "a short leftover budget is not evidence that the tier is down"
    );
}

#[tokio::test]
async fn first_packet_loss_recovers_inside_the_client_deadline() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let endpoint = socket.local_addr().expect("addr");
    let upstream = build_upstream_dns(DnsProtocol::Udp, &[endpoint.to_string()]).expect("upstream");
    let mut query = Message::new(7, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("retry.test.").expect("name"),
        RecordType::A,
    ));
    let responder = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        let mut seen = 0_u32;
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            seen += 1;
            if seen == 1 {
                continue;
            }
            let Ok(request) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response.metadata.response_code = hickory_proto::op::ResponseCode::NoError;
            if let Some(question) = request.queries.first() {
                response.add_query(question.clone());
                response.add_answer(hickory_proto::rr::Record::from_rdata(
                    question.name().clone(),
                    30,
                    hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                        std::net::Ipv4Addr::new(1, 2, 3, 4),
                    )),
                ));
            }
            if let Ok(wire) = crate::messages::encode_message(&response) {
                let _ = socket.send_to(&wire, peer).await;
            }
            break;
        }
    });
    let started = Instant::now();
    let result = tokio::time::timeout(DOH_FORWARD_TIMEOUT, upstream.exchange(&query, None))
        .await
        .expect("deadline")
        .expect("retry recovered");
    assert!(started.elapsed() < DOH_FORWARD_TIMEOUT);
    assert_eq!(result.message.answers.len(), 1);
    let _ = responder.await;
}

/// Plain DNS settings must build a plain pool. They once resolved to the
/// provider's `DoH` URLs, which the `https://` scheme turned into HTTPS while
/// the log still said UDP.
#[test]
fn plain_dns_settings_build_a_plain_dns_tier() {
    for (setting, protocol) in [("udp", DnsProtocol::Udp), ("tcp", DnsProtocol::Tcp)] {
        let urls = providers::resolve_upstream_urls(protocol, "quad9", "");
        let (endpoints, warnings) =
            super::endpoint::collect_upstream_endpoints(protocol, &urls).expect("endpoints");
        assert!(warnings.is_empty(), "{warnings:?}");
        let first = &endpoints[0];
        assert_eq!(first.protocol, protocol, "{setting}");
        assert_eq!(first.socket_addr.to_string(), "9.9.9.9:53", "{setting}");
        assert_eq!(
            endpoints.last().map(|endpoint| endpoint.protocol),
            Some(DnsProtocol::Https),
            "the provider's DoH stays as failover"
        );
    }
}

#[test]
fn parses_host_port_upstream() {
    let endpoints = parse_upstream_endpoints("1.1.1.1:53", DnsProtocol::Udp).expect("parse");
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].socket_addr.port(), 53);
}

#[test]
fn parses_doh_ip_url_with_tls_name() {
    let endpoints =
        parse_upstream_endpoints("https://1.1.1.1/dns-query", DnsProtocol::Https).expect("parse");
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].socket_addr, "1.1.1.1:443".parse().unwrap());
    assert_eq!(endpoints[0].protocol, DnsProtocol::Https);
    assert_eq!(
        endpoints[0].tls_dns_name.as_deref(),
        Some("cloudflare-dns.com")
    );
    assert_eq!(endpoints[0].http_endpoint.as_deref(), Some("/dns-query"));
}

#[test]
fn parses_doh_hostname_via_bootstrap() {
    let endpoints = parse_upstream_endpoints("https://dns.quad9.net/dns-query", DnsProtocol::Https)
        .expect("parse");
    assert_ne!(endpoints, []);
    assert_eq!(
        endpoints[0].socket_addr.ip(),
        IpAddr::from_str("9.9.9.9").unwrap()
    );
    assert_eq!(endpoints[0].tls_dns_name.as_deref(), Some("dns.quad9.net"));
}

#[test]
fn parses_dot_ip_with_tls_name() {
    let endpoints = parse_upstream_endpoints("1.1.1.1:853", DnsProtocol::Tls).expect("parse");
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].socket_addr, "1.1.1.1:853".parse().unwrap());
    assert_eq!(endpoints[0].protocol, DnsProtocol::Tls);
    assert_eq!(
        endpoints[0].tls_dns_name.as_deref(),
        Some("cloudflare-dns.com")
    );
    assert!(endpoints[0].http_endpoint.is_none());
}

#[test]
fn parses_tls_url_upstream() {
    let endpoints =
        parse_upstream_endpoints("tls://dns.quad9.net:853", DnsProtocol::Tls).expect("parse");
    assert_ne!(endpoints, []);
    assert_eq!(endpoints[0].protocol, DnsProtocol::Tls);
    assert_eq!(endpoints[0].tls_dns_name.as_deref(), Some("dns.quad9.net"));
}

#[test]
fn endpoint_label_includes_tls_without_custom_path() {
    let endpoint = parse_upstream_endpoints("https://1.1.1.1/dns-query", DnsProtocol::Https)
        .expect("parse")
        .pop()
        .expect("endpoint");
    let label = endpoint.label();
    assert!(label.contains("1.1.1.1:443"));
    assert!(label.contains("cloudflare-dns.com"));
    assert!(!label.contains("/dns-query"));
}

#[test]
fn empty_answer_for_error_preserves_query() {
    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("example.test.").expect("name"),
        RecordType::HTTPS,
    ));
    let error = resolve_error_msg("no records found");
    let response = empty_answer_for_error(&query, &error);
    assert_eq!(
        response.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(response.queries.len(), 1);
}

/// Builds the `NoRecords` error hickory raises for an answerless response.
fn no_records_error(
    rcode: hickory_proto::op::ResponseCode,
    authorities: Option<Vec<hickory_proto::rr::Record>>,
    soa: Option<hickory_proto::rr::Record<hickory_proto::rr::rdata::SOA>>,
) -> NetError {
    let query = Query::query(
        Name::from_ascii("missing.test.").expect("name"),
        RecordType::A,
    );
    let mut no_records = hickory_resolver::net::NoRecords::new(query, rcode);
    no_records.soa = soa.map(Box::new);
    no_records.authorities = authorities.map(Into::into);
    no_records.negative_ttl = Some(120);
    NetError::from(no_records)
}

fn sample_soa(ttl: u32, minimum: u32) -> hickory_proto::rr::Record<hickory_proto::rr::rdata::SOA> {
    let name = Name::from_ascii("test.").expect("name");
    hickory_proto::rr::Record::from_rdata(
        name.clone(),
        ttl,
        hickory_proto::rr::rdata::SOA::new(name.clone(), name, 1, 7200, 3600, 1_209_600, minimum),
    )
}

/// The negative TTL only survives if the SOA reaches the synthesized answer:
/// `ResponseCache` derives it from the authority section.
#[test]
fn empty_answer_for_error_keeps_the_authority_section() {
    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("missing.test.").expect("name"),
        RecordType::A,
    ));

    let authority = sample_soa(12, 12).into_record_of_rdata();
    let error = no_records_error(
        hickory_proto::op::ResponseCode::NXDomain,
        Some(vec![authority]),
        Some(sample_soa(12, 12)),
    );

    let response = empty_answer_for_error(&query, &error);
    assert_eq!(
        response.metadata.response_code,
        hickory_proto::op::ResponseCode::NXDomain
    );
    assert_eq!(response.authorities.len(), 1);
    assert_eq!(
        crate::response_cache::ResponseCache::message_ttl_seconds(&response),
        12,
        "SOA-derived negative TTL reaches the cache"
    );
}

/// Some upstreams return the SOA without a full authority section.
#[test]
fn empty_answer_for_error_falls_back_to_the_bare_soa() {
    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("missing.test.").expect("name"),
        RecordType::A,
    ));

    let error = no_records_error(
        hickory_proto::op::ResponseCode::NoError,
        None,
        Some(sample_soa(600, 9)),
    );

    let response = empty_answer_for_error(&query, &error);
    assert_eq!(
        response.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(response.authorities.len(), 1);
    assert_eq!(
        crate::response_cache::ResponseCache::message_ttl_seconds(&response),
        9
    );
}

/// An upstream that sends neither must still produce a well-formed answer.
#[test]
fn empty_answer_for_error_without_soa_stays_well_formed() {
    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("missing.test.").expect("name"),
        RecordType::A,
    ));

    let error = no_records_error(hickory_proto::op::ResponseCode::NXDomain, None, None);
    let response = empty_answer_for_error(&query, &error);

    assert_eq!(
        response.metadata.response_code,
        hickory_proto::op::ResponseCode::NXDomain
    );
    assert_eq!(response.authorities, []);
    assert_eq!(response.queries.len(), 1);
}

#[test]
fn transport_retry_policy_is_two_ordinary_sends() {
    assert_eq!(
        DNS_TRANSPORT_RETRY_ATTEMPTS, 1,
        "RetryDnsHandle remaining retries after the initial send"
    );
}

/// Requires network; validates Hickory rustls trust anchors (webpki-roots / platform verifier).
#[tokio::test]
#[ignore = "requires external network access"]
async fn cloudflare_doh_upstream_resolves_public_name() {
    let upstreams = providers::resolve_upstream_urls(DnsProtocol::Https, "cloudflare", "");
    let upstream = build_upstream_dns(DnsProtocol::Https, &upstreams).expect("upstream");

    let name = Name::from_ascii("cloudflare.com.").expect("name");
    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(name, RecordType::A));

    let response = upstream.exchange(&query, None).await;
    assert!(
        response.is_ok(),
        "DoH exchange failed (trust anchors or network): {:?}",
        response.err()
    );
    let message = response.expect("response");
    assert_ne!(message.message.answers, []);
}

/// Requires network; 0.26 makes the TLS server name mandatory on encrypted
/// transports, so exercise `DoT` and `DoQ` end to end rather than only
/// asserting that the configuration builds.
#[tokio::test]
#[ignore = "requires external network access"]
async fn encrypted_upstreams_resolve_public_name() {
    for (protocol, upstreams) in [
        (
            DnsProtocol::Tls,
            providers::resolve_upstream_urls(DnsProtocol::Tls, "cloudflare", ""),
        ),
        (
            DnsProtocol::Quic,
            providers::resolve_upstream_urls(DnsProtocol::Quic, "adguard", ""),
        ),
    ] {
        let upstream = build_upstream_dns(protocol, &upstreams).expect("upstream");

        let name = Name::from_ascii("cloudflare.com.").expect("name");
        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(name, RecordType::A));

        let response = upstream.exchange(&query, None).await;
        assert!(
            response.is_ok(),
            "{protocol:?} exchange failed (server name, trust anchors, or network): {:?}",
            response.err()
        );
        assert_ne!(response.expect("response").message.answers, []);
    }
}

#[test]
fn empty_upstreams_fail() {
    match build_upstream_dns(DnsProtocol::Https, &[]) {
        Err(error) => assert!(error.to_string().contains("no upstream")),
        Ok(_) => panic!("expected empty upstream list to fail"),
    }
}

/// Answers every framed query on every accepted connection, counting accepts.
async fn spawn_counting_tcp_upstream() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("tcp upstream bind");
    let addr = listener.local_addr().expect("tcp upstream address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut wire = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    if stream.read_exact(&mut wire).await.is_err() {
                        return;
                    }
                    let Ok(query) = Message::from_vec(&wire) else {
                        return;
                    };
                    let mut response = Message::response(query.metadata.id, OpCode::Query);
                    response.queries.clone_from(&query.queries);
                    response.metadata.recursion_available = true;
                    if let Some(question) = query.queries.first() {
                        response.add_answer(hickory_proto::rr::Record::from_rdata(
                            question.name().clone(),
                            300,
                            hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                                std::net::Ipv4Addr::new(192, 0, 2, 1),
                            )),
                        ));
                    }
                    let bytes = crate::messages::encode_message(&response).expect("encode");
                    let len = u16::try_from(bytes.len()).expect("frame");
                    if stream.write_all(&len.to_be_bytes()).await.is_err()
                        || stream.write_all(&bytes).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    (addr, accepted)
}

/// The regression this guards: an `http://` upstream was dialled as `DoH` on
/// port 80, which can never complete a TLS handshake.
#[test]
fn plain_http_upstream_is_a_config_error() {
    let error = parse_upstream_endpoints("http://1.1.1.1/dns-query", DnsProtocol::Https)
        .expect_err("http upstream refused");
    assert!(error.to_string().contains("https://"), "{error}");
}
