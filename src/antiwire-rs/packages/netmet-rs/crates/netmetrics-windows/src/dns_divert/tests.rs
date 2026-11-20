use super::nat::{NAT_RETENTION, NatTable, OriginalKey, PortReservation};
use super::packet::{
    PacketView, Redirect, bound_address_covers, interface_indices, owned_by_us, redirect_packet,
    stub_for,
};
use super::*;
use socket2::{Domain, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};

static DIVERT_TEST_LOCK: Mutex<()> = Mutex::new(());

struct TestNat;

impl Drop for TestNat {
    fn drop(&mut self) {
        *active_nat().lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

fn udp_query() -> Vec<u8> {
    let mut packet = vec![0u8; 28];
    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = 28;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
    packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
    packet[20..22].copy_from_slice(&50_000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&53u16.to_be_bytes());
    packet[24..26].copy_from_slice(&8u16.to_be_bytes());
    // Checksums are left zero: the divert loop has WinDivert compute them.
    packet
}

/// Whether `redirect_packet` rewrote the packet.
fn redirected(
    packet: &mut [u8],
    address: &mut DivertAddress,
    nat: &mut NatTable,
    ours: bool,
    now: Instant,
) -> bool {
    let view = PacketView::parse(packet).expect("readable packet");
    redirect_packet(packet, &view, address, nat, ours, now) == Redirect::Rewritten
}

fn address(outbound: bool, loopback: bool, if_idx: u32) -> DivertAddress {
    let mut layer_event = 0;
    if outbound {
        layer_event |= OUTBOUND_BIT;
    }
    if loopback {
        layer_event |= LOOPBACK_BIT;
    }
    let mut data = [0u8; 64];
    data[0..4].copy_from_slice(&if_idx.to_ne_bytes());
    DivertAddress {
        timestamp: 0,
        layer_event,
        reserved2: 0,
        data,
    }
}

#[test]
fn bypassed_query_is_aimed_at_the_stub_and_the_reply_restores_the_server() {
    let mut nat = NatTable::default();
    let now = Instant::now();
    let mut query = udp_query();
    let mut query_addr = address(true, false, 12);
    assert!(redirected(
        &mut query,
        &mut query_addr,
        &mut nat,
        false,
        now
    ));
    assert_eq!(&query[16..20], &[127, 0, 0, 1]);
    assert_eq!(&query[12..16], &[127, 0, 0, 1]);
    let mapped_port = u16::from_be_bytes([query[20], query[21]]);
    assert_eq!(query_addr.layer_event & LOOPBACK_BIT, LOOPBACK_BIT);
    assert_eq!(query_addr.layer_event & OUTBOUND_BIT, OUTBOUND_BIT);

    let mut reply = udp_query();
    reply[12..16].copy_from_slice(&[127, 0, 0, 1]);
    reply[16..20].copy_from_slice(&[127, 0, 0, 1]);
    reply[20..22].copy_from_slice(&53u16.to_be_bytes());
    reply[22..24].copy_from_slice(&mapped_port.to_be_bytes());
    let mut reply_addr = address(true, true, 1);
    assert!(redirected(
        &mut reply,
        &mut reply_addr,
        &mut nat,
        false,
        now
    ));
    assert_eq!(&reply[12..16], &[8, 8, 8, 8]);
    assert_eq!(&reply[16..20], &[192, 0, 2, 10]);
    assert_eq!(&reply[22..24], &50_000u16.to_be_bytes());
    assert_eq!(interface_indices(&reply_addr).0, 12);
    assert_eq!(reply_addr.layer_event & LOOPBACK_BIT, 0);
}

#[test]
fn unreadable_outbound_dns_is_dropped_rather_than_sent_unfiltered() {
    let mut fragment = udp_query();
    // More fragments: the ports of the rest of the query are not here.
    fragment[6] = 0x20;
    let mut addr = address(true, false, 1);
    assert!(PacketView::parse(&fragment).is_none());
    assert_eq!(
        handle_packet(&mut fragment, &mut addr, 0, Instant::now()),
        Verdict::Drop
    );
}

fn ipv6_udp_query_with_destination_options() -> Vec<u8> {
    let mut packet = vec![0u8; 56];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&16u16.to_be_bytes());
    packet[6] = 60;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&"2001:db8::10".parse::<Ipv6Addr>().expect("IPv6").octets());
    packet[24..40].copy_from_slice(&"2001:db8::53".parse::<Ipv6Addr>().expect("IPv6").octets());
    packet[40] = 17;
    packet[48..50].copy_from_slice(&50_000u16.to_be_bytes());
    packet[50..52].copy_from_slice(&53u16.to_be_bytes());
    packet[52..54].copy_from_slice(&8u16.to_be_bytes());
    packet
}

#[test]
fn a_query_behind_ipv6_extension_headers_is_seen_and_not_sent_on() {
    let mut nat = NatTable::default();
    let mut query = ipv6_udp_query_with_destination_options();
    let original = query.clone();
    let view = PacketView::parse(&query).expect("ports past the extension header");
    assert_eq!((view.src_port, view.dst_port), (50_000, 53));
    assert!(!view.rewritable);
    let mut addr = address(true, false, 1);
    assert_eq!(
        redirect_packet(
            &mut query,
            &view,
            &mut addr,
            &mut nat,
            false,
            Instant::now()
        ),
        Redirect::Unredirectable
    );
    assert_eq!(query, original, "nothing is half rewritten");
    assert_eq!(
        redirect_packet(&mut query, &view, &mut addr, &mut nat, true, Instant::now()),
        Redirect::Unchanged,
        "the daemon's own upstream still goes out"
    );
}

#[test]
fn the_flow_listener_answers_ownership_without_a_socket_table_read() {
    use crate::endpoint_owner::{EndpointOwnerFeed, publish, tests::SERIAL, withdraw};

    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    // A port nothing on this machine holds, so the socket table would
    // answer "not ours".
    let free = UdpSocket::bind("0.0.0.0:0").expect("bind");
    let port = free.local_addr().expect("port").port();
    drop(free);
    let view = PacketView::parse(&{
        let mut query = udp_query();
        query[20..22].copy_from_slice(&port.to_be_bytes());
        query
    })
    .expect("query");
    let our_pid = std::process::id();
    assert_eq!(owned_by_us(&view, our_pid, Instant::now()), Some(false));

    let feed = Arc::new(EndpointOwnerFeed::new(crate::endpoint_owner::trusted_owner));
    publish(&feed);
    let established = Instant::now();
    feed.received(
        established,
        Some((
            Protocol::Udp,
            LocalEndpoint {
                address: view.src,
                port,
            },
            our_pid,
        )),
        established,
    );
    let sent = Instant::now();
    feed.received(sent + Duration::from_millis(1), None, sent);
    let owner = owned_by_us(&view, our_pid, sent);
    withdraw(&feed);
    assert_eq!(owner, Some(true), "the FLOW record decides");
}

/// The regression this guards: a `System` owner recorded after ours, as a
/// reinjected packet's flow reports, made the divert drop our own `DoQ`.
#[test]
fn a_system_flow_owner_defers_to_the_socket_table() {
    use crate::endpoint_owner::{EndpointOwnerFeed, SYSTEM_PID, publish, tests::SERIAL, withdraw};

    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let held = UdpSocket::bind("0.0.0.0:0").expect("bind");
    let port = held.local_addr().expect("port").port();
    let view = PacketView::parse(&{
        let mut query = udp_query();
        query[20..22].copy_from_slice(&port.to_be_bytes());
        query
    })
    .expect("query");
    let our_pid = std::process::id();
    let endpoint = LocalEndpoint {
        address: view.src,
        port,
    };

    let feed = Arc::new(EndpointOwnerFeed::new(crate::endpoint_owner::trusted_owner));
    publish(&feed);
    let sent = Instant::now();
    let established = sent.checked_sub(Duration::from_millis(10)).expect("past");
    let echoed = sent.checked_sub(Duration::from_millis(5)).expect("past");
    feed.received(established, Some((Protocol::Udp, endpoint, our_pid)), sent);
    feed.received(echoed, Some((Protocol::Udp, endpoint, SYSTEM_PID)), sent);
    feed.received(sent + Duration::from_millis(1), None, sent);
    let owner = owned_by_us(&view, our_pid, sent);
    withdraw(&feed);
    drop(held);
    assert_eq!(owner, Some(true), "the socket table names us");
}

#[test]
fn wildcard_bind_covers_the_interface_address_chosen_for_the_packet() {
    let iface = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    assert!(bound_address_covers(iface, iface));
    assert!(bound_address_covers(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        iface
    ));
    assert!(bound_address_covers(
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        iface
    ));
    assert!(!bound_address_covers(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
        iface
    ));
    assert!(!bound_address_covers(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    ));
}

#[test]
fn traffic_already_at_the_stub_is_left_alone() {
    let mut nat = NatTable::default();
    let mut query = udp_query();
    query[16..20].copy_from_slice(&[127, 0, 0, 1]);
    let mut addr = address(true, false, 1);
    assert!(!redirected(
        &mut query,
        &mut addr,
        &mut nat,
        false,
        Instant::now()
    ));
    assert_eq!(&query[16..20], &[127, 0, 0, 1]);
}

#[test]
fn one_client_port_can_query_two_resolvers_without_reply_source_collision() {
    let mut nat = NatTable::default();
    let now = Instant::now();
    let mut first = udp_query();
    let mut second = udp_query();
    second[16..20].copy_from_slice(&[1, 1, 1, 1]);
    let mut first_addr = address(true, false, 12);
    let mut second_addr = address(true, false, 12);
    assert!(redirected(
        &mut first,
        &mut first_addr,
        &mut nat,
        false,
        now
    ));
    assert!(redirected(
        &mut second,
        &mut second_addr,
        &mut nat,
        false,
        now
    ));
    let first_port = u16::from_be_bytes([first[20], first[21]]);
    let second_port = u16::from_be_bytes([second[20], second[21]]);
    assert_ne!(first_port, second_port);

    for (port, resolver) in [(first_port, [8, 8, 8, 8]), (second_port, [1, 1, 1, 1])] {
        let mut reply = udp_query();
        reply[12..16].copy_from_slice(&[127, 0, 0, 1]);
        reply[16..20].copy_from_slice(&[127, 0, 0, 1]);
        reply[20..22].copy_from_slice(&53u16.to_be_bytes());
        reply[22..24].copy_from_slice(&port.to_be_bytes());
        let mut reply_addr = address(true, true, 1);
        assert!(redirected(
            &mut reply,
            &mut reply_addr,
            &mut nat,
            false,
            now
        ));
        assert_eq!(&reply[12..16], &resolver);
        assert_eq!(&reply[16..20], &[192, 0, 2, 10]);
        assert_eq!(&reply[22..24], &50_000u16.to_be_bytes());
    }
}

#[test]
fn redirect_origins_are_scoped_and_release_reserved_ports_on_expiry() {
    let now = Instant::now();
    for (protocol, tcp) in [(Protocol::Udp, false), (Protocol::Tcp, true)] {
        for client in [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V6("2001:db8::10".parse().expect("IPv6")),
        ] {
            let original = OriginalKey {
                tcp,
                client,
                port: 50_000,
                server: client,
            };
            let mut nat = NatTable::default();
            let port = nat.map_query(original, 12, 0, now).expect("map query");
            let mapped = LocalEndpoint {
                address: stub_for(client),
                port,
            };
            assert_eq!(
                nat.original_endpoint(protocol, mapped, now),
                Some(LocalEndpoint {
                    address: client,
                    port: original.port
                })
            );
            assert_eq!(nat.map_query(original, 12, 0, now), Some(port));
            let other_protocol = if tcp { Protocol::Udp } else { Protocol::Tcp };
            assert_eq!(nat.original_endpoint(other_protocol, mapped, now), None);
            let other_family = if client.is_ipv4() {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            };
            assert_eq!(
                nat.original_endpoint(
                    protocol,
                    LocalEndpoint {
                        address: other_family,
                        port
                    },
                    now
                ),
                None
            );
            assert!(
                PortReservation::bind(tcp, mapped.address, port).is_none(),
                "a direct stub client cannot bind an active redirect alias"
            );
            let wildcard = if client.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            };
            let wildcard_bound = if tcp {
                TcpListener::bind((wildcard, port)).is_ok()
            } else {
                UdpSocket::bind((wildcard, port)).is_ok()
            };
            assert!(
                !wildcard_bound,
                "a wildcard-bound direct stub client must not inherit a redirect origin"
            );
            let competing = Socket::new(
                if client.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                },
                if tcp { Type::STREAM } else { Type::DGRAM },
                None,
            )
            .expect("competing socket");
            competing.set_reuse_address(true).expect("enable reuse");
            assert!(
                competing
                    .bind(&SocketAddr::new(mapped.address, port).into())
                    .is_err(),
                "SO_REUSEADDR cannot claim an active redirect alias"
            );
            assert_eq!(
                nat.original_endpoint(protocol, mapped, now + NAT_RETENTION),
                None
            );
            assert!(
                PortReservation::bind(tcp, mapped.address, port).is_some(),
                "an expired alias must release its socket reservation"
            );
        }
    }
}

#[test]
fn redirect_alias_does_not_claim_an_existing_wildcard_client_port() {
    let client = UdpSocket::bind("0.0.0.0:0").expect("bind direct stub client");
    let client_port = client.local_addr().expect("client port").port();
    let mut nat = NatTable::with_next_port(client_port);
    let port = nat
        .map_query(
            OriginalKey {
                tcp: false,
                client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                port: 50_000,
                server: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            },
            1,
            0,
            Instant::now(),
        )
        .expect("reserve alias");
    assert_ne!(
        port, client_port,
        "a redirect alias must not steal a live direct client's source port"
    );
}

#[test]
#[ignore = "reads live Windows socket owners and binds an adapter socket; run elevated"]
fn redirected_udp_query_retains_the_real_socket_owner() {
    use netmetrics_core::{LocalEndpoint, Protocol};
    use std::net::UdpSocket;

    let _guard = DIVERT_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);

    // UDP connect chooses a route without sending traffic. Bind explicitly to
    // that adapter: a wildcard bind would hide the address lost by redirection.
    let route = UdpSocket::bind("0.0.0.0:0").expect("bind route probe");
    route
        .connect("192.0.2.1:53")
        .expect("choose an IPv4 adapter route");
    let IpAddr::V4(adapter) = route.local_addr().expect("routed local endpoint").ip() else {
        panic!("route probe did not choose IPv4");
    };
    assert!(!adapter.is_loopback() && !adapter.is_unspecified());
    drop(route);
    let client = UdpSocket::bind((adapter, 0)).expect("bind real adapter DNS client");
    let original = client.local_addr().expect("client endpoint");
    let owners = crate::owner_module::socket_owner_snapshot();
    let original_owner = owners.local_endpoint_owner(
        Protocol::Udp,
        LocalEndpoint {
            address: original.ip(),
            port: original.port(),
        },
    );
    assert_eq!(
        original_owner,
        netmetrics_core::Ownership::Resolved(std::process::id()),
        "the real Windows endpoint table must prove ownership before redirecting"
    );

    // Choose a currently unowned alias so an unrelated loopback socket cannot
    // accidentally satisfy the assertion intended for this adapter socket.
    let alias_port = (49_152..=u16::MAX)
        .find(|&port| {
            owners.local_endpoint_owner(
                Protocol::Udp,
                LocalEndpoint {
                    address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port,
                },
            ) == netmetrics_core::Ownership::NotFound
        })
        .expect("an unused redirected source port");
    *active_nat().lock().expect("active NAT") = Some(NatTable::with_next_port(alias_port));
    let _cleanup = TestNat;
    let mut query = udp_query();
    query[12..16].copy_from_slice(&adapter.octets());
    query[20..22].copy_from_slice(&original.port().to_be_bytes());
    let mut addr = address(true, false, 1);
    // PID 0 cannot own the client: exercise the foreign-client redirect path.
    assert_eq!(
        handle_packet(&mut query, &mut addr, 0, Instant::now()),
        Verdict::Rewritten
    );
    let redirected = PacketView::parse(&query).expect("redirected UDP packet");
    assert_eq!(redirected.src, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mapped_endpoint = LocalEndpoint {
        address: redirected.src,
        port: redirected.src_port,
    };
    let recovered_endpoint = original_endpoint(Protocol::Udp, mapped_endpoint)
        .expect("redirected query has an original socket endpoint");
    assert_eq!(
        recovered_endpoint,
        LocalEndpoint {
            address: original.ip(),
            port: original.port()
        }
    );
    let owners_after_redirect = crate::owner_module::socket_owner_snapshot();
    let redirected_owner =
        owners_after_redirect.local_endpoint_owner(Protocol::Udp, recovered_endpoint);
    eprintln!(
        "DNS redirect attribution: original={original} owner={original_owner:?}, \
         rewritten={}:{} owner={redirected_owner:?}",
        redirected.src, redirected.src_port
    );
    assert_eq!(
        redirected_owner, original_owner,
        "the proxy must recover the real caller from the rewritten source endpoint"
    );
}

#[test]
#[ignore = "opens the WinDivert driver and binds the local DNS port; run elevated"]
fn live_bypassed_udp_query_reaches_stub_and_reply_keeps_original_resolver() {
    use std::net::UdpSocket;
    use std::process::Command;

    let _guard = DIVERT_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);

    let _windivert = crate::windivert_opt_in::testing::allowed();
    let stub = UdpSocket::bind("127.0.0.1:53").expect("bind test DNS stub");
    stub.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set stub timeout");
    let mut divert = install(Box::new(|_| {})).expect("install DNS divert");
    assert!(
        install(Box::new(|_| {})).is_err(),
        "a second redirect cannot replace the live attribution table"
    );

    // A separate process is required: the divert exempts its own sockets.
    let script = "$ErrorActionPreference='Stop'; $u=[Net.Sockets.UdpClient]::new(0); $u.Client.ReceiveTimeout=5000; \
        $q=[byte[]](18,52,0,0,0,0,0,0,0,0,0,0); \
        [void]$u.Send($q,$q.Length,'8.8.8.8',53); \
        $r=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0); \
        $a=$u.Receive([ref]$r); \
        if($r.Address.ToString() -ne '8.8.8.8' -or $a[2] -ne 129){exit 2}";
    let child = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .spawn()
        .expect("start external DNS client");

    let mut query = [0u8; 512];
    let deadline = Instant::now() + Duration::from_secs(5);
    let (len, peer) = loop {
        let (len, peer) = stub.recv_from(&mut query).expect("diverted query at stub");
        if len >= 12 && query[..2] == [18, 52] {
            break (len, peer);
        }
        assert!(Instant::now() < deadline, "test query did not reach stub");
    };
    let origin = original_endpoint(
        Protocol::Udp,
        LocalEndpoint {
            address: peer.ip(),
            port: peer.port(),
        },
    )
    .expect("divert preserves the DNS client's original endpoint");
    let owner =
        crate::owner_module::socket_owner_snapshot().local_endpoint_owner(Protocol::Udp, origin);
    assert_eq!(
        owner,
        netmetrics_core::Ownership::Resolved(child.id()),
        "the stub must attribute the query to the external client, not this process's alias reservation"
    );
    query[2] = 129;
    query[3] = 128;
    stub.send_to(&query[..len], peer).expect("send test reply");
    assert!(
        child
            .wait_with_output()
            .expect("DNS client result")
            .status
            .success()
    );
    divert.disable();
    assert!(active_nat().lock().expect("active NAT").is_none());
    let replacement =
        install(Box::new(|_| {})).expect("reinstall while disabled handle is retained");
    drop(divert);
    assert!(active_nat().lock().expect("active NAT").is_some());
    drop(replacement);
}

#[test]
#[ignore = "opens the WinDivert driver and binds the local DNS port; run elevated"]
fn live_bypassed_tcp_query_reaches_stub_and_reply_keeps_original_resolver() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::process::Command;

    let _guard = DIVERT_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);

    let _windivert = crate::windivert_opt_in::testing::allowed();
    let stub = TcpListener::bind("127.0.0.1:53").expect("bind test DNS stub");
    stub.set_nonblocking(true).expect("set accept timeout");
    let _divert = install(Box::new(|_| {})).expect("install DNS divert");
    let script = "$ErrorActionPreference='Stop'; $c=[Net.Sockets.TcpClient]::new(); \
        $c.Connect('8.8.8.8',53); $s=$c.GetStream(); $s.ReadTimeout=5000; \
        $q=[byte[]](0,12,52,86,0,0,0,0,0,0,0,0,0,0); $s.Write($q,0,$q.Length); \
        $a=[byte[]]::new(14); $n=0; while($n -lt 14){$x=$s.Read($a,$n,14-$n); if($x -eq 0){exit 3}; $n+=$x}; \
        if($a[4] -ne 129 -or $c.Client.RemoteEndPoint.Address.ToString() -ne '8.8.8.8'){exit 2}";
    let child = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .spawn()
        .expect("start external DNS client");
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut stream, peer) = loop {
        match stub.accept() {
            Ok(connection) => break connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "test connection did not reach stub"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("accept test connection: {error}"),
        }
    };
    assert!(peer.ip().is_loopback());
    stream.set_nonblocking(false).expect("make stream blocking");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set query timeout");
    let mut query = [0u8; 14];
    stream
        .read_exact(&mut query)
        .expect("read DNS over TCP query");
    assert_eq!(&query[2..4], &[52, 86]);
    let origin = original_endpoint(
        Protocol::Tcp,
        LocalEndpoint {
            address: peer.ip(),
            port: peer.port(),
        },
    )
    .expect("divert preserves the TCP client's original endpoint");
    let owner =
        crate::owner_module::socket_owner_snapshot().local_endpoint_owner(Protocol::Tcp, origin);
    assert_eq!(
        owner,
        netmetrics_core::Ownership::Resolved(child.id()),
        "the stub must attribute the TCP query to the external client"
    );
    query[4] = 129;
    query[5] = 128;
    stream.write_all(&query).expect("send DNS over TCP reply");
    assert!(
        child
            .wait_with_output()
            .expect("DNS client result")
            .status
            .success()
    );
}
