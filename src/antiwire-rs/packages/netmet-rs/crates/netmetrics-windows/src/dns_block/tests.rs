use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use netmetrics_core::test_support::dns_message;

use super::*;

/// Set for the copy of this test binary that the live test runs. Unset, the helper it runs
/// there does nothing.
const CHILD: &str = "NETMETRICS_TEST_DNS_BLOCK_CHILD";
/// Marks the lines the copy reports with, among the test harness's own.
const REPORT: &str = "dns-block-child ";
/// A documentation address, which nothing answers (RFC 5737).
const NOWHERE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
/// Public resolvers. Windows drops a blocked datagram without telling the sender, so the
/// only sign that UDP is refused is an answer that stops coming.
const RESOLVERS_V4: [IpAddr; 3] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
];
const RESOLVERS_V6: [IpAddr; 2] = [
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
];
/// How Windows refuses a `connect` a filter blocked: `WSAEACCES`.
const REFUSED: &str = "PermissionDenied";
const CONNECTED: &str = "connected";
const ANSWERED: &str = "answered";
const SILENT: &str = "silent";

#[test]
fn the_plan_refuses_each_family_protocol_and_port_and_spares_each_exempt_program() {
    let exempt = vec![b"stub".to_vec(), b"service host".to_vec()];
    let plan = filter_plan(&exempt);

    let blocks: Vec<_> = plan
        .iter()
        .filter(|filter| filter.permitted_app.is_none())
        .collect();
    assert_eq!(blocks.len(), 8, "two families, two protocols, two ports");
    for family in [Family::V4, Family::V6] {
        for protocol in [TCP, UDP] {
            for port in [53, 853] {
                let block = FilterSpec {
                    family,
                    protocol,
                    port,
                    permitted_app: None,
                };
                assert!(plan.contains(&block), "{block:?}");
                for app in &exempt {
                    let permit = FilterSpec {
                        permitted_app: Some(app.as_slice()),
                        ..block
                    };
                    assert!(plan.contains(&permit), "{permit:?}");
                }
            }
        }
    }
    assert_eq!(plan.len(), 24, "nothing else");
}

/// With nobody exempt the stub could not reach its own upstream, so the plan is never
/// built that way; this only shows the blocks do not depend on the permits.
#[test]
fn the_plan_without_exempt_programs_is_the_blocks_alone() {
    let plan = filter_plan(&[]);
    assert_eq!(plan.len(), 8);
    assert!(plan.iter().all(|filter| filter.permitted_app.is_none()));
}

#[test]
fn windows_names_this_program_and_the_service_host() {
    let exempt = exempt_programs().expect("exempt programs");
    assert_eq!(exempt.len(), 2);
    assert!(exempt.iter().all(|id| !id.is_empty()));
    assert_ne!(exempt[0], exempt[1]);

    let service_host = system_directory()
        .expect("system directory")
        .join(SERVICE_HOST);
    assert!(service_host.is_file(), "{}", service_host.display());
}

#[test]
fn a_program_that_does_not_exist_has_no_id() {
    let missing = std::env::temp_dir().join("netmetrics-no-such-program.exe");
    let error = wfp::app_id(&missing).expect_err("a missing file");
    assert!(error.contains("FwpmGetAppIdFromFileName0"), "{error}");
}

/// Anyone may open a session; only an Administrator may write through it. Either way this
/// adds no filter, and what an Administrator's run adds, an empty sublayer, goes with the
/// session.
#[test]
fn a_session_writes_nothing_without_administrator_and_knows_no_stray_filter() {
    let engine = wfp::Engine::open().expect("open a session");
    match engine.add(&[]) {
        Ok(filters) => assert!(filters.is_empty()),
        Err(error) => assert!(error.contains("failed with status"), "{error}"),
    }
    assert!(engine.filter_is_there(u64::MAX).is_err());
}

/// Asks `resolvers` for a name that says nothing about this host, over UDP, and says whether
/// one of them answered.
fn udp_outcome(resolvers: &[IpAddr]) -> &'static str {
    const ID: u16 = 0x4e4d;
    let query = dns_message(ID, "example.com", None, 0);
    let answered = |resolver: &IpAddr| {
        let unspecified: IpAddr = match resolver {
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        let Ok(socket) = UdpSocket::bind((unspecified, 0)) else {
            return false;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(1)));
        if socket.send_to(&query, (*resolver, 53)).is_err() {
            return false;
        }
        let mut answer = [0_u8; 512];
        matches!(
            socket.recv_from(&mut answer),
            Ok((length, from))
                if from.ip() == *resolver && length >= 12 && answer[..2] == ID.to_be_bytes()
        )
    };
    if resolvers.iter().any(answered) {
        ANSWERED
    } else {
        SILENT
    }
}

fn tcp_outcome(target: IpAddr, port: u16) -> String {
    match TcpStream::connect_timeout(&SocketAddr::new(target, port), Duration::from_secs(1)) {
        Ok(_) => CONNECTED.to_owned(),
        Err(error) => format!("{:?}", error.kind()),
    }
}

/// Run by the copy of this test binary, which is not an exempt program: says how each kind
/// of traffic it tried fared.
#[test]
fn child_reports_how_its_dns_fared() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    let attempts = [
        ("udp", udp_outcome(&RESOLVERS_V4).to_owned()),
        ("udp6", udp_outcome(&RESOLVERS_V6).to_owned()),
        ("tcp", tcp_outcome(NOWHERE, 53)),
        ("tcp853", tcp_outcome(NOWHERE, 853)),
        ("other-port", tcp_outcome(NOWHERE, 80)),
        ("loopback", tcp_outcome(Ipv4Addr::LOCALHOST.into(), 53)),
    ];
    for (attempt, fared) in attempts {
        println!("{REPORT}{attempt}={fared}");
    }
}

/// Runs `copy`, a copy of this test binary, and returns what it reported.
fn child_report(copy: &Path) -> BTreeMap<String, String> {
    let output = Command::new(copy)
        .args([
            "--exact",
            "dns_block::tests::child_reports_how_its_dns_fared",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .expect("run the copy");
    assert!(output.status.success(), "the copy failed: {output:?}");
    let report: BTreeMap<String, String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().strip_prefix(REPORT)?.split_once('='))
        .map(|(attempt, fared)| (attempt.to_owned(), fared.to_owned()))
        .collect();
    assert_eq!(report.len(), 6, "the copy reported {report:?}");
    report
}

/// The block refuses another program's DNS to ports 53 and 853, leaves its other traffic
/// and loopback alone, lets this program through, and is gone once dropped.
///
/// The other program is a copy of this test binary under another name, which makes it
/// another program to WFP. While the block is up, every program on this host but the
/// system resolver has its direct DNS refused, for the few seconds this takes.
///
/// It needs the network: a public resolver must answer over UDP before the block, so that
/// its silence under the block means something. UDP to port 853 is refused by the same
/// filters with another port number, and has no answer to miss, so it is not exercised.
#[test]
#[ignore = "adds Windows Filtering Platform filters, which needs Administrator; asks public DNS resolvers"]
fn live_block_refuses_another_programs_dns_and_spares_this_one() {
    let copy = std::env::temp_dir().join(format!(
        "netmetrics-dns-block-child-{}.exe",
        std::process::id()
    ));
    std::fs::copy(std::env::current_exe().expect("this binary"), &copy).expect("copy");

    let before = child_report(&copy);
    assert!(
        before.values().all(|fared| fared != REFUSED),
        "something already refuses DNS here: {before:?}"
    );
    assert_eq!(
        before["udp"], ANSWERED,
        "no public resolver answers over UDP here, so a block could not be told: {before:?}"
    );

    let (tell, told) = std::sync::mpsc::channel();
    let block = install(Box::new(move |event| {
        let _ = tell.send(event);
    }))
    .expect("install the block");

    let during = child_report(&copy);
    assert_eq!(during["udp"], SILENT, "{during:?}");
    if before["udp6"] == ANSWERED {
        assert_eq!(during["udp6"], SILENT, "{during:?}");
    } else {
        eprintln!("no IPv6 resolver answers here: the IPv6 block was not exercised");
    }
    assert_eq!(during["tcp"], REFUSED, "{during:?}");
    assert_eq!(during["tcp853"], REFUSED, "{during:?}");
    assert_eq!(during["other-port"], before["other-port"], "{during:?}");
    assert_eq!(during["loopback"], before["loopback"], "{during:?}");
    // This program is exempt, as the stub is: that is its way upstream.
    assert_eq!(udp_outcome(&RESOLVERS_V4), ANSWERED);
    assert_ne!(tcp_outcome(NOWHERE, 53), REFUSED);

    drop(block);
    let events: Vec<_> = told.try_iter().collect();
    assert!(events.is_empty(), "the block was lost: {events:?}");
    let after = child_report(&copy);
    assert_eq!(after, before, "the block outlived its owner");

    let _ = std::fs::remove_file(&copy);
}
