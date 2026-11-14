//! The port-53 divert on the real host, started as root through the public API.
//!
//! A copy of this test binary, run as an unprivileged user, sends DNS to a documentation
//! address that nothing answers (RFC 5737, RFC 3849). The divert must deliver it to a listener
//! this test binds where the stub listens, show that listener the child's own source port, and
//! bring the listener's answer back to the child as if from the address it asked. Root's queries
//! must pass untouched, port 853 must be closed to the child, and dropping the divert must
//! remove every rule it installed.
//!
//! A query takes the divert only when it can leave the host, so IPv6 is exercised end to end
//! only where this host has an IPv6 route; without one the test says so. The IPv6 port-853 rule
//! is checked over loopback either way, and the rule listing must show the IPv6 rules loaded.
//!
//! While the divert is up, other processes that are not root, such as the system resolver, have
//! their DNS diverted to the listener too. The listener ignores every query but this test's.
//!
//! Another tool that deletes or empties the divert's own table or anchor, as a firewall manager
//! reloading would, must see it put back within a check interval, and the owner must hear of
//! both. Nothing may put it back once the divert is dropped.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use netmetrics::dns_divert::{self, DIVERT_CHECK_INTERVAL, DivertEvent, DnsDivert};
use netmetrics_core::test_support::{dns_message, dns_over_tcp};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

/// Where a child of this test binary sends; unset, the child helpers do nothing.
const CHILD_TARGET: &str = "NETMETRICS_TEST_DIVERT_TARGET";
/// The user and group the child runs as. Any ID but 0 is unprivileged, and neither platform
/// needs an account for it.
const UNPRIVILEGED: u32 = 65_534;
/// The name every query of this test asks for, which tells them from other processes' DNS.
const NAME: &str = "divert.netmetrics.test";
const DNS: u16 = 53;
const DNS_OVER_TLS: u16 = 853;
/// How long anything expected may take.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to watch for something that must not happen.
const QUIET: Duration = Duration::from_millis(1500);
/// Longest a child may run: a connection attempt and an answer, with room to start.
const CHILD_LIMIT: Duration = Duration::from_secs(20);

/// A word that only the divert's IPv6 rules are listed with.
#[cfg(target_os = "macos")]
const IPV6_RULE: &str = "inet6";
#[cfg(target_os = "linux")]
const IPV6_RULE: &str = "ip6 daddr";

#[derive(Clone, Copy)]
struct Family {
    /// Where the stub listens.
    loopback: IpAddr,
    /// A documentation address nothing answers.
    nowhere: IpAddr,
    unspecified: IpAddr,
}

const IPV4: Family = Family {
    loopback: IpAddr::V4(Ipv4Addr::LOCALHOST),
    nowhere: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
    unspecified: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
};

const IPV6: Family = Family {
    loopback: IpAddr::V6(Ipv6Addr::LOCALHOST),
    nowhere: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    unspecified: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
};

/// The families whose queries to the documentation address can leave this host, and so take
/// the divert. IPv4 must; many hosts, CI runners among them, have no IPv6 route.
fn routed_families() -> Vec<Family> {
    let routed = |family: Family| {
        UdpSocket::bind(SocketAddr::new(family.unspecified, 0))
            .and_then(|socket| socket.connect(SocketAddr::new(family.nowhere, DNS)))
    };
    if let Err(error) = routed(IPV4) {
        panic!("this test needs an IPv4 route to {}: {error}", IPV4.nowhere);
    }
    match routed(IPV6) {
        Ok(()) => vec![IPV4, IPV6],
        Err(error) => {
            eprintln!(
                "IPv6 queries are not diverted end to end here: no route to {} ({error})",
                IPV6.nowhere
            );
            vec![IPV4]
        }
    }
}

fn start_divert() -> DnsDivert {
    dns_divert::start(|event| eprintln!("divert: {event:?}")).expect("start the divert")
}

/// Starts the divert, and hands the test every event it reports.
fn start_reporting_divert() -> (DnsDivert, Receiver<DivertEvent>) {
    let (sender, events) = mpsc::channel();
    let divert = dns_divert::start(move |event| {
        eprintln!("divert: {event:?}");
        let _ = sender.send(event);
    })
    .expect("start the divert");
    (divert, events)
}

/// Longest a removal may go unnoticed, and then unrepaired: a check interval, and room for the
/// check or the repair, whose commands are each bounded by a timeout.
fn repair_bound() -> Duration {
    DIVERT_CHECK_INTERVAL + Duration::from_secs(10)
}

/// Removes whatever divert is left when it drops, for a test that drops its divert early and
/// then may fail before the end.
struct ClearLeftover;

impl Drop for ClearLeftover {
    fn drop(&mut self) {
        dns_divert::clear_leftover();
    }
}

/// A query for [`NAME`] whose ID is `id`.
fn query(id: u16) -> Vec<u8> {
    dns_message(id, NAME, None, 0)
}

/// The ID of a message that asks about [`NAME`], or `None` for any other message.
fn our_id(message: &[u8]) -> Option<u16> {
    // The question follows the 12-byte header, whose first two bytes are the ID.
    if message.get(12..) != query(0).get(12..) {
        return None;
    }
    message.first_chunk().map(|id| u16::from_be_bytes(*id))
}

fn read_framed(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut length = [0; 2];
    stream.read_exact(&mut length)?;
    let mut message = vec![0; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut message)?;
    Ok(message)
}

/// Asks over UDP with the socket's own port as the query ID, and waits for the answer.
fn ask_over_udp(target: SocketAddr) {
    let socket = UdpSocket::bind(SocketAddr::new(unspecified(target), 0)).expect("bind");
    // A connected socket takes datagrams from `target` only, so getting the answer shows it
    // came back from the address asked.
    socket.connect(target).expect("connect");
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("read timeout");
    let id = socket.local_addr().expect("local address").port();
    socket.send(&query(id)).expect("send the query");
    let mut answer = [0; 512];
    let length = socket.recv(&mut answer).expect("the answer");
    assert_eq!(our_id(&answer[..length]), Some(id), "a different answer");
}

/// Asks over TCP with the connection's own port as the query ID, and waits for the answer.
fn ask_over_tcp(target: SocketAddr) {
    let mut stream = TcpStream::connect_timeout(&target, IO_TIMEOUT).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("read timeout");
    let id = stream.local_addr().expect("local address").port();
    stream
        .write_all(&dns_over_tcp(&query(id)))
        .expect("send the query");
    let answer = read_framed(&mut stream).expect("the answer");
    assert_eq!(our_id(&answer), Some(id), "a different answer");
}

/// Sends a query over UDP and does not wait for anything.
fn try_udp(target: SocketAddr) {
    if let Ok(socket) = UdpSocket::bind(SocketAddr::new(unspecified(target), 0)) {
        let _ = socket.send_to(&query(0), target);
    }
}

/// Sends a query over TCP if a connection opens, and does not wait for an answer.
fn try_tcp(target: SocketAddr) {
    if let Ok(mut stream) = TcpStream::connect_timeout(&target, QUIET) {
        let _ = stream.write_all(&dns_over_tcp(&query(0)));
    }
}

fn unspecified(target: SocketAddr) -> IpAddr {
    match target {
        SocketAddr::V4(_) => IPV4.unspecified,
        SocketAddr::V6(_) => IPV6.unspecified,
    }
}

fn child_target() -> Option<SocketAddr> {
    let target = std::env::var(CHILD_TARGET).ok()?;
    Some(target.parse().expect("child target"))
}

/// A helper the divert tests run in an unprivileged child. Otherwise it does nothing.
#[test]
#[ignore = "a helper the divert tests run in an unprivileged child process"]
fn child_asks_over_udp() {
    if let Some(target) = child_target() {
        ask_over_udp(target);
    }
}

/// A helper the divert tests run in an unprivileged child. Otherwise it does nothing.
#[test]
#[ignore = "a helper the divert tests run in an unprivileged child process"]
fn child_asks_over_tcp() {
    if let Some(target) = child_target() {
        ask_over_tcp(target);
    }
}

/// A helper the divert tests run in an unprivileged child. Otherwise it does nothing.
#[test]
#[ignore = "a helper the divert tests run in an unprivileged child process"]
fn child_tries_udp() {
    if let Some(target) = child_target() {
        try_udp(target);
    }
}

/// A helper the divert tests run in an unprivileged child. Otherwise it does nothing.
#[test]
#[ignore = "a helper the divert tests run in an unprivileged child process"]
fn child_tries_tcp() {
    if let Some(target) = child_target() {
        try_tcp(target);
    }
}

/// A copy of this test binary that the unprivileged user can run. The original sits under the
/// building user's home, which other users may not be allowed to enter. `/tmp` is open to every
/// user on both platforms, where root's `TMPDIR` may not be.
struct ChildBinary {
    directory: PathBuf,
    path: PathBuf,
}

impl ChildBinary {
    fn copy() -> Self {
        let directory = PathBuf::from(format!(
            "/tmp/netmetrics-divert-test-{}",
            std::process::id()
        ));
        // A run that was killed may have left one behind under the same process ID.
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).expect("create the child's directory");
        let copy = Self {
            path: directory.join("child"),
            directory,
        };
        fs::set_permissions(&copy.directory, fs::Permissions::from_mode(0o755))
            .expect("open the child's directory");
        fs::copy(
            std::env::current_exe().expect("this test binary"),
            &copy.path,
        )
        .expect("copy this test binary");
        fs::set_permissions(&copy.path, fs::Permissions::from_mode(0o755))
            .expect("make the copy runnable");
        copy
    }

    /// Runs the child helper `helper` against `target` as the unprivileged user.
    fn start(&self, helper: &str, target: SocketAddr) -> RunningChild {
        let child = Command::new(&self.path)
            .args(["--ignored", "--exact", helper, "--test-threads=1"])
            .env(CHILD_TARGET, target.to_string())
            .current_dir("/")
            .gid(UNPRIVILEGED)
            .uid(UNPRIVILEGED)
            .spawn()
            .expect("start the unprivileged child");
        RunningChild(child)
    }

    /// Runs the child helper `helper` against `target` and waits for it to finish.
    fn run(&self, helper: &str, target: SocketAddr) {
        self.start(helper, target).finish(helper);
    }
}

impl Drop for ChildBinary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// A child that is killed if the test fails before it is waited for.
struct RunningChild(Child);

impl RunningChild {
    /// Waits for the child and fails unless it succeeded.
    fn finish(mut self, helper: &str) {
        let deadline = Instant::now() + CHILD_LIMIT;
        loop {
            if let Some(status) = self.0.try_wait().expect("child status") {
                assert!(
                    status.success(),
                    "the unprivileged {helper} failed: {status}"
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the unprivileged {helper} did not finish"
            );
            thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for RunningChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// UDP and TCP sockets on the stub's port, or on another port of loopback.
struct StubListener {
    udp: UdpSocket,
    tcp: TcpListener,
}

impl StubListener {
    fn bind(address: IpAddr, port: u16) -> Self {
        let at = SocketAddr::new(address, port);
        let tcp =
            TcpListener::bind(at).unwrap_or_else(|error| panic!("listen on TCP {at}: {error}"));
        tcp.set_nonblocking(true).expect("non-blocking accept");
        Self {
            udp: UdpSocket::bind(at).unwrap_or_else(|error| panic!("bind UDP {at}: {error}")),
            tcp,
        }
    }

    /// The next query of this test to arrive over UDP within `within`, and who sent it.
    fn next_udp(&self, within: Duration) -> Option<(u16, SocketAddr)> {
        let deadline = Instant::now() + within;
        let mut buffer = [0; 512];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            self.udp.set_read_timeout(Some(left)).expect("read timeout");
            match self.udp.recv_from(&mut buffer) {
                Ok((length, sender)) => {
                    if let Some(id) = our_id(&buffer[..length]) {
                        return Some((id, sender));
                    }
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    return None;
                }
                Err(error) => panic!("receive: {error}"),
            }
        }
    }

    /// The next connection to send a query of this test within `within`, that query's ID, and
    /// who connected.
    fn next_tcp(&self, within: Duration) -> Option<(TcpStream, u16, SocketAddr)> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            match self.tcp.accept() {
                Ok((mut stream, peer)) => {
                    // An accepted socket inherits non-blocking mode on macOS but not on Linux.
                    stream.set_nonblocking(false).expect("blocking stream");
                    stream
                        .set_read_timeout(Some(IO_TIMEOUT))
                        .expect("read timeout");
                    if let Some(id) = read_framed(&mut stream).ok().as_deref().and_then(our_id) {
                        return Some((stream, id, peer));
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept: {error}"),
            }
        }
        None
    }

    /// Answers the query of this test that arrives over UDP, after checking that its ID, the
    /// asker's own port, is the port it came from.
    fn answer_udp(&self, target: SocketAddr) {
        let (id, asker) = self.next_udp(IO_TIMEOUT).unwrap_or_else(|| {
            panic!(
                "the unprivileged UDP query to {target} did not reach the stub\n{}",
                packet_filter_state()
            )
        });
        assert_eq!(
            id,
            asker.port(),
            "the stub saw the UDP query to {target} come from {asker}, not the child's own port"
        );
        self.udp
            .send_to(&dns_message(id, NAME, Some(0), 0), asker)
            .expect("send the answer");
    }

    /// Answers the query of this test that arrives over TCP, after the same check.
    fn answer_tcp(&self, target: SocketAddr) {
        let (mut stream, id, asker) = self.next_tcp(IO_TIMEOUT).unwrap_or_else(|| {
            panic!(
                "the unprivileged TCP query to {target} did not reach the stub\n{}",
                packet_filter_state()
            )
        });
        assert_eq!(
            id,
            asker.port(),
            "the stub saw the TCP query to {target} come from {asker}, not the child's own port"
        );
        stream
            .write_all(&dns_over_tcp(&dns_message(id, NAME, Some(0), 0)))
            .expect("send the answer");
    }

    /// Whether a query of this test arrives, over UDP or TCP, before [`QUIET`] passes.
    fn hears_a_query(&self) -> bool {
        self.next_udp(QUIET).is_some() || self.next_tcp(QUIET).is_some()
    }
}

/// What the packet filter says about the divert now, for the message of a test whose query
/// went astray: each of the divert's rules with how many packets it has matched
/// (`pfctl -v`), pf's states, and its counters, which name the reason for each packet it
/// dropped (`pfctl(8)`).
#[cfg(target_os = "macos")]
fn packet_filter_state() -> String {
    let anchor = netmetrics_core::MACOS_DNS_DIVERT_ANCHOR;
    [
        vec!["-a", anchor, "-v", "-sn"],
        vec!["-a", anchor, "-v", "-sr"],
        vec!["-s", "state"],
        vec!["-s", "info"],
    ]
    .into_iter()
    .map(|args| {
        let printed = match Command::new("/sbin/pfctl").args(&args).output() {
            Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
            Err(error) => format!("could not run: {error}"),
        };
        format!("$ pfctl {}\n{printed}", args.join(" "))
    })
    .collect::<Vec<_>>()
    .join("\n")
}

/// What the packet filter says about the divert now, for the message of a test whose query
/// went astray: the divert's table as nft lists it.
#[cfg(target_os = "linux")]
fn packet_filter_state() -> String {
    format!("$ nft list table\n{}", rules_in_place())
}

/// The divert's rules as the host lists them now; empty when there are none.
#[cfg(target_os = "macos")]
fn rules_in_place() -> String {
    ["-sn", "-sr"]
        .into_iter()
        .filter_map(|show| {
            let output = Command::new("/sbin/pfctl")
                .args(["-a", netmetrics_core::MACOS_DNS_DIVERT_ANCHOR, show])
                .output()
                .expect("run pfctl");
            // pf may delete a flushed anchor, and pfctl then fails to list it.
            output
                .status
                .success()
                .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
        })
        .collect()
}

/// The divert's rules as the host lists them now; empty when there are none.
#[cfg(target_os = "linux")]
fn rules_in_place() -> String {
    let output = Command::new(nft())
        .args(netmetrics_core::linux_dns_divert_list_args())
        .output()
        .expect("run nft");
    // Dropping the divert deletes its table, and nft then fails to list it.
    if output.status.success() {
        String::from_utf8_lossy(&output.stdout).into_owned()
    } else {
        String::new()
    }
}

/// The installed `nft`.
#[cfg(target_os = "linux")]
fn nft() -> &'static str {
    netmetrics_core::LINUX_NFT_PATHS
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .expect("nft is installed")
}

/// How another tool takes the divert away. Each touches the divert's own table or anchor and
/// nothing else, so the host's other firewall rules are left alone.
#[derive(Clone, Copy, Debug)]
enum Removal {
    /// Deletes it.
    Delete,
    /// Leaves it in place, without the rules that divert anything.
    Empty,
}

/// Removes the divert's rules as another tool would: `nft delete table`, or `nft flush table`,
/// which leaves the table and its chains in place, hooked and empty.
#[cfg(target_os = "linux")]
fn remove_as_another_tool(removal: Removal) {
    let [_, table @ ..] = netmetrics_core::linux_dns_divert_disable_args();
    let verb = match removal {
        Removal::Delete => "delete",
        Removal::Empty => "flush",
    };
    let status = Command::new(nft())
        .arg(verb)
        .args(table)
        .status()
        .expect("run nft");
    assert!(status.success(), "nft {verb} table failed: {status}");
}

/// Removes the divert's rules as another tool would: `pfctl -a <anchor> -F all`, after which pf
/// deletes the empty anchor, or `-F rules`, which leaves the anchor holding only its `rdr`
/// rules, and no query reaches them without the filter rules that route it to `lo0`.
#[cfg(target_os = "macos")]
fn remove_as_another_tool(removal: Removal) {
    let what = match removal {
        Removal::Delete => "all",
        Removal::Empty => "rules",
    };
    let status = Command::new("/sbin/pfctl")
        .args(["-a", netmetrics_core::MACOS_DNS_DIVERT_ANCHOR, "-F", what])
        .status()
        .expect("run pfctl");
    assert!(status.success(), "pfctl -F {what} failed: {status}");
}

/// While the divert runs, another tool removes its rules by `removal`. The divert reports the
/// loss and then the restoration, each within [`repair_bound`], the same rules are listed
/// again, and an unprivileged query is diverted again.
fn removed_rules_are_put_back(removal: Removal) {
    let families = routed_families();
    let child = ChildBinary::copy();
    let _clear = ClearLeftover;
    let (_divert, events) = start_reporting_divert();
    let installed = rules_in_place();
    assert!(
        installed.contains(IPV6_RULE),
        "the divert's rules are not all listed:\n{installed}"
    );

    remove_as_another_tool(removal);

    let bound = repair_bound();
    match events.recv_timeout(bound) {
        Ok(DivertEvent::Lost(why)) => eprintln!("lost ({removal:?}): {why}"),
        other => panic!("the {removal:?} removal was not reported within {bound:?}: {other:?}"),
    }
    assert_eq!(
        events.recv_timeout(bound),
        Ok(DivertEvent::Restored),
        "the divert was not restored within {bound:?} of reporting the loss"
    );
    assert_eq!(
        rules_in_place(),
        installed,
        "the rules put back differ from the ones installed"
    );
    for family in families {
        let stub = StubListener::bind(family.loopback, DNS);
        let target = SocketAddr::new(family.nowhere, DNS);
        let asking = child.start("child_asks_over_udp", target);
        stub.answer_udp(target);
        asking.finish("child_asks_over_udp");
    }
}

#[test]
#[ignore = "requires root; installs the port-53 divert, deletes it, and binds port 53 on loopback"]
fn elevated_deleted_rules_are_put_back() {
    removed_rules_are_put_back(Removal::Delete);
}

#[test]
#[ignore = "requires root; installs the port-53 divert, empties it, and binds port 53 on loopback"]
fn elevated_emptied_rules_are_put_back() {
    removed_rules_are_put_back(Removal::Empty);
}

/// Dropped while it is putting its rules back, the divert leaves them removed, and nothing puts
/// them back for longer than a check interval after.
#[test]
#[ignore = "requires root; installs the port-53 divert and deletes it"]
fn elevated_a_divert_dropped_during_its_repair_stays_removed() {
    let _clear = ClearLeftover;
    let (divert, events) = start_reporting_divert();
    remove_as_another_tool(Removal::Delete);
    // The repair starts as soon as the loss is reported, so the drop races it.
    let bound = repair_bound();
    assert!(
        matches!(events.recv_timeout(bound), Ok(DivertEvent::Lost(_))),
        "the removal was not reported within {bound:?}"
    );

    drop(divert);

    let deadline = Instant::now() + DIVERT_CHECK_INTERVAL * 2;
    while Instant::now() < deadline {
        let left = rules_in_place();
        assert!(
            left.trim().is_empty(),
            "rules came back after the divert was dropped:\n{left}"
        );
        thread::sleep(Duration::from_millis(250));
    }
}

/// A query a process other than root sends to a resolver elsewhere reaches the stub, with its
/// own source port, and the stub's answer reaches it. `helper` is the child that asks, and
/// `answer` what the stub answers it with.
fn unprivileged_dns_reaches_the_stub(helper: &str, answer: fn(&StubListener, SocketAddr)) {
    let families = routed_families();
    let child = ChildBinary::copy();
    let _divert = start_divert();
    for family in families {
        let stub = StubListener::bind(family.loopback, DNS);
        let target = SocketAddr::new(family.nowhere, DNS);
        let asking = child.start(helper, target);
        answer(&stub, target);
        asking.finish(helper);
    }
}

/// UDP and TCP are tested apart, so that one failing does not hide what the other does.
#[test]
#[ignore = "requires root; installs the port-53 divert and binds port 53 on loopback"]
fn elevated_unprivileged_udp_dns_reaches_the_stub_from_its_own_port() {
    unprivileged_dns_reaches_the_stub("child_asks_over_udp", StubListener::answer_udp);
}

#[test]
#[ignore = "requires root; installs the port-53 divert and binds port 53 on loopback"]
fn elevated_unprivileged_tcp_dns_reaches_the_stub_from_its_own_port() {
    unprivileged_dns_reaches_the_stub("child_asks_over_tcp", StubListener::answer_tcp);
}

/// Root's queries, the stub's own upstream lookups among them, are not diverted.
#[test]
#[ignore = "requires root; installs the port-53 divert and binds port 53 on loopback"]
fn elevated_root_dns_is_not_diverted() {
    let families = routed_families();
    let _divert = start_divert();
    for family in families {
        let stub = StubListener::bind(family.loopback, DNS);
        let target = SocketAddr::new(family.nowhere, DNS);
        try_udp(target);
        try_tcp(target);
        assert!(
            !stub.hears_a_query(),
            "root's query to {target} was diverted to the stub"
        );
    }
}

/// Port 853 is closed to processes other than root, over UDP and TCP, in both families. The
/// rules match every interface, so loopback shows it without a route.
#[test]
#[ignore = "requires root; installs the port-53 divert and binds port 853 on loopback"]
fn elevated_unprivileged_port_853_is_closed() {
    let child = ChildBinary::copy();
    let _divert = start_divert();
    for family in [IPV4, IPV6] {
        let server = StubListener::bind(family.loopback, DNS_OVER_TLS);
        let target = SocketAddr::new(family.loopback, DNS_OVER_TLS);
        child.run("child_tries_udp", target);
        child.run("child_tries_tcp", target);
        assert!(
            !server.hears_a_query(),
            "the unprivileged child reached {target}"
        );
        // Root is let through, which shows the server would have heard the child.
        try_udp(target);
        assert!(
            server.next_udp(IO_TIMEOUT).is_some(),
            "root could not reach UDP {target}"
        );
        try_tcp(target);
        assert!(
            server.next_tcp(IO_TIMEOUT).is_some(),
            "root could not reach TCP {target}"
        );
    }
}

/// Dropping the divert removes every rule it installed, and the host behaves as before.
#[test]
#[ignore = "requires root; installs the port-53 divert and binds ports 53 and 853 on loopback"]
fn elevated_dropping_the_divert_removes_its_rules() {
    let families = routed_families();
    let child = ChildBinary::copy();
    let _clear = ClearLeftover;
    let divert = start_divert();
    let installed = rules_in_place();
    // The IPv6 rules count even where no IPv6 route lets a query take them.
    assert!(
        installed.contains(IPV6_RULE),
        "the divert's rules are not all listed:\n{installed}"
    );
    drop(divert);
    let left = rules_in_place();
    assert!(
        left.trim().is_empty(),
        "rules left after the divert was dropped:\n{left}"
    );

    for family in families {
        let stub = StubListener::bind(family.loopback, DNS);
        let target = SocketAddr::new(family.nowhere, DNS);
        child.run("child_tries_udp", target);
        child.run("child_tries_tcp", target);
        assert!(
            !stub.hears_a_query(),
            "the child's query to {target} was diverted after the divert was dropped"
        );
    }
    let server = StubListener::bind(IPV4.loopback, DNS_OVER_TLS);
    let target = SocketAddr::new(IPV4.loopback, DNS_OVER_TLS);
    let trying = child.start("child_tries_tcp", target);
    assert!(
        server.next_tcp(IO_TIMEOUT).is_some(),
        "{target} stayed closed to the child after the divert was dropped"
    );
    trying.finish("child_tries_tcp");
}
