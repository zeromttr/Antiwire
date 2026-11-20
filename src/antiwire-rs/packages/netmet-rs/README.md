# netmetrics

`netmetrics` is a synchronous Rust library that turns native host network telemetry into one bounded, batched `FlowEvent` stream. It is the flow-accounting package used by Antiwire (`antiwire-flow`). The public crate has no async runtime, packet-capture dependency, `sysinfo`, or database.

Native callbacks only enqueue into a bounded channel. A single collector worker owns the flow and process tables, coalesces byte deltas, and delivers fixed-size batches to a `FlowConsumer`.

The library is meant to run inside a privileged process. Without Administrator / `CAP_BPF` / root, the collector still starts, but it falls back to socket-table snapshots: no per-flow byte totals, and short-lived connections can be missed. Those fallbacks emit `FlowEvent::Degraded` instead of pretending they match the privileged path.

## What it reports

Each flow is a local-host 5-tuple (`tcp`/`udp`, local address/port, remote address/port) plus:

| Observation | Meaning |
| --- | --- |
| Open / close | Socket became visible or ended (or the local UDP bind disappeared) |
| Byte deltas | Incremental sent/received counts for that flow |
| Process | PID, executable path, name, and OS start time |
| Socket cookie | Platform token that splits a recycled 5-tuple from a continuing socket |
| Interface index | Host NIC the flow was observed on, when the backend can name one |
| DNS hints | Best-effort `query → answers` with TTL, keyed by PID when possible |
| Interface counters | Cumulative NIC rx/tx bytes, errors, and drops |

Addresses are reported in one form on every platform (`FlowKey::canonical`). Linux holds the addresses of an IPv6 socket that carries IPv4 as IPv4-mapped IPv6 (`::ffff:a.b.c.d`); such a flow is reported under its IPv4 addresses, so loopback filtering applies to it and one peer has one address. Loopback filtering (`ignore_loopback`, on by default) leaves out every flow that stays on the host (`FlowKey::stays_on_host`): one with a loopback address at either end, and one from an address to itself, whose two sockets are both on this host and share one key. A socket bound to `::` that exchanges IPv4 datagrams is reported as bound to `0.0.0.0`. Socket-table and endpoint-owner lookups accept either form. A socket bound to `::` owns an IPv4 endpoint on its port when no IPv4 socket does, on every platform, because it receives IPv4 unless it set `IPV6_V6ONLY` and the socket tables do not say which sockets did.

`Bytes` events are incremental. Cumulative session totals live on `FlowRecord` / `Collector::snapshot_flows()`. DNS-to-flow attribution is best effort and left to the consumer: with `dns_hints` on, the collector publishes each answer as a `DnsResolvedWithMetadata` event, naming the process that asked when it is known, and keeps none itself. Feed the events to a `DnsHintMap` to name flows.

A `DnsHintMap` retains up to ten distinct domains per PID/IP pair, with an
independent TTL for each name. Repeating a name refreshes it; an eleventh name
evicts the least recently recorded candidate. The configured capacity still
limits PID/IP pairs. Single-domain lookup returns `None` for ambiguous evidence,
including still-valid names discarded by the ten-name cap. At the core API,
`DnsHintMap::resolve_candidates` exposes the retained names and
`DnsHintMap::is_ambiguous` reports whether selecting one would be uncertain.

Point-in-time helpers that do not use the event stream:

- `socket_owner_snapshot()` — TCP 5-tuple and UDP bind owners from the OS table
- `active_connection_count()` — established TCP connections on the host (`ESTABLISHED` or `CLOSE-WAIT`), by one rule on every platform; never listeners, handshakes or UDP sockets

## Architecture

```
platform backend          collector worker              consumer
(ETW / eBPF / PKTAP)  →  bounded ingress  →  flow table  →  FlowEvent batches
                         (non-blocking)      coalescer
                                             process table
                                             DNS hint map
```

Crates in this workspace:

| Crate | Role |
| --- | --- |
| `netmetrics` | Public API: `Collector`, config, snapshots, socket table |
| `netmetrics-core` | Platform-independent types, flow table, DNS cache, coalescer |
| `netmetrics-sys` | Backend trait, `BackendEvent`, ring-buffer wire decoder |
| `netmetrics-windows` | Kernel ETW + IP Helper |
| `netmetrics-linux` | eBPF (Aya) + `/proc` fallback + port-53 DNS sniffer |
| `netmetrics-macos` | PKTAP via BPF, or netstat2 snapshot when PKTAP is unset |

Default Cargo features enable all three OS backends; only the current target is linked. For cross-compilation, disable defaults and enable exactly one of `windows`, `linux`, or `macos`.

This workspace is **edition 2024** / MSRV **1.90**. It is nested under `antiwire-rs` but is not an outer-workspace member. Run `cargo fmt` from this directory, not from `src/antiwire-rs` — formatting the nested crates from the outer edition-2021 workspace will fail their `fmt --check`.

## Platform backends

| Platform | Privileged source | Automatic fallback |
| --- | --- | --- |
| Windows | Kernel TCP/IP + Process ETW; optional DNS-Client ETW; UDP owner-module cookies | IP Helper TCP snapshots (open/close, no per-flow bytes) |
| Linux | CO-RE eBPF ring buffer (TCP/UDP bytes, cookies, close); port-53 capture (UDP and TCP) with socket-table PID | `/proc/net` socket/process/interface snapshots |
| macOS | PKTAP through a non-blocking BPF device (`NETMETRICS_PKTAP_INTERFACE`) | netstat2 TCP snapshot loop |

Degraded modes stay visible through `FlowEvent::Degraded`. They never silently claim byte-accounting parity. Where the privileged source fails at start (Windows, Linux, macOS) or while running (macOS), the backend reports why once, runs its fallback, and tries the privileged source again every 60 seconds; when it is back, `FlowEvent::Restored` names the fallback that ended.

### Windows

Kernel ETW supplies TCP/UDP bytes, opens, closes, and process start/stop (including `CreateTime`). Process-end events keep image identity even when start/rundown was missed, so a PID that only appears as it exits can still be attributed during the process grace window. DNS-Client ETW, when `dns_hints` is on, decodes the request/completion pair (3006/3008/3018/3020) plus the outcome, error, NETBIOS, and resolver-operation events that also carry `ClientPID` and `QueryBlob` (1013-1018, 1022, 1024-1028, 3009-3014, 3016-3023); a completion that carries no `ClientPID` borrows the caller from its matching 3006 request by `ActivityId` or query identifier, so answers are attributed to the querying PID and read real TTLs. Failed and denied lookups therefore still name the requesting process instead of falling back to the system resolver. The owner-module TCP/UDP tables supply socket cookies (`liCreateTimestamp`) and close UDP flows when a bind vanishes. TCP listener rows are retained separately: an inbound connection whose transient 5-tuple is already gone falls back to the PID that owns the local listening port, and that owner never contributes a cookie. UDP byte observations carry the bind cookie from an `ArcSwap` snapshot. When a payload PID is missing, the connection id (`connid`) learned from an earlier event of the same connection is tried first, then the live owner snapshot; if the process has already exited, a recently closed owner retained for 10 seconds can still pin the PID, as long as the event timestamp falls inside that socket's observed lifetime. The connection mapping also carries the owner cookie, so a missed lookup on an otherwise known connection cannot drop its socket identity. Interface index is a first-write routing estimate from `GetBestRoute2` (local and remote addresses), not evidence of the interface that carried a packet.

Needs Administrator (or Performance Log Users for ETW). ETW session names are prefixed `netmetrics` so stale-session recovery cannot stop a foreign trace. A named mutex distinguishes an orphaned session from a live collector.

While kernel ETW cannot start, the backend polls the IP Helper tables, and it tries ETW again every 60 seconds. When ETW starts, the first poll of the owner tables closes each connection the fallback announced that is no longer established: one that ended after the fallback's last poll and before the session started was seen by neither. A session that is lost mid-run restarts the backend, and a connection that ends during that restart is not closed this way.

WinDivert is a third-party kernel driver, and it is off until the application calls `windivert::set_enabled(true)`. Anti-cheat software can treat a loaded packet-capture driver as an integrity violation, so while WinDivert is off nothing is downloaded, loaded or run for it: flow owners come from ETW and the socket tables alone, historical endpoint ownership reports `Unavailable`, and `dns_divert::start` refuses DNS that bypasses the stub where WinDivert would send it there. A running collector follows the switch: turning it on starts the FLOW listener, and turning it off closes the listener and forgets the owners it recorded. Closing the handles does not unload the driver; WinDivert leaves it loaded until the next reboot or `sc stop WinDivert`.

Once turned on, the WinDivert FLOW listener starts on a thread of its own, since its first start downloads the package. A start that fails for a reason that can pass is tried again after 1 second, then after twice as long each time, hourly at most: the download failed, or `WinDivertOpen` failed with an error its manual gives a passing cause for, such as a Base Filtering Engine that is not running yet. A start that fails for a reason that lasts is reported once and not tried again: no Administrator privileges, a package that does not match its pinned hash, or an architecture without a driver. A listener that exits is restarted on the same schedule.

Historical endpoint ownership uses one shared bounded tracker and lookup API on all
three platforms. Windows supplies WinDivert FLOW events once WinDivert is turned on, Linux supplies eBPF owner
records from the connect, accept and send entry probes (plus byte records as extra
history), and macOS supplies PKTAP packet PIDs. Linux needs an object that emits owner
records and both send probes attached; otherwise ownership reports `Unavailable`. Events without a PID
never replace a known owner. Native event timestamps
preserve ownership across delayed delivery and port reuse. History retains up to
four owner changes per endpoint, for 120 seconds since its last event or lookup,
with an 8,192-endpoint bound. Repeated observations of one owner do not consume
history slots. Lookup never backdates a socket-table snapshot. On Linux a TCP
endpoint's history begins when it connects or is accepted and a UDP endpoint's at its
first send; on macOS it begins at the first packet, which for TCP is the SYN. Traffic
not observed by the source cannot establish an owner. Snapshot-only modes return
`Unavailable`.

### Linux

The Aya loader attaches `inet_sock_set_state`, TCP/UDP send/recv probes, `skb_consume_udp`, `tcp_connect`, `inet_csk_accept` and `udp_destroy_sock`. Records are versioned (`NMT1` v1–v3); v3 adds a socket cookie and interface index. The kernel assigns a socket's cookie only when asked, so BTF tracing programs ask: when a TCP socket first changes state and at a UDP socket's first send (Linux 5.12; the UDP ones need an architecture with BPF trampolines). A connection is attributed when it is made, to the process that connected or accepted it, not at its first byte.

Process starts are read from `/proc` the first time a PID uses the network. After that the `sched_process_exec` and `sched_process_exit` tracepoints keep the process current: an exec replaces its identity and an exit stops it at once. An exit record carries the name and start time, so a process that used the network and exited before `/proc` was read is still reported, by name and without its executable path. Without the exit tracepoint, exits are found by checking `/proc` every second. An unconnected UDP socket names its remote end per datagram: a send by the address in its `msghdr`, and a receive by the sender in the datagram's own IP and UDP headers, read where `skb_consume_udp` sees them. UDP destroy becomes `LocalEndpointClosed` so every flow on that bind drains. When the socket is not bound to a device, userspace does a route lookup equivalent to Windows `GetBestInterfaceEx`.

DNS: an AF_PACKET sniffer reads port 53, over UDP and TCP and in both directions, and maps the socket that sent a query to a PID via `/proc` (needs `CAP_NET_RAW`). It sees a query leave for any resolver, not only for a stub on loopback. Only a packet this host sent names its sender. Every lookup is published as a `DnsQuery` event when it is sent and again when it is answered, with the DNS response code as its status, so failed lookups are reported too. Hints with PID 0 are system-wide fallbacks. DNS the host encrypts (DoT, DoH, DoQ) cannot be read from packets.

Build `crates/netmetrics-linux/ebpf/netmetrics.bpf.c` with `ebpf/build.sh` on a Linux host (Clang, bpftool, kernel BTF). Install `netmetrics.bpf.o` at `/usr/lib/netmetrics/`, beside the daemon, or set `NETMETRICS_BPF_OBJECT`. Loading needs `CAP_BPF` (and kernel-dependent companions) or `CAP_SYS_ADMIN`.

When eBPF cannot start, the backend reports why and `SnapshotOnly` once, and polls `/proc/net` and the processes that own its sockets: connections are listed without byte counts, and endpoint ownership is `Unavailable`. It tries eBPF again every 60 seconds, and a retry costs a file check unless the start could end differently. The object is looked for again each time, so one installed or replaced later is used. An object whose load failed is loaded again only when that failure can pass, a lack of memory or a verification a signal interrupted (`ENOMEM`, `EAGAIN` in `bpf(2)`), or once the file has changed; any other failure, such as a missing privilege, a verifier rejection, a kernel without BTF or missing kernel functions, repeats for as long as the object and the kernel stay the same. eBPF takes over what the fallback listed: a connection the fallback announced is not announced again, one that ended while they switched is closed, the others close as eBPF closes any connection, and the processes the fallback reported stay tracked until they exit. Once started, eBPF runs until the collector stops. The DNS sniffer runs throughout.

### macOS

If `NETMETRICS_PKTAP_INTERFACE` names a safe PKTAP interface (`pktap`, `pktap0`, …), the backend creates it if missing and sets it to tap Ethernet, FireWire, "other" (tunnels) and loopback interfaces: macOS's default set plus lo0, so local DNS traffic shows its owner. It reads the interface through BPF with `BIOCSWANTPKTAP` set, attributes packets with PKTAP PIDs, reads DNS from port 53 over UDP and TCP, and maps `pth_ifname` through `if_nametoindex`. TCP close uses the live socket table (Listen and TIME_WAIT ignored) after a 2s grace; UDP uses bind disappearance, with a 5-minute idle last resort. A flow's cookie is its socket's flow ID from the PKTAP header (`pth_flowid`), a random number the kernel allocates per socket. Packets the host receives through the kernel's own stack do not carry it, so a flow first seen inbound has no cookie until it sends.

Every packet names its process, so a process is known from its first packet. The executable path (`proc_pidpath`) and the start time are read once; a kqueue with `EVFILT_PROC` then reports the process's exec and its exit as they happen. A process that has already exited when its packet is read is still reported, by the name the packet carried and without a path.

Interface counters come from the kernel's generic interface MIB, `net.link.generic.ifdata.<ifindex>.general` (`struct ifmibdata` in `<net/if_mib.h>`), read once per interface at each poll. The usual sources do not work for a program Apple did not sign: `getifaddrs` gives 32-bit counters that wrap every 4 GiB, and the routing sysctl `NET_RT_IFLIST2`, which has 64-bit fields, has its byte counters rounded to 1 KiB and truncated to 32 bits by the kernel (from macOS 13). The MIB entry carries the 64-bit counters whole. Transmit drops are the packets the interface's send queue dropped. Apple documents this MIB only in that header.

DNS lookups are published as on Linux: a `DnsQuery` event when a query is sent and again when it is answered. mDNSResponder sends each lookup on a socket delegated to the application that asked, and PKTAP names both, so the event carries the application as the requester and mDNSResponder as the resolver.

Without the env var, the backend emits `SnapshotOnly` and walks the TCP socket table. It has no socket token there, and derives a cookie from the tuple, the PID and the first observation. DNS requires PKTAP. With the env var, the backend falls back to the same walk whenever PKTAP cannot start or its read fails, and tries PKTAP again every 60 seconds. Flows pass from one source to the other, so a switch announces no flow twice: a TCP flow closes once the table stops listing it, and a UDP flow capture saw stays open while its socket is bound. Process exits are still reported, and endpoint ownership is `Unavailable` until PKTAP is back. Access to `/dev/bpf*` needs root or a packet-capture entitlement. A Network Extension is the planned successor for sandboxed deployments.

## Public API

```rust,no_run
use netmetrics::{Collector, FlowEvent};

let mut collector = Collector::builder()
    .session_name("netmetrics")
    .buffer_mb(32)
    .max_flows(65_536)
    .dns_hints(true)
    .build()?;

collector.start(Box::new(|event: FlowEvent| {
    println!("{event:?}");
}))?;

let _snapshot = collector.snapshot_flows();
let _stats = collector.stats();
// collector.stop()?;
# Ok::<(), netmetrics::MetricsError>(())
```

Implement `FlowConsumer::on_batch` to write a whole batch with one downstream lock or transaction. Closures work; `antiwire-flow` wraps the collector in a Tokio channel.

Other entry points:

- `Collector::snapshot_flows()` — immutable copy of the flow table
- `socket_owner_snapshot()` / `active_connection_count()` — OS tables, no collector required
- `windivert::set_enabled(bool)` / `windivert::is_enabled()` — the opt-in for WinDivert on Windows, off by default; see [Windows](#windows). It changes nothing on other platforms, nor on a Windows architecture WinDivert has no driver for: `windivert::is_supported()` says whether this build can use it
- `dns_divert::start(report)` — sends DNS that bypasses a local stub on port 53 back to it, and blocks port 853, until dropped. Windows does that only with WinDivert turned on, because redirecting a connection there needs a kernel driver. Without WinDivert, on any architecture, it refuses the traffic with filters in the Windows Filtering Platform: outbound TCP and UDP to ports 53 and 853 is blocked, loopback excepted, for every program but this process and `svchost.exe`, which hosts the system resolver. A program that names its own resolver then fails to resolve. The filters live in a dynamic session, so Windows deletes them when the divert is dropped or the process ends, and they are checked every `DIVERT_CHECK_INTERVAL` like the rules below. Each platform lets the stub's own upstream lookups through in its own way: Linux exempts only a socket marked with `dns_divert::exempt_socket` (root is diverted like any other user), macOS exempts every process of root, and Windows exempts the process that holds the divert. `report` receives a `DivertEvent` when the divert is lost, when it is restored, and when restoring it failed. Any root process can remove the kernel rules on Linux (an nftables table, or without `nft` a chain in the iptables `nat` and `filter` tables of each address family) and macOS (a pf anchor and a `pfctl -E` reference), so there the divert lists them every `DIVERT_CHECK_INTERVAL` (5 s), compares the listing with the one taken when it installed them, and installs them again on any difference: deleted, emptied, made dormant, pf disabled, or the `com.apple/*` anchors gone from the main ruleset. A loss lasts at most that interval plus one check and one repair. Each check is one `nft list table` on Linux (four `iptables-save` listings in the iptables form) and six `pfctl` listings on macOS.

`FlowEvent` variants: `Opened`, `Finishing`, `Closed`, `Bytes`, `ProcessStarted`, `ProcessStopped`, `DnsResolved`, `DnsResolvedWithMetadata`, `DnsQuery`, `Interface`, `Degraded`, `Restored`.

## Accounting limits

- Windows ETW and Linux probes count stack-level bytes; PKTAP counts captured IP lengths. Retransmission treatment can differ.
- On Linux, received bytes are the bytes an application takes off its socket, counted once however it reads them. A `MSG_PEEK` read is not counted, since the read that takes the data is. A TCP read that waits for more data, zero-copy receive and `TCP_QUICKACK` are counted by how far the socket's reader advanced, not by the length the kernel reports for each call, which repeats bytes. Two limits remain. A TCP connection established before the collector started has its first read counted by that length. And a UDP datagram longer than the buffer it is read into counts as the bytes copied, not as its length on the wire.
- Every source reports what it loses as `DegradeReason::BufferOverflow`, and those bytes are not counted: records the Linux eBPF ring had no room for, events a Windows ETW session did not record or deliver (`EventsLost` and `RealTimeBuffersLost`, read every second for each session; a lost buffer counts as one event, so the number is the least that was lost), and packets the macOS capture buffer dropped. A lost close or disconnect leaves its flow open: the report does not repair it.
- macOS reads packets through a BPF device, whose buffer the kernel cuts an oversized packet to fit. The backend asks for a 4 MiB buffer (and takes no less than 128 KiB), so every IP packet is captured whole, including the 16 KiB segments of loopback. The kernel keeps two such buffers and drops packets that arrive while both are full, which a burst faster than the reader can still cause; those packets are reported as `DegradeReason::BufferOverflow`, and their bytes are not counted. To keep reading, the capture thread leaves the listing of sockets, which it needs to close flows, to a thread of its own.
- Socket cookies only contradict when both sides share a `CookieSource`. An absent cookie never splits a flow.
- A socket-table row opens a flow only for an established connection, `ESTABLISHED` or `CLOSE-WAIT` (`TcpState::is_established`), and `active_connection_count()` counts by the same rule. That holds on every platform: the first Windows TCP poll and the IP Helper fallback, the Linux eBPF start, procfs fallback and reconciliation, and the macOS socket-table fallback. So a connection that is still being set up, or that finished before the collector started, is not opened, and a fallback closes a connection when this end sends its FIN rather than when its time-wait row expires. A connection whose application shut down only its sending side is not established either: Windows lists it exactly like one the application has closed, so no platform could count it and stay in step with the others.
- Live capture follows the same rule and still keeps every byte. Linux eBPF and macOS PKTAP open a TCP flow when its connection becomes established, and report `FlowEvent::Finishing` when it stops being so, which is when this end sends its FIN. A finishing flow is no longer an active connection (`FlowState::Finishing` in a snapshot), but it stays open for the bytes that still follow, as after `shutdown(SHUT_WR)`, and `FlowEvent::Closed` ends it when its socket closes. Windows reports no `Finishing`: its ETW source ends a flow with the disconnect event.
- On macOS the packets of a TCP handshake are held until the connection is established and counted on its flow then. A connection attempt that is refused or never answered is not a flow and its packets are not counted, as on Linux and Windows, whose byte counts never include a handshake.
- Two cases still leave a flow open while `active_connection_count()` does not count its connection. A connection that was already half-closed when the collector started is opened, without `Finishing`, by the first bytes it carries. And macOS learns that an application shut down its sending side from the FIN it sends, which follows the data still queued.
- On Windows, TCP polls after the first only attach a socket cookie and do not open a new flow. Time-wait and the other closing states stay in the owner map. On Linux, a `/proc/net/tcp` row a process holds names its owner in socket-table lookups whatever its state, a connection still being set up included; a time-wait row, or a handshake a listener has not completed, names none.
- A flow's interface is the one that owns its local address. `GetBestRoute2` is used only when that address is unspecified or missing from the unicast table. Loopback never inherits the default-route interface.
- UDP has no kernel disconnect event in the TCP/IP provider this collector enables (send and receive only). Close waits until the next UDP-table poll, at least 250 ms, sees the bind disappear. A UDP `FLOW_DELETED` from WinDivert is not a socket close. On the IP Helper fallback, a UDP exchange that starts and ends between polls is not recorded.
- DNS answers served by the local stub are recorded against the querying process, including answers taken from the stub cache. DNS-Client ETW still covers lookups that never reach the stub. The daemon's own upstream queries are not used as the client's name. On Windows, a lookup an application sends to a resolver itself, without the system DNS client, is not seen; Linux and macOS read the packets, so they report it and name its sender. On Linux, a query to `systemd-resolved` attributes to the app; the upstream query to a public resolver attributes to resolved.
- Procfs / IP Helper / macOS snapshot fallbacks can miss short-lived flows and do not invent per-flow byte totals.
- Capacity uses deterministic LRU eviction and reports counts via `DegradeReason::CapacityExceeded` and `CollectorStats`.
- The ingress queue is bounded. Byte bursts cannot displace a small lifecycle reserve; overflow is counted, not blocked in native callbacks.

## Example and tests

```bash
cargo run -p netmetrics --example basic
```

From this workspace:

```bash
cargo fmt
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Linux cross-check from Windows:

```bash
cargo clippy -p netmetrics-linux --target x86_64-unknown-linux-gnu --all-targets --all-features -- -D warnings -A clippy::collapsible_if
```

Elevated Windows tests are `#[ignore]`d (kernel ETW). See `crates/netmetrics/tests/native_windows.rs` and `collector_probe.rs`. Linux live/eBPF coverage is the `antiwire-rs` Docker image (`docker/linux-test.Dockerfile`).

## License

netmet is distributed under the [MIT License](LICENSE). The eBPF programs in
`crates/netmetrics-linux/ebpf` are the exception: they are licensed
`GPL-2.0-only OR BSD-2-Clause`, as their SPDX headers state, because the kernel requires a
GPL-compatible license for the helpers they call.
