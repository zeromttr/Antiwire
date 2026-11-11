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
- `active_connection_count()` — established sockets currently visible to the host

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
| `netmetrics-linux` | eBPF (Aya) + `/proc` fallback + UDP/53 sniffer |
| `netmetrics-macos` | PKTAP via BPF, or netstat2 snapshot when PKTAP is unset |

Default Cargo features enable all three OS backends; only the current target is linked. For cross-compilation, disable defaults and enable exactly one of `windows`, `linux`, or `macos`.

This workspace is **edition 2024** / MSRV **1.90**. It is nested under `antiwire-rs` but is not an outer-workspace member. Run `cargo fmt` from this directory, not from `src/antiwire-rs` — formatting the nested crates from the outer edition-2021 workspace will fail their `fmt --check`.

## Platform backends

| Platform | Privileged source | Automatic fallback |
| --- | --- | --- |
| Windows | Kernel TCP/IP + Process ETW; optional DNS-Client ETW; UDP owner-module cookies | IP Helper TCP snapshots (open/close, no per-flow bytes) |
| Linux | CO-RE eBPF ring buffer (TCP/UDP bytes, cookies, close); UDP/53 capture with socket-table PID | `/proc/net` socket/process/interface snapshots |
| macOS | PKTAP through a non-blocking BPF device (`NETMETRICS_PKTAP_INTERFACE`) | netstat2 TCP snapshot loop |

Degraded modes stay visible through `FlowEvent::Degraded`. They never silently claim byte-accounting parity.

### Windows

Kernel ETW supplies TCP/UDP bytes, opens, closes, and process start/stop (including `CreateTime`). Process-end events keep image identity even when start/rundown was missed, so a PID that only appears as it exits can still be attributed during the process grace window. DNS-Client ETW, when `dns_hints` is on, decodes the request/completion pair (3006/3008/3018/3020) plus the outcome, error, NETBIOS, and resolver-operation events that also carry `ClientPID` and `QueryBlob` (1013-1018, 1022, 1024-1028, 3009-3014, 3016-3023); a completion that carries no `ClientPID` borrows the caller from its matching 3006 request by `ActivityId` or query identifier, so answers are attributed to the querying PID and read real TTLs. Failed and denied lookups therefore still name the requesting process instead of falling back to the system resolver. The owner-module TCP/UDP tables supply socket cookies (`liCreateTimestamp`) and close UDP flows when a bind vanishes. TCP listener rows are retained separately: an inbound connection whose transient 5-tuple is already gone falls back to the PID that owns the local listening port, and that owner never contributes a cookie. UDP byte observations carry the bind cookie from an `ArcSwap` snapshot. When a payload PID is missing, the connection id (`connid`) learned from an earlier event of the same connection is tried first, then the live owner snapshot; if the process has already exited, a recently closed owner retained for 10 seconds can still pin the PID, as long as the event timestamp falls inside that socket's observed lifetime. The connection mapping also carries the owner cookie, so a missed lookup on an otherwise known connection cannot drop its socket identity. Interface index is a first-write routing estimate from `GetBestRoute2` (local and remote addresses), not evidence of the interface that carried a packet.

Needs Administrator (or Performance Log Users for ETW). ETW session names are prefixed `netmetrics` so stale-session recovery cannot stop a foreign trace. A named mutex distinguishes an orphaned session from a live collector.

Historical endpoint ownership uses one shared bounded tracker and lookup API on all
three platforms. Windows supplies WinDivert FLOW events, Linux supplies eBPF owner
records from the send entry probes (plus byte records as extra history), and macOS
supplies PKTAP packet PIDs. Linux needs an object that emits owner records and both
send probes attached; otherwise ownership reports `Unavailable`. Events without a PID
never replace a known owner. Native event timestamps
preserve ownership across delayed delivery and port reuse. History retains up to
four owner changes per endpoint, for 120 seconds since its last event or lookup,
with an 8,192-endpoint bound. Repeated observations of one owner do not consume
history slots. Lookup never backdates a socket-table snapshot. Linux/macOS history
begins at observed I/O, rather than at socket creation; traffic not observed by the
source cannot establish an owner. Snapshot-only modes return `Unavailable`.

### Linux

The Aya loader attaches `inet_sock_set_state`, TCP/UDP send/recv probes, and `udp_destroy_sock`. Records are versioned (`NMT1` v1–v3); v3 adds a socket cookie and interface index. Unconnected UDP remotes are filled from `msghdr`. UDP destroy becomes `LocalEndpointClosed` so every flow on that bind drains. When the socket is not bound to a device, userspace does a route lookup equivalent to Windows `GetBestInterfaceEx`.

DNS: an AF_PACKET sniffer parses UDP/53 and maps the stub socket to a PID via `/proc` (needs `CAP_NET_RAW`). Hints with PID 0 are system-wide fallbacks.

Build `crates/netmetrics-linux/ebpf/netmetrics.bpf.c` with `ebpf/build.sh` on a Linux host (Clang, bpftool, kernel BTF). Install `netmetrics.bpf.o` at `/usr/lib/netmetrics/`, beside the daemon, or set `NETMETRICS_BPF_OBJECT`. Loading needs `CAP_BPF` (and kernel-dependent companions) or `CAP_SYS_ADMIN`.

### macOS

If `NETMETRICS_PKTAP_INTERFACE` names a safe PKTAP interface (`pktap`, `pktap0`, …), the backend reads BPF, attributes packets with PKTAP PIDs, parses DNS from UDP/53 payloads, and maps `pth_ifname` through `if_nametoindex`. TCP close uses the live socket table (Listen and TIME_WAIT ignored) after a 2s grace; UDP uses bind disappearance, with a 5-minute idle last resort. Cookies are synthetic (tuple + PID + first-seen).

Without the env var, the backend emits `SnapshotOnly` and walks the TCP socket table. DNS requires PKTAP. Access to `/dev/bpf*` needs root or a packet-capture entitlement. A Network Extension is the planned successor for sandboxed deployments.

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

`FlowEvent` variants: `Opened`, `Closed`, `Bytes`, `ProcessStarted`, `ProcessStopped`, `DnsResolved`, `Interface`, `Degraded`.

## Accounting limits

- Windows ETW and Linux probes count stack-level bytes; PKTAP counts captured IP lengths. Retransmission treatment can differ.
- Socket cookies only contradict when both sides share a `CookieSource`. An absent cookie never splits a flow.
- The first Windows TCP poll records established and close-wait connections. Later polls only attach a socket cookie and do not open a new flow. Time-wait and the other closing states stay in the owner map and do not open a flow.
- A flow's interface is the one that owns its local address. `GetBestRoute2` is used only when that address is unspecified or missing from the unicast table. Loopback never inherits the default-route interface.
- UDP has no kernel disconnect event in the TCP/IP provider this collector enables (send and receive only). Close waits until the next UDP-table poll, at least 250 ms, sees the bind disappear. A UDP `FLOW_DELETED` from WinDivert is not a socket close. On the IP Helper fallback, a UDP exchange that starts and ends between polls is not recorded.
- DNS answers served by the local stub are recorded against the querying process, including answers taken from the stub cache. DNS-Client ETW still covers lookups that never reach the stub. The daemon's own upstream queries are not used as the client's name. UDP/53 to a third-party resolver is not named when it bypasses the stub. On Linux, a query to `systemd-resolved` attributes to the app; the upstream query to a public resolver attributes to resolved.
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
