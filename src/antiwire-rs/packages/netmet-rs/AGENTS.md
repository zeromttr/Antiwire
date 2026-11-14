# netmet

`netmetrics`: a synchronous library that turns native host network telemetry (ETW, eBPF, PKTAP)
into one bounded, batched `FlowEvent` stream. Antiwire uses it through `antiwire-flow`. It is
meant to move to a repository of its own, so it must not depend on any `antiwire-*` crate.

Project-wide rules are in the [root guide](../../../../AGENTS.md); elevation and the Docker
images are in the [antiwire-rs guide](../../AGENTS.md#elevated-tests). `README.md` documents the
public API, each platform backend, and the accounting limits.

## Workspace

**Edition 2024**, MSRV 1.90, its own `Cargo.lock`. Run commands from this directory; `cargo fmt`
from `src/antiwire-rs` reformats these crates to edition-2021 style.

```bash
cargo fmt
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo run -p netmetrics --example basic
```

`missing_docs` warns, `unsafe_op_in_unsafe_fn` is denied, and every `unsafe` block needs a
`// SAFETY:` comment. Public items that Antiwire does not call are kept on purpose:
`docs/api-compatibility.md` records each decision, and a removal goes there first.

## Crates

| Crate | What it holds |
|---|---|
| `netmetrics` | The public API. `collector/` is the worker that owns the flow and process tables (`supervisor.rs`, `reconcile.rs`, `publication.rs`); `config.rs` its builder options; `sockets.rs` and `active.rs` are the point-in-time socket-table helpers; `owner_cache/` and `endpoint_owner.rs` answer "which process owned this endpoint"; `dns_divert.rs` is the port-53 divert; `attribution.rs` reports attribution diagnostics. |
| `netmetrics-core` | Everything platform-independent. `flow/` is the flow table (`accounting.rs`, `attribution.rs`, `lifecycle.rs`, `snapshot.rs`), `coalescer.rs` merges byte deltas, `dns.rs` is `DnsHintMap`, `dns_parse.rs`, `dns_caller.rs` and `dns_transaction.rs` decode DNS and match answers to askers, `endpoint_owner/` is the bounded ownership history, `dns_divert.rs` the divert rules every backend shares, `types.rs` the event types, and `expiring_map.rs`, `ip_cache.rs`, `clock_lag.rs` small shared structures. |
| `netmetrics-sys` | The private contract backends implement: `backend.rs` (the trait and `BackendEvent`), `wire.rs` (the 64-byte `NMT1` ring record decoder), `sink.rs`, `stop.rs`, `poll.rs`, `ifindex.rs`, `unavailable.rs`. |
| `netmetrics-windows` | `windows/` is the ETW backend: `kernel_trace.rs` (TCP/IP), `process_trace.rs`, `dns_trace.rs` (DNS-Client), `session.rs`, and `fallback.rs` (IP Helper snapshots). `owner_module/` reads socket owners from the IP Helper tables. `windivert.rs`, `windivert_handle.rs` and `windivert_package.rs` load WinDivert; `dns_divert/` and `endpoint_owner/` use it. `interface/` maps flows to adapters, `process_image.rs` resolves executables, `session_names.rs` names the ETW sessions. |
| `netmetrics-linux` | `linux/ebpf` is the Aya loader, `linux/procfs` the fallback, `linux/process` and `linux/interface` the lookups, `dns_sniffer.rs` the AF_PACKET UDP/53 capture, `dns_divert.rs` the divert, `capability.rs` the privilege checks. The kernel programs are in `ebpf/`. |
| `netmetrics-macos` | `pktap.rs` and `bpf_records.rs` read PKTAP through a BPF device; `macos.rs` is the backend and its netstat2 fallback; `dns_divert.rs` the divert. |

## Invariants

- **Native callbacks only enqueue.** They push into a bounded channel and return; one collector
  worker owns the tables. Overflow is counted, never blocked on.
- **Degraded modes are visible.** A fallback emits `FlowEvent::Degraded` and never claims byte
  totals it did not measure.
- **Everything is bounded.** Tables evict by deterministic LRU and report the count.
- **Shared logic lives in `netmetrics-core`.** Flow accounting, DNS decoding, ownership history
  and divert rules are written once there; a backend supplies only native observations.
- **`FlowEvent` is a stored format.** Version-one JSON must keep deserializing
  (`tests/contract_json.rs`, `tests/public_api_compat.rs`).

## Unsafe code

The collector runs inside a privileged process and parses data it did not produce: packets, DNS
payloads, ETW events and kernel ring records. The
[unsafe code rules](../../AGENTS.md#unsafe-code) apply in full. On top of them:

- **Use the safe binding first.** ETW goes through `ferrisetw` and eBPF loading through `aya`.
  Raw calls are for what they do not cover: IP Helper tables, WinDivert, sockets, BPF devices.
- **`unsafe` belongs in the platform crates and `netmetrics-sys`.** `netmetrics-core` and the
  `netmetrics` library have none, and stay that way: every parser and table there is safe Rust.
- **Parse untrusted bytes with safe code.** Packets, DNS messages and `NMT1` ring records are
  decoded with `from_le_bytes` and checked slicing, as `netmetrics-sys/src/wire.rs` does, never
  by casting a pointer to a struct. Every length inside a packet is attacker-controlled: IP
  header length, IPv6 extension headers, DNS labels, compression pointers and `RDLENGTH`.
- **Bad input is an error value, never a panic.** A short or malformed record is dropped and
  counted. No indexing, `unwrap` or unchecked arithmetic on bytes from the wire or the kernel.
- **Variable-length OS tables are sized twice.** Ask for the size, allocate, call again, and
  retry when the table grew in between. Read only the entries that fit the buffer you
  allocated, whatever count the call reports.
- **Native callbacks do the minimum.** They copy what they need, enqueue it and return. A pointer
  the OS passes in is valid only during the callback, so never keep it. A callback never panics
  or unwinds into the OS.
- **Every handle is released in `Drop`:** ETW sessions, WinDivert handles, process handles,
  sockets and change notifications.
- **Fix `undocumented_unsafe_blocks`; never allow it.** `unsafe_op_in_unsafe_fn` is denied, so an
  `unsafe fn` still needs an explicit block, with its own comment, around each unsafe operation.
- **Loading WinDivert and writing eBPF have rules of their own:** see [WinDivert](#windivert)
  and [eBPF](#ebpf).

## Operating system calls

The [operating system call rules](../../AGENTS.md#operating-system-calls) apply in full: read
the official documentation before writing or changing a call, and cite it. For this library:

| Source | Official documentation |
|---|---|
| ETW providers and sessions | Microsoft Learn: Event Tracing for Windows; each provider's manifest for event layouts |
| IP Helper tables | Microsoft Learn: `GetExtendedTcpTable`, `GetExtendedUdpTable` and the `MIB_*` structures |
| WinDivert | `windivert.h` and the documentation of the pinned version, 2.2.2 |
| eBPF | `docs.kernel.org/bpf`, `bpf(2)`, `bpf-helpers(7)` |
| Packet sockets, `/proc` | `packet(7)`, `proc(5)`, `netlink(7)` |
| PF and interfaces on macOS | `pfctl(8)`, `pf.conf(5)`, `ifconfig(8)`, `bpf(4)` |
| PKTAP | Not a documented API. The reference is `bsd/net/pktap.h` in Apple's published XNU source |

- **Event and record layouts are versioned.** Check an ETW event's version before reading a
  field, and treat an unknown version as unknown, not as the newest one you have seen.
- **Kernel functions are not a stable interface.** A kprobe target can be renamed, inlined or
  removed in any kernel release. Attach each probe on its own, read kernel structures through
  CO-RE, and report a missing probe as `FlowEvent::Degraded`.
- **PKTAP is undocumented,** so every use of it follows the
  [undocumented behavior rule](../../AGENTS.md#read-the-official-documentation-first): assert the
  header layout, detect failure at run time, and fall back visibly.
- **The divert changes only its own objects:** its own nftables table (or, without `nft`, its
  own chains in the iptables `nat` and `filter` tables) and its own PF anchor.
  On macOS, enable PF with `pfctl -E` and release that token with `pfctl -X`. Never use `-e` or
  `-d`, which switch PF for the whole host.
- **Divert commands are built in `netmetrics-core/src/dns_divert.rs`** as pure functions, so
  every platform shares one tested definition. Add an argument there, not at the call site.
- **Remove what you installed.** A divert rule left behind after the collector stops sends the
  host's DNS nowhere. Removal runs on stop and on `Drop`, and tolerates being run twice.

## WinDivert

WinDivert is loaded dynamically from the official DLL. Do not vendor the DLL or `.sys`, and do
not compile WinDivert from source: the Microsoft-signed driver is the one inside the official
archive. Antiwire stays MIT because the LGPL-3.0 library is not linked statically.
`windivert_package.rs` downloads `https://reqrypt.org/download/WinDivert-2.2.2-A.zip`, verifies
it, and writes only its DLL and signed driver into `%LOCALAPPDATA%\antiwire\windivert\2.2.2-A`;
the archive stays in memory.

WinDivert is built only for `x86_64`: it has no ARM64 driver. Elsewhere, `windivert_unavailable.rs`
and `dns_divert_unavailable.rs` refuse at once, and nothing is downloaded.

It is the only library loaded at run time, and the only place a hash decides what code runs.
`windivert_package.rs` pins the SHA-256 of the archive, the DLL and the driver, and
`windivert_handle.rs` loads the DLL by its full path only after they match.

- **A version change replaces all three hashes,** taken from the official archive, and re-checks
  every function signature in `windivert_handle.rs` against that version's header.
- **The one `transmute_copy` there** is the only exception to the ban on `transmute`. It turns a
  `GetProcAddress` result into a typed function pointer. A wrong signature is undefined
  behavior on every call, so do not add an export without its exact C prototype.
- **The verified files stay locked while the handle is open,** so nothing can replace them
  between the check and the load. Keep that lock.
- **Never skip or soften the hash check,** fall back to another copy of the DLL, or load it by
  bare name.

## eBPF

`crates/netmetrics-linux/ebpf/*.bpf.c` are licensed `GPL-2.0-only OR BSD-2-Clause`, not MIT,
because the kernel requires it for the helpers they call. Build them with `ebpf/build.sh` on a
Linux host with Clang, bpftool and kernel BTF. `cargo test` does not load the objects; the
collector finds them at runtime. `ebpf/README.md` is the contract between the programs and the
loader.

- **Keep the verifier strict.** Bounds-check every packet access, keep every map bounded, and do
  not work around a verifier rejection by loosening a check.
- **Change the record layout in both places.** The 64-byte `NMT1` record is written by
  `netmetrics.bpf.c` and decoded by `wire.rs`; a change to one without the other corrupts every
  record.

## ETW sessions outlive their process

The `netmetrics` and `netmetrics-dns` sessions are kernel-owned and survive the process that
started them. A stale session makes every later start fail with `ERROR_ALREADY_EXISTS`, which
once caused a silent fallback with no byte accounting. The backend now clears a stale session
and retries once. **Running an elevated collector test stops the session a running daemon is
using**; restart the daemon afterwards.

## Elevated tests

All are `#[ignore]`d. Run them with the
[Windows procedure](../../AGENTS.md#on-windows), building in this workspace, so `$exe` comes from
`target\debug\deps\` here. For a unit test inside a crate, pass its name before `--ignored`.
`scripts/run-elevated-windows-tests.ps1` runs `native_windows` from a shell that is already
elevated.

| Test | Needs |
|---|---|
| `netmetrics/tests/collector_probe.rs` | Kernel ETW session; reports the live event mix |
| `netmetrics/tests/native_windows.rs` | Kernel ETW, plus DNS access for one case |
| `netmetrics/tests/native_linux.rs` | Linux BTF plus `CAP_BPF`/`CAP_PERFMON` (or `CAP_SYS_ADMIN`) and `CAP_NET_RAW` |
| `netmetrics/tests/endpoint_owner.rs` | root with working eBPF on Linux, or `NETMETRICS_PKTAP_INTERFACE` on macOS |
| `netmetrics-windows` `owner_module` live test | Enumerates the live TCP table |
| `netmetrics-windows` `process_trace` tests | Administrator; each starts its own process-image ETW session |
| `netmetrics-windows` `dns_divert` live tests | Administrator; open the WinDivert driver and bind the local DNS port |
| `netmetrics-windows` `official_package_records_this_process_on_connect` | Administrator; downloads the WinDivert package and opens the driver. It skips itself only when the download cannot be verified; a failed `WinDivertOpen` is a real failure |
| `netmetrics-windows` `live_loopback_flows_record_their_owner_before_the_server_reads` | Administrator and the same package; prints how many loopback UDP and TCP flows FLOW recorded before the server read from them |

`collector_probe.rs` and the `live_loopback_flows_…` test are diagnostics, not assertions. Read
the numbers they print, not the pass or fail. Containers cannot load the WinDivert driver, so
its tests need a native Windows run.
