# firew

A cross-platform library that creates, reads, updates and deletes native host firewall rules.
Antiwire uses it through `antiwire-enforce`. It is meant to move to a repository of its own, so
it must not depend on any `antiwire-*` crate.

Project-wide rules are in the [root guide](../../../../AGENTS.md); elevation and the Docker
images are in the [antiwire-rs guide](../../AGENTS.md#elevated-tests). `README.md` documents the
public API, and `docs/architecture.md` the ownership markers and lifecycle.

## Workspace

Edition 2021, MSRV 1.90, its own `Cargo.lock`. Run commands from this directory.

```bash
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
./scripts/run-offline-tests.sh      # the unprivileged tier, one crate at a time
```

`unsafe_code` is denied and `missing_docs` warns, so every public item needs a doc comment.
This is a published 1.0 API: removing or changing a public item is a breaking change, even when
Antiwire does not call it.

## Crates

| Crate | What it holds |
|---|---|
| `firew` (package `firew-rs`) | The public facade. `firewall/` is `Firewall`, `builder.rs` its builder, `engine.rs` the one synchronous implementation every adapter shares, `backend_factory.rs` picks the platform backend, `bulk_executor.rs` runs `BulkRequest`, `domain_manager/` resolves and refreshes domain-backed rules, `health.rs` is the health monitor, `async_tokio.rs`, `async_async_std.rs` and `async_smol.rs` are the runtime adapters. |
| `firew-core` | Portable types with no native code: `rule/` (builder, validation, representation), `rule_key.rs`, `action.rs`, `direction.rs`, `protocol.rs`, `port_range.rs`, `domain.rs`, `bulk.rs`, `registry.rs` (desired state), `error.rs`. |
| `firew-sys` | The private contract backends implement. `backend.rs` is the trait, `marker.rs` the ownership markers, `native_ref.rs` references to native objects, `expansion.rs` turns matcher alternatives into native rows, `reconstruct.rs` and `drift.rs` read rules back and detect drift, `forward.rs` picks a backend at open time, `mock.rs` is the test backend. |
| `firew-linux` | `detect.rs` chooses between `nftables/` and `iptables/` (with `ipset.rs`). |
| `firew-windows` | `inetfw.rs` (INetFw over COM) and `wfp.rs` (the WFP fallback), with bindings in `sys/`, object names in `naming.rs`, and a dedicated native thread in `worker.rs`. |
| `firew-macos` | PF: `pf_rules.rs` renders anchor rules, `pf_table/` handles tables. |
| `firew-bsd` | A stub; BSD support is deferred. |

## Invariants

- **Exact or rejected.** A rule is represented exactly by the backend, or refused before any
  native change with `UnsupportedMatcher` or `UnsupportedOperation`. Never drop a matcher.
  The README's capability table states what each backend covers; update it with the backend.
- **A failed native read is an error.** No backend falls back to an empty listing or to its
  in-process copy, because PF and nftables rewrite from what they read.
- **Rules are read back from what the rows enforce,** not from what their markers claim.
  Anything that is not exactly the expansion the rule installs is drift.
- **Ownership is the manager and application name pair.** Memory-mode `close` removes every rule
  in that namespace, so a test or helper needs its own application name.
- **Backends share `firew-sys`.** Expansion, markers, drift and reconstruction live there; do
  not reimplement them per platform.

## Unsafe code

This library changes the host firewall as Administrator or root, so the
[unsafe code rules](../../AGENTS.md#unsafe-code) apply in full. On top of them:

- **`unsafe` is allowed in one place: `crates/firew-windows/src/sys/`.** The workspace denies
  `unsafe_code`, and `sys/mod.rs` is the only opt-in. `sys/com/` wraps INetFw and `sys/wfp/` wraps
  WFP. Do not add an opt-in anywhere else; add a safe function to `sys` and call that.
- **Every other crate stays free of `unsafe`.** The Linux and macOS backends drive `nft`,
  `iptables`, `ipset` and `pfctl`, and need none.
- **`sys` exports safe types only.** A COM interface pointer, `BSTR`, `VARIANT` or WFP engine
  handle never leaves it, and each is released in `Drop`.
- **Native objects stay on their worker thread.** `worker.rs` gives each backend one dedicated
  thread, which initializes COM or opens the WFP engine and holds the result. Send it a request;
  never move an interface or handle to another thread.
- **Check every `HRESULT` and WFP status** before reading anything the call returned, and abort
  an open WFP transaction on every error path.
- **Native state is untrusted input.** Any process with the same privileges can create or edit
  rules, so names, markers and row contents read back from the firewall are parsed with bounds
  and format checks. A malformed row is drift, never a panic.
- **Only validated `firew-core` types reach native syntax.** Never format a caller's raw string
  into an nftables, iptables or PF rule, and never run a command through a shell. Pass each
  argument as its own `arg`.

## Operating system calls

A wrong firewall call can block all traffic or silently allow it, so the
[operating system call rules](../../AGENTS.md#operating-system-calls) apply in full: read the
official documentation before writing or changing a call, and cite it. For each backend that is:

| Backend | Official documentation |
|---|---|
| INetFw | Microsoft Learn: Windows Firewall with Advanced Security, `INetFwPolicy2`, `INetFwRule3` |
| WFP | Microsoft Learn: Windows Filtering Platform, the `Fwpm*` functions, filter arbitration |
| nftables | `nft(8)`, `libnftables-json(5)`, the nftables wiki |
| iptables, ipset | `iptables(8)`, `iptables-extensions(8)`, `ipset(8)` |
| PF | `pfctl(8)` and `pf.conf(5)` as shipped with macOS, whose PF differs from OpenBSD's |

- **Change only what the library owns:** its own table, chain, set, anchor or sublayer. Never
  flush, reload, enable or disable anything outside it, such as `nft flush ruleset`, `iptables -F`
  on a built-in chain, `pfctl -F all` without `-a`, or `pfctl -e` and `-d`.
- **Send a rule set as one batch through stdin,** as `pfctl -a <anchor> -f -` and `ipset restore`
  do, so it applies whole or not at all. Do not start one process per rule.
- **Read state back in a machine format** where the tool has one. nftables goes through the
  `nftables` crate's JSON, and iptables through the `iptables` crate; do not start those tools
  by hand beside them.
- **Match error text in one place.** `firew-sys/src/backend.rs` tells a missing object from a
  failed command by its message. Add a new match there, with a test against the real tool's
  output, and run that tool with `LC_ALL=C`.
- **A capability comes from the documentation, not from a test that happened to pass.** If the
  documentation does not say a backend can express a matcher exactly, reject it.
- **Free native memory with the function the API names:** `FwpmFreeMemory0` for WFP, and the COM
  rules for `BSTR` and `VARIANT`.

## Elevated tests

All are `#[ignore]`d. They create rules in dedicated test namespaces and remove them.

| Test | Needs | How |
|---|---|---|
| `firew-windows/tests/live_windows.rs`, `firew/tests/integration.rs` | Administrator | `./scripts/run-elevated-windows-tests.ps1` builds, elevates, waits, and checks `ELEVATED=yes` |
| `firew-linux/tests/live_linux.rs`, `firew/tests/integration.rs` | `CAP_NET_ADMIN` | the [Linux image](../../AGENTS.md#linux-image) in `live` mode, or natively on Linux |
| `firew-macos/tests/live_macos.rs` | root; changes live PF state in its own anchor | `sudo cargo test -p firew-macos --test live_macos -- --ignored --test-threads=1 --nocapture` |

`live_inetfw_address_set_ceiling` is a slow measurement, not a check; the wrapper skips it, and
`scripts/measure-inetfw-address-ceiling.ps1` runs it on its own. `docs/testing.md` has the full
tiers, including the feature-matrix checks.
