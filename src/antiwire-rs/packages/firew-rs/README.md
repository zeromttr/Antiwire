# firew-rs

`firew-rs` 1.0 is a strict, cross-platform native firewall library for Windows,
Linux, and macOS. A rule is either represented exactly by the selected backend or
rejected before native mutation with a structured capability error.

## Rule model

- `RuleKey` is the stable identity: 1–32 ASCII letters, digits, `_`, or `-`.
- Matcher alternatives within one field are ORed; populated fields are ANDed.
- `Direction::Both` requires complete inbound and outbound representations.
- Ports require TCP or UDP, are nonzero, and use validated inclusive ranges.
- Rules may expand to at most 256 native rows.
- Optional labels are display-only metadata and do not affect equality or
  reconciliation.
- DNS names are normalized lowercase ASCII hostnames. Domain-backed rules require
  memory mode because persistent DNS intent needs a separate long-running agent.

Backend preflight returns `ErrorKind::UnsupportedMatcher` or
`ErrorKind::UnsupportedOperation` when a native firewall cannot represent a field
or action exactly. Matchers are never silently discarded.

The current 1.0 backend capability boundary is intentionally conservative:

| Backend | Exact portable coverage | Preflight exclusions |
|---|---|---|
| nftables | local/remote addresses and ports, alternatives, both directions, numeric protocols, allow/drop/reject | application path, package SID |
| iptables | IPv4 local/remote addresses and ports, alternatives, both directions, numeric protocols, allow/drop/reject | IPv6, application path, package SID |
| INetFw | local/remote alternatives, both directions, numeric protocols, application path, package SID | reject |
| WFP | remote addresses, one remote port or port range, both directions, numeric protocols, application path | local endpoints, multiple remote ports, package SID, reject |
| PF | local/remote addresses and ports, alternatives, both directions, allow/drop/return-style reject | application path, package SID, custom protocol numbers |

## Quick start

```rust
use firew_rs::{Action, Direction, Firewall, Rule};

let mut firewall = Firewall::builder()
    .name_prefix("myapp")
    .application_name("daemon")
    .memory_mode(true)
    .build()?;

let rule = Rule::builder("block-bad", Action::Block, Direction::Outbound)
    .remote_address("203.0.113.1/32".parse()?)
    .build()?;

let id = firewall.add_rule(rule)?;
firewall.remove_rule(&id)?;
firewall.close()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Manager and application names are limited to 64 bytes. Memory mode is opt-in:
explicit `close` removes its managed rules. Persistent-mode rules survive `close`
and owner drop.

### Ownership and verdicts

- The manager and application names are the owner's identity. Every owner opened
  with the same pair shares one namespace, and memory-mode `close` or drop removes
  every rule in that namespace, including rules another owner with the same names
  installed. Give a short-lived helper its own application name.
- `Action::Allow` is a terminal accept placed ahead of the host's own filtering on
  Linux (an `iptables` chain jumped to first, an `nftables` base chain at priority
  0) and macOS (`pass quick`). It therefore bypasses deny policy that `ufw`,
  `firewalld`, or the rest of the PF ruleset applies later. On Windows, Windows
  Firewall and WFP arbitration let a block elsewhere still win over an allow.

## Native reconciliation

Native enumeration is the source of actual state across all supported backends:
`INetFw` COM enumeration and WFP filter enumeration on Windows, `nft -j list table`
and `iptables -S` / `ipset list` on Linux, and `pfctl` anchor/table queries on
macOS. Supply desired state after a restart with:

```rust,no_run
# use firew_rs::{Firewall, Rule};
# fn apply(firewall: &mut Firewall, desired: &[Rule]) -> Result<(), firew_rs::Error> {
let report = firewall.reconcile(desired)?;
for item in &report.items {
    println!("{}: {:?}", item.key, item.status);
}
// `Ok` means every change was attempted, not that every change succeeded.
report.into_result()?;
# Ok(())
# }
```

Reconciliation validates and resolves the complete desired set before mutation,
creates missing rules, replaces changed rules, and removes only objects recovered
from the library-owned native container. A failure to change one rule does not
stop the others; it is reported as `ReconcileStatus::Error` in the report, which
`has_errors` and `into_result` surface.

A failure to read native state is always an error, never an empty or remembered
listing: no backend mutates from a picture it could not confirm.

## Health monitoring

`spawn_health_monitor` re-checks native state on an interval and, with
`auto_repair`, reinstalls registered rules that are missing or were modified.
It deletes owned rules absent from the registry only after the caller has
declared the complete desired set with `reconcile` or `remove_all_rules`.
`add_rule`, `update_rule`, `remove_rule`, and bulk requests are incremental and
never make the monitor treat other rules in the namespace, such as ones recovered
from a persistent owner, as extras.

## Bulk execution

`BulkRequest` uses an explicit `TransactionMode`:

- `Sequential`: continue independent items after failures.
- `PreferNative`: use a native transaction when supported, otherwise report
  sequential best effort.
- `RequireNative`: reject before mutation when the backend has no native
  transaction.

`BulkExecution` reports actual atomicity and a typed result for every original
operation/item index. Evaluation order is delete, update, create, then read;
results are returned in caller order.

When a native transaction fails and its rollback fails too, the request returns
`ErrorKind::RollbackFailed`. Desired state returns to where it was before the
request, and the native-reference cache is rebuilt from a fresh listing, so a
rule the failed rollback left installed is still known and is not installed a
second time.

## Async adapters

Enable exactly the runtime features you use. Adapters consume the synchronous
owner so it cannot close shared state underneath async work:

```rust,no_run
# use firew_rs::Firewall;
# async fn example() -> Result<(), firew_rs::Error> {
let firewall = Firewall::builder().name_prefix("service").build()?;
let firewall = firewall.into_tokio();
firewall.close().await?;
# Ok(())
# }
```

The equivalent adapters are `into_async_std` and `into_smol`. Each uses its own
runtime's blocking facility and exposes ordinary method names such as `add_rule`.

## Privileges and testing

| OS | Native backend | Requirement |
|---|---|---|
| Linux | nftables, with iptables fallback | `CAP_NET_ADMIN` or root |
| Windows | INetFw, with WFP fallback | Administrator |
| macOS | PF anchor | root |

From the repository root:

```bash
./scripts/run-offline-tests.sh
cargo check --manifest-path crates/firew/Cargo.toml
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

See [testing](docs/testing.md) for privileged tiers and
[architecture](docs/architecture.md) for ownership markers and lifecycle details.

## License

firew is distributed under the [MIT License](LICENSE).
