# antiwire-rs

The daemon and everything it is built from. Project-wide rules, CI and releases are in the
[root guide](../../AGENTS.md).

## Workspaces

Three Cargo workspaces, and they do not share settings:

| Root | Edition | MSRV | Guide |
|---|---|---|---|
| `src/antiwire-rs` | 2021 | 1.90 | this file |
| `packages/firew-rs` | 2021 | 1.90 | [AGENTS.md](packages/firew-rs/AGENTS.md) |
| `packages/netmet-rs` | 2024 | 1.90 | [AGENTS.md](packages/netmet-rs/AGENTS.md) |

`firew-rs` and `netmet-rs` are nested but are **not** members of this workspace. They are
reached by path dependency, and each has its own `Cargo.lock` and `target/`.

**Run `cargo fmt` from inside the workspace you are editing.** `cargo fmt --all` from here
reformats the edition-2024 crates in `netmet-rs` to edition-2021 style, which their own
`cargo fmt --check` then rejects. To format one file: `rustfmt --edition 2024 <path>`.

```bash
cargo test --workspace --all-features     # what CI runs
cargo clippy --workspace --all-targets --all-features
```

Clippy runs `all` and `pedantic` as warnings, and `unsafe_code` warns: see
[unsafe code](#unsafe-code).

## Crates

All under `crates/`. The name prefix `antiwire-` is dropped below.

### Process and API

| Crate | What it holds |
|---|---|
| `daemon` | The binary. `cli.rs` has every flag. `daemon/` is the normal run (`daemon/windows` the Windows service), `heal/` is `--heal-host-state`, `reaper/` is `--reap-parent` (reverts host state when the watched daemon exits), `update_helper.rs` is `--apply-update` and `--recover-update`, `setup/` is the data directory and logging, `process_lock.rs` the single-instance lock. |
| `runtime` | `AntiwireRuntime`: starts and stops DNS redirection, firewall rules, flow collection and the schedulers. `context.rs` is the service graph, `host_revert.rs` reverts DNS and firewall state, `rule_retarget.rs` moves an application's rules to its updated executable, `keystore.rs` picks the key store that protects the database. |
| `ipc` | The gRPC server. `handlers/` has one file per API area, `proto_bridge/` converts between domain and wire types, `auth.rs` is the token, `ipc_tls.rs` the certificate, `endpoint.rs` where it listens, `stream.rs` the streaming RPCs. |
| `proto` | `proto/antiwire.proto`, the one `AntiwireService`, and its generated types. The client loads the same file at runtime. |
| `services` | What the handlers call; nothing here knows about gRPC. `rule_service/`, `hosts_blocklist/`, `geo_database/`, `network_mapping/`, `ai_decisions/`, `domain_lookup/`, `doh.rs` (the block on public DoH resolvers), `settings_service.rs` and `settings_feed.rs`, `sync_runner.rs` and `background.rs` (scheduled downloads), `assemble.rs` (wires them together). |
| `events` | Domain events and fan-out hubs. Producers publish here; `ipc` subscribes and converts. |

### DNS

| Crate | What it holds |
|---|---|
| `dns` | The resolver stub. `udp_server.rs`, `tcp_server.rs` and `listener.rs` take queries, `query_engine/` answers them, `upstream/` forwards, `response_cache/` caches. Blocking: `policy_adapter.rs` (rules and blocklists), `block/` (responses and signals), `ai/` (the AI gate), `new_domain.rs` (young domains), `rebinding.rs`, `special_use.rs`, `provider_block.rs` (an upstream's own block). Attribution: `port_mapper.rs` and `owner_worker.rs`. `interceptor.rs` starts and stops it, and `lifecycle.rs` does so when settings change; `network_watch.rs` handles network changes and resume. |
| `dns-redirect` | **The only way to change the host's DNS settings.** See [system DNS](#system-dns). |
| `dns-os` | The per-OS calls underneath `dns-redirect`: `linux.rs`, `macos.rs`, `windows/` (including `boot_heal.rs`), `redirect_journal.rs`. |

### Traffic

| Crate | What it holds |
|---|---|
| `flow` | netmetrics events to `connection_logs`. `bridge/` consumes the collector, `tracker/` owns flows (`attribution.rs`, `lifecycle.rs`, `persistence.rs`, `degradation.rs`), `process_resolver/` and `app_resolver.rs` name the process, `system_services/` attributes OS-originated requests, `correlator.rs` and `dns_block_recorder/` record blocked DNS queries, `domain_stats.rs` aggregates. |
| `capture` | On-demand packet capture through Npcap or libpcap: `session.rs`, `native.rs`, `app_filter.rs`. |
| `netmap` | LAN device discovery: `scan.rs`, `state.rs`. |
| `geo` | GeoIP (`geo.rs`, MaxMind databases on disk) and MAC vendor lookups (`oui.rs`). |

### Policy and enforcement

| Crate | What it holds |
|---|---|
| `policy` | Pure evaluation, no I/O. Rules: `rule.rs`, `rule_engine/` (`evaluate.rs`, `mutate.rs`, `dns_index.rs`, `boot_gate.rs`), `rule_index.rs`. Blocklists: `blocklist.rs`, `blocklist_line.rs`, `hosts.rs`, and `blocklist_catalog.rs` (the built-in list catalog). `app_identity.rs` decides which executable paths are the same application; `normalize.rs` normalizes rules, hostnames and networks. |
| `enforce` | Turns `policy::EnforcementOp` into host firewall rules through `firew-rs`: `mapping.rs`, `country.rs`, `filter.rs`, `worker.rs`. |

### Storage, secrets and outbound requests

| Crate | What it holds |
|---|---|
| `store` | The libSQL database. `migrations/` has the numbered SQL schema changes, `db.rs` is the connection, `models.rs` has the row types, `store/query/` has one file per table group (`connection_logs.rs`, `firewall.rs`, `dns.rs`, `dns_redirect.rs`, `settings.rs`, `alerts.rs`, `history.rs`, `retention.rs`, and others), `crypto.rs` encrypts sensitive settings. |
| `secrets` | The key store (`keystore.rs`), zeroized secret types, private files (`private_file.rs`, `acl.rs`), and the local group allowed to use the daemon (`group.rs`). |
| `http` | **The only outbound HTTP client.** It refuses destinations on this machine or the local network, so every request goes through it. |
| `downloader` | Blocklist and hosts downloads: size limits, gunzip, hash checks (`hosts/`). |
| `lookup` | Domain registration records from IANA, RDAP and WHOIS, plus certificate transparency (`ct.rs`). |
| `aibackend`, `ai` | The TypeSafe AI client, and domain classification on top of it. |
| `update` | The self-updater. `trust.rs` (repository and signing key), `channel.rs`, `manifest.rs`, `service.rs` (checks and status), `apply.rs` (the swap, run by the helper), `package*.rs` (Linux packages), `service_control/` (systemd, launchd). Design: `tasks/update-plan.md`. |

### Shared homes

Put shared code here instead of copying it:

| Kind of code | Home |
|---|---|
| Cache sizes, timeouts, queue lengths | `tuning` |
| Outbound HTTP | `http` |
| Events between producers and the API | `events` |
| Rule, hostname and network normalization; application identity | `policy` |
| SIEM export, log retention, crash log, code-signing checks | `platform` |
| Test fakes other crates need | the owning crate's `test_support.rs`, behind its `test-support` feature |

## Unsafe code

The daemon runs as SYSTEM or root and reads input from the network and from unprivileged local
users. A memory-safety bug here is a privilege escalation, so treat every `unsafe` block as
security-critical code. These rules also apply in `firew-rs` and `netmet-rs`, which add their
own. [Operating system calls](#operating-system-calls) covers what the call itself must get right.

**Avoid it.**

- Use a safe API first: `std`, or a safe function of the `windows` or `windows-service` crate.
  `unsafe` is for calling the operating system when no safe equivalent exists.
- Never use it for speed or to get past the borrow checker. No `get_unchecked`,
  `unwrap_unchecked`, `from_utf8_unchecked`, `unreachable_unchecked`, `transmute` or `static mut`.
- Reuse the wrapper that exists before writing a native call again. Most native code is in
  `antiwire-daemon/src/daemon/windows/` (service, privileges, sessions), `antiwire-platform`
  (`code_signing.rs`, `process_wait.rs`), `antiwire-secrets` (`acl.rs`, `group.rs`,
  `windows.rs`), `antiwire-dns-os` (`windows/native.rs`, `linux.rs`),
  `antiwire-flow/src/process_resolver/`, `antiwire-dns/src/udp_socket.rs` and
  `antiwire-capture/src/native.rs`. Firewall calls belong in `firew`, and flow telemetry in
  `netmet`.

**Contain it.**

- Opt in as narrowly as possible: `#[expect(unsafe_code, reason = "...")]` on the item, or
  `#![allow(unsafe_code)]` at the top of a module that is all native calls. Never on a crate.
- Put the call inside a small safe function whose signature makes misuse impossible. Nothing
  outside the module sees a raw pointer or handle.
- Keep each block to the one operation that needs it.
- A native handle or allocation lives in a type that releases it in `Drop`, exactly once.

**Prove it.**

- Every `unsafe` block has a `// SAFETY:` comment directly above it that says why each
  requirement of the call holds here. It does not restate what the call does.
- Every `unsafe fn` and `unsafe trait` has a `# Safety` section saying what the caller must
  guarantee. Prefer a safe function that checks over an `unsafe fn` that trusts.
- `unsafe impl Send` or `Sync` needs the same written proof. Prefer a design that needs neither.
- A block you edit that has no `// SAFETY:` comment gets one.

**Guard the boundary.**

- **Check every result:** the return code, `GetLastError` or `errno`, a null pointer, and the
  length written. Never read an output buffer after a failed call.
- **Lengths, counts and offsets from outside are untrusted,** whether they come from the OS, the
  network, a file or another process. Convert with `try_from`, do arithmetic with `checked_*`,
  and check bounds before building a slice. No `as` cast that can truncate or change sign.
- **A pointer must not outlive what it points to.** Keep the owning `Vec`, `CString` or wide
  string in a named binding until the call returns; a temporary is freed at the end of its
  statement.
- **Strings for the OS are NUL-terminated and have no interior NUL.** Reject one; do not truncate.
- **Structures the OS fills:** set the size field (`cbSize`, `cbStruct`). Use `mem::zeroed` only
  where all-zero is a valid value of the type, and `assume_init` only after the call reported
  success and wrote the whole value.
- **Read unaligned or foreign-layout bytes with `from_le_bytes` or `ptr::read_unaligned`,** never
  by casting the pointer to a struct.
- **Never unwind across a native boundary.** A callback the OS calls catches panics and does the
  minimum.
- **Load a library only by absolute path:** a system library from its system directory, and one
  the daemon downloads only after its hash matches a pinned value. Never by bare name, and
  never from a directory an unprivileged user can write.

**Test it.** Each safe wrapper has a test that calls it, with a failure path where the OS allows
one. Say in the commit message that the change adds or edits `unsafe`, so a reviewer reads those
lines first.

## Operating system calls

Every call into the operating system changes or reads state the daemon does not own, whether it
goes through an API or through a program such as `netsh`, `pfctl` or `systemctl`. A wrong
argument can cut the host off the network. These rules also apply in `firew-rs` and `netmet-rs`.

### Read the official documentation first

Before you write or change any system call, command or native declaration, read its official
documentation and follow it. Do not rely on memory, on a forum answer, or on what another call
site happens to do.

| Platform | Source |
|---|---|
| Windows APIs, COM, WFP, ETW, PowerShell, `netsh` | Microsoft Learn (`learn.microsoft.com`) |
| Linux system calls, `/proc`, netlink | The man-pages project (`man7.org`) and `docs.kernel.org` |
| `nft`, `iptables`, `ipset`, `systemctl`, `resolvectl` | Each tool's own man page and project documentation |
| macOS APIs and tools | Apple's developer documentation and the tool's man page |
| A third-party library | The header and documentation of the exact version in use |

- **Check all of it:** each parameter and its unit, the return value and error convention, who
  frees what and with which function, thread requirements, the privilege needed, the minimum OS
  version, and the remarks about failure.
- **Cite it.** Name the page in the wrapper's doc comment or its `// SAFETY:` comment, as a link
  or a man page reference such as `pfctl(8)`, so a reviewer can check the claim.
- **Do not depend on undocumented behavior.** If the documentation does not cover what you need,
  or you cannot reach it, say so instead of guessing. Where there is no alternative, isolate the
  call, mark it as undocumented, detect at run time whether it works, and fail visibly.
- **Then prove it on a real system.** Documentation says what should happen; an
  [elevated test](#elevated-tests) shows what does.

### Commands

- **Prefer a native API.** Run a program only when no API exists or the program is the
  documented interface. The Windows DNS path does this: `windows/native.rs` first, PowerShell as
  the fallback.
- **Never go through a shell.** Use `Command::new(program)` with each argument passed to `arg`.
  No `sh -c`, and no `cmd /c` or `powershell -Command` line built by formatting values into it.
  When an interpreter is unavoidable, the script is a constant and values reach it through
  stdin. For a Windows command line, use `antiwire-dns-os/src/windows/command_line.rs`; do not
  quote by hand.
- **Name the program by absolute path** in a system directory, as the macOS code does
  (`/sbin/pfctl`, `/usr/bin/ditto`). A bare name is looked up on `PATH`, which a privileged
  process must not trust. Give a call site its full path when you touch it.
- **Validate every argument** against the type or character set the tool accepts before it is
  passed. A value that came from the network, a file, the client or another process never
  reaches a command unvalidated.
- **Bound every child.** Give it a timeout, kill it when the timeout passes or the daemon stops,
  and limit how much output is read. `antiwire-dns-os/src/windows/command.rs` runs children in a
  kill-on-close job.
- **Set the environment deliberately.** Pass what the tool needs (`DEBIAN_FRONTEND` for `apt-get`,
  `LC_ALL=C` when output is parsed) and do not let an inherited variable change its behavior.
- **Check the exit status, then parse strictly.** A failed command is an error, never an empty
  result. Prefer a machine format (`nft -j`, `ConvertTo-Json`, an exit code) to text meant for
  people, which changes with the locale and the tool's version.
- **Never put a secret on a command line.** Other processes can read it. Use stdin or a private
  file.
- **Save before you change, and read back after.** A command that changes host state records the
  original first and confirms the new state afterwards, as [system DNS](#system-dns) does.
- **Keep argument building pure and tested.** Build the argument list in a function that runs
  nothing, test it, and test each parser against output captured from the real tool.

### ABI

- **Use the binding that exists:** `windows`, `windows-service` and `libc` for this workspace.
  Never declare by hand a function, structure or constant they provide.
- **A hand-written declaration is copied from the official header** of the exact version in use,
  and its comment names that header. Today those are the pcap declarations in
  `antiwire-capture/src/native.rs` and the WinDivert ones in `netmetrics-windows`.
- **Match the layout exactly.** `#[repr(C)]` on every structure, packing only where the header
  packs, and the header's integer widths: a `DWORD` is `u32`, a `BOOL` is `i32`, and
  `SIZE_T` or `ULONG_PTR` is `usize`. Never `bool`, `char` or a Rust `enum` across the boundary.
- **Assert the layout at compile time.** Check `size_of` and `offset_of!` against the documented
  values in a `const` assertion, so a wrong field fails the build.
- **Match the calling convention:** `extern "system"` for Win32, `extern "C"` for C libraries.
- **Layouts change with the architecture and the OS version.** Releases ship x86-64 and ARM64,
  so nothing may assume a pointer width or an alignment. Fill in the size or version field the
  API asks for, and check at run time before using a field newer than the oldest supported OS.
- **Follow the documented ownership.** Free memory with the function the API names, and no other.
  Know which side owns each buffer, whether a size counts bytes or characters, and whether it
  includes the terminator.
- **Follow the documented conventions.** `BOOL`, `HRESULT`, `NTSTATUS` and Win32 error codes
  report failure differently, and an invalid handle is `NULL` for some APIs and
  `INVALID_HANDLE_VALUE` for others. Text is UTF-16 for `W` functions.

## System DNS

Anything that changes the host's DNS settings to point at the resolver, or puts them back, goes
through `antiwire-dns-redirect`: `DnsRedirect` for a running resolver, `restore_orphaned` for
what a dead daemon left. No other crate calls `antiwire-dns-os` for DNS, so every caller follows
the same rules: originals are saved before anything changes, and the record is cleared only
after a confirmed restore. The record is the store's `dns_redirect` table, which only that crate
writes, plus a journal in the data directory.

The port-53 divert, which catches DNS sent past those settings, is separate:
`netmetrics::dns_divert`. Tests fake the OS with `RedirectBackend`, never the host's adapters.

## Elevated tests

Rule enforcement (INetFw/WFP), kernel ETW accounting and DNS redirection all need Administrator.
All are `#[ignore]`d, so a plain `cargo test` skips them; run them with `-- --ignored`.

### On Windows

`sudo.exe` ships with Windows 11 and is on `PATH`. It runs in **Force New Window** mode here, so
output goes to a window you cannot read. Build unelevated, then run the built test binary from a
`.cmd` script that writes to a file:

```powershell
cargo test -p antiwire-flow --test live_byte_pipeline --no-run
$out = "$env:TEMP\antiwire_test.txt"
$cmd = "$env:TEMP\antiwire_test.cmd"
$exe = (Get-ChildItem target\debug\deps\live_byte_pipeline-*.exe | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
Set-Content $cmd -Encoding ascii @"
@echo off
net session >nul 2>&1 && (echo ELEVATED=yes) > "$out" || (echo ELEVATED=no) > "$out"
"$exe" --ignored --nocapture >> "$out" 2>&1
"@
sudo $cmd
```

- **Do not pass an inline `sudo cmd /c "... > file"` from PowerShell 7.** It re-quotes the
  embedded quotes, `cmd` never runs the redirect, and `sudo` still exits 0, so the run looks
  like it happened when it did not.
- **`sudo` returns when the prompt is accepted, not when the test finishes.** Wait until `$out`
  contains `test result`, then check that its first line is `ELEVATED=yes`. No file means the
  prompt was declined or never shown.
- `logman query -ets`, `SetPerTcpConnectionEStats`, and anything touching WFP or adapter DNS
  settings need elevation too.

### Tests in this workspace

| Test | Needs |
|---|---|
| `antiwire-flow/tests/live_byte_pipeline.rs` | Kernel ETW; proves bytes reach the store |
| `antiwire-capture/tests/live_capture.rs` | Npcap or libpcap with capture permission; the application-capture case also needs a loopback capture interface |
| `antiwire-enforce/tests/live_firewall.rs` | Administrator and native firewall access |
| `antiwire-enforce/tests/stale_test_rules.rs` | Administrator; **deletes** the inbound "Query User" rules Windows creates for each rebuilt test binary under a `deps` directory |
| `antiwire-dns-os/tests/windows_dns_redirect.rs` | Elevated shell; **modifies adapter DNS settings** |
| `antiwire-dns-redirect/tests/live_redirect.rs` | Elevated shell or root; **points the host's DNS at 127.0.0.1** for a few seconds, then restores it. With an installed daemon redirecting DNS, the adapters already point at loopback, so the round trip proves less |

The `netmetrics` and `firew` tests are listed in their own guides. Running an elevated
`netmetrics` collector test stops the ETW session a running daemon is using; see
[ETW sessions](packages/netmet-rs/AGENTS.md#etw-sessions-outlive-their-process).

### Native or Docker: pick by host

Run a platform's tests natively when you are on that platform. Use Docker only for a platform
you are not on.

| Host | Windows tests | Linux tests |
|---|---|---|
| Windows | **Native**, elevated as above. Do not use the Windows image. | Docker (Linux image) |
| Linux | — | **Native**, elevated with `sudo`. Do not use the Linux image. |
| macOS | Docker (Windows image) | Docker (Linux image) |

macOS tests always run natively on macOS. Docker Desktop for Mac runs Linux containers only, so
the Windows image there needs a Windows Docker engine reached through `docker context`. If none
is available, say the Windows tests were not run.

Without running anything, a cross-target check still catches type and lint errors:

```bash
cargo check -p netmetrics-linux --target x86_64-unknown-linux-gnu --all-targets
cargo check -p netmetrics-macos --target x86_64-apple-darwin --all-targets
```

### Linux image

`docker/linux-test.Dockerfile` covers all three workspaces. Build from this directory, not the
repository root:

```bash
docker build -f docker/linux-test.Dockerfile -t antiwire-rs-linux-test .
```

| Mode | Command | Needs |
|---|---|---|
| `offline` (default) | `docker run --rm antiwire-rs-linux-test` | nothing |
| `live` | `docker run --rm --cap-add=NET_ADMIN antiwire-rs-linux-test live` | `NET_ADMIN` |
| `ebpf` | `docker run --rm -v /sys/kernel/btf:/sys/kernel/btf:ro antiwire-rs-linux-test ebpf` | host BTF |
| `all` | both flags together | both |
| `shell` | drops into the container | — |

`offline` runs the unprivileged suites of all three workspaces with `--all-features`. `live` adds
the `#[ignore]`d `firew-linux` tests; a container grants `CAP_NET_ADMIN` without touching the
host firewall. `ebpf` builds the CO-RE object, which needs a kernel built with
`CONFIG_DEBUG_INFO_BTF`. The entrypoint checks for the capability and the BTF mount first and
fails with a specific message. GitHub builds this image only for the privileged Linux tests.

### Windows image

Use it from macOS only. `docker/windows-test.Dockerfile` runs the daemon and the elevated Windows
tests in a disposable container, where `ContainerAdministrator` is already elevated, so nothing
goes through `sudo` and tests change the container, not the host. It needs a Docker engine in
Windows containers mode.

```powershell
docker build -f docker/windows-test.Dockerfile -t antiwire-rs-windows-test .
docker run --rm --isolation=hyperv antiwire-rs-windows-test <mode>
```

| Mode | What it does |
|---|---|
| `offline` (default) | Unprivileged suites for all three workspaces |
| `daemon` | Starts `antiwire-daemon --no-service --foreground`, waits for the gRPC listener, checks it stays up, prints its logs |
| `live` | The `#[ignore]`d firewall, kernel ETW and DNS redirect tests |
| `all` | All three |
| `shell` | PowerShell prompt in the container (add `-it`) |

`daemon` honours `ANTIWIRE_LISTEN` (default `127.0.0.1:50051`) and `ANTIWIRE_DAEMON_TIMEOUT`
(seconds, default 60); pass them with `-e`.

- **Always use `--isolation=hyperv`.** Process isolation shares the host kernel, so the
  container's ETW sessions would stop a host daemon's, and the host build would have to match
  the `ltsc2022` base image.
- **The WinDivert test is not run.** Containers cannot load its kernel driver.
- **`live` prints the state of the `mpssvc` and `BFE` services first.** If either is missing or
  stopped, the firewall tests fail, and that points to the container, not to Antiwire.
- **`live_inetfw_address_set_ceiling` is skipped.** It is a slow measurement, not a check.
- **A container is not a real Windows machine.** It catches regressions in start-up and
  enforcement. Before claiming a change works on Windows, run it natively there.
