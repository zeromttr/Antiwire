# Agent guide

Antiwire is a host firewall and network monitor for Windows, Linux and macOS: a privileged Rust
daemon, and an Electron client that talks to it over gRPC.

## Where things are

Read the guide for the area you are changing before you start.

| Path | What it is | Guide |
|---|---|---|
| `src/antiwire-rs` | The daemon and its crates (Rust) | [AGENTS.md](src/antiwire-rs/AGENTS.md) |
| `src/antiwire-rs/packages/firew-rs` | `firew`, the native firewall rule library | [AGENTS.md](src/antiwire-rs/packages/firew-rs/AGENTS.md) |
| `src/antiwire-rs/packages/netmet-rs` | `netmet`, the native flow telemetry library | [AGENTS.md](src/antiwire-rs/packages/netmet-rs/AGENTS.md) |
| `src/antiwire-client` | The desktop client (Electron, React, Bun) | [AGENTS.md](src/antiwire-client/AGENTS.md) |
| `scripts/` | Release, version and CI-planning scripts and their tests (`bun test scripts`) | — |
| `packaging/`, `installer.iss` | Linux packages (nfpm), the macOS installer, the Windows installer (Inno Setup) | — |
| `data/` | The HaGeZi abused-TLD list and its hash, rebuilt by `hagezi-abused-tlds.yml` | — |
| `.github/workflows` | `ci.yml`, `release.yml`, `nightly.yml`, `packages.yml` | below |

## Rules for every change

**No dead code.** When a change leaves something unused, delete it in the same change: functions,
types, fields, parameters, imports, constants, settings, feature flags, IPC commands, message
keys, scripts, test helpers, whole files. Do not comment code out, keep a stub for later, or hide
it from the compiler or linter (`#[allow(dead_code)]`, `#[allow(unused)]`, a `_` prefix,
`eslint-disable`). Git history keeps what was removed. The one exception is the public API of
`firew` and `netmet`: other projects may call it, so it follows each library's compatibility
rules, not Antiwire's call sites.

**No duplication.** Before adding a helper, type, constant, component or script, search for one
that already does the job, and use or extend it. When two places need the same logic, move it to
the shared home for that kind of code (each guide names them) and call it from both. Never copy a
constant, a validation rule, a wire type or a test fixture. The guides follow the same rule: a
fact lives in one of them, and the others link to it.

**Test elevated, or do not claim the result.** Antiwire is a firewall. An unelevated daemon
still runs, but it enforces nothing and reports zero bytes, so an unelevated run proves nothing.
See [elevated tests](src/antiwire-rs/AGENTS.md#elevated-tests). Say what you did not run.

**Keep the README's privacy section true.** It lists every connection Antiwire makes. Change it
with any change to what the daemon or the updater fetches.

**Do not edit any `AGENTS.md` on your own.** This covers every `AGENTS.md` file anywhere in the
repository, including one added later, and creating, moving or deleting one. Such a file changes
only when the user explicitly asks for that change, and only after they confirm the exact edit
you propose. A request to change code is not a request to change a guide. If your work makes a
guide wrong or incomplete, say so and propose the edit; do not make it.

## The repository name

`[workspace.package] repository` in `src/antiwire-rs/Cargo.toml` is the one place the project's
GitHub repository is named. Do not write `github.com/<owner>/antiwire` anywhere else; read it:

| Where | How |
|---|---|
| Daemon (update feed) | `env!("CARGO_PKG_REPOSITORY")` in `antiwire-update/src/trust.rs` |
| Client (main and renderer) | `REPOSITORY_URL` / `releaseUrl()` from `shared/project.ts`, defined at build time by `vite.shared.ts` |
| Workflows and packaging | `node scripts/repository.mjs` (`url`, or `check <owner/name>`); nfpm's homepage is `${ANTIWIRE_REPOSITORY_URL}` |

To move the project, change that line. `release.yml` checks it against `github.repository` and
refuses to release from anywhere else. Installed daemons keep the URL they were built with and
rely on GitHub's redirect for a transferred repository, so never reuse the old name.

`firew-rs` and `netmet-rs` are meant to move to repositories of their own (`zeromttr/firew` and
`zeromttr/netmet`), and their `repository` metadata names those. Nothing reads it. Do not point
it at this repository or read this repository's value from it.

## The product version

Three files state it, and `node scripts/check-versions.mjs` fails when they differ:
`src/antiwire-rs/Cargo.toml` (`[workspace.package]`), `src/antiwire-client/package.json`, and
`ANTIWIRE_VERSION` in `.github/workflows/packages.yml`. Change all three with
`scripts/set-version.mjs`.

## CI

One workflow, `.github/workflows/ci.yml`. Its `plan` job runs `scripts/ci-plan.mjs`, which maps
the changed files to areas, and only those areas' jobs run. Markdown starts nothing. The plan
job's summary lists what it chose and why.

| Change under | Runs |
|---|---|
| `src/antiwire-rs/crates`, its `Cargo.toml`/`Cargo.lock`, its `ci-*-os.sh` scripts | `antiwire-rs` suite |
| `packages/netmet-rs` (not `ebpf/`) | `netmet-rs` suite, and `antiwire-rs`, which depends on it by path |
| `packages/netmet-rs/crates/netmetrics-linux/ebpf` | eBPF object build only |
| `packages/firew-rs` | `firew-rs` suite, and `antiwire-rs` |
| the Linux image, the Windows test entrypoint, `ci-elevated-unix.sh` | nothing, except in an elevated run |
| anything under `src/antiwire-client`, `antiwire-proto/proto` | Bun checks, tests, and build |
| the three version sources, `scripts/` (except the HaGeZi updater) | version check and script tests |
| a `deny.toml` | `cargo deny` only |
| `ci.yml` or `scripts/ci-plan.mjs` | everything |

- **`deny` gates the rest.** It checks `src/antiwire-rs/deny.toml` against `antiwire-rs` and,
  when they changed, `netmet-rs` and `firew-rs`, which have no policy of their own. No other job
  starts until it succeeds. It is skipped, and does not block, when no Rust dependency graph is
  affected.
- **Draft pull requests run nothing** until they are marked ready.
- **Every job has `timeout-minutes`.** Keep one on any job you add; a hung job otherwise bills
  for six hours.
- **Elevated tests run in CI only when a developer asks.** They are `#[ignore]`d, and no pull
  request, push or schedule runs them. `gh workflow run ci.yml --ref <branch> -f elevated=true`
  runs them, and nothing else, as Administrator or root on the `os` runners (`-f scope=all`
  for every suite). On Linux the `firew-rs` ones run in the Linux image.

CI minutes are paid for (macOS costs 10x Linux, Windows 2x), so not every leg runs every time:

| Leg | Pull requests | Pushes to `main` | Scheduled |
|---|---|---|---|
| Ubuntu | yes | yes | — |
| Windows | yes | no (the PR already ran it) | weekly, for areas changed in the last 8 days, to publish their caches |
| macOS | **no** | no | nightly, for areas changed on `main` in the last 25 hours |

**macOS breakage surfaces after merging** unless you test for it first. For a change that could
affect macOS, run its leg on the branch before merging:

```bash
gh workflow run ci.yml --ref <branch> -f os=macos
```

`os` is `all` (default), `ubuntu`, `windows` or `macos`. `windows-arm` and `linux-arm` run the
Rust suites natively on ARM64 Windows and ARM64 Linux; only a dispatch that names one runs it.
`-f scope=all` runs every area instead of the changed ones; a dispatch from `main` needs it, since nothing there differs from `main`.
`packages.yml` calls `ci.yml` with both set to `all` before it builds. Before pushing, check the
other platforms locally: see
[native or Docker](src/antiwire-rs/AGENTS.md#native-or-docker-pick-by-host).

**Only `main` writes caches** (rust-cache archives, Bun packages, the Linux test image). Every other ref reads `main`'s copies and writes nothing. A cache saved on a pull request
is readable only there, but counts against the cache limit. The weekly Windows run and
the macOS nightly check out `main`, so they publish; a dispatch from another branch restores and
does not save. An area nobody edits for a week loses its archives, and its next change builds
once without them.

**CI runs on Blacksmith machines**, the `blacksmith-*` labels in the workflows and in
`RUNNER_LABELS` in `scripts/ci-plan.mjs`. The Blacksmith GitHub App must be installed on the
repository, or those jobs wait in the queue and never start. The rust-cache and Bun archives are
stored in Blacksmith's cache (25 GB a week, an entry is dropped after seven days unused); the
Linux test image's layers stay in GitHub's 10 GB cache. In `release.yml` the jobs
that read the update signing key or write to the repository (`prepare`, `publish`,
`channel-feed`) stay on GitHub's runners, as do `nightly.yml` and the HaGeZi updater. The
`windows-arm` leg stays on GitHub's `windows-11-arm`, because Blacksmith has no ARM64 Windows
machine. The Windows and Linux release builds use 8-vCPU machines.

## Releases and update channels

`release.yml` publishes a `v<version>` tag, and the version picks the update channel: `vX.Y.Z` is
stable, `vX.Y.Z-beta.N` or `vX.Y.Z-rc.N` is beta. Any other prerelease label is refused.

`nightly.yml` publishes nightlies, and only when a developer starts it. It has no schedule, and
an agent must not start it unless asked (`gh workflow run nightly.yml`). It tags
`vX.Y.Z-nightly.DATE.RUN` on a commit that only stamps the version, then calls `release.yml`. Do
not push nightly tags by hand, and do not bump the version on `main` to a nightly.

- `scripts/release-channel.mjs` holds the channel rules and `nightly-version`. It has to agree
  with `antiwire-update/src/channel.rs`.
- The `channel-beta` and `channel-nightly` releases are update feeds that CI rewrites. Never
  delete or edit them.
- The design is in `tasks/update-plan.md`, section 6.
