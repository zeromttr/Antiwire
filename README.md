<div align="center">
  <img src="icon.svg" alt="Antiwire logo" width="256" height="256" />
  <h1>Antiwire</h1>
  <p><strong>An all-in-one network monitoring and security suite, built in Rust</strong></p>

  [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
  [![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org/)
  [![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#platform-support)
</div>

Antiwire is an open-source, cross-platform network monitoring and security suite. It shows
which applications are talking to the network and lets you decide which ones may, combining an
application firewall, DNS filtering, packet capture, local network mapping, and domain threat
lookups in one app.

The daemon, which does the monitoring and enforcement, is written in Rust. The desktop app is
built with React and Electron and talks to the daemon over gRPC.

Antiwire is at version `0.1.0` and under active development.

![Antiwire UI example](UI%20Example.png)

## Features

- Live traffic, active connections per application, and connection history.
- Firewall rules for domains, IP addresses, CIDR ranges, and countries, and on Windows for
  applications.
- DNS filtering with encrypted upstreams (DoH, DoT, DoQ), optional community blocklists, and
  optional blocking of newly registered domains.
- GeoIP lookup, local network mapping, activity analytics, and on-demand packet capture.
- Optional SIEM forwarding (Wazuh, syslog, HTTP webhook).
- Everything is stored locally, with sensitive settings encrypted.

## Platform support

| Platform | Monitoring | Firewall | Rules on applications | DNS redirection |
| --- | --- | --- | --- | --- |
| Windows x64 | ETW (falls back to IP Helper). With WinDivert turned on, also the app that opened each connection, as it opens | Windows Firewall (falls back to WFP) | Yes | WinDivert, once you turn it on |
| Windows ARM64 | ETW (falls back to IP Helper) | Windows Firewall (falls back to WFP) | Yes | None |
| Linux | eBPF (falls back to procfs) | nftables (falls back to iptables) | No | nftables (falls back to iptables) |
| macOS | PKTAP | PF | No | PF |

DNS redirection sends DNS queries that try to skip Antiwire's resolver back through it. On Linux
that covers every program, those running as root included; on macOS programs running as root are
not redirected.

The iptables fallback is for a Linux system without `nft`. Its firewall rules cover IPv4 only:
a rule on an IPv6 address is refused there, and the blocks Antiwire builds itself, on public
DNS-over-HTTPS resolvers and on countries, leave their IPv6 addresses out and say so in the log.

nftables, iptables and PF match addresses and ports, not the program that opened a
connection. So on Linux and macOS Antiwire shows what each application does, but cannot block
one, and the app leaves those controls out. Rules on domains, addresses and countries work on
every platform.

A rule on an address never covers this computer's own loopback range (`127.0.0.0/8` and
`::1`), so blocking a wide range such as `0.0.0.0/0` does not cut programs off from services
on the same machine, Antiwire's resolver among them.

WinDivert is a third-party Windows driver, and Antiwire does not use it unless you turn it
on, in Settings under "DNS & privacy". Anti-cheat software may treat the driver as an integrity
violation: a game may refuse to run, or ban the account. While it is off, Antiwire neither
downloads nor loads it. Which app opened a connection then comes from ETW and the socket tables
alone, and DNS sent straight to another resolver is not redirected (the adapters still point
at Antiwire's resolver). Turning it on downloads the driver from the WinDivert website. After
you turn it off again, Windows keeps the driver loaded until the computer restarts.

WinDivert has no ARM64 driver, so the Windows ARM64 build leaves it out entirely: it never
downloads or loads it, and its settings do not offer it.

iCloud Private Relay does not work on a Mac that runs Antiwire. macOS turns Private Relay off
for as long as an app applies its own packet filter rules
([Apple Support](https://support.apple.com/en-us/102022)), and Antiwire's firewall and DNS
redirection are PF rules. A compatibility mode is being tested: Settings → DNS → Private Relay
compatibility, on macOS only. It is experimental and largely untested. With it on, Antiwire
loads no PF rules at all, so rules on addresses and countries, DNS-over-HTTPS blocking and DNS
redirection are off. Rules on domains and blocklists still apply to lookups made through the
system's DNS settings, and what Private Relay carries, Safari browsing for one, is not filtered.

The daemon needs Administrator or root. Without it, it still runs but cannot enforce rules or
count traffic. When it falls back to a weaker collector, the app shows a degraded state.

## Installed version: prerequisites

If you use a pre-built installer, you don't need Rust or Bun. Install these first so every
feature works.

<details>
<summary>Windows (winget)</summary>

Nothing extra is needed for the app. For packet capture, download and install
[Npcap](https://npcap.com/#download) from its website. WinDivert is optional: on x64,
Antiwire downloads it itself once you turn it on; the ARM64 build does not use it.

</details>

<details>
<summary>Windows (Chocolatey)</summary>

Nothing extra is needed for the app. For packet capture, download and install
[Npcap](https://npcap.com/#download) from its website. WinDivert is optional: on x64,
Antiwire downloads it itself once you turn it on; the ARM64 build does not use it.

</details>

<details>
<summary>Debian / Ubuntu (apt)</summary>

```bash
sudo apt-get install -y libpcap0.8 nftables iptables ipset
```

</details>

<details>
<summary>Fedora (dnf)</summary>

```bash
sudo dnf install -y libpcap nftables iptables ipset
```

</details>

<details>
<summary>macOS</summary>

Nothing extra is needed. macOS already includes libpcap and PF.

The installer package is not signed with an Apple Developer ID, so macOS refuses to open it
on a double-click. Try once, then allow it under System Settings → Privacy & Security → Open
Anyway. Or install it from a terminal:
`sudo installer -pkg Antiwire-<version>-macos-aarch64.pkg -target /`.

</details>

## Building from source

You need [Rust 1.90+](https://rustup.rs/) with a C toolchain (the Visual Studio Build Tools on
Windows) and [Bun](https://bun.sh/). `bun install` downloads Electron itself. For packet
capture, install [Npcap](https://npcap.com/) on Windows or libpcap on Linux and macOS.

<details>
<summary>Windows (winget)</summary>

```powershell
winget install --id Rustlang.Rustup
winget install --id Oven-sh.Bun
winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

For packet capture, download and install
[Npcap](https://npcap.com/#download) from its website.

</details>

<details>
<summary>Windows (Chocolatey)</summary>

```powershell
choco install rustup.install bun visualstudio2022-workload-vctools -y
```

For packet capture, download and install
[Npcap](https://npcap.com/#download) from its website.

</details>

<details>
<summary>Debian / Ubuntu (apt)</summary>

```bash
sudo apt-get update
sudo apt-get install -y build-essential curl wget file pkg-config libssl-dev \
  clang llvm libbpf-dev libpcap-dev nftables iptables
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
curl -fsSL https://bun.sh/install | bash
```

</details>

<details>
<summary>Fedora (dnf)</summary>

```bash
sudo dnf group install -y c-development
sudo dnf install -y curl wget file pkgconf-pkg-config openssl-devel \
  clang llvm libbpf-devel libpcap-devel nftables iptables
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
curl -fsSL https://bun.sh/install | bash
```

</details>

<details>
<summary>macOS (Homebrew)</summary>

```bash
xcode-select --install
brew install oven-sh/bun/bun libpcap
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

</details>

Start the daemon in an elevated terminal, then the app in a second terminal:

```bash
# Administrator terminal (sudo on Linux/macOS), from src/antiwire-rs
cargo run -p antiwire-daemon -- --no-service
```

```bash
# From src/antiwire-client
bun install
bun run dev
```

## Testing

```bash
# From src/antiwire-rs
cargo test --workspace
```

```bash
# From src/antiwire-client
bun test src/lib
```

Tests that change the host firewall or DNS are opt-in. See [AGENTS.md](AGENTS.md) for the
elevated test suites and the Linux Docker image.

## Packaging

- **Windows:** compile [`installer.iss`](installer.iss) with Inno Setup.
- **Linux:** `.deb` and `.rpm` packages from [`packaging/linux`](packaging/linux).
- **macOS:** see [`packaging/macos/README.md`](packaging/macos/README.md).

Each GitHub release has the installers (`.exe`, `.pkg`, `.deb`, `.rpm`), a portable archive of
the plain files for each platform (`.zip` on Windows, `.tar.gz` on macOS and Linux), and
`SHA256SUMS` for every file. Check a download with
`sha256sum --check --ignore-missing SHA256SUMS`.

Releases come in three update channels, chosen in Settings → Updates: **stable**, **beta**
(`-beta.N` and `-rc.N` versions), and **nightly** (development builds the developers publish).
Each channel also gets the releases of the more stable ones.

## Privacy and security

Your connection history, rules, and settings stay on your machine. Antiwire has no telemetry,
analytics, or crash reporting. It checks GitHub for updates, and installs one only when you
click Install.

These are the only connections Antiwire makes to the internet.

**On by default**

| What | Where to | What is sent | Why |
| --- | --- | --- | --- |
| Encrypted DNS | Cloudflare (`1.1.1.1`) by default; you can pick another provider | The domain names your computer looks up | Resolves domains privately over DNS-over-HTTPS instead of plain DNS |
| Update check (release builds) | `github.com`, which serves the files from `*.githubusercontent.com` | Nothing | Reads the signed release manifests of your update channel and the more stable ones, every 6 hours. Nothing is downloaded or installed until you click Install |

**Only if you turn it on**

| What | Where to | What is sent | Why |
| --- | --- | --- | --- |
| WinDivert download (Windows x64 only) | `reqrypt.org` | Nothing | Downloads the official signed driver once, checks its hash, and keeps it locally. A download that fails is tried again, at intervals that grow to an hour, until one succeeds or you turn WinDivert off |
| Blocklists | The list's host (GitHub, jsDelivr, GitLab, or the URL you add) | Nothing | Downloads ad, tracker, and malware block lists, daily by default |
| GeoIP | `cdn.jsdelivr.net` | Nothing | Downloads a country/city database about every 90 days. Lookups then happen locally |
| Newly registered domain blocking | IANA and each domain's registry (RDAP or WHOIS) | Registered domain names (`example.com` for `www.example.com`) | Looks up when each domain was registered and blocks those younger than the age you pick (1 week to 3 months). Dates are cached for a day |
| AI domain classification | `api.typesafe.ai` (needs your API key) | Domain names | Rates unknown domains (ads, tracking, malware) to suggest block or allow |
| SIEM forwarding | The syslog server or webhook you enter | Event details (app, domain, action) | Sends events to your security tools |
| Network map | Your local network only | Local discovery traffic | Finds devices on your LAN. Runs when you click Scan, or on a schedule if you enable it |

**Only when you click**

| What | Where to | What is sent | Why |
| --- | --- | --- | --- |
| Domain lookup | IANA, the domain's registry (RDAP or WHOIS), and `crt.sh` | The domain name | Shows who registered a domain and which subdomains appear in public certificates |
| Check now (Settings → Updates) | `github.com` | Nothing | Reads the release manifests at once instead of at the next scheduled check |
| Install update | `github.com` | Nothing | Downloads the release you confirmed and checks it against the signed manifest. On Linux it also downloads the installed version's package, to roll back to if the new one fails |
| Reputation links | VirusTotal, AlienVault OTX, Talos, urlscan, URLhaus, IBM X-Force, or Google Safe Browsing | The domain name | Opens that site's report in your browser |

Turning off the DNS resolver in settings stops the DNS traffic above.

The daemon can change firewall rules and adapter DNS settings. Only run it where you understand
the effect of those changes.

## Contributing

Contributions are welcome. Open an issue to report a bug or propose a change, or send a pull
request. [Building from source](#building-from-source) and [Testing](#testing) cover what you
need to build Antiwire and run its tests.

## License

Antiwire is distributed under the [MIT License](LICENSE). Third-party software, data, and
fonts keep their own licenses; see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
