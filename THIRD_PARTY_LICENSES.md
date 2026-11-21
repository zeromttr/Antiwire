# Third-party licenses

Antiwire is MIT licensed (see [LICENSE](LICENSE)). It uses the third-party projects, data, and
runtime components listed below, each under its own license. This file lists **direct**
dependencies only; each package's transitive dependencies carry their own licenses, which are
recorded in `Cargo.lock`, `bun.lock`, and the packages' own metadata.

Versions are those locked at the time of writing. Where a project offers a choice of licenses
(for example `MIT OR Apache-2.0`), Antiwire uses it under either.

## License texts

| License | Text |
| --- | --- |
| MIT | https://opensource.org/license/mit |
| Apache-2.0 | https://www.apache.org/licenses/LICENSE-2.0 |
| BSD-3-Clause | https://opensource.org/license/bsd-3-clause |
| ISC | https://opensource.org/license/isc-license-txt |
| Zlib | https://opensource.org/license/zlib |
| Unlicense | https://unlicense.org/ |
| MPL-2.0 | https://www.mozilla.org/en-US/MPL/2.0/ |
| LGPL-3.0 | https://www.gnu.org/licenses/lgpl-3.0.html |
| GPL-3.0 | https://www.gnu.org/licenses/gpl-3.0.html |
| SIL OFL 1.1 | https://openfontlicense.org/ |
| CC0 1.0 | https://creativecommons.org/publicdomain/zero/1.0/ |
| CC BY-NC 4.0 | https://creativecommons.org/licenses/by-nc/4.0/ |

## Runtime components

These are not compiled into Antiwire. They are downloaded at runtime or installed by the user.

| Component | Used for | How it is obtained | License |
| --- | --- | --- | --- |
| [WinDivert](https://reqrypt.org/windivert.html) 2.2.2 | Windows flow ownership and DNS diversion, when the user turns it on | Official signed package downloaded from reqrypt.org and loaded dynamically, only once the user turns WinDivert on; not statically linked | LGPL-3.0 |
| [Npcap](https://npcap.com/) | Windows packet capture | Installed by the user | [Npcap License](https://github.com/nmap/npcap/blob/master/LICENSE) |
| [libpcap](https://www.tcpdump.org/) | Linux and macOS packet capture | System library | BSD-3-Clause |
| WebView2 Loader | Windows desktop UI | Microsoft redistributable shipped by the installer | [Microsoft WebView2 terms](https://developer.microsoft.com/microsoft-edge/webview2/) |

## Data

| Data | Used for | How it is obtained | License |
| --- | --- | --- | --- |
| [MaxMind GeoLite2 City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | GeoIP lookup | Downloaded at runtime | [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) |
| [ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks) | Country firewall rules | Bundled in the client | CC0 1.0 |
| IEEE OUI registry | MAC vendor lookup | Bundled in the daemon | [IEEE Registration Authority](https://standards.ieee.org/products-programs/regauth/) terms |
| [HaGeZi DNS blocklists](https://github.com/hagezi/dns-blocklists) | Optional blocklists; abused-TLD list bundled as `data/hagezi-abused-tlds.txt` | Downloaded at runtime / bundled | GPL-3.0 |
| [StevenBlack/hosts](https://github.com/StevenBlack/hosts) | Optional blocklist | Downloaded at runtime | MIT |
| [1Hosts](https://github.com/badmojr/1Hosts) | Optional blocklist | Downloaded at runtime | MPL-2.0 |
| [URLhaus via malware-filter](https://gitlab.com/malware-filter/urlhaus-filter) | Optional blocklist | Downloaded at runtime | CC0 1.0 / MIT |
| [Phishing Army](https://phishing.army/) | Optional blocklist | Downloaded at runtime | CC BY-NC 4.0 (non-commercial use) |
| [someonewhocares.org hosts](https://someonewhocares.org/hosts/) | Optional blocklist | Downloaded at runtime | Project's own terms |

## Fonts

| Font | License |
| --- | --- |
| [IBM Plex Sans](https://github.com/IBM/plex) (via `@fontsource/ibm-plex-sans` 5.3.0) | SIL OFL 1.1 |
| [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) (via `@fontsource/jetbrains-mono` 5.3.0) | SIL OFL 1.1 |
| [Cascadia Mono](https://github.com/microsoft/cascadia-code) (used if installed; not bundled) | SIL OFL 1.1 |

## Desktop client (JavaScript)

Shipped in the application:

| Package | Version | License |
| --- | --- | --- |
| [electron](https://github.com/electron/electron) | 45.2.1 | MIT |
| [react, react-dom](https://github.com/facebook/react) | 19.3.1 | MIT |
| [react-router](https://github.com/remix-run/react-router) | 8.5.1 | MIT |
| [@radix-ui/react-alert-dialog, @radix-ui/react-dialog](https://github.com/radix-ui/primitives) | 1.2.1, 1.3.1 | MIT |
| [@tanstack/react-virtual](https://github.com/TanStack/virtual) | 3.14.24 | MIT |
| [lucide-react](https://github.com/lucide-icons/lucide) | 1.66.0 | ISC |
| [clsx](https://github.com/lukeed/clsx) | 2.1.1 | MIT |
| [@internationalized/date](https://github.com/adobe/react-spectrum) | 3.12.4 | Apache-2.0 |
| [@inlang/paraglide-js](https://github.com/opral/paraglide-js) | 2.29.3 | MIT |
| [@grpc/grpc-js, @grpc/proto-loader](https://github.com/grpc/grpc-node) | 1.14.7, 0.8.1 | Apache-2.0 |
| [zod](https://github.com/colinhacks/zod) | 4.6.7 | MIT |

Electron bundles Chromium and Node.js, each under its own licenses. The packaged app ships
their full texts as `LICENSES.chromium.html` and `LICENSE.electron.txt` next to the executable.

Build and development tools (not shipped):

| Package | Version | License |
| --- | --- | --- |
| [electron-builder](https://github.com/electron-userland/electron-builder) | 26.18.0 | MIT |
| [electron-vite](https://github.com/alex8088/electron-vite) | 6.0.0 | MIT |
| [@electron/fuses](https://github.com/electron/fuses) | 2.1.3 | MIT |
| [vite](https://github.com/vitejs/vite) | 8.3.5 | MIT |
| [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react) | 6.1.2 | MIT |
| [typescript](https://github.com/microsoft/TypeScript) | 6.0.2 | Apache-2.0 |
| [eslint](https://github.com/eslint/eslint), [@eslint/js](https://github.com/eslint/eslint) | 10.14.0, 10.0.1 | MIT |
| [eslint-plugin-react-hooks](https://github.com/facebook/react) | 7.1.1 | MIT |
| [typescript-eslint](https://github.com/typescript-eslint/typescript-eslint) | 8.72.1 | MIT |
| [globals](https://github.com/sindresorhus/globals) | 17.13.0 | MIT |
| [prettier](https://github.com/prettier/prettier) | 3.9.10 | MIT |
| [@inlang/plugin-m-function-matcher](https://github.com/opral/inlang) | 2.4.0 | MIT |
| [@inlang/plugin-message-format](https://github.com/opral/inlang) | 4.5.6 | MIT |
| [@playwright/test](https://github.com/microsoft/playwright) | 1.64.1 | Apache-2.0 |
| [@types/node](https://github.com/DefinitelyTyped/DefinitelyTyped), [@types/react, @types/react-dom](https://github.com/DefinitelyTyped/DefinitelyTyped) | 26.6.5, 19.3.0 | MIT |
| [bun-types](https://github.com/oven-sh/bun) | 1.4.5 | MIT |

## Rust crates

Direct dependencies of the daemon (`src/antiwire-rs`) and its nested `netmet-rs` and `firew-rs`
workspaces.

| Crate | Version | License |
| --- | --- | --- |
| [aes](https://github.com/RustCrypto/block-ciphers) | 0.8.4 | MIT OR Apache-2.0 |
| [aes-gcm](https://github.com/RustCrypto/AEADs) | 0.10.3 | Apache-2.0 OR MIT |
| [ahash](https://github.com/tkaitchuck/ahash) | 0.8.12 | MIT OR Apache-2.0 |
| [anyhow](https://github.com/dtolnay/anyhow) | 1.0.104 | MIT OR Apache-2.0 |
| [arc-swap](https://github.com/vorner/arc-swap) | 1.9.2 | MIT OR Apache-2.0 |
| [async-std](https://github.com/async-rs/async-std) | 1.13.2 | Apache-2.0 OR MIT |
| [async-trait](https://github.com/dtolnay/async-trait) | 0.1.91 | MIT OR Apache-2.0 |
| [atomic-write-file](https://github.com/andreacorbellini/rust-atomic-write-file) | 0.3.0 | BSD-3-Clause |
| [aya](https://github.com/aya-rs/aya) | 0.13.1 | MIT OR Apache-2.0 |
| [base64](https://github.com/marshallpierce/rust-base64) | 0.22.1 | MIT OR Apache-2.0 |
| [bytes](https://github.com/tokio-rs/bytes) | 1.12.1 | MIT |
| [cbc](https://github.com/RustCrypto/block-modes) | 0.1.2 | MIT OR Apache-2.0 |
| [clap](https://github.com/clap-rs/clap) | 4.6.4 | MIT OR Apache-2.0 |
| [crossbeam-queue](https://github.com/crossbeam-rs/crossbeam) | 0.3.14 | MIT OR Apache-2.0 |
| [dashmap](https://github.com/xacrimon/dashmap) | 6.2.1 | MIT |
| [data-encoding](https://github.com/ia0/data-encoding) | 2.11 | MIT |
| [directories](https://github.com/soc/directories-rs) | 6.0.0 | MIT OR Apache-2.0 |
| [ferrisetw](https://github.com/n4r1b/ferrisetw) | 1.2.0 | MIT OR Apache-2.0 |
| [flate2](https://github.com/rust-lang/flate2-rs) | 1.1.9 | MIT OR Apache-2.0 |
| [futures-util](https://github.com/rust-lang/futures-rs) | 0.3.33 | MIT OR Apache-2.0 |
| [getrandom](https://github.com/rust-random/getrandom) | 0.2.17 | MIT OR Apache-2.0 |
| [hickory-proto, hickory-resolver](https://github.com/hickory-dns/hickory-dns) | 0.26.3 | MIT OR Apache-2.0 |
| [hyper-util](https://github.com/hyperium/hyper-util) | 0.1.21 | MIT |
| [ipconfig](https://github.com/liranringel/ipconfig) | 0.3.4 | MIT OR Apache-2.0 |
| [ipnet](https://github.com/krisprice/ipnet) | 2.12 | MIT OR Apache-2.0 |
| [ipnetwork](https://github.com/achanda/ipnetwork) | 0.20.0 | MIT OR Apache-2.0 |
| [iptables](https://github.com/yaa110/rust-iptables) | 0.6.0 | MIT |
| [libc](https://github.com/rust-lang/libc) | 0.2.189 | MIT OR Apache-2.0 |
| [libloading](https://github.com/nagisa/rust_libloading) | 0.8.9 | ISC |
| [lru](https://github.com/jeromefroe/lru-rs) | 0.18.2 | MIT |
| [maxminddb](https://github.com/oschwald/maxminddb-rust) | 0.30.3 | ISC |
| [moka](https://github.com/moka-rs/moka) | 0.12 | (MIT OR Apache-2.0) AND Apache-2.0 |
| [netstat2](https://github.com/ohadravid/netstat2-rs) | 0.11.2 | MIT OR Apache-2.0 |
| [nftables](https://github.com/nftables-rs/nftables-rs) | 0.6.3 | MIT OR Apache-2.0 |
| [parking_lot](https://github.com/Amanieu/parking_lot) | 0.12.5 | MIT OR Apache-2.0 |
| [pfctl](https://github.com/mullvad/pfctl-rs) | 0.6.1 | MIT OR Apache-2.0 |
| [prefix-trie](https://github.com/tiborschneider/prefix-trie) | 0.9.4 | MIT OR Apache-2.0 |
| [proptest](https://github.com/proptest-rs/proptest) (tests only) | 1.11.0 | MIT OR Apache-2.0 |
| [prost](https://github.com/tokio-rs/prost) | 0.13.5 | Apache-2.0 |
| [protoc-bin-vendored](https://github.com/stepancheg/rust-protoc-bin-vendored) (build only) | 3.2.0 | MIT |
| [rcgen](https://github.com/rustls/rcgen) | 0.13.2 | MIT OR Apache-2.0 |
| [reqwest](https://github.com/seanmonstar/reqwest) | 0.12.28 | MIT OR Apache-2.0 |
| [rusqlite](https://github.com/rusqlite/rusqlite) (bundles [SQLite](https://sqlite.org/copyright.html), public domain) | 0.32.1 | MIT |
| [serde](https://github.com/serde-rs/serde) | 1.0.229 | MIT OR Apache-2.0 |
| [serde_json](https://github.com/serde-rs/json) | 1.0.151 | MIT OR Apache-2.0 |
| [serde_path_to_error](https://github.com/dtolnay/path-to-error) | 0.1.20 | MIT OR Apache-2.0 |
| [sha2](https://github.com/RustCrypto/hashes) | 0.10.9 | MIT OR Apache-2.0 |
| [single-instance](https://github.com/WLBF/single-instance) | 0.3.3 | MIT |
| [smallvec](https://github.com/servo/rust-smallvec) | 1.15.2 | MIT OR Apache-2.0 |
| [smol](https://github.com/smol-rs/smol) | 1.3.0 | Apache-2.0 OR MIT |
| [socket2](https://github.com/rust-lang/socket2) | 0.6.5 | MIT OR Apache-2.0 |
| [subtle](https://github.com/dalek-cryptography/subtle) | 2.6.1 | BSD-3-Clause |
| [sysinfo](https://github.com/GuillaumeGomez/sysinfo) | 0.33.1 | MIT |
| [syslog](https://github.com/Geal/rust-syslog) | 6.1.1 | MIT |
| [tempfile](https://github.com/Stebalien/tempfile) | 3.27.0 | MIT OR Apache-2.0 |
| [thiserror](https://github.com/dtolnay/thiserror) | 2.0 | MIT OR Apache-2.0 |
| [time](https://github.com/time-rs/time) | 0.3.55 | MIT OR Apache-2.0 |
| [tokio, tokio-stream, tokio-util](https://github.com/tokio-rs/tokio) | 1.53.1, 0.1.19, 0.7.19 | MIT |
| [tonic, tonic-build](https://github.com/hyperium/tonic) | 0.12.3 | MIT |
| [tower](https://github.com/tower-rs/tower) | 0.5.3 | MIT |
| [tracing, tracing-subscriber](https://github.com/tokio-rs/tracing) | 0.1.44, 0.3.23 | MIT |
| [ureq](https://github.com/algesten/ureq) | 3.4.2 | MIT OR Apache-2.0 |
| [url](https://github.com/servo/rust-url) | 2.5.8 | MIT OR Apache-2.0 |
| [windows, windows-core](https://github.com/microsoft/windows-rs) | 0.62.2, 0.57.0 | MIT OR Apache-2.0 |
| [windows-service](https://github.com/mullvad/windows-service-rs) | 0.8.1 | MIT OR Apache-2.0 |
| [xorf](https://github.com/ayazhafiz/xorf) | 0.13.0 | MIT |
| [zeroize](https://github.com/RustCrypto/utils) | 1.9.0 | Apache-2.0 OR MIT |
| [zip](https://github.com/zip-rs/zip2) | 8.6.0 | MIT |
