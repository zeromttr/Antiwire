# macOS package

`antiwire-<version>-macos-aarch64.tar.gz` and `Antiwire-<version>-macos-aarch64.dmg` hold
the same directory, built by `scripts/package-archive.sh` (from `release.yml` and
`packages.yml`):

```text
Antiwire.app
Daemon/antiwire-daemon
Daemon/com.antiwire.daemon.plist
install.sh
uninstall.sh
```

## Install

```bash
chmod +x install.sh uninstall.sh
./install.sh
```

This copies the app to `/Applications`, installs the daemon to
`/usr/local/libexec/antiwire/versions/<version>/daemon/antiwire-daemon`, and loads
`com.antiwire.daemon` via launchd with `--data-dir /var/lib/antiwire` (same default
the release daemon uses on Unix). The version comes from `Antiwire.app`'s
`Info.plist`, and is recorded in `/var/lib/antiwire/install-state.json`.

## Updates

Antiwire installs updates only when you click Install in the app's footer. The
daemon downloads the signed release, then a short-lived helper:

1. unloads the launchd job (`launchctl bootout`), so `KeepAlive` cannot restart the
   old daemon;
2. backs up the database;
3. points the job's `ProgramArguments` at the new version's tree and loads it again;
4. keeps the new version if the same process is still running 15 seconds later, and
   otherwise restores the database and the previous version;
5. replaces `/Applications/Antiwire.app` with the new bundle. Reopen the app to use it.

Its log is `/var/lib/antiwire/update.log`.

Only root and members of the `antiwire` group can use the daemon. `install.sh`
creates the group and adds the account that ran it. To add another account:

```bash
sudo dseditgroup -o edit -a USERNAME -t user antiwire
```

## Build locally

From the repo root:

```bash
cargo build --release -p antiwire-daemon
# (from src/antiwire-rs)

bun install && bun run package:dir
# (from src/antiwire-client; the app is dist/mac*/Antiwire.app)
```
