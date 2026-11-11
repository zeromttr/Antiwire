# Linux tarball

`antiwire-<version>-linux-<arch>.tar.gz` holds the same files as the `.deb` and `.rpm`,
unpackaged. Prefer a package where your distribution takes one; use the tarball elsewhere.

```text
antiwire-daemon
antiwire-app/            the Electron client; its executable is antiwire-app/antiwire
ebpf/netmetrics.bpf.o
ebpf/dns_filter.bpf.o
antiwire-daemon.service
antiwire.desktop
antiwire.png
scripts/postinstall.sh   the packages' hooks, which install.sh and uninstall.sh run
scripts/preremove.sh
install.sh
uninstall.sh
```

## Install

The daemon needs `nftables`, `iptables`, and `ipset`. Install them first, then:

```bash
sudo ./install.sh
```

This copies the files to the paths the packages use (`/usr/bin`, `/usr/lib/antiwire`,
`/usr/lib/netmetrics`, `/usr/lib/systemd/system`), creates the `antiwire` group, adds the
account that ran `sudo`, and enables and starts `antiwire-daemon.service`. Sign out and
back in before opening Antiwire, so the group membership applies.

## Updates

Installed from the `.deb` or `.rpm`, Antiwire updates itself when you click Install in the
app: the daemon downloads the next release's package, checks it against the release's
signed `manifest-linux.json`, and installs it with your package manager (`apt-get`, `dnf`,
or `zypper`). If the new version does not start, the previous package is reinstalled and
the database restored. The log is `/var/lib/antiwire/update.log`.

A tarball install is told when an update is available but not updated. Download the new
tarball and run its `install.sh` again.

## Uninstall

```bash
sudo ./uninstall.sh
```

The daemon's data directory and the `antiwire` group are left in place.

## Verify the download

Each release publishes `SHA256SUMS` for every asset:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```
