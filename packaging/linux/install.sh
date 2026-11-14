#!/bin/sh
# Installs Antiwire from the unpacked Linux tarball to the same paths the .deb and .rpm
# use, then runs the packages' post-install hook: it creates the antiwire group, adds the
# account that ran sudo, and enables and starts the systemd service.
#
#   sudo ./install.sh
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "error: run this with sudo: sudo $0" >&2
  exit 1
fi
for f in antiwire-daemon antiwire-app/antiwire ebpf/netmetrics.bpf.o ebpf/dns_filter.bpf.o \
  antiwire-daemon.service antiwire.desktop antiwire.png scripts/postinstall.sh; do
  if [ ! -e "$ROOT/$f" ]; then
    echo "error: $f not found next to install.sh" >&2
    exit 1
  fi
done
for tool in nft iptables ipset; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "warning: $tool is not installed; the daemon needs nftables, iptables and ipset" >&2
  fi
done

# A running daemon holds its binary and eBPF objects open.
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop antiwire-daemon.service 2>/dev/null || true
fi

install -D -m 0755 "$ROOT/antiwire-daemon" /usr/bin/antiwire-daemon
rm -rf /usr/lib/antiwire
mkdir -p /usr/lib
cp -R "$ROOT/antiwire-app" /usr/lib/antiwire
ln -sfn /usr/lib/antiwire/antiwire /usr/bin/antiwire
install -D -m 0644 "$ROOT/ebpf/netmetrics.bpf.o" /usr/lib/netmetrics/netmetrics.bpf.o
install -D -m 0644 "$ROOT/ebpf/dns_filter.bpf.o" /usr/lib/netmetrics/dns_filter.bpf.o
install -D -m 0644 "$ROOT/antiwire-daemon.service" /usr/lib/systemd/system/antiwire-daemon.service
install -D -m 0644 "$ROOT/antiwire.desktop" /usr/share/applications/antiwire.desktop
install -D -m 0644 "$ROOT/antiwire.png" /usr/share/icons/hicolor/128x128/apps/antiwire.png

# With no argument the hook behaves as on a first package install.
sh "$ROOT/scripts/postinstall.sh"
