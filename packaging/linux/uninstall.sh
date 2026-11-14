#!/bin/sh
# Removes what install.sh installed. Keeps the daemon's data directory and the antiwire
# group, as the .deb and .rpm do.
#
#   sudo ./uninstall.sh
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "error: run this with sudo: sudo $0" >&2
  exit 1
fi

sh "$ROOT/scripts/preremove.sh"

# antiwire-reaper is the link the daemon makes of its own executable when it starts.
rm -f /usr/bin/antiwire /usr/bin/antiwire-daemon /usr/bin/antiwire-reaper
rm -rf /usr/lib/antiwire
rm -f /usr/lib/netmetrics/netmetrics.bpf.o /usr/lib/netmetrics/dns_filter.bpf.o
rmdir /usr/lib/netmetrics 2>/dev/null || true
rm -f /usr/lib/systemd/system/antiwire-daemon.service
rm -f /usr/share/applications/antiwire.desktop
rm -f /usr/share/icons/hicolor/128x128/apps/antiwire.png

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
