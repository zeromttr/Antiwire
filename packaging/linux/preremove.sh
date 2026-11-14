#!/bin/sh
set -eu

# What the package manager is doing decides what happens to the service:
#
#   Debian prerm   remove | upgrade NEW | failed-upgrade OLD | deconfigure ...
#   RPM %preun     0 when the package is erased, 1 or more during an upgrade
#   uninstall.sh   no argument
#
# RPM runs the old package's %preun after the new package's %post, so stopping
# the service during an RPM upgrade would stop the daemon the new package had
# just restarted. Disabling it on any upgrade would leave it off after reboot.
action="${1:-}"

if ! command -v systemctl >/dev/null 2>&1; then
  exit 0
fi

case "$action" in
  remove | deconfigure | 0 | "")
    systemctl stop antiwire-daemon.service || true
    systemctl disable antiwire-daemon.service || true
    systemctl daemon-reload || true
    ;;
  upgrade | failed-upgrade)
    # Debian replaces the files next; the new postinst starts the service again.
    systemctl stop antiwire-daemon.service || true
    ;;
  *)
    # An RPM upgrade: the new package's %post has already restarted the service.
    ;;
esac
