#!/bin/sh
set -eu

# Only root and members of this group may use the daemon: it makes its IPC socket and
# token group-owned (see IPC_CLIENT_GROUP in antiwire-proto). The group has to exist
# before the daemon starts below. Membership only applies to new logins.
GROUP=antiwire
if ! getent group "$GROUP" >/dev/null 2>&1; then
  groupadd --system "$GROUP"
fi

# The account that ran the package manager through sudo or pkexec.
install_user="${SUDO_USER:-}"
if [ -z "$install_user" ] && [ -n "${PKEXEC_UID:-}" ]; then
  install_user="$(getent passwd "$PKEXEC_UID" | cut -d: -f1)"
fi
if [ -n "$install_user" ] && [ "$install_user" != "root" ]; then
  if usermod -aG "$GROUP" "$install_user"; then
    echo "Added $install_user to the $GROUP group. Sign out and back in before opening Antiwire."
  fi
else
  echo "To let an account use Antiwire, run: sudo usermod -aG $GROUP USERNAME"
fi

# Electron's renderer sandbox needs its setuid helper on kernels without unprivileged
# user namespaces. Package managers do not keep the setuid bit from the archive.
SANDBOX=/usr/lib/antiwire/chrome-sandbox
if [ -f "$SANDBOX" ]; then
  chown root:root "$SANDBOX"
  chmod 4755 "$SANDBOX"
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  # Debian passes "configure" on both install and upgrade. RPM passes the number of
  # versions installed once this one is: 1 on a first install, 2 or more during an
  # upgrade. install.sh passes nothing. Each case runs the new daemon. When a Debian
  # upgrade or removal fails, dpkg runs the old package's postinst with abort-*, after its
  # prerm stopped the service, so that case starts the old daemon again.
  case "${1:-}" in
    configure | abort-upgrade | abort-remove | abort-deconfigure | [1-9]* | "")
      systemctl enable antiwire-daemon.service || true
      systemctl restart antiwire-daemon.service || true
      ;;
  esac
fi
