#!/bin/bash
# Installs Antiwire.app to /Applications and registers the elevated daemon
# via launchd. Run from the unpacked macOS package directory (needs sudo).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
APP_SRC="$ROOT/Antiwire.app"
DAEMON_SRC="$ROOT/Daemon/antiwire-daemon"
PLIST_SRC="$ROOT/Daemon/com.antiwire.daemon.plist"
LABEL="com.antiwire.daemon"
PLIST_DST="/Library/LaunchDaemons/${LABEL}.plist"
# Each version gets its own tree so the updater can swap and roll back without
# overwriting a running binary. See tasks/update-plan.md.
INSTALL_ROOT="/usr/local/libexec/antiwire"
DATA_DIR="/var/lib/antiwire"

if [[ ! -d "$APP_SRC" ]]; then
  echo "error: Antiwire.app not found next to install.sh" >&2
  exit 1
fi
if [[ ! -f "$DAEMON_SRC" || ! -f "$PLIST_SRC" ]]; then
  echo "error: Daemon payload missing under Daemon/" >&2
  exit 1
fi

# The app and the daemon are built as one release, so the bundle's version names
# the daemon's tree too.
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP_SRC/Contents/Info.plist")"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "error: Antiwire.app has no usable version (got '$VERSION')" >&2
  exit 1
fi
DAEMON_DST="$INSTALL_ROOT/versions/$VERSION/daemon/antiwire-daemon"

if sudo launchctl print "system/${LABEL}" >/dev/null 2>&1; then
  sudo launchctl bootout "system/${LABEL}" || true
fi

echo "Installing Antiwire.app to /Applications..."
sudo mkdir -p /Applications
sudo rm -rf /Applications/Antiwire.app
# ditto keeps the bundle's symlinks and code signature intact.
sudo ditto "$APP_SRC" /Applications/Antiwire.app

echo "Installing antiwire-daemon $VERSION..."
sudo mkdir -p "$(dirname "$DAEMON_DST")" "$DATA_DIR"
sudo cp "$DAEMON_SRC" "$DAEMON_DST"
sudo chown -R root:wheel "$INSTALL_ROOT"
sudo chmod 755 "$DAEMON_DST"
# Installs from before the versioned layout kept the daemon here.
sudo rm -f /usr/local/libexec/antiwire-daemon /usr/local/libexec/antiwire-reaper

# A manual install starts a fresh rollback history on purpose: older trees on disk
# are not recorded, so nothing can roll back to them. The updater reads `current`.
printf '{"current":"%s","previous":null,"pending":null,"last_error":null}\n' "$VERSION" |
  sudo tee "$DATA_DIR/install-state.json" >/dev/null

# Only root and members of this group may use the daemon: it makes its IPC socket and
# token group-owned (see IPC_CLIENT_GROUP in antiwire-proto). The group has to exist
# before the daemon starts below.
GROUP="antiwire"
if ! dscl . -read "/Groups/${GROUP}" >/dev/null 2>&1; then
  echo "Creating the ${GROUP} group..."
  sudo dseditgroup -o create -r "Antiwire Users" "$GROUP"
fi
INSTALL_USER="${SUDO_USER:-$USER}"
if [[ "$INSTALL_USER" != "root" ]]; then
  echo "Adding ${INSTALL_USER} to the ${GROUP} group..."
  sudo dseditgroup -o edit -a "$INSTALL_USER" -t user "$GROUP"
fi

echo "Installing LaunchDaemon ${LABEL}..."
sudo cp "$PLIST_SRC" "$PLIST_DST"
# The template names no version; point it at this one. plutil takes the array as a
# single JSON argument, so a path is never split on spaces.
sudo plutil -replace ProgramArguments -json \
  "[\"$DAEMON_DST\",\"--data-dir\",\"$DATA_DIR\"]" "$PLIST_DST"
sudo chown root:wheel "$PLIST_DST"
sudo chmod 644 "$PLIST_DST"
sudo launchctl bootstrap system "$PLIST_DST"
sudo launchctl enable "system/${LABEL}"
sudo launchctl kickstart -k "system/${LABEL}"

echo "Antiwire $VERSION installed. Open /Applications/Antiwire.app to use the UI."
echo "If it cannot connect to the daemon, sign out and back in so the ${GROUP} group applies."
