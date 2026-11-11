#!/bin/bash
# Removes the Antiwire LaunchDaemon, daemon versions, and app bundle.
set -euo pipefail

LABEL="com.antiwire.daemon"
PLIST_DST="/Library/LaunchDaemons/${LABEL}.plist"
DATA_DIR="/var/lib/antiwire"

if sudo launchctl print "system/${LABEL}" >/dev/null 2>&1; then
  sudo launchctl bootout "system/${LABEL}" || true
fi

sudo rm -f "$PLIST_DST"
# Self-updates add version trees this package never installed, so the whole tree goes.
sudo rm -rf /usr/local/libexec/antiwire
# Installs from before the versioned layout.
sudo rm -f /usr/local/libexec/antiwire-daemon /usr/local/libexec/antiwire-reaper
sudo rm -rf /Applications/Antiwire.app
# The update state describes the removed versions; updates/ is staging only.
sudo rm -rf "$DATA_DIR/install-state.json" "$DATA_DIR/updates"

echo "Antiwire uninstalled. Data under $DATA_DIR and the antiwire group were left in place."
