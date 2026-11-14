#!/bin/bash
# The installer package's postinstall script (scripts/package-macos-pkg.sh). Installer has
# copied the package directory to $2 and runs this as root: install.sh does the install,
# as it does for a manual one, and the staged copy is removed.
set -euo pipefail

STAGE="$2"
if [[ ! -f "$STAGE/install.sh" ]]; then
  echo "error: install.sh not found in $STAGE" >&2
  exit 1
fi

bash "$STAGE/install.sh"
rm -rf "$STAGE"
