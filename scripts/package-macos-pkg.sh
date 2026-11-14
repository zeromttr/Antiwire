#!/usr/bin/env bash
# Builds the macOS installer package from the unpacked portable archive.
#
#   scripts/package-macos-pkg.sh --version 0.2.0 --platform macos-aarch64 \
#     --package-dir package/antiwire-0.2.0-macos-aarch64 --out stage
#
# Writes OUT/Antiwire-VERSION-PLATFORM.pkg and prints its path. Run on macOS, from the
# repository root. The package holds the archive's directory as it is (see
# package-archive.sh). Installer copies it to STAGE and runs packaging/macos/pkg-postinstall.sh,
# which hands over to the directory's own install.sh, so the install steps are written once.
set -euo pipefail

usage() {
  echo "usage: $0 --version V --platform OS-ARCH --package-dir DIR --out DIR" >&2
  exit 2
}

VERSION= PLATFORM= PACKAGE_DIR= OUT=
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --version) VERSION="$2" ;;
    --platform) PLATFORM="$2" ;;
    --package-dir) PACKAGE_DIR="$2" ;;
    --out) OUT="$2" ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$VERSION" ] && [ -n "$PLATFORM" ] && [ -n "$PACKAGE_DIR" ] && [ -n "$OUT" ] || usage
[ -d "$PACKAGE_DIR/Antiwire.app" ] && [ -f "$PACKAGE_DIR/install.sh" ] \
  || { echo "error: $PACKAGE_DIR is not an unpacked macOS archive" >&2; exit 1; }

# Where Installer puts the files before the postinstall script installs them for real.
STAGE="/Library/Application Support/Antiwire/installer"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/root" "$WORK/scripts" "$OUT"
OUT="$(cd "$OUT" && pwd)"

# ditto keeps the bundle's symlinks and ad-hoc signature intact.
ditto "$PACKAGE_DIR" "$WORK/root"
cp packaging/macos/pkg-postinstall.sh "$WORK/scripts/postinstall"
chmod +x "$WORK/scripts/postinstall"

# Installer moves a "relocatable" bundle to wherever a copy with the same identifier already
# is, which here would be /Applications/Antiwire.app and leave STAGE without the app.
pkgbuild --analyze --root "$WORK/root" "$WORK/components.plist" >/dev/null
/usr/libexec/PlistBuddy -c 'Set :0:BundleIsRelocatable false' "$WORK/components.plist"

PKG="$OUT/Antiwire-$VERSION-$PLATFORM.pkg"
pkgbuild --root "$WORK/root" \
  --component-plist "$WORK/components.plist" \
  --scripts "$WORK/scripts" \
  --identifier com.antiwire.installer \
  --version "$VERSION" \
  --install-location "$STAGE" \
  "$PKG" >/dev/null

echo "$PKG"
