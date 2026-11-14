#!/usr/bin/env bash
# Builds the portable archive for one platform: the release's plain files, unpackaged,
# under one top-level directory named after the archive.
#
#   scripts/package-archive.sh --os windows --version 0.2.0 --platform windows-x86_64 \
#     --daemon src/antiwire-rs/target/release/antiwire-daemon.exe \
#     --client src/antiwire-client/dist/win-unpacked --out stage
#   scripts/package-archive.sh --os macos --version 0.2.0 --platform macos-aarch64 \
#     --daemon src/antiwire-rs/target/release/antiwire-daemon \
#     --client src/antiwire-client/dist/mac-arm64/Antiwire.app --out stage
#   scripts/package-archive.sh --os linux --version 0.2.0 --platform linux-x86_64 \
#     --daemon src/antiwire-rs/target/release/antiwire-daemon \
#     --client src/antiwire-client/dist/linux-unpacked \
#     --ebpf src/antiwire-rs/packages/netmet-rs/crates/netmetrics-linux/ebpf \
#     --icon src/antiwire-client/resources/icons/128x128.png --out stage
#
# Writes OUT/antiwire-VERSION-PLATFORM.zip on Windows and .tar.gz elsewhere, and prints
# its path. Run from the repository root. Layouts:
#
#   windows  daemon/antiwire-daemon.exe, ui/ (the installed version tree, without setup)
#   macos    Antiwire.app, Daemon/, install.sh, uninstall.sh, README.md
#   linux    antiwire-daemon, antiwire-app/, ebpf/, the systemd unit, the desktop entry,
#            the icon, scripts/, install.sh, uninstall.sh, README.md
set -euo pipefail

usage() {
  echo "usage: $0 --os windows|macos|linux --version V --platform OS-ARCH" \
    "--daemon FILE --client PATH --out DIR [--ebpf DIR --icon FILE]" >&2
  exit 2
}

OS= VERSION= PLATFORM= DAEMON= CLIENT= OUT= EBPF= ICON=
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --os) OS="$2" ;;
    --version) VERSION="$2" ;;
    --platform) PLATFORM="$2" ;;
    --daemon) DAEMON="$2" ;;
    --client) CLIENT="$2" ;;
    --out) OUT="$2" ;;
    --ebpf) EBPF="$2" ;;
    --icon) ICON="$2" ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$OS" ] && [ -n "$VERSION" ] && [ -n "$PLATFORM" ] && [ -n "$DAEMON" ] \
  && [ -n "$CLIENT" ] && [ -n "$OUT" ] || usage

# The version and platform become file names, so only plain values get through.
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
  || { echo "error: bad version '$VERSION'" >&2; exit 1; }
[[ "$PLATFORM" =~ ^[a-z0-9_]+-[a-z0-9_]+$ ]] \
  || { echo "error: bad platform '$PLATFORM'" >&2; exit 1; }
[ -f "$DAEMON" ] || { echo "error: daemon not found: $DAEMON" >&2; exit 1; }
[ -d "$CLIENT" ] || { echo "error: client directory not found: $CLIENT" >&2; exit 1; }

NAME="antiwire-$VERSION-$PLATFORM"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DIR="$WORK/$NAME"
mkdir -p "$DIR" "$OUT"
OUT="$(cd "$OUT" && pwd)"

case "$OS" in
  windows)
    mkdir -p "$DIR/daemon" "$DIR/ui"
    cp "$DAEMON" "$DIR/daemon/antiwire-daemon.exe"
    cp -R "$CLIENT/." "$DIR/ui/"
    ARCHIVE="$OUT/$NAME.zip"
    rm -f "$ARCHIVE"
    # Windows' bsdtar writes a zip when the name ends in .zip; zip is the fallback elsewhere.
    if [ -x /c/Windows/System32/tar.exe ]; then
      /c/Windows/System32/tar.exe -a -c -f "$ARCHIVE" -C "$WORK" "$NAME"
    else
      (cd "$WORK" && zip -qry "$ARCHIVE" "$NAME")
    fi
    ;;

  macos)
    mkdir -p "$DIR/Daemon"
    # ditto keeps the bundle's symlinks and ad-hoc signature intact.
    ditto "$CLIENT" "$DIR/Antiwire.app"
    cp "$DAEMON" "$DIR/Daemon/antiwire-daemon"
    cp packaging/macos/com.antiwire.daemon.plist "$DIR/Daemon/"
    cp packaging/macos/install.sh packaging/macos/uninstall.sh packaging/macos/README.md "$DIR/"
    chmod +x "$DIR/install.sh" "$DIR/uninstall.sh" "$DIR/Daemon/antiwire-daemon"
    ARCHIVE="$OUT/$NAME.tar.gz"
    tar -C "$WORK" -czf "$ARCHIVE" "$NAME"
    ;;

  linux)
    [ -n "$EBPF" ] && [ -n "$ICON" ] || usage
    mkdir -p "$DIR/ebpf" "$DIR/scripts"
    cp "$DAEMON" "$DIR/antiwire-daemon"
    cp -R "$CLIENT" "$DIR/antiwire-app"
    cp "$EBPF/netmetrics.bpf.o" "$EBPF/dns_filter.bpf.o" "$DIR/ebpf/"
    cp "$ICON" "$DIR/antiwire.png"
    cp packaging/linux/antiwire-daemon.service packaging/linux/antiwire.desktop "$DIR/"
    # The package hooks, so a tarball install sets up the group and service the same way.
    cp packaging/linux/postinstall.sh packaging/linux/preremove.sh "$DIR/scripts/"
    cp packaging/linux/install.sh packaging/linux/uninstall.sh packaging/linux/README.md "$DIR/"
    chmod +x "$DIR/antiwire-daemon" "$DIR/install.sh" "$DIR/uninstall.sh" \
      "$DIR/scripts/postinstall.sh" "$DIR/scripts/preremove.sh"
    ARCHIVE="$OUT/$NAME.tar.gz"
    # Owned by root rather than the build runner's uid, as the packages' files are.
    tar -C "$WORK" --owner=0 --group=0 --numeric-owner -czf "$ARCHIVE" "$NAME"
    ;;

  *) usage ;;
esac

echo "$ARCHIVE"
