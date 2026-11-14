#!/bin/sh
set -eu

# The daemon links its own executable as antiwire-reaper when it starts, so the package
# manager does not know the file and leaves it behind. It goes when the package does, and
# stays through an upgrade, where the new daemon brings it up to date itself.
#
#   Debian postrm  remove | purge | upgrade | failed-upgrade | abort-* ...
#   RPM %postun    0 when the package is erased, 1 or more during an upgrade
#
# A removal keeps the data directory and the antiwire group, so installing again finds the
# rules and the history. `apt purge` asks for those to go too: the directory holds the
# connection history of every account on the machine.
case "${1:-}" in
  remove | 0)
    rm -f /usr/bin/antiwire-reaper
    ;;
  purge)
    rm -f /usr/bin/antiwire-reaper
    rm -rf /var/lib/antiwire
    if getent group antiwire >/dev/null 2>&1; then
      groupdel antiwire || true
    fi
    ;;
esac
