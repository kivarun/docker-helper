#!/bin/sh
set -eu

# DEB postremove — called by dpkg after package files are removed.
# $1 = action (remove, upgrade, purge, failed-upgrade)

case "$1" in
  remove)
    # Live-system guard.
    if [ -d /run/systemd/system ]; then
      systemctl daemon-reload || echo "warning: daemon-reload failed after removal" >&2
    fi
    exit 0
    ;;
  upgrade)
    exit 0
    ;;
  purge)
    # Remove app-owned persistent/runtime state.
    rm -rf /etc/docker-helper
    rm -rf /var/lib/docker-helper
    rm -rf /run/docker-helper

    # Clean up the legacy managed-roots fragment on purge.
    rm -f /etc/apparmor.d/docker-helper.d/managed-roots
    rmdir /etc/apparmor.d/docker-helper.d 2>/dev/null || true

    exit 0
    ;;
  *)
    exit 0
    ;;
esac
