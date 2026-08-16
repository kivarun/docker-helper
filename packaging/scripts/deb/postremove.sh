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
    # TEST_SEAM: override paths for test-controlled execution.
    purge_etc="${PURGE_ETC_DIR:-/etc/docker-helper}"
    purge_lib="${PURGE_LIB_DIR:-/var/lib/docker-helper}"
    purge_run="${PURGE_RUN_DIR:-/run/docker-helper}"
    purge_aadir="${PURGE_AA_DIR:-/etc/apparmor.d/docker-helper.d}"

    rm -rf "$purge_etc"
    rm -rf "$purge_lib"
    rm -rf "$purge_run"

    # Clean up the managed-roots directory if it's empty.
    rmdir "$purge_aadir" 2>/dev/null || true

    exit 0
    ;;
  *)
    exit 0
    ;;
esac
