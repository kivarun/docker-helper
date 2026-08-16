#!/bin/sh
set -eu

# DEB preremove — called by dpkg before removing package files.
# $1 = action (remove, upgrade, deconfigure, failed-upgrade)

case "$1" in
  remove)
    ;;
  *)
    exit 0
    ;;
esac

# Live-system guard.
if [ ! -d /run/systemd/system ]; then
  exit 0
fi

# Stop the service if it is active.
if systemctl is-active --quiet docker-helper.service; then
  if ! systemctl stop docker-helper.service; then
    exit 1
  fi
fi

# Disable the service if it is enabled.
if systemctl is-enabled --quiet docker-helper.service 2>/dev/null; then
  if ! systemctl disable docker-helper.service; then
    exit 1
  fi
fi

# Unload AppArmor profile (best-effort).
if ! apparmor_parser -R /etc/apparmor.d/docker-helper-system 2>/dev/null; then
  echo "warning: failed to unload AppArmor profile docker-helper-system" >&2
fi

exit 0
