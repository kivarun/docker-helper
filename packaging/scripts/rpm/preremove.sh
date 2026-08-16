#!/bin/sh
set -eu

# RPM preremove (%preun) — called by rpm before removing package files.
# $1 = 0 (final erase) or >0 (upgrade, another instance remains)

if [ "$1" != "0" ]; then
  exit 0
fi

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
unload_output=$(apparmor_parser -R /etc/apparmor.d/docker-helper-system 2>&1) || {
  echo "warning: failed to unload AppArmor profile docker-helper-system: $unload_output" >&2
}

exit 0
