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

# Unload the AppArmor profile ONLY if it is actually loaded. Absence is a
# normal idempotent success: a host that never loaded our profile (for example
# one now booted under a different MAC backend) must not emit a bogus warning.
# Only a real failure removing a present, loaded profile warns.
if [ -r /sys/kernel/security/apparmor/profiles ] && \
   grep -q '^docker-helper-system ' /sys/kernel/security/apparmor/profiles; then
  unload_output=$(apparmor_parser -R /etc/apparmor.d/docker-helper-system 2>&1) || {
    echo "warning: failed to unload AppArmor profile docker-helper-system: $unload_output" >&2
  }
fi

# Remove the SELinux policy module ONLY if it is actually installed. Absence is
# a normal idempotent success: an AppArmor-only host never installed our module
# and must not emit a bogus "failed to remove" warning. Only a real failure
# removing an installed module warns.
if semodule -l 2>/dev/null | grep -qw docker_helper; then
  semodule -r docker_helper 2>/dev/null || {
    echo "warning: failed to remove SELinux module docker_helper" >&2
  }
fi

exit 0
