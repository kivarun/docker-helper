#!/bin/sh
set -eu

# DEB postinstall — called by dpkg after unpacking.
# $1 = action (configure, abort-upgrade, abort-deconfigure, etc.)

case "$1" in
  configure)
    ;;
  *)
    exit 0
    ;;
esac

# Live-system guard: only do runtime actions on a live system.
if [ ! -d /run/systemd/system ]; then
  exit 0
fi

# Capture whether the service was active before we make changes.
was_active=false
systemctl is-active --quiet docker-helper.service && was_active=true

# DEB packages require AppArmor confinement for system mode.
aa_enabled="$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null | tr -d '[:space:]')" || true
if [ "$aa_enabled" = "Y" ]; then
  if ! apparmor_parser --replace --skip-read-cache /etc/apparmor.d/docker-helper-system; then
    exit 1
  fi
else
  # Check if SELinux is the active MAC (informative only — DEB packages
  # do not install the SELinux module; use the RPM on SELinux hosts).
  selinux_enforcing="$(cat /sys/fs/selinux/enforce 2>/dev/null | tr -d '[:space:]')" || true
  if [ "$selinux_enforcing" = "1" ]; then
    echo "warning: SELinux enforcing but AppArmor is not active; DEB package does not install the SELinux module (system mode will not start)" >&2
  else
    echo "warning: AppArmor LSM is not active; skipping apparmor_parser (system mode will not start)" >&2
  fi
fi

# Reload systemd unit files.
if ! systemctl daemon-reload; then
  exit 1
fi

# Restart only if the service was already active.
if [ "$was_active" = "true" ]; then
  if ! systemctl try-restart docker-helper.service; then
    exit 1
  fi
fi

exit 0
