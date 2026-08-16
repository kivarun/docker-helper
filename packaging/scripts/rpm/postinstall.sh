#!/bin/sh
set -eu

# RPM postinstall — called by rpm after installing/upgrading.
# $1 = 1 (initial install) or >1 (upgrade/reinstall/parallel)

# Live-system guard.
if [ ! -d /run/systemd/system ]; then
  exit 0
fi

# Capture whether the service was active before we make changes.
was_active=false
systemctl is-active --quiet docker-helper.service && was_active=true

# Load/replace the production AppArmor profile.
if ! apparmor_parser --replace --skip-read-cache /etc/apparmor.d/docker-helper-system; then
  exit 1
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
