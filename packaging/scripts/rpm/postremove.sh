#!/bin/sh
set -eu

# RPM postremove (%postun) — called by rpm after removing package files.
# $1 = 0 (final erase) or >0 (upgrade)

if [ "$1" != "0" ]; then
  exit 0
fi

# Live-system guard.
if [ ! -d /run/systemd/system ]; then
  exit 0
fi

# Reload systemd unit files after unit is gone.
systemctl daemon-reload || echo "warning: daemon-reload failed after removal" >&2

exit 0
