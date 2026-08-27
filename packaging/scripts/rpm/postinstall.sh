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

# Detect MAC backend(s).
aa_enabled="$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null | tr -d '[:space:]')" || true
selinux_enforcing="$(cat /sys/fs/selinux/enforce 2>/dev/null | tr -d '[:space:]')" || true

aa_active=false
selinux_active=false
[ "$aa_enabled" = "Y" ] && aa_active=true
[ "$selinux_enforcing" = "1" ] && selinux_active=true

if [ "$aa_active" = "true" ] && [ "$selinux_active" = "true" ]; then
  echo "warning: both AppArmor and SELinux are active (unsupported configuration)" >&2
fi

if [ "$aa_active" = "true" ]; then
  # AppArmor state preparation/migration (only when AppArmor is active).
  AA_STATE_FILE="${AA_STATE_FILE:-/var/lib/docker-helper/apparmor/managed-boundaries}"
  AA_LEGACY_FRAGMENT="${AA_LEGACY_FRAGMENT:-/etc/apparmor.d/docker-helper.d/managed-roots}"
  AA_STATE_DIR="$(dirname "$AA_STATE_FILE")"
  AA_TOP_STATE_DIR="$(dirname "$AA_STATE_DIR")"
  mkdir -p "$AA_TOP_STATE_DIR"
  chmod 0700 "$AA_TOP_STATE_DIR"
  mkdir -p "$AA_STATE_DIR"
  chmod 0755 "$AA_STATE_DIR"
  if [ -f "$AA_LEGACY_FRAGMENT" ] && [ ! -f "$AA_STATE_FILE" ]; then
    tmp_file="$(mktemp "$AA_STATE_DIR/managed-boundaries-XXXXXX.tmp")"
    if ! cp "$AA_LEGACY_FRAGMENT" "$tmp_file" || ! chmod 0644 "$tmp_file" || ! mv -f "$tmp_file" "$AA_STATE_FILE"; then
      rm -f "$tmp_file"
      exit 1
    fi
  fi

  # Load AppArmor profile.
  if ! apparmor_parser --replace --skip-read-cache /etc/apparmor.d/docker-helper-system; then
    exit 1
  fi

  # Clean up legacy fragment after successful profile replacement.
  if [ -f "$AA_LEGACY_FRAGMENT" ] && [ -f "$AA_STATE_FILE" ]; then
    rm -f "$AA_LEGACY_FRAGMENT"
    rmdir /etc/apparmor.d/docker-helper.d 2>/dev/null || true
  fi
fi

if [ "$selinux_active" = "true" ]; then
  if ! semodule -i /usr/share/selinux/docker_helper.pp; then
    exit 1
  fi
  if command -v restorecon >/dev/null 2>&1; then
    restorecon /usr/bin/docker-helper || true
    restorecon -R /etc/docker-helper 2>/dev/null || true
    restorecon -R /var/lib/docker-helper 2>/dev/null || true
    restorecon -R /run/docker-helper 2>/dev/null || true
  fi
fi

if [ "$aa_active" = "false" ] && [ "$selinux_active" = "false" ]; then
  echo "warning: no supported MAC backend active (system mode will not start)" >&2
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
