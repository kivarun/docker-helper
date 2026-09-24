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

# Builder identity + subordinate-ID provisioning through the ONE canonical
# provisioning owner (packaging/scripts/lib/provision-builder.sh, shipped as
# /usr/share/docker-helper/lib/provision-builder.sh): executed, never
# re-implemented. Idempotent (verify-first) and fail-closed: a provisioning
# failure aborts the scriptlet so rpm reports the failure.
PROVISION_BUILDER="${PROVISION_BUILDER:-/usr/share/docker-helper/lib/provision-builder.sh}"
if ! sh "$PROVISION_BUILDER"; then
  echo "error: builder identity provisioning failed; package scriptlet aborted" >&2
  exit 1
fi

# Detect MAC backend(s).
aa_enabled="$(tr -d '[:space:]' < /sys/module/apparmor/parameters/enabled 2>/dev/null)" || true
selinux_enforcing="$(tr -d '[:space:]' < /sys/fs/selinux/enforce 2>/dev/null)" || true

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
    # bindfs is an explicit RPM Requires (SELinux read-only projection
    # backend); apply the shipped docker_helper_bindfs_exec_t file context
    # so the confined daemon can exec the projection worker.
    restorecon /usr/bin/bindfs 2>/dev/null || true
    restorecon -R /etc/docker-helper 2>/dev/null || true
    restorecon -R /var/lib/docker-helper 2>/dev/null || true
    # Relabel only the helper-owned /run/docker-helper dir itself to
    # docker_helper_runtime_t. Never recurse into /run/docker-helper/mounts:
    # those entries are bind-mount aliases of the real workspace inodes, and a
    # recursive relabel through them would relabel the actual workspace files
    # to docker_helper_runtime_t, corrupting the SELinux workspace model.
    restorecon /run/docker-helper 2>/dev/null || true
  fi
fi

if [ "$aa_active" = "false" ] && [ "$selinux_active" = "false" ]; then
  echo "warning: no supported MAC backend active (system mode will not start)" >&2
fi

# Reload systemd unit files.
if ! systemctl daemon-reload; then
  exit 1
fi

# Enable the builder service (Package activation enables both units; the
# main unit's Wants= provides the start coupling on the daemon's own
# starts). Failure to enable is a real installation failure.
if ! systemctl enable docker-helper-builder.service; then
  echo "error: systemctl enable docker-helper-builder.service failed" >&2
  exit 1
fi

# Restart only if the service was already active. try-restart is the
# inactive-safe restart operation: under this guard it enqueues the same
# restart job `systemctl restart` would, and the shipped unit's
# RuntimeDirectoryPreserve=restart keeps the /run/docker-helper inode across
# that restart, so a long-lived container bind-mounting /run/docker-helper
# continues to see the recreated socket after the package action.
if [ "$was_active" = "true" ]; then
  if ! systemctl try-restart docker-helper.service; then
    exit 1
  fi
fi

exit 0
