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
  # RPM scriptlet ordering (P4-B1.2): container-selinux installs its policy
  # module in ITS %posttrans, and rpm runs every %post scriptlet of a
  # transaction before any %posttrans. Loading the docker_helper module from
  # %post therefore fails on a fresh SELinux install: the container policy
  # symbols it requires are only in the store after container-selinux's
  # %posttrans (P4-B1 diagnosis: cil:33 typeattributeset). The module load,
  # the exact relabels and the restart of an already-active service are
  # owned by %posttrans (packaging/scripts/rpm/posttrans.sh); this scriptlet
  # records only the was-active decision %posttrans needs.
  mkdir -p /run/docker-helper-rpm
  printf 'was_active=%s\n' "$was_active" > /run/docker-helper-rpm/posttrans-state
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

# Restart only if the service was already active — except on SELinux hosts,
# where %posttrans owns the restart after the module load and relabels
# (scriptlet ordering contract, P4-B1.2). AppArmor and MAC-less hosts keep
# the same-phase restart. try-restart is the inactive-safe restart
# operation: under this guard it enqueues the same restart job
# `systemctl restart` would, and the shipped unit's
# RuntimeDirectoryPreserve=restart keeps the /run/docker-helper inode across
# that restart, so a long-lived container bind-mounting /run/docker-helper
# continues to see the recreated socket after the package action.
if [ "$was_active" = "true" ] && [ "$selinux_active" != "true" ]; then
  if ! systemctl try-restart docker-helper.service; then
    exit 1
  fi
fi

exit 0
