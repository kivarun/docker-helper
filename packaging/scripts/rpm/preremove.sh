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

# Stop the builder service too (the main unit's Wants= only pulls it in on
# start; it is not a stop-bound). Tolerant of hosts where the unit was never
# installed (e.g. a 2.3 → 2.4 upgrade host) — absence is a normal no-op.
if systemctl is-active --quiet docker-helper-builder.service 2>/dev/null; then
  if ! systemctl stop docker-helper-builder.service; then
    exit 1
  fi
fi

# Disable the service if it is enabled.
if systemctl is-enabled --quiet docker-helper.service 2>/dev/null; then
  if ! systemctl disable docker-helper.service; then
    exit 1
  fi
fi

# Disable the builder service if it is enabled (same tolerance).
if systemctl is-enabled --quiet docker-helper-builder.service 2>/dev/null; then
  if ! systemctl disable docker-helper-builder.service; then
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

# restore_third_party_binary_labels — after a verified-successful
# docker_helper module removal the module's file-context rules are gone, so
# the three third-party binaries the deployment lifecycle relabeled at
# install (the rootlesskit launch vehicle, the bindfs projection dependency,
# the slirp4netns user-network helper) must be restored to the canonical
# labels the remaining fcontext policy resolves for these paths. Pointed
# paths only: no other path is touched and no fcontext rule is added or
# removed here. Every failure is an explicit warning (best-effort, like the
# module removal); the restoration itself is verified against matchpathcon,
# so an unverified or mismatched label never counts as a successful cleanup.
restore_third_party_binary_labels() {
  if ! command -v restorecon >/dev/null 2>&1; then
    echo "warning: restorecon not available; third-party binary labels not restored" >&2
    return
  fi
  restorecon_err=""
  if ! restorecon_err="$(restorecon /usr/bin/rootlesskit /usr/bin/bindfs /usr/bin/slirp4netns 2>&1 >/dev/null)"; then
    echo "warning: failed to restore third-party binary labels (rootlesskit, bindfs, slirp4netns): $restorecon_err" >&2
    return
  fi
  for label_path in /usr/bin/rootlesskit /usr/bin/bindfs /usr/bin/slirp4netns; do
    if [ ! -e "$label_path" ]; then
      echo "warning: $label_path not present; third-party label restore skipped" >&2
      continue
    fi
    actual_label="$(stat -c '%C' "$label_path" 2>/dev/null)" || actual_label=""
    canonical_label="$(matchpathcon "$label_path" 2>/dev/null | awk '{print $2}')" || canonical_label=""
    if [ -z "$actual_label" ] || [ -z "$canonical_label" ]; then
      echo "warning: cannot verify third-party label for $label_path (stat or matchpathcon unavailable)" >&2
      continue
    fi
    [ "$actual_label" = "$canonical_label" ] || \
      echo "warning: $label_path label '$actual_label' does not match canonical '$canonical_label' after module removal" >&2
  done
}

# Remove helper-owned local fcontext customizations BEFORE removing the
# module. The confined daemon registers local fcontext rules for non-home
# workspace boundaries (docker_helper_workspace_t); those local rules
# reference types that only the module defines, so an uncleaned rule makes
# `semodule -r` fail its store validation and leaves the module loaded after
# erase — stale durable state that then also breaks later package actions in
# the same environment. Only rules whose context references a docker_helper
# type are touched; foreign local customizations stay untouched. Absence of
# semanage is a normal idempotent no-op.
if command -v semanage >/dev/null 2>&1; then
  semanage fcontext -l -C -n 2>/dev/null \
    | awk '/object_r:docker_helper_/ {print $1}' \
    | while IFS= read -r fcrule; do
        semanage fcontext -d "$fcrule" >/dev/null 2>&1 || true
      done
fi

# Remove the SELinux policy module ONLY if it is actually installed. Absence is
# a normal idempotent success: an AppArmor-only host never installed our module
# and must not emit a bogus "failed to remove" warning. Only a real failure
# removing an installed module warns. A removal attempt is retried once after a
# bounded pause: commit-time failures (semanage store locks, transient policy
# reload problems under a busy systemd) can be transient; a persistent failure
# keeps the warning and appends semodule's own stderr for diagnosability.
# Cleanup is verified: after the removal attempts the module must actually be
# gone from the policy store before the third-party label restore runs.
if semodule -l 2>/dev/null | grep -qw docker_helper; then
  remove_err=""
  if ! remove_err="$(semodule -r docker_helper 2>&1 >/dev/null)"; then
    sleep 2
    if ! remove_err="$(semodule -r docker_helper 2>&1 >/dev/null)"; then
      echo "warning: failed to remove SELinux module docker_helper: $remove_err" >&2
    fi
  fi
  if semodule -l 2>/dev/null | grep -qw docker_helper; then
    echo "warning: SELinux module docker_helper still installed after removal attempts; third-party binary labels not restored" >&2
  else
    restore_third_party_binary_labels
  fi
fi

exit 0
