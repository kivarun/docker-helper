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
if semodule -l 2>/dev/null | grep -qw docker_helper; then
  remove_err=""
  if ! remove_err="$(semodule -r docker_helper 2>&1 >/dev/null)"; then
    sleep 2
    if ! remove_err="$(semodule -r docker_helper 2>&1 >/dev/null)"; then
      echo "warning: failed to remove SELinux module docker_helper: $remove_err" >&2
    fi
  fi
fi

exit 0
