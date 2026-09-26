#!/bin/sh
set -eu

# RPM posttrans (%posttrans) — SELinux module load, exact relabels, and the
# deferred restart of an already-active service.
#
# Scriptlet ordering contract (P4-B1 diagnosis + P4-B1.2): rpm runs ALL %post
# scriptlets of a transaction before ANY %posttrans, and %posttrans scriptlets
# run in transaction install order. container-selinux installs its policy
# module in its own %posttrans (openSUSE convention), so the container policy
# symbols the docker_helper module requires (container_domain,
# container_net_domain, container_runtime_t, container_runtime_exec_t,
# container_var_run_t) are in the store by the time this scriptlet runs on a
# fresh SELinux install. Loading the module from %post fails there and must
# not return there.
#
# This scriptlet fails loudly when the module cannot load; it never bypasses
# the container-policy precondition and never restarts the service on a
# failed load. AppArmor and MAC-less hosts exit immediately: their behavior
# is owned entirely by %post (unchanged).

# Live-system guard (same as %post).
if [ ! -d /run/systemd/system ]; then
  exit 0
fi

# MAC backend detection (same detection as %post).
selinux_enforcing="$(tr -d '[:space:]' < /sys/fs/selinux/enforce 2>/dev/null)" || true
if [ "$selinux_enforcing" != "1" ]; then
  exit 0
fi

# Container policy must be loaded before the docker_helper module can
# resolve its require statements. container-selinux provides these symbols
# (bsc#1252672); its %posttrans installs the module before this one.
if ! semodule -l 2>/dev/null | grep -qw container; then
  echo "error: SELinux container policy module not loaded; refusing to load docker_helper policy (requires container-selinux)" >&2
  exit 1
fi

# Ordering marker: appears in the transaction log only after this scriptlet
# started, which is after container-selinux's %posttrans finished (rpm runs
# %posttrans scriptlets sequentially in transaction install order).
echo "docker-helper posttrans: container policy loaded; installing docker_helper module"

if ! semodule -i /usr/share/selinux/docker_helper.pp; then
  echo "error: semodule failed to load /usr/share/selinux/docker_helper.pp; docker-helper.service was not restarted" >&2
  exit 1
fi

if command -v restorecon >/dev/null 2>&1; then
  restorecon /usr/bin/docker-helper || true
  # bindfs is an explicit RPM Requires (SELinux read-only projection
  # backend); apply the shipped docker_helper_bindfs_exec_t file context
  # so the confined daemon can exec the projection worker.
  restorecon /usr/bin/bindfs 2>/dev/null || true
  # rootlesskit is an explicit RPM Requires (builder backend runtime); apply
  # the shipped docker_helper_rootlesskit_exec_t file context so the
  # confined builder manager can exec its launch vehicle.
  restorecon /usr/bin/rootlesskit 2>/dev/null || true
  # slirp4netns is an explicit RPM Requires (the launch vehicle's
  # user-network helper); apply the shipped
  # docker_helper_slirp4netns_exec_t file context so the rootlesskit child
  # domain can exec it (and only the rootlesskit child domain can).
  restorecon /usr/bin/slirp4netns 2>/dev/null || true
  # newuidmap is a distro dependency of the launch vehicle (the setuid-root
  # UID-map helper); apply the shipped docker_helper_newuidmap_exec_t file
  # context so the rootlesskit child's exec transitions into its dedicated
  # domain (and only that child can exec it).
  restorecon /usr/bin/newuidmap 2>/dev/null || true
  restorecon -R /etc/docker-helper 2>/dev/null || true
  restorecon -R /var/lib/docker-helper 2>/dev/null || true
  # Relabel only the helper-owned /run/docker-helper dir itself to
  # docker_helper_runtime_t. Never recurse into /run/docker-helper/mounts:
  # those entries are bind-mount aliases of the real workspace inodes, and a
  # recursive relabel through them would relabel the actual workspace files
  # to docker_helper_runtime_t, corrupting the SELinux workspace model.
  restorecon /run/docker-helper 2>/dev/null || true
  # P5-S1 builder-owned trees (the dedicated docker_helper_builder_runtime_t /
  # docker_helper_builder_state_t types). Recursive here is safe: the builder
  # runtime/state trees contain only builder-owned objects (manager/op
  # sockets, pid files, per-op BuildKit state) — no workspace bind-mount
  # aliases live under these stems. Fresh installs created no builder dirs
  # yet (restorecon no-ops); upgrades/reinstalls migrate dirs labeled under
  # an older module to the dedicated types.
  restorecon -R /run/docker-helper-builder 2>/dev/null || true
  restorecon -R /var/lib/docker-helper-builder 2>/dev/null || true
fi

# Deferred restart: only when %post recorded the service as active before
# this transaction (fresh installs never restart), and only after the module
# load and relabels succeeded. The state file survives a failed %posttrans
# until the recovery transaction's %post overwrites it.
was_active=false
STATE_FILE=/run/docker-helper-rpm/posttrans-state
if [ -f "$STATE_FILE" ]; then
  recorded="$(sed -n 's/^was_active=//p' "$STATE_FILE")"
  [ "$recorded" = "true" ] && was_active=true
  rm -f "$STATE_FILE"
fi

if [ "$was_active" = "true" ]; then
  if ! systemctl try-restart docker-helper.service; then
    echo "error: systemctl try-restart docker-helper.service failed after the SELinux module load" >&2
    exit 1
  fi
fi

exit 0
