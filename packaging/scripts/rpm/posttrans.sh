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
#
# The FIFO read/write constraint module (docker-helper-fifo-rw-constraint,
# priority 400) is installed AFTER the docker_helper.pp module: it carries
# its own separately owned CIL artifact, refuses collisions against a
# non-identical resident module, verifies its store identity, and requires
# the exact constraint statement to be verifiable in the LOADED policy
# (seinfo) before this scriptlet may declare success. Its own helper
# library lives at the packaged constraint-module path, so posttrans and
# the uninstaller drive one lifecycle owner.

# Live-system guard (same as %post).
if [ ! -d /run/systemd/system ]; then
  exit 0
fi

# MAC backend detection (same detection as %post).
selinux_enforcing="$(tr -d '[:space:]' < /sys/fs/selinux/enforce 2>/dev/null)" || true
if [ "$selinux_enforcing" != "1" ]; then
  exit 0
fi

# stop_backends_and_fail is the ONE centralized fail-closed abort for every
# %posttrans failure BEFORE the constraint module's effective-policy
# acceptance: a missing container policy, a failed docker_helper.pp load, a
# missing/unsourcable lifecycle library, and a failed constraint install
# (the constraint install itself ends in that acceptance). A previously
# active docker-helper daemon and builder backend may still be running
# their PRE-upgrade process images against a policy that does not carry
# the required setup (or the FIFO constraint, once the main module loads
# without it) — neither backend may keep executing operations. Both
# services are stopped, the stop is then VERIFIED against the actual
# service state, and only a verified stop may be reported as a safe
# stopped state; an unconfirmed stop is a separate CRITICAL verdict naming
# exactly which unit remained active. The deferred-restart decision below
# is NOT consumed: the recorded was-active state survives for the recovery
# transaction, and the stopped services are only ever restarted by an
# explicit operator action or a later successful transaction that observes
# them active again. Always exits 1.
stop_backends_and_fail() {
  reason="$1"
  echo "error: docker-helper posttrans: ${reason}; stopping the running backends" >&2
  for unit in docker-helper.service docker-helper-builder.service; do
    if ! systemctl stop "$unit" 2>/dev/null; then
      echo "warning: could not stop $unit" >&2
    fi
  done
  stopped_confirmed=true
  for unit in docker-helper.service docker-helper-builder.service; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      stopped_confirmed=false
      echo "CRITICAL: $unit is STILL ACTIVE after the stop attempts; the system is NOT in a verified stopped state" >&2
    fi
  done
  if [ "$stopped_confirmed" = "true" ]; then
    echo "error: docker-helper posttrans: both backends confirmed stopped (verified); the transaction is failed and nothing restarts" >&2
  else
    echo "CRITICAL: docker-helper backends were NOT all verified stopped; manual intervention is required" >&2
  fi
  exit 1
}

# Container policy must be loaded before the docker_helper module can
# resolve its require statements. container-selinux provides these symbols
# (bsc#1252672); its %posttrans installs the module before this one.
if ! semodule -l 2>/dev/null | grep -qw container; then
  stop_backends_and_fail "SELinux container policy module not loaded; refusing to load docker_helper policy (requires container-selinux)"
fi

# Ordering marker: appears in the transaction log only after this scriptlet
# started, which is after container-selinux's %posttrans finished (rpm runs
# %posttrans scriptlets sequentially in transaction install order).
echo "docker-helper posttrans: container policy loaded; installing docker_helper module"

if ! semodule -i /usr/share/selinux/docker_helper.pp; then
  stop_backends_and_fail "semodule failed to load /usr/share/selinux/docker_helper.pp"
fi

# The separately owned FIFO read/write constraint module (same %posttrans
# contract: loud failure, no restart). The constraint install library is
# sourced from its packaged path; every failure below is routed through
# the centralized fail-closed abort above. The lifecycle library never
# overwrites an unexpected resident module and never declares success on
# an unverifiable store or loaded policy.
CONSTRAINT_LIB=/usr/share/docker-helper/selinux/constraint-module.sh
CONSTRAINT_CIL=/usr/share/selinux/docker-helper-fifo-rw-constraint.cil

if [ ! -r "$CONSTRAINT_LIB" ]; then
  stop_backends_and_fail "the constraint module lifecycle library is missing at $CONSTRAINT_LIB"
fi
if ! . "$CONSTRAINT_LIB"; then
  stop_backends_and_fail "the constraint module lifecycle library failed to source from $CONSTRAINT_LIB"
fi
if ! dh_constraint_install "$CONSTRAINT_CIL"; then
  stop_backends_and_fail "the FIFO constraint module install failed (collision, store identity, or loaded-policy verification)"
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
  # newgidmap is a distro dependency of the launch vehicle (the root-owned
  # GID-map helper; its privilege mechanism is the distro chkstat-applied
  # cap_setgid file capability, untouched by docker-helper); apply the
  # shipped docker_helper_newgidmap_exec_t file context so the rootlesskit
  # child's exec transitions into its dedicated domain (and only that
  # child can exec it). Label-only: restorecon never alters owner, mode,
  # or xattrs.
  restorecon /usr/bin/newgidmap 2>/dev/null || true
  # nsenter is a distro dependency of the launch vehicle (RootlessKit's
  # network setup execs it to create the tap device inside the flow's
  # namespaces); apply the shipped docker_helper_nsenter_exec_t file
  # context so the rootlesskit child's same-domain exec is allowed — the
  # distro bin_t label is denied for the flow domain (the live enforcing
  # boundary evidence recorded in the policy, P5-S2 Phase 4C-3; the
  # P5-S1 run reproduced it on a host whose nsenter still carried the
  # distro label). Label-only: restorecon never alters owner, mode, or
  # xattrs.
  restorecon /usr/bin/nsenter 2>/dev/null || true
  # buildkitd is the bundled BuildKit daemon payload (the launch chain's
  # exec target); apply the shipped docker_helper_buildkitd_exec_t file
  # context so the payload carries its private executable identity —
  # buildkit-runc joins the SAME identity (4C-84: the LookPath-selected
  # worker runtime binary; the generic bin_t label denied its exec from
  # the daemon domain). buildkit-runc is the WRAPPER role (a byte-copy of
  # the product binary, R4-P3-P0 D-2) and the relocated original pinned
  # runtime lives at the dedicated runtime/ subpath — the wrapper's fixed
  # handoff target, the SAME identity, no transition. The exact canonical
  # paths only. Label-only: restorecon never alters owner, mode, or xattrs.
  restorecon /usr/libexec/docker-helper/buildkit/buildkitd 2>/dev/null || true
  restorecon /usr/libexec/docker-helper/buildkit/buildkit-runc 2>/dev/null || true
  restorecon /usr/libexec/docker-helper/buildkit/runtime/buildkit-runc 2>/dev/null || true
  # buildctl carries its OWN private exec identity (R7-A: the failed full
  # artifact-gate run proved the generic bin_t distro label is unusable
  # for the confined daemon domain — the standing bin_t grant carries no
  # execute_no_trans, so the in-domain exec failed closed). Label-only:
  # restorecon never alters owner, mode, or xattrs.
  restorecon /usr/libexec/docker-helper/buildkit/buildctl 2>/dev/null || true
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
