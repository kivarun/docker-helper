#!/bin/sh
# Shared FIFO read/write constraint module lifecycle for the SELinux
# backend. Sourced by the RPM scriptlets (posttrans, preremove) and by the
# manual installer/uninstaller; every function fails loud where an
# installation decision is made and stays idempotent-tolerant where
# absence is a normal state.
#
# The constraint module (docker-helper-fifo-rw-constraint.cil) is a
# separately owned product artifact: it is never merged into the
# docker_helper.pp policy package. Its exact candidate bytes carry their
# own identity via the distribution release evidence, so any divergence in
# the module store is a collision, not an upgrade.

# The canonical module identity. Changing any of these requires new
# distribution evidence (fresh isolated-policy measurements), never a
# silent rename.
DH_CONSTRAINT_MODULE=docker-helper-fifo-rw-constraint
DH_CONSTRAINT_PRIORITY=400
DH_CONSTRAINT_STATEMENT='mlsconstrain fifo_file { read write } (h1 dom h2 or t1 != mcs_constrained_type);'

# dh_constraint_error: loud stderr with the constraint-module scope prefix.
dh_constraint_error() {
  echo "error: [${DH_CONSTRAINT_MODULE}] $*" >&2
}

# dh_constraint_store_root: the policy store root of the system's default
# SELINUXTYPE policy (libsemanage reads /etc/selinux/config; a missing or
# empty config falls back to the standard targeted layout). An explicit
# DH_CONSTRAINT_STORE_ROOT overrides the derived root — the test seam for
# an emulated policy store; never set by the production scriptlets.
dh_constraint_store_root() {
  if [ -n "${DH_CONSTRAINT_STORE_ROOT:-}" ]; then
    echo "$DH_CONSTRAINT_STORE_ROOT"
    return
  fi
  selinuxtype="$(sed -n 's/^SELINUXTYPE=//p' /etc/selinux/config 2>/dev/null | tail -n 1)"
  [ -n "$selinuxtype" ] || selinuxtype=targeted
  echo "/etc/selinux/$selinuxtype"
}

# dh_constraint_store_blobs: prints every known-shape module-store blob
# holding the constraint module source CIL at our fixed priority (the
# per-module directory carrying the compressed 'cil' source blob; older
# layouts keep an HLL directory). Only existing paths are printed.
dh_constraint_store_blobs() {
  module_dir="$(dh_constraint_store_root)/active/modules/${DH_CONSTRAINT_PRIORITY}/${DH_CONSTRAINT_MODULE}"
  if [ -f "$module_dir/cil" ]; then
    echo "$module_dir/cil"
  fi
  hll_dir="$(dh_constraint_store_root)/active/modules/${DH_CONSTRAINT_PRIORITY}/hll/${DH_CONSTRAINT_MODULE}"
  if [ -d "$hll_dir" ]; then
    for blob in "$hll_dir"/*; do
      [ -f "$blob" ] && echo "$blob"
    done
  fi
}

# dh_constraint_store_identity: verifies the module resident in the store
# at our priority. Sets dh_constraint_store_identity_rc only:
#   0 identical (byte-exact blob, or at minimum the exact constraint
#     statement resident when byte extraction is impossible),
#   1 absent, 2 mismatch, 3 unreadable/never-identical.
dh_constraint_store_identity() {
  dh_constraint_store_identity_rc=3
  cil="$1"
  [ -r "$cil" ] || return
  blobs="$(dh_constraint_store_blobs 2>/dev/null)"
  if [ -z "$blobs" ]; then
    dh_constraint_store_identity_rc=1
    return
  fi
  for blob in $blobs; do
    if bzip2 -dc "$blob" 2>/dev/null | cmp -s - "$cil"; then
      dh_constraint_store_identity_rc=0
      return
    fi
  done
  for blob in $blobs; do
    if bzip2 -dc "$blob" 2>/dev/null | grep -Fqx "$DH_CONSTRAINT_STATEMENT"; then
      dh_constraint_store_identity_rc=0
      return
    fi
  done
  dh_constraint_store_identity_rc=2
}

# dh_constraint_preinstall_collision: refuses to proceed when a module with
# our name is already resident at our priority and is NOT byte-identical to
# the artifact about to be installed. An identical resident module is not a
# collision (idempotent repeat install / same-content upgrade).
dh_constraint_preinstall_collision() {
  cil="$1"
  dh_constraint_store_identity "$cil"
  case "$dh_constraint_store_identity_rc" in
    0|1) return 0 ;;
    2)
      dh_constraint_error "a different module named $DH_CONSTRAINT_MODULE is already installed at priority $DH_CONSTRAINT_PRIORITY; refusing to overwrite it silently (an explicit repair requires removing it first: semodule -X $DH_CONSTRAINT_PRIORITY -r $DH_CONSTRAINT_MODULE)"
      exit 2
      ;;
    *)
      dh_constraint_error "the resident $DH_CONSTRAINT_MODULE store content cannot be read or verified; refusing to install over an unverifiable module (remove it explicitly: semodule -X $DH_CONSTRAINT_PRIORITY -r $DH_CONSTRAINT_MODULE)"
      exit 2
      ;;
  esac
}

# dh_constraint_effective_policy_check: the acceptance gate for install —
# the LOADED policy (never only the store listing) must carry the exact
# fifo_file read/write constraining statement. seinfo renders each policy
# constraint on its own indented entry line; leading whitespace is
# normalized before the comparison. Tool absence or any query failure is
# fail-closed: a trusted query is the only authority for the effective
# policy shape.
dh_constraint_effective_policy_check() {
  if ! command -v seinfo >/dev/null 2>&1; then
    dh_constraint_error "seinfo is not available; the loaded policy cannot be verified for the $DH_CONSTRAINT_MODULE constraint (install setools-console and re-run the module install)"
    exit 2
  fi
  if ! query_out="$(seinfo --constrain fifo_file /sys/fs/selinux/policy 2>&1)"; then
    dh_constraint_error "the seinfo constraint query failed against the loaded policy: $query_out"
    exit 2
  fi
  if ! printf '%s\n' "$query_out" | sed 's/^[[:space:]]*//' | grep -Fqx "$DH_CONSTRAINT_STATEMENT"; then
    dh_constraint_error "the loaded policy does not carry the installed fifo_file read/write constraint after the module install (this can follow a failed reload or a store/policy mismatch); refusing to declare success"
    dh_constraint_error "re-verify with: seinfo --constrain fifo_file /sys/fs/selinux/policy"
    exit 2
  fi
}

# dh_constraint_install: the RPM and install-system install contract.
#   1. artifact readable;
#   2. collision/ownership pre-check against the module store;
#   3. semodule install at the fixed priority;
#   4. store identity re-verified immediately after the install;
#   5. effective-policy check against the loaded policy.
# Any failed step exits non-zero: the RPM %posttrans contract declares the
# whole transaction failed and the service is not restarted (docker-helper
# stays down until the module state is repaired).
dh_constraint_install() {
  cil="$1"
  [ -r "$cil" ] || {
    dh_constraint_error "constraint module artifact not readable at $cil"
    exit 1
  }
  if ! command -v semodule >/dev/null 2>&1; then
    dh_constraint_error "semodule not available; cannot install $DH_CONSTRAINT_MODULE"
    exit 1
  fi
  dh_constraint_preinstall_collision "$cil"

  echo "docker-helper [${DH_CONSTRAINT_MODULE}]: installing at priority $DH_CONSTRAINT_PRIORITY from $cil"
  if ! semodule -X "$DH_CONSTRAINT_PRIORITY" -i "$cil"; then
    dh_constraint_error "semodule failed to install $DH_CONSTRAINT_MODULE at priority $DH_CONSTRAINT_PRIORITY (the transaction is failed; the service has not been restarted)"
    exit 1
  fi

  dh_constraint_store_identity "$cil"
  case "$dh_constraint_store_identity_rc" in
    0) ;;
    2)
      dh_constraint_error "the installed module store does not match the shipped constraint artifact; refusing to declare success"
      exit 2
      ;;
    *)
      dh_constraint_error "the installed module store content cannot be read or verified after install; refusing to declare success"
      exit 2
      ;;
  esac

  dh_constraint_effective_policy_check
}

# dh_constraint_remove: the final-erase uninstall contract (upgrades never
# call this — the next install transaction would hit a manufactured
# absent-module window). Absence of the module is the normal idempotent
# success (AppArmor-only hosts and hosts that never loaded it). A real
# removal failure of a present module is only a warning plus an explicit
# remediation command: uninstall must proceed, a surviving constraint is
# fail-SECURE, and the helper's own classification path surfaces the
# remaining state on every subsequent enforcing deployment.
dh_constraint_remove() {
  command -v semodule >/dev/null 2>&1 || return 0
  if ! semodule -l 2>/dev/null | grep -qw "$DH_CONSTRAINT_MODULE"; then
    return 0
  fi
  echo "docker-helper [${DH_CONSTRAINT_MODULE}]: removing (priority $DH_CONSTRAINT_PRIORITY)"
  remove_err=""
  if ! remove_err="$(semodule -r "$DH_CONSTRAINT_MODULE" 2>&1 >/dev/null)"; then
    sleep 2
    if ! remove_err="$(semodule -r "$DH_CONSTRAINT_MODULE" 2>&1 >/dev/null)"; then
      dh_constraint_error "failed to remove the module from the policy store: $remove_err"
      dh_constraint_error "manual remediation: semodule -X $DH_CONSTRAINT_PRIORITY -r $DH_CONSTRAINT_MODULE"
      return 1
    fi
  fi
  if semodule -l 2>/dev/null | grep -qw "$DH_CONSTRAINT_MODULE"; then
    dh_constraint_error "the module is still installed after the removal attempts"
    dh_constraint_error "manual remediation: semodule -X $DH_CONSTRAINT_PRIORITY -r $DH_CONSTRAINT_MODULE"
    return 1
  fi
  return 0
}
