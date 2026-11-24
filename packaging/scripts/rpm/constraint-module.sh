#!/bin/sh
# Shared FIFO read/write constraint module lifecycle for the SELinux
# backend. Sourced by the RPM scriptlets (posttrans, preremove) and by the
# manual installer/uninstaller; every function fails loud where an
# installation decision is made and stays idempotent-tolerant where
# absence is a normal state. The install/remove functions REPORT failure
# through their exit status; the calling scriptlet owns the abort
# semantics (the RPM %posttrans stops the running backend on failure, the
# installer aborts the installation).
#
# The constraint module (docker-helper-fifo-rw-constraint.cil) is a
# separately owned product artifact: it is never merged into the
# docker_helper.pp policy package. Its exact candidate bytes carry their
# own identity via the distribution release evidence, so any divergence in
# the module store is a collision, not an upgrade: the identity decision is
# byte-exact CIL comparison ONLY — a statement-level or name-level match
# never substitutes for the bytes.

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
# holding the constraint module source CIL at OUR priority (the
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

# dh_constraint_same_name_elsewhere: prints the module directories holding
# a module with OUR NAME at any priority OTHER than ours (both the
# per-module layout and the older priority/hll layout), one per line. A
# same-name module outside our priority is a collision by definition here:
# our module name is product-owned end to end and must never appear at
# another priority, whatever its bytes are.
dh_constraint_same_name_elsewhere() {
  store="$(dh_constraint_store_root)"
  for dir in "$store"/active/modules/*/"${DH_CONSTRAINT_MODULE}" \
             "$store"/active/modules/*/hll/"${DH_CONSTRAINT_MODULE}"; do
    # Unmatched globs stay literal; only real module directories count.
    [ -d "$dir" ] || continue
    rel="${dir#"${store}"/active/modules/}"
    prio="${rel%%/*}"
    [ "$prio" = "$DH_CONSTRAINT_PRIORITY" ] && continue
    echo "$dir"
  done
}

# dh_constraint_store_identity: verifies the module resident in the store
# at our priority. The identity decision is BYTE-EXACT over EVERY
# recognized store blob: MATCH only when each blob decodes and is
# byte-identical to the installed candidate CIL — one differing, corrupt,
# or undecodable blob is a refusal. A resident module directory without
# verifiable content is UNVERIFIABLE, never ABSENT. Sets
# dh_constraint_store_identity_rc only:
#   0 all blobs decode and are byte-exact identical,
#   1 absent (no module directory at our priority at all),
#   2 present, decodable, but at least one blob differs from the
#     candidate (identity failure),
#   3 unverifiable (a present module directory carries no recognizable
#     blob, some blob is corrupt/undecodable, or the bzip2 tooling is
#     missing — the identity can never be trusted here).
dh_constraint_store_identity() {
  dh_constraint_store_identity_rc=3
  cil="$1"
  [ -r "$cil" ] || return
  if ! command -v bzip2 >/dev/null 2>&1; then
    return
  fi
  blobs="$(dh_constraint_store_blobs 2>/dev/null)"
  if [ -z "$blobs" ]; then
    if dh_constraint_module_dir_present; then
      # A module directory exists but carries no recognizable blob: its
      # content can never be trusted, so this is UNVERIFIABLE (a refusal),
      # not an absent module.
      dh_constraint_store_identity_rc=3
    else
      dh_constraint_store_identity_rc=1
    fi
    return
  fi
  for blob in $blobs; do
    if ! bzip2 -dc "$blob" >/dev/null 2>&1; then
      dh_constraint_store_identity_rc=3
      return
    fi
    if ! bzip2 -dc "$blob" 2>/dev/null | cmp -s - "$cil"; then
      dh_constraint_store_identity_rc=2
      return
    fi
  done
  dh_constraint_store_identity_rc=0
}

# dh_constraint_module_dir_present: reports (exit status) whether ANY
# module directory with our name exists at our priority, in either store
# layout — even one without a recognizable blob.
dh_constraint_module_dir_present() {
  [ -d "$(dh_constraint_store_root)/active/modules/${DH_CONSTRAINT_PRIORITY}/${DH_CONSTRAINT_MODULE}" ] || \
    [ -d "$(dh_constraint_store_root)/active/modules/${DH_CONSTRAINT_PRIORITY}/hll/${DH_CONSTRAINT_MODULE}" ]
}

# dh_constraint_preinstall_collision: the fail-closed ownership pre-check.
# Refuses to proceed (returns 2) when
#   - a module with our name is resident at ANY other priority (an
#     unexpected same-name module is a collision whatever its bytes), or
#   - the resident module at our priority is present but not byte-exactly
#     identical to the artifact about to be installed (a different or an
#     UNVERIFIABLE resident module is never overwritten silently).
# An absent module at our priority, or a byte-exact resident module, is
# not a collision (fresh install / idempotent repeat install).
dh_constraint_preinstall_collision() {
  cil="$1"
  foreign="$(dh_constraint_same_name_elsewhere 2>/dev/null)"
  if [ -n "$foreign" ]; then
    dh_constraint_error "a module named $DH_CONSTRAINT_MODULE is already installed outside priority $DH_CONSTRAINT_PRIORITY ($foreign); refusing to proceed (remove it explicitly; the constraint module name is product-owned at priority $DH_CONSTRAINT_PRIORITY only)"
    return 2
  fi
  dh_constraint_store_identity "$cil"
  case "$dh_constraint_store_identity_rc" in
    0|1) return 0 ;;
    2)
      dh_constraint_error "a DIFFERENT module named $DH_CONSTRAINT_MODULE is already installed at priority $DH_CONSTRAINT_PRIORITY; refusing to overwrite it silently (an explicit repair requires removing it first: semodule -X $DH_CONSTRAINT_PRIORITY -r $DH_CONSTRAINT_MODULE)"
      return 2
      ;;
    *)
      dh_constraint_error "the resident $DH_CONSTRAINT_MODULE store content cannot be read or verified; refusing to install over an unverifiable module (remove it explicitly: semodule -X $DH_CONSTRAINT_PRIORITY -r $DH_CONSTRAINT_MODULE)"
      return 2
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
    return 2
  fi
  if ! query_out="$(seinfo --constrain fifo_file /sys/fs/selinux/policy 2>&1)"; then
    dh_constraint_error "the seinfo constraint query failed against the loaded policy: $query_out"
    return 2
  fi
  if ! printf '%s\n' "$query_out" | sed 's/^[[:space:]]*//' | grep -Fqx "$DH_CONSTRAINT_STATEMENT"; then
    dh_constraint_error "the loaded policy does not carry the installed fifo_file read/write constraint after the module install (this can follow a failed reload or a store/policy mismatch); refusing to declare success"
    dh_constraint_error "re-verify with: seinfo --constrain fifo_file /sys/fs/selinux/policy"
    return 2
  fi
}

# dh_constraint_install: the RPM and install-system install contract.
#   1. artifact readable;
#   2. collision/ownership pre-check against the module store (all
#      priorities, byte-exact identity only);
#   3. semodule install at the fixed priority;
#   4. store identity re-verified immediately after the install
#      (byte-exact; an unverifiable store is a refusal);
#   5. effective-policy check against the loaded policy.
# Any failed step RETURNS non-zero; the calling scriptlet owns the abort
# semantics (see the file header).
dh_constraint_install() {
  cil="$1"
  [ -r "$cil" ] || {
    dh_constraint_error "constraint module artifact not readable at $cil"
    return 1
  }
  if ! command -v semodule >/dev/null 2>&1; then
    dh_constraint_error "semodule not available; cannot install $DH_CONSTRAINT_MODULE"
    return 1
  fi
  if ! dh_constraint_preinstall_collision "$cil"; then
    return 2
  fi

  echo "docker-helper [${DH_CONSTRAINT_MODULE}]: installing at priority $DH_CONSTRAINT_PRIORITY from $cil"
  if ! semodule -X "$DH_CONSTRAINT_PRIORITY" -i "$cil"; then
    dh_constraint_error "semodule failed to install $DH_CONSTRAINT_MODULE at priority $DH_CONSTRAINT_PRIORITY (the transaction is failed; recovery is owned by the calling scriptlet)"
    return 1
  fi

  dh_constraint_store_identity "$cil"
  case "$dh_constraint_store_identity_rc" in
    0) ;;
    2)
      dh_constraint_error "the installed module store does not match the shipped constraint artifact; refusing to declare success"
      return 2
      ;;
    *)
      dh_constraint_error "the installed module store content cannot be read or verified after install; refusing to declare success"
      return 2
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
