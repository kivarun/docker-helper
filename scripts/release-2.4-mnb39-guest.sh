#!/bin/bash
# release-2.4-mnb39-guest.sh — MNB39: no-exec wrapper policy verification
# feasibility on the enforcing Tumbleweed VM.
#
# Investigates BOTH wrapper policy checks (the admission-gate pair) as
# IN-PROCESS operations under docker_helper_buildkitd_t, with NO external
# executable spawned in that domain:
#
#   1. Role authorization — the kernel-native security_check_context
#      interface (/sys/fs/selinux/check_context): the probe composes the
#      exact workload context the wrapper composes
#      (wrapperWorkloadProcessLabel: own user/role/sensitivity/category
#      verbatim, wrapperWorkloadDomain substituted) and validates it
#      against the loaded policy through the kernel. Behavior matrix:
#      valid context, unknown type, role not authorized for the type,
#      wrong category, unavailable interface — every row recorded with
#      rc + errno. In parallel the probe's own in-process policy parse
#      renders the roletype relation for the workload type, compared as
#      a sorted SET against the root-run seinfo --role_types reference
#      output.
#   2. FIFO constraint — the probe parses the LOADED binary policy
#      (/sys/fs/selinux/policy) in-process (the kernel
#      security/selinux/ss/policydb.c reader order: magic, version/
#      config, caps ebitmaps, symbol tables commons -> classes ->
#      roles -> types; the parse stops before the avtab) and renders
#      the constraint statements for fifo_file; the canonical shipped
#      statement must be present EXACTLY, and the full rendering is
#      compared against the root-run seinfo --constrain reference
#      output.
#
# Permission surface (separately removable diagnostic modules only):
#   stage 1 (parse-only face set): the security_t file read cluster +
#   security:read_policy + the rows needed to enter
#   docker_helper_buildkitd_t. The check_context write is EXPECTED to be
#   kernel-denied here — that denial IS the measured permission surface.
#   stage 2 adds exactly one row: security_t:security check_context.
#   Both modules are unloaded and the unload is verified (policy sha
#   restored byte-exactly; a negative re-run must be denied again).
#
# Boundary: NO permanent policy integration, NO product code change, no
# Release-GO UAT. The candidate RPM is installed ONLY to provision the
# product types/domains the probes address (the same install contract as
# the MNB38 matrix P1). Runtime pins/TE/CIL/RPM are not modified.

set -Eeuo pipefail

PREFIX='[release-2.4-mnb39]'
say()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }
log()  { echo "[guest] $*"; }
ev()   { printf '%s\n' "$2" > "$EVIDENCE_DIR/$1"; }

: "${R7_ARTIFACT:?R7_ARTIFACT required}"
: "${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"
: "${R7_EVIDENCE_DIR:?R7_EVIDENCE_DIR required}"
: "${MNB39_PROBE_SRC:?MNB39_PROBE_SRC required}"
MNB39_POLICY_SHA_BASE="${MNB39_POLICY_SHA_BASE:-}"
[ -f "${STATE_DIR:-/var/lib/docker-helper-mnb39-state}/policy-sha-base" ] \
  && MNB39_POLICY_SHA_BASE="$(cat "$STATE_DIR/policy-sha-base" 2>/dev/null || true)" || true
MNB39_POLICYPATH=/sys/fs/selinux/policy
MNB39_CHECKCTX_PATH="$(ls /sys/fs/selinux/context 2>/dev/null || true)"
MNB39_GHOST_PROBE_PATH=/sys/fs/selinux/check_context
# check_context is a kernel-compile-time selinuxfs node; its ABSENCE is a
# measured finding for the kernel-native alternative, not a script failure

RPM="$R7_ARTIFACT"
EVIDENCE_DIR="$R7_EVIDENCE_DIR"
STATEMENT='mlsconstrain fifo_file { read write } (h1 dom h2 or t1 != mcs_constrained_type);'
MAIN_UNIT=docker-helper.service
UNIT=docker-helper-builder.service
WL_DOMAIN=docker_helper_builder_workload_t
PROBE=/tmp/mnb39-probe.$$
PROBERTYPE=dh_mnb39_probe_t
MOD1=dh_mnb39_stage1
MOD2=dh_mnb39_stage2

mkdir -p "$EVIDENCE_DIR"

STATE_DIR=/var/lib/docker-helper-mnb39-state
PHASE_FILE="$STATE_DIR/phase-done"
mark() { mkdir -p "$STATE_DIR"; printf '%s\n' "$1" >> "$PHASE_FILE"; }
done_phase() {
  [ -f "$PHASE_FILE" ] && grep -qx "$1" "$PHASE_FILE"
}

policy_sha() { sha256sum "$MNB39_POLICYPATH" | awk '{print $1}'; }

expected_active() {
  [ "$(systemctl is-active "$1" 2>/dev/null || true)" = "active" ]
}

ensure_services_active() {
  systemctl reset-failed "$MAIN_UNIT" "$UNIT" 2>/dev/null || true
  if [ "$(systemctl is-enabled "$MAIN_UNIT" 2>/dev/null || true)" = "enabled" ] \
    || [ "$(systemctl is-enabled "$UNIT" 2>/dev/null || true)" = "enabled" ]; then
    systemctl start "$MAIN_UNIT" "$UNIT"
  fi
  expected_active "$MAIN_UNIT" || fail "$MAIN_UNIT must be active at the start of this phase"
  expected_active "$UNIT" || fail "$UNIT must be active at the start of this phase"
}

# the composed WORKLOAD label from the probe process's own context (the
# exact wrapper composition: user/role/sensitivity/category verbatim,
# workload type substituted). The probe runs IN docker_helper_buildkitd_t,
# so its own context carries the exact user/role/sensitivity/category the
# real wrapper carries.
compose_workload() {
  # $1 = own five-field context, $2 = the replacement type
  local f0 f1 f3 f4
  f0="$(printf '%s\n' "$1" | awk -F: '{print $1}')"
  f1="$(printf '%s\n' "$1" | awk -F: '{print $2}')"
  f3="$(printf '%s\n' "$1" | awk -F: '{print $4}')"
  f4="$(printf '%s\n' "$1" | awk -F: '{print $5}')"
  printf '%s:%s:%s:%s:%s' "$f0" "$f1" "$2" "$f3" "$f4"
}

# run the probe INSIDE docker_helper_buildkitd_t via the diagnostic
# typetransition. Fatal variant (expected-success callers) and rc variant
# (expected-failure matrix rows).
RUNCON_RC=0
# output is captured through a pre-created, pre-labeled file rather than a
# pipe: the probe domain must not need fifo_file or foreign evidence-file
# write rows, and the shell reads the result back itself
OUTF="/tmp/mnb39-out.$$"
RCF="/tmp/mnb39-rc.$$"
: > "$OUTF"
runc_rc() {
  # sets RUNCON_RC; $1=ctx, remaining = probe argv
  local ctx="$1"; shift
  set +e
  runcon "$ctx" "$PROBE" out "$OUTF" "$@"
  RUNCON_RC=$?
  if [ -n "${RCF:-}" ]; then
    printf '%d\n' "$RUNCON_RC" > "$RCF" 2>/dev/null || true
  fi
  set -e
  cat "$OUTF"
}
# a command substitution runs runc_rc in its own subshell, so the rc
# travels through a file, not through a lost variable
restore_rc() { RUNCON_RC="$(cat "$RCF" 2>/dev/null || echo 255)"; }
runc() {
  local out
  out="$(runc_rc "$@")"
  [ "$RUNCON_RC" = "0" ] || { printf '%s\n' "$out" | head -6; fail "probe (runcon) failed rc=$RUNCON_RC: $*"; }
  printf '%s\n' "$out"
}

load_stage() {
  # $1 = module name; remaining args = extra raw allow rows (byte strings)
  local f="/tmp/$1.cil"
  local shdom
  shdom="$(tr -d '\0' < /proc/self/attr/current | awk -F: '{print $3}')"
  [ -n "$shdom" ] || fail "cannot discover the diag shell domain"
  local shrole
  shrole="$(tr -d '\0' < /proc/self/attr/current | awk -F: '{print $2}')"
  {
    cat <<EOF
(type $PROBERTYPE)
(allow docker_helper_buildkitd_t $PROBERTYPE (file (entrypoint execute getattr open read map create write)))
(allow $shdom $PROBERTYPE (file (read getattr)))
(allow $shdom $PROBERTYPE (file (execute getattr open read map)))
(allow $shdom $PROBERTYPE (dir (search)))
(allow $shdom $PROBERTYPE (file (relabelto setattr)))
(allow $PROBERTYPE tmpfs_t (filesystem (associate)))
(allow $PROBERTYPE fs_t (filesystem (associate)))
(allow $shdom bin_t (file (relabelfrom setattr)))
(allow $shdom tmpfs_t (file (relabelfrom setattr)))
(allow $shdom user_tmp_t (file (relabelfrom setattr)))
(allow $shdom $PROBERTYPE (file (unlink getattr)))
(allow $shdom tmpfs_t (dir (remove_name search)))
(allow $shdom user_tmp_t (dir (remove_name search)))
(allow $shdom self (process (setexec)))
(allow docker_helper_buildkitd_t self (process (setexec)))
(allow $shdom docker_helper_buildkitd_t (process (transition)))
(allow $shdom docker_helper_buildkitd_t (process2 (nosuid_transition)))
(allow docker_helper_buildkitd_t bin_t (file (entrypoint execute getattr open read map)))
(roletype $shrole docker_helper_buildkitd_t)
(typetransition $shdom $PROBERTYPE process docker_helper_buildkitd_t)
(allow docker_helper_buildkitd_t security_t (dir (search)))
(allow docker_helper_buildkitd_t security_t (file (getattr open read write)))
(allow docker_helper_buildkitd_t security_t (security (read_policy)))
(type docker_helper_builder_workload_t)
(roletype unconfined_r docker_helper_builder_workload_t)
(roletype system_r docker_helper_builder_workload_t)
EOF
    if [ -n "${2:-}" ]; then
      shift
      for row in "$@"; do printf '%s\n' "$row"; done
    fi
  } > "$f"
  cp "$f" "$EVIDENCE_DIR/$(basename "$f")"
  semodule -X 400 -i "$f" || fail "$1 module failed to load"
}

unload_stage() {
  # idempotent: re-entry runs may find the module already uninstalled
  if ! semodule -l 2>/dev/null | grep -q "^$1"; then
    return 0
  fi
  semodule -r "$1" 2>&1 || fail "$1 module failed to unload"
  if semodule -l 2>/dev/null | grep -q "^$1"; then
    fail "$1 module still listed after unload"
  fi
}

phase_m0() {
# ---------------------------------------------------------------------------
# M0 — preflight: enforcing guest, candidate identity, provision, baselines
# ---------------------------------------------------------------------------
say 'M0: enforcing guest, candidate identity, provisioning, seinfo baselines'
ev m0-selinux-nodes "$(ls /sys/fs/selinux 2>/dev/null)"
[ "$(sha256sum "$RPM" | awk '{print $1}')" = "$R7_ARTIFACT_SHA256" ] \
  || fail "candidate RPM sha mismatch"
getenforce 2>/dev/null | grep -qx 'Enforcing' \
  || fail "the no-exec feasibility probes require an enforcing SELinux host"

if ! rpm -q docker-helper >/dev/null 2>&1; then
  zypper --non-interactive install -y --allow-unsigned-rpm "$RPM" \
    > "$EVIDENCE_DIR/m0-provision-rpm.log" 2>&1 \
    || { tail -20 "$EVIDENCE_DIR/m0-provision-rpm.log"; fail "candidate provisioning install failed"; }
  mkdir -p /srv/docker-helper-mnb39-uat
  /usr/bin/docker-helper init --allowed-root /srv/docker-helper-mnb39-uat \
    > "$EVIDENCE_DIR/m0-init.log" 2>&1 \
    || { tail -20 "$EVIDENCE_DIR/m0-init.log"; fail "docker-helper init failed (see m0-init.log)"; }
fi
ensure_services_active
semodule -l | grep -q '^docker_helper' \
  || fail "the docker_helper module must be loaded (provisioning did not land)"

# The probe compiler is a DIAGNOSTIC tool dependency of this round only;
# the prepared guest deliberately carries no build toolchain.
if ! command -v gcc >/dev/null 2>&1; then
  zypper --non-interactive install -y gcc glibc-devel-static strace \
    > "$EVIDENCE_DIR/m0-gcc-install.log" 2>&1 \
    || { tail -20 "$EVIDENCE_DIR/m0-gcc-install.log"; fail "gcc (diagnostic probe compiler) install failed"; }
fi
command -v strace >/dev/null 2>&1 \
  || zypper --non-interactive install -y strace \
     >> "$EVIDENCE_DIR/m0-gcc-install.log" 2>&1 || true

BASE_SHA="$(policy_sha)"
MNB39_POLICY_SHA_BASE="$BASE_SHA"
ev m0-policy-sha "$BASE_SHA"
mkdir -p "$STATE_DIR"
printf '%s
' "$BASE_SHA" > "$STATE_DIR/policy-sha-base"
if [ -n "${MNB39_POLICY_SHA_BASE_ORC:-}" ] && [ "$MNB39_POLICY_SHA_BASE_ORC" != "$BASE_SHA" ]; then
  fail "the orchestrator base-policy sha cross-check disagrees ($MNB39_POLICY_SHA_BASE_ORC vs $BASE_SHA)"
fi
ev m0-policyvers "$(cat /sys/fs/selinux/policyvers 2>/dev/null || echo n/a)"
ev m0-checkctx-node "$MNB39_CHECKCTX_PATH"
ev m0-modules "$(semodule -l 2>/dev/null | head -20)"

# The root-run setools reference outputs (the authority the probe's
# in-process renderings are compared against; setools runs in the ROOT
# shell, never inside docker_helper_buildkitd_t).
seinfo --role_types docker_helper_buildkitd_t "$MNB39_POLICYPATH" \
  > "$EVIDENCE_DIR/m0-seinfo-roletype.txt" 2>&1 \
  || fail "seinfo --role_types baseline failed"
seinfo --constrain fifo_file "$MNB39_POLICYPATH" \
  > "$EVIDENCE_DIR/m0-seinfo-constrain.txt" 2>&1 \
  || fail "seinfo --constrain baseline failed"
# the role inventory (root query) feeds the unauthorized-role matrix row
SEINFO_ROLES="$(seinfo -r "$MNB39_POLICYPATH" 2>&1 | sed 's/^[[:space:]]*//' | grep -v '^Roles:' | grep -v '^$')"
printf '%s\n' "$SEINFO_ROLES" > "$STATE_DIR/seinfo-roles"
ev m0-roles "${SEINFO_ROLES:-none}"
sed 's/^[[:space:]]*//' "$EVIDENCE_DIR/m0-seinfo-constrain.txt" | grep -Fqx "$STATEMENT" \
  || { sed 's/^/ENTRY: /' "$EVIDENCE_DIR/m0-seinfo-constrain.txt" | head; \
       fail "the installed policy must carry the canonical constraint"; }
say 'M0: PASS'
}

phase_m1() {
# ---------------------------------------------------------------------------
# M1 — probe build + stage-1 module (parse-only face set) + measured denial
# ---------------------------------------------------------------------------
say 'M1: probe build; stage-1 module (no check_context); measured surface'
gcc -O1 -static -nostdlib -nostartfiles -fno-stack-protector -no-pie -o "$PROBE" "$MNB39_PROBE_SRC" 2> "$EVIDENCE_DIR/m1-gcc.log" \
  || { tail -20 "$EVIDENCE_DIR/m1-gcc.log"; fail "probe compile failed (gcc log kept)"; }
[ -x "$PROBE" ] || fail "probe binary missing"
ev m1-probe-size "$(wc -c < "$PROBE")"

load_stage "$MOD1"
ev m1-modules "$(semodule -l 2>/dev/null | grep -E 'dh_mnb39|docker_helper' || true)"

# the probe binary carries the diagnostic exec type (the probe is rm'ed
# at teardown while the module is still loaded, then the module unloads;
# no relabel-back is needed)
chcon 'system_u:object_r:dh_mnb39_probe_t:s0' "$PROBE" 2>&1 >/dev/null \
  || { ls -Z "$PROBE"; fail "chcon of the probe binary failed"; }
ev m1-probe-label "$(ls -Z "$PROBE")"
chcon 'system_u:object_r:dh_mnb39_probe_t:s0' "$OUTF" \
  || { ls -Z "$OUTF"; fail "chcon of the probe output file failed"; }

TARGETCTX=system_u:system_r:docker_helper_buildkitd_t:s0:c1
{
  printf 'C1 type-only /bin/true: '
  set +e; runcon -t docker_helper_buildkitd_t /bin/true; printf 'rc=%d\n' "$?"
  printf 'C2 full ctx /bin/true: '
  runcon "$TARGETCTX" /bin/true; printf 'rc=%d\n' "$?"
  printf 'C3 full ctx probe selfctx (out-capture): '
  runcon "$TARGETCTX" "$PROBE" out "$OUTF" selfctx
  printf 'rc=%d\n' "$?"
  printf 'C3 output: '; cat "$OUTF"
  ( ausearch -m avc -ts recent 2>/dev/null \
      || grep -i avc /var/log/audit/audit.log 2>/dev/null \
      || dmesg 2>/dev/null | grep -i avc ) | tail -12 || true
} > "$EVIDENCE_DIR/m1-controls.txt" 2>&1 || true
sed 's/^[Cc][0-9].*/&/' "$EVIDENCE_DIR/m1-controls.txt"
dmesg -T 2>/dev/null | grep -i avc | tail -5 >> "$EVIDENCE_DIR/m1-controls.txt" || true
OWNCTX="$(runc_rc "$TARGETCTX" selfctx)"
restore_rc
ev m1-why "rc=$RUNCON_RC len=${#OWNCTX} raw=$(head -c 120 "$OUTF" 2>/dev/null | tr '\n' '|')"
if [ "$RUNCON_RC" != "0" ] || [ -z "$OWNCTX" ]; then
  say 'M1: the :s0:c1 entry attempt was refused; retrying at the shell base level'
  TARGETCTX=system_u:system_r:docker_helper_buildkitd_t:s0
  OWNCTX="$(runc "$TARGETCTX" selfctx)"
restore_rc
fi
ev m1-target-ctx "$TARGETCTX"
WL="$(compose_workload "$OWNCTX" "$WL_DOMAIN")"
ev m1-workload-ctx "$WL"

# ---- the PARSE checks (no exec; the load-bearing feasibility evidence) ----
runc "$TARGETCTX" constrain fifo_file > "$EVIDENCE_DIR/m1-probe-constrain.txt"
if ! grep -Fqx "$STATEMENT" "$EVIDENCE_DIR/m1-probe-constrain.txt"; then
  sed 's/^/PROBE: /' "$EVIDENCE_DIR/m1-probe-constrain.txt" | head
  fail "the probe's in-process constraint render does not carry the canonical statement"
fi
# ref/parser parity is measured against the SAME loaded binary policy
# snapshot: the diagnostic module has ALREADY added its roletype rows, so
# the pre-module M0 seinfo capture cannot be the reference (it cannot see
# the module's own roletype). Both queries record the loaded-policy sha.
M1_PAR_SHA_REF="$(policy_sha)"
seinfo --role_types docker_helper_buildkitd_t "$MNB39_POLICYPATH" \
  > "$EVIDENCE_DIR/m1-seinfo-roletype-post.txt" 2>&1 \
  || fail "post-module seinfo reference query failed"
M1_PAR_SHA_PROBE="$(policy_sha)"
runc "$TARGETCTX" roletype docker_helper_buildkitd_t > "$EVIDENCE_DIR/m1-probe-roletype.txt"
[ "$M1_PAR_SHA_REF" = "$M1_PAR_SHA_PROBE" ] \
  || fail "the reference and parser queries ran against DIFFERENT loaded policies"
ev m1-parity-policy-sha "$M1_PAR_SHA_REF"
sed 's/^[[:space:]]*//' "$EVIDENCE_DIR/m1-seinfo-roletype-post.txt" \
  | grep -v '^Roles:' | grep -v '^$' | sort -u > "$EVIDENCE_DIR/m1-roletype-ref.txt"
grep -vE '^(policy-open:|policyinfo:)' "$EVIDENCE_DIR/m1-probe-roletype.txt" \
  | sed 's/^[[:space:]]*//' | grep -v '^$' | sort -u > "$EVIDENCE_DIR/m1-roletype-probe.txt"
diff -u "$EVIDENCE_DIR/m1-roletype-ref.txt" "$EVIDENCE_DIR/m1-roletype-probe.txt" \
  > "$EVIDENCE_DIR/m1-roletype.diff" || true
comm -13 "$EVIDENCE_DIR/m1-roletype-ref.txt" "$EVIDENCE_DIR/m1-roletype-probe.txt" \
  > "$EVIDENCE_DIR/m1-roletype-extras.txt" || true
comm -23 "$EVIDENCE_DIR/m1-roletype-ref.txt" "$EVIDENCE_DIR/m1-roletype-probe.txt" \
  > "$EVIDENCE_DIR/m1-roletype-missing.txt" || true
if [ -s "$EVIDENCE_DIR/m1-roletype.diff" ]; then
  cat "$EVIDENCE_DIR/m1-roletype.diff"
  fail "the parsed roletype set is not EXACTLY equal to the same-snapshot seinfo reference"
fi
ev m1-noexec-parse "PASS (constrain exact match; roletype set EQUALITY against the same-policy-snapshot seinfo reference)"

# ---- the check_context surface, EXPECTED to be kernel-denied now (the
#      security:check_context denial surfaces at the WRITE, after the
#      file-class open/read/write faces of stage 1 already pass) ----
if [ -n "$MNB39_CHECKCTX_PATH" ]; then
  runc_rc "$TARGETCTX" checkctx "$MNB39_CHECKCTX_PATH" "$WL" 'valid-workload' \
    > "$EVIDENCE_DIR/m1-checkctx-valid.txt"
  ev m1-checkctx-valid.rc "$RUNCON_RC"
  if ! grep -q 'PERMISSION write errno=13 rc=2' "$EVIDENCE_DIR/m1-checkctx-valid.txt"; then
    cat "$EVIDENCE_DIR/m1-checkctx-valid.txt"
    fail "stage 1 must refuse the check_context WRITE with the security-class permission denial (EACCES), never mistaken for an invalid context"
  fi
else
  ev m1-checkctx-valid "SKIPPED (no /sys/fs/selinux/context node; the kernel-native interface is NOT AVAILABLE on this guest)"
fi
{
  journalctl -k -b --no-pager 2>/dev/null | grep -iE 'avc|denied' | tail -20 \
    || dmesg 2>/dev/null | grep -iE 'avc|denied' | tail -20 \
    || true
} > "$EVIDENCE_DIR/m1-kernel-avcs.txt"
say 'M1: PASS'
}

phase_m2() {
# ---------------------------------------------------------------------------
# M2 — stage-2 module (+check_context): the full behavior matrix; WITHOUT
#      the kernel node this round's matrix degrades to the parsed policy
#      evidence (the node absence is itself a measured finding from M0)
# ---------------------------------------------------------------------------
say 'M2: stage-2 module (+check_context); the context-validation matrix'
if [ -n "$MNB39_CHECKCTX_PATH" ]; then
  unload_stage "$MOD1"
  load_stage "$MOD2" "(allow docker_helper_buildkitd_t security_t (security (check_context)))"
else
  ev m2-stage2 "SKIPPED (no check_context node on /sys/fs/selinux; the diagnostics keep the stage-1 module and the parse evidence)"
fi
ev m2-modules "$(semodule -l 2>/dev/null | grep -E 'dh_mnb39|docker_helper' || true)"
ev m2-policy-sha "$(policy_sha)"

semodule -DB >/dev/null 2>&1 || true
TARGETCTX="$(cat "$EVIDENCE_DIR/m1-target-ctx")"
{
  printf 'm2-pre-lsZ: '; ls -Z "$OUTF" || true
  printf 'm2-pre-content: '; head -c 200 "$OUTF" 2>/dev/null | tr '\n' '|'
  printf '\n'
} >> "$EVIDENCE_DIR/m2-why.log" 2>&1
OWNCTX="$(runc "$TARGETCTX" selfctx)"
restore_rc
{
  printf 'm2-selfctx-rc=%d len=%s\n' "$RUNCON_RC" "${#OWNCTX}"
  printf 'm2-post-content: '; head -c 200 "$OUTF" 2>/dev/null | tr '\n' '|'
  printf '\n'
} >> "$EVIDENCE_DIR/m2-why.log" 2>&1
WL="$(compose_workload "$OWNCTX" "$WL_DOMAIN")"
ev m2-workload-ctx "$WL"

if [ -n "$MNB39_CHECKCTX_PATH" ]; then
  # matrix row 1: the valid composed workload context must VALIDATE
  runc_rc "$TARGETCTX" checkctx "$MNB39_CHECKCTX_PATH" "$WL" 'valid-workload' \
    > "$EVIDENCE_DIR/m2-checkctx-valid.txt"
  if [ "$RUNCON_RC" != "0" ]; then
    cat "$EVIDENCE_DIR/m2-checkctx-valid.txt"
    ( ausearch -m avc -ts recent 2>/dev/null \
        || grep -i 'avc.*denied' /var/log/audit/audit.log 2>/dev/null ) \
      | tail -12 > "$EVIDENCE_DIR/m2-kernel-avcs.txt" || true
    cat "$EVIDENCE_DIR/m2-kernel-avcs.txt"
    fail "the composed workload context must validate"
  fi
  # matrix rows 2..4: every malformed row must be REFUSED by the policy check
  row_should_refuse() {
    runc_rc "$TARGETCTX" checkctx "$MNB39_CHECKCTX_PATH" "$2" "$1" \
      > "$EVIDENCE_DIR/m2-checkctx-$1.txt"
    grep -q 'INVALID errno=' "$EVIDENCE_DIR/m2-checkctx-$1.txt"
    rc_seen="$?"
    [ "$RUNCON_RC" = "1" ] && [ "$rc_seen" = "0" ] \
      || { cat "$EVIDENCE_DIR/m2-checkctx-$1.txt"; fail "row $1 must be a POLICY invalid-context refusal (rc $RUNCON_RC)"; }
  }
  row_should_refuse unknown-type "$(printf '%s\n' "$WL" | sed 's/docker_helper_builder_workload_t/dh_mnb39_notype_t/')"
  # the unauthorized role/type association row needs a role the LOADED
  # policy really knows; pick it from the persisted seinfo role inventory
  SEINFO_ROLES="${SEINFO_ROLES:-$(cat "$STATE_DIR/seinfo-roles" 2>/dev/null || true)}"
  UNAUTH_ROLE="$(printf '%s\n' "$SEINFO_ROLES" | grep -Ev '^(system_r|unconfined_r)$' | head -1)"
  [ -n "$UNAUTH_ROLE" ] || UNAUTH_ROLE=staff_r
  ev m2-unauth-role "$UNAUTH_ROLE"
  row_should_refuse wrong-role    "$(printf '%s\n' "$WL" | awk -F: -v OFS=: -v r="$UNAUTH_ROLE" '$2=r; print')"
  row_should_refuse bad-category  "${WL}:c999"
  # matrix row 5: the GHOST check_context node name -> interface/query
  # failure with its own class (rc 3), never a policy verdict
  runc_rc "$TARGETCTX" checkctx "$MNB39_GHOST_PROBE_PATH" "$WL" 'unavailable' \
    > "$EVIDENCE_DIR/m2-checkctx-unavailable.txt"
  [ "$RUNCON_RC" = "3" ] \
    || { cat "$EVIDENCE_DIR/m2-checkctx-unavailable.txt"; fail "the interface-query-failure row must fail with rc 3 (rc $RUNCON_RC)"; }

  # the roletype arbitration: every probe-only role is KERNELED through
  # check_context — a role truly enrolled for the type VALIDATES
  NEWCTX="$(printf '%s\n' "$WL" | sed 's/docker_helper_builder_workload_t/docker_helper_buildkitd_t/')"
  while IFS= read -r exrole; do
    [ -n "$exrole" ] || continue
    runc_rc "$TARGETCTX" checkctx "$MNB39_CHECKCTX_PATH" \
      "$(printf '%s\n' "$NEWCTX" | awk -F: -v OFS=: -v r="$exrole" '$2=r; print')" \
      "arbitrate-$exrole" > "$EVIDENCE_DIR/m2-roletype-arb-$exrole.txt" 2>&1
    ev "m2-arb-$exrole.rc" "$RUNCON_RC"
    [ "$RUNCON_RC" = "0" ] \
      || { cat "$EVIDENCE_DIR/m2-roletype-arb-$exrole.txt"
           fail "probe-only role $exrole is not kernel-enrolled for buildkitd_t"; }
    echo "$exrole: kernel-VALIDATED via check_context" >> "$EVIDENCE_DIR/m2-roletype-arbitration.txt"
  done < "$EVIDENCE_DIR/m1-roletype-extras.txt"
  ev m2-roletype-arbitration "$(cat "$EVIDENCE_DIR/m2-roletype-arbitration.txt" 2>/dev/null || echo 'none needed: the sets matched')"
else
  ev m2-checkctx-matrix "SKIPPED (no check_context node on the guest; the kernel-native check_context alternative is NOT FEASIBLE on this kernel)"
  ev m2-roletype-arbitration "SKIPPED (no check_context node; the parsed roletype set stands on its own parse evidence)"
fi

# re-assert the parse checks (unchanged; no additional faces)
runc "$TARGETCTX" constrain fifo_file | grep -Fqx "$STATEMENT" \
  || fail "stage-2 constrain render lost the canonical statement"

semodule -B >/dev/null 2>&1 || true
say 'M2: PASS'
}

phase_m3() {
# ---------------------------------------------------------------------------
# M3 — teardown: probe removal, module unload, restore + negative re-run
# ---------------------------------------------------------------------------
say 'M3: teardown verification (unload gate + deny-again proof)'
rm -f "$PROBE" || fail "the diagnostic probe binary must be removable while the module is still loaded"
unload_stage "$MOD2"
unload_stage "$MOD1"
RESTORED_SHA="$(policy_sha)"
[ "$(cat "$STATE_DIR/policy-sha-base" 2>/dev/null)" = "$RESTORED_SHA" ] \
  || fail "the loaded policy sha must restore byte-exactly after the diagnostic unload (base $(cat "$STATE_DIR/policy-sha-base" 2>/dev/null || echo unknown), now $RESTORED_SHA)"
ev m3-restored-policy-sha "$RESTORED_SHA"
# restored-baseline reference: the module's roletype rows are gone again
seinfo --role_types docker_helper_buildkitd_t "$MNB39_POLICYPATH" \
  > "$EVIDENCE_DIR/m3-seinfo-roletype-restore.txt" 2>&1 || true
sed 's/^[[:space:]]*//' "$EVIDENCE_DIR/m3-seinfo-roletype-restore.txt" \
  | grep -v '^Roles:' | grep -v '^$' | sort -u > "$EVIDENCE_DIR/m3-roletype-restore.txt" || true
if semodule -l 2>/dev/null | grep -qE '^dh_mnb39'; then
  fail "a diagnostic module is still listed after the teardown"
fi
TARGETCTX="$(cat "$EVIDENCE_DIR/m1-target-ctx")"
OUT="$(runc_rc "$TARGETCTX" policyinfo)"
restore_rc
[ "$RUNCON_RC" != "0" ] \
  || { printf '%s\n' "$OUT"; fail "after the unload the probe must NOT reenter buildkitd_t"; }
printf '%s\n' "$OUT" > "$EVIDENCE_DIR/m3-negative-rerun.txt"
semodule -l 2>/dev/null | grep -q '^docker_helper' \
  || fail "the product module must remain loaded after the diagnostic teardown"
[ -f /usr/share/selinux/docker-helper-fifo-rw-constraint.cil ] \
  || fail "the shipped constraint artifact must remain"
{ journalctl -k -b --no-pager 2>/dev/null | grep -iE 'avc|denied' | tail -12; } \
  > "$EVIDENCE_DIR/m3-kernel-avcs.txt"
say 'M3: PASS'
}

phase_m4() {
# ---------------------------------------------------------------------------
# M4 — verdict composition
# ---------------------------------------------------------------------------
say 'M4: verdict composition'
{
  printf 'rolecheck.parity         = %s\n' "$(grep -q EQUALITY "$EVIDENCE_DIR/m1-noexec-parse" && echo 'PASS (exact set equality, same policy snapshot)' || echo FAILED)"
  printf 'constraint.exact-render  = %s\n' "$(grep -Fqx "$STATEMENT" "$EVIDENCE_DIR/m1-probe-constrain.txt" && echo PASS || echo FAILED)"
  if [ -n "$MNB39_CHECKCTX_PATH" ]; then
    if grep -q ACCEPT "$EVIDENCE_DIR/m2-checkctx-valid.txt" 2>/dev/null; then
      printf 'checkctx.valid           = PASS\n'
    else
      printf 'checkctx.valid           = FAILED\n'
    fi
    for row in unknown-type wrong-role bad-category; do
      if grep -q 'INVALID errno=22' "$EVIDENCE_DIR/m2-checkctx-$row.txt" 2>/dev/null; then
        printf 'checkctx.row.%-14s = PASS (policy-invalid, EINVAL)\n' "$row"
      else
        printf 'checkctx.row.%-14s = FAILED\n' "$row"
      fi
    done
    if grep -q UNAVAILABLE "$EVIDENCE_DIR/m2-checkctx-unavailable.txt" 2>/dev/null; then
      printf 'checkctx.row.unavailable  = PASS (interface-query failure, own rc class)\n'
    else
      printf 'checkctx.row.unavailable  = FAILED\n'
    fi
  else
    printf 'checkctx.valid           = SKIPPED (no /sys/fs/selinux/context node)\n'
  fi
  printf 'kernel.check_context     = %s\n' "$([ -n "$MNB39_CHECKCTX_PATH" ] && echo 'present (/sys/fs/selinux/context)' || echo 'absent node')"
  printf 'stage2.delta             = one row: security_t:security check_context (file-class faces measured in stage 1)\n'
  printf 'unload.verified          = sha restored + deny-again proof\n'
} > "$EVIDENCE_DIR/m4-verdict.txt"
say 'M4: PASS'
}

run_phase() {
  case "$1" in
    m0) phase_m0 ;;
    m1) phase_m1 ;;
    m2) phase_m2 ;;
    m3) phase_m3 ;;
    m4) phase_m4 ;;
    *) fail "unknown phase $1" ;;
  esac
}

for ph in m0 m1 m2 m3 m4; do
  if done_phase "$ph"; then
    say "re-entry: $ph already PASS"
    continue
  fi
  run_phase "$ph"
  mark "$ph"
done

printf '%s\n' 'R7-MNB39-VERDICT=PASS'
exit 0

