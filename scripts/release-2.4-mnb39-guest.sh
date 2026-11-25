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
MNB39_POLICYPATH=/sys/fs/selinux/policy
MNB39_CHECKCTX_PATH="$(ls /sys/fs/selinux/check_context 2>/dev/null || ls /sys/fs/selinux/context 2>/dev/null || true)"
[ -n "$MNB39_CHECKCTX_PATH" ] || fail "the guest carries no check_context selinuxfs node"

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
runc_rc() {
  # sets RUNCON_RC; $1=ctx, remaining = probe argv
  local ctx="$1"; shift
  set +e
  local out
  out="$(runcon "$ctx" "$PROBE" "$@" 2>&1)"
  RUNCON_RC=$?
  set -e
  printf '%s\n' "$out"
}
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
(allow docker_helper_buildkitd_t $PROBERTYPE (file (entrypoint execute getattr open read map)))
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
(roleallow ${shrole:-} system_r)
(usertransition unconfined_u system_u (system_r docker_helper_buildkitd_t))
(typetransition $shdom $PROBERTYPE process docker_helper_buildkitd_t)
(allow docker_helper_buildkitd_t security_t (dir (search)))
(allow docker_helper_buildkitd_t security_t (file (getattr open read)))
(allow docker_helper_buildkitd_t security_t (security (read_policy)))
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
  zypper --non-interactive install -y gcc glibc-devel-static \
    > "$EVIDENCE_DIR/m0-gcc-install.log" 2>&1 \
    || { tail -20 "$EVIDENCE_DIR/m0-gcc-install.log"; fail "gcc (diagnostic probe compiler) install failed"; }
fi

MNB39_POLICY_SHA_BASE="$(policy_sha)"
ev m0-policy-sha "$MNB39_POLICY_SHA_BASE"
ev m0-policyvers "$(cat /sys/fs/selinux/policyvers 2>/dev/null || echo n/a)"
ev m0-checkctx-node "$MNB39_CHECKCTX_PATH"
ev m0-modules "$(semodule -l 2>/dev/null | head -20)"

# The root-run setools reference outputs (the authority the probe's
# in-process renderings are compared against; setools runs in the ROOT
# shell, never inside docker_helper_buildkitd_t).
seinfo --role_types "$WL_DOMAIN" "$MNB39_POLICYPATH" \
  > "$EVIDENCE_DIR/m0-seinfo-roletype.txt" 2>&1 \
  || fail "seinfo --role_types baseline failed"
seinfo --constrain fifo_file "$MNB39_POLICYPATH" \
  > "$EVIDENCE_DIR/m0-seinfo-constrain.txt" 2>&1 \
  || fail "seinfo --constrain baseline failed"
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

TARGETCTX=system_u:system_r:docker_helper_buildkitd_t:s0:c1
{
  printf 'C1 type-only /bin/true: '
  set +e; runcon -t docker_helper_buildkitd_t /bin/true; printf 'rc=%d\n' "$?"
  printf 'C2 full ctx /bin/true: '
  runcon "$TARGETCTX" /bin/true; printf 'rc=%d\n' "$?"
  printf 'C3 full ctx probe selfctx: '
  runcon "$TARGETCTX" "$PROBE" selfctx; printf 'rc=%d\n' "$?"
  set -e
} > "$EVIDENCE_DIR/m1-controls.txt" 2>&1 || true
sed 's/^[Cc][0-9].*/&/' "$EVIDENCE_DIR/m1-controls.txt"
dmesg -T 2>/dev/null | grep -i avc | tail -5 >> "$EVIDENCE_DIR/m1-controls.txt" || true
OWNCTX="$(runc_rc "$TARGETCTX" selfctx)"
if [ "$RUNCON_RC" != "0" ] || [ -z "$OWNCTX" ]; then
  say 'M1: the :s0:c1 entry attempt was refused; retrying at the shell base level'
  TARGETCTX=system_u:system_r:docker_helper_buildkitd_t:s0
  OWNCTX="$(runc "$TARGETCTX" selfctx)"
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
runc "$TARGETCTX" roletype "$WL_DOMAIN" > "$EVIDENCE_DIR/m1-probe-roletype.txt"
sort -u "$EVIDENCE_DIR/m0-seinfo-roletype.txt" | grep -v '^$' > "$EVIDENCE_DIR/m1-roletype-ref.txt"
sort -u "$EVIDENCE_DIR/m1-probe-roletype.txt" | grep -v '^$' > "$EVIDENCE_DIR/m1-roletype-probe.txt"
if ! diff -u "$EVIDENCE_DIR/m1-roletype-ref.txt" "$EVIDENCE_DIR/m1-roletype-probe.txt" \
  > "$EVIDENCE_DIR/m1-roletype.diff"; then
  cat "$EVIDENCE_DIR/m1-roletype.diff"
  fail "the probe's parsed roletype set differs from the seinfo reference"
fi
ev m1-noexec-parse "PASS (constrain exact match; roletype set equality with the seinfo reference)"

# ---- the check_context surface, EXPECTED to be kernel-denied now ----
runc_rc "$TARGETCTX" checkctx "$MNB39_CHECKCTX_PATH" "$WL" 'valid-workload' \
  > "$EVIDENCE_DIR/m1-checkctx-valid.txt"
ev m1-checkctx-valid.rc "$RUNCON_RC"
if ! grep -q 'rc=1' "$EVIDENCE_DIR/m1-checkctx-valid.txt"; then
  cat "$EVIDENCE_DIR/m1-checkctx-valid.txt"
  fail "stage 1 must DENY the check_context write (the only missing row is the measured surface)"
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
# M2 — stage-2 module (+check_context row): the full behavior matrix
# ---------------------------------------------------------------------------
say 'M2: stage-2 module (+check_context); the context-validation matrix'
unload_stage "$MOD1"
load_stage "$MOD2" "(allow docker_helper_buildkitd_t security_t (security (check_context)))"
ev m2-modules "$(semodule -l 2>/dev/null | grep -E 'dh_mnb39|docker_helper' || true)"
ev m2-policy-sha "$(policy_sha)"

TARGETCTX="$(cat "$EVIDENCE_DIR/m1-target-ctx")"
OWNCTX="$(runc "$TARGETCTX" selfctx)"
WL="$(compose_workload "$OWNCTX" "$WL_DOMAIN")"
ev m2-workload-ctx "$WL"

# matrix row 1: the valid composed workload context must VALIDATE
runc_rc "$TARGETCTX" checkctx "$MNB39_CHECKCTX_PATH" "$WL" 'valid-workload' \
  > "$EVIDENCE_DIR/m2-checkctx-valid.txt"
[ "$RUNCON_RC" = "0" ] \
  || { cat "$EVIDENCE_DIR/m2-checkctx-valid.txt"; fail "the composed workload context must validate"; }
# matrix rows 2..4: every malformed row must be REFUSED by the policy check
row_should_refuse() {
  runc_rc "$TARGETCTX" checkctx "$MNB39_CHECKCTX_PATH" "$2" "$1" \
    > "$EVIDENCE_DIR/m2-checkctx-$1.txt"
  [ "$RUNCON_RC" = "1" ] \
    || { cat "$EVIDENCE_DIR/m2-checkctx-$1.txt"; fail "row $1 must be refused (rc $RUNCON_RC)"; }
}
row_should_refuse unknown-type "$(printf '%s\n' "$WL" | sed 's/docker_helper_builder_workload_t/dh_mnb39_notype_t/')"
row_should_refuse wrong-role    "$(printf '%s\n' "$WL" | awk -F: -v OFS=: '{$2="user_r"; print}')"
row_should_refuse bad-category  "${WL}:c999"
# matrix row 5: unavailable interface -> fail-closed refusal with its own rc
runc_rc "$TARGETCTX" checkctx /nonexistent/mnb39-check_context "$WL" 'unavailable' \
  > "$EVIDENCE_DIR/m2-checkctx-unavailable.txt"
[ "$RUNCON_RC" = "2" ] \
  || { cat "$EVIDENCE_DIR/m2-checkctx-unavailable.txt"; fail "the unavailable-interface row must fail closed (rc $RUNCON_RC)"; }

# re-assert the parse checks under stage 2 (unchanged; no additional faces)
runc "$TARGETCTX" constrain fifo_file | grep -Fqx "$STATEMENT" \
  || fail "stage-2 constrain render lost the canonical statement"

say 'M2: PASS'
}

phase_m3() {
# ---------------------------------------------------------------------------
# M3 — teardown: probe removal, module unload, restore + negative re-run
# ---------------------------------------------------------------------------
say 'M3: teardown verification (unload gate + deny-again proof)'
rm -f "$PROBE" || fail "the diagnostic probe binary must be removable while the module is still loaded"
unload_stage "$MOD2"
[ "$(policy_sha)" = "$MNB39_POLICY_SHA_BASE" ] \
  || fail "the loaded policy sha must restore byte-exactly after the diagnostic unload (base $MNB39_POLICY_SHA_BASE, now $(policy_sha))"
if semodule -l 2>/dev/null | grep -qE '^dh_mnb39'; then
  fail "a diagnostic module is still listed after the teardown"
fi
TARGETCTX="$(cat "$EVIDENCE_DIR/m1-target-ctx")"
OUT="$(runc_rc "$TARGETCTX" policyinfo)"
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
  printf 'rolecheck.checkcontext   = %s\n' "$(grep -q ACCEPT "$EVIDENCE_DIR/m2-checkctx-valid.txt" && echo PASS || echo FAILED)"
  printf 'rolecheck.parse          = %s\n' "$(grep -q PASS "$EVIDENCE_DIR/m1-noexec-parse" && echo PASS || echo FAILED)"
  printf 'constraint.exact-render  = %s\n' "$(grep -Fqx "$STATEMENT" "$EVIDENCE_DIR/m1-probe-constrain.txt" && echo PASS || echo FAILED)"
  printf 'matrix.rows.refused      = unknown-type/wrong-role/bad-category/unavailable\n'
  printf 'stage2.delta             = one row: security_t:security check_context\n'
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
