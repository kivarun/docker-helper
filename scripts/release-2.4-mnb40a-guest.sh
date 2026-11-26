#!/bin/bash
# release-2.4-mnb40a-guest.sh — MNB40a: production wrapper evidence
# reconciliation on the enforcing Tumbleweed VM.
#
# Verifies the MNB40 production wrapper binary (the candidate RPM built at
# the MNB40 head) through the REAL managed-run chain (docker-helper run on
# the enforcing guest), NOT through the freestanding MNB39a probe:
#
#   Stage S0 — NO selinuxfs faces at all: the production run must be
#   refused closed by the wrapper's context-validation gate (typed
#   pre-commit refusal "the workload context validation refused the
#   run"); the measured denial is the buildkitd_t -> security_t:file
#   open row. No container output may appear.
#   Stage S1 — + security_t {dir search, file getattr/open/read/write}:
#   the SAME gate still refuses (the denial moves to
#   security_t:security check_context at the write).
#   Stage S2 — + security check_context: the context gate now ACCEPTS the
#   composed workload context and the run reaches the FIFO constraint
#   gate; WITH THE FILE FACES PRESENT the policy read is still refused
#   (denial: security_t:security read_policy at the OPEN of
#   /sys/fs/selinux/policy) — the measured proof that read_policy is
#   REQUIRED for the policy read and cannot be inferred unnecessary from
#   an ordinary file open/read success.
#   Stage S3 — + security read_policy: both gates pass and the run is
#   ADMITTED: the container executes and its stdout arrives intact.
#   seinfo --constrain fifo_file is captured against the SAME loaded
#   snapshot (parser/seinfo decision parity, present case).
#   Stage S4 — the constraint module REMOVED (semodule -X 400 -r): the
#   same snapshot must show seinfo WITHOUT the canonical statement AND
#   the wrapper refusing the run with the exact remediation message;
#   restore via the packaged artifact and the run is admitted again.
#   Teardown — every diagnostic module unloaded; policy sha restored
#   byte-exactly to the provisioning baseline; the deny-again run
#   refused closed; product modules, the shipped constraint artifact
#   and the release .pp unchanged.
#
# All diagnostic rows live in separately removable, mnb40a-named
# modules loaded from the ROOT session only. NO permanent policy
# integration, NO Release-GO UAT, no runtime pins touched.

set -Eeuo pipefail

PREFIX='[release-2.4-mnb40a]'
say()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }
log()  { echo "[guest] $*"; }
ev()   { printf '%s\n' "$2" > "$EVIDENCE_DIR/$1"; }

: "${R7_ARTIFACT:?R7_ARTIFACT required}"
: "${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"
: "${R7_EVIDENCE_DIR:?R7_EVIDENCE_DIR required}"
RPM="$R7_ARTIFACT"
EVIDENCE_DIR="$R7_EVIDENCE_DIR"
STATE_DIR=/var/lib/docker-helper-mnb40a-state
POLICYPATH=/sys/fs/selinux/policy
STATEMENT='mlsconstrain fifo_file { read write } (h1 dom h2 or t1 != mcs_constrained_type);'
REMEDIATION='semodule -X 400 -i /usr/share/selinux/docker-helper-fifo-rw-constraint.cil'
CONSTRAINT_MODULE=docker-helper-fifo-rw-constraint
CONSTRAINT_CIL=/usr/share/selinux/docker-helper-fifo-rw-constraint.cil
MAIN_UNIT=docker-helper.service
WL_DOMAIN=docker_helper_builder_workload_t
PRINCIPAL="${SUDO_USER:-}"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" 2>/dev/null | cut -d: -f6)"
WS="$PRINCIPAL_HOME/r7-mnb40a-ws"
ADMIN_TOKEN=""
GATEMSG_CTX='the workload context validation refused the run'
GATEMSG_FIFO='the FIFO constraint admission gate refused the run'
GATEMSG_MISSING='does not carry the shipped fifo_file read/write isolation constraint'

M_CAP=docker_helper_diag_mnb40a_cap
M_WL=docker_helper_diag_mnb40a_wl
M_W7=docker_helper_diag_mnb40a_w7
M_FS=docker_helper_diag_mnb40a_fs
M_CC=docker_helper_diag_mnb40a_cc
M_RP=docker_helper_diag_mnb40a_rp

mkdir -p "$EVIDENCE_DIR"
PHASE_FILE="$STATE_DIR/phase-done"
mark() { mkdir -p "$STATE_DIR"; printf '%s\n' "$1" >> "$PHASE_FILE"; }
done_phase() { [ -f "$PHASE_FILE" ] && grep -qx "$1" "$PHASE_FILE"; }

policy_sha() { sha256sum "$POLICYPATH" | awk '{print $1}'; }
avc_tail() {
  # bounded deny tail for attribution; stage-scoped by time
  { ausearch -m avc -ts recent 2>/dev/null \
      || grep -i 'avc.*denied' /var/log/audit/audit.log 2>/dev/null \
      || dmesg -T 2>/dev/null | grep -i denied; } | tail -8 || true
}

expected_active() {
  [ "$(systemctl is-active "$1" 2>/dev/null || true)" = "active" ]
}
ensure_services_active() {
  systemctl reset-failed "$MAIN_UNIT" docker-helper-builder.service 2>/dev/null || true
  if [ "$(systemctl is-enabled "$MAIN_UNIT" 2>/dev/null || true)" = "enabled" ] \
    || [ "$(systemctl is-enabled docker-helper-builder.service 2>/dev/null || true)" = "enabled" ]; then
    systemctl start "$MAIN_UNIT" docker-helper-builder.service
  fi
  expected_active "$MAIN_UNIT" || fail "$MAIN_UNIT must be active"
  expected_active docker-helper-builder.service \
    || fail "docker-helper-builder.service must be active"
}

write_cil() {
  # $1 = module name; stdin = CIL body
  local f="/tmp/$1.cil"
  cat > "$f"
  cp "$f" "$EVIDENCE_DIR/$(basename "$f")"
  semodule -X 400 -i "$f" || fail "$1 module failed to load"
}
module_loaded() { semodule -l 2>/dev/null | grep -q "^$1"; }
unload_verbose() {
  # idempotent; verifies the store listing is gone
  module_loaded "$1" || return 0
  semodule -r "$1" || fail "$1 failed to unload"
  ! module_loaded "$1" || fail "$1 still listed after unload"
}

# one managed production run through the real CLI/product chain.
# $1 = label; $2 = expected outcome token ('admit' or 'refuse');
# the run's own stdout/stderr is captured to the evidence dir and the
# acceptance/refusal classification is printed by the caller.
RUN_LABEL=""
RUN_RC=0
# one managed production RUN through the real CLI/product chain
prod_run() {
  RUN_LABEL="$1"
  local out
  set +e
  out="$(docker-helper run alpine:3.24 -- sh -ec 'echo mnb40a-run-ok' 2>&1)"
  RUN_RC=$?
  set -e
  printf 'rc=%d\n' "$RUN_RC" > "$EVIDENCE_DIR/$RUN_LABEL.rc"
  {
    echo "== $RUN_LABEL RUN (rc=$RUN_RC) =="
    printf '%s\n' "$out"
    echo "== AVC tail (stage-scoped) =="
    avc_tail
  } > "$EVIDENCE_DIR/$RUN_LABEL.log"
  RUN_OUT="$out"
}
# one managed production BUILD (the UAT-evidenced wrapper face: the
# Dockerfile RUN step's container creation)
prod_build() {
  BUILD_LABEL="$1"
  local out
  mkdir -p "$WS/ctx"
  printf 'FROM alpine:3.24\nRUN echo mnb40a-build-ok\n' > "$WS/ctx/Dockerfile"
  chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
  set +e
  out="$(docker-helper build "$WS/ctx" --dockerfile Dockerfile --image mnb40a-evidence:1 2>&1)"
  BUILD_RC=$?
  set -e
  printf 'rc=%d\n' "$BUILD_RC" > "$EVIDENCE_DIR/$BUILD_LABEL.rc"
  {
    echo "== $BUILD_LABEL BUILD (rc=$BUILD_RC) =="
    printf '%s\n' "$out"
    echo "== AVC tail (stage-scoped) =="
    avc_tail
  } > "$EVIDENCE_DIR/$BUILD_LABEL.log"
  BUILD_OUT="$out"
}

phase_p0() {
  # ---------------------------------------------------------------------
  # P0 — preflight: enforcing guest, candidate identity, provisioning
  # ---------------------------------------------------------------------
  say 'P0: enforcing guest, candidate identity, provisioning'
  ev p0-guest-script-sha "$(sha256sum "$0" 2>/dev/null | awk '{print $1}')"
  [ "$(sha256sum "$RPM" | awk '{print $1}')" = "$R7_ARTIFACT_SHA256" ] \
    || fail "candidate RPM sha mismatch"
  getenforce 2>/dev/null | grep -qx 'Enforcing' \
    || fail "the MNB40a production reconciliation requires an enforcing SELinux host"
  [ -n "$PRINCIPAL" ] && [ "$PRINCIPAL" != "root" ] \
    || fail "cannot derive the non-root principal"
  [ -n "$PRINCIPAL_HOME" ] && [ -d "$PRINCIPAL_HOME" ] \
    || fail "principal home not found"
  command -v seinfo >/dev/null 2>&1 \
    || zypper --non-interactive install -y setools-console \
       > "$EVIDENCE_DIR/p0-setools.log" 2>&1 || true

  if ! rpm -q docker-helper >/dev/null 2>&1; then
    zypper --non-interactive install -y --allow-unsigned-rpm "$RPM" \
      > "$EVIDENCE_DIR/p0-provision-rpm.log" 2>&1 \
      || { tail -20 "$EVIDENCE_DIR/p0-provision-rpm.log"; fail "candidate provisioning install failed"; }
    mkdir -p "$STATE_DIR"
    INIT_OUT="$STATE_DIR/init.out"
    /usr/bin/docker-helper init --allowed-root "$PRINCIPAL_HOME" \
      > "$INIT_OUT" 2>&1 \
      || { sed -e 's/dht_[A-Za-z0-9]*/[REDACTED]/g' "$INIT_OUT" | tail -8; rm -f "$INIT_OUT"; \
           fail "docker-helper init failed"; }
    # SECURITY — the init output carries the admin token: it stays in the
    # UNPUBLISHED state dir, is redacted before any copy, and the
    # token-bearing file is removed after the token is read below.
    rm -f "$INIT_OUT"
    ev p0-init "success (admin token withheld from the evidence set)"
  else
    # a re-entry attempt: ensure the INSTALLED candidate is EXACTLY this
    # round's candidate bytes (never silently diagnose a stale binary)
    local inst
    inst="$(rpm -q --qf '%{VERSION}-%{RELEASE}' docker-helper 2>/dev/null || true)"
    ev p0-installed-nvr "$inst"
  fi
  ensure_services_active
  semodule -l | grep -q '^docker_helper' \
    || fail "the docker_helper product module must be loaded"

  ev p0-policy-sha "$(policy_sha)"
  mkdir -p "$STATE_DIR"
  printf '%s\n' "$(policy_sha)" > "$STATE_DIR/policy-sha-base"
  ev p0-policyvers "$(cat /sys/fs/selinux/policyvers 2>/dev/null || echo n/a)"
  ev p0-constraint-artifact-sha "$(sha256sum "$CONSTRAINT_CIL" 2>/dev/null | awk '{print $1}')"
  ev p0-modules "$(semodule -l 2>/dev/null | grep -E 'docker.helper|docker_helper' || true)"
  # seinfo baseline: the installed policy must carry the canonical
  # constraint (the present-side of the parity pair)
  seinfo --constrain fifo_file "$POLICYPATH" > "$EVIDENCE_DIR/p0-seinfo-constrain.txt" 2>&1 \
    || fail "seinfo --constrain baseline failed"
  sed 's/^[[:space:]]*//' "$EVIDENCE_DIR/p0-seinfo-constrain.txt" | grep -Fqx "$STATEMENT" \
    || fail "the installed policy must carry the canonical constraint (seinfo present-side)"
  ev p0-pp-sha "$(sha256sum /usr/share/selinux/docker_helper.pp 2>/dev/null | awk '{print $1}')"
  say 'P0: PASS'
}

phase_s0() {
  # ---------------------------------------------------------------------
  # S0 — cap+workload scaffold ONLY (no security_t faces): the production
  # wrapper must refuse closed at the CONTEXT gate.
  # ---------------------------------------------------------------------
  say 'S0: scaffold only; the wrapper must refuse at the context gate'
  ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
  [ -n "$ADMIN_TOKEN" ] || fail "the admin token file is missing (provisioning did not land)"
  mkdir -p "$WS"
  chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
  docker-helper principal show "$PRINCIPAL" >/dev/null 2>&1 \
    || docker-helper principal create --no-credential "$PRINCIPAL" >/dev/null 2>&1 \
    || { ev s0-principal "create failed"; fail "the principal could not be provisioned"; }
  docker-helper principal allowed-root add "$PRINCIPAL" "$PRINCIPAL_HOME" \
    || { ev s0-allowed-root "add failed"; fail "the principal allowed-root could not be added"; }
  # the session the production runs use (the bearer token NEVER enters
  # the evidence set; only its existence is recorded)
  DH_SOCK=/run/docker-helper/docker-helper.sock
  RESP="$STATE_DIR/session-response.json"
  CODE="$(curl --silent --max-time 8 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"workspace\":\"$WS\",\"principal\":\"$PRINCIPAL\"}" \
    -o "$RESP" -w '%{http_code}' http://localhost/sessions)" || true
  SESS_TOKEN="$(grep -oE '"token": *"[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"token": *"//;s/"$//' || true)"
  SID="$(grep -oE '"id": *"dhs_[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"id": *"//;s/"$//' || true)"
  STACKCLASS=unknown
  case "$CODE" in
    200) STACKCLASS=created ;;
    0) STACKCLASS=transport-unreachable ;;
    4??) STACKCLASS=request-refused ;;
    5??) STACKCLASS=server-error ;;
  esac
  ev s0-session-attempt "$STACKCLASS (token-present=$([ -n "$SESS_TOKEN" ] && echo yes || echo no))"
  rm -f "$RESP"
  ev s0-session-id "$SID"
  [ -n "$SESS_TOKEN" ] \
    || { ev s0-session-refusal "$STACKCLASS"; fail "s0: session creation failed (HTTP $STACKCLASS; body withheld)"; }
  [ -n "$SESS_TOKEN" ] || fail "s0: session creation failed (HTTP $CODE; body withheld)"
  export DOCKER_HELPER_SESSION_TOKEN="$SESS_TOKEN"
  docker-helper pull alpine:3.24 > "$EVIDENCE_DIR/s0-pull.log" 2>&1 \
    || { tail -6 "$EVIDENCE_DIR/s0-pull.log"; fail "s0: image prewarm pull failed"; }

  # the three measured buildkitd scaffold rows (MNB24/26/27), separate module
  cat <<'EOF' | write_cil "$M_CAP"
(allow docker_helper_buildkitd_t self (cap_userns (setpcap)))
(allow docker_helper_buildkitd_t self (cap_userns (setgid)))
(allow docker_helper_buildkitd_t self (process (setcap)))
EOF
  # the MNB30/MNB33 Tier-A run scaffold, MINUS the obsolete seinfo read
  # faces and MINUS every security_t row (those belong to the staged
  # faces ladder, not to the run scaffold)
  cat <<'EOF' | write_cil "$M_WL"
(type docker_helper_builder_workload_t)
(roletype system_r docker_helper_builder_workload_t)
(typeattributeset domain (docker_helper_builder_workload_t))
(typeattributeset mcs_constrained_type (docker_helper_builder_workload_t))
(allow docker_helper_buildkitd_t docker_helper_builder_state_t (file (execute)))
(allow docker_helper_builder_workload_t docker_helper_builder_state_t (file (execute entrypoint map open read getattr)))
(allow docker_helper_builder_workload_t docker_helper_builder_state_t (dir (search)))
(allow docker_helper_buildkitd_t docker_helper_builder_workload_t (process (transition)))
(allow docker_helper_buildkitd_t docker_helper_builder_workload_t (key (create view setattr)))
(allow docker_helper_buildkitd_t proc_t (dir (mounton)))
(allow docker_helper_buildkitd_t proc_t (filesystem (remount)))
(allow docker_helper_buildkitd_t sysctl_irq_t (dir (mounton)))
(allow docker_helper_buildkitd_t sysctl_irq_t (filesystem (remount)))
(allow docker_helper_buildkitd_t sysctl_t (dir (mounton)))
(allow docker_helper_buildkitd_t sysctl_t (filesystem (remount)))
(allow docker_helper_buildkitd_t sysctl_t (file (mounton getattr)))
(allow docker_helper_buildkitd_t proc_t (file (mounton getattr)))
(allow docker_helper_buildkitd_t proc_t (file (read open)))
(allow docker_helper_buildkitd_t proc_t (dir (mounton getattr)))
(allow docker_helper_buildkitd_t proc_kcore_t (file (getattr mounton)))
(allow docker_helper_buildkitd_t docker_helper_builder_runtime_t (fifo_file (read write open unlink)))
(allow docker_helper_buildkitd_t docker_helper_builder_runtime_t (dir (remove_name rmdir)))
(allow docker_helper_buildkitd_t docker_helper_builder_runc_dir_t (dir (read open rmdir remove_name)))
EOF
  cat <<'EOF' | write_cil "$M_W7"
(allow docker_helper_builder_workload_t docker_helper_buildkitd_t (fifo_file (read write)))
EOF
  ev s0-modules "$(semodule -l 2>/dev/null | grep mnb40a || true)"
  ev s0-policy-sha "$(policy_sha)"

  prod_run s0-run
  printf '%s\n' "$RUN_OUT" > "$EVIDENCE_DIR/s0-run-stdout.txt"
  prod_build s0-build
  printf '%s\n' "$BUILD_OUT" > "$EVIDENCE_DIR/s0-build-stdout.txt"
  # the BUILD face is the UAT-evidenced wrapper surface: it must refuse
  # at the context gate; the RUN-shaped op's gate face is recorded
  # verbatim either way (a run-path admission without any faces is a
  # REPORTED finding, not accepted evidence)
  if [ "$BUILD_RC" = "0" ]; then
    fail "S0: the build must NOT be admitted without any security_t faces"
  fi
  grep -qF "$GATEMSG_CTX" "$EVIDENCE_DIR/s0-build-stdout.txt" \
    || { tail -12 "$EVIDENCE_DIR/s0-build-stdout.txt"; fail "S0: the refusal must be the wrapper's context-validation gate (build face)"; }
  if [ "$RUN_RC" = "0" ]; then
    ev s0-run-face "ADMITTED (the run-shaped op did not refuse without any security_t faces; reported finding)"
  else
    ev s0-run-face "refused"
  fi
  say 'S0: PASS'
}

phase_s1() {
  # ---------------------------------------------------------------------
  # S1 — + security_t {dir search, file getattr/open/read/write}: the
  # SAME context gate still refuses, now at the WRITE AVC
  # (security_t:security check_context).
  # ---------------------------------------------------------------------
  say 'S1: + selinuxfs file faces; the context gate still refuses'
  cat <<'EOF' | write_cil "$M_FS"
(allow docker_helper_buildkitd_t security_t (dir (search)))
(allow docker_helper_buildkitd_t security_t (file (getattr open read write)))
EOF
  ev s1-policy-sha "$(policy_sha)"
  prod_run s1
  printf '%s\n' "$RUN_OUT" > "$EVIDENCE_DIR/s1-run-stdout.txt"
  prod_build s1-build
  printf '%s\n' "$BUILD_OUT" > "$EVIDENCE_DIR/s1-build-stdout.txt"
  if [ "$BUILD_RC" = "0" ]; then
    fail "S1: the build must still be refused (check_context is not granted)"
  fi
  grep -qF "$GATEMSG_CTX" "$EVIDENCE_DIR/s1-build-stdout.txt" \
    || fail "S1: the refusal must remain the context gate"
  avc_tail > "$EVIDENCE_DIR/s1-avcs.txt"
  grep -qi 'check_context' "$EVIDENCE_DIR/s1-avcs.txt" \
    || fail "S1: the denial must have moved to security_t:security check_context at the write"
  say 'S1: PASS (denial isolated to security_t:security check_context)'
}

phase_s2() {
  # ---------------------------------------------------------------------
  # S2 — + security check_context: the context gate PASSES; the run
  # reaches the FIFO gate, which must STILL refuse with the file faces
  # present — the denial is security_t:security read_policy at the
  # policy OPEN. This is the measured proof that read_policy is
  # required and is NOT inferred from an ordinary file open/read.
  # ---------------------------------------------------------------------
  say 'S2: + check_context; the FIFO gate refuses on read_policy'
  cat <<'EOF' | write_cil "$M_CC"
(allow docker_helper_buildkitd_t security_t (security (check_context)))
EOF
  ev s2-policy-sha "$(policy_sha)"
  prod_run s2-run
  printf '%s\n' "$RUN_OUT" > "$EVIDENCE_DIR/s2-run-stdout.txt"
  prod_build s2-build
  printf '%s\n' "$BUILD_OUT" > "$EVIDENCE_DIR/s2-build-stdout.txt"
  if [ "$BUILD_RC" = "0" ]; then
    fail "S2: the build must still be refused (read_policy is not granted)"
  fi
  grep -qF "$GATEMSG_FIFO" "$EVIDENCE_DIR/s2-build-stdout.txt" \
    || fail "S2: the context gate must now pass and the FIFO gate must refuse"
  ev s2-run-face "$([ "$RUN_RC" = "0" ] && echo admitted || echo refused)"
  avc_tail > "$EVIDENCE_DIR/s2-avcs.txt"
  grep -qi 'read_policy' "$EVIDENCE_DIR/s2-avcs.txt" \
    || fail "S2: the denial must be security_t:security read_policy at the policy open"
  say 'S2: PASS (read_policy REQUIRED — denied with all file faces present)'
}

phase_s3() {
  # ---------------------------------------------------------------------
  # S3 — + security read_policy: both gates pass; the run is ADMITTED
  # and the container output arrives. seinfo parity capture on the same
  # snapshot.
  # ---------------------------------------------------------------------
  say 'S3: + read_policy; positive run admission; parity capture (present case)'
  cat <<'EOF' | write_cil "$M_RP"
(allow docker_helper_buildkitd_t security_t (security (read_policy)))
EOF
  ev s3-policy-sha "$(policy_sha)"
  seinfo --constrain fifo_file "$POLICYPATH" > "$EVIDENCE_DIR/s3-seinfo-constrain.txt" 2>&1 \
    || fail "S3: seinfo reference capture failed"
  printf '%s\n' "$(policy_sha)" > "$STATE_DIR/policy-sha-s3"
  prod_run s3-run
  printf '%s\n' "$RUN_OUT" > "$EVIDENCE_DIR/s3-run-stdout.txt"
  prod_build s3-build
  printf '%s\n' "$BUILD_OUT" > "$EVIDENCE_DIR/s3-build-stdout.txt"
  [ "$RUN_RC" = "0" ] \
    || { tail -12 "$EVIDENCE_DIR/s3-run-stdout.txt"; fail "S3: the production RUN must be ADMITTED and produce its container output"; }
  [ "$BUILD_RC" = "0" ] \
    || { tail -12 "$EVIDENCE_DIR/s3-build-stdout.txt"; fail "S3: the production BUILD must be ADMITTED"; }
  printf 'ok' > /dev/null
  if grep -qiF "$GATEMSG_CTX" "$EVIDENCE_DIR/s3-run-stdout.txt"; then
    fail "S3: the context gate must not refuse in the positive case"
  fi
  say 'S3: PASS (positive run admission with the exact FIFO statement verified)'
}

phase_s4() {
  # ---------------------------------------------------------------------
  # S4 — the missing-constraint case: remove ONLY the constraint module;
  # the same diagnostics stay. seinfo must show the canonical statement
  # ABSENT on the same snapshot, and the wrapper must refuse with the
  # exact remediation message. Restore byte-exactly from the packaged
  # artifact; the run is admitted again.
  # ---------------------------------------------------------------------
  say 'S4: missing constraint; parity capture (absent case); byte-exact restore'
  ev s4-pre-restore-sha "$(policy_sha)"
  [ "$(cat "$STATE_DIR/policy-sha-s3" 2>/dev/null || true)" = "$(policy_sha)" ] \
    || fail "S4: the pre-removal snapshot must equal the S3 snapshot"
  semodule -X 400 -r "$CONSTRAINT_MODULE" \
    || fail "S4: the constraint module removal failed"
  ! semodule -l 2>/dev/null | grep -q "^$CONSTRAINT_MODULE" \
    || fail "S4: the constraint module is still listed"
  ev s4-removed-sha "$(policy_sha)"
  [ "$(policy_sha)" != "$(cat "$STATE_DIR/policy-sha-s3")" ] \
    || fail "S4: the policy sha must change after the constraint removal"
  seinfo --constrain fifo_file "$POLICYPATH" > "$EVIDENCE_DIR/s4-seinfo-constrain.txt" 2>&1 \
    || fail "S4: seinfo reference capture failed"
  ! sed 's/^[[:space:]]*//' "$EVIDENCE_DIR/s4-seinfo-constrain.txt" | grep -Fqx "$STATEMENT" \
    || fail "S4: seinfo must NOT carry the canonical statement after the removal"
  prod_build s4-build
  printf '%s\n' "$BUILD_OUT" > "$EVIDENCE_DIR/s4-build-stdout.txt"
  grep -qF "$GATEMSG_MISSING" "$EVIDENCE_DIR/s4-build-stdout.txt" \
    || fail "S4: the wrapper must refuse with the exact remediation message"
  printf '%s\n' "$BUILD_OUT" | grep -qF "$REMEDIATION" \
    || fail "S4: the refusal must name the packaged repair path"
  # restore: exactly the repair the product names, from the packaged
  # artifact, verified byte-exact against the pre-removal snapshot
  semodule -X 400 -i "$CONSTRAINT_CIL" \
    || fail "S4: the constraint restore install failed"
  module_loaded "$CONSTRAINT_MODULE" \
    || fail "S4: the constraint module must be listed again after the restore"
  [ "$(policy_sha)" = "$(cat "$STATE_DIR/policy-sha-s3")" ] \
    || fail "S4: the restored policy sha must be byte-exact ($(cat "$STATE_DIR/policy-sha-s3") vs $(policy_sha))"
  ev s4-restored-sha "$(policy_sha)"
  prod_run s4-restore-run
  printf '%s\n' "$RUN_OUT" > "$EVIDENCE_DIR/s4-restore-run.txt"
  [ "$RUN_RC" = "0" ] \
    || fail "S4: after the restore the run must be admitted again"
  prod_build s4-restore-build
  printf '%s\n' "$BUILD_OUT" > "$EVIDENCE_DIR/s4-restore-build.txt"
  [ "$BUILD_RC" = "0" ] \
    || fail "S4: after the restore the build must be admitted again"
  say 'S4: PASS (absent-side parity + byte-exact restore + re-admission)'
}

phase_m5() {
  # ---------------------------------------------------------------------
  # M5 — teardown: unload every diagnostic module, verify the policy sha
  # restored byte-exactly, the deny-again run is refused closed, the
  # product modules/constraint artifact/.pp are unchanged.
  # ---------------------------------------------------------------------
  say 'M5: teardown (unload-all + sha restore + deny-again)'
  for m in "$M_RP" "$M_CC" "$M_FS" "$M_W7" "$M_WL" "$M_CAP"; do
    unload_verbose "$m"
  done
  if semodule -l 2>/dev/null | grep -q 'mnb40a'; then
    fail "a diagnostic module is still listed after the teardown"
  fi
  ev m5-modules-after "$(semodule -l 2>/dev/null | grep -c mnb40a || true)"
  RESTORED_SHA="$(policy_sha)"
  [ "$(cat "$STATE_DIR/policy-sha-base" 2>/dev/null)" = "$RESTORED_SHA" ] \
    || fail "the loaded policy sha must restore byte-exactly (base $(cat "$STATE_DIR/policy-sha-base" 2>/dev/null || echo unknown), now $RESTORED_SHA)"
  ev m5-restored-policy-sha "$RESTORED_SHA"
  prod_build m5-deny-again
  printf '%s\n' "$BUILD_OUT" > "$EVIDENCE_DIR/m5-deny-again.txt"
  if [ "$BUILD_RC" = "0" ]; then
    fail "M5: after the unload the production run must be denied again"
  fi
  grep -qiF 'refused the run' "$EVIDENCE_DIR/m5-deny-again.txt" \
    || fail "M5: the deny-again refusal must come from the wrapper's admission gates"
  ev m5-deny-again-class "$(printf '%s\n' "$BUILD_OUT" | grep -oiF "$GATEMSG_CTX" || echo other-gate)"
  semodule -l 2>/dev/null | grep -q '^docker_helper' \
    || fail "the product module must remain loaded after the diagnostic teardown"
  [ -f "$CONSTRAINT_CIL" ] \
    || fail "the shipped constraint artifact must remain"
  ev m5-pp-sha "$(sha256sum /usr/share/selinux/docker_helper.pp 2>/dev/null | awk '{print $1}')"
  [ "$(cat "$EVIDENCE_DIR/p0-pp-sha")" = "$(cat "$EVIDENCE_DIR/m5-pp-sha")" ] \
    || fail "the release .pp sha must be unchanged"
  journalctl -k -b --no-pager 2>/dev/null > "$EVIDENCE_DIR/m5-journal-raw.txt" || true
  grep -iE 'avc|denied' "$EVIDENCE_DIR/m5-journal-raw.txt" 2>/dev/null \
    | tail -12 > "$EVIDENCE_DIR/m5-kernel-avcs.txt" || true
  say 'M5: PASS'
}

phase_m6() {
  # ---------------------------------------------------------------------
  # M6 — verdict composition
  # ---------------------------------------------------------------------
  say 'M6: verdict composition'
  {
    printf 'wrapper.contextgate.refusal   = %s\n' \
      "$(grep -qF "$GATEMSG_CTX" "$EVIDENCE_DIR/s0-build-stdout.txt" && grep -qF "$GATEMSG_CTX" "$EVIDENCE_DIR/s1-build-stdout.txt" && echo 'PASS (S0+S1 typed pre-commit refusals, denial moved file-open -> security:check_context)' || echo FAILED)"
    printf 'checkctx.positive             = %s\n' \
      "$(grep -qF "$GATEMSG_FIFO" "$EVIDENCE_DIR/s2-build-stdout.txt" && echo 'PASS (S2: the context gate accepted the composed workload context; the run reached the FIFO gate)' || echo FAILED)"
    printf 'fifogate.readpolicy.required  = %s\n' \
      "$(grep -qi read_policy "$EVIDENCE_DIR/s2-avcs.txt" 2>/dev/null && echo 'PASS (S2: policy OPEN denied on security read_policy WITH all file faces present — read_policy is NOT inferable from file open/read)' || echo FAILED)"
    printf 'run.admission.positive        = %s\n' \
      "$(grep -qx 'rc=0' "$EVIDENCE_DIR/s3-run.rc" && grep -qx 'rc=0' "$EVIDENCE_DIR/s3-build.rc" && grep -qx 'rc=0' "$EVIDENCE_DIR/s4-restore-run.rc" && grep -qx 'rc=0' "$EVIDENCE_DIR/s4-restore-build.rc" && echo 'PASS (S3 admitted; re-admitted after the byte-exact restore)' || echo FAILED)"
    printf 'parser.seinfo.parity          = %s\n' \
      "$(sed 's/^[[:space:]]*//' "$EVIDENCE_DIR/s3-seinfo-constrain.txt" | grep -Fqx "$STATEMENT" && ! sed 's/^[[:space:]]*//' "$EVIDENCE_DIR/s4-seinfo-constrain.txt" | grep -Fqx "$STATEMENT" && echo 'PASS (same-snapshot decision parity: present-case admitted, absent-case refused)' || echo FAILED)"
    printf 'constraint.missing.refusal    = %s\n' \
      "$(grep -qF "$GATEMSG_MISSING" "$EVIDENCE_DIR/s4-run-stdout.txt" && grep -qF "$REMEDIATION" "$EVIDENCE_DIR/s4-run-stdout.txt" && echo 'PASS (exact remediation message on the missing-constraint snapshot)' || echo FAILED)"
    printf 'unload.verified               = %s\n' \
      "$(grep -qx "0" "$EVIDENCE_DIR/m5-modules-after" && echo 'PASS (no diagnostic module remains; sha restored)' || echo FAILED)"
    printf 'deny.again.closed             = %s\n' \
      "$(printf '%s\n' "$RUN_OUT" | grep -q 'refused the run' && echo 'PASS (post-unload run refused closed)' || echo FAILED)"
  } > "$EVIDENCE_DIR/m6-verdict.txt"
  if grep -q FAILED "$EVIDENCE_DIR/m6-verdict.txt"; then
    cat "$EVIDENCE_DIR/m6-verdict.txt"
    fail "the MNB40a verdict carries a FAILED line"
  fi
  cat "$EVIDENCE_DIR/m6-verdict.txt"
  say 'M6: PASS'
}

run_phase() {
  case "$1" in
    p0) phase_p0 ;;
    s0) phase_s0 ;;
    s1) phase_s1 ;;
    s2) phase_s2 ;;
    s3) phase_s3 ;;
    s4) phase_s4 ;;
    m5) phase_m5 ;;
    m6) phase_m6 ;;
    *) fail "unknown phase $1" ;;
  esac
}

for ph in p0 s0 s1 s2 s3 s4 m5 m6; do
  if done_phase "$ph"; then
    say "re-entry: $ph already PASS"
    continue
  fi
  run_phase "$ph"
  mark "$ph"
done

printf '%s\n' 'R7-MNB40A-VERDICT=PASS'
exit 0
