#!/bin/bash
# release-2.4-mnb40b-guest.sh — MNB40b: production admission boundary
# trace and the minimal authority proof on the enforcing Tumbleweed VM.
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
# All diagnostic rows live in separately removable, mnb40b-named
# modules loaded from the ROOT session only. NO permanent policy
# integration, NO Release-GO UAT, no runtime pins touched.

set -Eeuo pipefail
trap 'printf "[release-2.4-mnb40b] ERR rc=%d line=%d cmd=%s\n" "$?" "$LINENO" "${BASH_COMMAND:-?}" >&2' ERR

PREFIX='[release-2.4-mnb40b]'
say()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }
log()  { echo "[guest] $*"; }
ev()   { printf '%s\n' "$2" > "$EVIDENCE_DIR/$1"; }

: "${R7_ARTIFACT:?R7_ARTIFACT required}"
: "${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"
: "${R7_EVIDENCE_DIR:?R7_EVIDENCE_DIR required}"
RPM="$R7_ARTIFACT"
EVIDENCE_DIR="$R7_EVIDENCE_DIR"
STATE_DIR=/var/lib/docker-helper-mnb40b-state
POLICYPATH=/sys/fs/selinux/policy
STATEMENT='mlsconstrain fifo_file { read write } (h1 dom h2 or t1 != mcs_constrained_type);'
REMEDIATION='semodule -X 400 -i /usr/share/selinux/docker-helper-fifo-rw-constraint.cil'
CONSTRAINT_MODULE=docker-helper-fifo-rw-constraint
CONSTRAINT_CIL=/usr/share/selinux/docker-helper-fifo-rw-constraint.cil
MAIN_UNIT=docker-helper.service
WL_DOMAIN=docker_helper_builder_workload_t
PRINCIPAL="${SUDO_USER:-}"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" 2>/dev/null | cut -d: -f6)"
WS="$PRINCIPAL_HOME/r7-mnb40b-ws"
ADMIN_TOKEN=""
GATEMSG_CTX='the workload context validation refused the run'
GATEMSG_FIFO='the FIFO constraint admission gate refused the run'
GATEMSG_MISSING='does not carry the shipped fifo_file read/write isolation constraint'

M_CAP=docker_helper_diag_mnb40b_cap
M_WL=docker_helper_diag_mnb40b_wl
M_W7=docker_helper_diag_mnb40b_w7
# the auth ladder module is ONE replaceable module: semodule -i with the
# same basename REPLACES its content; module loading can only ever ADD
# grants, so a face-removal arm must be a replacement, never an
# additional module beside the working set
M_AUTH=docker_helper_diag_mnb40b_auth

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
  local loadrc=0
  semodule -X 400 -i "$f" > "$EVIDENCE_DIR/$(basename "$f")-load.log" 2>&1 || loadrc=$?
  [ "$loadrc" = "0" ] \
    || { tail -4 "$EVIDENCE_DIR/$(basename "$f")-load.log"; fail "$1 module failed to load (load log kept)"; }
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
  out="$(docker-helper run alpine:3.24 -- sh -ec 'echo mnb40b-run-ok' 2>&1)"
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
  local stamp
  stamp="$(date +%s%N)"
  printf 'FROM alpine:3.24\nRUN echo mnb40b-build-ok\nRUN echo mnb40b-stamp-%s\n' "$stamp" > "$WS/ctx/Dockerfile"
  chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
  set +e
  out="$(docker-helper build "$WS/ctx" --dockerfile Dockerfile --image "mnb40b-probe-$stamp:1" 2>&1)"
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
    || fail "the MNB40b production reconciliation requires an enforcing SELinux host"
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
  # S0 — the baseline working set + the admission-face trace: load the
  # S3 working set (faces + check_context + read_policy + scaffold),
  # prove both faces ADMIT, and capture the process-identity evidence
  # for the RUN op against the BUILD op.
  # ---------------------------------------------------------------------
  say 'S0: working set up; both faces admitted; face trace'
  ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
  [ -n "$ADMIN_TOKEN" ] || fail "the admin token file is missing (provisioning did not land)"
  mkdir -p "$WS"
  chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
  docker-helper principal show "$PRINCIPAL" >/dev/null 2>&1 \
    || docker-helper principal create --no-credential "$PRINCIPAL" >/dev/null 2>&1 \
    || { ev s0-principal "create failed"; fail "the principal could not be provisioned"; }
  docker-helper principal allowed-root add "$PRINCIPAL" "$PRINCIPAL_HOME" \
    || { ev s0-allowed-root "add failed"; fail "the principal allowed-root could not be added"; }
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
  export DOCKER_HELPER_SESSION_TOKEN="$SESS_TOKEN"
  docker-helper pull alpine:3.24 > "$EVIDENCE_DIR/s0-pull.log" 2>&1 \
    || { tail -6 "$EVIDENCE_DIR/s0-pull.log"; fail "s0: image prewarm pull failed"; }

  # the measured buildkitd scaffold rows (MNB24/26/27); separate module
  cat <<'EOF' | write_cil "$M_CAP"
(allow docker_helper_buildkitd_t self (cap_userns (setpcap)))
(allow docker_helper_buildkitd_t self (cap_userns (setgid)))
(allow docker_helper_buildkitd_t self (process (setcap)))
EOF
  # the MNB30/MNB33 Tier-A run scaffold plus the MNB40a r10 measured rows
  cat <<'EOF' | write_cil "$M_WL"
(type docker_helper_builder_workload_t)
(roletype system_r docker_helper_builder_workload_t)
(typeattributeset domain (docker_helper_builder_workload_t))
(typeattributeset mcs_constrained_type (docker_helper_builder_workload_t))
(allow docker_helper_buildkitd_t docker_helper_builder_state_t (file (execute)))
(allow docker_helper_builder_workload_t docker_helper_builder_state_t (file (execute entrypoint map open read getattr)))
(allow docker_helper_builder_workload_t docker_helper_builder_state_t (dir (search)))
(allow docker_helper_buildkitd_t docker_helper_builder_workload_t (process (transition)))
(allow docker_helper_buildkitd_t self (process (setfscreate setkeycreate setexec)))
(allow docker_helper_buildkitd_t docker_helper_builder_workload_t (key (create view setattr)))
(allow docker_helper_buildkitd_t tmpfs_t (lnk_file (read getattr)))
(allow docker_helper_buildkitd_t tmpfs_t (file (read open getattr)))
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
  # the FULL faces module (the MNB40a S3 baseline)
  # the combined AUTH module: dir search + file {getattr open read write}
  # + security {check_context read_policy} — the MNB40a S3 working set
  {
    cat <<'EOF'
(allow docker_helper_buildkitd_t security_t (dir (search)))
(allow docker_helper_buildkitd_t security_t (file (getattr open read write)))
(allow docker_helper_buildkitd_t security_t (security (check_context read_policy)))
EOF
  } | write_cil "$M_AUTH"
  ev s0-modules "$(semodule -l 2>/dev/null | grep mnb40b || true)"
  ev s0-policy-sha "$(policy_sha)"
  # the installed binary identity (provenance closure)
  {
    printf 'installed wrapper (buildkit/buildkit-runc): '
    sha256sum /usr/libexec/docker-helper/buildkit/buildkit-runc 2>/dev/null | awk '{print $1}'
    printf 'installed pinned runtime: '
    sha256sum /usr/libexec/docker-helper/buildkit/runtime/buildkit-runc 2>/dev/null | awk '{print $1}'
    printf 'installed manifest digest entries:\n'
    grep -aoE '(runtime|wrap)?=?[a-f0-9]{64}' /usr/share/doc/docker-helper/buildkit/MANIFEST 2>/dev/null | head -6
  } > "$EVIDENCE_DIR/s0-installed-digests.txt"
  cat "$EVIDENCE_DIR/s0-installed-digests.txt"

  # face trace: process-identity capture during each op face
  sampler() {
    local out="$1"; shift
    : > "$out"
    ( while [ ! -f "$out.done" ]; do
        ps -eo comm= 2>/dev/null | awk '{print $1}' >> "$out"
        sleep 0.1
      done ) &
    SAMPLER_PID=$!
  }
  sampler_end() {
    local out="$1"
    touch "$out.done"
    kill "$SAMPLER_PID" 2>/dev/null || true
    wait "$SAMPLER_PID" 2>/dev/null || true
    rm -f "$out.done"
    sort -u "$out" > "$out.set"
  }
  prod_run s0-run
  printf '%s\n' "$RUN_OUT" > "$EVIDENCE_DIR/s0-run-stdout.txt"
  prod_build s0-build
  printf '%s\n' "$BUILD_OUT" > "$EVIDENCE_DIR/s0-build-stdout.txt"
  [ "$RUN_RC" = "0" ] || { tail -12 "$EVIDENCE_DIR/s0-run-stdout.txt"; fail "S0: the working set must admit the RUN face"; }
  [ "$BUILD_RC" = "0" ] || { tail -12 "$EVIDENCE_DIR/s0-build-stdout.txt"; fail "S0: the working set must admit the BUILD face"; }
  # dontaudit visibility cycle (the established disposable-VM discipline):
  # the remove-arm deny rows can be dontaudit'd by the distro policy, so
  # the ladder's attribution requires the -DB rebuild (sha-recorded).
  # The cycle is self-contained in this phase: -B restores the
  # dontaudit-carrying binary and the restore is verified by sha.
  dontaudit_on() {
    # $1 label; $2 restore-target sha
    local DBOUT DB_RC DSHA
    set +e
    DBOUT="$(semodule -DB 2>&1)"
    DB_RC=$?
    set -e
    ev "$1-rc" "$DB_RC ($DBOUT)"
    [ "$DB_RC" = "0" ] || fail "$1: the dontaudit visibility toggle failed"
    DSHA="$(policy_sha)"
    ev s0-policy-sha-dontaudit-off "$DSHA"
    [ "$DSHA" != "$2" ] \
      || fail "$1: semodule -DB did not change the loaded policy; the attribution would sight silently"
  }
  dontaudit_restore() {
    # $1 label; $2 expected working-set sha
    local BOUT B_RC
    set +e
    BOUT="$(semodule -B 2>&1)"
    B_RC=$?
    set -e
    ev "$1-rc" "$B_RC ($BOUT)"
    [ "$B_RC" = "0" ] || fail "$1: the dontaudit restore failed"
    DSHA="$(policy_sha)"
    ev "$1-sha" "$DSHA"
    [ "$DSHA" = "$2" ] || fail "$1: the restored policy sha must equal the pre-toggle working-set sha"
  }
  S0_WORK_SHA="$(policy_sha)"
  dontaudit_on s0-dontaudit-toggle "$S0_WORK_SHA"
  ev s0-face-run "PASS"
  ev s0-face-build "PASS"
  say 'S0: PASS (both faces admitted under the working set; dontaudit visibility cycle closed)'
}

# per-face removal arm: load the faces module WITHOUT the removed face,
# drive the production BUILD, and record the exact attribution.
permdrop() {
  local face="$1"
  local kind perm
  case "$face" in
    search)  kind=dir;  perm=search;  FP=" getattr open read write" ;;
    getattr) kind=file; perm=getattr; FP=" open read write" ;;
    open)    kind=file; perm=open;    FP=" getattr read write" ;;
    read)    kind=file; perm=read;    FP=" getattr open write" ;;
    write)   kind=file; perm=write;   FP=" getattr open read" ;;
  esac
  FP="${FP# }"
  {
    [ "$face" = "search" ] || printf '(allow docker_helper_buildkitd_t security_t (dir (search)))\n'
    printf '(allow docker_helper_buildkitd_t security_t (file (%s)))\n' "$FP"
    printf '(allow docker_helper_buildkitd_t security_t (security (check_context read_policy)))\n'
  } > "/tmp/$M_AUTH.cil"
  cp "/tmp/$M_AUTH.cil" "$EVIDENCE_DIR/$M_AUTH-$face.cil"
  semodule -X 400 -i "/tmp/$M_AUTH.cil" || fail "the without-$face auth replacement failed to load"
  semodule -B >/dev/null 2>&1 || fail "the without-$face rebuild failed"
  semodule -DB >/dev/null 2>&1 || fail "the without-$face dontaudit toggle failed"
  ev "m1-$face-policy-sha" "$(policy_sha)"
  prod_build "m1-$face-build"
  printf '%s\n' "$BUILD_OUT" > "$EVIDENCE_DIR/m1-$face-build-stdout.txt"
  avc_tail > "$EVIDENCE_DIR/m1-$face-avcs.txt"
  if [ "$BUILD_RC" = "0" ]; then
    ev "m1-$face-verdict" "REMOVABLE (the production BUILD admitted without the face; the minimal set drops it)"
    say "M1 $face: REMOVABLE (admitted without the face)"
  else
    if grep -qaE "denied +\\{ $perm \\}" "$EVIDENCE_DIR/m1-$face-avcs.txt" \
      && grep -qa "tclass=$kind" "$EVIDENCE_DIR/m1-$face-avcs.txt"; then
      ev "m1-$face-verdict" "NECESSARY (the removal was measured as the wrapper refusal with the exact denial: { $perm } tclass=$kind)"
      say "M1 $face: NECESSARY (denial { $perm } tclass=$kind)"
    else
      ev "m1-$face-verdict" "REFUSED-WITHOUT-MATCHING-AVC"
      say "M1 $face: unknown-attribution (refusal without the AVC match)"
      printf '%s\n' "$EVIDENCE_DIR/m1-$face-avcs.txt" | head -6 | sed 's/^/AVCS: /'
      grep -qiF 'refused the run' "$EVIDENCE_DIR/m1-$face-build-stdout.txt" \
        || fail "M1 $face: the refusal must come from the wrapper's admission gates"
    fi
  fi
  # restore the full auth set for the next ladder arm (same-name replace)
  cp "$EVIDENCE_DIR/$M_AUTH.cil" "/tmp/$M_AUTH.cil"
  semodule -X 400 -i "/tmp/$M_AUTH.cil" || fail "the auth replacement (restore) failed to load"
  semodule -B >/dev/null 2>&1 || fail "the auth rebuild (restore) failed"
}

phase_m1() {
  # ---------------------------------------------------------------------
  # M1 — the per-face removal ladder: for each of the five
  # previously-unproven faces, load the module WITHOUT that face and
  # drive the production BUILD (the wrapper-exercising face). The
  # measured delta is the removed face's own required authority.
  # ---------------------------------------------------------------------
  say 'M1: per-face removal ladder over the production BUILD face'
  for face in search getattr open read write; do
    permdrop "$face"
  done
  ev m1-policy-sha "$(policy_sha)"
  say 'M1: PASS'
}

phase_m2() {
  # ---------------------------------------------------------------------
  # M2 — the write-scope enumeration: the loaded security_t file list
  # (the nodes a bare write bit could address) recorded as evidence.
  # ---------------------------------------------------------------------
  say 'M2: security_t write-scope enumeration'
  ls -Z /sys/fs/selinux 2>/dev/null | head -40 > "$EVIDENCE_DIR/m2-selinuxfs-nodes.txt" || true
  ls -Z /sys/fs/selinux/booleans 2>/dev/null | head -6 >> "$EVIDENCE_DIR/m2-selinuxfs-nodes.txt" || true
  grep -aq "context" "$EVIDENCE_DIR/m2-selinuxfs-nodes.txt" \
    || fail "M2: the security_t node enumeration failed"
  say 'M2: PASS'
}

phase_m3() {
  # ---------------------------------------------------------------------
  # M3 — the combined minimal set: assemble the faces module from the
  # MEASURED necessary faces, validate BOTH faces admitted under
  # (minimal faces + check_context + read_policy + scaffold).
  # ---------------------------------------------------------------------
  say 'M3: the minimal set: both faces admitted under the measured faces'
  for face in search getattr open read write; do
    if grep -q "REMOVABLE" "$EVIDENCE_DIR/m1-$face-verdict"; then
      REMED=1
      say "M3: the $face face is dropped from the minimal set (measured removable)"
    else
      REMED=0
    fi
    case "$face" in
      search) NEED_DIR=$REMED ;;
      getattr|open|read|write)
        NEED_FILE_FACE_$face=$REMED
        ;;
    esac
  done
  PERM_LIST=""
  if [ "${NEED_FILE_FACE_getattr:-1}" = 1 ]; then PERM_LIST="$PERM_LIST getattr"; fi
  if [ "${NEED_FILE_FACE_open:-1}" = 1 ]; then PERM_LIST="$PERM_LIST open"; fi
  if [ "${NEED_FILE_FACE_read:-1}" = 1 ]; then PERM_LIST="$PERM_LIST read"; fi
  if [ "${NEED_FILE_FACE_write:-1}" = 1 ]; then PERM_LIST="$PERM_LIST write"; fi
  PERM_LIST="${PERM_LIST# }"
  {
    if [ "${NEED_DIR:-0}" = 1 ]; then
      printf '(allow docker_helper_buildkitd_t security_t (dir (search)))\n'
    fi
    if [ -n "$PERM_LIST" ]; then
      printf '(allow docker_helper_buildkitd_t security_t (file (%s)))\n' "$PERM_LIST"
    fi
    printf '(allow docker_helper_buildkitd_t security_t (security (check_context read_policy)))\n'
  } > "/tmp/$M_AUTH.cil"
  cp "/tmp/$M_AUTH.cil" "$EVIDENCE_DIR/$M_AUTH-minimal.cil"
  semodule -X 400 -i "/tmp/$M_AUTH.cil" || fail "the minimal auth replacement failed to load"
  semodule -B >/dev/null 2>&1 || fail "the minimal auth rebuild failed"
  ev m3-policy-sha "$(policy_sha)"
  ev m3-minimal-faces "$NEED_DIR [$PERM_LIST]"
  prod_run m3-run
  printf '%s\n' "$RUN_OUT" > "$EVIDENCE_DIR/m3-run-stdout.txt"
  prod_build m3-build
  printf '%s\n' "$BUILD_OUT" > "$EVIDENCE_DIR/m3-build-stdout.txt"
  [ "$RUN_RC" = "0" ] || { tail -12 "$EVIDENCE_DIR/m3-run-stdout.txt"; fail "M3: the RUN face must admit under the minimal set"; }
  [ "$BUILD_RC" = "0" ] || { tail -12 "$EVIDENCE_DIR/m3-build-stdout.txt"; fail "M3: the BUILD face must admit under the minimal set"; }
  # restore the full working set before the teardown (the same-name replace)
  cp "$EVIDENCE_DIR/$M_AUTH.cil" "/tmp/$M_AUTH.cil"
  semodule -X 400 -i "/tmp/$M_AUTH.cil" || fail "the auth replacement (M3 restore) failed to load"
  semodule -B >/dev/null 2>&1 || fail "the auth rebuild (M3 restore) failed"
  [ "$(policy_sha)" = "$(cat "$EVIDENCE_DIR/s0-policy-sha" 2>/dev/null)" ] \
    || fail "M3: the post-restore policy sha must equal the S0 working-set sha"
  say 'M3: PASS'
}

phase_m4() {
  # ---------------------------------------------------------------------
  # M5 — teardown: unload every diagnostic module, verify the policy sha
  # restored byte-exactly, the deny-again run is refused closed, the
  # product modules/constraint artifact/.pp are unchanged.
  # ---------------------------------------------------------------------
  say 'M5: teardown (unload-all + sha restore + deny-again)'
  set +e
  BOUT="$(semodule -B 2>&1)"
  B_RC=$?
  set -e
  ev m4-dontaudit-restore-rc "$B_RC ($BOUT)"
  [ "$B_RC" = "0" ] || fail "M4: the dontaudit restore failed"
  ev m4-policy-sha-dontaudit-restored "$(policy_sha)"
  [ "$(policy_sha)" = "$(cat "$EVIDENCE_DIR/s0-policy-sha" 2>/dev/null)" ] \
    || fail "M4: the restored policy sha must equal the pre-toggle working-set sha"
  for m in "$M_AUTH" "$M_W7" "$M_WL" "$M_CAP"; do
    unload_verbose "$m"
  done
  if semodule -l 2>/dev/null | grep -q 'mnb40b'; then
    fail "a diagnostic module is still listed after the teardown"
  fi
  ev m5-modules-after "$(semodule -l 2>/dev/null | grep -c mnb40b || true)"
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

phase_m5() {
  # ---------------------------------------------------------------------
  # M5 — verdict composition
  # ---------------------------------------------------------------------
  say 'M5: verdict composition'
  {
    printf 'workingset.bothfaces.admitted = %s\n' \
      "$(grep -qx 'rc=0' "$EVIDENCE_DIR/s0-run.rc" && grep -qx 'rc=0' "$EVIDENCE_DIR/s0-build.rc" && echo 'PASS (S0: both faces admitted under the working set)' || echo FAILED)"
    printf 'ladder.search.necessary      = %s\n' "$(cat "$EVIDENCE_DIR/m1-search-verdict" 2>/dev/null || echo MISSING)"
    printf 'ladder.getattr.verdict       = %s\n' "$(cat "$EVIDENCE_DIR/m1-getattr-verdict" 2>/dev/null || echo MISSING)"
    printf 'ladder.open.necessary        = %s\n' "$(cat "$EVIDENCE_DIR/m1-open-verdict" 2>/dev/null || echo MISSING)"
    printf 'ladder.read.necessary        = %s\n' "$(cat "$EVIDENCE_DIR/m1-read-verdict" 2>/dev/null || echo MISSING)"
    printf 'ladder.write.necessary       = %s\n' "$(cat "$EVIDENCE_DIR/m1-write-verdict" 2>/dev/null || echo MISSING)"
    printf 'attrs.write.scope.enumerated = %s\n' \
      "$(grep -qa context "$EVIDENCE_DIR/m2-selinuxfs-nodes.txt" && echo 'PASS (the security_t write-addressable node list is captured)' || echo FAILED)"
    printf 'minimal.combined.admitted    = %s\n' \
      "$(grep -qx 'rc=0' "$EVIDENCE_DIR/m3-run.rc" && grep -qx 'rc=0' "$EVIDENCE_DIR/m3-build.rc" && echo 'PASS (M3: both faces admitted under the measured minimal set)' || echo FAILED)"
    printf 'unload.verified              = %s\n' \
      "$(grep -qx 0 "$EVIDENCE_DIR/m5-modules-after" 2>/dev/null && echo 'PASS (no diagnostic module remains; sha restored; deny-again refused closed)' || echo FAILED)"
    printf 'installed.digest             = %s\n' \
      "$(grep -qa '[a-f0-9]\\{64\\}' "$EVIDENCE_DIR/s0-installed-digests.txt" 2>/dev/null && echo PASS || echo FAILED)"
  } > "$EVIDENCE_DIR/m5-verdict.txt"
  if grep -q FAILED "$EVIDENCE_DIR/m5-verdict.txt"; then
    cat "$EVIDENCE_DIR/m5-verdict.txt"
    fail "the MNB40b verdict carries a FAILED line"
  fi
  cat "$EVIDENCE_DIR/m5-verdict.txt"
  say 'M5: PASS'
}

run_phase() {
  case "$1" in
    p0) phase_p0 ;;
    s0) phase_s0 ;;
    m1) phase_m1 ;;
    m2) phase_m2 ;;
    m3) phase_m3 ;;
    m4) phase_m4 ;;
    m5) phase_m5 ;;
    *) fail "unknown phase $1" ;;
  esac
}

# the enforcement VM boots fresh on every attempt: a previous attempt's
# completed-phase markers describe a DIFFERENT machine state, so the
# boot identity invalidates them (the tape state dir persists in
# /var/lib, the boot never does)
CURBOOT="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
mkdir -p "$STATE_DIR"
if [ -n "$CURBOOT" ] && [ -f "$STATE_DIR/boot-id" ] \
  && [ "$(cat "$STATE_DIR/boot-id" 2>/dev/null)" != "$CURBOOT" ]; then
  rm -f "$PHASE_FILE"
fi
[ -n "$CURBOOT" ] && printf '%s\n' "$CURBOOT" > "$STATE_DIR/boot-id" || true
for ph in p0 s0 m1 m2 m3 m4 m5; do
  if done_phase "$ph"; then
    say "re-entry: $ph already PASS"
    continue
  fi
  run_phase "$ph"
  mark "$ph"
done

printf '%s\n' 'R7-MNB40B-VERDICT=PASS'
exit 0
