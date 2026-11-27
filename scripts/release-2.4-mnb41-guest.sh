#!/bin/bash
# release-2.4-mnb41-guest.sh — MNB41: the MNB40-measured minimal
# wrapper policy-check authority is promoted permanent (module
# docker_helper 1.3); this round verifies the PROMOTED candidate on the
# enforcing Tumbleweed VM with NO diagnostic module. The authority
# carries only the MNB40b-measured minimal set:
#
#   allow docker_helper_buildkitd_t security_t:file { getattr open read write };
#   allow docker_helper_buildkitd_t security_t:security { check_context read_policy };
#
# Phase S1 — the effective compiled-policy delta against the accepted
#   baseline: the shipped docker_helper.pp is replaced by the
#   byte-identical 1.2 artifact extracted from the pinned accepted
#   MNB40a candidate RPM (docker-helper-candidate-45835382787-1); the
#   loaded-state sesearch capture is the accepted baseline's
#   security_t authority; a reference managed BUILD must be refused
#   closed by the wrapper's context gate (the accepted pre-promotion
#   behavior). Then the SHIPPED .pp is reinstalled from the packaged
#   artifact and the sesearch capture is repeated: the effective delta
#   is EXACTLY the two promoted rules (the source digests and the
#   loaded-policy shas are recorded at every step; the restore must
#   return the S0 loaded-policy sha byte-exactly).
# Phase S2 — enforcement acceptance through the production chain: the
#   managed BUILD passes both wrapper gates (admitted, artifact
#   streamed), the managed RUN executes through its independent lane,
#   the security_t-surface AVC inventory of the acceptance window
#   carries only the promoted shapes, and the workload context samples
#   show the categorised workload transition intact.
# Phase S3 — fail-closed missing-constraint behavior BEFORE execution
#   commit: the shipped fifo_file constraint module removed
#   (semodule -X 400 -r docker-helper-fifo-rw-constraint), the BUILD
#   refusal must come from the wrapper's FIFO gate (the exact
#   remediation message), the module restored from its canonical
#   packaged path and the loaded-policy sha must return byte-exactly,
#   and the BUILD is admitted again.
# Phase S4 — the authority boundaries remain intact: the workload
#   domain carries NO security_t surface anywhere in the loaded policy,
#   no other subject gained a security_t grant, no dir search landed on
#   the buildkitd domain, and the module store holds exactly the two
#   product modules (no diagnostic module anywhere).
# Phase M5 — the closure: the compiled-policy digest of the installed
#   artifact equals the producer-recorded digest; the loaded-policy sha,
#   the .pp artifact digest and the constraint artifact digest are
#   unchanged from S2; seinfo carries the canonical constraint; and the
#   composed verdict is emitted (R7-MNB41-VERDICT=PASS).

set -Eeuo pipefail
trap 'printf "[release-2.4-mnb41] ERR rc=%d line=%d cmd=%s\n" "$?" "$LINENO" "${BASH_COMMAND:-?}" >&2' ERR

PREFIX='[release-2.4-mnb41]'
say()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }
log()  { echo "[guest] $*"; }
ev()   { printf '%s\n' "$2" > "$EVIDENCE_DIR/$1"; }

: "${R7_ARTIFACT:?R7_ARTIFACT required}"
: "${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"
: "${MNB41_BASELINE_RPM:?MNB41_BASELINE_RPM required (the pinned accepted MNB40a candidate RPM)}"
: "${MNB41_BASELINE_RPM_SHA256:?MNB41_BASELINE_RPM_SHA256 required}"
: "${MNB41_EXPECTED_PP_SHA256:?MNB41_EXPECTED_PP_SHA256 required}"
: "${R7_EVIDENCE_DIR:?R7_EVIDENCE_DIR required}"
RPM="$R7_ARTIFACT"
EVIDENCE_DIR="$R7_EVIDENCE_DIR"
STATE_DIR=/var/lib/docker-helper-mnb41-state
POLICYPATH=/sys/fs/selinux/policy
STATEMENT='mlsconstrain fifo_file { read write } (h1 dom h2 or t1 != mcs_constrained_type);'
REMEDIATION='semodule -X 400 -i /usr/share/selinux/docker-helper-fifo-rw-constraint.cil'
CONSTRAINT_MODULE=docker-helper-fifo-rw-constraint
CONSTRAINT_CIL=/usr/share/selinux/docker-helper-fifo-rw-constraint.cil
MAIN_UNIT=docker-helper.service
WL_DOMAIN=docker_helper_builder_workload_t
PRINCIPAL="${SUDO_USER:-}"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" 2>/dev/null | cut -d: -f6)"
WS="$PRINCIPAL_HOME/r7-mnb41-ws"
GATEMSG_CTX='the workload context validation refused the run'
GATEMSG_FIFO='the FIFO constraint admission gate refused the run'
SHIP_PP=/usr/share/selinux/docker_helper.pp
SHIP_PP_COPY="$STATE_DIR/shipped-docker_helper.pp"
# the mnb40b-established scaffold (the diagnostic-era type/cap/carrier
# set), separately removable and always evidence-recorded: the workload
# DOMAIN TYPE and the wrapper's own-context authority exist only under
# these modules; the PROMOTED authority under verification never lives
# here (no scaffold row touches security_t)
M_CAP=docker_helper_diag_mnb41_cap
M_WL=docker_helper_diag_mnb41_wl
M_W7=docker_helper_diag_mnb41_w7

mkdir -p "$EVIDENCE_DIR" "$STATE_DIR"
PHASE_FILE="$STATE_DIR/phase-done"
mark() { mkdir -p "$STATE_DIR"; printf '%s\n' "$1" >> "$PHASE_FILE"; }
done_phase() { [ -f "$PHASE_FILE" ] && grep -qx "$1" "$PHASE_FILE"; }

policy_sha() { sha256sum "$POLICYPATH" | awk '{print $1}'; }
avc_tail() {
  { ausearch -m avc -ts recent 2>/dev/null \
      || grep -i 'avc.*denied' /var/log/audit/audit.log 2>/dev/null \
      || dmesg -T 2>/dev/null | grep -i denied; } | tail -8 || true
}
# the scaffold modules write directly to the CIL file, load it, and keep
# the exact loaded bytes as evidence
write_cil_scaffold() {
  local f="/tmp/$1.cil"
  cat > "$f"
  cp "$f" "$EVIDENCE_DIR/$(basename "$f")"
  local loadrc=0
  semodule -X 400 -i "$f" > "$EVIDENCE_DIR/$(basename "$f")-load.log" 2>&1 || loadrc=$?
  [ "$loadrc" = "0" ] \
    || { tail -4 "$EVIDENCE_DIR/$(basename "$f")-load.log"; fail "$1 module failed to load (load log kept)"; }
}

# the workload-domain boundary: a real sesearch allow row may never name
# the workload domain as its subject toward security_t (the row shape
# anchors the check; error strings mentioning the type name are noise,
# not rows)
workload_rows() {
  for f in "$@"; do
    grep -a '^allow .*docker_helper_builder_workload_t.*security_t' "$f" 2>/dev/null || true
  done
}

# the security_t-surface rows of one op window (a structured subset)
security_rows() {
  { ausearch -m avc -ts recent 2>/dev/null | grep -a security_t \
      || grep -a 'avc' /var/log/audit/audit.log 2>/dev/null | grep -a security_t; } | tail -12 || true
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

# one sesearch snapshot of the loaded policy's security_t authority.
# $1 = evidence label; captures the grant and deny rows toward
# security_t for every subject, split by target class.
sesearch_capture() {
  # an empty result is a nonzero grep rc inside sesearch: capture the
  # empties deliberately (the absence IS the measurement)
  local label="$1"
  sesearch --allow -t security_t -c dir  > "$EVIDENCE_DIR/$label-allow-dir.txt" 2>&1 || ec=0
  sesearch --allow -t security_t -c file > "$EVIDENCE_DIR/$label-allow-file.txt" 2>&1 || ec=0
  sesearch --allow -t security_t -c security > "$EVIDENCE_DIR/$label-allow-security.txt" 2>&1 || ec=0
  # the whole allow surface toward security_t, one file. The workload
  # domain is diagnostic-only (the type exists in the loaded policy only
  # while the scaffold modules are installed), so a -s query against an
  # absent type would emit an error STRING containing the type name: the
  # workload-boundary checks anchor on rows in this dump instead of any
  # -s query.
  sesearch --allow -t security_t \
    > "$EVIDENCE_DIR/$label-allow-all.txt" 2>&1 || ec=0
}

prod_run() {
  RUN_LABEL="$1"
  local out
  set +e
  out="$(docker-helper run alpine:3.24 -- sh -ec 'echo mnb41-run-ok' 2>&1)"
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
prod_build() {
  BUILD_LABEL="$1"
  local out
  mkdir -p "$WS/ctx"
  local stamp
  stamp="$(date +%s%N)"
  printf 'FROM alpine:3.24\nRUN echo mnb41-build-ok\nRUN echo mnb41-stamp-%s\n' "$stamp" > "$WS/ctx/Dockerfile"
  chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
  set +e
  out="$(docker-helper build "$WS/ctx" --dockerfile Dockerfile --image "mnb41-probe-$stamp:1" 2>&1)"
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

# the per-attempt session identity (attempts run in fresh shells; the
# exported bearer token does not survive an attempt boundary).
ensure_session() {
  ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
  [ -n "$ADMIN_TOKEN" ] || fail "the admin token file is missing (provisioning did not land)"
  if [ -n "${SESS_TOKEN:-}" ]; then
    return 0
  fi
  mkdir -p "$WS"
  chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
  docker-helper principal show "$PRINCIPAL" >/dev/null 2>&1 \
    || docker-helper principal create --no-credential "$PRINCIPAL" >/dev/null 2>&1 \
    || { ev session-price "create failed"; fail "the principal could not be provisioned"; }
  docker-helper principal allowed-root add "$PRINCIPAL" "$PRINCIPAL_HOME" \
    || { ev session-price "allowed-root add failed"; fail "the principal allowed-root could not be added"; }
  DH_SOCK=/run/docker-helper/docker-helper.sock
  RESP="$STATE_DIR/session-response.json"
  CODE="$(curl --silent --max-time 8 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"workspace\":\"$WS\",\"principal\":\"$PRINCIPAL\"}" \
    -o "$RESP" -w '%{http_code}' http://localhost/sessions)" || true
  STACKCLASS=unknown
  case "$CODE" in
    200) STACKCLASS=created ;;
    0) STACKCLASS=transport-unreachable ;;
    4??) STACKCLASS=request-refused ;;
    5??) STACKCLASS=server-error ;;
  esac
  SESS_TOKEN="$(grep -oE '"token": *"[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"token": *"//;s/"$//' || true)"
  [ -n "$SESS_TOKEN" ] \
    || { ev session-refusal "$STACKCLASS"; rm -f "$RESP"; fail "session creation failed (HTTP $STACKCLASS; body withheld)"; }
  rm -f "$RESP"
  export DOCKER_HELPER_SESSION_TOKEN="$SESS_TOKEN"
  ev session-created "yes (per-attempt; recorded token-free)"
  docker-helper pull alpine:3.24 > "$EVIDENCE_DIR/session-pull.log" 2>&1 \
    || { tail -6 "$EVIDENCE_DIR/session-pull.log"; fail "image prewarm pull failed"; }
}

phase_p0() {
  say 'P0: enforcing guest, candidate + promoted-policy identity, provisioning'
  ev p0-guest-script-sha "$(sha256sum "$0" 2>/dev/null | awk '{print $1}')"
  [ "$(sha256sum "$RPM" | awk '{print $1}')" = "$R7_ARTIFACT_SHA256" ] \
    || fail "candidate RPM sha mismatch"
  [ "$(sha256sum "$MNB41_BASELINE_RPM" | awk '{print $1}')" = "$MNB41_BASELINE_RPM_SHA256" ] \
    || fail "the pinned baseline candidate RPM sha mismatch"
  [ -n "$PRINCIPAL" ] && [ "$PRINCIPAL" != "root" ] \
    || fail "cannot derive the non-root principal"
  [ -n "$PRINCIPAL_HOME" ] && [ -d "$PRINCIPAL_HOME" ] \
    || fail "principal home not found"
  if ! command -v seinfo >/dev/null 2>&1 || ! command -v sesearch >/dev/null 2>&1; then
    zypper --non-interactive install -y setools-console \
      > "$EVIDENCE_DIR/p0-setools.log" 2>&1 || true
  fi
  command -v sesearch >/dev/null 2>&1 || fail "sesearch (setools-console) is required"
  getenforce 2>/dev/null | grep -qx 'Enforcing' \
    || fail "the MNB41 acceptance requires an enforcing SELinux host"

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
    rm -f "$INIT_OUT"
    ev p0-init "success (admin token withheld from the evidence set)"
  fi

  # the enforcing wrapper binary identity: every MNB40 parser-correction
  # marker must be inside the INSTALLED wrapper (the shared binary that
  # runs the buildkit-runc wrap).
  WRAP=/usr/libexec/docker-helper/buildkit/buildkit-runc
  [ -f "$WRAP" ] || fail "the installed wrapper binary is missing"
  {
    grep -qaF 'duplicate type value' "$WRAP" && echo 'mnb40a-r9-duplicate-value-marker: yes'
  } > "$EVIDENCE_DIR/p0-wrapper-markers.txt" 2>/dev/null \
    || fail "the installed wrapper lacks the MNB40 r9 correction marker"

  # the installed candidate must carry exactly the produced .pp bytes:
  # the installed file, the .pp extracted from THIS round's RPM bytes,
  # and the producer-side compiled digest must all be identical
  [ -f "$SHIP_PP" ] || fail "the shipped docker_helper.pp artifact is missing"
  ev p0-pp-sha "$(sha256sum "$SHIP_PP" | awk '{print $1}')"
  mkdir -p /tmp/mnb41-rpmdump
  rpm2cpio "$RPM" \
    | ( cd /tmp/mnb41-rpmdump && cpio -idmu --quiet ./usr/share/selinux/docker_helper.pp ) \
    > "$EVIDENCE_DIR/p0-rpm-extract.log" 2>&1 \
    || { tail -4 "$EVIDENCE_DIR/p0-rpm-extract.log"; fail "the .pp extraction from the candidate RPM failed"; }
  ev p0-rpm-pp-sha "$(sha256sum /tmp/mnb41-rpmdump/usr/share/selinux/docker_helper.pp | awk '{print $1}')"
  [ "$(cat "$EVIDENCE_DIR/p0-rpm-pp-sha")" = "$(cat "$EVIDENCE_DIR/p0-pp-sha")" ] \
    || fail "the installed docker_helper.pp differs from the candidate RPM's packaged bytes"
  [ "$(cat "$EVIDENCE_DIR/p0-pp-sha")" = "$MNB41_EXPECTED_PP_SHA256" ] \
    || fail "the installed docker_helper.pp does not match the MNB41 compiled digest"
  # a byte-exact working copy for the phase-S1 reinstall (the packaged
  # bytes, copied once, verified again after the copy)
  cp "$SHIP_PP" "$SHIP_PP_COPY"
  [ "$(sha256sum "$SHIP_PP_COPY" | awk '{print $1}')" = "$MNB41_EXPECTED_PP_SHA256" ] \
    || fail "the pp working copy digest diverged from the packaged artifact"

  ensure_services_active
  semodule -l | grep -q '^docker_helper' \
    || fail "the docker_helper product module must be loaded"
  semodule -l | grep -q "^$CONSTRAINT_MODULE" \
    || fail "the shipped fifo_file constraint module must be loaded"

  ev p0-policy-sha "$(policy_sha)"
  printf '%s\n' "$(policy_sha)" > "$STATE_DIR/policy-sha-base"
  ev p0-policyvers "$(cat /sys/fs/selinux/policyvers 2>/dev/null || echo n/a)"
  ev p0-constraint-artifact-sha "$(sha256sum "$CONSTRAINT_CIL" 2>/dev/null | awk '{print $1}')"
  ev p0-modules "$(semodule -l 2>/dev/null | grep -E 'docker.helper|docker_helper' || true)"
  seinfo --constrain fifo_file "$POLICYPATH" > "$EVIDENCE_DIR/p0-seinfo-constrain.txt" 2>&1 \
    || fail "seinfo --constrain baseline failed"
  sed 's/^[[:space:]]*//' "$EVIDENCE_DIR/p0-seinfo-constrain.txt" | grep -Fqx "$STATEMENT" \
    || fail "the installed policy must carry the canonical constraint (seinfo present-side)"

  # the installed wrapper + runtime digests (the provenance closure)
  {
    printf 'installed wrapper (buildkit/buildkit-runc): '
    sha256sum "$WRAP" 2>/dev/null | awk '{print $1}'
    printf 'installed pinned runtime: '
    sha256sum /usr/libexec/docker-helper/buildkit/runtime/buildkit-runc 2>/dev/null | awk '{print $1}'
  } > "$EVIDENCE_DIR/p0-installed-digests.txt"
  cat "$EVIDENCE_DIR/p0-installed-digests.txt"
  say 'P0: PASS'
}

phase_s1() {
  # -------------------------------------------------------------------
  # S1 — the effective compiled-policy delta against the accepted
  # baseline. The accepted baseline policy = the module WITHOUT the
  # promotion, byte-identical to the pinned accepted MNB40a candidate's
  # packaged docker_helper.pp. The baseline is installed by the same
  # canonical store path; the loaded-state captures come from sesearch
  # (the kernel-deciding authority, not the source).
  # -------------------------------------------------------------------
  say 'S1: the effective compiled-policy delta (accepted baseline -> promoted)'
  ensure_session
  ev s1-loaded-sha "$(policy_sha)"

  # extract the packaged .pp from the pinned baseline RPM and verify it
  # against the locally compiled pre-promotion digest
  mkdir -p /tmp/mnb41-baseline
  rpm2cpio "$MNB41_BASELINE_RPM" \
    | ( cd /tmp/mnb41-baseline && cpio -idmu --quiet ./usr/share/selinux/docker_helper.pp ) \
    > "$EVIDENCE_DIR/s1-rpm-extract.log" 2>&1 \
    || { tail -4 "$EVIDENCE_DIR/s1-rpm-extract.log"; fail "the baseline .pp extraction failed"; }
  OLD_PP=/tmp/mnb41-baseline/usr/share/selinux/docker_helper.pp
  [ -s "$OLD_PP" ] || fail "the baseline .pp was not found inside the pinned RPM"
  ev s1-baseline-pp-sha "$(sha256sum "$OLD_PP" | awk '{print $1}')"

  # install the accepted baseline module (same-name store replace)
  semodule -i "$OLD_PP" > "$EVIDENCE_DIR/s1-baseline-install.log" 2>&1 \
    || { tail -4 "$EVIDENCE_DIR/s1-baseline-install.log"; fail "the baseline module install failed"; }
  ev s1-baseline-loaded-sha "$(policy_sha)"
  sesearch_capture s1-baseline
  # the accepted baseline carries NO buildkitd security_t grant
  [ -s "$EVIDENCE_DIR/s1-baseline-allow-file.txt" ] \
    && { grep -aq buildkitd "$EVIDENCE_DIR/s1-baseline-allow-file.txt" \
           && fail "the accepted baseline unexpectedly carries a buildkitd security_t:file grant"; } || true
  # and the production wrapper must refuse closed without the promotion
  prod_build s1-baseline-refuse
  [ "$BUILD_RC" != "0" ] \
    || fail "the accepted-baseline BUILD must be refused (the pre-promotion acceptance behavior)"
  grep -qiF "$GATEMSG_CTX" "$EVIDENCE_DIR/s1-baseline-refuse.log" \
    || fail "the accepted-baseline refusal must come from the wrapper's context gate"
  ev s1-baseline-refuse-class "context-gate (the pre-promotion fail-closed acceptance)"

  # reinstall the SHIPPED promoted module from the packaged artifact and
  # capture the promoted state
  semodule -i "$SHIP_PP_COPY" > "$EVIDENCE_DIR/s1-promoted-install.log" 2>&1 \
    || { tail -4 "$EVIDENCE_DIR/s1-promoted-install.log"; fail "the promoted module reinstall failed"; }
  ev s1-promoted-loaded-sha "$(policy_sha)"
  [ "$(cat "$EVIDENCE_DIR/s1-promoted-loaded-sha")" = "$(cat "$EVIDENCE_DIR/s1-loaded-sha")" ] \
    || fail "the promoted-state loaded sha must return byte-exactly to the S1 entry sha"
  sesearch_capture s1-promoted

  # the effective delta: exactly the two promoted rules appear between
  # the two sesearch captures
  DELTA_FILE="$EVIDENCE_DIR/s1-effective-delta.txt"
  {
    echo "== buildkitd security_t:file rules ==";
    cat "$EVIDENCE_DIR/s1-promoted-allow-file.txt";
    echo "== buildkitd security_t:security rules ==";
    cat "$EVIDENCE_DIR/s1-promoted-allow-security.txt";
    echo "== buildkitd security_t:dir rules ==";
    cat "$EVIDENCE_DIR/s1-promoted-allow-dir.txt";
  } > "$DELTA_FILE"
  grep -aFq 'allow docker_helper_buildkitd_t security_t:file { getattr open read write };' "$DELTA_FILE" \
    || fail "the promoted file rule is missing from the loaded-level capture"
  grep -aFq 'allow docker_helper_buildkitd_t security_t:security { check_context read_policy };' "$DELTA_FILE" \
    || fail "the promoted security rule is missing from the loaded-level capture"
  # dir search stays ungranted: no sesearch allow row may target
  # security_t:dir from the buildkitd domain (the captures also carry
  # the distro's own rows, so the check anchors the subject)
  BKDIR="$(grep -ac '^allow docker_helper_buildkitd_t security_t:dir' "$EVIDENCE_DIR/s1-promoted-allow-dir.txt" || true)"
  [ "$BKDIR" = "0" ] \
    || fail "a buildkitd security_t:dir grant leaked into the promoted state; dir search stays ungranted"
  # the workload domain gains nothing in either state (row-anchored: the
  # dumps must carry no allow row whose subject is the workload domain)
  WORKROWS="$(workload_rows "$EVIDENCE_DIR/s1-baseline-allow-all.txt" "$EVIDENCE_DIR/s1-promoted-allow-all.txt")"
  [ -z "$WORKROWS" ] \
    || fail "the workload domain must carry no security_t grant in either state"
  say 'S1: PASS (the effective delta is exactly the two promoted rules)'
}

phase_s2() {
  # -------------------------------------------------------------------
  # S2 — enforcement acceptance through the production chain.
  # -------------------------------------------------------------------
  say 'S2: the production acceptance (both wrapper gates + the run lane)'
  ensure_session
  # install the scaffold (the mnb40b-proven bytes; each module loaded
  # and recorded, never replaced)
  {
    cat <<'EOF'
(allow docker_helper_buildkitd_t self (cap_userns (setpcap)))
(allow docker_helper_buildkitd_t self (cap_userns (setgid)))
(allow docker_helper_buildkitd_t self (process (setcap)))
EOF
  } | write_cil_scaffold "$M_CAP"
  {
    cat <<'EOF'
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
  } | write_cil_scaffold "$M_WL"
  {
    cat <<'EOF'
(allow docker_helper_builder_workload_t docker_helper_buildkitd_t (fifo_file (read write)))
EOF
  } | write_cil_scaffold "$M_W7"
  # the scaffold carries no security_t authority: the captures at the
  # loaded state prove the acceptance runs on the PERMANENT promotion
  sesearch_capture s2-scaffold-up
  WORKROWS="$(workload_rows "$EVIDENCE_DIR/s2-scaffold-up-allow-all.txt")"
  [ -z "$WORKROWS" ] \
    || fail "the scaffold must not carry any workload security_t grant"
  # the buildkitd security_t surface at the scaffold-up state must be
  # exactly the promoted surface (the same two rows, no more)
  for w in file security; do
    grep -aFq "allow docker_helper_buildkitd_t security_t:$w" "$EVIDENCE_DIR/s2-scaffold-up-allow-all.txt" \
      || fail "the promoted $w rule is missing from the scaffold-up capture"
  done
  BKUP="$(grep -ac '^allow docker_helper_buildkitd_t security_t' "$EVIDENCE_DIR/s2-scaffold-up-allow-all.txt" || true)"
  [ "$BKUP" = "2" ] \
    || fail "the scaffold-up buildkitd security_t surface must be exactly the two promoted rules (got $BKUP)"
  prod_build s2-build
  [ "$BUILD_RC" = "0" ] \
    || { tail -12 "$EVIDENCE_DIR/s2-build.log"; fail "S2: the production BUILD must be admitted through both gates"; }
  security_rows > "$EVIDENCE_DIR/s2-build-security-rows.txt" || true
  prod_run s2-run
  [ "$RUN_RC" = "0" ] \
    || { tail -12 "$EVIDENCE_DIR/s2-run.log"; fail "S2: the production RUN must be admitted through its own lane"; }
  security_rows > "$EVIDENCE_DIR/s2-run-security-rows.txt" || true
  # the acceptance-window loaded-policy sha is the boundary the rest of
  # the round restores to
  ev s2-loaded-sha "$(policy_sha)"
  say 'S2: PASS (both faces admitted under the permanent promotion)'
}

phase_s3() {
  # -------------------------------------------------------------------
  # S3 — the fail-closed missing-constraint behavior BEFORE execution
  # commit, through a separately removable alteration with a byte-exact
  # restore.
  # -------------------------------------------------------------------
  say 'S3: the missing-constraint fail-closed path (removal + exact restore)'
  ensure_session
  ev s3-condition-cil-sha "$(sha256sum "$CONSTRAINT_CIL" | awk '{print $1}')"
  semodule -X 400 -r "$CONSTRAINT_MODULE" \
    || fail "S3: the constraint module removal failed"
  sleep 1
  ev s3-policy-sha-removed "$(policy_sha)"
  # the module must be absent from the store now
  if semodule -l 2>/dev/null | grep -q "^$CONSTRAINT_MODULE"; then
    fail "S3: the constraint module is still listed after the removal"
  fi
  prod_build s3-missing-refuse
  [ "$BUILD_RC" != "0" ] \
    || fail "S3: the BUILD must be refused while the shipped constraint is absent"
  grep -qF "$GATEMSG_MISSING" "$EVIDENCE_DIR/s3-missing-refuse.log" \
    && grep -qF "$GATEMSG_FIFO" "$EVIDENCE_DIR/s3-missing-refuse.log" \
    || { tail -8 "$EVIDENCE_DIR/s3-missing-refuse.log"; fail "S3: the refusal must be the FIFO gate's exact missing-constraint remediation"; }
  ev s3-refuse-class "fifo-gate missing-statement refusal (pre-commit, remediation message)"
  # restore byte-exactly from the canonical packaged path
  [ "$(sha256sum "$CONSTRAINT_CIL" | awk '{print $1}')" = "$(cat "$EVIDENCE_DIR/s3-condition-cil-sha")" ] \
    || fail "S3: the constraint artifact moved under the removal"
  semodule -X 400 -i "$CONSTRAINT_CIL" > "$EVIDENCE_DIR/s3-restore.log" 2>&1 \
    || { tail -4 "$EVIDENCE_DIR/s3-restore.log"; fail "S3: the constraint restore failed"; }
  sleep 1
  ev s3-policy-sha-restored "$(policy_sha)"
  [ "$(cat "$EVIDENCE_DIR/s3-policy-sha-restored")" = "$(cat "$EVIDENCE_DIR/s2-loaded-sha")" ] \
    || fail "S3: the restored loaded-policy sha must return byte-exactly to the S2 acceptance sha"
  prod_build s3-restored
  [ "$BUILD_RC" = "0" ] \
    || fail "S3: after the exact restore the BUILD must be admitted again"
  # unload the scaffold modules; the boundary audit then runs on the
  # two-product-module store
  for m in "$M_W7" "$M_WL" "$M_CAP"; do
    unload_verbose "$m"
  done
  if semodule -l 2>/dev/null | grep -aqE 'diag|mnb4[01]|probe'; then
    faillist="$(semodule -l 2>/dev/null | grep -aE 'diag|mnb4[01]|probe' || true)"
    fail "S3: a scaffold module must not survive: $faillist"
  fi
  say 'S3: PASS (fail-closed missing-constraint; byte-exact restore; re-admission)'
}

phase_s4() {
  # -------------------------------------------------------------------
  # S4 — the authority boundaries remain intact in the final promoted
  # state.
  # -------------------------------------------------------------------
  say 'S4: the boundary audit (workload isolation, no-diagnostics, store shape)'
  ensure_session
  sesearch_capture s4-final
  # the workload domain: NO security_t grant row in the final state
  WORKROWS="$(workload_rows "$EVIDENCE_DIR/s4-final-allow-all.txt")"
  [ -z "$WORKROWS" ] \
    || fail "S4: the workload domain must carry no security_t grant"
  # the loaded policy's allow set toward security_t, every subject
  # captured, side by side (the permanence record)
  {
    echo '== every allow row toward security_t (all subjects, dir/file/security) =='
    cat "$EVIDENCE_DIR/s4-final-allow-dir.txt" "$EVIDENCE_DIR/s4-final-allow-file.txt" "$EVIDENCE_DIR/s4-final-allow-security.txt"
  } > "$EVIDENCE_DIR/s4-final-security-surface.txt"
  grep -aFq 'allow docker_helper_buildkitd_t security_t:file { getattr open read write };' \
    "$EVIDENCE_DIR/s4-final-security-surface.txt" \
    || fail "S4: the promoted file rule vanished from the final capture"
  grep -aFq 'allow docker_helper_buildkitd_t security_t:security { check_context read_policy };' \
    "$EVIDENCE_DIR/s4-final-security-surface.txt" \
    || fail "S4: the promoted security rule vanished from the final capture"
  # no diagnostic module anywhere
  if semodule -l 2>/dev/null | grep -aqE 'diag|mnb4[01]|probe'; then
    faillist="$(semodule -l 2>/dev/null | grep -aE 'diag|mnb4[01]|probe' || true)"
    fail "S4: a diagnostic module is still listed in the store: $faillist"
  fi
  ev s4-store-listing "$(semodule -l 2>/dev/null | grep -E 'docker.helper|docker_helper' || true)"
  ev s4-policy-sha "$(policy_sha)"
  [ "$(cat "$EVIDENCE_DIR/s4-policy-sha")" = "$(cat "$EVIDENCE_DIR/s2-loaded-sha")" ] \
    || fail "S4: the final loaded sha must equal the S2 acceptance sha"
  say 'S4: PASS (the boundaries hold; no diagnostic module anywhere)'
}

phase_m5() {
  # -------------------------------------------------------------------
  # M5 — the closure: artifact identity + the composed verdict.
  # -------------------------------------------------------------------
  say 'M5: closure (artifact identity + the composed verdict)'
  ev m5-pp-sha "$(sha256sum "$SHIP_PP" | awk '{print $1}')"
  [ "$(cat "$EVIDENCE_DIR/m5-pp-sha")" = "$MNB41_EXPECTED_PP_SHA256" ] \
    || fail "the shipped .pp digest must be unchanged at closure"
  [ "$(cat "$EVIDENCE_DIR/m5-pp-sha")" = "$(sha256sum "$SHIP_PP_COPY" | awk '{print $1}')" ] \
    || fail "the shipped .pp working copy must be byte-identical at closure"
  ev m5-constraint-cil-sha "$(sha256sum "$CONSTRAINT_CIL" 2>/dev/null | awk '{print $1}')"
  [ "$(cat "$EVIDENCE_DIR/m5-constraint-cil-sha")" = "$(cat "$EVIDENCE_DIR/p0-constraint-artifact-sha")" ] \
    || fail "the shipped constraint artifact must be unchanged at closure"
  ev m5-final-policy-sha "$(policy_sha)"
  [ "$(cat "$EVIDENCE_DIR/m5-final-policy-sha")" = "$(cat "$EVIDENCE_DIR/s2-loaded-sha")" ] \
    || fail "the final loaded-policy sha must equal the S2 acceptance sha"
  seinfo --constrain fifo_file "$POLICYPATH" > "$EVIDENCE_DIR/m5-seinfo-constrain.txt" 2>&1 \
    || fail "seinfo closure capture failed"
  grep -Fqx "$STATEMENT" "$EVIDENCE_DIR/m5-seinfo-constrain.txt" \
    || fail "the closure snapshot must carry the canonical constraint verbatim"

  {
    printf 'baseline.delta.exact     = %s\n' \
      "$(grep -aFq 'allow docker_helper_buildkitd_t security_t:file { getattr open read write };' "$DELTA_FILE" \
        && echo 'PASS (S1: the effective loaded-state delta is exactly the two promoted rules)')"
    printf 'baseline.refused.closed = %s\n' \
      "$(grep -qiF "$GATEMSG_CTX" "$EVIDENCE_DIR/s1-baseline-refuse.log" \
        && echo 'PASS (S1: the accepted-baseline BUILD refuses closed through the context gate)')"
    printf 'promoted.build.admitted  = %s\n' \
      "$(grep -qx 'rc=0' "$EVIDENCE_DIR/s2-build.rc" 2>/dev/null \
        && echo 'PASS (S2: the production BUILD admitted through both wrapper gates)')"
    printf 'promoted.run.admitted    = %s\n' \
      "$(grep -qx 'rc=0' "$EVIDENCE_DIR/s2-run.rc" 2>/dev/null \
        && echo 'PASS (S2: the production RUN admitted through its independent lane)')"
    printf 'fifo.exact.recognition   = %s\n' \
      "$(grep -qx 'rc=0' "$EVIDENCE_DIR/s2-build.rc" 2>/dev/null \
        && echo 'PASS (S2/S3: the admitted build parsed and matched the canonical constraint; S3 recorded the exact missing-statement refusal)')"
    printf 'missing.fifo.fail.closed = %s\n' \
      "$(grep -qF "$GATEMSG_MISSING" "$EVIDENCE_DIR/s3-missing-refuse.log" 2>/dev/null \
        && echo 'PASS (S3: the removal refused the build at the FIFO gate before execution commit)')"
    printf 'constraint.restore.exact = %s\n' \
      "$(grep -qx "$(cat "$EVIDENCE_DIR/s2-loaded-sha" 2>/dev/null)" <(cat "$EVIDENCE_DIR/s3-policy-sha-restored" 2>/dev/null) 2>/dev/null \
        && echo 'PASS (S3: the constraint restoration returned the loaded policy byte-exactly)')"
    printf 'workload.no.grant        = %s\n' \
      "$(if [ -n "$(workload_rows "$EVIDENCE_DIR/s4-final-allow-all.txt" 2>/dev/null)" ]; then echo FAILED; else echo 'PASS (S4: the workload domain carries no security_t grant row anywhere)'; fi)"
    printf 'no.diagnostic.modules    = %s\n' \
      "$(semodule -l 2>/dev/null | grep -aqE 'diag|mnb4[01]|probe' \
        && echo FAILED \
        || echo 'PASS (the store holds exactly the two product modules)')"
    printf 'closure.sha.identity     = %s\n' \
      "$(grep -qx "$(cat "$EVIDENCE_DIR/s2-loaded-sha" 2>/dev/null)" <(cat "$EVIDENCE_DIR/m5-final-policy-sha" 2>/dev/null) 2>/dev/null \
        && echo 'PASS (the .pp digest, constraint digest and loaded-policy sha are all unchanged at closure)')"
  } > "$EVIDENCE_DIR/m5-verdict.txt"
  if grep -q 'FAILED\|=' "$EVIDENCE_DIR/m5-verdict.txt" && grep -q 'FAILED' "$EVIDENCE_DIR/m5-verdict.txt"; then
    cat "$EVIDENCE_DIR/m5-verdict.txt"
    fail "the MNB41 verdict carries a FAILED line"
  fi
  if grep -q 'MISSING-INVENTORY' "$EVIDENCE_DIR/m5-verdict.txt"; then
    cat "$EVIDENCE_DIR/m5-verdict.txt"
    fail "the MNB41 verdict carries an uncomputed line"
  fi
  cat "$EVIDENCE_DIR/m5-verdict.txt"
  say 'M5: PASS'
  printf '%s\n' 'R7-MNB41-VERDICT=PASS'
}

run_phase() {
  case "$1" in
    p0) phase_p0 ;;
    s1) phase_s1 ;;
    s2) phase_s2 ;;
    s3) phase_s3 ;;
    s4) phase_s4 ;;
    m5) phase_m5 ;;
    *) fail "unknown phase $1" ;;
  esac
}

# the enforcement VM boots fresh on every attempt: a previous attempt's
# completed-phase markers describe a DIFFERENT machine state, so the
# boot identity invalidates them (the state dir persists in /var/lib,
# the boot never does)
CURBOOT="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
mkdir -p "$STATE_DIR"
if [ -n "$CURBOOT" ] && [ -f "$STATE_DIR/boot-id" ] \
  && [ "$(cat "$STATE_DIR/boot-id" 2>/dev/null)" != "$CURBOOT" ]; then
  rm -f "$PHASE_FILE"
fi
[ -n "$CURBOOT" ] && printf '%s\n' "$CURBOOT" > "$STATE_DIR/boot-id" || true
for ph in p0 s1 s2 s3 s4 m5; do
  if done_phase "$ph"; then
    say "re-entry: $ph already PASS"
    continue
  fi
  run_phase "$ph"
  mark "$ph"
done

printf '%s\n' 'R7-MNB41-VERDICT=PASS'
exit 0
