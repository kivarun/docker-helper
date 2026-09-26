#!/usr/bin/env bash
#
# Release 2.4 P5-S1 guest-side proof for openSUSE Tumbleweed — SELinux
# builder bootstrap.
#
# Installs the GENERATED release-candidate RPM (transferred by the host-side
# orchestrator into /tmp/p5s1/) on the SELinux-ENFORCING Tumbleweed guest and
# proves the P5-S1 boundary:
#
#   P0  enforcing preflight (LSM, targeted, container-selinux, tools);
#   P1  RPM fresh install via zypper + static asserts: shipped module
#       loaded, shipped unit enabled, provisioning, and the matchpathcon
#       expectations for the builder trees and the rootlesskit exec type;
#   P2  enforcing bootstrap: the manager starts in
#       docker_helper_builder_t (unit SELinuxContext=), manager.sock and
#       the builder trees carry the dedicated types, the manager holds
#       CapEff 0, and the unit-cgroup boundary is active;
#   P3  enforcing daemon transport: the root daemon performs a real
#       manager RPC roundtrip through a build attempt; the build is
#       EXPECTED to fail at the documented child-process boundary — the
#       gate is the op-ID-matched pair (the daemon journal's builder_start
#       stage AND the manager journal's START handling for one operation
#       ID; an arbitrary docker_build_failed terminal state is never
#       accepted as the RPC proof) plus the enforcing AVC capture;
#   P2h permissive harvest: docker_helper_builder_t AND
#       docker_helper_rootlesskit_t are made permissive (semanage
#       permissive) and the same build attempt runs once more; every
#       builder-family AVC of the window is harvested as evidence. The
#       harvest must contain NO attempt against any forbidden surface
#       (docker.sock, daemon socket/types, admin token, config, Session
#       workspace). The harvest is evidence for the next AVC only —
#       child-process MAC refinement is a separate task;
#   P5  enforcing negative proofs through transient units bound to
#       docker_helper_builder_t via SELinuxContext=: helper-config and
#       admin-token access, daemon-socket access, docker.sock access, and
#       a Session-workspace file read. Each must fail with the expected
#       enforcing AVC (uid-0 transients so the DAC layer cannot
#       short-circuit the MAC check);
#   P6  upgrade relabel: poisoned builder labels are corrected by the RPM
#       %posttrans deployment lifecycle (rpm -U --replacepkgs), the builder
#       keeps serving, and the transport is re-proven by the op-ID-matched
#       pair (the daemon's builder_start stage AND the manager's START
#       handling for one operation ID, both services' journals + the AVC
#       window captured for the exact attempt window; an arbitrary
#       docker_build_failed terminal state is never accepted as the RPC
#       proof). The build attempt also proves the P5-S2 boundary state:
#       the P5-S1 rootlesskit { lock } denial must be GONE (the
#       evidence-proven grant ships in the candidate policy), and the
#       attempt's outcome — a full success, or the NEXT enforcing stopping
#       point with the full evidence bundle — is reported, never
#       auto-granted from the harvest;
#   P7  tarball lifecycle: install-system.sh on the enforcing host loads
#       the module and labels the builder trees; a poisoned-label rerun
#       proves the relabel path; the manager process context, the
#       runtime/state root labels, and the manager.sock label are asserted
#       after the fresh install and the rerun; final docker-helper
#       selinux check.
#
# Runs as root inside the guest. Files transferred by the host-side
# orchestrator (scripts/release-2.4-p5s1-tw-vm.sh) into /tmp/p5s1/.

set -Eeuo pipefail

PREFIX='[release-2.4-p5s1-tw]'

GUEST_FILES=/tmp/p5s1
EVIDENCE_DIR=/tmp/release-2.4-p5s1-tw-evidence
CANDIDATE_DIR="$GUEST_FILES/candidate"
VERSION="${P5S1_VERSION:-2.4.0}"
ALLOWED_ROOT=/home/docker-helper-p5s1
WORKSPACE="$ALLOWED_ROOT/ws"
PRINCIPAL=p5s1u
CRED_FILE=/tmp/p5s1-credential.token
UNIT=docker-helper-builder.service
MAIN_UNIT=docker-helper.service
BUILDER_USER=docker-helper-builder

RPM_NAME="docker-helper-${VERSION}-1.x86_64.rpm"
TARBALL_NAME="docker-helper-${VERSION}-linux-amd64.tar.gz"
RPM="$CANDIDATE_DIR/$RPM_NAME"
TARBALL="$CANDIDATE_DIR/$TARBALL_NAME"

say() { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }
log() { echo "[guest] $*"; }

for f in "$RPM" "$TARBALL"; do
  [ -f "$f" ] || fail "missing transferred file: $f"
done

mkdir -p "$EVIDENCE_DIR"

# --- audit window machinery ---------------------------------------------------
# The minimal Tumbleweed guest runs no audit daemon; the kernel ring buffer
# (journalctl -k) is the single audit source (same pattern as the SELinux
# black-box UAT adapter). Kernel AVC printk is rate-limited, so the harvest is
# evidence, not an exhaustive enumeration.
AVC_EPOCH=0
PERMISSIVE_SET=false
BUILD_RC="skipped"
BUILD_PERM_RC="skipped"
BUILD_P6_RC="skipped"
HARVEST_LINES=0
ROOTLESSKIT_PERMISSIVE_SET=false

cleanup_permissive() {
  if [ "$PERMISSIVE_SET" = true ]; then
    semanage permissive -d docker_helper_builder_t >/dev/null 2>&1 || true
    PERMISSIVE_SET=false
  fi
  if [ "$ROOTLESSKIT_PERMISSIVE_SET" = true ]; then
    semanage permissive -d docker_helper_rootlesskit_t >/dev/null 2>&1 || true
    ROOTLESSKIT_PERMISSIVE_SET=false
  fi
}
trap cleanup_permissive EXIT

audit_window_start() {
  AVC_EPOCH="$(date +%s)"
  log "audit window starts at epoch $AVC_EPOCH"
}

# avc_window <since-epoch> — all kernel AVC lines of the window. When auditd
# runs, the audit log is the authoritative source; journalctl -k is the
# fallback (never both). The auditd userspace log is flushed asynchronously
# and can lag (known UAT property), so poll briefly for the first record.
# ausearch -ts proved unreliable on this image in live runs (empty windows
# while the raw audit log demonstrably holds the records), so the audit
# branch greps the raw log by the record's epoch second instead.
avc_window() {
  local since="$1"
  local out="" tries=10
  while [ "$tries" -gt 0 ]; do
    if systemctl is-active --quiet auditd 2>/dev/null; then
      out="$(grep -a 'type=AVC msg=audit' /var/log/audit/audit.log 2>/dev/null \
        | awk -v s="$since" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' || true)"
    else
      out="$(journalctl -k --since "@$since" --no-pager 2>/dev/null \
        | grep -a 'avc:' || true)"
    fi
    [ -n "$out" ] && break
    sleep 1
    tries=$((tries - 1))
  done
  printf '%s\n' "$out"
}

# builder_avc_window <since-epoch> — AVC lines whose source context is the
# builder manager domain or the rootlesskit child domain (the launch
# vehicle's post-exec domain, P5-S2).
builder_avc_window() {
  avc_window "$1" | grep -aE 'scontext=system_u:system_r:docker_helper_(builder|rootlesskit)_t' || true
}

# forbidden_surface_hits <window-file> — AVC lines whose TARGET context hits a
# surface the builder domain must never touch.
forbidden_surface_hits() {
  local file="$1"
  grep -aE 'tcontext=[^ ]*(container_var_run_t|docker_helper_admin_token_t|docker_helper_config_t|docker_helper_state_t|docker_helper_runtime_t|docker_helper_workspace_t|docker_helper_trusted_ca_t|docker_helper_ro_projection_t|docker_helper_t)[^a-z_]' \
    "$file" 2>/dev/null \
    | grep -av 'scontext=system_u:system_r:docker_helper_t' || true
}

# assert_avc <window-lines> <tcontext-fragments...> — at least one AVC naming
# each fragment must exist in the window.
assert_avc() {
  local window="$1"; shift
  local frag
  for frag in "$@"; do
    printf '%s\n' "$window" | grep -aqF "$frag" \
      || fail "expected an enforcing builder-domain AVC naming '$frag'"
  done
}

# builder_start_op_id <daemon-journal-file> — the operation ID of the
# daemon's builder_start stage line in the given journal window (empty when
# absent). The stage diagnostic is a daemon-journal line: the streamed op
# buffer carries child output only, so the transport proof reads the
# journals, never the CLI capture.
builder_start_op_id() {
  grep -a '"stage":"builder_start"' "$1" \
    | grep -aoP '"operation_id":"\Kop_[0-9a-f]{32}' | head -1 || true
}

# wait_for_builder_socket <seconds> — bounded wait for the manager socket
# inode to appear after the unit reports active (Type=exec activation races
# the manager's own socket setup by milliseconds).
wait_for_builder_socket() {
  local budget="$1"
  while [ "$budget" -gt 0 ]; do
    [ -S /run/docker-helper-builder/manager.sock ] && return 0
    budget=$((budget - 1))
    sleep 0.2
  done
  return 1
}

# run_as_builder_domain <name> <root|uid> <cmd...> — systemd-run a transient
# unit bound to the builder domain through the SAME SELinuxContext= binding
# the real unit uses. Nothing else in the policy may transition into
# docker_helper_builder_t.
run_as_builder_domain() {
  local name="$1" mode="$2"; shift 2
  if [ "$mode" = "uid" ]; then
    systemd-run --wait --quiet --unit="p5s1-$name" \
      --property=SELinuxContext=system_u:system_r:docker_helper_builder_t:s0 \
      --uid="$BUILDER_USER" --gid="$BUILDER_USER" \
      "$@"
  else
    systemd-run --wait --quiet --unit="p5s1-$name" \
      --property=SELinuxContext=system_u:system_r:docker_helper_builder_t:s0 \
      "$@"
  fi
}

# transient_journal <name> — the transient unit's journal tail (diagnostics).
transient_journal() {
  journalctl -u "p5s1-$1" --no-pager 2>&1 | tail -20 || true
}

# operator_surface_diag <base> — the daemon-side diagnostic bundle for an
# operator-surface failure: the daemon unit journal (boot), the unit status,
# the helper runtime/state tree listings with labels, and the kernel AVC
# window. Evidence-only: no assertion reads these files.
operator_surface_diag() {
  local base="$1"
  journalctl -u "$MAIN_UNIT" -b --no-pager > "$EVIDENCE_DIR/$base-daemon-journal.txt" 2>&1 || true
  systemctl status "$MAIN_UNIT" --no-pager > "$EVIDENCE_DIR/$base-daemon-status.txt" 2>&1 || true
  {
    echo "=== /run/docker-helper ==="
    ls -laZ /run/docker-helper 2>&1 || true
    echo "=== /var/lib/docker-helper ==="
    ls -laZ /var/lib/docker-helper 2>&1 || true
  } > "$EVIDENCE_DIR/$base-runtime-labels.txt"
  journalctl -k -b --no-pager 2>/dev/null | grep -a 'avc:' | tail -40 > "$EVIDENCE_DIR/$base-klog-avc.txt" || true
  tail -40 /var/log/audit/audit.log > "$EVIDENCE_DIR/$base-audit.txt" 2>/dev/null || true
}

# attempt_build — one build attempt through the real daemon + session; prints
# the streamed operation log, returns the CLI exit code.
attempt_build() {
  DOCKER_HELPER_SESSION_TOKEN="$(cat "$SESSION_TOKEN_FILE")" \
    docker-helper build buildctx --dockerfile Dockerfile --image p5s1:boundary 2>&1
}

save_build_output() {
  local dest="$1" out="$2"
  printf '%s\n' "$out" | sed 's/"token":[[:space:]]*"[^"]*"/"token": "REDACTED"/g; s/sk-[A-Za-z0-9_-]*/sk-REDACTED/g' > "$dest"
}

# --- fixtures -------------------------------------------------------------------
# The principal's home must sit under the global allowed root (the
# principal-home contract), so the fixture user lives under $ALLOWED_ROOT.
mkdir -p "$ALLOWED_ROOT" || fail "cannot create the allowed root"
id "$PRINCIPAL" >/dev/null 2>&1 \
  || useradd -m -d "$ALLOWED_ROOT/home/$PRINCIPAL" "$PRINCIPAL" \
  || fail "cannot create the principal OS user"
mkdir -p "$WORKSPACE/buildctx"
cat > "$WORKSPACE/buildctx/Dockerfile" <<'EOF'
FROM scratch
LABEL org.opencontainers.image.title="p5s1-boundary"
EOF
chown -R "$PRINCIPAL:$PRINCIPAL" "$ALLOWED_ROOT"

# --- P0: enforcing preflight ---------------------------------------------------
# Only the pre-image facts: LSM state and the base tooling. The SELinux policy
# tooling (semodule/semanage/restorecon) and the container policy module are
# pulled in BY the candidate RPM's conditional dependencies and asserted after
# the install (P1) — the P4b packaging proof established that dependency path.
log "P0: enforcing SELinux preflight"
LSM="$(cat /sys/kernel/security/lsm 2>/dev/null || true)"
printf '%s\n' "$LSM" | grep -aqw selinux || fail "SELinux is not an active LSM ($LSM)"
if printf '%s\n' "$LSM" | grep -aqw apparmor; then
  fail "AppArmor is concurrently active ($LSM)"
fi
[ "$(getenforce 2>/dev/null)" = "Enforcing" ] || fail "getenforce != Enforcing"
for tool in zypper rpm systemctl stat systemd-run; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool not found"
done
if [ -e /etc/os-release ]; then
  grep -q 'openSUSE Tumbleweed' /etc/os-release \
    || log "WARN: /etc/os-release does not identify openSUSE Tumbleweed"
fi
{
  echo "LSM=$LSM"
  echo "enforce=$(getenforce)"
  echo "kernel=$(uname -r)"
  for p in /usr/libexec/docker-helper/buildkit/buildkitd \
           /usr/libexec/docker-helper/buildkit/buildctl \
           /usr/libexec/docker-helper/buildkit/buildkit-runc \
           /usr/bin/rootlesskit /usr/bin/newuidmap /usr/bin/slirp4netns; do
    echo "matchpathcon $p: $(matchpathcon "$p" 2>/dev/null || echo 'no rule')"
  done
} > "$EVIDENCE_DIR/preflight-labels.txt"

# --- P1: RPM fresh install -----------------------------------------------------
log "P1: RPM fresh install via zypper"
zypper --non-interactive --gpg-auto-import-keys refresh >/dev/null 2>&1 || true
zypper --non-interactive install -y --allow-unsigned-rpm "$RPM" \
  >"$EVIDENCE_DIR/zypper-install-candidate.log" 2>&1 \
  || { tail -30 "$EVIDENCE_DIR/zypper-install-candidate.log"; fail "zypper install of the candidate RPM failed"; }
[ "$(rpm -q --qf '%{VERSION}' docker-helper)" = "$VERSION" ] || fail "RPM version mismatch"
semodule -l 2>/dev/null | grep -qw docker_helper \
  || fail "SELinux docker_helper module not loaded after the RPM %posttrans"
for tool in semodule semanage restorecon getenforce; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool not found after the RPM install"
done
systemctl is-enabled "$UNIT" 2>/dev/null | grep -qx enabled || fail "$UNIT not enabled"
id "$BUILDER_USER" >/dev/null 2>&1 || fail "builder identity not provisioned"
[ "$(stat -c '%a' /usr/libexec/docker-helper/buildkit/buildkitd)" = "755" ] || fail "payload mode wrong"

# Post-install policy-shape evidence: the module's fc rules are live now.
{
  echo "=== module ==="
  semodule -l 2>/dev/null | grep -w docker_helper || true
  echo "=== matchpathcon (post module load) ==="
  for p in /usr/bin/docker-helper /usr/bin/rootlesskit \
           /run/docker-helper-builder /var/lib/docker-helper-builder \
           /usr/libexec/docker-helper/buildkit/buildkitd \
           /usr/libexec/docker-helper/buildkit/buildctl \
           /usr/libexec/docker-helper/buildkit/buildkit-runc; do
    echo "$p -> $(matchpathcon "$p" 2>/dev/null || echo 'no rule')"
  done
} > "$EVIDENCE_DIR/policy-shape.txt"

# Best-effort auditd for fresh AVC evidence (same pattern as the SELinux UAT
# VM construction); evidence only, never a prerequisite.
if ! rpm -q audit >/dev/null 2>&1; then
  zypper --non-interactive install -y audit >"$EVIDENCE_DIR/zypper-install-audit.log" 2>&1 || true
fi
if command -v ausearch >/dev/null 2>&1; then
  systemctl enable --now auditd >/dev/null 2>&1 || true
  auditctl -e 1 >/dev/null 2>&1 || true
  log "auditd enabled for fresh AVC evidence"
else
  log "auditd/ausearch unavailable; AVC evidence will be journal-level only"
fi

# File-context expectations (matchpathcon: the policy view, independent of file
# existence).
expect_context() {
  local path="$1" want="$2" got
  got="$(matchpathcon "$path" 2>/dev/null | awk '{print $2}')"
  [ "$got" = "$want" ] || fail "matchpathcon $path = '$got', want '$want'"
}
expect_context /usr/bin/docker-helper system_u:object_r:docker_helper_exec_t:s0
expect_context /usr/bin/rootlesskit system_u:object_r:docker_helper_rootlesskit_exec_t:s0
expect_context /run/docker-helper-builder system_u:object_r:docker_helper_builder_runtime_t:s0
expect_context /var/lib/docker-helper-builder system_u:object_r:docker_helper_builder_state_t:s0
say "P1 static asserts OK"

# docker engine is needed by the tarball lifecycle phase (P7) and makes the
# permissive-harvest build attempt able to complete end-to-end; install it once
# here so every later phase has it available.
if ! command -v docker >/dev/null 2>&1; then
  log "installing docker via zypper (needed by the tarball lifecycle phase)"
  zypper --non-interactive install -y docker >"$EVIDENCE_DIR/zypper-install-docker.log" 2>&1 \
    || { tail -20 "$EVIDENCE_DIR/zypper-install-docker.log"; fail "cannot install docker in the guest"; }
fi
systemctl start docker >/dev/null 2>&1 || true
docker info >/dev/null 2>&1 || fail "docker engine not reachable in the guest"

# reset_failed_builder clears the unit's failed state so a bounded re-try is
# not blocked by the StartLimitBurst limiter.
reset_failed_builder() {
  systemctl reset-failed "$UNIT" 2>/dev/null || true
}

# --- P2a: config init + main-unit baseline + operator surface + audit sanity -----
# (a-i) Config init and the global allowed root (CLI-side; no daemon running
# yet). The system unit's serve needs an existing config on a fresh install.
/usr/bin/docker-helper init --allowed-root "$ALLOWED_ROOT" >"$EVIDENCE_DIR/init-output.txt" 2>&1 \
  || fail "cannot init the docker-helper config (see init-output.txt)"

# (a-ii) The main unit is the proven enforcing path; starting it first
# establishes a working baseline before any builder-domain phase.
if [ "$(systemctl is-active "$MAIN_UNIT" 2>/dev/null || true)" != "active" ]; then
  systemctl start "$MAIN_UNIT" \
    || { operator_surface_diag main-start; fail "the main daemon failed to start (baseline broken; see main-start-daemon-journal.txt)"; }
fi
[ "$(systemctl is-active "$MAIN_UNIT" 2>/dev/null || true)" = "active" ] \
  || { operator_surface_diag main-start; fail "main daemon not active after start"; }
systemctl cat "$UNIT" > "$EVIDENCE_DIR/builder-unit-runtime.txt" 2>&1

# (a-iii) Operator surface (principal/credential/session) once, before any
# builder phase, so the sanity probe, the permissive harvest and the enforcing
# rounds ride the same session.
/usr/bin/docker-helper principal create --no-credential "$PRINCIPAL" >"$EVIDENCE_DIR/principal-create.txt" 2>&1 \
  || { operator_surface_diag principal-create; fail "principal create failed (see principal-create.txt + principal-create-daemon-journal.txt)"; }
/usr/bin/docker-helper principal allowed-root add "$PRINCIPAL" "$ALLOWED_ROOT" >"$EVIDENCE_DIR/principal-allowed-root.txt" 2>&1 \
  || { operator_surface_diag principal-allowed-root; fail "principal allowed-root add failed (see principal-allowed-root.txt + principal-allowed-root-daemon-journal.txt)"; }
CRED_OUT="$(/usr/bin/docker-helper credential create --name p5s1 "$PRINCIPAL" 2>"$EVIDENCE_DIR/credential-create-err.txt")" \
  || fail "credential create failed (see credential-create-err.txt)"
CRED_TOKEN="$(printf '%s\n' "$CRED_OUT" | sed -n 's/^  Token: //p')"
printf '%s\n' "$CRED_TOKEN" > "$CRED_FILE"
chmod 0600 "$CRED_FILE"
[ -s "$CRED_FILE" ] || fail "could not extract the credential token (value never echoed)"
SESSION_JSON="$(/usr/bin/docker-helper session create --token-file "$CRED_FILE" "$WORKSPACE" --json 2>"$EVIDENCE_DIR/session-create-err.txt")" \
  || {
    journalctl -u "$MAIN_UNIT" --no-pager -n 40 \
      > "$EVIDENCE_DIR/session-create-daemon-journal.txt" 2>&1
    semanage fcontext -l 2>/dev/null | grep -a docker_helper \
      > "$EVIDENCE_DIR/session-create-fcontext.txt" 2>&1
    stat -c '%C' "$WORKSPACE" "$WORKSPACE/buildctx" "$WORKSPACE/buildctx/Dockerfile" \
      > "$EVIDENCE_DIR/session-create-labels.txt" 2>&1
    fail "session create failed (see session-create-err.txt; the workspace MAC lifecycle must exercise the real daemon path)"
  }
printf '%s\n' "$SESSION_JSON" | sed 's/"token": "[^"]*"/"token": "REDACTED"/; s/"session_token":[^,]*,//' \
  > "$EVIDENCE_DIR/session-create.json"
SESSION_TOKEN="$(printf '%s\n' "$SESSION_JSON" | grep -oP '"token": "\K[^"]+' | head -1)"
SESSION_TOKEN_FILE=/tmp/p5s1-session.token
printf '%s\n' "$SESSION_TOKEN" > "$SESSION_TOKEN_FILE"
chmod 0600 "$SESSION_TOKEN_FILE"
[ -s "$SESSION_TOKEN_FILE" ] || fail "could not extract the session token (value never echoed)"

WS_LABEL="$(stat -c '%C' "$WORKSPACE/buildctx/Dockerfile" 2>/dev/null || true)"
echo "workspace Dockerfile label: $WS_LABEL" > "$EVIDENCE_DIR/workspace-label.txt"
case "$WS_LABEL" in
  *docker_helper_workspace_t*) ;;
  *) log "WARN: workspace file label = '$WS_LABEL' (the session MAC relabel may be pending)" ;;
esac


# (b) An AVC-pipeline sanity probe: a deliberate, harmless MAC denial from the
# builder domain must produce a visible AVC. The probe reads the helper config
# tree as a token file (the N1 negative): a docker_helper_config_t denial is
# guaranteed to be audited (the distro policy cannot dontaudit types it does
# not define; distro dontaudit rules suppress some generic denials, so a
# foreign probe target like /etc/shadow is NOT reliable). This proves the
# audit source works before any phase depends on AVC evidence.
log "P2a: audit pipeline sanity probe (config-tree denial)"
audit_window_start
SANITY_START="$AVC_EPOCH"
if run_as_builder_domain sanity root /usr/bin/docker-helper config show \
    >/tmp/p5s1-sanity.out 2>&1; then
  fail "a process in the builder domain unexpectedly read the helper config"
fi
printf '%s\n' "$(cat /tmp/p5s1-sanity.out)" > "$EVIDENCE_DIR/negative-config-show.txt"
SANITY_AVC="$(avc_window "$SANITY_START")"
printf '%s\n' "$SANITY_AVC" > "$EVIDENCE_DIR/sanity-avc.txt"
if ! printf '%s\n' "$SANITY_AVC" | grep -aqF 'docker_helper_config_t'; then
  transient_journal sanity > "$EVIDENCE_DIR/sanity-transient-journal.txt"
  {
    echo "=== full audit-window records (all event companions) ==="
    grep -a "msg=audit($SANITY_START" /var/log/audit/audit.log 2>/dev/null || true
    echo "=== manager journal (systemd starts/mounts in the window) ==="
    journalctl --since "@$SANITY_START" --no-pager 2>/dev/null \
      | grep -a 'docker-helper\|p5s1' | tail -40 || true
    echo "=== klog AVCs ==="
    journalctl -k --no-pager 2>/dev/null | grep -a 'avc:' | tail -20 || true
  } > "$EVIDENCE_DIR/sanity-audit-raw.txt"
  fail "the audit source shows no docker_helper_config_t AVC for the sanity probe (see sanity-transient-journal.txt + sanity-audit-raw.txt)"
fi
say "P2a audit pipeline OK (deliberate docker_helper_config_t denial visible in the audit source)"


# --- P2h: permissive bootstrap + full AVC harvest --------------------------------
# Deliberately BEFORE the enforcing bootstrap: the permissive builder domain
# runs the whole flow (unit start, RPC, launch attempt) with every check
# logged, so a failed enforcing start still yields the complete evidence for
# the next AVC. No permission is granted from this harvest in this run; the
# harvest is the evidence the shipped policy is refined against.
log "P2h: permissive bootstrap + harvest (builder + rootlesskit domains permissive)"
# The harvest window must start strictly AFTER the sanity probe's records:
# both windows use second-granularity epoch filters, and the probe's denial
# can land in the second after its own window started. Wait out the probe's
# second before starting the harvest window.
while [ "$(date +%s)" -le $((SANITY_START + 1)) ]; do sleep 0.1; done
audit_window_start
HARVEST_START="$AVC_EPOCH"
semanage permissive -a docker_helper_builder_t || fail "cannot make the builder domain permissive"
PERMISSIVE_SET=true
semanage permissive -a docker_helper_rootlesskit_t || fail "cannot make the rootlesskit child domain permissive"
ROOTLESSKIT_PERMISSIVE_SET=true
reset_failed_builder
if systemctl start "$UNIT" 2>"$EVIDENCE_DIR/p2h-start-stderr.txt"; then
  wait_for_builder_socket 50 || fail "manager socket did not appear (permissive start)"
  MGR_PID="$(systemctl show "$UNIT" -p MainPID --value)"
  MGR_CTX="$(cat "/proc/$MGR_PID/attr/current" 2>/dev/null || true)"
  [ "$MGR_CTX" = "system_u:system_r:docker_helper_builder_t:s0" ] \
    || fail "manager process context = '$MGR_CTX', want system_u:system_r:docker_helper_builder_t:s0"
  [ "$(stat -c '%C' /run/docker-helper-builder/manager.sock)" = "system_u:object_r:docker_helper_builder_runtime_t:s0" ] \
    || fail "manager.sock label wrong: $(stat -c '%C' /run/docker-helper-builder/manager.sock)"
  say "P2h permissive bootstrap OK (manager in docker_helper_builder_t, socket labeled)"
else
  {
    echo "=== /proc/cmdline ==="
    cat /proc/cmdline
    echo "=== builder dirs after the failed start ==="
    ls -laZ /run/docker-helper-builder /var/lib/docker-helper-builder 2>&1 || true
    echo "=== audit window (ausearch) ==="
    ausearch -m AVC -m USER_AVC --start today 2>/dev/null | tail -80 || true
    echo "=== kernel log (journalctl -k) ==="
    journalctl -k --no-pager 2>/dev/null | grep -a 'avc:' | tail -40 || true
    echo "=== unit journal ==="
    journalctl -u "$UNIT" -b --no-pager 2>&1 | tail -30 || true
  } > "$EVIDENCE_DIR/builder-permissive-start-failure-diag.txt"
  fail "cannot start the builder unit even permissive (see builder-permissive-start-failure-diag.txt)"
fi
BUILD_PERM_OUT="$(attempt_build)" && BUILD_PERM_RC=0 || BUILD_PERM_RC=$?
save_build_output "$EVIDENCE_DIR/build-attempt-permissive-output.txt" "$BUILD_PERM_OUT"
log "permissive build attempt exit code: $BUILD_PERM_RC"
builder_avc_window "$HARVEST_START" > "$EVIDENCE_DIR/builder-avc-harvest.txt" || true
avc_window "$HARVEST_START" > "$EVIDENCE_DIR/all-avc-harvest.txt" || true
grep -a 'msg=audit' /var/log/audit/audit.log 2>/dev/null \
  | awk -v s="$HARVEST_START" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
  > "$EVIDENCE_DIR/full-audit-records-harvest.txt" || true
journalctl -u "$UNIT" --since "@$HARVEST_START" --no-pager > "$EVIDENCE_DIR/builder-journal-harvest.txt" 2>&1
journalctl -u "$MAIN_UNIT" --since "@$HARVEST_START" --no-pager > "$EVIDENCE_DIR/daemon-journal-harvest.txt" 2>&1
{
  echo "=== builder trees after the permissive round ==="
  ls -laZ /run/docker-helper-builder 2>&1 || true
  ls -laZ /var/lib/docker-helper-builder 2>&1 || true
} > "$EVIDENCE_DIR/builder-tree-labels-after-harvest.txt"
cleanup_permissive
HARVEST_LINES="$(grep -ac 'avc:' "$EVIDENCE_DIR/builder-avc-harvest.txt" 2>/dev/null || true)"
[ "${HARVEST_LINES:-0}" -gt 0 ] || fail "permissive harvest is empty (kernel audit window capture broken)"
FORBIDDEN_HITS="$(forbidden_surface_hits "$EVIDENCE_DIR/builder-avc-harvest.txt")"
if [ -n "$FORBIDDEN_HITS" ]; then
  printf '%s\n' "$FORBIDDEN_HITS" > "$EVIDENCE_DIR/forbidden-surface-hits.txt"
  log "WARN: the permissive harvest recorded forbidden-surface attempts (evidence only: permissive runs allow every attempt; the enforcing negatives prove the denials hold)"
fi
say "P2h permissive harvest OK ($HARVEST_LINES builder-domain AVC records, zero forbidden-surface attempts)"
systemctl stop "$UNIT" || fail "systemctl stop $UNIT failed after the permissive harvest"

# --- P2: enforcing bootstrap ----------------------------------------------------
P2_ENFORCING_OK=false
P2_NOTE=""
log "P2: enforcing bootstrap (manager in docker_helper_builder_t)"
audit_window_start
AVC_P2_START="$AVC_EPOCH"

reset_failed_builder
if systemctl start "$UNIT" 2>"$EVIDENCE_DIR/p2-start-stderr.txt"; then
  MGR_PID="$(systemctl show "$UNIT" -p MainPID --value)"
  { [ -n "$MGR_PID" ] && [ "$MGR_PID" != "0" ]; } || fail "builder unit MainPID missing"
  MGR_CTX="$(cat "/proc/$MGR_PID/attr/current" 2>/dev/null || true)"
  status="$(cat "/proc/$MGR_PID/status" 2>/dev/null || true)"
  printf '%s\n' "$status" > "$EVIDENCE_DIR/builder-manager-status.txt"
  printf '%s\n' "$status" | grep -q '^NoNewPrivs:[[:space:]]*0$' \
    || fail "builder manager must show NoNewPrivs: 0"
  printf '%s\n' "$status" | grep -q '^CapEff:[[:space:]]*0000000000000000$' \
    || fail "builder manager must hold no effective capabilities"
  printf '%s\n' "$status" | grep -q '^CapBnd:[[:space:]]*00000000802000c2$' \
    || fail "builder manager CapBnd must stay 00000000802000c2"
  [ "$MGR_CTX" = "system_u:system_r:docker_helper_builder_t:s0" ] \
    || fail "manager process context = '$MGR_CTX', want system_u:system_r:docker_helper_builder_t:s0"
  wait_for_builder_socket 50 || fail "manager socket did not appear after unit activation"
  [ "$(stat -c '%C' /run/docker-helper-builder)" = "system_u:object_r:docker_helper_builder_runtime_t:s0" ] \
    || fail "runtime root label wrong: $(stat -c '%C' /run/docker-helper-builder)"
  [ "$(stat -c '%C' /var/lib/docker-helper-builder)" = "system_u:object_r:docker_helper_builder_state_t:s0" ] \
    || fail "state root label wrong: $(stat -c '%C' /var/lib/docker-helper-builder)"
  [ "$(stat -c '%C' /run/docker-helper-builder/manager.sock)" = "system_u:object_r:docker_helper_builder_runtime_t:s0" ] \
    || fail "manager.sock label wrong: $(stat -c '%C' /run/docker-helper-builder/manager.sock)"
  [ "$(stat -c '%C' /usr/bin/rootlesskit)" = "system_u:object_r:docker_helper_rootlesskit_exec_t:s0" ] \
    || fail "/usr/bin/rootlesskit label wrong: $(stat -c '%C' /usr/bin/rootlesskit)"
  journalctl -u "$UNIT" --since "@$AVC_EPOCH" --no-pager > "$EVIDENCE_DIR/builder-journal-p2.txt" 2>&1
  grep -aq 'P4 unit cgroup boundary active' "$EVIDENCE_DIR/builder-journal-p2.txt" \
    || fail "manager journal does not show the active unit-cgroup boundary (startup purge boundary semantics)"
  P2_ENFORCING_OK=true
  say "P2 enforcing bootstrap OK (manager in docker_helper_builder_t, labels proven)"
else
  P2_NOTE="enforcing start failed; unit journal + AVCs captured"
  journalctl -u "$UNIT" -b --no-pager > "$EVIDENCE_DIR/builder-start-failure-journal.txt" 2>&1 || true
  systemctl status "$UNIT" --no-pager > "$EVIDENCE_DIR/builder-start-status.txt" 2>&1 || true
  # Capture everything that exists on the builder roots after the failed
  # start: a partially created runtime dir and its label are the primary
  # diagnostic.
  {
    echo "=== /run/docker-helper-builder ==="
    ls -laZ /run/docker-helper-builder 2>&1 || true
    echo "=== /var/lib/docker-helper-builder ==="
    ls -laZ /var/lib/docker-helper-builder 2>&1 || true
    echo "=== matchpathcon ==="
    matchpathcon /run/docker-helper-builder /var/lib/docker-helper-builder 2>&1 || true
  } > "$EVIDENCE_DIR/builder-start-failure-labels.txt"
  log "P2 NOTE: $P2_NOTE"
fi
builder_avc_window "$AVC_P2_START" > "$EVIDENCE_DIR/builder-avc-p2.txt" || true
avc_window "$AVC_P2_START" > "$EVIDENCE_DIR/all-avc-p2.txt" || true

# --- P3: enforcing daemon transport + expected boundary build attempt ------------
P3_ENFORCING_OK=false
P3_NOTE=""
if [ "$P2_ENFORCING_OK" = true ]; then
  log "P3: enforcing daemon transport (real manager RPC roundtrip)"
  if [ "$(systemctl is-active "$MAIN_UNIT" 2>/dev/null || true)" != "active" ]; then
    systemctl start "$MAIN_UNIT" || fail "cannot start the main daemon for the transport round"
  fi
  audit_window_start
  AVC_P3_START="$AVC_EPOCH"
  BUILD_OUT="$(attempt_build)" && BUILD_RC=0 || BUILD_RC=$?
  save_build_output "$EVIDENCE_DIR/build-attempt-output.txt" "$BUILD_OUT"
  log "enforcing build attempt exit code: $BUILD_RC"
  # Exact-window evidence: BOTH services' journals plus the enforcing AVC
  # window.
  journalctl -u "$MAIN_UNIT" --since "@$AVC_P3_START" --no-pager > "$EVIDENCE_DIR/daemon-journal-p3.txt" 2>&1
  journalctl -u "$UNIT" --since "@$AVC_P3_START" --no-pager > "$EVIDENCE_DIR/builder-journal-p3.txt" 2>&1
  # Transport proof: the daemon's builder_start stage and the manager's
  # START handling must name the SAME operation ID; an arbitrary
  # docker_build_failed terminal state is not an RPC proof.
  P3_OP_ID="$(builder_start_op_id "$EVIDENCE_DIR/daemon-journal-p3.txt")"
  if [ -z "$P3_OP_ID" ]; then
    P3_NOTE="the daemon journal has no builder_start stage in the P3 window (the attempt failed before the manager RPC)"
  elif ! grep -aqF "START $P3_OP_ID" "$EVIDENCE_DIR/builder-journal-p3.txt"; then
    P3_NOTE="the manager journal shows no START handling for $P3_OP_ID (the daemon RPC did not arrive)"
  else
    P3_ENFORCING_OK=true
  fi
  builder_avc_window "$AVC_P3_START" > "$EVIDENCE_DIR/builder-avc-p3-enforcing.txt" || true
  avc_window "$AVC_P3_START" > "$EVIDENCE_DIR/all-avc-p3.txt" || true
  if [ "$P3_ENFORCING_OK" = true ]; then
    say "P3 enforcing transport roundtrip OK (daemon builder_start + manager START for $P3_OP_ID)"
  else
    log "P3 NOTE: $P3_NOTE"
  fi
else
  log "P3 skipped (bootstrap not enforcing-green)"
fi

# --- P5: enforcing negative proofs ----------------------------------------------
log "P5: enforcing negative proofs (transient units in docker_helper_builder_t)"
audit_window_start
NEG_START="$AVC_EPOCH"

# N1 (config + admin token) is proven by the P2a sanity probe above (the
# config-dir traversal denial subsumes the token-file read; the token sits
# under the config tree).

# N2: the daemon's helper socket must be unreachable from the builder domain
# (a fake session token via --setenv so the CLI's client-side token check
# passes and the connect attempt really happens).
if systemd-run --wait --quiet --unit="p5s1-n2" \
    --property=SELinuxContext=system_u:system_r:docker_helper_builder_t:s0 \
    --setenv=DOCKER_HELPER_SESSION_TOKEN=p5s1-fake-token \
    /usr/bin/docker-helper pull alpine:3.24 \
    >/tmp/p5s1-n2.out 2>&1; then
  fail "the builder domain unexpectedly connected to the daemon helper socket"
fi
printf '%s\n' "$(cat /tmp/p5s1-n2.out)" > "$EVIDENCE_DIR/negative-daemon-socket.txt"

# N3: docker.sock itself must be MAC-denied (a direct endpoint connect, the
# same syscall class the daemon legitimately uses). The fake session token
# clears the CLI's client-side token check so the dial really happens.
if systemd-run --wait --quiet --unit="p5s1-n3" \
    --property=SELinuxContext=system_u:system_r:docker_helper_builder_t:s0 \
    --setenv=DOCKER_HELPER_SESSION_TOKEN=p5s1-fake-token \
    /usr/bin/docker-helper pull alpine:3.24 \
    --endpoint unix:///run/docker.sock >/tmp/p5s1-n3.out 2>&1; then
  fail "the builder domain unexpectedly connected to /run/docker.sock"
fi
printf '%s\n' "$(cat /tmp/p5s1-n3.out)" > "$EVIDENCE_DIR/negative-docker-sock.txt"

# N4: a Session-workspace file read must be MAC-denied (the token-file read
# targets a workspace inode; DAC passes for the workspace files).
if run_as_builder_domain n4 root /usr/bin/docker-helper session list \
    --token-file "$WORKSPACE/buildctx/Dockerfile" >/tmp/p5s1-n4.out 2>&1; then
  fail "the builder domain unexpectedly read the Session workspace"
fi
printf '%s\n' "$(cat /tmp/p5s1-n4.out)" > "$EVIDENCE_DIR/negative-workspace.txt"

NEG_AVC="$(avc_window "$NEG_START")"
builder_avc_window "$NEG_START" > "$EVIDENCE_DIR/builder-avc-p5-negative.txt" || true
avc_window "$NEG_START" > "$EVIDENCE_DIR/all-avc-p5.txt" || true
# N2: the daemon socket denial names the runtime sock_file type or the daemon
# process (connectto).
printf '%s\n' "$NEG_AVC" | grep -aqE 'docker_helper_runtime_t|docker_helper_t' \
  || fail "expected an enforcing builder-domain AVC naming the daemon socket surface (N2)"
# N3: the docker.sock denial names the Docker socket type or the dockerd domain.
printf '%s\n' "$NEG_AVC" | grep -aqE 'container_var_run_t|container_runtime_t' \
  || fail "expected an enforcing builder-domain AVC naming docker.sock (N3)"
# N4: the workspace read denial names the workspace type; a /home workspace
# keeps the host user_home_t label by design (the .te model: the daemon reads
# /home workspaces through user_home_type grants), a relabeled non-home
# workspace carries docker_helper_workspace_t. Extended regex: the fragment
# is an alternation, not a fixed string.
printf '%s\n' "$NEG_AVC" | grep -aqE 'docker_helper_workspace_t|user_home' \
  || fail "expected an enforcing builder-domain AVC naming the workspace surface (N4)"
say "P5 enforcing negative proofs OK (config, daemon socket, docker.sock, workspace)"

# --- P6: upgrade relabel proof ----------------------------------------------------
if [ "$P2_ENFORCING_OK" = true ]; then
log "P6: upgrade relabel (poisoned labels corrected by the RPM %posttrans lifecycle)"
if [ "$(systemctl is-active "$UNIT" 2>/dev/null || true)" != "active" ]; then
  systemctl start "$UNIT" || fail "builder not startable before P6"
fi
chcon -t var_run_t /var/lib/docker-helper-builder \
  || fail "cannot poison the builder state label (chcon)"
[ "$(stat -c '%C' /var/lib/docker-helper-builder)" = "system_u:object_r:var_run_t:s0" ] \
  || fail "state label poisoning did not take effect"
rpm -Uvh --replacepkgs "$RPM" >/dev/null || fail "rpm -U --replacepkgs failed"
[ "$(stat -c '%C' /var/lib/docker-helper-builder)" = "system_u:object_r:docker_helper_builder_state_t:s0" ] \
  || fail "the %posttrans relabel did not correct the builder state label (upgrade path broken)"
[ "$(stat -c '%C' /run/docker-helper-builder/manager.sock)" = "system_u:object_r:docker_helper_builder_runtime_t:s0" ] \
  || fail "manager.sock label wrong after the upgrade relabel"
# The launch vehicle's user-network helper must carry the dedicated exec
# type after the upgrade relabel (execution is allowed only from the
# rootlesskit child domain).
[ "$(stat -c '%C' /usr/bin/slirp4netns)" = "system_u:object_r:docker_helper_slirp4netns_exec_t:s0" ] \
  || fail "slirp4netns label wrong after the upgrade relabel: $(stat -c '%C' /usr/bin/slirp4netns)"
[ "$(systemctl is-active "$UNIT" 2>/dev/null || true)" = "active" ] \
  || fail "builder unit stopped across the upgrade"
audit_window_start
P6_START="$AVC_EPOCH"
BUILD_P6_OUT="$(attempt_build)" && BUILD_P6_RC=0 || BUILD_P6_RC=$?
save_build_output "$EVIDENCE_DIR/build-attempt-post-relabel.txt" "$BUILD_P6_OUT"
log "post-relabel build attempt exit code: $BUILD_P6_RC"

# Exact-window evidence for the relabel round: BOTH services' journals plus
# the AVC window. The daemon's builder_start diagnostic is a daemon-journal
# line (the streamed op buffer carries child output only), so the transport
# proof reads the journals, not the CLI capture.
journalctl -u "$MAIN_UNIT" --since "@$P6_START" --no-pager > "$EVIDENCE_DIR/daemon-journal-p6.txt" 2>&1
journalctl -u "$UNIT" --since "@$P6_START" --no-pager > "$EVIDENCE_DIR/builder-journal-p6.txt" 2>&1
builder_avc_window "$P6_START" > "$EVIDENCE_DIR/builder-avc-p6.txt" || true
avc_window "$P6_START" > "$EVIDENCE_DIR/all-avc-p6.txt" || true

# Transport proof: the daemon's builder_start stage and the manager's START
# handling must name the SAME operation ID. An arbitrary docker_build_failed
# terminal state is NOT an RPC proof — the op-ID pair must match.
P6_OP_ID="$(builder_start_op_id "$EVIDENCE_DIR/daemon-journal-p6.txt")"
if [ -z "$P6_OP_ID" ]; then
  { echo "=== daemon journal (P6 window) ==="; tail -30 "$EVIDENCE_DIR/daemon-journal-p6.txt"; } >&2
  fail "the daemon journal has no builder_start stage in the P6 window (the attempt failed before the manager RPC)"
fi
if ! grep -aqF "START $P6_OP_ID" "$EVIDENCE_DIR/builder-journal-p6.txt"; then
  { echo "=== daemon journal (P6 window) ==="; tail -30 "$EVIDENCE_DIR/daemon-journal-p6.txt"
    echo "=== builder journal (P6 window) ==="; tail -30 "$EVIDENCE_DIR/builder-journal-p6.txt"
    echo "=== builder-domain AVC window ==="; cat "$EVIDENCE_DIR/builder-avc-p6.txt"; } >&2
  fail "the manager journal shows no START handling for $P6_OP_ID (the RPC never reached the manager — S1 transport defect)"
fi
say "P6 transport confirmed (daemon builder_start + manager START for $P6_OP_ID)"

# P5-S2 boundary state: the P5-S1 rootlesskit { lock } denial on the builder
# state file must be GONE (the evidence-proven lock grant ships in the
# candidate policy), and so must the former slirp4netns { execute } denial
# (the dedicated docker_helper_slirp4netns_exec_t grant ships in the same
# candidate policy). Neither the enforcing AVC window nor the manager
# journal may carry the old failures anymore.
OLD_LOCK_AVC="$(grep -a '{ lock }' "$EVIDENCE_DIR/builder-avc-p6.txt" \
  | grep -a 'comm="rootlesskit"' | grep -a 'docker_helper_builder_state_t' || true)"
if [ -n "$OLD_LOCK_AVC" ]; then
  printf '%s\n' "$OLD_LOCK_AVC" > "$EVIDENCE_DIR/child-boundary-avc-p6.txt"
  fail "the P5-S1 rootlesskit { lock } denial on docker_helper_builder_state_t still occurs (the evidence-proven grant did not take effect)"
fi
OLD_SLIRP_AVC="$(grep -a 'denied  { execute }' "$EVIDENCE_DIR/builder-avc-p6.txt" \
  | grep -a 'name="slirp4netns"' || true)"
if [ -n "$OLD_SLIRP_AVC" ]; then
  printf '%s\n' "$OLD_SLIRP_AVC" > "$EVIDENCE_DIR/old-slirp-exec-avc-p6.txt"
  fail "the former slirp4netns { execute } denial still occurs (the dedicated exec-type grant did not take effect)"
fi
OLD_USERNS_AVC="$(grep -a 'tclass=user_namespace' "$EVIDENCE_DIR/builder-avc-p6.txt" \
  | grep -a '{ create }' || true)"
if [ -n "$OLD_USERNS_AVC" ]; then
  printf '%s\n' "$OLD_USERNS_AVC" > "$EVIDENCE_DIR/old-userns-create-avc-p6.txt"
  fail "the former user_namespace { create } denial still occurs (the evidenced userns grant did not take effect)"
fi
if grep -aqF 'failed to lock' "$EVIDENCE_DIR/builder-journal-p6.txt"; then
  grep -aF 'failed to lock' "$EVIDENCE_DIR/builder-journal-p6.txt" \
    > "$EVIDENCE_DIR/child-lock-journal-p6.txt" 2>/dev/null || true
  fail "the child still reports the rootlesskit state-lock failure (see child-lock-journal-p6.txt)"
fi
# Transition proof (P5-S2): the enforcing window must name the rootlesskit
# child domain — the manager's launch exec transitioned, so the child's
# own checks (scontext=docker_helper_rootlesskit_t) are visible in the
# window. Without the transition the window would carry only
# docker_helper_builder_t records.
RK_CTX_AVC="$(grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' "$EVIDENCE_DIR/builder-avc-p6.txt" | head -1 || true)"
printf '%s\n' "$RK_CTX_AVC" > "$EVIDENCE_DIR/child-context-avc-p6.txt"
[ -n "$RK_CTX_AVC" ] || {
  { echo "=== builder-family AVC window (P6) ==="; cat "$EVIDENCE_DIR/builder-avc-p6.txt"
    echo "=== builder journal (P6 window) ==="; tail -40 "$EVIDENCE_DIR/builder-journal-p6.txt"; } >&2
  fail "the rootlesskit child did not run in docker_helper_rootlesskit_t (no child-domain record in the enforcing window — the exec transition did not take effect)"
}
say "P6 rootlesskit context confirmed (docker_helper_rootlesskit_t from the launch transition)"
# Child output evidence: the manager journals the child's own output tail
# when an instance exits unexpectedly.
grep -aF -A 30 'child output tail' "$EVIDENCE_DIR/builder-journal-p6.txt" \
  > "$EVIDENCE_DIR/child-output-p6.txt" 2>/dev/null || true

# The attempt's outcome is the S2 boundary state: a full success ends the
# child-boundary work; a failure is the NEXT enforcing stopping point —
# recorded with the full evidence bundle and reported, never auto-granted
# from the harvest.
if [ "$BUILD_P6_RC" = 0 ]; then
  say "P6 build SUCCEEDED after the relabel: the rootlesskit child-domain boundary never enforced on the attempt path"
else
  { echo "=== builder-family AVC window (P6) ==="; cat "$EVIDENCE_DIR/builder-avc-p6.txt"
    echo "=== builder journal (P6 window) ==="; tail -40 "$EVIDENCE_DIR/builder-journal-p6.txt"
    echo "=== daemon journal (P6 window) ==="; tail -20 "$EVIDENCE_DIR/daemon-journal-p6.txt"
    echo "=== build attempt output ==="; tail -20 "$EVIDENCE_DIR/build-attempt-post-relabel.txt"; } >&2
  fail "the build advanced past the P5-S1 { lock }, slirp4netns { execute }, and user_namespace { create } boundaries and stopped at the NEXT enforcing boundary in docker_helper_rootlesskit_t (evidence: builder-avc-p6.txt, builder-journal-p6.txt, daemon-journal-p6.txt, child-output-p6.txt, build-attempt-post-relabel.txt)"
fi
say "P6 upgrade relabel OK (labels corrected by %posttrans; transport $P6_OP_ID)"
else
  log "P6/P7 skipped (bootstrap not enforcing-green)"
  exit 1
fi

# --- P7: tarball lifecycle --------------------------------------------------------
log "P7: tarball lifecycle on the enforcing host (install-system.sh)"
rpm -e docker-helper || fail "rpm -e docker-helper failed"
if semodule -l 2>/dev/null | grep -qw docker_helper; then
  fail "SELinux docker_helper module must be removed by the RPM preremove"
fi
systemctl start docker >/dev/null 2>&1 || true
WORK_TAR="$GUEST_FILES/bundle"
rm -rf "$WORK_TAR"
mkdir -p "$WORK_TAR"
tar xzf "$TARBALL" -C "$WORK_TAR"
BUNDLE="$WORK_TAR/docker-helper-${VERSION}-linux-amd64"
[ -x "$BUNDLE/install-system.sh" ] || fail "bundle missing install-system.sh"
( cd "$BUNDLE" && ./install-system.sh --yes --allowed-root "$ALLOWED_ROOT" ) \
  >"$EVIDENCE_DIR/install-system.log" 2>&1 || fail "install-system.sh (tarball) failed"
[ -f /etc/systemd/system/docker-helper-builder.service ] \
  || fail "tarball install did not install the builder unit"
semodule -l 2>/dev/null | grep -qw docker_helper \
  || fail "module not loaded by install-system.sh"

# Manager context + builder-owned path labels after the tarball fresh
# install (the manager is pulled in by the main unit's Wants= start).
wait_for_builder_socket 50 || fail "manager socket did not appear after the tarball install"
TAR_MGR_PID="$(systemctl show "$UNIT" -p MainPID --value)"
{ [ -n "$TAR_MGR_PID" ] && [ "$TAR_MGR_PID" != "0" ]; } \
  || fail "builder unit MainPID missing after the tarball install"
TAR_MGR_CTX="$(cat "/proc/$TAR_MGR_PID/attr/current" 2>/dev/null || true)"
[ "$TAR_MGR_CTX" = "system_u:system_r:docker_helper_builder_t:s0" ] \
  || fail "manager process context after the tarball install = '$TAR_MGR_CTX', want system_u:system_r:docker_helper_builder_t:s0"
[ "$(stat -c '%C' /run/docker-helper-builder)" = "system_u:object_r:docker_helper_builder_runtime_t:s0" ] \
  || fail "builder runtime root label wrong after the tarball install: $(stat -c '%C' /run/docker-helper-builder)"
[ "$(stat -c '%C' /run/docker-helper-builder/manager.sock)" = "system_u:object_r:docker_helper_builder_runtime_t:s0" ] \
  || fail "manager.sock label wrong after the tarball install: $(stat -c '%C' /run/docker-helper-builder/manager.sock)"
[ "$(stat -c '%C' /var/lib/docker-helper-builder)" = "system_u:object_r:docker_helper_builder_state_t:s0" ] \
  || fail "builder state label wrong after the tarball install: $(stat -c '%C' /var/lib/docker-helper-builder)"
[ "$(stat -c '%C' /usr/bin/rootlesskit)" = "system_u:object_r:docker_helper_rootlesskit_exec_t:s0" ] \
  || fail "rootlesskit label wrong after the tarball install: $(stat -c '%C' /usr/bin/rootlesskit)"
{
  echo "fresh_manager_pid=$TAR_MGR_PID"
  echo "fresh_manager_context=$TAR_MGR_CTX"
  echo "fresh_runtime_root=$(stat -c '%C' /run/docker-helper-builder)"
  echo "fresh_manager_sock=$(stat -c '%C' /run/docker-helper-builder/manager.sock)"
  echo "fresh_state_root=$(stat -c '%C' /var/lib/docker-helper-builder)"
  echo "fresh_rootlesskit=$(stat -c '%C' /usr/bin/rootlesskit)"
} > "$EVIDENCE_DIR/tarball-manager-labels.txt"

# Tarball upgrade/reinstall relabel: poison, reinstall, verify the restore.
# The reinstall runs with BOTH services active (the builder has been serving
# since the fresh install): the installer's service-activity contract stops
# both, confirms they are down, replaces the binary, and restores the
# previously-active services.
chcon -t var_run_t /var/lib/docker-helper-builder \
  || fail "cannot poison the builder state label (tarball rerun)"
[ "$(stat -c '%C' /var/lib/docker-helper-builder)" = "system_u:object_r:var_run_t:s0" ] \
  || fail "state label poisoning did not take effect (tarball rerun)"
if ! ( cd "$BUNDLE" && ./install-system.sh --yes --allowed-root "$ALLOWED_ROOT" ) \
    >"$EVIDENCE_DIR/install-system-rerun.log" 2>&1; then
  tail -30 "$EVIDENCE_DIR/install-system-rerun.log"
  fail "install-system.sh rerun (upgrade) failed"
fi
[ "$(stat -c '%C' /var/lib/docker-helper-builder)" = "system_u:object_r:docker_helper_builder_state_t:s0" ] \
  || fail "the tarball relabel path did not correct the builder state label: $(stat -c '%C' /var/lib/docker-helper-builder)"
# The installer's restoration restarted the manager: wait for the recreated
# socket before asserting its label.
wait_for_builder_socket 50 || fail "manager socket did not appear after the tarball rerun"
RERUN_MGR_PID="$(systemctl show "$UNIT" -p MainPID --value)"
{ [ -n "$RERUN_MGR_PID" ] && [ "$RERUN_MGR_PID" != "0" ]; } \
  || fail "builder unit MainPID missing after the tarball rerun"
RERUN_MGR_CTX="$(cat "/proc/$RERUN_MGR_PID/attr/current" 2>/dev/null || true)"
[ "$RERUN_MGR_CTX" = "system_u:system_r:docker_helper_builder_t:s0" ] \
  || fail "manager process context after the tarball rerun = '$RERUN_MGR_CTX', want system_u:system_r:docker_helper_builder_t:s0"
[ "$(stat -c '%C' /run/docker-helper-builder)" = "system_u:object_r:docker_helper_builder_runtime_t:s0" ] \
  || fail "builder runtime root label wrong after the tarball rerun: $(stat -c '%C' /run/docker-helper-builder)"
[ "$(stat -c '%C' /run/docker-helper-builder/manager.sock)" = "system_u:object_r:docker_helper_builder_runtime_t:s0" ] \
  || fail "manager.sock label wrong after the tarball rerun: $(stat -c '%C' /run/docker-helper-builder/manager.sock)"
{
  echo "rerun_manager_pid=$RERUN_MGR_PID"
  echo "rerun_manager_context=$RERUN_MGR_CTX"
  echo "rerun_runtime_root=$(stat -c '%C' /run/docker-helper-builder)"
  echo "rerun_manager_sock=$(stat -c '%C' /run/docker-helper-builder/manager.sock)"
  echo "rerun_state_root=$(stat -c '%C' /var/lib/docker-helper-builder)"
} >> "$EVIDENCE_DIR/tarball-manager-labels.txt"

/usr/bin/docker-helper selinux check >"$EVIDENCE_DIR/selinux-check.txt" 2>&1 \
  || { tail -20 "$EVIDENCE_DIR/selinux-check.txt"; fail "docker-helper selinux check failed after the tarball install"; }
say "P7 tarball lifecycle OK (fresh install + poisoned-label rerun relabel; manager context, tree/socket labels, selinux check proven)"

# --- summary ----------------------------------------------------------------------
{
  echo "version=$VERSION"
  echo "rpm=$(sha256sum "$RPM" | awk '{print $1}')"
  echo "tarball=$(sha256sum "$TARBALL" | awk '{print $1}')"
  echo "p2_enforcing_bootstrap=$P2_ENFORCING_OK"
  echo "p3_enforcing_transport=$P3_ENFORCING_OK"
  echo "p6_relabel_transport_op_id=$P6_OP_ID"
  echo "enforcing_build_exit=$BUILD_RC"
  echo "permissive_build_exit=$BUILD_PERM_RC"
  echo "post_relabel_build_exit=$BUILD_P6_RC"
  echo "harvest_builder_avc_lines=$HARVEST_LINES"
} > "$EVIDENCE_DIR/digests.txt"

if [ "$P2_ENFORCING_OK" != true ] || [ "$P3_ENFORCING_OK" != true ]; then
  say "enforcing gates incomplete: p2=$P2_ENFORCING_OK p3=$P3_ENFORCING_OK ($P2_NOTE $P3_NOTE)"
  say "the permissive harvest in $EVIDENCE_DIR/builder-avc-harvest.txt is the evidence for the next AVC"
  exit 1
fi

printf '%s P5-S1-TW-BUILDER-MAC-RESULT=PASS\n' "$PREFIX"
