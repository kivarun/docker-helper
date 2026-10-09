#!/usr/bin/env bash
#
# uat-diag-selinux-utab-dontaudit.sh — disposable-VM diagnostic for the utab
# writability-probe suppression (dontaudit docker_helper_t mount_var_run_t:file
# write). Runs INSIDE the enforcing SELinux guest, as root, against the exact
# candidate RPM state the VM already has.
#
# The shipped policy deliberately does NOT grant mount_var_run_t:file write:
# the Step-7 experiment (branch diag/ro-selinux-utab-write, run 37832314572)
# proved the denied { write } (comm="mount", name=utab, run 37784360967) is
# libmount's writability probe (try_write(): eaccess(R_OK|W_OK)) and that the
# bindfs projection mount produces no utab entry at all (no userspace mount
# options). The shipped policy suppresses the recurring probe record with a
# dontaudit. This diagnostic proves the suppression's boundary on the live
# enforcing system by toggling the policy INSIDE this disposable VM only:
#
#   Phase A (shipped policy, dontaudit loaded):
#     one fresh RO canary -> NO utab AVC in the phase window, the run exits 0
#     and reads the marker through the bindfs projection, utab unchanged.
#   Phase B (semodule -DB: dontaudit rules disabled by a policy rebuild):
#     the same canary -> the ORIGINAL utab write-probe AVC is visible again,
#     the run still exits 0 and reads the marker (the denial never blocked
#     the projection), utab unchanged.
#   Phase C (semodule -B: normal rebuild):
#     the dontaudit rule is restored (sesearch + the exported CIL file), and
#     a third canary is AVC-silent again.
#
# Audit-window isolation is mandatory: each phase owns a bounded window
# (epoch marker -> collection immediately after the phase's canary); the
# diagnostic AVCs of phase B must never leak into any acceptance S13
# accounting. The caller (scripts/uat-vm-opensuse-selinux.sh) runs this
# diagnostic as its own stage BEFORE the workload acceptance, whose audit
# window starts afterwards.
#
# Guaranteed restore: the EXIT trap always rebuilds the policy (semodule -B)
# and verifies the restored dontaudit + allow set; a failed restore is a
# hard failure. The utab fixture is created only when absent (policy-default
# label, one inert foreign record) and removed on restore; a pre-existing
# utab is byte-compared against a real file copy (Bash command substitution
# strips trailing newlines, so byte-exactness is decided on files — with the
# cmp-free files_identical primitive, because cmp is absent from the minimal
# guest image).
#
# Required output fields (printed verbatim): UTABDIAG_DONTAUDIT_LOADED=,
# UTABDIAG_PROBE_AVC_SUPPRESSED=, UTABDIAG_PROBE_AVC_VISIBLE_DB=,
# UTABDIAG_DONTAUDIT_RESTORED=, UTABDIAG_RESULT=.
#
# Env inputs:
#   UAT_RPM          guest path of the exact candidate RPM (required)
#   UAT_RPM_SHA256   expected SHA-256 of the candidate RPM (required)

set -uo pipefail

PREFIX="[utab-diag]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }
info() { printf '%s %s\n' "$PREFIX" "$*"; }
# The MAC adapter's preflight/confinement helpers report through fail_uat.
fail_uat() {
  printf '\n%s FAILED: %s\n' "$PREFIX" "$1" >&2
  exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"
# shellcheck source=scripts/uat-mac-selinux.sh
source "$SCRIPT_DIR/uat-mac-selinux.sh"

UAT_RPM="${UAT_RPM:-}"
UAT_RPM_SHA256="${UAT_RPM_SHA256:-}"
[ -n "$UAT_RPM" ] && [ -f "$UAT_RPM" ] || { echo "error: UAT_RPM must be an existing file: $UAT_RPM" >&2; exit 1; }
[ -n "$UAT_RPM_SHA256" ] || { echo "error: UAT_RPM_SHA256 is required" >&2; exit 1; }
ACTUAL_SHA="$(sha256sum "$UAT_RPM" | awk '{print $1}')"
[ "$ACTUAL_SHA" = "$UAT_RPM_SHA256" ] || {
  echo "error: candidate RPM SHA-256 mismatch (expected $UAT_RPM_SHA256, got $ACTUAL_SHA)" >&2
  exit 1
}
[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
[ "$(getenforce 2>/dev/null || true)" = "Enforcing" ] || { echo "error: SELinux not enforcing" >&2; exit 1; }

PRINCIPAL="opc"
WS="/home/opc/uat-utab-diag"
IMAGE="alpine:3.24"
UTAB=/run/mount/utab
# wait_service_health (the shared readiness owner) contract: callers set the
# systemd unit and the API socket. The usage lives inside the sourced lib,
# which shellcheck cannot resolve here.
# shellcheck disable=SC2034
SERVICE="docker-helper.service"
# shellcheck disable=SC2034
SOCK="/run/docker-helper/docker-helper.sock"
UTAB_DIAG_CREATED=0
UTAB_DIAG_DIR_CREATED=0
UTAB_DIAG_FOREIGN_LINE='ID=4242 UNIQID=20990101 SRC=/uat-utab-diag-foreign-src TARGET=/uat-utab-diag-foreign-target OPTS=foreign-opt'
FAILURES=""

diag_fail() { FAILURES="$FAILURES $1"; info "FAIL: $1" >&2; }
diag_ok()   { info "ok: $*"; }

# utab_snapshot_copy TARGET COPY — byte-exact snapshot of the utab state:
# a real file copy when present, a marker file when absent. Returns 0.
utab_snapshot_copy() {
  local target="$1" copy="$2"
  rm -f "$copy"
  if [ -e "$target" ]; then
    cp -p "$target" "$copy" || return 1
    printf 'present' > "$copy.state"
  else
    printf 'absent' > "$copy.state"
  fi
  return 0
}

# files_identical compares two files byte-for-byte WITHOUT depending on cmp
# (absent from the minimal openSUSE Tumbleweed cloud image — the same reason
# scripts/uat-install-tarball.sh owns this primitive: sha256sum is guaranteed
# (coreutils) and is already the UAT's canonical integrity primitive). The
# byte-exactness is still decided on the REAL FILE COPIES, never on captured
# strings (Bash command substitution strips trailing newlines).
files_identical() {
  local a="$1" b="$2"
  [ "$(sha256sum "$a" | awk '{print $1}')" = "$(sha256sum "$b" | awk '{print $1}')" ]
}

# utab_unchanged TARGET COPY — true when the current utab state is byte-exact
# the snapshotted one (files_identical on the real files; presence compared
# via the state marker).
utab_unchanged() {
  local target="$1" copy="$2" was
  was="$(cat "$copy.state" 2>/dev/null || true)"
  if [ "$was" = "present" ]; then
    [ -e "$target" ] || return 1
    files_identical "$copy" "$target"
  else
    [ ! -e "$target" ]
  fi
}

# utab_diag_residue — fail-closed helper-owned residue inventory (the shared
# lib primitives): exit 0 = clean (0/0/0), 1 = residue, 2 = inventory
# unavailable (never "clean").
utab_diag_residue() {
  local c p w
  c="$(helper_container_count)" || return 2
  p="$(inventory_count /run/docker-helper/mounts)" || return 2
  w="$(inventory_count /run/docker-helper/workload-mac)" || return 2
  [ "$c" = "0" ] && [ "$p" = "0" ] && [ "$w" = "0" ]
}

# utab_diag_canary PHASE — one fresh RO canary through the production CLI:
# fresh session, marker read through the bindfs projection, exit code. Prints
# CANARY_EXIT=<rc>. The session is deleted before returning.
utab_diag_canary() {
  local phase="$1" sid token json ec
  json="$(docker-helper session create --token-file "$UTAB_DIAG_CRED" "$WS" --json 2>&1)" \
    || { echo "error: phase $phase session create failed: $(printf '%s' "$json" | redact | tail -2)" >&2; return 1; }
  sid="$(printf '%s\n' "$json" | json_field id)"
  [ -n "$sid" ] || { echo "error: phase $phase session create returned no id" >&2; return 1; }
  token="$(printf '%s\n' "$json" | json_field token)"
  [ -n "$token" ] || { echo "error: phase $phase session create returned no token" >&2; return 1; }
  DOCKER_HELPER_SESSION_TOKEN="$token" \
    docker-helper run --mount canary-ro:/mnt/canary:ro "$IMAGE" -- \
    sh -ec 'cat /mnt/canary/marker.txt' >/tmp/uat-utab-diag-run.log 2>&1
  ec=$?
  echo "CANARY_EXIT=$ec"
  redact </tmp/uat-utab-diag-run.log 2>/dev/null | sed 's/^/  run: /' || true
  if [ "$(cat /tmp/uat-utab-diag-run.log 2>/dev/null)" != "canary-ro-marker" ]; then
    info "phase $phase: the marker was NOT read cleanly through the projection" >&2
    ec=1
  fi
  docker-helper session delete --token-file "$UTAB_DIAG_CRED" "$sid" >/dev/null 2>&1 || true
  return "$ec"
}

# restore_policy guarantees the VM's final policy state even on early failure:
# rebuild normally only when the dontaudit is missing, then verify the shipped
# boundary is back.
restore_policy() {
  if ! sesearch --dontaudit -s docker_helper_t -t mount_var_run_t 2>/dev/null | grep -q mount_var_run_t; then
    info "restore: dontaudit missing — rebuilding (semodule -B)"
    semodule -B >/dev/null 2>&1 || true
  fi
  if sesearch --dontaudit -s docker_helper_t -t mount_var_run_t 2>/dev/null | grep -q mount_var_run_t \
      && sesearch -A -s docker_helper_t -t mount_var_run_t -c file 2>/dev/null | grep -q "getattr" \
      && ! sesearch -A -s docker_helper_t -t mount_var_run_t 2>/dev/null | grep -qE '\bwrite\b'; then
    info "restore verified: dontaudit present, allow read set unchanged, no write allow"
  else
    echo "error: policy restore FAILED (dontaudit missing or allow set changed)" >&2
    exit 3
  fi
}
trap restore_policy EXIT

say "utab dontaudit boundary diagnostic (disposable-VM policy toggle, isolated windows)"
info "RPM: $UAT_RPM (sha256 verified)"
# The audit-window epoch must exist before mac_preflight prints it (the pin
# regression's canonical call order); the per-phase windows re-record it.
mac_audit_start
mac_preflight

# ---------------------------------------------------------------------------
# service + principal + credential bootstrap (public CLI only)
# ---------------------------------------------------------------------------
systemctl enable --now docker-helper.service >/dev/null 2>&1 || { echo "error: cannot enable+start docker-helper" >&2; exit 1; }
wait_service_health || { echo "error: docker-helper service not healthy" >&2; exit 1; }
DAEMON_PID="$(systemctl show -p MainPID --value docker-helper.service)"
mac_verify_confinement "$DAEMON_PID"

rm -rf "$WS"
mkdir -p "$WS/canary-ro"
printf 'canary-ro-marker\n' > "$WS/canary-ro/marker.txt"
chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
chmod 0755 "$WS" "$WS/canary-ro"

docker-helper principal create --no-credential "$PRINCIPAL" >/dev/null 2>&1 || true
docker-helper principal allowed-root add "$PRINCIPAL" /home/opc >/dev/null 2>&1 || true
launcher_json="$(docker-helper launcher show --principal "$PRINCIPAL" --json 2>/dev/null)" \
  || { echo "error: principal '$PRINCIPAL' has no default Launcher" >&2; exit 1; }
printf '%s\n' "$launcher_json" | grep -q '"name": "default"' \
  || { echo "error: default launcher show returned an unexpected name" >&2; exit 1; }

UTAB_DIAG_CRED="/tmp/uat-utab-diag-cred"
rm -f "$UTAB_DIAG_CRED"
CRED_OUT="$(docker-helper credential create --name "uat-utab-diag-$(date +%s)" "$PRINCIPAL" 2>&1)" \
  || { echo "error: credential create failed: $CRED_OUT" >&2; exit 1; }
CRED_TOKEN="$(printf '%s\n' "$CRED_OUT" | sed -n 's/^  Token: //p' | tr -d '[:space:]')"
[ -n "$CRED_TOKEN" ] || { echo "error: could not parse credential token" >&2; exit 1; }
printf '%s\n' "$CRED_TOKEN" > "$UTAB_DIAG_CRED"
chmod 600 "$UTAB_DIAG_CRED"
CRED_ID="$(printf '%s\n' "$CRED_OUT" | sed -n 's/^  ID:    //p' | tr -d '[:space:]')"

# ---------------------------------------------------------------------------
# utab fixture: created only when absent, with one inert foreign record
# ---------------------------------------------------------------------------
if [ -e "$UTAB" ]; then
  info "utab: PRE-EXISTING (left in place; byte-compared per phase)"
else
  UTAB_DIAG_CREATED=1
  if [ ! -d /run/mount ]; then
    mkdir -p /run/mount && restorecon /run/mount 2>/dev/null || true
    UTAB_DIAG_DIR_CREATED=1
  fi
  printf '%s\n' "$UTAB_DIAG_FOREIGN_LINE" > "$UTAB"
  chmod 644 "$UTAB"
  restorecon "$UTAB" 2>/dev/null || true
  info "utab: ABSENT - created with one inert foreign record ($(stat -c '%A %U:%G %C' "$UTAB" 2>&1))"
fi

# ---------------------------------------------------------------------------
# Phase A: shipped policy (dontaudit loaded) — probe AVC suppressed
# ---------------------------------------------------------------------------
say "Phase A: shipped policy (dontaudit loaded)"
A_DONTAUDIT="$(sesearch --dontaudit -s docker_helper_t -t mount_var_run_t 2>/dev/null | grep -c 'mount_var_run_t' || true)"
[ -n "$A_DONTAUDIT" ] || A_DONTAUDIT=0
if [ "$A_DONTAUDIT" -ge 1 ]; then
  diag_ok "dontaudit rule loaded ($(sesearch --dontaudit -s docker_helper_t -t mount_var_run_t 2>/dev/null | head -1))"
else
  diag_fail "the shipped dontaudit rule is NOT loaded"
fi
echo "UTABDIAG_DONTAUDIT_LOADED=$A_DONTAUDIT"

mac_audit_start
utab_snapshot_copy "$UTAB" /tmp/uat-utab-diag-preA || diag_fail "phase A utab snapshot failed"
A_CANARY="$(utab_diag_canary A)" || diag_fail "phase A canary failed (rc!=0 or marker unreadable)"
echo "$A_CANARY"
sleep 1
A_AVC="$(audit_records 'avc:[[:space:]]+denied' | grep -F 'docker_helper_t' | grep -F 'mount_var_run_t' | grep -F 'tclass=file' | grep -E 'denied[[:space:]]+\{[^}]*\bwrite\b[^}]*\}' || true)"
if [ -z "$A_AVC" ]; then
  diag_ok "no utab write AVC in the phase A window (probe suppressed)"
  echo "UTABDIAG_PROBE_AVC_SUPPRESSED=yes"
else
  diag_fail "an utab write AVC appeared in the phase A window despite the dontaudit: $A_AVC"
  echo "UTABDIAG_PROBE_AVC_SUPPRESSED=no"
fi
utab_unchanged "$UTAB" /tmp/uat-utab-diag-preA \
  && diag_ok "phase A: utab unchanged" \
  || diag_fail "phase A: utab changed"

# ---------------------------------------------------------------------------
# Phase B: semodule -DB — dontaudit rules disabled, the probe AVC visible
# ---------------------------------------------------------------------------
say "Phase B: semodule -DB (dontaudit rules disabled)"
DB_OUT="$(semodule -DB 2>&1)" || diag_fail "semodule -DB failed: $DB_OUT"
B_DONTAUDIT="$(sesearch --dontaudit -s docker_helper_t -t mount_var_run_t 2>/dev/null | grep -c 'mount_var_run_t' || true)"
[ -n "$B_DONTAUDIT" ] || B_DONTAUDIT=0
if [ "$B_DONTAUDIT" -eq 0 ]; then
  diag_ok "dontaudit rules disabled by the -DB rebuild"
else
  diag_fail "dontaudit rules still present after semodule -DB"
fi

mac_audit_start
utab_snapshot_copy "$UTAB" /tmp/uat-utab-diag-preB || diag_fail "phase B utab snapshot failed"
B_CANARY="$(utab_diag_canary B)" || diag_fail "phase B canary failed (rc!=0 or marker unreadable)"
echo "$B_CANARY"
sleep 1
B_AVC="$(audit_records 'avc:[[:space:]]+denied' | grep -F 'docker_helper_t' | grep -F 'mount_var_run_t' | grep -F 'tclass=file' | grep -E 'denied[[:space:]]+\{[^}]*\bwrite\b[^}]*\}' || true)"
if [ -n "$B_AVC" ]; then
  diag_ok "the original utab write-probe AVC is visible again with -DB: $(printf '%s\n' "$B_AVC" | head -1)"
  echo "UTABDIAG_PROBE_AVC_VISIBLE_DB=yes"
else
  diag_fail "the utab write-probe AVC did NOT reappear with the dontaudit disabled"
  echo "UTABDIAG_PROBE_AVC_VISIBLE_DB=no"
fi
utab_unchanged "$UTAB" /tmp/uat-utab-diag-preB \
  && diag_ok "phase B: utab unchanged" \
  || diag_fail "phase B: utab changed"

# ---------------------------------------------------------------------------
# Phase C: semodule -B — dontaudit restored
# ---------------------------------------------------------------------------
say "Phase C: semodule -B (normal rebuild, dontaudit restored)"
B_REBUILD_OUT="$(semodule -B 2>&1)" || diag_fail "semodule -B failed: $B_REBUILD_OUT"
C_DONTAUDIT="$(sesearch --dontaudit -s docker_helper_t -t mount_var_run_t 2>/dev/null | grep -c 'mount_var_run_t' || true)"
[ -n "$C_DONTAUDIT" ] || C_DONTAUDIT=0
if [ "$C_DONTAUDIT" -ge 1 ]; then
  diag_ok "dontaudit rule restored ($(sesearch --dontaudit -s docker_helper_t -t mount_var_run_t 2>/dev/null | head -1))"
  echo "UTABDIAG_DONTAUDIT_RESTORED=yes"
else
  diag_fail "the dontaudit rule was NOT restored by semodule -B"
  echo "UTABDIAG_DONTAUDIT_RESTORED=no"
fi
# The exported CIL must carry the dontaudit as well (compiled parity at the
# module level: semodule -c -E writes the real CIL file into the working
# directory; stdout carries only a status line).
CIL_DIR="$(mktemp -d /tmp/uat-utab-diag-cil.XXXXXX)"
( cd "$CIL_DIR" && semodule -c -E docker_helper ) >"$CIL_DIR/out" 2>"$CIL_DIR/err" || true
if [ -f "$CIL_DIR/docker_helper.cil" ] \
    && grep -E '(dontaudit docker_helper_t mount_var_run_t \(file \(.*write.*\))' "$CIL_DIR/docker_helper.cil"; then
  diag_ok "the exported CIL file carries the dontaudit rule"
else
  diag_fail "the exported CIL file does not carry the dontaudit rule ($(ls -la "$CIL_DIR" 2>&1 | sed 's/^/    /'))"
fi
rm -rf "$CIL_DIR"

mac_audit_start
utab_snapshot_copy "$UTAB" /tmp/uat-utab-diag-preC || diag_fail "phase C utab snapshot failed"
C_CANARY="$(utab_diag_canary C)" || diag_fail "phase C canary failed (rc!=0 or marker unreadable)"
echo "$C_CANARY"
sleep 1
C_AVC="$(audit_records 'avc:[[:space:]]+denied' | grep -F 'docker_helper_t' | grep -F 'mount_var_run_t' | grep -F 'tclass=file' | grep -E 'denied[[:space:]]+\{[^}]*\bwrite\b[^}]*\}' || true)"
if [ -z "$C_AVC" ]; then
  diag_ok "no utab write AVC in the phase C window (restored suppression)"
else
  diag_fail "an utab write AVC appeared in the phase C window after the restore: $C_AVC"
fi
utab_unchanged "$UTAB" /tmp/uat-utab-diag-preC \
  && diag_ok "phase C: utab unchanged" \
  || diag_fail "phase C: utab changed"

# ---------------------------------------------------------------------------
# restore the utab fixture exactly
# ---------------------------------------------------------------------------
if [ "$UTAB_DIAG_CREATED" = 1 ]; then
  rm -f "$UTAB"
  [ "$UTAB_DIAG_DIR_CREATED" = 1 ] && rmdir /run/mount 2>/dev/null || true
  info "restore: diagnostic-created utab removed (pre-existing state restored)"
else
  info "restore: utab was pre-existing - left untouched"
fi
rm -f /tmp/uat-utab-diag-preA /tmp/uat-utab-diag-preA.state \
      /tmp/uat-utab-diag-preB /tmp/uat-utab-diag-preB.state \
      /tmp/uat-utab-diag-preC /tmp/uat-utab-diag-preC.state
# Tidy authorization state: revoke the diagnostic credential (best-effort; the
# disposable VM is disposed anyway).
if [ -n "$CRED_ID" ]; then
  docker-helper credential revoke "$CRED_ID" >/dev/null 2>&1 \
    && info "restore: diagnostic credential $CRED_ID revoked" \
    || info "restore: diagnostic credential revoke unavailable (best-effort; disposable VM)"
fi
if utab_diag_residue; then
  diag_ok "residue clean (containers=0 pins=0 wlmac=0)"
else
  diag_fail "residue not clean or the inventory was unavailable (rc=$?)"
fi

if [ -n "$FAILURES" ]; then
  echo "UTABDIAG_RESULT=FAIL (failures:$FAILURES)"
  echo "error: utab dontaudit boundary diagnostic RED" >&2
  exit 1
fi
echo "UTABDIAG_RESULT=PASS"
say "utab dontaudit boundary diagnostic PASSED (suppression effective, probe visible under -DB, dontaudit restored)"
