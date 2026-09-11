#!/usr/bin/env bash
#
# uat-migration-rpm-211.sh — Release 2.2 migration gate 2.1.1 -> candidate on
# the RPM path, running INSIDE the openSUSE Tumbleweed guests of the artifact
# gate (invoked by scripts/uat-vm-opensuse-apparmor.sh and
# scripts/uat-vm-opensuse-selinux.sh, which own the VM construction, the
# guest transfer of the exact candidate RPM and the pinned v2.1.1 baseline
# RPM, and the baseline SHA binding).
#
# The DEB consumer job (scripts/uat-release2-acceptance.sh scenario M) owns
# the fail-closed migration-refusal case and the no-half-migration state
# proofs (SQLite-level, platform-independent). This script owns the RPM-path
# migration acceptance over real published-v2.1.1 state, upgraded through the
# package manager with the service running (the natural production path):
#   R1  the pinned v2.1.1 baseline RPM verifies and installs (version 2.1.1)
#   R2  real pre-upgrade state through the v2.1.1 CLI: two path-only global
#       roots, two path-only Principal roots, one restricted path-only
#       Launcher root, principal + launcher credentials, two live Sessions
#   R3  zypper-free real rpm -U upgrade to the exact candidate RPM with the
#       service running (packaged restart path); version identity verified
#   R4  legacy path-only config keeps read_write authority while config.json
#       keeps the legacy path-only string form
#   R5  Principal and Launcher roots migrated as read_write
#   R6  both pre-existing Sessions carry the compatibility
#       workspace/read_write snapshot
#   R7  identity preservation: principal credential authority, launcher
#       identity, both Session IDs
#   R8  a real operation of the pre-existing Session keeps the 2.1 writable
#       behavior
#   R9  restart idempotency: policy/snapshots stable, sessions schema final,
#       snapshot table canonical
#
# Fail-closed contract: PASS -> continue; FAIL -> gate red; BLOCKED -> a
# required prerequisite is unavailable -> gate red.
# Exit status: 0 = all PASS, 1 = any FAIL, 2 = any BLOCKED (and none FAIL).
#
# Env inputs (guest paths):
#   UAT_VERSION             candidate version string (required)
#   UAT_RPM                 guest path of the exact candidate RPM (required)
#   UAT_RPM_SHA256          expected SHA-256 of the candidate RPM (required)
#   UAT_BASELINE211_RPM     guest path of the pinned v2.1.1 baseline RPM (required)
#   UAT_BASELINE211_SHA256  expected SHA-256 of the baseline RPM (required)
#   UAT_ALLOWED_ROOT        global allowed root (default /home/opc/uat-mig211-roots)
#
# Requires: root, systemd, Docker, rpm. Exits as above.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Shared measurement primitives only (structural rich allowed-root JSON parse,
# fail-closed residue inventory); the script's own helpers below win.
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

VERSION="${UAT_VERSION:-2.2.0-uat}"
BASELINE_VERSION="2.1.1"
# The migration guest's global allowed root lives under /home. Location does
# not affect the migration semantics under test (path-only policy, ownership,
# credentials, snapshots), but it decides which MAC machinery the v2.1.1
# baseline itself can serve: on an enforcing SELinux host the v2.1.1 policy
# cannot run restorecon for its own non-home fcontext path (captured on
# run 6: "restorecon failed for /opt/...: exit status 255"), so /opt-hosted
# workspaces would make the pre-upgrade session seeding fail for baseline
# limitations unrelated to 2.2 migration behavior. Home workspaces are the
# pre-upgrade state the baseline actually serves on both MAC backends
# (v2.1.1 skips fcontext for /home paths).
ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-/home/opc/uat-mig211-roots}"
RPM_PATH_IN="${UAT_RPM:-}"
RPM_SHA256_IN="${UAT_RPM_SHA256:-}"
BASELINE_RPM_IN="${UAT_BASELINE211_RPM:-}"
BASELINE_SHA_IN="${UAT_BASELINE211_SHA256:-}"

PREFIX="[uat-migration-rpm-211]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }
info() { printf '%s %s\n' "$PREFIX" "$*"; }

redact() {
  sed -E \
    -e 's/dht_[A-Za-z0-9_-]+/<redacted-token>/g' \
    -e 's/dhc_[A-Za-z0-9_-]+/<redacted-token>/g'
}

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
[ -n "$RPM_PATH_IN" ] && [ -f "$RPM_PATH_IN" ] || { echo "error: UAT_RPM must be an existing file: $RPM_PATH_IN" >&2; exit 1; }
[ -n "$RPM_SHA256_IN" ] || { echo "error: UAT_RPM_SHA256 is required" >&2; exit 1; }
CAND_ACTUAL_SHA="$(sha256sum "$RPM_PATH_IN" | awk '{print $1}')"
[ "$CAND_ACTUAL_SHA" = "$RPM_SHA256_IN" ] || {
  echo "error: candidate RPM SHA-256 mismatch (expected $RPM_SHA256_IN, got $CAND_ACTUAL_SHA)" >&2
  exit 1
}
[ -n "$BASELINE_RPM_IN" ] && [ -f "$BASELINE_RPM_IN" ] || { echo "error: UAT_BASELINE211_RPM must be an existing file: $BASELINE_RPM_IN" >&2; exit 1; }
[ -n "$BASELINE_SHA_IN" ] || { echo "error: UAT_BASELINE211_SHA256 is required" >&2; exit 1; }
BASE_ACTUAL_SHA="$(sha256sum "$BASELINE_RPM_IN" | awk '{print $1}')"
[ "$BASE_ACTUAL_SHA" = "$BASELINE_SHA_IN" ] || {
  echo "error: v2.1.1 baseline RPM SHA-256 mismatch (expected $BASELINE_SHA_IN, got $BASE_ACTUAL_SHA)" >&2
  exit 1
}

FAIL_COUNT=0
BLOCKED_COUNT=0
acc_ok() { printf '  ok:   %s\n' "$*"; }
acc_fail() { printf '  FAIL: %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
acc_blocked() { printf '  BLOCKED: %s\n' "$*" >&2; BLOCKED_COUNT=$((BLOCKED_COUNT + 1)); }
# acc_fail_ctx prints the FAIL line plus the first lines of each diagnostic
# capture file. Capture files may contain credential output; redact() masks
# bearer tokens before anything reaches the log.
acc_fail_ctx() { # msg diagfile...
  acc_fail "$1"
  shift
  local f
  for f in "$@"; do
    [ -s "$f" ] && sed -n '1,4p' "$f" | redact | sed 's/^/      | /' >&2
  done
}
scenario() { say "scenario $1"; }

dh() { /usr/bin/docker-helper "$@"; }
SOCK="/run/docker-helper/docker-helper.sock"

json_field() { grep -oP "\"$1\": \"\K[^\"]+" | head -1; }

wait_health() {
  local _i=0
  for _i in $(seq 1 100); do
    curl --silent --fail --max-time 1 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1 && return 0
    if ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
      return 1
    fi
    sleep 0.2
  done
  return 1
}

wait_service_active() {
  local _i=0
  for _i in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && return 0
    sleep 1
  done
  return 1
}

cleanup() {
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  systemctl disable docker-helper.service >/dev/null 2>&1 || true
  rpm -e docker-helper >/dev/null 2>&1 || true
  rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper
}
trap cleanup EXIT

# ==============================================================================
# R1: install the pinned v2.1.1 baseline RPM
# ==============================================================================
scenario "R1: pinned v2.1.1 baseline RPM"
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl disable docker-helper.service >/dev/null 2>&1 || true
rpm -e docker-helper >/dev/null 2>&1 || true
rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper
if rpm -i "$BASELINE_RPM_IN" >/tmp/uat-mig211-install.log 2>&1 \
    && [ "$(docker-helper version)" = "$BASELINE_VERSION" ]; then
  acc_ok "v2.1.1 baseline RPM installed (sha256 verified: $BASE_ACTUAL_SHA)"
else
  acc_blocked "v2.1.1 baseline RPM install/version failed (see /tmp/uat-mig211-install.log)"
fi

# The baseline's own init contract requires the allowed-root directory to
# exist (it is not created implicitly); the /home-based root is created here
# before the baseline validates it.
mkdir -p "$ALLOWED_ROOT" || acc_blocked "cannot create the global allowed root $ALLOWED_ROOT"
if docker-helper init --allowed-root "$ALLOWED_ROOT" >/tmp/uat-mig211-init.log 2>&1; then
  acc_ok "system init on v2.1.1 baseline (path-only global root)"
else
  acc_fail_ctx "system init failed on v2.1.1 baseline" /tmp/uat-mig211-init.log
fi
systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
wait_service_active || acc_fail "v2.1.1 daemon not active (migration gate)"
wait_health || acc_fail "v2.1.1 daemon not healthy (migration gate)"

# ==============================================================================
# R2: seed real pre-upgrade state through the v2.1.1 CLI
# ==============================================================================
scenario "R2: v2.1.1 pre-upgrade state"
# Fresh-window anchor for the self-diagnosing journal capture below: the
# daemon journal also holds session-create failures from earlier guest
# stages, so the capture must be scoped to this scenario's own window.
M_R2_T0="$(date +%s)"
# The migration principal is scenario-owned: v2.1.1 requires the principal's
# OS home to sit under a global allowed root at creation (outside_global_root),
# and the guest's opc SSH user (cloud-init home /home/opc) must not be moved.
# A dedicated user with its home under the global allowed root satisfies the
# baseline's own contract without touching the guest's own user.
M_USER="mig211u"
umask 077
M_DIAG=/tmp/uat-mig211-diag
rm -rf "$M_DIAG"; mkdir -p "$M_DIAG"
umask 022
if ! getent passwd "$M_USER" >/dev/null 2>&1; then
  mkdir -p "$ALLOWED_ROOT/mig211-home"
  if useradd -m -d "$ALLOWED_ROOT/mig211-home" "$M_USER" >"$M_DIAG/useradd.out" 2>&1; then
    acc_ok "OS user for principal seeding created ($M_USER, home under the global root)"
  else
    acc_blocked "cannot create OS user $M_USER (useradd failed): $(redact <"$M_DIAG/useradd.out" | head -2)"
  fi
fi
M_HOME="$(getent passwd "$M_USER" | cut -d: -f6)"
M_POLICY="$M_HOME/uat-mig211-policy"
mkdir -p "$M_HOME/ws" "$M_POLICY/sub/ws"
printf 'mig-input\n' > "$M_POLICY/sub/ws/input.txt"
chown -R "$M_USER:$M_USER" "$M_POLICY" "$M_HOME/ws" >"$M_DIAG/chown.out" 2>&1 || true
dh config allowed-root add "$M_POLICY" >"$M_DIAG/gadd.out" 2>&1
if dh config allowed-root list 2>/dev/null | grep -qx "$M_POLICY" \
    && dh config allowed-root list 2>/dev/null | grep -qx "$ALLOWED_ROOT"; then
  acc_ok "R2 two path-only global roots seeded"
else
  acc_fail_ctx "R2 global allowed-root seeding failed" "$M_DIAG/gadd.out"
fi

dh principal create --system --no-credential "$M_USER" >"$M_DIAG/pcreate.out" 2>&1 || true
dh principal set --system "$M_USER" enabled true >"$M_DIAG/pset.out" 2>&1 || true
dh principal allowed-root add --system "$M_USER" "$ALLOWED_ROOT" >"$M_DIAG/padd1.out" 2>&1 || true
dh principal allowed-root add --system "$M_USER" "$M_POLICY" >"$M_DIAG/padd2.out" 2>&1 || true
if dh principal allowed-root list --system "$M_USER" 2>"$M_DIAG/plist.err" | grep -qx "$M_POLICY" \
    && dh principal allowed-root list --system "$M_USER" 2>/dev/null | grep -qx "$ALLOWED_ROOT"; then
  acc_ok "R2 two path-only Principal roots seeded"
else
  acc_fail_ctx "R2 Principal allowed-root seeding failed" "$M_DIAG/pcreate.out" "$M_DIAG/padd2.out" "$M_DIAG/plist.err"
fi

dh credential create --system --name mig211 "$M_USER" >"$M_DIAG/pcred.out" 2>&1 || true
M_P_CRED_OUT="$(cat "$M_DIAG/pcred.out")"
M_P_TOKEN="$(printf '%s\n' "$M_P_CRED_OUT" | sed -n 's/^  Token: //p' | tr -d '[:space:]')"
if [ -n "$M_P_TOKEN" ]; then
  printf '%s\n' "$M_P_TOKEN" > /tmp/uat-mig211-pc.tok; chmod 600 /tmp/uat-mig211-pc.tok
  acc_ok "R2 principal credential issued"
else
  acc_fail_ctx "R2 principal credential issuance failed" "$M_DIAG/pcred.out"
fi

dh launcher create --system --principal "$M_USER" --name mlaunch \
  --allowed-root "$M_POLICY/sub" --no-credential >"$M_DIAG/lcreate.out" 2>&1 || true
M_L_OUT="$(cat "$M_DIAG/lcreate.out")"
M_L_ID="$(printf '%s\n' "$M_L_OUT" | json_field id)"
if [ -n "$M_L_ID" ] \
    && dh launcher allowed-root list --system --principal "$M_USER" "$M_L_ID" 2>"$M_DIAG/llist.err" | grep -qx "$M_POLICY/sub"; then
  acc_ok "R2 restricted path-only Launcher root seeded ($M_L_ID)"
else
  acc_fail_ctx "R2 restricted Launcher root seeding failed" "$M_DIAG/lcreate.out" "$M_DIAG/llist.err"
fi
dh launcher credential create --system --principal "$M_USER" "$M_L_ID" >"$M_DIAG/lcred.out" 2>&1 || true
M_LC_OUT="$(cat "$M_DIAG/lcred.out")"
M_LC_TOKEN="$(printf '%s\n' "$M_LC_OUT" | json_field token)"
if [ -n "$M_LC_TOKEN" ]; then
  printf '%s\n' "$M_LC_TOKEN" > /tmp/uat-mig211-lc.tok; chmod 600 /tmp/uat-mig211-lc.tok
  acc_ok "R2 launcher credential issued"
else
  acc_fail_ctx "R2 launcher credential issuance failed" "$M_DIAG/lcred.out"
fi

M_S1_JSON="$(dh session create --system --token-file /tmp/uat-mig211-lc.tok --workspace "$M_POLICY/sub/ws" --json 2>"$M_DIAG/s1.err" || true)"
M_S1_ID="$(printf '%s' "$M_S1_JSON" | json_field id)"
M_S1_TOKEN="$(printf '%s' "$M_S1_JSON" | json_field token)"
M_S2_JSON="$(dh session create --system --token-file /tmp/uat-mig211-pc.tok --workspace "$M_HOME/ws" --json 2>"$M_DIAG/s2.err" || true)"
M_S2_ID="$(printf '%s' "$M_S2_JSON" | json_field id)"
if [ -n "$M_S1_ID" ] && [ -n "$M_S2_ID" ]; then
  acc_ok "R2 live Sessions seeded (launcher=$M_S1_ID principal=$M_S2_ID)"
else
  # Self-diagnosing capture: the v2.1.1 daemon answers a failed create with
  # the generic 500 internal_error, but names the internal cause in its
  # operational log ("session creation error"); the loaded policy module and
  # the workspace labels pin down which MAC path the baseline exercised.
  # Scoped to this scenario's fresh window (M_R2_T0) so stale entries from
  # earlier guest stages cannot shadow the actual R2 failure lines.
  journalctl -u docker-helper.service --no-pager -o cat --since "@$M_R2_T0" \
    2>"$M_DIAG/journal.err" | grep -E 'session creation' | tail -4 \
    >"$M_DIAG/daemon-journal.txt" || true
  {
    semodule -l 2>&1 | grep -w docker_helper || echo "(docker_helper module not loaded)"
    getenforce 2>&1 || true
    ls -Zd "$M_HOME" "$M_HOME/ws" "$M_POLICY/sub/ws" 2>&1 || true
  } >"$M_DIAG/sel-state.txt" 2>&1
  acc_fail_ctx "R2 Session seeding failed (launcher: '$M_S1_ID', principal: '$M_S2_ID')" \
    "$M_DIAG/s1.err" "$M_DIAG/s2.err" "$M_DIAG/daemon-journal.txt" "$M_DIAG/sel-state.txt"
fi

M_CONFIG_SHA="$(sha256sum /etc/docker-helper/config.json | awk '{print $1}')"
M_AUTH_PRE_HTTP="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
  --unix-socket "$SOCK" -H "Authorization: Bearer $M_P_TOKEN" http://localhost/auth 2>/dev/null || true)"
[ "$M_AUTH_PRE_HTTP" = 200 ] \
  && acc_ok "pre-upgrade principal credential authenticates on v2.1.1" \
  || acc_fail "pre-upgrade principal credential broken on v2.1.1 (http=$M_AUTH_PRE_HTTP)"

# ==============================================================================
# R3: real rpm -U upgrade to the exact candidate with the service running
# ==============================================================================
scenario "R3: rpm -U upgrade to the candidate (packaged restart path)"
if rpm -Uvh "$RPM_PATH_IN" >/tmp/uat-mig211-upgrade.log 2>&1 \
    && [ "$(docker-helper version)" = "$VERSION" ]; then
  acc_ok "R3 upgraded to candidate RPM ($VERSION) with the service running"
else
  acc_fail "R3 candidate upgrade failed (see /tmp/uat-mig211-upgrade.log: $(redact </tmp/uat-mig211-upgrade.log | tail -3))"
fi
wait_service_active || acc_fail "R3 daemon not active after the packaged restart"
wait_health || acc_fail "R3 daemon not healthy after the packaged restart"
acc_ok "R3 packaged restart path completed (service active, healthy)"

# ==============================================================================
# R4-R9: post-migration proofs
# ==============================================================================
# R4: the migrated roots' read_write authority is proven through the rich
# --json projection, parsed structurally (the default human list is the
# 2.1-compatible one path per line surface and carries no ACCESS column).
M_LIST_JSON="$(dh config allowed-root list --json 2>/dev/null || true)"
M_RW_GLOBAL="$(printf '%s' "$M_LIST_JSON" | allowed_root_json_access "$ALLOWED_ROOT")"
M_RW_POLICY="$(printf '%s' "$M_LIST_JSON" | allowed_root_json_access "$M_POLICY")"
if [ "$M_RW_GLOBAL" = read_write ] && [ "$M_RW_POLICY" = read_write ]; then
  acc_ok "R4 migrated path-only global roots carry read_write authority (rich projection)"
else
  acc_fail "R4 global root access semantics wrong (rich projection: $M_LIST_JSON)"
fi
M_HUMAN_LIST="$(dh config allowed-root list 2>/dev/null || true)"
if printf '%s\n' "$M_HUMAN_LIST" | grep -qx "$ALLOWED_ROOT" \
    && printf '%s\n' "$M_HUMAN_LIST" | grep -qx "$M_POLICY"; then
  acc_ok "R4 default human list keeps the 2.1 one-path-per-line contract (no ACCESS column)"
else
  acc_fail "R4 default human list lost the 2.1 one-path-per-line contract: $M_HUMAN_LIST"
fi
if python3 -c '
import json, sys
cfg = json.load(open("/etc/docker-helper/config.json"))
roots = cfg.get("allowed_roots", [])
sys.exit(0 if isinstance(roots, list) and len(roots) == 2 and all(isinstance(r, str) for r in roots) else 1)
' 2>/dev/null; then
  acc_ok "R4 config.json keeps the legacy path-only string form"
else
  acc_fail "R4 config.json legacy path-only form not preserved"
fi

M_PLIST_JSON="$(dh principal allowed-root list --system "$M_USER" --json 2>/dev/null || true)"
M_RW_P_GLOBAL="$(printf '%s' "$M_PLIST_JSON" | allowed_root_json_access "$ALLOWED_ROOT")"
M_RW_P_POLICY="$(printf '%s' "$M_PLIST_JSON" | allowed_root_json_access "$M_POLICY")"
if [ "$M_RW_P_GLOBAL" = read_write ] && [ "$M_RW_P_POLICY" = read_write ]; then
  acc_ok "R5 Principal roots migrated as read_write (rich projection)"
else
  acc_fail "R5 Principal root migration wrong (rich projection: $M_PLIST_JSON)"
fi
M_LLIST_JSON="$(dh launcher allowed-root list --system --principal "$M_USER" "$M_L_ID" --json 2>/dev/null || true)"
M_RW_L_SUB="$(printf '%s' "$M_LLIST_JSON" | allowed_root_json_access "$M_POLICY/sub")"
if [ "$M_RW_L_SUB" = read_write ]; then
  acc_ok "R5 Launcher root migrated as read_write (rich projection)"
else
  acc_fail "R5 Launcher root migration wrong (rich projection: $M_LLIST_JSON)"
fi

M_S1_SHOW="$(dh session show --system --id "$M_S1_ID" 2>/dev/null || true)"
M_S2_SHOW="$(dh session show --system --id "$M_S2_ID" 2>/dev/null || true)"
if printf '%s\n' "$M_S1_SHOW" | grep -Eq "^$(printf '%s' "$M_POLICY/sub/ws" | sed 's/[.[\*^$]/\\&/g')[[:space:]]+read_write$" \
    && printf '%s\n' "$M_S2_SHOW" | grep -Eq "^$(printf '%s' "$M_HOME/ws" | sed 's/[.[\*^$]/\\&/g')[[:space:]]+read_write$"; then
  acc_ok "R6 pre-existing Sessions carry the compatibility workspace/read_write snapshot"
else
  acc_fail "R6 compatibility snapshot wrong (S1: $(printf '%s\n' "$M_S1_SHOW" | tail -4 | tr '\n' '; '))"
fi

M_AUTH_HTTP="$(curl --silent --output /tmp/uat-mig211-auth.json --write-out '%{http_code}' --max-time 5 \
  --unix-socket "$SOCK" -H "Authorization: Bearer $M_P_TOKEN" http://localhost/auth 2>/dev/null || true)"
if [ "$M_AUTH_HTTP" = 200 ] && grep -q '"authority":"principal"' /tmp/uat-mig211-auth.json \
    && grep -q "\"principal\":\"$M_USER\"" /tmp/uat-mig211-auth.json; then
  acc_ok "R7 principal credential keeps its identity after migration"
else
  acc_fail "R7 principal credential identity check failed (http=$M_AUTH_HTTP)"
fi
M_LAUNCHERS="$(dh launcher list --system --principal "$M_USER" --json 2>/dev/null || true)"
if printf '%s\n' "$M_LAUNCHERS" | grep -q "\"id\": \"$M_L_ID\"" \
    && printf '%s\n' "$M_LAUNCHERS" | grep -q '"name": "mlaunch"'; then
  acc_ok "R7 launcher identity preserved (same ID and name)"
else
  acc_fail "R7 launcher identity changed after migration"
fi
M_SESSIONS="$(dh session list --system --token-file /etc/docker-helper/admin.token --json 2>/dev/null || true)"
if printf '%s\n' "$M_SESSIONS" | grep -q "$M_S1_ID" \
    && printf '%s\n' "$M_SESSIONS" | grep -q "$M_S2_ID"; then
  acc_ok "R7 both pre-existing Session IDs preserved"
else
  acc_fail "R7 pre-existing Session IDs not preserved"
fi

if [ -n "${M_S1_TOKEN:-}" ]; then
  M_RUN_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$M_S1_TOKEN" \
    dh run --image alpine:3.24 --mount .:/mnt/ws -- \
    sh -ec 'echo migrated-write > /mnt/ws/after-migration.txt && cat /mnt/ws/input.txt && echo MIG211-RW-OK' 2>&1)"
  if printf '%s\n' "$M_RUN_OUT" | grep -q 'MIG211-RW-OK' \
      && [ "$(cat "$M_POLICY/sub/ws/after-migration.txt" 2>/dev/null)" = "migrated-write" ]; then
    acc_ok "R8 old Session still exposes its workspace writable (2.1 behavior preserved)"
  else
    acc_fail "R8 old Session writable behavior changed: $(printf '%s\n' "$M_RUN_OUT" | redact | tail -3)"
  fi
else
  acc_fail "R8 old Session bearer unavailable (seed failed earlier)"
fi

# R9 pre-restart baseline: the canonical, formatting-independent rich
# projection of the migrated policy (config and Principal roots). The
# post-restart check compares this projection, never formatted output.
M_R9_CONFIG_PROJ_BEFORE="$(dh config allowed-root list --json 2>/dev/null | allowed_root_json_projection)"
M_R9_PRINCIPAL_PROJ_BEFORE="$(dh principal allowed-root list --system "$M_USER" --json 2>/dev/null | allowed_root_json_projection)"

systemctl restart docker-helper.service >/dev/null 2>&1 || true
wait_service_active || acc_fail "R9 daemon not active after restart"
if wait_health; then
  M_S1_SHOW2="$(dh session show --system --id "$M_S1_ID" 2>/dev/null || true)"
  if printf '%s\n' "$M_S1_SHOW2" | grep -Eq "^$(printf '%s' "$M_POLICY/sub/ws" | sed 's/[.[\*^$]/\\&/g')[[:space:]]+read_write$"; then
    acc_ok "R9 snapshot stable across restart (idempotent migration)"
  else
    acc_fail "R9 snapshot changed after restart"
  fi
  M_R9_CONFIG_JSON="$(dh config allowed-root list --json 2>/dev/null || true)"
  M_R9_PRINCIPAL_JSON="$(dh principal allowed-root list --system "$M_USER" --json 2>/dev/null || true)"
  M_R9_CONFIG_RW="$(printf '%s' "$M_R9_CONFIG_JSON" | allowed_root_json_access "$M_POLICY")"
  M_R9_PRINCIPAL_RW="$(printf '%s' "$M_R9_PRINCIPAL_JSON" | allowed_root_json_access "$M_POLICY")"
  if [ "$(printf '%s' "$M_R9_CONFIG_JSON" | allowed_root_json_projection)" = "$M_R9_CONFIG_PROJ_BEFORE" ] \
      && [ "$(printf '%s' "$M_R9_PRINCIPAL_JSON" | allowed_root_json_projection)" = "$M_R9_PRINCIPAL_PROJ_BEFORE" ] \
      && [ "$M_R9_CONFIG_RW" = read_write ] && [ "$M_R9_PRINCIPAL_RW" = read_write ]; then
    acc_ok "R9 migrated policy stable across restart (canonical rich projection identical, read_write kept)"
  else
    acc_fail "R9 migrated policy changed after restart (projection before: config=[$M_R9_CONFIG_PROJ_BEFORE] principal=[$M_R9_PRINCIPAL_PROJ_BEFORE])"
  fi
  if [ "$(sha256sum /etc/docker-helper/config.json | awk '{print $1}')" = "$M_CONFIG_SHA" ]; then
    acc_ok "R9 config.json unchanged across upgrade and restart"
  else
    acc_fail "R9 config.json was rewritten outside the config transaction"
  fi
  if python3 -c '
import sqlite3, sys
db = sqlite3.connect("/var/lib/docker-helper/docker-helper.db")
scols = [r[1] for r in db.execute("PRAGMA table_info(sessions)")]
snapcols = [r[1] for r in db.execute("PRAGMA table_info(session_filesystem_snapshot_entries)")]
ok = ("principal_id" not in scols and "launcher_id" in scols
      and snapcols == ["session_id", "position", "path", "access"])
sys.exit(0 if ok else 1)
' 2>/dev/null; then
    acc_ok "R9 final schema after restart: sessions final, snapshot table canonical"
  else
    acc_fail "R9 final schema wrong after restart"
  fi
else
  acc_fail "R9 daemon not healthy after restart (idempotency not exercised)"
fi

# ==============================================================================
# summary
# ==============================================================================
echo
echo "======= 2.1.1 -> CANDIDATE MIGRATION GATE SUMMARY (RPM guest) ======="
printf '  FAILS:    %d\n' "$FAIL_COUNT"
printf '  BLOCKED:  %d\n' "$BLOCKED_COUNT"
echo "====================================================================="

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory migration scenario FAILED" >&2
  exit 1
fi
if [ "$BLOCKED_COUNT" -gt 0 ]; then
  echo "RESULT: migration BLOCKED (required scenario not exercised)" >&2
  exit 2
fi
echo "RESULT: 2.1.1 -> candidate RPM migration gate PASSED"
