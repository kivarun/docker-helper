#!/usr/bin/env bash
#
# uat-regression-allowed-root-recovery.sh — Release-2.2 targeted regression
# group 21: global allowed-root recovery universe (Ubuntu / DEB / AppArmor).
#
# The recovery scenario: an operator deletes a stored global allowed-root
# directory outside docker-helper. Runtime validation is REQUIRED to fail
# closed (reload rejected, daemon startup fails), but the stored-config
# inspection and the existing-entity completion surfaces must still expose
# the stale entry so the operator can address it:
#
#   A. fail-closed reload — `reload` rejects the runtime config whose stored
#      root no longer exists and the daemon keeps serving the last valid
#      policy;
#   B. fail-closed startup — a service restart with the stale entry must NOT
#      become healthy;
#   C. recovery-safe inspection — `config allowed-root list` still exits 0
#      and shows the stale stored root (ENOENT keeps the cleaned absolute
#      stored identity) instead of failing with the startup error;
#   D. the rich `--json` projection still carries the stale entry with its
#      stored access mode;
#   E. remove completion — `config allowed-root remove <TAB>` offers the
#      stored-root universe (including the stale entry), and a typed stale
#      prefix completes exactly that identity;
#   F. set-access completion — the PATH positional of
#      `config allowed-root set-access <TAB>` offers the same stored-root
#      universe;
#   G. silent, non-blocking degradation — a failed stored-root query leaves
#      completion silent (no suggestions, no stderr, process success)
#      instead of stalling the shell;
#   H. recovery mutation — `config allowed-root remove <stale>` succeeds with
#      the daemon down and removes exactly the stale entry;
#   I. recovery restores startup — the service becomes healthy again with the
#      repaired config and the stale root is gone from the list.
#
# Each subcase is independent evidence of one invariant of the recovery
# scenario; A/B pin the runtime fail-closed contract that must NOT weaken.
# Docker is not required.
#
# Requires: installed docker-helper system service (active), root, bash.
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "21. allowed-root recovery universe"

reg_require_root
reg_require_service
reg_require_cmd bash "completion acceptance drives a real Bash"

TMPDIR_REG21="/tmp/uat-reg21"
mkdir -p "$TMPDIR_REG21"

SERVICE=docker-helper.service
# shellcheck disable=SC2034  # consumed by the shared wait_service_health owner
SOCK=/run/docker-helper/docker-helper.sock

# stale is the stored root whose directory is deleted; survivor stays on disk
# so the config always keeps at least one valid global root (remove refuses
# the final root, and the repaired config must stay valid). The tree lives
# under an existing policy-legal global root (/tmp would be rejected by the
# workspace-root policy), which the collect-all runner guarantees to exist.
BASE="$(reg_config_global_roots | sed -n '1p')/uat-reg21-recovery-tree"
if [ -z "$BASE" ] || [ "$BASE" = "/uat-reg21-recovery-tree" ]; then
  reg_blocked "no global allowed root under which to place the recovery fixture"
fi
SURVIVOR="$BASE/keep"
STALE="$BASE/stale"
mkdir -p "$SURVIVOR" "$STALE"

cleanup() {
  systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
  systemctl enable --now "$SERVICE" >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    systemctl is-active --quiet "$SERVICE" && break
    sleep 1
  done
  dh config allowed-root remove "$STALE" >/dev/null 2>&1 || true
  dh config allowed-root remove "$SURVIVOR" >/dev/null 2>&1 || true
  rm -rf "$BASE"
}
trap cleanup EXIT

# --- fixture: stored config = [survivor, stale], both directories exist ------

if ! dh config allowed-root add "$SURVIVOR" >/dev/null 2>&1 \
    || ! dh config allowed-root add --access read_only "$STALE" >/dev/null 2>&1; then
  reg_blocked "fixture setup failed: cannot store the recovery roots"
fi

# run_completion SCRIPT WORDS... drives the completion function Bash actually
# registered for docker-helper (discovered through `complete -p`, one -F
# registration) with the given command line; prints one COMPREPLY entry per
# line (same harness contract as group 20, including the process-success
# contract of its assertion). Env mutations are performed by the caller
# through the DOCKER_HELPER_CONFIG prefix variable.
run_completion() {
  local script="$1"
  shift
  local words="" w wq err_file
  for w in "$@"; do
    printf -v wq '%q' "$w"
    words+="${words:+ }${wq}"
  done
  err_file="$TMPDIR_REG21/comp.err"
  : > "$err_file"
  bash -c '
    set -u
    source "$1" || exit 3
    mapfile -t specs < <(complete -p docker-helper)
    if [ ${#specs[@]} -ne 1 ]; then
      echo "registrations: ${specs[*]:-none}" >&2
      exit 5
    fi
    func="${specs[0]#*-F }"
    if [ "$func" = "${specs[0]}" ]; then
      echo "no -F function in compspec: ${specs[0]}" >&2
      exit 6
    fi
    func="${func%% *}"
    [ -n "$func" ] || { echo "empty -F function" >&2; exit 6; }
    eval "COMP_WORDS=($2)"
    COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
    COMPREPLY=()
    "$func" || exit 4
    printf "%s\n" "${COMPREPLY[@]}"
  ' _ "$script" "$words" 2>"$err_file"
  local rc=$?
  printf '%s\n' "$rc" > "$TMPDIR_REG21/comp.rc"
}

# completion_harness_diag LABEL-free diagnostic of the last run_completion
# invocation (rc + the query trace), safe under set -u when nothing ran yet.
completion_harness_diag() {
  local rc
  rc="$(cat "$TMPDIR_REG21/comp.rc" 2>/dev/null || echo none)"
  printf 'rc=%s trace: %s' "$rc" "$(grep -a -m 4 -E 'docker-helper (completion|config)' "$TMPDIR_REG21/comp.err" 2>/dev/null | redact)"
}

# assert_completion LABEL EXPECTED ACTUAL: both sides are LC_ALL=C sorted and
# deduplicated; a non-zero completion process status fails the assertion
# before any suggestion comparison (same process-success contract as
# group 20).
assert_completion() {
  local label="$1" expected="$2" actual="$3"
  local want have rc
  rc="$(cat "$TMPDIR_REG21/comp.rc" 2>/dev/null || echo none)"
  if [ "$rc" != "0" ]; then
    reg_fail "$label: completion process failed (rc=$rc) before suggestion comparison ($(completion_harness_diag))"
    return 1
  fi
  want="$(printf '%s' "$expected" | LC_ALL=C sort -u)"
  have="$(printf '%s' "$actual" | LC_ALL=C sort -u)"
  if [ "$want" = "$have" ]; then
    reg_ok "$label"
    return 0
  fi
  reg_fail "$label: suggestions = [$(printf '%s' "$actual" | tr '\n' ' ' | redact)] want [$(printf '%s' "$expected" | tr '\n' ' ')] ($(completion_harness_diag))"
  return 1
}

# --- break the filesystem: delete the stale root outside docker-helper -------

rmdir "$STALE"

# --- A. fail-closed reload ---------------------------------------------------

if dh reload >/dev/null 2>&1; then
  reg_fail "A: reload accepted a runtime config whose stored root is missing (validation must fail closed)"
else
  reg_ok "A: reload fails closed on the missing stored root"
fi
wait_service_health || reg_fail "A: the daemon must keep serving the last valid policy after a rejected reload"

# --- B. fail-closed startup --------------------------------------------------

systemctl restart "$SERVICE" >/dev/null 2>&1 || true
startup_failed=1
for _ in $(seq 1 30); do
  if ! systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    startup_failed=0
    break
  fi
  sleep 1
done
if [ "$startup_failed" -eq 0 ]; then
  reg_ok "B: daemon startup fails closed with the stale stored root (unit left failed/inactive)"
else
  reg_fail "B: the service stayed active for 30s after restart — startup did not fail closed"
fi

# --- fixture completion script (generated by the installed binary) ----------

script="$TMPDIR_REG21/completion.bash"
if ! dh completion bash > "$script" 2>/dev/null || [ ! -s "$script" ]; then
  reg_fail "fixture: completion script generation failed"
  reg_result
fi

# --- C. recovery-safe inspection ---------------------------------------------

list_out="$(dh config allowed-root list 2>&1)"
list_rc=$?
if [ "$list_rc" -eq 0 ] && printf '%s\n' "$list_out" | grep -Fx "$STALE" && printf '%s\n' "$list_out" | grep -Fx "$SURVIVOR"; then
  reg_ok "C: config allowed-root list still shows the stale stored root (recovery-safe inspection)"
else
  reg_fail "C: list rc=$list_rc out=[$(printf '%s' "$list_out" | tr '\n' ' ' | redact)] — the stale entry must stay visible and addressable"
fi

# --- D. the rich --json projection keeps the stale entry ----------------------

json_out="$(dh config allowed-root list --json 2>/dev/null || true)"
if printf '%s' "$json_out" | python3 -c '
import json, sys
try:
    entries = json.load(sys.stdin)
except Exception:
    sys.exit(1)
want = {sys.argv[1], sys.argv[2]}
got = {e.get("path") for e in entries}
stale = [e for e in entries if e.get("path") == sys.argv[2]]
sys.exit(0 if want <= got and len(entries) == 2 and stale and stale[0].get("access") == "read_only" else 1)
' "$SURVIVOR" "$STALE"; then
  reg_ok "D: the --json projection carries the stale entry with its stored access mode"
else
  reg_fail "D: the --json projection lost the stale entry or its stored access: $(printf '%s' "$json_out" | tr '\n' ' ' | redact)"
fi

# --- E. remove completion offers the stored-root universe --------------------

out="$(run_completion "$script" /usr/bin/docker-helper config allowed-root remove "")"
assert_completion "E: config allowed-root remove <TAB> offers the stored roots including the stale entry" "$(printf '%s\n%s\n' "$SURVIVOR" "$STALE")" "$out" || true

# A typed stale prefix completes exactly that stored identity.
out="$(run_completion "$script" /usr/bin/docker-helper config allowed-root remove "$STALE")"
assert_completion "E: the typed stale identity completes exactly itself" "$STALE" "$out" || true

# --- F. set-access completion shares the same universe -----------------------

out="$(run_completion "$script" /usr/bin/docker-helper config allowed-root set-access "")"
assert_completion "F: config allowed-root set-access <TAB> offers the same stored-root universe" "$(printf '%s\n%s\n' "$SURVIVOR" "$STALE")" "$out" || true
out="$(run_completion "$script" /usr/bin/docker-helper config allowed-root set-access "$STALE" "")"
assert_completion "F: after PATH the ACCESS positional completes the canonical vocabulary" "$(printf 'read_write\nread_only\n')" "$out" || true

# --- G. silent, non-blocking degradation -------------------------------------

# A stored-root query failure (unreadable config) must leave the completion
# silent: no suggestions, no stderr, and a successful process.
out="$(DOCKER_HELPER_CONFIG=/nonexistent/uat-reg21-config.json run_completion "$script" /usr/bin/docker-helper config allowed-root remove "")"
g_rc="$(cat "$TMPDIR_REG21/comp.rc" 2>/dev/null)"
g_err_size="$(wc -c < "$TMPDIR_REG21/comp.err" 2>/dev/null || echo 0)"
if [ -z "$out" ] && [ "$g_rc" = 0 ] && [ "$g_err_size" = 0 ]; then
  reg_ok "G: a failed stored-root query degrades silently (no suggestions, no stderr, process success)"
else
  reg_fail "G: degraded completion suggestions = [$(printf '%s' "$out" | tr '\n' ' ' | redact)] rc=$g_rc stderr_bytes=$g_err_size ($(completion_harness_diag))"
fi

# --- H. recovery mutation with the daemon down -------------------------------

if dh config allowed-root remove "$STALE" >/dev/null 2>&1; then
  reg_ok "H: the stale stored root is removable through the recovery mutation"
else
  reg_fail "H: config allowed-root remove of the stale root failed"
fi
if dh config allowed-root list 2>/dev/null | grep -Fxq "$STALE"; then
  reg_fail "H: the stale entry is still stored after the removal"
else
  reg_ok "H: the stale entry is gone from the stored config"
fi

# --- I. recovery restores daemon startup -------------------------------------

systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
systemctl start "$SERVICE" >/dev/null 2>&1 || true
if wait_service_health; then
  reg_ok "I: daemon startup succeeds again after the recovery removal"
else
  reg_fail "I: the service did not become healthy after the recovery removal"
fi
if reg_config_global_roots | grep -Fxq "$STALE"; then
  reg_fail "I: the recovered config still lists the stale root"
else
  reg_ok "I: the recovered global roots no longer contain the stale entry"
fi

rm -rf "$TMPDIR_REG21"
reg_result
