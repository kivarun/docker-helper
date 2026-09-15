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

# Recovery preparation: drop stale stored global roots left by earlier
# fixture lifecycles. A stored root whose path no longer exists makes every
# runtime-strict config transaction (add, set-access, reload, daemon
# startup) fail closed — that is the required runtime contract, and the
# recovery group must seed its fixture into a valid runtime config. Only
# entries whose path is gone are dropped, through the same recovery mutation
# this group asserts (remove resolves the missing path through the identity
# owner); valid roots are never touched.
while IFS= read -r stale_global; do
  [ -n "$stale_global" ] || continue
  if [ ! -e "$stale_global" ]; then
    dh config allowed-root remove "$stale_global" >/dev/null 2>&1 || true
  fi
done < <(reg_config_global_roots)

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
human_out="$(dh config allowed-root list 2>/dev/null || true)"
# The JSON path set is exactly the default human list's path set (the same
# recovery-safe universe, two representations) and the fixture entries keep
# their stored access modes.
if printf '%s' "$json_out" | python3 -c '
import json, sys
try:
    entries = json.load(sys.stdin)
except Exception:
    sys.exit(1)
byp = {e.get("path"): e.get("access") for e in entries}
survivor, stale, human = sys.argv[1], sys.argv[2], sys.argv[3]
sys.exit(0 if byp.get(survivor) == "read_write" and byp.get(stale) == "read_only"
         and sorted(byp) == sorted(human.splitlines()) else 1)
' "$SURVIVOR" "$STALE" "$human_out"; then
  reg_ok "D: the --json projection carries the stale entry with its stored access mode"
else
  reg_fail "D: the --json projection lost the stale entry or its stored access: $(printf '%s' "$json_out" | tr '\n' ' ' | redact)"
fi

# --- E. remove completion offers the stored-root universe --------------------

# The expected universe is the recovery-safe list projection itself (the same
# owner the completion queries); it contains the stale entry plus any valid
# global roots of the environment.
universe="$(reg_config_global_roots)"
if printf '%s\n' "$universe" | grep -Fxq "$STALE" && printf '%s\n' "$universe" | grep -Fxq "$SURVIVOR"; then
  :
else
  reg_fail "E: the recovery-safe list universe lost the fixture roots: [$(printf '%s' "$universe" | tr '\n' ' ' | redact)]"
fi
out="$(run_completion "$script" /usr/bin/docker-helper config allowed-root remove "")"
assert_completion "E: config allowed-root remove <TAB> offers the stored roots including the stale entry" "$universe" "$out" || true

# A typed stale prefix completes exactly that stored identity.
out="$(run_completion "$script" /usr/bin/docker-helper config allowed-root remove "$STALE")"
assert_completion "E: the typed stale identity completes exactly itself" "$STALE" "$out" || true

# --- F. set-access completion shares the same universe -----------------------

out="$(run_completion "$script" /usr/bin/docker-helper config allowed-root set-access "")"
assert_completion "F: config allowed-root set-access <TAB> offers the same stored-root universe" "$universe" "$out" || true
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

# --- J-O. M4: strict config document grammar (exact keys, duplicates) ---------
#
# The persisted config.json is security policy/state, so its document grammar
# is strict and fail-closed at the ONE ingest boundary: exactly one top-level
# JSON object, no trailing tokens, duplicate top-level members refused, and
# every member matched by EXACT spelling (case variants such as
# Operation_Max_Completed are refused as unknown instead of being silently
# folded onto the canonical field by encoding/json case-insensitive struct
# matching — the pre-M4 fold could deliver a negative operation_max_completed
# to the operation supervisor's completed-cap consumer). All rejection
# happens before effective config and before runtime side effects.

M4_CONFIG=/etc/docker-helper/config.json
M4_SNAP="$TMPDIR_REG21/config.m4.bak"
M4_J_START="$(date '+%Y-%m-%d %H:%M:%S')"
if ! cp "$M4_CONFIG" "$M4_SNAP"; then
  reg_blocked "M4: cannot snapshot $M4_CONFIG"
fi
m4_restore_config() {
  cp "$M4_SNAP" "$M4_CONFIG"
}

# m4_start_fails LABEL: start the service and prove it does NOT become healthy.
m4_start_fails() {
  local label="$1" failed=1
  systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
  systemctl start "$SERVICE" >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    if ! systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
      failed=0
      break
    fi
    sleep 1
  done
  if [ "$failed" -eq 0 ]; then
    reg_ok "$label"
  else
    reg_fail "$label: the service stayed active for 30s — startup did not fail closed"
  fi
}

# m4_journal_asserts LABEL: the refusal window must contain the bounded
# actionable config diagnostic and no Go panic / runtime crash evidence.
m4_journal_asserts() {
  local label="$1" window
  window="$(journalctl -u "$SERVICE" --since "$M4_J_START" --no-pager 2>/dev/null || true)"
  if printf '%s' "$window" | grep -q 'unknown configuration field'; then
    reg_ok "$label: journal contains the bounded config-grammar diagnostic"
  else
    reg_fail "$label: no config-grammar diagnostic in the journal window"
  fi
  if printf '%s' "$window" | grep -qiE '^panic|runtime error:|goroutine [0-9]+ \['; then
    reg_fail "$label: panic/crash evidence in the journal window: $(printf '%s' "$window" | grep -iE '^panic|runtime error:' | head -2 | redact)"
  else
    reg_ok "$label: no panic or runtime crash in the journal window"
  fi
}

# --- J. startup fails closed on the case-variant negative override ----------

systemctl stop "$SERVICE" >/dev/null 2>&1 || true
python3 - "$M4_CONFIG" <<'PY' || reg_fail "M4 J: cannot inject the case-variant members"
import json, sys
path = sys.argv[1]
with open(path) as f:
    doc = json.load(f)
doc.pop("operation_max_completed", None)
doc["operation_max_completed"] = 200
doc["Operation_Max_Completed"] = -1
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
m4_start_fails "J: daemon startup fails closed on the case-variant negative override (canonical 200 stays valid; the case variant is a grammar refusal)"
m4_journal_asserts "J"

# --- K. recovery: restore the canonical config, startup succeeds -------------

m4_restore_config
systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
systemctl start "$SERVICE" >/dev/null 2>&1 || true
if wait_service_health; then
  reg_ok "K: daemon startup succeeds again after restoring the canonical config"
else
  reg_fail "K: the service did not become healthy after the config restore"
fi

# --- L. reload refuses the malformed document; the running daemon keeps ------
#     serving the previous effective config. The daemon stays up on the good
#     effective config while the FILE on disk is malformed: startup would
#     (correctly) refuse this document, so the fixture only rewrites the file
#     under the running daemon.

python3 - "$M4_CONFIG" <<'PY' || reg_fail "M4 L: cannot inject the case-variant member for the reload refusal"
import json, sys
path = sys.argv[1]
with open(path) as f:
    doc = json.load(f)
doc.pop("operation_max_completed", None)
doc["operation_max_completed"] = 200
doc["Operation_Max_Completed"] = -1
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
if dh reload >/dev/null 2>&1; then
  reg_fail "L: reload accepted a case-variant config document (must fail closed)"
else
  reg_ok "L: reload fails closed on the case-variant document"
fi
if wait_service_health; then
  reg_ok "L: the daemon keeps serving the previous effective config after the refused reload"
else
  reg_fail "L: the daemon is not healthy after the refused reload"
fi
m4_restore_config
if dh reload >/dev/null 2>&1; then
  reg_ok "L: reload succeeds again after restoring the canonical config"
else
  reg_fail "L: reload failed after the canonical restore"
fi

# --- M. config mutation refuses the malformed document, bytes unchanged ------

systemctl stop "$SERVICE" >/dev/null 2>&1 || true
python3 - "$M4_CONFIG" <<'PY' || reg_fail "M4 M: cannot inject the case-variant member for the mutation refusal"
import json, sys
path = sys.argv[1]
with open(path) as f:
    doc = json.load(f)
doc.pop("operation_max_completed", None)
doc["operation_max_completed"] = 200
doc["Operation_Max_Completed"] = -1
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
M4_SHA_BEFORE="$(sha256sum "$M4_CONFIG" | cut -d' ' -f1)"
M4_EXTRA_ROOT="$BASE/m4-extra-root"
mkdir -p "$M4_EXTRA_ROOT"
if dh config set operation_max_completed 300 >/dev/null 2>&1; then
  reg_fail "M: config set accepted a case-variant document (must refuse without rewriting)"
else
  reg_ok "M: config set refuses the case-variant document"
fi
if dh config allowed-root add "$M4_EXTRA_ROOT" >/dev/null 2>&1; then
  reg_fail "M: config allowed-root add accepted a case-variant document (must refuse without rewriting)"
else
  reg_ok "M: config allowed-root add refuses the case-variant document"
fi
M4_SHA_AFTER="$(sha256sum "$M4_CONFIG" | cut -d' ' -f1)"
if [ "$M4_SHA_BEFORE" = "$M4_SHA_AFTER" ]; then
  reg_ok "M: the refused mutations left config.json byte-for-byte unchanged"
else
  reg_fail "M: a refused mutation rewrote config.json (before $M4_SHA_BEFORE, after $M4_SHA_AFTER)"
fi
m4_restore_config

# --- N. unknown-member startup refusal ---------------------------------------

systemctl stop "$SERVICE" >/dev/null 2>&1 || true
python3 - "$M4_CONFIG" <<'PY' || reg_fail "M4 N: cannot inject the unknown member"
import json, sys
path = sys.argv[1]
with open(path) as f:
    doc = json.load(f)
doc["unknown_m4_field"] = 1
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
m4_start_fails "N: daemon startup fails closed on an unknown top-level member"
m4_restore_config

# --- O. duplicate-member startup refusal --------------------------------------

systemctl stop "$SERVICE" >/dev/null 2>&1 || true
printf '{\n  "allowed_roots": ["%s"],\n  "session_ttl": "12h",\n  "session_ttl": "1h"\n}\n' "$SURVIVOR" > "$M4_CONFIG" \
  || reg_fail "M4 O: cannot write the duplicate-member fixture"
m4_start_fails "O: daemon startup fails closed on duplicate top-level members (never last-wins)"
m4_restore_config

# --- P. the canonical config still starts, reloads, and mutates normally ------

systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
systemctl start "$SERVICE" >/dev/null 2>&1 || true
if wait_service_health; then
  reg_ok "P: the canonical config starts the daemon normally after the M4 refusals"
else
  reg_fail "P: the service did not become healthy on the restored canonical config"
fi
if dh config set session_ttl "12h" >/dev/null 2>&1; then
  reg_ok "P: config set still works on the canonical config"
else
  reg_fail "P: config set failed on the canonical config"
fi

rm -rf "$TMPDIR_REG21"
reg_result
