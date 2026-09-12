#!/usr/bin/env bash
#
# uat-regression-lib.sh — shared helpers for the Release-2 targeted UAT
# regression groups (scripts/uat-regression-*.sh) and their collect-all
# runners (scripts/uat-regressions-runner-*.sh). The standalone Release-2
# acceptance suites (uat-release2-acceptance.sh, uat-migration-rpm-211.sh,
# uat-access-modes.sh) source it for the shared measurement primitives only
# and keep their own scenario accounting.
#
# Every regression script sources this file. The lib owns only the small amount
# of per-regression bookkeeping (subcase ok/fail accounting, the final
# PASS/FAIL/BLOCKED verdict, the common redaction helper), the structural
# rich allowed-root JSON parse shared by the list-output contracts, and the
# fail-closed residue inventory primitives. It deliberately does NOT own any
# docker-helper operation, MAC behavior or install logic: that stays in the
# individual scripts, which run against an already-installed, running
# docker-helper system service.
#
# Contract between the collect-all runners and the individual scripts:
#   exit 0 = PASS      (script prints REGRESSION_RESULT=PASS)
#   exit 1 = FAIL      (script prints REGRESSION_RESULT=FAIL)
#   exit 2 = BLOCKED   (script prints REGRESSION_RESULT=BLOCKED)
#
# BLOCKED is valid ONLY when a real prerequisite (no service, no docker, no
# root) prevents execution. A previous regression's failure is never a reason
# to BLOCK a later group.
#
# Mandatory-runner aggregation (fail-closed): a mandatory UAT runner returns
# nonzero when ANY group is FAIL or BLOCKED — a BLOCKED group means the
# required scenario was NOT successfully exercised, which is not acceptable for
# Release-2. Exit semantics (shared by both collect-all runners):
#   all PASS                -> 0
#   one or more BLOCKED,
#     no FAIL               -> 2
#   one or more FAIL        -> 1

# --- result accounting -------------------------------------------------------

# reg_classify_rc RC: map a group's exit code to its verdict label.
#   0 = PASS, 1 = FAIL, 2 = BLOCKED, anything else = FAIL.
reg_classify_rc() {
  case "$1" in
    0) printf 'PASS\n' ;;
    2) printf 'BLOCKED\n' ;;
    *) printf 'FAIL\n' ;;
  esac
}

# reg_aggregate_exit FAIL_COUNT BLOCKED_COUNT: the runner's final exit status
# from its per-group accounting (fail-closed; see the contract above).
reg_aggregate_exit() {
  local fail_count="${1:-0}" blocked_count="${2:-0}"
  if [ "$fail_count" -gt 0 ]; then
    printf '1\n'
  elif [ "$blocked_count" -gt 0 ]; then
    printf '2\n'
  else
    printf '0\n'
  fi
}

reg_init() {
  REG_NAME="$1"
  REG_FAILURES=""
  echo
  echo "===================== REGRESSION: $REG_NAME ====================="
}

reg_ok()   { printf '  ok:   %s\n' "$*"; }

reg_fail() {
  printf '  FAIL: %s\n' "$*" >&2
  REG_FAILURES="${REG_FAILURES}$(printf '\n  - %s' "$*")"
}

reg_info() { printf '  ...:  %s\n' "$*"; }

# reg_result emits the final verdict and exits (0 = PASS, 1 = FAIL).
reg_result() {
  if [ -z "$REG_FAILURES" ]; then
    echo "REGRESSION_RESULT=PASS"
    echo "===================== REGRESSION: $REG_NAME => PASS ====================="
    exit 0
  fi
  printf '%s\n' "FAILED SUBCASES:${REG_FAILURES}" >&2
  echo "REGRESSION_RESULT=FAIL"
  echo "===================== REGRESSION: $REG_NAME => FAIL ====================="
  exit 1
}

# reg_blocked records a missing prerequisite (real only) and exits 2.
reg_blocked() {
  echo "REGRESSION_RESULT=BLOCKED"
  echo "REGRESSION_BLOCKED_REASON=$*"
  exit 2
}

# reg_require_cmd exits BLOCKED when a required binary is absent.
reg_require_cmd() {
  local cmd="$1" why="${2:-required for this regression}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    reg_blocked "$cmd not found ($why)"
  fi
}

reg_require_root() {
  [ "$(id -u)" -eq 0 ] || reg_blocked "must run as root"
}

# reg_require_service exits BLOCKED when the docker-helper system service is
# not active.
reg_require_service() {
  if ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
    reg_blocked "docker-helper.service is not active"
  fi
}

# reg_require_docker exits BLOCKED when the Docker daemon is unreachable.
reg_require_docker() {
  if ! docker info >/dev/null 2>&1; then
    reg_blocked "Docker daemon is not reachable (docker info failed)"
  fi
}

# redact masks bearer-token values (admin/session dht_, credential dhc_) in a
# captured stream so they never reach the CI log. Session IDs (dhs_) and
# credential IDs (dhcr_) are not bearer secrets and are left intact.
redact() {
  sed -E \
    -e 's/dht_[A-Za-z0-9_-]+/<redacted-token>/g' \
    -e 's/dhc_[A-Za-z0-9_-]+/<redacted-token>/g'
}

# json_field extracts a string field from a JSON document read on stdin.
json_field() { # field
  grep -oP "\"$1\": \"\K[^\"]+" | head -1
}

# --- canonical rich allowed-root list helpers --------------------------------
# The default human `allowed-root list` is the 2.1-compatible surface: one
# canonical path per line, no ACCESS column. Access-aware assertions must use
# the rich `--json` projection (the canonical [{"path","access"}, ...] list in
# stored-entry order) and parse it structurally — never by grepping a
# pretty-printed layout for a path and an access on the same or neighboring
# lines. These helpers are the shared owner of that structural parse for the
# UAT suites. Fail-closed: any inspection failure (unparsable JSON, wrong
# shape, malformed entry, missing path) reports failure and prints nothing, so
# an inspection error can never be mistaken for a verified value.

# allowed_root_json_access PATH prints the canonical access mode
# (read_write|read_only) of PATH from the rich allowed-root JSON list read on
# stdin. Exit 1 when the document is not that list, PATH is absent, or any
# entry is malformed.
allowed_root_json_access() { # PATH
  python3 -c '
import json, sys
try:
    entries = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(entries, list):
    sys.exit(1)
for entry in entries:
    if not (isinstance(entry, dict) and isinstance(entry.get("path"), str)
            and entry.get("access") in ("read_write", "read_only")):
        sys.exit(1)
for entry in entries:
    if entry["path"] == sys.argv[1]:
        print(entry["access"])
        sys.exit(0)
sys.exit(1)
' "$1" 2>/dev/null
}

# allowed_root_json_projection prints the canonical, formatting-independent
# projection of the rich allowed-root JSON list read on stdin: one
# "path<TAB>access" line per entry, in stored-entry order. Exit 1 when the
# document is not that list, so a stability comparison can never mistake an
# inspection failure for an unchanged policy.
allowed_root_json_projection() {
  python3 -c '
import json, sys
try:
    entries = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(entries, list):
    sys.exit(1)
for entry in entries:
    if not (isinstance(entry, dict) and isinstance(entry.get("path"), str)
            and entry.get("access") in ("read_write", "read_only")):
        sys.exit(1)
for entry in entries:
    print("%s\t%s" % (entry["path"], entry["access"]))
' 2>/dev/null
}

# session_list_count prints the authoritative number of active Sessions from
# `dh session list --system --json`. Fail-closed: the list command must
# succeed and the document must be exactly the canonical session-list shape
# (`{"ok":true,"sessions":[{"id","workspace"},...]}` with well-formed session
# objects); a command failure, malformed JSON, an unexpected shape, or a
# malformed session entry exits 1 — never a silent 0. "Cannot inspect" is
# never "zero sessions": the no-state-on-refusal proofs must distinguish a
# positively empty inventory from an unavailable one.
session_list_count() {
  local out rc
  out="$(dh session list --system --json 2>/dev/null)"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    printf '  session list inventory unavailable (session list failed)\n' >&2
    return 1
  fi
  printf '%s' "$out" | python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not (isinstance(doc, dict) and doc.get("ok") is True):
    sys.exit(1)
sessions = doc.get("sessions")
if not isinstance(sessions, list):
    sys.exit(1)
for session in sessions:
    if not (isinstance(session, dict) and isinstance(session.get("id"), str) and session["id"]
            and isinstance(session.get("workspace"), str) and session["workspace"]):
        sys.exit(1)
print(len(sessions))
' 2>/dev/null
}

# dh is the docker-helper CLI used by the regressions (system mode).
dh() { /usr/bin/docker-helper "$@"; }

# durable_session_snapshot_counts DB_PATH prints the durable Session/snapshot
# row counts of the authoritative system database as
# "<sessions>\t<snapshot_entries>\t<snapshot_meta>" (one line, tab-separated).
# The required table set comes from the schema owner
# (session_snapshot_store.go): the sessions table plus the immutable snapshot
# child tables session_filesystem_snapshot_entries and
# session_filesystem_snapshot_meta. Fail-closed: the helper opens the
# database read-only through the python3 stdlib sqlite3 module and never
# mutates it; a missing database file, an unopenable database, an SQL error,
# a parse failure, or an unexpected schema (any required table absent) exits
# 1 with no counts printed — an unavailable inventory is never a zero count.
durable_session_snapshot_counts() {
  local db="$1"
  if [ -z "$db" ]; then
    printf '  durable DB inventory unavailable (no database path)\n' >&2
    return 1
  fi
  if [ ! -f "$db" ]; then
    printf '  durable DB inventory unavailable (database file absent: %s)\n' "$db" >&2
    return 1
  fi
  python3 - "$db" 2>/dev/null <<'UAT_DB_PY'
import sqlite3, sys
path = sys.argv[1]
required = (
    "sessions",
    "session_filesystem_snapshot_entries",
    "session_filesystem_snapshot_meta",
)
try:
    con = sqlite3.connect("file:" + path + "?mode=ro", uri=True)
    tables = {row[0] for row in con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    if not set(required) <= tables:
        raise LookupError("unexpected schema: missing snapshot tables")
    counts = []
    for table in required:
        row = con.execute('SELECT COUNT(*) FROM "%s"' % table).fetchone()
        if row is None:
            raise ValueError("unreadable count")
        counts.append(str(row[0]))
except Exception:
    sys.exit(1)
print("\t".join(counts))
UAT_DB_PY
}

# wait_service_health: the single shared readiness owner for the regression
# family. Returns 0 only when the docker-helper system service is active AND
# GET /health succeeds over its unix API socket, within a bounded poll (no
# blind sleeps). Callers set $SERVICE (systemd unit name) and $SOCK (API
# socket path). systemd active alone is never a readiness oracle: with
# Type=exec the unit reports active as soon as the binary is exec'd, before
# the startup sequence (snapshot integrity, startup reconciliation, session
# cleanup) completes and the listener serves /health.
wait_service_health() {
  for _ in $(seq 1 60); do
    if systemctl is-active --quiet "$SERVICE" 2>/dev/null \
        && curl --silent --fail --max-time 1 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# --- fail-closed residue inventory primitives --------------------------------
# Canonical owner of the release-critical residue inventory contract (the
# workload AppArmor/SELinux UAT matrices and the access-mode UAT residue
# proofs). Three observable states, never mixed:
#   ABSENT  -> positively proven absent (count 0 / empty inventory);
#   PRESENT -> positively proven present (count > 0 / entries);
#   UNKNOWN -> the inspection itself failed -> error status, never 0/empty.
# "Cannot inspect" is never "clean".

# helper_container_count counts helper-owned containers (including exited —
# --rm removes them on exit, and a pre-admission refusal never creates one).
# A docker inventory failure is UNKNOWN (exit 1), never zero residue.
helper_container_count() {
  local out rc
  out="$(docker ps -a --filter 'label=com.dockerhelper.schema=1' -q 2>/dev/null)"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    printf '  helper container inventory unavailable (docker ps failed)\n' >&2
    return 1
  fi
  if [ -z "$out" ]; then
    printf '0'
    return 0
  fi
  printf '%s\n' "$out" | wc -l | tr -d ' '
}

# wait_no_helper_containers waits until the helper-owned container inventory
# is positively empty. Exit status: 0 = positively empty, 1 = residue/timeout,
# 2 = inventory unavailable (never reports clean).
wait_no_helper_containers() {
  local _i=0 count
  for _i in $(seq 1 40); do
    count="$(helper_container_count)" || return 2
    [ "$count" = "0" ] && return 0
    sleep 0.25
  done
  return 1
}

# inventory_count DIR prints the number of entries in DIR. A positively
# absent directory is an empty inventory (the owner creates it lazily);
# an existing but unreadable directory is an inventory error, never 0.
inventory_count() {
  local dir="$1" out rc
  out="$(ls -A -- "$dir" 2>/dev/null)"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    if [ ! -e "$dir" ]; then
      printf '0'
      return 0
    fi
    printf '  inventory %s is unreadable\n' "$dir" >&2
    return 1
  fi
  if [ -z "$out" ]; then
    printf '0'
    return 0
  fi
  printf '%s\n' "$out" | wc -l | tr -d ' '
}

# --- SELinux fcontext/label inventory primitives (fail-closed tri-state) -----
# Canonical owner of the SELinux inventory contract for the SELinux UAT
# suites. Every mandatory SELinux residue/coverage observation distinguishes
# exactly three states:
#   PRESENT -> positively proven present (rule in a readable inventory);
#   ABSENT  -> positively proven absent (readable inventory, rule not in it);
#   ERROR   -> the inspection itself failed (semanage/stat failure, malformed
#              listing) -> the caller must fail the scenario.
# "Cannot inspect" is never "no rule", never "not relabeled", and never
# "restored": an inability to observe state is never evidence of absence.

# selinux_fcontext_patterns prints the first-field pattern of every local
# semanage fcontext customization, one per line (equivalence redirects
# included: their first field is the DEST path). Exit 0 with a readable
# inventory; exit 1 when the inventory command fails OR a non-empty row is
# not an absolute-path data row (the same fail-closed listing contract the
# daemon itself applies) — a partially unreadable listing is never an empty
# but successful one.
selinux_fcontext_patterns() {
  local out rc
  out="$(semanage fcontext -l -C -n 2>/dev/null)"
  rc=$?
  [ "$rc" -eq 0 ] || return 1
  if printf '%s\n' "$out" | awk 'NF && $1 !~ /^\// {found=1} END {exit !found}'; then
    return 1
  fi
  printf '%s\n' "$out" | awk 'NF && $1 ~ /^\// {print $1}'
}

# selinux_rule_state PATTERN — tri-state exact membership of one local
# fcontext rule: first-field equality, so a child-path rule never satisfies a
# parent pattern and vice versa. Exit 0 = PRESENT, 1 = ABSENT,
# 2 = inventory unavailable.
selinux_rule_state() {
  local patterns
  patterns="$(selinux_fcontext_patterns)" || return 2
  printf '%s\n' "$patterns" | grep -Fxq -- "$1"
}

# selinux_rule_line PATTERN prints the full raw listing line of the local
# fcontext rule whose first field equals PATTERN. Exit 0 = PRESENT (line
# printed), 1 = ABSENT, 2 = inventory unavailable. A byte-for-byte survival
# proof compares this line across an operation; a failed read is never a
# missing line.
selinux_rule_line() {
  local out rc line
  out="$(semanage fcontext -l -C -n 2>/dev/null)"
  rc=$?
  [ "$rc" -eq 0 ] || return 2
  line="$(printf '%s\n' "$out" | awk -v p="$1" 'NF && $1 == p {print; exit}')"
  [ -n "$line" ] || return 1
  printf '%s\n' "$line"
}

# selinux_context_type PATH prints the SELinux type component (third
# colon-separated field) of PATH's security context. Exit 0 with the type;
# exit 2 when the context read fails or the output is not a full SELinux
# context — a mandatory label observation on an unreadable path is an
# inventory error, never "not relabeled" and never "restored".
selinux_context_type() {
  local ctx
  ctx="$(stat -c '%C' -- "$1" 2>/dev/null)" || return 2
  case "$ctx" in
    *:*:*:*) printf '%s\n' "$(printf '%s' "$ctx" | cut -d: -f3)" ;;
    *) return 2 ;;
  esac
}

# reg_expect_se_rule EXPECTATION PATTERN LABEL — tri-state fcontext rule
# assertion with the regression accounting. EXPECTATION is "present" or
# "absent". An unavailable inventory fails the group in every direction
# (never evidence of absence); PRESENT where absence is expected fails.
reg_expect_se_rule() {
  local expectation="$1" pattern="$2" label="$3" rc
  selinux_rule_state "$pattern"; rc=$?
  case "$rc" in
    0) if [ "$expectation" = "present" ]; then reg_ok "$label"; else reg_fail "$label: rule '$pattern' is PRESENT"; fi ;;
    1) if [ "$expectation" = "absent" ]; then reg_ok "$label"; else reg_fail "$label: rule '$pattern' is ABSENT"; fi ;;
    *) reg_fail "$label: fcontext inventory unavailable (semanage failed); absence is never assumed" ;;
  esac
}

# reg_expect_se_context EXPECTATION PATH WANT LABEL — tri-state SELinux
# context-type assertion. EXPECTATION is "is" (type equals WANT) or "is-not".
# A failed context read fails the group in every direction.
reg_expect_se_context() {
  local expectation="$1" path="$2" want="$3" label="$4" type rc
  type="$(selinux_context_type "$path")"; rc=$?
  case "$rc" in
    0) case "$expectation" in
         is) if [ "$type" = "$want" ]; then reg_ok "$label"; else reg_fail "$label (type '$type', want '$want')"; fi ;;
         is-not) if [ "$type" = "$want" ]; then reg_fail "$label (type '$type')"; else reg_ok "$label (type '$type')"; fi ;;
         *) reg_fail "$label: reg_expect_se_context expectation must be is|is-not" ;;
       esac ;;
    *) reg_fail "$label: SELinux context inventory unavailable for $path (context read failed)" ;;
  esac
}

# reg_expect_no_se_rule_for FRAGMENT LABEL — no local fcontext rule mentions
# FRAGMENT (regex over-match / residue check). An inventory failure fails the
# group; an empty match on a readable inventory is the positive proof.
reg_expect_no_se_rule_for() {
  local fragment="$1" label="$2" patterns rc
  patterns="$(selinux_fcontext_patterns)"; rc=$?
  case "$rc" in
    0) if printf '%s\n' "$patterns" | grep -Fq -- "$fragment"; then reg_fail "$label"; else reg_ok "$label"; fi ;;
    *) reg_fail "$label: fcontext inventory unavailable (semanage failed); absence is never assumed" ;;
  esac
}

# selinux_rules_for FRAGMENT prints every local rule pattern mentioning
# FRAGMENT. Exit 0 with the (possibly empty) matching set on a readable
# inventory; exit 2 when the inventory is unavailable. Callers must treat
# exit 2 as a failure, never as "no rules".
selinux_rules_for() {
  local patterns
  patterns="$(selinux_fcontext_patterns)" || return 2
  printf '%s\n' "$patterns" | grep -F -- "$1" || true
}

# --- shared ubuntu/deb/apparmor setup helpers --------------------------------
# Used by the Ubuntu-hosted regression groups. The collect-all runner inits the
# system service with global allowed root /home, so every /home/* home below is
# authorized for principal/session use.

# reg_config_global_roots prints the global allowed root paths from
# `config allowed-root list`, one per line. The default human list is the
# 2.1-compatible one path per line surface, so the first field of every data
# row is the path; a PATH/ACCESS table header (no leading slash) is skipped.
reg_config_global_roots() {
  dh config allowed-root list 2>/dev/null | awk 'NF && $1 ~ /^\// {print $1}'
}

# reg_setup_principal USER creates (or reuses) the OS user + docker-helper
# principal (enabled), and prints the user's home directory.
reg_setup_principal() {
  local user="$1" home launcher_json root root_ok home_base
  # The OS user's home must be under a global allowed root, or `principal
  # create` rejects it (final model). Pick a home base that is under an
  # existing allowed root: prefer /home when it is itself allowed (the common
  # default), otherwise fall back to /opt when allowed, else the first root.
  home_base=""
  root_ok=0
  while read -r root; do
    [ -n "$root" ] || continue
    case "$root" in
      /home|/home/*)
        if [ "$root" = "/home" ]; then home_base="/home"; root_ok=1; break; fi
        ;;
    esac
  done <<< "$(reg_config_global_roots)"
  if [ "$root_ok" != 1 ]; then
    if reg_config_global_roots | grep -qx '/opt'; then
      home_base="/opt"; root_ok=1
    fi
  fi
  if [ "$root_ok" != 1 ]; then
    home_base="$(reg_config_global_roots | sed -n '1p')"
  fi
  if [ -z "$home_base" ]; then
    echo "error: no global allowed root under which to place principal '$user' home" >&2
    return 1
  fi
  if ! getent passwd "$user" >/dev/null 2>&1; then
    useradd -m -d "$home_base/$user" -s /bin/bash "$user" || return 1
  fi
  home="$(getent passwd "$user" | cut -d: -f6)"
  dh principal create --system --no-credential "$user" >/dev/null 2>&1 || true
  dh principal set --system "$user" enabled true >/dev/null 2>&1 || true
  # Final ownership model: a selector-less principal Session resolves to the
  # principal's inherit-scope 'default' Launcher, so that Launcher must exist
  # before any reg_session. Eager default provisioning provisions it
  # atomically at principal creation (also when reusing a principal across
  # stages), so prove presence positively via the canonical Admin-scoped
  # launcher show path: 'default' must exist, belong to the principal, and be
  # enabled with inherit scope.
  launcher_json="$(dh launcher show --system --principal "$user" 2>/dev/null)" \
    || { echo "error: principal '$user' has no default Launcher after principal create (eager provisioning broken)" >&2; return 1; }
  printf '%s\n' "$launcher_json" | grep -q "\"principal\": \"$user\"" \
    || { echo "error: default launcher does not belong to principal '$user': $launcher_json" >&2; return 1; }
  printf '%s\n' "$launcher_json" | grep -q '"name": "default"' \
    || { echo "error: default launcher show returned an unexpected name: $launcher_json" >&2; return 1; }
  printf '%s\n' "$launcher_json" | grep -q '"enabled": true' \
    || { echo "error: default launcher is not enabled: $launcher_json" >&2; return 1; }
  printf '%s\n' "$launcher_json" | grep -q '"scope": "inherit"' \
    || { echo "error: default launcher is not inherit scope: $launcher_json" >&2; return 1; }
  printf '%s' "$home"
}

# reg_principal_credential USER CREDFILE creates a fresh credential for USER,
# writes the token to CREDFILE, and sets REG_CRED_ID / REG_CRED_TOKEN.
reg_principal_credential() {
  local user="$1" credfile="$2" out
  rm -f "$credfile"
  out="$(dh credential create --system --name reg "$user" 2>/dev/null)" || return 1
  REG_CRED_ID="$(printf '%s\n' "$out" | sed -n 's/^  ID:    //p' | tr -d '[:space:]')"
  REG_CRED_TOKEN="$(printf '%s\n' "$out" | sed -n 's/^  Token: //p' | tr -d '[:space:]')"
  [ -n "$REG_CRED_ID" ] && [ -n "$REG_CRED_TOKEN" ] || return 1
  printf '%s\n' "$REG_CRED_TOKEN" > "$credfile"
  chmod 600 "$credfile"
  return 0
}

# reg_session CREDFILE WORKSPACE creates a principal session via the credential
# file and sets REG_SESSION_ID / REG_SESSION_TOKEN.
reg_session() {
  local credfile="$1" ws="$2" json
  json="$(dh session create --system --token-file "$credfile" --workspace "$ws" --json 2>/dev/null)" || return 1
  REG_SESSION_ID="$(printf '%s' "$json" | json_field id)"
  REG_SESSION_TOKEN="$(printf '%s' "$json" | json_field token)"
  [ -n "$REG_SESSION_ID" ] && [ -n "$REG_SESSION_TOKEN" ] || return 1
  return 0
}

