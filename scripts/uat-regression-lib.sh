#!/usr/bin/env bash
#
# uat-regression-lib.sh — shared helpers for the Release-2 targeted UAT
# regression groups (scripts/uat-regression-*.sh) and their collect-all
# runners (scripts/uat-regressions-runner-*.sh).
#
# Every regression script sources this file. The lib owns only the small amount
# of per-regression bookkeeping (subcase ok/fail accounting, the final
# PASS/FAIL/BLOCKED verdict and the common redaction helper). It deliberately
# does NOT own any docker-helper operation, MAC behavior or install logic:
# that stays in the individual regression scripts, which run against an
# already-installed, running docker-helper system service.
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

# dh is the docker-helper CLI used by the regressions (system mode).
dh() { /usr/bin/docker-helper "$@"; }

# --- shared ubuntu/deb/apparmor setup helpers --------------------------------
# Used by the Ubuntu-hosted regression groups. The collect-all runner inits the
# system service with global allowed root /home, so every /home/* home below is
# authorized for principal/session use.

# reg_setup_principal USER creates (or reuses) the OS user + docker-helper
# principal (enabled), and prints the user's home directory.
reg_setup_principal() {
  local user="$1" home admin_token launcher_http launcher_json root root_ok home_base
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
  done <<< "$(dh config allowed-root list 2>/dev/null || true)"
  if [ "$root_ok" != 1 ]; then
    if dh config allowed-root list 2>/dev/null | grep -qx '/opt'; then
      home_base="/opt"; root_ok=1
    fi
  fi
  if [ "$root_ok" != 1 ]; then
    home_base="$(dh config allowed-root list 2>/dev/null | sed -n '1p')"
  fi
  if [ -z "$home_base" ]; then
    echo "error: no global allowed root under which to place principal '$user' home" >&2
    return 1
  fi
  if ! getent passwd "$user" >/dev/null 2>&1; then
    useradd -m -d "$home_base/$user" -s /bin/bash "$user" || return 1
  fi
  home="$(getent passwd "$user" | cut -d: -f6)"
  dh principal create --system "$user" >/dev/null 2>&1 || true
  dh principal set --system "$user" enabled true >/dev/null 2>&1 || true
  # Final ownership model: a selector-less principal Session resolves to the
  # principal's inherit-scope 'default' Launcher, so that Launcher must exist
  # before any reg_session. There is no Launcher CLI command, so the admin
  # creates it over the raw control-plane API using the system admin token
  # (never printed; sent only as an Authorization header). The regression
  # runners always exercise the candidate release, which implements the
  # Launcher API, so the create must report ok:true.
  admin_token="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
  if [ -z "$admin_token" ]; then
    echo "error: could not read the admin token from /etc/docker-helper/admin.token" >&2
    return 1
  fi
  launcher_http="$(curl --silent --output /tmp/reg-launcher.json --write-out '%{http_code}' --max-time 5 \
    --unix-socket /run/docker-helper/docker-helper.sock -H "Authorization: Bearer $admin_token" \
    -H 'Content-Type: application/json' \
    -d '{"scope":"inherit"}' "http://localhost/principals/$user/launchers" 2>/dev/null || true)"
  launcher_json="$(cat /tmp/reg-launcher.json 2>/dev/null || true)"
  # Idempotent: a fresh create reports ok:true; reusing a principal whose
  # default Launcher already exists (e.g. the same guest reused across stages)
  # reports 409 launcher_exists. Either confirms the Launcher is present.
  if ! printf '%s\n' "$launcher_json" | grep -q '"ok":true' \
    && ! printf '%s\n' "$launcher_json" | grep -q '"launcher_exists"'; then
    echo "error: default launcher create for principal '$user' failed (http=$launcher_http)" >&2
    return 1
  fi
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

