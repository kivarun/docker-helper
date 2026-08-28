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

# --- result accounting -------------------------------------------------------

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
  local user="$1" home
  if ! getent passwd "$user" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$user" || return 1
  fi
  home="$(getent passwd "$user" | cut -d: -f6)"
  dh principal create --system "$user" >/dev/null 2>&1 || true
  dh principal set --system "$user" enabled true >/dev/null 2>&1 || true
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

