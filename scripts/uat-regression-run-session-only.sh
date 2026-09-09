#!/usr/bin/env bash
#
# uat-regression-run-session-only.sh — targeted UAT regression group 19 on
# Ubuntu/system-mode (deb/AppArmor); also wired into the openSUSE SELinux
# guest runner as group 7, because the invariant is platform-independent:
#
#   `run` is a data-plane operation and requires exactly a Session bearer
#   token. A Principal/Launcher credential must not be usable instead of a
#   Session token and must not provide implicit or sessionless run access.
#
# The regression settles, with reproducible black-box evidence, the external
# UAT D2 observation "run went through with a Launcher credential installed
# and no DOCKER_HELPER_SESSION_TOKEN". The canonical contract it pins:
#
#   - data-plane /run requires a Session bearer token (requireSessionCapability);
#   - the agent-facing CLI reads the bearer ONLY from
#     DOCKER_HELPER_SESSION_TOKEN (an installed credential is control-plane
#     authority and must not act as implicit run authorization);
#   - no implicit/hidden/default Session is created for run;
#   - admin authority does not substitute for Session capability on /run;
#   - a present-but-empty or present-but-wrong bearer is still not run
#     authorization (the operator observation was most plausibly stale
#     environment contamination — this regression proves contamination cannot
#     grant run access either).
#
# Subcases (independent, collect-all):
#   A. CLI run with no DOCKER_HELPER_SESSION_TOKEN (nothing installed) —
#      fail closed before any HTTP request.
#   B. Canonical `credential install` of a Launcher credential into a private
#      XDG_CONFIG_HOME: the installed credential authenticates for
#      control-plane Session listing/creation, yet CLI run still fails closed
#      without a Session token; an empty-string token fails closed; a
#      present-but-invalid canary token is refused by the daemon; the CLI
#      resolves to /usr/bin/docker-helper only.
#   C. Direct POST /run against the system socket (daemon contract, so the
#      CLI and the daemon cannot mask each other):
#      C1 no Authorization bearer;
#      C2 Authorization: Bearer <Launcher credential>;
#      C3 Authorization: Bearer <Principal credential>;
#      C4 Authorization: Bearer <admin token> (admin authority is not Session
#         capability);
#      C5 Authorization: Bearer <invalid canary Session-shaped token>.
#   D. Positive control: a real Session (created through the installed
#      Launcher credential) runs the marker workload with
#      DOCKER_HELPER_SESSION_TOKEN set, proving the negatives are not
#      endpoint/image/workspace/setup failures. Session deleted afterwards.
#   E. Credential coexistence: Launcher credential installed next to a valid
#      Session bearer — run succeeds; after the installed credential is
#      deliberately replaced with an unusable (well-formed but unknown)
#      token, the same Session bearer still runs. Data-plane authorization is
#      determined by the Session capability alone. Session deleted after.
#
# Every negative subcase also proves, black-box:
#   - the Session set before == Session set after (no implicit Session);
#   - the workspace marker a workload would write is absent (no workload);
#   - the daemon journal shows no run.start/run.rejected/run.finish in the
#     invocation window (no run Operation/container evidence; the run surface
#     is synchronous with no operation identity), and for the direct-HTTP
#     negatives that an auth.failure for /run IS present (the request reached
#     the daemon and was refused at Session auth).
#
# No bearer value is ever printed; captured output reaches a CI log only
# through the shared redact() helper.
#
# Requires: installed docker-helper system service (active), Docker reachable,
# root, curl, sudo. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see
# uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "19. Run requires Session capability"

reg_require_root
reg_require_service
reg_require_docker
reg_require_cmd curl "direct HTTP negative controls"
reg_require_cmd sudo "user-scoped CLI invocations"

IMAGE="alpine:3.24"
TMPDIR_REG19="/tmp/uat-reg19"
SOCK="/run/docker-helper/docker-helper.sock"
ADMIN_TOKEN="/etc/docker-helper/admin.token"
USER_NAME="uatreg19"
mkdir -p "$TMPDIR_REG19"
chmod 700 "$TMPDIR_REG19"

# The invoking harness environment must not carry a Session bearer: every
# controlled invocation below constructs its own environment explicitly, and
# an inherited variable here would make the fixture itself the contamination
# source this regression exists to rule out.
if [ -n "${DOCKER_HELPER_SESSION_TOKEN:-}" ]; then
  reg_fail "harness environment already carries DOCKER_HELPER_SESSION_TOKEN (contaminated runner state)"
else
  reg_ok "harness environment: DOCKER_HELPER_SESSION_TOKEN present: no"
fi

# --- fixture -----------------------------------------------------------------

home="$(reg_setup_principal "$USER_NAME")" || { reg_blocked "fixture principal setup failed"; }
ws="$home/ws-runonly"
xdg="$home/.config-uat19"
installed_cred_file="$xdg/docker-helper/credential.token"
mkdir -p "$ws" "$xdg"
chown -R "$USER_NAME:$USER_NAME" "$home"
chmod 700 "$xdg"

default_launcher_json="$(dh launcher show --system --principal "$USER_NAME" 2>/dev/null)" \
  || { reg_fail "fixture: launcher show failed"; reg_result; }
DEFAULT_LAUNCHER_ID="$(printf '%s' "$default_launcher_json" | json_field id)"
[ -n "$DEFAULT_LAUNCHER_ID" ] || { reg_fail "fixture: launcher show returned no ID"; reg_result; }

# Launcher credential (UAT-created fixture; installed canonically by the
# owning user in subcase B).
launcher_cred_out="$(dh launcher credential create --system --principal "$USER_NAME" default 2>/dev/null)" \
  || { reg_fail "fixture: launcher credential create failed"; reg_result; }
LAUNCHER_CRED_ID="$(printf '%s' "$launcher_cred_out" | grep -o '"id": "dhcr_[^"]*"' | head -1 | cut -d'"' -f4)"
LAUNCHER_CRED_TOKEN_FILE="$TMPDIR_REG19/launcher.token"
printf '%s\n' "$(printf '%s' "$launcher_cred_out" | json_field token)" > "$LAUNCHER_CRED_TOKEN_FILE"
chmod 600 "$LAUNCHER_CRED_TOKEN_FILE"
if [ -z "$LAUNCHER_CRED_ID" ] || ! grep -qE '^dhc_[0-9a-f]{64}$' "$LAUNCHER_CRED_TOKEN_FILE"; then
  reg_fail "fixture: launcher credential create returned no usable one-time token"
  reg_result
fi
# Principal credential (for the direct-HTTP Principal-bearer negative).
principal_cred_out="$(dh principal credential create --system --name default "$USER_NAME" 2>/dev/null)" \
  || { reg_fail "fixture: principal credential create failed"; reg_result; }
PRINCIPAL_CRED_ID="$(printf '%s\n' "$principal_cred_out" | sed -n 's/^  ID:    //p' | tr -d '[:space:]')"
PRINCIPAL_CRED_TOKEN_FILE="$TMPDIR_REG19/principal.token"
printf '%s\n' "$(printf '%s\n' "$principal_cred_out" | sed -n 's/^  Token: //p' | tr -d '[:space:]')" > "$PRINCIPAL_CRED_TOKEN_FILE"
chmod 600 "$PRINCIPAL_CRED_TOKEN_FILE"
grep -qE '^dhc_[0-9a-f]{64}$' "$PRINCIPAL_CRED_TOKEN_FILE" \
  || { reg_fail "fixture: principal credential create returned no usable one-time token"; reg_result; }

# The present-but-invalid canary bearer: well-formed Session-shape, never a
# real credential. Written to a file so it never appears in printed evidence.
CANARY_TOKEN_FILE="$TMPDIR_REG19/canary.token"
printf 'dht_%s\n' "$(printf 'a%.0s' $(seq 64))" > "$CANARY_TOKEN_FILE"
chmod 600 "$CANARY_TOKEN_FILE"

# --- controlled user environment ---------------------------------------------

# U_ENV is the clean user environment for every UAT user invocation: no
# inherited runner environment may leak in. The contamination vectors this
# regression rules out are precisely inherited state, wrapper entries, and
# installed-credential resolution; XDG_CONFIG_HOME isolates the installed
# credential to a private UAT location.
U_ENV=(env -i "HOME=$home" "XDG_CONFIG_HOME=$xdg" \
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")

# dhx runs docker-helper as the fixture user with the strictly controlled
# environment. dhx_env prepends additional KEY=VALUE assignments (never a
# secret in a printed form; tokens live in 0600 files under $TMPDIR_REG19).
dhx() {
  sudo -u "$USER_NAME" "${U_ENV[@]}" /usr/bin/docker-helper "$@"
}

dhx_env() { # ASSIGNMENT... -- docker-helper args...
  local assignments=()
  while [ "$1" != "--" ]; do
    assignments+=("$1")
    shift
  done
  shift
  sudo -u "$USER_NAME" env -i "HOME=$home" "XDG_CONFIG_HOME=$xdg" \
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "${assignments[@]}" /usr/bin/docker-helper "$@"
}

# --- journal window helpers ---------------------------------------------------

# journal_window E0 E1: daemon journal lines for the [E0, E1] wall-clock window.
journal_window() {
  journalctl -u docker-helper.service -o cat --utc --since "@$1" --until "@$2" 2>/dev/null || true
}

# journal_wait_for E0 PATTERN: bounded wait for a record that must appear
# (journald flush latency). Returns 0 when seen within ~6s.
journal_wait_for() { # e0 pattern
  local e0="$1" pattern="$2" tries=6
  while [ "$tries" -gt 0 ]; do
    if journal_window "$e0" "$(date +%s)" | grep -qF -- "$pattern"; then
      return 0
    fi
    tries=$((tries - 1))
    [ "$tries" -gt 0 ] && sleep 1
  done
  return 1
}

# assert_no_run_journal LABEL E0 E1 REACHED_DAEMON(yes|no): proves the
# invocation window contains no run.* audit evidence (no admitted run, no
# rejected-after-auth run, no workload completion). A flushed record cannot
# un-happen, so the absence checks are single-shot over the closed window.
# When REACHED_DAEMON=yes, an auth.failure for /run MUST be present (the
# request reached the daemon and was refused exactly at Session
# authentication); that presence check retries bounded for journald flush.
assert_no_run_journal() { # label e0 e1 reached
  local label="$1" e0="$2" e1="$3" reached="$4" w
  w="$(journal_window "$e0" "$e1")"
  if printf '%s\n' "$w" | grep -qE '"event":"run\.(start|finish|rejected)"'; then
    reg_fail "$label: run audit evidence appeared (the run Operation/container path was reached)"
    return 1
  fi
  if [ "$reached" = "yes" ]; then
    if journal_wait_for "$e0" '"event":"auth.failure"' \
      && printf '%s\n' "$(journal_window "$e0" "$(date +%s)")" | grep -q '"path":"/run"'; then
      reg_ok "$label: request reached the daemon and was refused at Session auth (auth.failure on /run)"
    else
      reg_fail "$label: expected auth.failure for /run was not observed in the journal window"
    fi
  else
    if printf '%s\n' "$w" | grep -q '"event":"auth.failure"'; then
      reg_fail "$label: an auth.failure reached the daemon although the CLI must fail before any HTTP request"
    else
      reg_ok "$label: no run.* and no auth.failure audit evidence (no daemon contact)"
    fi
  fi
}

# --- session-set helpers -------------------------------------------------------

# session_set returns the sorted Session IDs visible for the fixture principal.
session_set() {
  dh session list --system --json --principal "$USER_NAME" 2>/dev/null \
    | grep -o '"id": "dhs_[A-Za-z0-9]*"' | cut -d'"' -f4 | sort
}

assert_session_set_unchanged() { # label before after
  if [ "$2" = "$3" ]; then
    reg_ok "$1: Session set before == after (no implicit Session created)"
  else
    reg_fail "$1: Session set changed (before: $(printf '%s' "$2" | tr '\n' ' ') after: $(printf '%s' "$3" | tr '\n' ' '))"
  fi
}

# --- shared assertion helpers ---------------------------------------------------

assert_no_workload() { # label marker
  if [ -e "$ws/$2" ]; then
    reg_fail "$1: workload marker exists — a workload RAN under rejected authority"
  else
    reg_ok "$1: workload marker absent (no workload executed)"
  fi
}

assert_cli_fail_closed() { # label expected_stderr_fragment
  if [ "$CLI_RC" = 0 ]; then
    reg_fail "$1: run exited 0 — FAIL-CLOSED violated (stderr: $(head -3 "$TMPDIR_REG19/cli.err" | redact | tr '\n' ' '))"
    return 1
  fi
  if ! grep -qF "$2" "$TMPDIR_REG19/cli.err"; then
    reg_fail "$1: stderr missed the expected diagnostic (rc=$CLI_RC, stderr: $(head -3 "$TMPDIR_REG19/cli.err" | redact | tr '\n' ' '))"
    return 1
  fi
  reg_ok "$1: run rejected (rc=$CLI_RC, \"$2\")"
}

# cli_run MARKER [ASSIGNMENT...] runs the canonical CLI run invocation as the
# fixture user with the controlled environment and captures CLI_RC plus
# stdout/stderr in files. Each ASSIGNMENT is a KEY=VALUE environment entry
# for the CLI process only.
cli_run() { # marker [assignment...]
  local marker="$1"
  shift
  local script="echo UAT19-RAN > /workspace/$marker; echo finished"
  if [ "$#" -gt 0 ]; then
    dhx_env "$@" -- run --system --image "$IMAGE" \
      --mount .:/workspace \
      -- sh -ec "$script" \
      >"$TMPDIR_REG19/cli.out" 2>"$TMPDIR_REG19/cli.err"
  else
    dhx run --system --image "$IMAGE" \
      --mount .:/workspace \
      -- sh -ec "$script" \
      >"$TMPDIR_REG19/cli.out" 2>"$TMPDIR_REG19/cli.err"
  fi
  CLI_RC=$?
}

# http_run_negative LABEL MARKER AUTHFILE writes the run request (the workload
# the request WOULD execute) and POSTs it to the system socket, optionally
# with one Authorization header built from a 0600 file (the bearer value never
# appears in an argv or in the log). Captures HTTP_STATUS and the response.
http_run_negative() { # label marker authfile
  local label="$1" marker="$2" authfile="$3"
  local body="$TMPDIR_REG19/body.json"
  printf '{"image":"%s","command":["sh","-ec","echo UAT19-RAN > /workspace/%s; echo finished"],"mounts":[{"source":".","target":"/workspace"}]}\n' \
    "$IMAGE" "$marker" > "$body"
  chmod 600 "$body"
  local -a curl_args=(
    -sS -o "$TMPDIR_REG19/http.out" -w '%{http_code}'
    --unix-socket "$SOCK" -X POST http://localhost/run
    -H 'Content-Type: application/json'
    --data-binary "@$body"
  )
  if [ -n "$authfile" ]; then
    printf 'Authorization: Bearer %s\n' "$(cat "$authfile")" > "$TMPDIR_REG19/auth.header"
    chmod 600 "$TMPDIR_REG19/auth.header"
    curl_args+=(--header "@$TMPDIR_REG19/auth.header")
  fi
  HTTP_STATUS="$(curl "${curl_args[@]}")"
  HTTP_RC=$?
}

assert_http_session_auth_failure() { # label
  if [ "$HTTP_RC" -ne 0 ]; then
    reg_fail "$1: curl transport failure against the system socket (rc=$HTTP_RC)"
    return 1
  fi
  if [ "$HTTP_STATUS" != "401" ]; then
    reg_fail "$1: expected HTTP 401, got $HTTP_STATUS ($(redact <"$TMPDIR_REG19/http.out" | head -1))"
    return 1
  fi
  if ! grep -q '"code":"unauthorized"' "$TMPDIR_REG19/http.out" \
    || ! grep -qF '"message":"Session authentication required."' "$TMPDIR_REG19/http.out"; then
    reg_fail "$1: unauthorized body missed the non-disclosing Session-auth contract ($(redact <"$TMPDIR_REG19/http.out" | head -1))"
    return 1
  fi
  reg_ok "$1: HTTP 401 unauthorized / \"Session authentication required.\""
}

# ---------------------------------------------------------------------------
# Subcase A: CLI run with no DOCKER_HELPER_SESSION_TOKEN, nothing installed.
# The CLI must fail closed before any HTTP request.
# ---------------------------------------------------------------------------
subcase_a() {
  reg_info "subcase A: CLI run without DOCKER_HELPER_SESSION_TOKEN"
  local marker="uat19-a.marker" s_before s_after e0 e1
  rm -f "$ws/$marker"
  s_before="$(session_set)"
  reg_info "invocation env: DOCKER_HELPER_SESSION_TOKEN present: no"
  e0="$(date +%s)"
  cli_run "$marker"
  e1="$(date +%s)"
  assert_cli_fail_closed "A" "DOCKER_HELPER_SESSION_TOKEN is not set" || return
  assert_no_workload "A" "$marker"
  assert_no_run_journal "A" "$e0" "$e1" no
  s_after="$(session_set)"
  assert_session_set_unchanged "A" "$s_before" "$s_after"
}

# ---------------------------------------------------------------------------
# Subcase B: canonical Launcher-credential install (private XDG_CONFIG_HOME),
# then the CLI negative matrix with the installed credential present.
# ---------------------------------------------------------------------------
subcase_b() {
  reg_info "subcase B: installed Launcher credential is not implicit run authorization"
  local marker s_before s_after e0 e1 out

  # B0: canonical install by the owning user (never as root). The redirect
  # is opened by the invoking (root) shell so the owning user receives the
  # one-time token on stdin without gaining file access.
  # shellcheck disable=SC2024
  if sudo -u "$USER_NAME" "${U_ENV[@]}" \
    /usr/bin/docker-helper credential install --force \
    < "$LAUNCHER_CRED_TOKEN_FILE" >"$TMPDIR_REG19/install.out" 2>"$TMPDIR_REG19/install.err"; then
    reg_ok "B: Launcher credential installed at \$XDG_CONFIG_HOME/docker-helper/credential.token"
  else
    reg_fail "B: canonical credential install failed ($(head -2 "$TMPDIR_REG19/install.err" | redact | tr '\n' ' '))"
    return
  fi
  if [ -f "$installed_cred_file" ]; then
    reg_ok "B: installed credential file exists"
  else
    reg_fail "B: installed credential file missing at $installed_cred_file"
    return
  fi
  local mode
  mode="$(stat -c '%a' "$installed_cred_file" 2>/dev/null || true)"
  if [ "$mode" = "600" ]; then
    reg_ok "B: installed credential file mode 0600"
  else
    reg_fail "B: installed credential file mode is $mode, want 600"
  fi
  if grep -qE '^dhc_[0-9a-f]{64}$' "$installed_cred_file"; then
    reg_ok "B: installed credential is a well-formed Launcher credential token (value not printed)"
  else
    reg_fail "B: installed credential file does not contain the expected token format"
  fi

  # B1: the installed credential IS active control-plane authority.
  if out="$(dhx session list --system --json 2>"$TMPDIR_REG19/b1.err")"; then
    reg_ok "B: installed Launcher credential authenticates a control-plane operation (session list)"
  else
    reg_fail "B: installed Launcher credential failed a control-plane operation ($(head -2 "$TMPDIR_REG19/b1.err" | redact | tr '\n' ' '))"
    return
  fi

  # B2: CLI run with no session token, installed credential present.
  marker="uat19-b2.marker"
  rm -f "$ws/$marker"
  s_before="$(session_set)"
  reg_info "invocation env: DOCKER_HELPER_SESSION_TOKEN present: no (installed credential present)"
  e0="$(date +%s)"
  cli_run "$marker"
  e1="$(date +%s)"
  assert_cli_fail_closed "B2" "DOCKER_HELPER_SESSION_TOKEN is not set" || return
  assert_no_workload "B2" "$marker"
  assert_no_run_journal "B2" "$e0" "$e1" no
  s_after="$(session_set)"
  assert_session_set_unchanged "B2" "$s_before" "$s_after"

  # B3: present-but-empty bearer (temporary env prefix contamination vector).
  marker="uat19-b3.marker"
  rm -f "$ws/$marker"
  reg_info "invocation env: DOCKER_HELPER_SESSION_TOKEN present: yes (empty value)"
  cli_run "$marker" "DOCKER_HELPER_SESSION_TOKEN="
  assert_cli_fail_closed "B3" "DOCKER_HELPER_SESSION_TOKEN is not set" || return
  assert_no_workload "B3" "$marker"

  # B4: present-but-invalid canary bearer (stale/wrong token contamination).
  marker="uat19-b4.marker"
  rm -f "$ws/$marker"
  s_before="$(session_set)"
  reg_info "invocation env: DOCKER_HELPER_SESSION_TOKEN present: yes (invalid canary bearer)"
  e0="$(date +%s)"
  cli_run "$marker" "DOCKER_HELPER_SESSION_TOKEN=$(cat "$CANARY_TOKEN_FILE")"
  e1="$(date +%s)"
  assert_cli_fail_closed "B4" "Session authentication required" || return
  assert_no_workload "B4" "$marker"
  assert_no_run_journal "B4" "$e0" "$e1" yes
  s_after="$(session_set)"
  assert_session_set_unchanged "B4" "$s_before" "$s_after"

  # B5: the CLI resolution inside the controlled environment.
  if [ "$(sudo -u "$USER_NAME" "${U_ENV[@]}" sh -c 'command -v docker-helper')" = "/usr/bin/docker-helper" ]; then
    reg_ok "B: docker-helper resolves to /usr/bin/docker-helper only (no wrapper/shadowing entry)"
  else
    reg_fail "B: docker-helper resolution in the controlled environment is unexpected"
  fi
}

# ---------------------------------------------------------------------------
# Subcase C: direct HTTP negatives against the system socket — the daemon
# contract, independent of any CLI behavior.
# ---------------------------------------------------------------------------
subcase_c() {
  reg_info "subcase C: direct POST /run negative controls on the system socket"
  local marker s_before s_after e0 e1

  # C1: no Authorization bearer.
  marker="uat19-c1.marker"
  rm -f "$ws/$marker"
  s_before="$(session_set)"
  e0="$(date +%s)"
  http_run_negative "C1" "$marker" ""
  e1="$(date +%s)"
  assert_http_session_auth_failure "C1" || return
  assert_no_workload "C1" "$marker"
  assert_no_run_journal "C1" "$e0" "$e1" yes
  s_after="$(session_set)"
  assert_session_set_unchanged "C1" "$s_before" "$s_after"

  # C2: Launcher credential as the bearer.
  marker="uat19-c2.marker"
  rm -f "$ws/$marker"
  s_before="$(session_set)"
  e0="$(date +%s)"
  http_run_negative "C2" "$marker" "$LAUNCHER_CRED_TOKEN_FILE"
  e1="$(date +%s)"
  assert_http_session_auth_failure "C2" || return
  assert_no_workload "C2" "$marker"
  assert_no_run_journal "C2" "$e0" "$e1" yes
  s_after="$(session_set)"
  assert_session_set_unchanged "C2" "$s_before" "$s_after"

  # C3: Principal credential as the bearer.
  marker="uat19-c3.marker"
  rm -f "$ws/$marker"
  s_before="$(session_set)"
  e0="$(date +%s)"
  http_run_negative "C3" "$marker" "$PRINCIPAL_CRED_TOKEN_FILE"
  e1="$(date +%s)"
  assert_http_session_auth_failure "C3" || return
  assert_no_workload "C3" "$marker"
  assert_no_run_journal "C3" "$e0" "$e1" yes
  s_after="$(session_set)"
  assert_session_set_unchanged "C3" "$s_before" "$s_after"

  # C4: admin bearer — admin authority is not Session capability.
  marker="uat19-c4.marker"
  rm -f "$ws/$marker"
  s_before="$(session_set)"
  e0="$(date +%s)"
  http_run_negative "C4" "$marker" "$ADMIN_TOKEN"
  e1="$(date +%s)"
  assert_http_session_auth_failure "C4" || return
  assert_no_workload "C4" "$marker"
  assert_no_run_journal "C4" "$e0" "$e1" yes
  s_after="$(session_set)"
  assert_session_set_unchanged "C4" "$s_before" "$s_after"

  # C5: invalid canary Session-shaped bearer.
  marker="uat19-c5.marker"
  rm -f "$ws/$marker"
  s_before="$(session_set)"
  e0="$(date +%s)"
  http_run_negative "C5" "$marker" "$CANARY_TOKEN_FILE"
  e1="$(date +%s)"
  assert_http_session_auth_failure "C5" || return
  assert_no_workload "C5" "$marker"
  assert_no_run_journal "C5" "$e0" "$e1" yes
  s_after="$(session_set)"
  assert_session_set_unchanged "C5" "$s_before" "$s_after"
}

# create_fixture_session LABEL: creates a real Session under the fixture
# Launcher through the installed credential (control-plane authority of the
# install path), writes the bearer to a 0600 file, and proves the Session
# belongs to the expected Launcher and workspace. Prints nothing but the
# Session ID shape. SID_FILE/STOK_FILE are set as globals on success.
create_fixture_session() { # label
  local label="$1" out
  if ! out="$(dhx session create --system --workspace "$ws" --json 2>"$TMPDIR_REG19/create.err")"; then
    reg_fail "$label: session create through the installed Launcher credential failed ($(head -2 "$TMPDIR_REG19/create.err" | redact | tr '\n' ' '))"
    return 1
  fi
  printf '%s\n' "$out" > "$TMPDIR_REG19/session-create.json"
  chmod 600 "$TMPDIR_REG19/session-create.json"
  SID_FILE="$TMPDIR_REG19/sid"
  STOK_FILE="$TMPDIR_REG19/stok"
  printf '%s\n' "$(printf '%s' "$out" | grep -o '"id": "dhs_[A-Za-z0-9]*"' | head -1 | cut -d'"' -f4)" > "$SID_FILE"
  printf '%s\n' "$(printf '%s' "$out" | json_field token)" > "$STOK_FILE"
  chmod 600 "$SID_FILE" "$STOK_FILE"
  local sid stok
  sid="$(cat "$SID_FILE")"
  stok="$(cat "$STOK_FILE")"
  if [ -z "$sid" ] || [ -z "$stok" ]; then
    reg_fail "$label: session create returned no Session identity"
    return 1
  fi
  if printf '%s' "$out" | grep -qF "\"launcher_id\": \"$DEFAULT_LAUNCHER_ID\"" \
    && printf '%s' "$out" | grep -qF "\"workspace\": \"$ws\""; then
    reg_ok "$label: Session $sid belongs to the expected Launcher and workspace"
  else
    reg_fail "$label: created Session does not carry the expected Launcher/workspace binding"
    return 1
  fi
  return 0
}

delete_fixture_session() { # label sid
  if dh session delete --system --id "$2" >/dev/null 2>&1; then
    reg_ok "$1: fixture Session deleted"
  else
    reg_fail "$1: fixture Session delete failed"
  fi
}

# ---------------------------------------------------------------------------
# Subcase D: positive control — a real Session token runs the marker workload.
# ---------------------------------------------------------------------------
subcase_d() {
  reg_info "subcase D: positive control (Session bearer runs the workload)"
  local marker="uat19-d.marker" s_before s_after e0 e1 sid stok
  rm -f "$ws/$marker"
  s_before="$(session_set)"
  create_fixture_session "D" || return
  sid="$(cat "$TMPDIR_REG19/sid")"
  stok="$(cat "$TMPDIR_REG19/stok")"
  s_after="$(session_set)"
  if printf '%s' "$s_after" | grep -qF "$sid"; then
    reg_ok "D: fixture Session is visible to Session list (created, not implicit)"
  else
    reg_fail "D: fixture Session missing from the Session list"
  fi

  reg_info "invocation env: DOCKER_HELPER_SESSION_TOKEN present: yes (real Session bearer)"
  e0="$(date +%s)"
  cli_run "$marker" "DOCKER_HELPER_SESSION_TOKEN=$stok"
  e1="$(date +%s)"
  if [ "$CLI_RC" = 0 ] && [ "$(cat "$ws/$marker" 2>/dev/null || true)" = "UAT19-RAN" ]; then
    reg_ok "D: run with a real Session bearer executed the marker workload (exit 0, marker content)"
  else
    reg_fail "D: run with a real Session bearer did not execute the workload (rc=$CLI_RC, stderr: $(head -3 "$TMPDIR_REG19/cli.err" | redact | tr '\n' ' '))"
    delete_fixture_session "D (cleanup)" "$sid"
    return
  fi
  if journal_wait_for "$e0" '"event":"run.start"' && printf '%s' "$(journal_window "$e0" "$(date +%s)")" | grep -q '"event":"run.finish"'; then
    reg_ok "D: run.start/run.finish audit evidence present for the admitted run"
  else
    reg_fail "D: run.start/run.finish audit evidence missing for the admitted run"
  fi

  delete_fixture_session "D" "$sid"
  s_after="$(session_set)"
  assert_session_set_unchanged "D (post-delete)" "$s_before" "$s_after"
}

# ---------------------------------------------------------------------------
# Subcase E: credential coexistence — Launcher credential installed next to a
# valid Session bearer; the data plane is determined by the Session
# capability alone.
# ---------------------------------------------------------------------------
subcase_e() {
  reg_info "subcase E: installed credential coexists with the Session bearer without granting run"
  local marker="uat19-e1.marker" marker2="uat19-e2.marker" s_before s_after sid stok
  rm -f "$ws/$marker" "$ws/$marker2"
  s_before="$(session_set)"
  create_fixture_session "E" || return
  sid="$(cat "$TMPDIR_REG19/sid")"
  stok="$(cat "$TMPDIR_REG19/stok")"

  # E1: installed Launcher credential + valid Session bearer -> run succeeds.
  cli_run "$marker" "DOCKER_HELPER_SESSION_TOKEN=$stok"
  if [ "$CLI_RC" = 0 ] && [ "$(cat "$ws/$marker" 2>/dev/null || true)" = "UAT19-RAN" ]; then
    reg_ok "E1: run succeeds with the Launcher credential installed next to the Session bearer"
  else
    reg_fail "E1: run failed although both authorities were present (rc=$CLI_RC, stderr: $(head -3 "$TMPDIR_REG19/cli.err" | redact | tr '\n' ' '))"
    delete_fixture_session "E (cleanup)" "$sid"
    return
  fi

  # E2: replace the installed credential with a deliberately unusable
  # (well-formed but unknown) token through the canonical install path; the
  # same Session bearer must still run.
  # shellcheck disable=SC2024
  if ! printf 'dhc_%s\n' "$(printf '0%.0s' $(seq 64))" \
    | sudo -u "$USER_NAME" "${U_ENV[@]}" /usr/bin/docker-helper credential install --force \
    >"$TMPDIR_REG19/install2.out" 2>"$TMPDIR_REG19/install2.err"; then
    reg_fail "E: unusable-credential install failed ($(head -2 "$TMPDIR_REG19/install2.err" | redact | tr '\n' ' '))"
    delete_fixture_session "E (cleanup)" "$sid"
    return
  fi
  cli_run "$marker2" "DOCKER_HELPER_SESSION_TOKEN=$stok"
  if [ "$CLI_RC" = 0 ] && [ "$(cat "$ws/$marker2" 2>/dev/null || true)" = "UAT19-RAN" ]; then
    reg_ok "E2: run still succeeds with an unusable installed credential — data plane follows the Session capability alone"
  else
    reg_fail "E2: run failed with an unusable installed credential (rc=$CLI_RC, stderr: $(head -3 "$TMPDIR_REG19/cli.err" | redact | tr '\n' ' '))"
  fi

  delete_fixture_session "E" "$sid"
  s_after="$(session_set)"
  assert_session_set_unchanged "E (post-delete)" "$s_before" "$s_after"
}

subcase_a
subcase_b
subcase_c
subcase_d
subcase_e

# --- best-effort cleanup (kept for evidence on failure) ----------------------
dh launcher credential delete --system --principal "$USER_NAME" default >/dev/null 2>&1 || true
dh principal credential revoke --system "$PRINCIPAL_CRED_ID" >/dev/null 2>&1 || true
dh principal delete --system "$USER_NAME" >/dev/null 2>&1 || true
userdel -r "$USER_NAME" >/dev/null 2>&1 || true
rm -rf "$TMPDIR_REG19"

reg_result
