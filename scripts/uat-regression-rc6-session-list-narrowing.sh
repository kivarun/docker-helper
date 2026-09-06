#!/usr/bin/env bash
#
# uat-regression-rc6-session-list-narrowing.sh — Release-2.1 RC6 targeted
# regression group 13: scope-first session-list narrowing acceptance
# (Ubuntu / DEB / AppArmor).
#
# The RC5 selector UAT did not exercise `session list`, so the missing
# Release-2.1 narrowing contract escaped. This group is the dedicated
# packaged CLI/daemon black-box regression for it, exercised through the
# installed CLI/daemon (the exact public R2.1 paths):
#
#   A. admin narrowing — the unfiltered list and every --principal /
#      --launcher narrowing returns exactly the requested ownership scope;
#      a dhl_ ID narrows without --principal, a Launcher name without
#      --principal is rejected instead of searched globally, and a foreign
#      Launcher under a named Principal fails non-disclosing.
#   B. Principal-credential narrowing — the unfiltered list stays inside
#      the credential's own Principal, --launcher (name and dhl_ ID)
#      narrows inside that scope, a foreign Launcher fails non-disclosing,
#      and --principal is rejected even when it names the credential's own
#      Principal.
#   C. Launcher-credential authority — the selector-less list remains
#      restricted to its own Launcher's sessions and narrowing selectors
#      stay rejected (no redundant second contract).
#   D. help and completion surface — `session list --help` shows both
#      narrowing selectors and the generated Bash completion offers them
#      for `docker-helper session list --`, so the flags cannot disappear
#      again unnoticed.
#
# Fixture per narrowing subcase:
#   Principal A: default Launcher (Session A-default), alpha Launcher
#                (Session A-alpha)
#   Principal B: default Launcher (Session B-default), beta Launcher
#                (Session B-beta)
#
# Each subcase uses its own OS users/Principals so results are independent.
# A subcase failure does not stop the others (collect-all).
#
# Requires: installed docker-helper system service (active), root, bash.
# Docker is not required (no data-plane operations).
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "13. RC6 session-list narrowing acceptance"

reg_require_root
reg_require_service
reg_require_cmd bash "completion acceptance drives a real Bash"

TMPDIR_REG13="/tmp/uat-reg13"
mkdir -p "$TMPDIR_REG13"

# session_list_contains JSON SID: the listed --json document contains SID.
session_list_contains() {
  printf '%s' "$1" | grep -q "\"id\": \"$2\""
}

# assert_narrowed LABEL JSON PRESENT_IDS ABSENT_IDS: PRESENT_IDS and
# ABSENT_IDS are '|' separated Session IDs; every present ID must be listed
# and every absent ID must not be.
assert_narrowed() {
  local label="$1" json="$2" present_csv="$3" absent_csv="$4"
  local sid rc=0
  for sid in $(printf '%s' "$present_csv" | tr '|' ' '); do
    if session_list_contains "$json" "$sid"; then
      reg_ok "$label: lists $sid"
    else
      reg_fail "$label: expected Session $sid missing from the list"
      rc=1
    fi
  done
  for sid in $(printf '%s' "$absent_csv" | tr '|' ' '); do
    if session_list_contains "$json" "$sid"; then
      reg_fail "$label: narrowed list leaked $sid"
      rc=1
    fi
  done
  [ "$rc" = 0 ]
}

# cleanup_sessions SID...: best-effort teardown shared by every subcase.
cleanup_sessions() {
  local sid
  for sid in "$@"; do
    [ -n "$sid" ] && dh session delete --system --id "$sid" >/dev/null 2>&1 || true
  done
}

# cleanup_principal USER: best-effort teardown shared by every subcase.
cleanup_principal() {
  local user="$1"
  dh principal delete --system "$user" >/dev/null 2>&1 || true
  userdel -r "$user" >/dev/null 2>&1 || true
}

# setup_pair USER_A USER_B: provision the A/B Principal pair, create each
# Principal's extra Launcher (alpha/beta), and print one line with the
# fixture state (alpha dhl_ ID, beta dhl_ ID, home A, home B — bare values,
# space separated, read positionally). Returns non-zero on setup failure.
setup_pair() {
  local user_a="$1" user_b="$2" home_a home_b alpha_out beta_out
  home_a="$(reg_setup_principal "$user_a")" || return 1
  home_b="$(reg_setup_principal "$user_b")" || return 1

  alpha_out="$(dh launcher create --system --principal "$user_a" --name alpha --no-credential 2>&1)" || {
    echo "error: alpha launcher create failed: $(printf '%s' "$alpha_out" | head -2 | tr '\n' ' ')" >&2
    return 1
  }
  beta_out="$(dh launcher create --system --principal "$user_b" --name beta --no-credential 2>&1)" || {
    echo "error: beta launcher create failed: $(printf '%s' "$beta_out" | head -2 | tr '\n' ' ')" >&2
    return 1
  }

  printf '%s %s %s %s\n' \
    "$(printf '%s' "$alpha_out" | json_field id)" \
    "$(printf '%s' "$beta_out" | json_field id)" \
    "$home_a" "$home_b"
}

create_session() { # cred workspace extra-args...
  local cred="$1" ws="$2" out rc
  shift 2
  out="$(dh session create --system --token-file "$cred" --workspace "$ws" --json "$@" 2>"$TMPDIR_REG13/last-session-create.err")"
  rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$out" ]; then
    head -2 "$TMPDIR_REG13/last-session-create.err" >&2
    return 1
  fi
  printf '%s' "$out" | json_field id
}

# ---------------------------------------------------------------------------
# A. admin narrowing
# ---------------------------------------------------------------------------
subcase_a() {
  reg_info "subcase A: admin narrowing"
  local user_a="uatreg13a" user_b="uatreg13b" fx
  local ALPHA_ID BETA_ID HOME_A HOME_B
  fx="$(setup_pair "$user_a" "$user_b")" || { reg_fail "A: fixture setup failed"; return; }
  read -r ALPHA_ID BETA_ID HOME_A HOME_B <<<"$fx"

  local cred_a="$TMPDIR_REG13/a.token"
  reg_principal_credential "$user_a" "$cred_a" || { reg_fail "A: principal credential create failed"; return; }
  local cred_b="$TMPDIR_REG13/b.token"
  reg_principal_credential "$user_b" "$cred_b" || { reg_fail "A: principal credential create failed (B)"; return; }

  mkdir -p "$HOME_A/a-ws" "$HOME_A/a-extra" "$HOME_B/b-ws" "$HOME_B/b-extra"
  chown -R "$user_a:$user_a" "$HOME_A"
  chown -R "$user_b:$user_b" "$HOME_B"

  local sid_ad sid_aa sid_bd sid_bb
  sid_ad="$(create_session "$cred_a" "$HOME_A/a-ws")"
  sid_aa="$(create_session "$cred_a" "$HOME_A/a-extra" --launcher alpha)"
  sid_bd="$(create_session "$cred_b" "$HOME_B/b-ws")"
  sid_bb="$(create_session "$cred_b" "$HOME_B/b-extra" --launcher beta)"
  for sid in "$sid_ad" "$sid_aa" "$sid_bd" "$sid_bb"; do
    [ -n "$sid" ] || { reg_fail "A: fixture Session create failed"; cleanup_sessions "$sid_ad" "$sid_aa" "$sid_bd" "$sid_bb"; cleanup_principal "$user_a"; cleanup_principal "$user_b"; rm -f "$cred_a" "$cred_b"; return; }
  done

  local out
  # 1. unfiltered list contains all four fixture Sessions.
  out="$(dh session list --system --json 2>/dev/null)"
  assert_narrowed "A1 unfiltered" "$out" "$sid_ad|$sid_aa|$sid_bd|$sid_bb" ""

  # 2. --principal A lists A's sessions and excludes B's.
  out="$(dh session list --system --principal "$user_a" --json 2>/dev/null)"
  assert_narrowed "A2 --principal A" "$out" "$sid_ad|$sid_aa" "$sid_bd|$sid_bb"

  # 3. --principal B lists B's sessions and excludes A's.
  out="$(dh session list --system --principal "$user_b" --json 2>/dev/null)"
  assert_narrowed "A3 --principal B" "$out" "$sid_bd|$sid_bb" "$sid_ad|$sid_aa"

  # 4. --principal A --launcher alpha returns only A-alpha.
  out="$(dh session list --system --principal "$user_a" --launcher alpha --json 2>/dev/null)"
  assert_narrowed "A4 --principal A --launcher alpha" "$out" "$sid_aa" "$sid_ad|$sid_bd|$sid_bb"

  # 5. --launcher <alpha dhl ID> without Principal returns only A-alpha.
  out="$(dh session list --system --launcher "$ALPHA_ID" --json 2>/dev/null)"
  assert_narrowed "A5 --launcher <alpha ID>" "$out" "$sid_aa" "$sid_ad|$sid_bd|$sid_bb"

  # 6. --launcher alpha without Principal fails instead of resolving the
  #    name globally.
  local name_err name_rc
  name_err="$(dh session list --system --launcher alpha --json 2>&1)"; name_rc=$?
  if [ "$name_rc" -ne 0 ] && printf '%s' "$name_err" | grep -q 'launcher_name_requires_principal'; then
    reg_ok "A6: --launcher alpha without --principal is rejected, not searched globally"
  else
    reg_fail "A6: name-shaped --launcher without --principal was not rejected (rc=$name_rc): $(printf '%s' "$name_err" | head -2 | tr '\n' ' ')"
  fi

  # 7. --principal A --launcher <B beta dhl ID> fails non-disclosing.
  local foreign_err foreign_rc
  foreign_err="$(dh session list --system --principal "$user_a" --launcher "$BETA_ID" --json 2>&1)"; foreign_rc=$?
  if [ "$foreign_rc" -ne 0 ] \
      && printf '%s' "$foreign_err" | grep -q 'launcher not found' \
      && ! printf '%s' "$foreign_err" | grep -q "$BETA_ID"; then
    reg_ok "A7: foreign Launcher under a named Principal fails non-disclosing"
  else
    reg_fail "A7: foreign Launcher narrowing did not fail non-disclosing (rc=$foreign_rc): $(printf '%s' "$foreign_err" | head -2 | tr '\n' ' ')"
  fi

  cleanup_sessions "$sid_ad" "$sid_aa" "$sid_bd" "$sid_bb"
  cleanup_principal "$user_a"
  cleanup_principal "$user_b"
  rm -f "$cred_a" "$cred_b"
}

# ---------------------------------------------------------------------------
# B. Principal-credential narrowing
# ---------------------------------------------------------------------------
subcase_b() {
  reg_info "subcase B: Principal-credential narrowing"
  local user_a="uatreg13c" user_b="uatreg13d" fx
  local ALPHA_ID BETA_ID HOME_A HOME_B
  fx="$(setup_pair "$user_a" "$user_b")" || { reg_fail "B: fixture setup failed"; return; }
  read -r ALPHA_ID BETA_ID HOME_A HOME_B <<<"$fx"

  local cred_a="$TMPDIR_REG13/b.token"
  reg_principal_credential "$user_a" "$cred_a" || { reg_fail "B: principal credential create failed"; return; }
  local cred_b="$TMPDIR_REG13/b2.token"
  reg_principal_credential "$user_b" "$cred_b" || { reg_fail "B: principal credential create failed (B)"; return; }

  mkdir -p "$HOME_A/b-ws" "$HOME_A/b-extra" "$HOME_B/b-ws2" "$HOME_B/b-extra2"
  chown -R "$user_a:$user_a" "$HOME_A"
  chown -R "$user_b:$user_b" "$HOME_B"

  local sid_ad sid_aa sid_bd sid_bb
  sid_ad="$(create_session "$cred_a" "$HOME_A/b-ws")"
  sid_aa="$(create_session "$cred_a" "$HOME_A/b-extra" --launcher alpha)"
  sid_bd="$(create_session "$cred_b" "$HOME_B/b-ws2")"
  sid_bb="$(create_session "$cred_b" "$HOME_B/b-extra2" --launcher beta)"
  for sid in "$sid_ad" "$sid_aa" "$sid_bd" "$sid_bb"; do
    [ -n "$sid" ] || { reg_fail "B: fixture Session create failed"; cleanup_sessions "$sid_ad" "$sid_aa" "$sid_bd" "$sid_bb"; cleanup_principal "$user_a"; cleanup_principal "$user_b"; rm -f "$cred_a" "$cred_b"; return; }
  done

  local out
  # 8. unfiltered list sees A's sessions and not B's.
  out="$(dh session list --system --token-file "$cred_a" --json 2>/dev/null)"
  assert_narrowed "B8 unfiltered" "$out" "$sid_ad|$sid_aa" "$sid_bd|$sid_bb"

  # 9. --launcher alpha (name) returns only A-alpha.
  out="$(dh session list --system --token-file "$cred_a" --launcher alpha --json 2>/dev/null)"
  assert_narrowed "B9 --launcher alpha" "$out" "$sid_aa" "$sid_ad|$sid_bd|$sid_bb"

  # 10. --launcher <alpha dhl ID> returns only A-alpha.
  out="$(dh session list --system --token-file "$cred_a" --launcher "$ALPHA_ID" --json 2>/dev/null)"
  assert_narrowed "B10 --launcher <alpha ID>" "$out" "$sid_aa" "$sid_ad|$sid_bd|$sid_bb"

  # 11. foreign B Launcher fails non-disclosing.
  local f_err f_rc
  f_err="$(dh session list --system --token-file "$cred_a" --launcher "$BETA_ID" --json 2>&1)"; f_rc=$?
  if [ "$f_rc" -ne 0 ] \
      && printf '%s' "$f_err" | grep -q 'launcher not found' \
      && ! printf '%s' "$f_err" | grep -q "$BETA_ID"; then
    reg_ok "B11: foreign Launcher fails non-disclosing"
  else
    reg_fail "B11: foreign Launcher narrowing did not fail non-disclosing (rc=$f_rc): $(printf '%s' "$f_err" | head -2 | tr '\n' ' ')"
  fi

  # 12. --principal A is rejected for Principal authority even for self.
  local p_err p_rc
  p_err="$(dh session list --system --token-file "$cred_a" --principal "$user_a" --json 2>&1)"; p_rc=$?
  if [ "$p_rc" -ne 0 ] && printf '%s' "$p_err" | grep -q 'invalid_selector'; then
    reg_ok "B12: --principal is rejected for Principal authority"
  else
    reg_fail "B12: --principal was not rejected for Principal authority (rc=$p_rc): $(printf '%s' "$p_err" | head -2 | tr '\n' ' ')"
  fi

  cleanup_sessions "$sid_ad" "$sid_aa" "$sid_bd" "$sid_bb"
  cleanup_principal "$user_a"
  cleanup_principal "$user_b"
  rm -f "$cred_a" "$cred_b"
}

# ---------------------------------------------------------------------------
# C. Launcher-credential authority
# ---------------------------------------------------------------------------
subcase_c() {
  reg_info "subcase C: Launcher-credential authority"
  local user_a="uatreg13e" user_b="uatreg13f" fx
  local ALPHA_ID BETA_ID HOME_A HOME_B
  fx="$(setup_pair "$user_a" "$user_b")" || { reg_fail "C: fixture setup failed"; return; }
  read -r ALPHA_ID BETA_ID HOME_A HOME_B <<<"$fx"

  local cred_a="$TMPDIR_REG13/c.token"
  reg_principal_credential "$user_a" "$cred_a" || { reg_fail "C: principal credential create failed"; return; }

  mkdir -p "$HOME_A/c-ws" "$HOME_A/c-extra"
  chown -R "$user_a:$user_a" "$HOME_A"

  # Issue the alpha Launcher credential (the positional selector is the
  # Launcher's global dhl_ ID).
  local lc_out lc_token lc_cred
  lc_out="$(dh launcher credential create --system --principal "$user_a" "$ALPHA_ID" 2>"$TMPDIR_REG13/lc.err")"
  lc_token="$(printf '%s' "$lc_out" | json_field token || true)"
  if [ -z "$lc_token" ]; then
    reg_fail "C: launcher credential create failed: $(head -2 "$TMPDIR_REG13/lc.err" 2>/dev/null | tr '\n' ' ')"
    return
  fi
  lc_cred="$TMPDIR_REG13/c.lc.token"
  printf '%s\n' "$lc_token" > "$lc_cred"; chmod 600 "$lc_cred"

  local sid_ad sid_aa
  sid_ad="$(create_session "$cred_a" "$HOME_A/c-ws")"
  sid_aa="$(create_session "$lc_cred" "$HOME_A/c-extra")"
  [ -n "$sid_ad" ] && [ -n "$sid_aa" ] || { reg_fail "C: fixture Session create failed"; cleanup_sessions "$sid_ad" "$sid_aa"; cleanup_principal "$user_a"; cleanup_principal "$user_b"; rm -f "$cred_a" "$lc_cred"; return; }

  local out
  # 13. selector-less list remains restricted to the launcher's own Sessions:
  #     A-alpha present, A-default (same Principal, other launcher) absent.
  out="$(dh session list --system --token-file "$lc_cred" --json 2>/dev/null)"
  assert_narrowed "C13 launcher list stays own-scoped" "$out" "$sid_aa" "$sid_ad"

  # Narrowing selectors stay rejected for this authority (no redundant
  # second contract).
  local s_err s_rc
  s_err="$(dh session list --system --token-file "$lc_cred" --launcher "$ALPHA_ID" --json 2>&1)"; s_rc=$?
  if [ "$s_rc" -ne 0 ] && printf '%s' "$s_err" | grep -q 'invalid_selector'; then
    reg_ok "C: launcher-credential --launcher selector stays rejected"
  else
    reg_fail "C: launcher-credential --launcher selector was not rejected (rc=$s_rc): $(printf '%s' "$s_err" | head -2 | tr '\n' ' ')"
  fi
  s_err="$(dh session list --system --token-file "$lc_cred" --principal "$user_a" --json 2>&1)"; s_rc=$?
  if [ "$s_rc" -ne 0 ] && printf '%s' "$s_err" | grep -q 'invalid_selector'; then
    reg_ok "C: launcher-credential --principal selector stays rejected"
  else
    reg_fail "C: launcher-credential --principal selector was not rejected (rc=$s_rc): $(printf '%s' "$s_err" | head -2 | tr '\n' ' ')"
  fi

  cleanup_sessions "$sid_ad" "$sid_aa"
  cleanup_principal "$user_a"
  cleanup_principal "$user_b"
  rm -f "$cred_a" "$lc_cred"
}

# ---------------------------------------------------------------------------
# D. help and completion surface
# ---------------------------------------------------------------------------
subcase_d() {
  reg_info "subcase D: help and completion surface"
  local help_out script out rc_diag

  # help: both narrowing flags must be discoverable.
  if help_out="$(dh session list --help 2>/dev/null)"; then
    if printf '%s' "$help_out" | grep -q -- '--principal' && printf '%s' "$help_out" | grep -q -- '--launcher'; then
      reg_ok "D: session list --help shows --principal and --launcher"
    else
      reg_fail "D: session list --help does not show the narrowing flags"
    fi
  else
    reg_fail "D: session list --help failed"
  fi

  # completion: the generated script sourced in a real Bash drives the
  # function Bash actually registered for docker-helper (discovered through
  # `complete -p`, one -F registration) so `docker-helper session list --`
  # offers the two narrowing flags.
  script="$TMPDIR_REG13/completion.bash"
  if ! dh completion bash > "$script" 2>/dev/null || [ ! -s "$script" ]; then
    reg_fail "D: completion script generation failed"
    return
  fi
  local d_err="$TMPDIR_REG13/d.err"
  out="$(bash -c '
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
    COMP_WORDS=(/usr/bin/docker-helper session list --)
    COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
    "$func" || exit 4
    printf "%s\n" "${COMPREPLY[@]}"
  ' _ "$script" 2>"$d_err")"
  local rc=$?
  rc_diag="$(head -3 "$d_err" 2>/dev/null | tr '\n' ' ')"
  if [ "$rc" = 5 ]; then
    reg_fail "D: docker-helper is not registered exactly once by the generated script: $rc_diag"
    return
  fi
  if [ "$rc" = 6 ]; then
    reg_fail "D: docker-helper completion is not registered with a -F function: $rc_diag"
    return
  fi
  if [ "$rc" -ne 0 ]; then
    reg_fail "D: registered completion function failed (rc=$rc): $rc_diag"
    return
  fi
  if printf '%s\n' "$out" | grep -q -- '--principal' && printf '%s\n' "$out" | grep -q -- '--launcher'; then
    reg_ok "D: completion offers --principal and --launcher for session list"
  else
    reg_fail "D: completion did not offer the narrowing flags: $(printf '%s' "$out" | head -5 | tr '\n' ' ')"
  fi

  rm -f "$script" "$d_err"
}

subcase_a
subcase_b
subcase_c
subcase_d

rm -rf "$TMPDIR_REG13"
reg_result
