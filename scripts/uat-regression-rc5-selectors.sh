#!/usr/bin/env bash
#
# uat-regression-rc5-selectors.sh — Release-2.1 RC5 targeted regression
# group 10: launcher/session selector and completion acceptance
# (Ubuntu / DEB / AppArmor).
#
# Black-box acceptance coverage for the RC5 selector defects, exercised
# through the installed packaged CLI/daemon (the exact public R2.1 paths
# that escaped the previous UAT):
#
#   A. non-default Launcher Session creation — a Principal credential
#      creates Sessions targeted with --launcher (name and dhl_ ID) at a
#      second, restricted Launcher; the created Sessions are owned by that
#      Launcher and the effective workspace policy is that Launcher's
#      restricted root (inside accepted, outside rejected).
#   B. admin global Launcher ID targeting — read and mutation paths operate
#      on a non-default Launcher using ONLY its global dhl_ ID and without
#      --principal; a name-shaped selector without --principal stays
#      rejected and a foreign/unknown ID stays non-disclosing.
#   C. Launcher credential Session self-selection — session create with the
#      credential's own dhl_ ID succeeds, the no-selector path still
#      resolves self, and a foreign ID fails with the daemon's
#      non-disclosing launcher-not-found through the Session create path
#      (never the launcher control plane, which this authority cannot use);
#      a name-shaped selector is rejected locally with the dhl_ ID hint.
#   D. default Launcher create UX — launcher create without --name for a
#      Principal that already has its auto-provisioned 'default' fails
#      before the credential prompt with the default identified and a
#      --name hint, creates no second Launcher, and an explicit duplicate
#      name keeps the stable launcher_exists conflict naming the Launcher
#      and Principal.
#   E. Bash path completion '//' — the generated completion script sourced
#      in a real Bash drives the function Bash actually registered for
#      docker-helper (discovered through `complete -p`, one -F registration)
#      so a directory continuation after '.../work/' yields '.../work/child'
#      and never '.../work//child'.
#
# Each subcase uses its own OS user/Principal so results are independent.
# A subcase failure does not stop the others (collect-all).
#
# Requires: installed docker-helper system service (active), root, bash,
# realpath. Docker is not required (no data-plane operations).
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "10. RC5 selector and completion acceptance"

reg_require_root
reg_require_service
reg_require_cmd bash "completion acceptance drives a real Bash"
reg_require_cmd realpath "completion roots canonicalization"

TMPDIR_RC5="/tmp/uat-reg10"
mkdir -p "$TMPDIR_RC5"

# session_field SESSION_JSON: parse a --json session create/list document.
session_field() { # field
  json_field "$1"
}

# assert_no_doubled_separator STREAM WHAT: every candidate line must be free
# of a doubled separator.
assert_no_doubled_separator() {
  local stream="$1" what="$2"
  if printf '%s\n' "$stream" | grep -q '//'; then
    reg_fail "$what: doubled separator in completion candidates: $(printf '%s' "$stream" | grep '//' | head -3 | tr '\n' ' ')"
  else
    reg_ok "$what: no doubled separator in candidates"
  fi
}

# cleanup_principal USER: best-effort teardown shared by every subcase.
cleanup_principal() {
  local user="$1"
  dh principal delete --system "$user" >/dev/null 2>&1 || true
  userdel -r "$user" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# A. non-default Launcher Session creation (Principal credential + --launcher)
# ---------------------------------------------------------------------------
subcase_a() {
  reg_info "subcase A: non-default Launcher Session creation"
  local user="uatreg10a" home cred sub ws_in ws_out alpha_out alpha_id sid1 sid2
  home="$(reg_setup_principal "$user")" || { reg_fail "A: setup principal failed"; return; }
  cred="/tmp/uat-reg10/a.token"
  reg_principal_credential "$user" "$cred" || { reg_fail "A: principal credential create failed"; return; }

  sub="$home/a-sub"; ws_in="$sub/proj"; ws_out="$home/a-out"
  mkdir -p "$ws_in" "$ws_out"
  chown -R "$user:$user" "$home"

  alpha_out="$(dh launcher create --system --principal "$user" --name alpha \
      --allowed-root "$sub" --no-credential 2>&1)"
  alpha_id="$(printf '%s' "$alpha_out" | json_field id || true)"
  if [ -n "$alpha_id" ]; then
    reg_ok "A: restricted Launcher alpha created ($alpha_id)"
  else
    reg_fail "A: restricted Launcher create failed: $(printf '%s' "$alpha_out" | head -2 | tr '\n' ' ')"
    return
  fi

  # Name-shaped selector through the public CLI.
  if sid1="$(dh session create --system --token-file "$cred" --workspace "$ws_in" \
        --launcher alpha --json 2>/dev/null)"; then
    if [ "$(printf '%s' "$sid1" | session_field launcher_id)" = "$alpha_id" ] \
        && [ "$(printf '%s' "$sid1" | session_field launcher)" = "alpha" ]; then
      reg_ok "A: --launcher alpha (name) owns the Session"
    else
      reg_fail "A: name-targeted Session is not owned by alpha: $(printf '%s' "$sid1" | head -3 | tr '\n' ' ')"
    fi
  else
    reg_fail "A: session create with --launcher alpha (name) failed"
  fi

  # ID-shaped selector through the public CLI.
  if sid2="$(dh session create --system --token-file "$cred" --workspace "$ws_in" \
        --launcher "$alpha_id" --json 2>/dev/null)"; then
    if [ "$(printf '%s' "$sid2" | session_field launcher_id)" = "$alpha_id" ]; then
      reg_ok "A: --launcher <dhl_ ID> owns the Session"
    else
      reg_fail "A: ID-targeted Session is not owned by alpha"
    fi
  else
    reg_fail "A: session create with --launcher <dhl_ ID> failed"
  fi

  # Effective workspace policy: outside the restricted root is rejected even
  # though it stays inside the Principal's own allowed roots.
  local out_err out_rc
  out_err="$(dh session create --system --token-file "$cred" --workspace "$ws_out" \
      --launcher alpha --json 2>&1)"; out_rc=$?
  if [ "$out_rc" -ne 0 ] && printf '%s' "$out_err" | grep -q 'workspace must be inside an allowed root'; then
    reg_ok "A: workspace outside the restricted Launcher root is rejected"
  else
    reg_fail "A: workspace outside the restricted root was not rejected (rc=$out_rc): $(printf '%s' "$out_err" | head -2 | tr '\n' ' ')"
  fi

  # Cleanup.
  for s in $(printf '%s' "$sid1" | session_field id) $(printf '%s' "$sid2" | session_field id); do
    [ -n "$s" ] && dh session delete --system --id "$s" >/dev/null 2>&1 || true
  done
  cleanup_principal "$user"
  rm -f "$cred"
}

# ---------------------------------------------------------------------------
# B. admin global Launcher ID targeting (read + mutation, no --principal)
# ---------------------------------------------------------------------------
subcase_b() {
  reg_info "subcase B: admin global Launcher ID targeting"
  local user="uatreg10b" home beta_out beta_id show_out show2 unknown_id
  home="$(reg_setup_principal "$user")" || { reg_fail "B: setup principal failed"; return; }
  mkdir -p "$home/ws"; chown -R "$user:$user" "$home"

  beta_out="$(dh launcher create --system --principal "$user" --name beta --no-credential 2>&1)"
  beta_id="$(printf '%s' "$beta_out" | json_field id || true)"
  [ -n "$beta_id" ] || { reg_fail "B: launcher create failed: $(printf '%s' "$beta_out" | head -2 | tr '\n' ' ')"; return; }

  # Read path: ONLY the global ID, no --principal.
  if show_out="$(dh launcher show --system "$beta_id" 2>/dev/null)"; then
    if printf '%s' "$show_out" | grep -q "\"principal\": \"$user\"" \
        && [ "$(printf '%s' "$show_out" | json_field name)" = "beta" ]; then
      reg_ok "B: launcher show by global dhl_ ID without --principal resolves the Launcher"
    else
      reg_fail "B: ID show returned the wrong Launcher: $(printf '%s' "$show_out" | head -3 | tr '\n' ' ')"
    fi
  else
    reg_fail "B: launcher show by global dhl_ ID failed"
  fi

  # Mutation path: disable + re-enable by global ID only.
  if dh launcher set --system --enabled false "$beta_id" >/dev/null 2>&1; then
    show2="$(dh launcher show --system "$beta_id" 2>/dev/null || true)"
    if printf '%s' "$show2" | grep -q '"enabled": false'; then
      reg_ok "B: launcher set --enabled false by global dhl_ ID"
    else
      reg_fail "B: ID disable did not persist: $(printf '%s' "$show2" | head -3 | tr '\n' ' ')"
    fi
  else
    reg_fail "B: launcher set --enabled false by global dhl_ ID failed"
  fi
  if dh launcher set --system --enabled true "$beta_id" >/dev/null 2>&1; then
    show2="$(dh launcher show --system "$beta_id" 2>/dev/null || true)"
    if printf '%s' "$show2" | grep -q '"enabled": true'; then
      reg_ok "B: launcher set --enabled true by global dhl_ ID"
    else
      reg_fail "B: ID re-enable did not persist"
    fi
  else
    reg_fail "B: launcher set --enabled true by global dhl_ ID failed"
  fi

  # Name-shaped selector without --principal stays rejected for admin.
  local name_err name_rc
  name_err="$(dh launcher show --system beta 2>&1)"; name_rc=$?
  if [ "$name_rc" -ne 0 ] && printf '%s' "$name_err" | grep -q -- '--principal is required for admin authentication'; then
    reg_ok "B: name-shaped selector without --principal is rejected"
  else
    reg_fail "B: name-shaped selector without --principal was not rejected (rc=$name_rc): $(printf '%s' "$name_err" | head -2 | tr '\n' ' ')"
  fi

  # Foreign/unknown ID stays non-disclosing.
  unknown_id="dhl_$(printf 'ab%.0s' $(seq 1 16))"
  local unk_err unk_rc
  unk_err="$(dh launcher show --system "$unknown_id" 2>&1)"; unk_rc=$?
  if [ "$unk_rc" -ne 0 ] && printf '%s' "$unk_err" | grep -q 'launcher not found'; then
    reg_ok "B: unknown global dhl_ ID is the non-disclosing launcher-not-found"
  else
    reg_fail "B: unknown dhl_ ID show did not fail non-disclosing (rc=$unk_rc): $(printf '%s' "$unk_err" | head -2 | tr '\n' ' ')"
  fi

  cleanup_principal "$user"
}

# ---------------------------------------------------------------------------
# C. Launcher credential Session self-selection
# ---------------------------------------------------------------------------
subcase_c() {
  reg_info "subcase C: Launcher credential Session self-selection"
  local user="uatreg10c" foreign_user="uatreg10c2" home fhome
  local cred lc_out lc_token gamma_out gamma_id f_out f_id sid self_sid
  home="$(reg_setup_principal "$user")" || { reg_fail "C: setup principal failed"; return; }
  fhome="$(reg_setup_principal "$foreign_user")" || { reg_fail "C: setup foreign principal failed"; return; }
  mkdir -p "$home/ws" "$fhome/ws"
  chown -R "$user:$user" "$home"
  chown -R "$foreign_user:$foreign_user" "$fhome"

  gamma_out="$(dh launcher create --system --principal "$user" --name gamma --no-credential 2>&1)"
  gamma_id="$(printf '%s' "$gamma_out" | json_field id || true)"
  [ -n "$gamma_id" ] || { reg_fail "C: launcher create failed: $(printf '%s' "$gamma_out" | head -2 | tr '\n' ' ')"; return; }

  lc_out="$(dh launcher credential create --system --principal "$user" "$gamma_id" 2>/dev/null)"
  lc_token="$(printf '%s' "$lc_out" | json_field token || true)"
  [ -n "$lc_token" ] || { reg_fail "C: launcher credential create failed"; return; }
  cred="/tmp/uat-reg10/c.token"
  printf '%s\n' "$lc_token" > "$cred"; chmod 600 "$cred"

  f_out="$(dh launcher create --system --principal "$foreign_user" --name fgamma --no-credential 2>&1)"
  f_id="$(printf '%s' "$f_out" | json_field id || true)"
  [ -n "$f_id" ] || { reg_fail "C: foreign launcher create failed"; return; }

  # Own explicit ID through the Session path (the RC5 defect: this used to be
  # resolved through the launcher control plane, which this authority cannot
  # use).
  if sid="$(dh session create --system --token-file "$cred" --workspace "$home/ws" \
        --launcher "$gamma_id" --json 2>/dev/null)"; then
    if [ "$(printf '%s' "$sid" | session_field launcher_id)" = "$gamma_id" ] \
        && [ "$(printf '%s' "$sid" | session_field launcher)" = "gamma" ]; then
      reg_ok "C: own dhl_ ID creates a Session on the credential's own Launcher"
    else
      reg_fail "C: own-ID Session is not owned by gamma: $(printf '%s' "$sid" | head -3 | tr '\n' ' ')"
    fi
  else
    reg_fail "C: session create with own dhl_ ID failed"
  fi

  # No-selector self behavior is unchanged.
  if self_sid="$(dh session create --system --token-file "$cred" --workspace "$home/ws" --json 2>/dev/null)"; then
    if [ "$(printf '%s' "$self_sid" | session_field launcher_id)" = "$gamma_id" ]; then
      reg_ok "C: no-selector Session still resolves self"
    else
      reg_fail "C: no-selector Session is not owned by gamma"
    fi
  else
    reg_fail "C: no-selector session create failed"
  fi

  # Foreign ID: non-disclosing launcher-not-found through the SESSION path.
  # If the CLI ever fell back to the launcher control plane the failure would
  # instead be the 401 'Authentication required for launcher management.'
  local f_err f_rc
  f_err="$(dh session create --system --token-file "$cred" --workspace "$home/ws" \
      --launcher "$f_id" --json 2>&1)"; f_rc=$?
  if [ "$f_rc" -ne 0 ] \
      && printf '%s' "$f_err" | grep -q 'launcher not found' \
      && ! printf '%s' "$f_err" | grep -q 'Authentication required for launcher management' \
      && ! printf '%s' "$f_err" | grep -q "$f_id"; then
    reg_ok "C: foreign dhl_ ID fails non-disclosing through the Session path"
  else
    reg_fail "C: foreign dhl_ ID was not rejected non-disclosing (rc=$f_rc): $(printf '%s' "$f_err" | head -2 | tr '\n' ' ')"
  fi

  # Name-shaped selector under a Launcher credential: rejected locally with
  # the actionable dhl_ ID hint (no control-plane resolution exists).
  local n_err n_rc
  n_err="$(dh session create --system --token-file "$cred" --workspace "$home/ws" \
      --launcher gamma --json 2>&1)"; n_rc=$?
  if [ "$n_rc" -ne 0 ] \
      && printf '%s' "$n_err" | grep -q "Launcher authentication requires the Launcher's dhl_ ID" \
      && ! printf '%s' "$n_err" | grep -q 'Authentication required for launcher management'; then
    reg_ok "C: name-shaped --launcher under Launcher credential is rejected with the dhl_ ID hint"
  else
    reg_fail "C: name-shaped --launcher was not rejected with the dhl_ ID hint (rc=$n_rc): $(printf '%s' "$n_err" | head -2 | tr '\n' ' ')"
  fi

  # Cleanup.
  for s in $(printf '%s' "$sid" | session_field id) $(printf '%s' "$self_sid" | session_field id); do
    [ -n "$s" ] && dh session delete --system --id "$s" >/dev/null 2>&1 || true
  done
  cleanup_principal "$user"
  cleanup_principal "$foreign_user"
  rm -f "$cred"
}

# ---------------------------------------------------------------------------
# D. default Launcher create UX
# ---------------------------------------------------------------------------
subcase_d() {
  reg_info "subcase D: default Launcher create UX"
  local user="uatreg10d" home conflict_err conflict_rc dup_err dup_rc
  local delta_out list_out
  home="$(reg_setup_principal "$user")" || { reg_fail "D: setup principal failed"; return; }
  mkdir -p "$home/ws"; chown -R "$user:$user" "$home"

  # No --name and no credential flags: the pre-flight conflict must fire
  # BEFORE the credential prompt (a prompt-first flow would fail with the
  # non-interactive credential-choice error instead).
  conflict_err="$(dh launcher create --system --principal "$user" 2>&1 </dev/null)"; conflict_rc=$?
  if [ "$conflict_rc" -ne 0 ] \
      && printf '%s' "$conflict_err" | grep -q 'launcher "default" already exists for principal' \
      && printf '%s' "$conflict_err" | grep -q -- '--name NAME' \
      && ! printf '%s' "$conflict_err" | grep -q 'issue-credential'; then
    reg_ok "D: default create fails before the credential prompt with the --name hint"
  else
    reg_fail "D: default create did not fail with the pre-flight conflict (rc=$conflict_rc): $(printf '%s' "$conflict_err" | head -2 | tr '\n' ' ')"
  fi
  if printf '%s' "$conflict_err" | grep -q "\"$user\""; then
    reg_ok "D: pre-flight conflict identifies the Principal"
  else
    reg_fail "D: pre-flight conflict does not name the Principal: $(printf '%s' "$conflict_err" | head -2 | tr '\n' ' ')"
  fi

  # With --no-credential the same pre-flight conflict applies.
  conflict_err="$(dh launcher create --system --principal "$user" --no-credential 2>&1)"; conflict_rc=$?
  if [ "$conflict_rc" -ne 0 ] && printf '%s' "$conflict_err" | grep -q 'launcher "default" already exists for principal'; then
    reg_ok "D: default create with --no-credential reports the same pre-flight conflict"
  else
    reg_fail "D: default create with --no-credential did not report the conflict (rc=$conflict_rc)"
  fi

  # No second Launcher was created.
  list_out="$(dh launcher list --system --principal "$user" --json 2>/dev/null || true)"
  if [ "$(printf '%s' "$list_out" | grep -c '"name": "default"')" = "1" ]; then
    reg_ok "D: no second Launcher was created"
  else
    reg_fail "D: unexpected default Launcher count after pre-flight rejection"
  fi

  # Explicit duplicate name keeps the stable daemon conflict code, naming the
  # Launcher and its Principal.
  dup_err="$(dh launcher create --system --principal "$user" --name default --no-credential 2>&1)"; dup_rc=$?
  if [ "$dup_rc" -ne 0 ] \
      && printf '%s' "$dup_err" | grep -q 'launcher_exists' \
      && printf '%s' "$dup_err" | grep -q 'already exists for principal' \
      && printf '%s' "$dup_err" | grep -q 'default' \
      && printf '%s' "$dup_err" | grep -q "$user"; then
    reg_ok "D: explicit duplicate name keeps launcher_exists naming Launcher and Principal"
  else
    reg_fail "D: explicit duplicate name conflict changed (rc=$dup_rc): $(printf '%s' "$dup_err" | head -2 | tr '\n' ' ')"
  fi

  # A fresh explicit name still creates normally.
  delta_out="$(dh launcher create --system --principal "$user" --name delta --no-credential 2>&1)"
  if printf '%s' "$delta_out" | json_field name | grep -q '^delta$'; then
    reg_ok "D: explicit fresh name still creates a Launcher"
  else
    reg_fail "D: fresh-name create broken: $(printf '%s' "$delta_out" | head -2 | tr '\n' ' ')"
  fi

  cleanup_principal "$user"
}

# ---------------------------------------------------------------------------
# E. Bash path completion '//'
# ---------------------------------------------------------------------------
subcase_e() {
  reg_info "subcase E: Bash path completion '//'"
  local user="uatreg10e" home cred work script out
  home="$(reg_setup_principal "$user")" || { reg_fail "E: setup principal failed"; return; }
  cred="/tmp/uat-reg10/e.token"
  reg_principal_credential "$user" "$cred" || { reg_fail "E: principal credential create failed"; return; }

  work="$home/e5/work"
  mkdir -p "$work/child" "$home/e5"
  chown -R "$user:$user" "$home"

  # Generate the real completion script from the installed CLI.
  script="$TMPDIR_RC5/completion.bash"
  if ! dh completion bash > "$script" 2>/dev/null || [ ! -s "$script" ]; then
    reg_fail "E: completion script generation failed"
    return
  fi

  # Drive the function Bash actually registered for docker-helper, the way
  # Bash does: source the script, discover the registered compspec through
  # `complete -p` (asserting exactly one registration and a -F function),
  # invoke the registered function with COMP_WORDS/COMP_CWORD, and inspect
  # COMPREPLY. The test never assumes an internal helper name.
  local e_err="$TMPDIR_RC5/e.err"
  out="$(bash -c '
    set -u
    source "$1" || exit 3
    # Exactly one registration for docker-helper, discovered from Bash.
    mapfile -t specs < <(complete -p docker-helper)
    if [ ${#specs[@]} -ne 1 ]; then
      echo "registrations: ${specs[*]:-none}" >&2
      exit 5
    fi
    # Parse/assert the registered -F FUNCTION.
    func="${specs[0]#*-F }"
    if [ "$func" = "${specs[0]}" ]; then
      echo "no -F function in compspec: ${specs[0]}" >&2
      exit 6
    fi
    func="${func%% *}"
    if [ -z "$func" ]; then
      echo "empty -F function in compspec: ${specs[0]}" >&2
      exit 6
    fi
    COMP_WORDS=(/usr/bin/docker-helper session create --system --token-file "$2" --workspace "$3")
    COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
    "$func" || exit 4
    printf "%s\n" "${COMPREPLY[@]}"
  ' _ "$script" "$cred" "$work/" 2>"$e_err")"
  local rc=$?
  local diag
  diag="$(head -3 "$e_err" 2>/dev/null | tr '\n' ' ')"
  if [ "$rc" -eq 5 ]; then
    reg_fail "E: docker-helper is not registered exactly once by the generated script: $diag"
    return
  fi
  if [ "$rc" -eq 6 ]; then
    reg_fail "E: docker-helper completion is not registered with a -F function: $diag"
    return
  fi
  if [ "$rc" -ne 0 ]; then
    reg_fail "E: registered completion function failed (rc=$rc): $diag"
    return
  fi

  if printf '%s\n' "$out" | grep -qF "$work/child"; then
    reg_ok "E: directory continuation after '.../work/' yields '$work/child'"
  else
    reg_fail "E: completion did not offer $work/child: $(printf '%s' "$out" | head -5 | tr '\n' ' ')"
  fi
  assert_no_doubled_separator "$out" "E"

  # Cleanup.
  cleanup_principal "$user"
  rm -f "$cred" "$script"
}

subcase_a
subcase_b
subcase_c
subcase_d
subcase_e

rm -rf "$TMPDIR_RC5"
reg_result
