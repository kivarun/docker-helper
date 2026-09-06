#!/usr/bin/env bash
#
# uat-regression-rc8-cli-ux.sh — Release-2.1 RC8 targeted regression group 14:
# CLI/UX acceptance (Ubuntu / DEB / AppArmor).
#
# The manual UAT for RC8 found two contract defects that unit tests had
# missed because they only exist end to end on the packaged CLI/daemon:
#
#   A. Principal self-read — a Principal credential must read exactly the
#      Principal it authenticated as through the daemon-side Principal
#      control target owner: the own `principal show` succeeds with the
#      full document, FIELD extraction (username, uid, gid, home, enabled,
#      allowed_roots) consumes the same response, a foreign selector is the
#      established non-disclosing not-found, a Launcher credential has no
#      Principal-read authority, and admin read is unchanged.
#   B. restricted-Launcher workspace completion — `session create
#      --workspace <TAB>` must resolve exactly the Session-create target
#      the typed selectors resolve (the invariant completion(selectors)
#      == real create(selectors)): the typed --launcher (name or
#      --launcher= form) reaches the daemon's canonical Session-create
#      policy owner, so the completion offers only the restricted
#      Launcher's effective roots and never the wider Principal ceiling;
#      selectorless completion keeps the default-target semantics.
#   C. unique deterministic candidates — nested roots (a root under a
#      wider root) must not produce duplicate suggestions, and the same
#      typed line yields the same COMPREPLY.
#   D. RC8 CLI surface — `launcher scope` is gone, the launcher
#      allowed-root add/list/remove/inherit commands and the principal
#      allowed-root list command are discoverable.
#   E. selector-value completion — the values of the --principal/--launcher
#      flags complete from the daemon's scope-aware selector introspection:
#      an admin sees Principal names and, with a typed --principal context,
#      that Principal's Launcher names (or, without one, only globally
#      resolvable Launcher IDs, never names); a Principal credential sees
#      its own Launchers; the offered selector resolves to the same
#      Session-create target a real create with that selector would use.
#
# Each subcase is independent (collect-all). Docker is not required.
#
# Requires: installed docker-helper system service (active), root, bash.
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "14. RC8 CLI/UX acceptance"

reg_require_root
reg_require_service
reg_require_cmd bash "completion acceptance drives a real Bash"

TMPDIR_REG14="/tmp/uat-reg14"
mkdir -p "$TMPDIR_REG14"

# run_completion SCRIPT WORDS... drives the completion function Bash actually
# registered for docker-helper (discovered through `complete -p`, one -F
# registration) with the given command line; prints one COMPREPLY entry per
# line. The snippet's exit code and stderr are surfaced through
# RC_COMPLETION / ERR_COMPLETION for failure attribution.
run_completion() {
  local script="$1"
  shift
  local words="" w wq err_file
  for w in "$@"; do
    printf -v wq '%q' "$w"
    words+="${words:+ }${wq}"
  done
  err_file="$TMPDIR_REG14/comp.err"
  RC_COMPLETION=0
  ERR_COMPLETION=""
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
  RC_COMPLETION=$?
  if [ "$RC_COMPLETION" -ne 0 ]; then
    ERR_COMPLETION="$(head -2 "$err_file" | tr '\n' ' ')"
  fi
  rm -f "$err_file"
}

# assert_completion LABEL EXPECTED ACTUAL: EXPECTED and ACTUAL are
# '|'-separated COMPREPLY entries compared as exact ordered sets. The
# harness rc/stderr from the last run_completion are reported on failure.
assert_completion() {
  local label="$1" expected_csv="$2" actual="$3"
  local want have
  want="$(printf '%s' "$expected_csv" | tr '|' '\n')"
  have="$(printf '%s' "$actual" | LC_ALL=C sort -u)"
  if [ "$want" = "$have" ]; then
    reg_ok "$label"
    return 0
  fi
  reg_fail "$label: suggestions = [$(printf '%s' "$actual" | tr '\n' ' ' | redact)] want [$expected_csv] (harness rc=$RC_COMPLETION err=$ERR_COMPLETION)"
  return 1
}

# assert_unique LABEL COMPREPLY: no duplicate candidate.
assert_unique() {
  local label="$1" actual="$2" dups
  dups="$(printf '%s' "$actual" | LC_ALL=C sort | uniq -d)"
  if [ -z "$dups" ]; then
    reg_ok "$label"
  else
    reg_fail "$label: duplicate suggestions: $(printf '%s' "$dups" | tr '\n' ' ' | redact)"
  fi
}

# launcher_credential_token USER LAUNCHER creates a launcher credential
# through the packaged CLI and prints the token (the JSON document's token
# field).
launcher_credential_token() {
  local user="$1" launcher="$2" out
  out="$(dh launcher credential create --system --principal "$user" "$launcher" 2>/dev/null)" || return 1
  printf '%s' "$out" | json_field token
}

# ---------------------------------------------------------------------------
# A. Principal self-read
# ---------------------------------------------------------------------------
subcase_a() {
  reg_info "subcase A: principal self-read"
  local user_a="uatreg14a" user_b="uatreg14b" home_a
  home_a="$(reg_setup_principal "$user_a")" || { reg_fail "A: fixture setup failed"; return; }
  reg_setup_principal "$user_b" >/dev/null 2>&1 || { reg_fail "A: foreign fixture setup failed"; cleanup_principal "$user_a"; return; }
  local cred_a="$TMPDIR_REG14/a.token"
  reg_principal_credential "$user_a" "$cred_a" || { reg_fail "A: principal credential create failed"; cleanup_principal "$user_a"; cleanup_principal "$user_b"; return; }

  local out rc
  # 1. own show: success with the full document.
  if out="$(dh principal show --token-file "$cred_a" "$user_a" 2>&1)" && printf '%s' "$out" | grep -q '"username"'; then
    reg_ok "A: principal credential reads its own Principal"
  else
    reg_fail "A: own principal show failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 2. FIELD extraction consumes the same response.
  local field want
  for field in username enabled; do
    out="$(dh principal show --token-file "$cred_a" "$user_a" "$field" 2>&1)"
    case "$field" in
      username) want="$user_a" ;;
      enabled)  want="true" ;;
    esac
    if [ "$out" = "$want" ]; then
      reg_ok "A: FIELD extraction ($field) over the own-Principal show response"
    else
      reg_fail "A: FIELD extraction ($field) = '$(printf '%s' "$out" | head -1 | redact)' want '$want'"
    fi
  done
  out="$(dh principal show --token-file "$cred_a" "$user_a" allowed_roots 2>&1)"
  if printf '%s' "$out" | grep -q '"'"$home_a"'"'; then
    reg_ok "A: FIELD extraction (allowed_roots) carries the stored roots"
  else
    reg_fail "A: FIELD extraction (allowed_roots) = $(printf '%s' "$out" | head -1 | redact)"
  fi

  # 3. foreign selector: the established non-disclosing not-found.
  out="$(dh principal show --token-file "$cred_a" "$user_b" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'principal_not_found' \
      && ! printf '%s' "$out" | grep -q "$user_b"; then
    reg_ok "A: foreign principal show is the non-disclosing not-found"
  else
    reg_fail "A: foreign principal show not rejected non-disclosing (rc=$rc): $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 4. Launcher credential: no Principal-read authority.
  local lc_token
  lc_token="$(launcher_credential_token "$user_a" default)" || lc_token=""
  if [ -n "$lc_token" ]; then
    printf '%s\n' "$lc_token" > "$TMPDIR_REG14/a-lc.token"
    out="$(dh principal show --token-file "$TMPDIR_REG14/a-lc.token" "$user_a" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ] && ! printf '%s' "$out" | grep -q 'allowed_roots'; then
      reg_ok "A: launcher credential has no Principal-read authority"
    else
      reg_fail "A: launcher credential reached a Principal document (rc=$rc)"
    fi
  else
    reg_fail "A: launcher credential create failed"
  fi

  # 5. admin read of any Principal is unchanged.
  if out="$(dh principal show --system "$user_b" 2>&1)" && printf '%s' "$out" | grep -q '"username"'; then
    reg_ok "A: admin principal read is unchanged"
  else
    reg_fail "A: admin principal show failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  cleanup_principal "$user_a"
  cleanup_principal "$user_b"
  rm -f "$cred_a" "$TMPDIR_REG14/a-lc.token"
}

# ---------------------------------------------------------------------------
# B. restricted-Launcher workspace completion
# ---------------------------------------------------------------------------
subcase_b() {
  reg_info "subcase B: restricted-Launcher workspace completion"
  local user="uatreg14b" script
  local home
  home="$(reg_setup_principal "$user")" || { reg_fail "B: fixture setup failed"; return; }
  local opt="$home/opt"
  mkdir -p "$opt/proj"
  chown -R "$user:$user" "$home"

  local create_out
  create_out="$(dh launcher create --system --principal "$user" --name killme --allowed-root "$opt" --no-credential 2>&1)" || {
    reg_fail "B: restricted launcher create failed: $(printf '%s' "$create_out" | head -2 | tr '\n' ' ' | redact)"
    cleanup_principal "$user"
    return
  }
  printf '%s' "$create_out" | json_field id >/dev/null || {
    reg_fail "B: restricted launcher create returned no launcher id"
    cleanup_principal "$user"
    return
  }

  local cred="$TMPDIR_REG14/b.token"
  reg_principal_credential "$user" "$cred" || { reg_fail "B: principal credential create failed"; cleanup_principal "$user"; return; }

  script="$TMPDIR_REG14/completion.bash"
  if ! dh completion bash > "$script" 2>/dev/null || [ ! -s "$script" ]; then
    reg_fail "B: completion script generation failed"
    cleanup_principal "$user"
    rm -f "$cred"
    return
  fi

  local out
  # The machine-facing introspection surface the completion harness drives
  # must answer on the packaged CLI before the COMPREPLY contract is
  # asserted; its failure would attribute to the CLI, not the harness.
  local roots_out roots_rc
  roots_out="$(dh completion roots session --system --principal "$user" --launcher killme 2>&1)"; roots_rc=$?
  if [ "$roots_rc" -eq 0 ] && printf '%s' "$roots_out" | grep -qx "$opt"; then
    reg_ok "B: introspection query (admin + typed selectors) answers the restricted root"
  else
    reg_fail "B: introspection query (admin + typed selectors) failed (rc=$roots_rc): $(printf '%s' "$roots_out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 1. admin + --principal USER --launcher NAME: only the restricted root.
  out="$(run_completion "$script" /usr/bin/docker-helper --system session create \
    --principal "$user" --launcher killme --workspace "")"
  assert_completion "B: admin --principal+--launcher offers only the restricted root" "$opt" "$out" || true

  # 2. the wider Principal ceiling must not leak into the suggestion.
  if printf '%s' "$out" | grep -qx "$home"; then
    reg_fail "B: the wider Principal root leaked into the suggestions"
  else
    reg_ok "B: the wider Principal root stays out of the restricted suggestions"
  fi

  # 3. --launcher=NAME reaches the same query (identical suggestions).
  local out_eq
  out_eq="$(run_completion "$script" /usr/bin/docker-helper --system session create \
    --principal="$user" --launcher=killme --workspace "")"
  if [ "$out" = "$out_eq" ]; then
    reg_ok "B: --launcher=NAME form offers the same suggestions"
  else
    reg_fail "B: --launcher=NAME form differs: [$(printf '%s' "$out_eq" | tr '\n' ' ' | redact)]"
  fi

  # 4. Principal credential + --launcher NAME: the daemon resolves the
  #    selector inside the credential's own scope.
  out="$(run_completion "$script" /usr/bin/docker-helper --system session create \
    --token-file "$cred" --launcher killme --workspace "")"
  assert_completion "B: principal credential --launcher offers only the restricted root" "$opt" "$out" || true
  if printf '%s' "$out" | grep -qx "$home"; then
    reg_fail "B: principal credential completion leaked the wider Principal root"
  else
    reg_ok "B: principal credential completion stays inside the restricted root"
  fi

  # 5. selectorless completion keeps the default-target semantics: the
  #    default Launcher inherits the Principal ceiling (the home root).
  roots_out="$(dh completion roots session --system --token-file "$cred" 2>&1)"; roots_rc=$?
  if [ "$roots_rc" -eq 0 ] && printf '%s' "$roots_out" | grep -qx "$home"; then
    reg_ok "B: introspection query (principal credential, selectorless) answers the default target"
  else
    reg_fail "B: introspection query (principal credential, selectorless) failed (rc=$roots_rc): $(printf '%s' "$roots_out" | head -2 | tr '\n' ' ' | redact)"
  fi
  out="$(run_completion "$script" /usr/bin/docker-helper --system session create \
    --token-file "$cred" --workspace "")"
  assert_completion "B: selectorless principal-credential completion keeps the default target" "$home" "$out" || true

  # 6. continuation inside the restricted root: only its subdirectories.
  out="$(run_completion "$script" /usr/bin/docker-helper --system session create \
    --token-file "$cred" --launcher killme --workspace "$opt/")"
  assert_completion "B: continuation offers the restricted subdirectories" "$opt/proj" "$out" || true

  # 7. a foreign selector fails silently: no policy guess, no suggestion.
  out="$(run_completion "$script" /usr/bin/docker-helper --system session create \
    --token-file "$cred" --launcher does-not-exist --workspace "")"
  if [ -z "$out" ]; then
    reg_ok "B: foreign --launcher selector degrades silently"
  else
    reg_fail "B: foreign --launcher selector suggested [$(printf '%s' "$out" | tr '\n' ' ' | redact)]"
  fi

  cleanup_principal "$user"
  rm -f "$cred" "$script"
}

# ---------------------------------------------------------------------------
# C. unique deterministic candidates
# ---------------------------------------------------------------------------
subcase_c() {
  reg_info "subcase C: unique deterministic completion candidates"
  local user="uatreg14c" script home opt out out2
  home="$(reg_setup_principal "$user")" || { reg_fail "C: fixture setup failed"; return; }
  opt="$home/opt"
  mkdir -p "$opt/deeper"
  chown -R "$user:$user" "$home"

  local cred="$TMPDIR_REG14/c.token"
  reg_principal_credential "$user" "$cred" || { reg_fail "C: principal credential create failed"; cleanup_principal "$user"; return; }

  # Nested roots: the default Launcher's ceiling spans home and home/opt.
  if ! out="$(dh principal allowed-root add --system "$user" "$opt" 2>&1)"; then
    reg_fail "C: nested root fixture failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
    cleanup_principal "$user"
    rm -f "$cred"
    return
  fi

  script="$TMPDIR_REG14/completion-c.bash"
  if ! dh completion bash > "$script" 2>/dev/null || [ ! -s "$script" ]; then
    reg_fail "C: completion script generation failed"
    dh principal allowed-root remove --system "$user" "$opt" >/dev/null 2>&1 || true
    cleanup_principal "$user"
    rm -f "$cred"
    return
  fi

  # The nested roots must reach the introspection surface before the
  # COMPREPLY contract is asserted.
  local roots_out roots_rc
  roots_out="$(dh completion roots session --system --token-file "$cred" 2>&1)"; roots_rc=$?
  if [ "$roots_rc" -eq 0 ]; then
    assert_unique "C: introspection output is duplicate-free" "$roots_out"
    if printf '%s' "$roots_out" | grep -qx "$opt"; then
      reg_ok "C: introspection query carries the nested root"
    else
      reg_fail "C: introspection query lacks the nested root: [$(printf '%s' "$roots_out" | tr '\n' ' ' | redact)]"
    fi
  else
    reg_fail "C: introspection query failed (rc=$roots_rc): $(printf '%s' "$roots_out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # Completing inside the wider root offers the nested root once: it
  # qualifies both as an entry anchor and as a directory under home.
  out="$(run_completion "$script" /usr/bin/docker-helper --system session create \
    --token-file "$cred" --workspace "$home/")"
  assert_unique "C: nested roots produce no duplicate suggestions" "$out"
  assert_completion "C: nested root is offered" "$home/opt" "$out" || true

  # Deterministic: the same typed line yields the same COMPREPLY.
  out2="$(run_completion "$script" /usr/bin/docker-helper --system session create \
    --token-file "$cred" --workspace "$home/")"
  if [ "$out" = "$out2" ]; then
    reg_ok "C: the same input yields the same ordered COMPREPLY"
  else
    reg_fail "C: COMPREPLY is not deterministic: [$(printf '%s' "$out" | tr '\n' ' ' | redact)] vs [$(printf '%s' "$out2" | tr '\n' ' ' | redact)]"
  fi

  dh principal allowed-root remove --system "$user" "$opt" >/dev/null 2>&1 || true
  cleanup_principal "$user"
  rm -f "$cred" "$script"
}

# ---------------------------------------------------------------------------
# D. RC8 CLI surface
# ---------------------------------------------------------------------------
subcase_d() {
  reg_info "subcase D: RC8 CLI surface"
  local out rc

  # 1. `launcher scope` is gone entirely (no alias, no help entry).
  if dh launcher scope --help >/dev/null 2>&1; then
    reg_fail "D: launcher scope still exists"
  else
    reg_ok "D: launcher scope is removed from the CLI"
  fi
  if out="$(dh launcher --help 2>&1)" && printf '%s' "$out" | grep -q 'scope set'; then
    reg_fail "D: launcher --help still mentions scope"
  else
    reg_ok "D: launcher help no longer mentions scope"
  fi

  # 2. launcher allowed-root subcommands are discoverable.
  if out="$(dh launcher allowed-root --help 2>&1)"; then
    local sub
    for sub in add list remove inherit; do
      if printf '%s' "$out" | grep -q "^  $sub"; then
        reg_ok "D: launcher allowed-root $sub is discoverable"
      else
        reg_fail "D: launcher allowed-root $sub missing from help"
      fi
    done
  else
    reg_fail "D: launcher allowed-root --help failed"
  fi

  # 3. principal allowed-root list is discoverable.
  if out="$(dh principal allowed-root --help 2>&1)" && printf '%s' "$out" | grep -q '^  list'; then
    reg_ok "D: principal allowed-root list is discoverable"
  else
    reg_fail "D: principal allowed-root list missing from help"
  fi
}

# ---------------------------------------------------------------------------
# E. selector-value completion
# ---------------------------------------------------------------------------
subcase_e() {
  reg_info "subcase E: selector-value completion"
  local user="uatreg14d" script home opt
  home="$(reg_setup_principal "$user")" || { reg_fail "E: fixture setup failed"; return; }
  opt="$home/opt"
  mkdir -p "$opt"
  chown -R "$user:$user" "$home"

  local create_out
  create_out="$(dh launcher create --system --principal "$user" --name killme --allowed-root "$opt" --no-credential 2>&1)" || {
    reg_fail "E: restricted launcher create failed: $(printf '%s' "$create_out" | head -2 | tr '\n' ' ' | redact)"
    cleanup_principal "$user"
    return
  }
  printf '%s' "$create_out" | json_field id >/dev/null || {
    reg_fail "E: restricted launcher create returned no launcher id"
    cleanup_principal "$user"
    return
  }

  local cred="$TMPDIR_REG14/e.token"
  reg_principal_credential "$user" "$cred" || { reg_fail "E: principal credential create failed"; cleanup_principal "$user"; return; }

  script="$TMPDIR_REG14/completion-e.bash"
  if ! dh completion bash > "$script" 2>/dev/null || [ ! -s "$script" ]; then
    reg_fail "E: completion script generation failed"
    cleanup_principal "$user"
    rm -f "$cred"
    return
  fi

  local out
  # The selector introspection surface the completion harness drives must
  # answer on the packaged CLI before the COMPREPLY contract is asserted.
  local sel_out sel_rc
  sel_out="$(dh completion selectors principal --system 2>&1)"; sel_rc=$?
  if [ "$sel_rc" -eq 0 ] && printf '%s\n' "$sel_out" | grep -qx "$user"; then
    reg_ok "E: introspection selectors principal answers for admin"
  else
    reg_fail "E: selectors principal query failed (rc=$sel_rc): $(printf '%s' "$sel_out" | head -2 | tr '\n' ' ' | redact)"
  fi
  sel_out="$(dh completion selectors launcher --system --principal "$user" 2>&1)"; sel_rc=$?
  if [ "$sel_rc" -eq 0 ] && printf '%s\n' "$sel_out" | grep -qx 'killme'; then
    reg_ok "E: introspection selectors launcher answers with the Principal context"
  else
    reg_fail "E: selectors launcher (context) query failed (rc=$sel_rc): $(printf '%s' "$sel_out" | head -2 | tr '\n' ' ' | redact)"
  fi
  sel_out="$(dh completion selectors launcher --system --token-file "$cred" 2>&1)"; sel_rc=$?
  if [ "$sel_rc" -eq 0 ] && printf '%s\n' "$sel_out" | grep -qx 'killme'; then
    reg_ok "E: introspection selectors launcher answers for a principal credential"
  else
    reg_fail "E: selectors launcher (principal credential) query failed (rc=$sel_rc): $(printf '%s' "$sel_out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 1. admin --principal <TAB>: Principal names.
  out="$(run_completion "$script" /usr/bin/docker-helper --system launcher create --principal "")"
  if printf '%s\n' "$out" | grep -qx "$user"; then
    reg_ok "E: admin --principal offers the daemon's Principal names"
  else
    reg_fail "E: admin --principal suggestions = [$(printf '%s' "$out" | tr '\n' ' ' | redact)]"
  fi

  # 2. admin + typed --principal: that Principal's Launcher names.
  out="$(run_completion "$script" /usr/bin/docker-helper --system session create --principal "$user" --launcher "")"
  if printf '%s\n' "$out" | grep -qx 'killme'; then
    reg_ok "E: admin --launcher under a typed --principal offers the Principal's Launcher names"
  else
    reg_fail "E: admin --launcher suggestions = [$(printf '%s' "$out" | tr '\n' ' ' | redact)]"
  fi

  # 3. admin without a Principal context: only globally resolvable IDs.
  local id_out
  id_out="$(dh launcher list --system --principal "$user" --json 2>/dev/null | json_field id)"
  out="$(run_completion "$script" /usr/bin/docker-helper --system session create --launcher "")"
  if printf '%s\n' "$out" | grep -qx "$id_out" && ! printf '%s\n' "$out" | grep -qx 'killme'; then
    reg_ok "E: admin --launcher without a context offers only the resolvable Launcher ID"
  else
    reg_fail "E: admin --launcher suggestions = [$(printf '%s' "$out" | tr '\n' ' ' | redact)] want the ID $id_out only"
  fi

  # 4. Principal credential: its own Launchers only (foreign names absent —
  #    the fixture has none, so any name leak would be visible).
  out="$(run_completion "$script" /usr/bin/docker-helper --system session create --token-file "$cred" --launcher "")"
  if printf '%s\n' "$out" | grep -qx 'killme'; then
    reg_ok "E: principal credential --launcher offers its own Launchers"
  else
    reg_fail "E: principal credential --launcher suggestions = [$(printf '%s' "$out" | tr '\n' ' ' | redact)]"
  fi

  # 5. the inline --flag=value form completes like the separated form.
  local out_eq
  out_eq="$(run_completion "$script" /usr/bin/docker-helper --system session create --principal="$user" --launcher=ki)"
  if [ "$out_eq" = "$out" ] || printf '%s\n' "$out_eq" | grep -qx 'killme'; then
    reg_ok "E: the --launcher=value form offers the same selector"
  else
    reg_fail "E: --launcher=value form suggestions = [$(printf '%s' "$out_eq" | tr '\n' ' ' | redact)]"
  fi

  # 6. integration invariant: the offered selector resolves to exactly the
  #    Session-create target a real create with that selector would use —
  #    the restricted root, never the wider Principal ceiling.
  out="$(run_completion "$script" /usr/bin/docker-helper --system session create \
    --token-file "$cred" --launcher killme --workspace "")"
  assert_completion "E: the offered selector resolves the restricted create target" "$opt" "$out" || true

  cleanup_principal "$user"
  rm -f "$cred" "$script"
}

subcase_a
subcase_b
subcase_c
subcase_d
subcase_e

rm -rf "$TMPDIR_REG14"
reg_result
