#!/usr/bin/env bash
# uat-regression-rc5-cli-grammar.sh — Release 2.2 RC5 CLI grammar and
# stored-roots completion acceptance.
#
# What is proven (against the installed system service and the real
# generated completion script):
#   A. interspersed flags parser — flags after positional arguments parse
#      and mutate; an unknown option after a positional stays a parse
#      error; a bare `--` keeps option-like tokens positional data; a
#      dash-leading VALUE reaches the domain validation through `--`.
#   B. PATH-first launcher allowed-root grammar — add/set-access/remove
#      read PATH first and the optional trailing positional is the
#      LAUNCHER selector; the retired [LAUNCHER] PATH order is not
#      silently accepted as the old meaning.
#   C. /tmp wide namespace — the exact /tmp root is refused as too broad
#      while a /tmp descendant is accepted by the config CLI.
#   D. canonical rich projection — config show, principal show, and
#      launcher show carry only the rich allowed_roots projection
#      ({path, access} values); the retired allowed_root_entries spelling
#      is not an alias and is rejected as an unknown field.
#   E. completion universes — flags are offered after positionals (used
#      non-repeatables suppressed, repeatables keep being offered), the
#      `--` sentinel stops flag completion, and every allowed-root
#      mutation completes exactly the stored roots it addresses (stored
#      global roots, stored Principal roots, stored Launcher roots, the
#      launcher add ceiling) with no generic host-filesystem leakage.
#   F. completion assertion trust (self-check) — the completion process
#      result is contractual evidence: a non-zero completion exit status
#      fails the assertion before any suggestion comparison, including
#      when the expected output is empty.
#
# Each subcase is independent (collect-all). Docker is not required.
#
# Requires: installed docker-helper system service (active), root, bash.
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "20. RC5 CLI grammar and stored-roots completion acceptance"

reg_require_root
reg_require_service
reg_require_cmd bash "completion acceptance drives a real Bash"

TMPDIR_REG20="/tmp/uat-reg20"
mkdir -p "$TMPDIR_REG20"

# cleanup_principal USER removes the fixture Principal and its OS user.
cleanup_principal() {
  local user="$1"
  dh principal delete --system "$user" >/dev/null 2>&1 || true
  userdel -r "$user" >/dev/null 2>&1 || true
}

# run_completion SCRIPT WORDS... drives the completion function Bash actually
# registered for docker-helper (discovered through `complete -p`, one -F
# registration) with the given command line; prints one COMPREPLY entry per
# line. The snippet's exit code and stderr are persisted to files under
# TMPDIR_REG20 (command substitution would lose shell variables) and are
# reported by assert_completion for failure attribution.
run_completion() {
  local script="$1"
  shift
  local words="" w wq err_file
  for w in "$@"; do
    printf -v wq '%q' "$w"
    words+="${words:+ }${wq}"
  done
  err_file="$TMPDIR_REG20/comp.err"
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
    set -x
    "$func" || exit 4
    set +x
    printf "%s\n" "${COMPREPLY[@]}"
  ' _ "$script" "$words" 2>"$err_file"
  local rc=$?
  printf '%s\n' "$rc" > "$TMPDIR_REG20/comp.rc"
}

# completion_harness_diag LABEL-free diagnostic of the last run_completion
# invocation (rc + key trace lines), safe under set -u when nothing ran yet.
completion_harness_diag() {
  local rc
  rc="$(cat "$TMPDIR_REG20/comp.rc" 2>/dev/null || echo none)"
  printf 'rc=%s trace: %s' "$rc" "$(grep -a -m 4 -E 'docker-helper (completion|config)' "$TMPDIR_REG20/comp.err" 2>/dev/null | redact)"
}

# assert_completion LABEL EXPECTED ACTUAL: EXPECTED and ACTUAL are
# newline-separated; both sides are LC_ALL=C sorted and deduplicated. The
# completion PROCESS result is contractual evidence, not diagnostic-only
# metadata: a non-zero exit status of the last run_completion fails the
# assertion before any suggestion comparison — an empty (or even matching)
# suggestion list from a crashed completion is never a valid PASS.
assert_completion() {
  local label="$1" expected="$2" actual="$3"
  local want have rc
  rc="$(cat "$TMPDIR_REG20/comp.rc" 2>/dev/null || echo none)"
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

# ---------------------------------------------------------------------------
# F. completion assertion harness trust (self-check)
# ---------------------------------------------------------------------------
subcase_f() {
  reg_info "subcase F: completion assertion harness trust (self-check)"
  local script="$TMPDIR_REG20/harness-fake-completion.bash"
  cat > "$script" <<'EOF'
# Fake docker-helper completion registration driven by environment knobs so
# the harness self-check can prove the assertion's process-success contract:
# FAKE_COMPLETION_RC is the function's exit status, FAKE_COMPLETION_OUT its
# stdout.
_dh_uat_fake_completion() {
  if [ -n "${FAKE_COMPLETION_OUT:-}" ]; then
    printf '%s\n' "${FAKE_COMPLETION_OUT:-}"
  fi
  return "${FAKE_COMPLETION_RC:-0}"
}
complete -F _dh_uat_fake_completion docker-helper
EOF

  # assertion_failed EXPECTED ACTUAL runs the REAL assert_completion in a
  # subshell (which contains the reg_fail accounting) and returns 0 when the
  # assertion failed (assert_completion itself returns nonzero on failure).
  assertion_failed() {
    ( assert_completion "harness self-check" "$1" "$2" ) >/dev/null 2>&1
    [ $? -ne 0 ]
  }

  local out
  # The fake's knobs must be exported: run_completion drives them through a
  # child bash, and assignment-prefix variables do not reach it.
  # 1. rc=0 + expected empty -> the assertion passes.
  export FAKE_COMPLETION_RC=0
  unset FAKE_COMPLETION_OUT || true
  out="$(run_completion "$script" docker-helper arg)" || true
  if assertion_failed "" "$out"; then
    reg_fail "F: rc=0 with empty output and empty expectation must pass the assertion"
  else
    reg_ok "F: rc=0 with empty output and empty expectation passes"
  fi

  # 2. rc=0 + matching non-empty output -> the assertion passes.
  export FAKE_COMPLETION_RC=0 FAKE_COMPLETION_OUT="--access"
  out="$(run_completion "$script" docker-helper arg)" || true
  if assertion_failed "--access" "$out"; then
    reg_fail "F: rc=0 with matching non-empty output must pass the assertion"
  else
    reg_ok "F: rc=0 with matching non-empty output passes"
  fi

  # 3. rc!=0 + empty output + expected empty -> the assertion fails (the
  #    confirmed false-positive class: a crashed completion with empty
  #    stdout used to pass an empty expectation).
  export FAKE_COMPLETION_RC=4
  unset FAKE_COMPLETION_OUT || true
  out="$(run_completion "$script" docker-helper arg)" || true
  if assertion_failed "" "$out"; then
    reg_ok "F: rc=4 with empty output and empty expectation fails the assertion"
  else
    reg_fail "F: rc=4 with empty output and empty expectation passed the assertion (false positive)"
  fi

  # 4. rc!=0 + matching-looking output -> the assertion fails: the exit
  #    status is checked before any suggestion comparison.
  export FAKE_COMPLETION_RC=4 FAKE_COMPLETION_OUT="--access"
  out="$(run_completion "$script" docker-helper arg)" || true
  if assertion_failed "--access" "$out"; then
    reg_ok "F: rc=4 with matching-looking output fails the assertion"
  else
    reg_fail "F: rc=4 with matching-looking output passed the assertion (false positive)"
  fi
  unset FAKE_COMPLETION_RC FAKE_COMPLETION_OUT || true

  rm -f "$script"
}

# ---------------------------------------------------------------------------
# A. interspersed flags parser (isolated config; the real in-process parser)
# ---------------------------------------------------------------------------
subcase_a() {
  reg_info "subcase A: interspersed flags parser"
  local cfg="$TMPDIR_REG20/parser-config"
  mkdir -p "$cfg" /tmp/uat-reg20-parser-root
  export DOCKER_HELPER_CONFIG="$cfg/config.json"
  dh init --allowed-root /tmp/uat-reg20-parser-root >/dev/null 2>&1
  local probe=/tmp/uat-reg20-parser-root/probe
  mkdir -p "$probe"

  # 1. flags after positional parse and mutate.
  local out
  if out="$(dh config allowed-root add "$probe" --access read_only 2>&1)" && printf '%s' "$out" | grep -q 'added'; then
    reg_ok "A: config allowed-root add PATH --access parses and adds"
  else
    reg_fail "A: config allowed-root add PATH --access failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
  out="$(dh config allowed-root list --json 2>&1)"
  if printf '%s' "$out" | grep -q '"access": "read_only"'; then
    reg_ok "A: the post-positional --access value was applied"
  else
    reg_fail "A: post-positional --access not applied: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 2. an unknown option after a positional stays a parse error.
  local rc=0
  out="$(dh config allowed-root add "$probe" --bogus 2>&1)" || rc=$?
  if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -q 'not defined'; then
    reg_ok "A: unknown option after the positional stays a parse error"
  else
    reg_fail "A: unknown option after positional: rc=$rc out=$(printf '%s' "$out" | head -1 | redact)"
  fi

  # 3. a bare -- keeps option-like tokens positional data.
  rc=0
  out="$(dh config allowed-root add "$probe" -- --access 2>&1)" || rc=$?
  if [ "$rc" -eq 2 ] && ! printf '%s' "$out" | grep -q 'access must be'; then
    reg_ok "A: the bare -- sentinel keeps option-like tokens positional"
  else
    reg_fail "A: bare -- sentinel: rc=$rc out=$(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 4. a dash-leading VALUE reaches the domain validation through --.
  rc=0
  out="$(dh config set -- session_ttl -1h 2>&1)" || rc=$?
  if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -q 'positive'; then
    reg_ok "A: a dash-leading VALUE reaches the domain validation through --"
  else
    reg_fail "A: dash-leading VALUE via --: rc=$rc out=$(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  unset DOCKER_HELPER_CONFIG
}

# ---------------------------------------------------------------------------
# B. PATH-first launcher allowed-root grammar (live daemon)
# ---------------------------------------------------------------------------
subcase_b() {
  reg_info "subcase B: PATH-first launcher allowed-root grammar"
  local user="uatreg20b" home
  home="$(reg_setup_principal "$user")" || { reg_fail "B: fixture setup failed"; return; }
  mkdir -p "$home/b1" "$home/b2"
  chown -R "$user:$user" "$home"
  if ! dh launcher create --principal "$user" --name build-agent --no-credential >/dev/null 2>&1; then
    reg_fail "B: launcher create failed"
    cleanup_principal "$user"
    return
  fi

  local out rc
  # 1. add PATH LAUNCHER: the new grammar targets the named launcher.
  if out="$(dh launcher allowed-root add --principal "$user" "$home/b1" build-agent 2>&1)" && printf '%s' "$out" | grep -q 'added'; then
    reg_ok "B: launcher allowed-root add PATH LAUNCHER adds to the named launcher"
  else
    reg_fail "B: add PATH LAUNCHER failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
  out="$(dh launcher allowed-root list --principal "$user" build-agent 2>&1)"
  if printf '%s' "$out" | grep -qx "$home/b1"; then
    reg_ok "B: the named launcher carries the added root"
  else
    reg_fail "B: list build-agent missing the root: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 2. the retired [LAUNCHER] PATH order is not silently accepted.
  rc=0
  out="$(dh launcher allowed-root add --principal "$user" build-agent "$home/b2" 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    reg_ok "B: the retired [LAUNCHER] PATH order is no longer the accepted meaning"
  else
    reg_fail "B: the retired [LAUNCHER] PATH order still mutated something: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 3. set-access PATH ACCESS [LAUNCHER].
  if out="$(dh launcher allowed-root set-access --principal "$user" "$home/b1" read_only build-agent 2>&1)" && printf '%s' "$out" | grep -q 'read_only'; then
    reg_ok "B: launcher allowed-root set-access PATH ACCESS LAUNCHER works"
  else
    reg_fail "B: set-access PATH ACCESS LAUNCHER failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 4. remove PATH [LAUNCHER].
  if out="$(dh launcher allowed-root remove --principal "$user" "$home/b1" build-agent 2>&1)" && printf '%s' "$out" | grep -q 'removed'; then
    reg_ok "B: launcher allowed-root remove PATH LAUNCHER works"
  else
    reg_fail "B: remove PATH LAUNCHER failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  cleanup_principal "$user"
}

# ---------------------------------------------------------------------------
# C. /tmp wide namespace (isolated config)
# ---------------------------------------------------------------------------
subcase_c() {
  reg_info "subcase C: /tmp wide namespace"
  local cfg="$TMPDIR_REG20/tmpns-config"
  mkdir -p "$cfg" /tmp/uat-reg20-tmpns
  export DOCKER_HELPER_CONFIG="$cfg/config.json"
  dh init --allowed-root /tmp/uat-reg20-tmpns >/dev/null 2>&1

  # 1. the exact /tmp namespace is too broad.
  local out rc
  rc=0
  out="$(dh config allowed-root add /tmp 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'too broad'; then
    reg_ok "C: the exact /tmp root is refused as too broad"
  else
    reg_fail "C: exact /tmp root: rc=$rc out=$(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 2. a /tmp descendant is accepted.
  local probe=/tmp/uat-reg20-tmpns/probe
  mkdir -p "$probe"
  if out="$(dh config allowed-root add "$probe" 2>&1)" && printf '%s' "$out" | grep -q 'added'; then
    reg_ok "C: a /tmp descendant is accepted by the config CLI"
  else
    reg_fail "C: /tmp descendant rejected: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 3. a forbidden system tree stays forbidden.
  rc=0
  out="$(dh config allowed-root add /etc 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'forbidden'; then
    reg_ok "C: a forbidden system tree stays forbidden"
  else
    reg_fail "C: /etc accepted: rc=$rc out=$(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  unset DOCKER_HELPER_CONFIG
}

# ---------------------------------------------------------------------------
# D. canonical rich projection (live daemon)
# ---------------------------------------------------------------------------
subcase_d() {
  reg_info "subcase D: canonical rich allowed_roots projection"
  local user="uatreg20d" home
  home="$(reg_setup_principal "$user")" || { reg_fail "D: fixture setup failed"; return; }
  mkdir -p "$home/d1"
  chown -R "$user:$user" "$home"
  dh launcher create --system --principal "$user" --name legacyprobe --allowed-root "$home/d1" --no-credential >/dev/null 2>&1

  local out rc
  # 1. config show carries only the canonical allowed_roots projection.
  out="$(dh config show 2>&1)"
  if printf '%s' "$out" | grep -q '"allowed_roots"' && ! printf '%s' "$out" | grep -q '"allowed_root_entries"'; then
    reg_ok "D: config show carries allowed_roots only"
  else
    reg_fail "D: config show projection: $(printf '%s' "$out" | head -3 | tr '\n' ' ' | redact)"
  fi

  # 2. config show allowed_roots is the rich FIELD and prints the array.
  out="$(dh config show allowed_roots 2>&1)"
  if printf '%s' "$out" | grep -q '"path"' && printf '%s' "$out" | grep -q '"access"'; then
    reg_ok "D: config show allowed_roots FIELD prints the rich array"
  else
    reg_fail "D: config show allowed_roots: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 3. the retired spelling is an unknown config show FIELD, never an alias.
  rc=0
  out="$(dh config show allowed_root_entries 2>&1)" || rc=$?
  if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -q 'unknown field'; then
    reg_ok "D: config show allowed_root_entries is an unknown field"
  else
    reg_fail "D: config show allowed_root_entries: rc=$rc out=$(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 4. principal show FIELD: allowed_roots works; allowed_root_entries is
  #    rejected as unknown.
  out="$(dh principal show "$user" allowed_roots 2>&1)"
  if printf '%s' "$out" | grep -q '"'"$home"'"'; then
    reg_ok "D: principal show allowed_roots FIELD carries the stored roots"
  else
    reg_fail "D: principal show allowed_roots: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
  rc=0
  out="$(dh principal show "$user" allowed_root_entries 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'unknown field'; then
    reg_ok "D: principal show allowed_root_entries is an unknown field"
  else
    reg_fail "D: principal show allowed_root_entries: rc=$rc out=$(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 5. launcher show carries the canonical allowed_roots only.
  out="$(dh launcher show --principal "$user" legacyprobe 2>&1)"
  if printf '%s' "$out" | grep -q '"allowed_roots"' && ! printf '%s' "$out" | grep -q '"allowed_root_entries"'; then
    reg_ok "D: launcher show carries allowed_roots only"
  else
    reg_fail "D: launcher show projection: $(printf '%s' "$out" | head -3 | tr '\n' ' ' | redact)"
  fi

  cleanup_principal "$user"
}

# ---------------------------------------------------------------------------
# E. completion universes
# ---------------------------------------------------------------------------
subcase_e() {
  reg_info "subcase E: completion universes"
  local user="uatreg20e" home
  home="$(reg_setup_principal "$user")" || { reg_fail "E: fixture setup failed"; return; }
  mkdir -p "$home/e1" "$home/e2"
  chown -R "$user:$user" "$home"

  # Seed stored roots in every family through the real CLI.
  dh launcher create --system --principal "$user" --name build-agent --no-credential >/dev/null 2>&1
  dh config allowed-root add "$home/e2" >/dev/null 2>&1
  dh principal allowed-root add --system "$user" "$home/e1" >/dev/null 2>&1
  dh launcher allowed-root add --system --principal "$user" "$home/e2" build-agent >/dev/null 2>&1

  local script="$TMPDIR_REG20/completion-20.bash"
  if ! dh completion bash > "$script" 2>/dev/null || [ ! -s "$script" ]; then
    reg_fail "E: completion script generation failed"
    cleanup_principal "$user"
    return
  fi

  local out
  # 1. flags are offered after a positional argument.
  out="$(run_completion "$script" /usr/bin/docker-helper launcher allowed-root add "$home/e1" --a)"
  assert_completion "E: --access is offered after the positional PATH" "--access" "$out" || true

  # 2. a used non-repeatable flag is suppressed; the remaining ones are not.
  out="$(run_completion "$script" /usr/bin/docker-helper launcher allowed-root add --access read_only "$home/e1" --a)"
  assert_completion "E: the used --access is suppressed" "" "$out" || true
  out="$(run_completion "$script" /usr/bin/docker-helper launcher allowed-root add --access read_only "$home/e1" --p)"
  assert_completion "E: the remaining --principal is still offered" "--principal" "$out" || true

  # 3. a repeatable flag keeps being offered after a prior occurrence.
  out="$(run_completion "$script" /usr/bin/docker-helper launcher create --allowed-root "$home/e1" --al)"
  assert_completion "E: the repeatable --allowed-root is still offered" "--allowed-root" "$out" || true

  # 4. the -- sentinel stops flag completion.
  out="$(run_completion "$script" /usr/bin/docker-helper launcher allowed-root add "$home/e1" -- --)"
  assert_completion "E: after -- no flags are offered" "" "$out" || true

  # 5. launcher allowed-root add PATH completes the effective Principal
  #    ceiling as boundary segments — never the host filesystem.
  local eff_roots expected_top
  eff_roots="$(dh completion roots principal --principal "$user" 2>/dev/null)"
  expected_top="$(printf '%s\n' "$eff_roots" | sed -n 's|^/||p' | sed 's|/.*$||' | LC_ALL=C sort -u | sed 's|^|/|')"
  out="$(run_completion "$script" /usr/bin/docker-helper launcher allowed-root add --principal "$user" "")"
  if [ -n "$expected_top" ]; then
    assert_completion "E: launcher add PATH offers exactly the ceiling boundary segments" "$expected_top" "$out" || true
  else
    reg_fail "E: launcher add ceiling probe failed (completion roots principal empty)"
  fi

  # 6. launcher allowed-root remove PATH completes the stored Launcher
  #    roots of the default Launcher; the stored root completes exactly.
  dh launcher allowed-root add --system --principal "$user" "$home/e1" >/dev/null 2>&1
  out="$(run_completion "$script" /usr/bin/docker-helper launcher allowed-root remove --principal "$user" "")"
  assert_completion "E: launcher remove PATH offers exactly the default-Launcher stored roots" "$home/e1" "$out" || true

  # 7. principal allowed-root mutations: USER completes from the daemon
  #    selector introspection; PATH completes the stored Principal roots
  #    (derived from the authoritative list — fixture provisioning may
  #    seed the Principal's home as a stored root too).
  local stored_pr
  stored_pr="$(dh principal allowed-root list --system "$user" 2>/dev/null)"
  out="$(run_completion "$script" /usr/bin/docker-helper principal allowed-root remove "$user" "")"
  assert_completion "E: principal remove USER PATH offers the stored Principal roots" "$stored_pr" "$out" || true

  # 8. config allowed-root mutations complete the stored global roots
  #    (derived from the authoritative list; the global ceiling itself is
  #    always a stored root).
  local stored_global
  stored_global="$(dh config allowed-root list 2>/dev/null)"
  out="$(run_completion "$script" /usr/bin/docker-helper config allowed-root remove "")"
  assert_completion "E: config remove PATH offers exactly the stored global roots" "$stored_global" "$out" || true

  cleanup_principal "$user"
}

subcase_f
subcase_a
subcase_b
subcase_c
subcase_d
subcase_e

rm -rf "$TMPDIR_REG20"
reg_result
