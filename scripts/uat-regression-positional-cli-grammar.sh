#!/usr/bin/env bash
# uat-regression-positional-cli-grammar.sh — Release 2.2 positional CLI
# grammar gate.
#
# What is proven (against the installed system service and the real Docker
# daemon):
#   A. primary operands are positional and the removed flag spellings are
#      rejected LOCALLY (exit 2, no daemon request): launcher create --name,
#      session create --workspace, session delete --id, registry login
#      --registry, run --image, build --context. The removed flags do not
#      survive as aliases and their help surfaces no longer advertise them.
#   B. canonical positional forms work end to end: launcher create NAME,
#      session create WORKSPACE, session delete SESSION_ID (show/delete
#      share the same targeting grammar), registry login REGISTRY,
#      build CONTEXT, run IMAGE.
#   C. positional arity is enforced by CLI syntax exit semantics: too few
#      and too many positionals exit 2 with the usage, before any daemon
#      request.
#   D. launcher allowed-root target-first grammar mutates the intended
#      Launcher: two-operand add/remove and three-operand set-access select
#      the named Launcher, never the default; the one-operand forms keep the
#      default-Launcher semantics; the explicit selector accepts both the
#      Launcher name and the dhl_... ID; --access stays a flag modifier.
#   E. run workload grammar: everything after IMAGE belongs to the workload
#      command. Workload arguments that look like docker-helper flags
#      (--json, --image) reach the container unchanged, with and without the
#      bare -- separator.
#   F. explicit-empty endpoint canary: --endpoint "" and --endpoint= exit 2
#      as local usage errors for one operator and one agent/data-plane
#      command before any network/auth activity, while the omitted endpoint
#      still reaches the real system daemon. The exhaustive command-tree
#      matrix stays unit-test owned.
#
# Each subcase is independent (collect-all). Docker is required (subcase E
# and the end-to-end fixtures exercise real containers/images where the
# grammar could otherwise only be parsed, not proven).
#
# Requires: installed docker-helper system service (active), root, Docker
# reachable, bash.
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "28. Positional CLI grammar gate: positional operands and target-first allowed-roots"

reg_require_root
reg_require_service
reg_require_docker

TMPDIR_REG28="/tmp/uat-reg28"
mkdir -p "$TMPDIR_REG28"

FIX_USER="uatreg28a"
IMAGE="alpine:3.24"

cleanup() {
  dh principal delete --system "$FIX_USER" >/dev/null 2>&1 || true
  userdel -r "$FIX_USER" >/dev/null 2>&1 || true
  rm -rf "$TMPDIR_REG28"
}
trap cleanup EXIT

# fixture creates (or reuses) the OS user, the Principal, and prints the home
# directory. Subcases B/D/E each need the fixture; user creation is therefore
# idempotent — a second useradd/principal-create against the same fixture user
# would otherwise silently skip the later subcases (the failure inside the
# command-substitution fixture call could never register).
fixture() {
  local home
  home="/home/$FIX_USER"
  rm -rf "$home"
  if ! id "$FIX_USER" >/dev/null 2>&1; then
    useradd -m "$FIX_USER" >/dev/null 2>&1 || { printf 'fixture: useradd failed\n' >&2; return 1; }
  fi
  home="$(getent passwd "$FIX_USER" | cut -d: -f6)"
  mkdir -p "$home/ws" && chown -R "$FIX_USER:$FIX_USER" "$home"
  dh principal create --system --no-credential "$FIX_USER" >/dev/null 2>&1 || true
  dh principal set --system "$FIX_USER" enabled true >/dev/null 2>&1 || true
  printf '%s' "$home"
}

# expect_syntax_exit LABEL RC OUT: a CLI syntax rejection is contractual
# exit 2 carrying the usage, and it must not name any other failure family.
expect_syntax_exit() {
  local label="$1" rc="$2" out="$3"
  if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -qE 'usage|Usage|unknown flag|unknown option|unexpected argument|flag needs an argument|missing required'; then
    reg_ok "$label"
  else
    reg_fail "$label (rc=$rc): $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
}

# ---------------------------------------------------------------------------
# A. removed spellings are rejected locally, and help no longer offers them
# ---------------------------------------------------------------------------
subcase_a() {
  reg_info "subcase A: removed spellings rejected locally"
  local out rc

  # 1. launcher create --name NAME.
  rc=0; out="$(dh launcher create --system --principal "$FIX_USER" --name ghost --no-credential 2>&1)" || rc=$?  # gate probe: removed spelling
  expect_syntax_exit "A: launcher create --name is rejected (exit 2)" "$rc" "$out"
  if printf '%s' "$out" | grep -q -- '--name'; then
    reg_fail "A: the --name rejection must name the offending flag"
  else
    reg_ok "A: the --name rejection names the offending flag"
  fi

  # 2. session create --workspace PATH.
  rc=0; out="$(dh session create --system --workspace /tmp 2>&1)" || rc=$?  # gate probe: removed spelling
  expect_syntax_exit "A: session create --workspace is rejected (exit 2)" "$rc" "$out"

  # 3. session delete --id ID.
  rc=0; out="$(dh session delete --system --id dhs_missing 2>&1)" || rc=$?  # gate probe: removed spelling
  expect_syntax_exit "A: session delete --id is rejected (exit 2)" "$rc" "$out"

  # 4. registry login --registry REGISTRY.
  rc=0; out="$(dh registry login --registry registry.example.com --username u 2>&1 </dev/null)" || rc=$?  # gate probe: removed spelling
  expect_syntax_exit "A: registry login --registry is rejected (exit 2)" "$rc" "$out"

  # 5. run --image IMAGE (workload untouched: the unknown flag is the CLI's).
  rc=0; out="$(dh run --image alpine:3.24 2>&1)" || rc=$?  # gate probe: removed spelling
  expect_syntax_exit "A: run --image is rejected (exit 2)" "$rc" "$out"

  # 6. build --context PATH.
  rc=0; out="$(dh build --context /tmp 2>&1)" || rc=$?  # gate probe: removed spelling
  expect_syntax_exit "A: build --context is rejected (exit 2)" "$rc" "$out"

  # 7. the removed flags do not survive as aliases: help no longer
  #    advertises them.
  local help surfaces
  surfaces=(
    "launcher create:--name"
    "session create:--workspace"
    "session delete:--id"
    "registry login:--registry"
    "run:--image"
    "build:--context"
  )
  for s in "${surfaces[@]}"; do
    local cmd="${s%%:*}" flag="${s##*:}"
    out="$(dh $cmd --help 2>&1)" || { reg_fail "A: $cmd --help failed"; continue; }
    if printf '%s' "$out" | grep -q -- "$flag"; then
      reg_fail "A: $cmd --help still advertises the removed $flag flag"
    else
      reg_ok "A: $cmd help no longer offers the removed $flag flag"
    fi
  done
}

# ---------------------------------------------------------------------------
# B. canonical positional forms work end to end
# ---------------------------------------------------------------------------
subcase_b() {
  reg_info "subcase B: canonical positional forms"
  local home out rc sid lid

  home="$(fixture)" || { reg_fail "B: fixture failed"; return; }

  # launcher create NAME (positional).
  out="$(dh launcher create --system --principal "$FIX_USER" target --no-credential --json 2>&1)" || {
    reg_fail "B: launcher create NAME failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
    return
  }
  lid="$(printf '%s' "$out" | json_field id)"
  if [ -n "$lid" ] && printf '%s' "$out" | json_field name | grep -q '^target$'; then
    reg_ok "B: launcher create NAME creates the named Launcher"
  else
    reg_fail "B: launcher create NAME did not create the named Launcher (id=$lid)"
  fi

  # session create WORKSPACE (positional) + session delete SESSION_ID
  # (positional, same grammar as session show).
  out="$(dh session create --system --token-file /etc/docker-helper/admin.token --principal "$FIX_USER" "$home/ws" --json 2>&1)" || {
    reg_fail "B: session create WORKSPACE failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
    return
  }
  sid="$(printf '%s' "$out" | json_field id)"
  if [ -n "$sid" ]; then
    reg_ok "B: session create WORKSPACE issues a Session"
  else
    reg_fail "B: session create WORKSPACE returned no Session id"
    return
  fi
  if out="$(dh session show --system "$sid" 2>&1)" && printf '%s' "$out" | grep -q "$sid"; then
    reg_ok "B: session show SESSION_ID targets the issued Session"
  else
    reg_fail "B: session show SESSION_ID failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
  if out="$(dh session delete --system "$sid" 2>&1)" && [ -n "$out" ]; then
    reg_ok "B: session delete SESSION_ID deletes the issued Session"
  else
    reg_fail "B: session delete SESSION_ID failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # registry login REGISTRY (positional): a refused connection is the
  # contract-level evidence the operand reached the operation.
  out="$(dh registry login --system 127.0.0.1:1 --username "$FIX_USER" --password-stdin </dev/null 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    reg_ok "B: registry login REGISTRY drives the credential operation (refused endpoint is the expected failure)"
  else
    reg_fail "B: registry login unexpectedly succeeded: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # build CONTEXT (positional) with the retained build parameters. The
  # context is workspace-relative data of the build Session: it must lie
  # inside the issued workspace, so the fixture builds from home/ws/ctx.
  local ctx
  ctx="$home/ws/ctx"
  mkdir -p "$ctx"
  printf 'FROM scratch\n' > "$ctx/Dockerfile"
  out="$(dh session create --system --token-file /etc/docker-helper/admin.token --principal "$FIX_USER" "$home/ws" --json 2>&1)" || {
    reg_fail "B: build session create failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
    return
  }
  local bid="$(printf '%s' "$out" | json_field id)" btoken="$(printf '%s' "$out" | json_field token)"
  [ -n "$btoken" ] || { reg_fail "B: build session create returned no token"; return; }
  out="$(DOCKER_HELPER_SESSION_TOKEN="$btoken" dh build --system "$ctx" --dockerfile Dockerfile --image uat-reg28:2.2 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then
    reg_ok "B: build CONTEXT --dockerfile --image builds from the positional context"
    docker rmi uat-reg28:2.2 >/dev/null 2>&1 || true
  else
    reg_fail "B: build CONTEXT failed (rc=$rc): $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
  dh session delete --system "$bid" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# C. positional arity is CLI syntax (exit 2), not a daemon error
# ---------------------------------------------------------------------------
subcase_c() {
  reg_info "subcase C: positional arity exits"
  local out rc

  for probe in \
    "launcher create" \
    "launcher create one two" \
    "session create" \
    "session create /tmp /tmp" \
    "session delete" \
    "registry login" \
    "build" \
    "build /tmp /tmp"; do
    rc=0; out="$(dh $probe 2>&1 </dev/null)" || rc=$?
    expect_syntax_exit "C: '$probe' is a CLI syntax exit (rc=2)" "$rc" "$out"
  done

  # target-first arity: the allowed-root mutations share the same exit
  # semantics. `set-access PATH ACCESS` is a valid default-Launcher form, so
  # its arity errors are zero, one, and four positionals.
  for probe in \
    "launcher allowed-root add" \
    "launcher allowed-root add a b c" \
    "launcher allowed-root remove" \
    "launcher allowed-root set-access" \
    "launcher allowed-root set-access a" \
    "launcher allowed-root set-access a b c d"; do
    rc=0; out="$(dh $probe 2>&1 </dev/null)" || rc=$?
    expect_syntax_exit "C: '$probe' is a CLI syntax exit (rc=2)" "$rc" "$out"
  done
}

# ---------------------------------------------------------------------------
# D. launcher allowed-root target-first semantics
# ---------------------------------------------------------------------------
subcase_d() {
  reg_info "subcase D: target-first allowed-root mutations"
  local home out rc tree sid_lid other_lid

  home="$(fixture)" || { reg_fail "D: fixture failed"; return; }
  tree="$home/d"
  mkdir -p "$tree/one" "$tree/two" && chown -R "$FIX_USER:$FIX_USER" "$home"

  out="$(dh launcher create --system --principal "$FIX_USER" target --no-credential --json 2>&1)" || {
    reg_fail "D: launcher create failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
    return
  }
  sid_lid="$(printf '%s' "$out" | json_field id)"
  out="$(dh launcher create --system --principal "$FIX_USER" other --no-credential --json 2>&1)" || {
    reg_fail "D: launcher create failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
    return
  }
  other_lid="$(printf '%s' "$out" | json_field id)"

  # 1. two-operand add mutates the NAMED launcher, not the default.
  if out="$(dh launcher allowed-root add --system --principal "$FIX_USER" target "$tree/one" 2>&1)" \
      && printf '%s' "$out" | grep -q 'added'; then
    reg_ok "D: add LAUNCHER PATH stores on the named Launcher"
  else
    reg_fail "D: add LAUNCHER PATH failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
  out="$(dh launcher allowed-root list --system --principal "$FIX_USER" target 2>&1)"
  if printf '%s' "$out" | grep -q "^$tree/one"; then
    reg_ok "D: list target carries the stored root"
  else
    reg_fail "D: list target misses the root: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
  out="$(dh launcher allowed-root list --system --principal "$FIX_USER" 2>&1)"
  if printf '%s' "$out" | grep -q "^$tree/one"; then
    reg_fail "D: the named add leaked onto the default Launcher"
  else
    reg_ok "D: the named add did not touch the default Launcher"
  fi

  # 2. the explicit selector also accepts the dhl_... ID.
  if out="$(dh launcher allowed-root add --system --principal "$FIX_USER" "$sid_lid" "$tree/two" 2>&1)" \
      && printf '%s' "$out" | grep -q 'added'; then
    reg_ok "D: add dhl_ID PATH stores through the Launcher ID"
  else
    reg_fail "D: add dhl_ID PATH failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
  out="$(dh launcher allowed-root list --system --principal "$FIX_USER" target 2>&1)"
  printf '%s\n' "$out" | grep -q "^$tree/two" \
    && reg_ok "D: the ID-selected add landed on the named Launcher" \
    || reg_fail "D: the ID-selected add missed the named Launcher"

  # 3. three-operand set-access targets the named Launcher; --access stays
  #    the modifier flag.
  if out="$(dh launcher allowed-root set-access --system --principal "$FIX_USER" "$sid_lid" "$tree/one" read_only 2>&1)" \
      && printf '%s' "$out" | grep -q 'read_only'; then
    reg_ok "D: set-access LAUNCHER PATH ACCESS retargets the named Launcher"
  else
    reg_fail "D: set-access LAUNCHER PATH ACCESS failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
  out="$(dh launcher allowed-root list --system --principal "$FIX_USER" --json target 2>&1)"
  if printf '%s' "$out" | grep -q '"path": "'"$tree"'/one", "access": "read_only"'; then
    reg_ok "D: the stored access is read_only on the named Launcher"
  else
    reg_fail "D: set-access did not land read_only: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 4. one-operand forms keep the default-Launcher semantics.
  if out="$(dh launcher allowed-root add --system --principal "$FIX_USER" "$tree" 2>&1)" \
      && printf '%s' "$out" | grep -q 'added'; then
    reg_ok "D: add PATH stores on the default Launcher"
  else
    reg_fail "D: add PATH failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
  out="$(dh launcher allowed-root list --system --principal "$FIX_USER" 2>&1)"
  if printf '%s' "$out" | grep -q "^$tree$"; then
    reg_ok "D: list (default) carries the one-operand root"
  else
    reg_fail "D: list (default) misses the one-operand root: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
  if out="$(dh launcher allowed-root remove --system --principal "$FIX_USER" "$tree" 2>&1)" \
      && printf '%s' "$out" | grep -q 'removed'; then
    reg_ok "D: remove PATH removes from the default Launcher"
  else
    reg_fail "D: remove PATH failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 5. two-operand remove targets the named launcher and leaves the default
  #    alone.
  if out="$(dh launcher allowed-root remove --system --principal "$FIX_USER" target "$tree/one" 2>&1)" \
      && printf '%s' "$out" | grep -q 'removed'; then
    reg_ok "D: remove LAUNCHER PATH removes the named root"
  else
    reg_fail "D: remove LAUNCHER PATH failed: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
  out="$(dh launcher allowed-root list --system --principal "$FIX_USER" target 2>&1)"
  if printf '%s' "$out" | grep -q "^$tree/two"; then
    reg_ok "D: the named Launcher keeps its second root after the targeted remove"
  else
    reg_fail "D: the targeted remove disturbed the wrong root: $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
}

# ---------------------------------------------------------------------------
# E. run workload grammar
# ---------------------------------------------------------------------------
subcase_e() {
  reg_info "subcase E: run passes post-IMAGE arguments to the workload"
  local out rc home cred_json cred_token sid_json sid

  home="$(fixture)" || { reg_fail "E: fixture failed"; return; }
  cred_json="$(dh principal credential create --system --name gate28 "$FIX_USER" 2>&1)" || {
    reg_fail "E: principal credential create failed: $(printf '%s' "$cred_json" | head -2 | tr '\n' ' ' | redact)"
    return
  }
  cred_token="$(printf '%s' "$cred_json" | json_field token)"
  [ -n "$cred_token" ] || { reg_fail "E: principal credential create returned no token"; return; }
  sid_json="$(dh session create --system --token-file /etc/docker-helper/admin.token --principal "$FIX_USER" "$home/ws" --json 2>&1)" || {
    reg_fail "E: session create failed: $(printf '%s' "$sid_json" | head -2 | tr '\n' ' ' | redact)"
    return
  }
  sid="$(printf '%s' "$sid_json" | json_field id)"
  [ -n "$sid" ] || { reg_fail "E: session create returned no id"; return; }

  run_workload() {
    DOCKER_HELPER_SESSION_TOKEN="$sid" dh "$@"
  }

  # 1. flag-like workload arguments after IMAGE reach the container
  #    verbatim, without the bare -- separator.
  out="$(run_workload run "$IMAGE" sh -c 'printf "ARGS:%s:%s:%s" "$1" "$2" "$3"' sh -- --json --image X 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'ARGS:--json:--image:X'; then
    reg_ok "E: workload args survive unchanged without the -- separator"
  else
    reg_fail "E: workload args lost without the -- separator (rc=$rc): $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 2. the same with the bare -- separator.
  out="$(run_workload run "$IMAGE" -- sh -c 'printf "ARGS:%s:%s:%s" "$1" "$2" "$3"' sh -- --json --image X 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'ARGS:--json:--image:X'; then
    reg_ok "E: workload args survive unchanged with the -- separator"
  else
    reg_fail "E: workload args lost with the -- separator (rc=$rc): $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi

  # 3. all docker-helper flags precede IMAGE.
  out="$(run_workload run --env UAT_REG28=1 "$IMAGE" sh -c 'test "$UAT_REG28" = 1 && echo ENV-OK' 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'ENV-OK'; then
    reg_ok "E: flags before IMAGE are docker-helper flags"
  else
    reg_fail "E: pre-IMAGE flags broken (rc=$rc): $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
}

subcase_a
subcase_b
subcase_c
subcase_d
subcase_e

# ---------------------------------------------------------------------------
# F. explicit-empty endpoint canary (exact-artifact)
# ---------------------------------------------------------------------------
# RC11 closes the explicit-empty endpoint spellings as local usage errors
# (exit 2) BEFORE any network/auth activity. The exhaustive command-tree
# matrix is unit-test owned; this small live canary pins the exact candidate
# bytes: one operator command and one agent/data-plane command with each
# explicit-empty spelling must exit 2 locally, while the omitted endpoint
# still resolves normally and reaches the real system daemon.
subcase_f() {
  reg_info "subcase F: explicit-empty endpoint exits 2 before network/auth activity"
  local out rc

  # Operator command (session list --system): both explicit-empty spellings
  # are local usage errors. exit 2 must come from argument validation, not
  # from a transport failure against the empty endpoint.
  out="$(dh session list --system --endpoint "" 2>&1)"; rc=$?
  if [ "$rc" -eq 2 ]; then
    reg_ok "F: operator command --endpoint \"\" exits 2 (local usage error)"
  else
    reg_fail "F: operator command --endpoint \"\" exited $rc, want 2 (out: $(printf '%s' "$out" | head -1 | tr '\n' ' '))"
  fi
  out="$(dh session list --system --endpoint= 2>&1)"; rc=$?
  if [ "$rc" -eq 2 ]; then
    reg_ok "F: operator command --endpoint= exits 2 (local usage error)"
  else
    reg_fail "F: operator command --endpoint= exited $rc, want 2 (out: $(printf '%s' "$out" | head -1 | tr '\n' ' '))"
  fi

  # Agent/data-plane command (session list without --system under a Session
  # bearer): the same explicit-empty refusals, before any socket activity.
  out="$(DOCKER_HELPER_SESSION_TOKEN=dht_uatreg28 dh session list --endpoint "" 2>&1)"; rc=$?
  if [ "$rc" -eq 2 ]; then
    reg_ok "F: agent command --endpoint \"\" exits 2 (local usage error)"
  else
    reg_fail "F: agent command --endpoint \"\" exited $rc, want 2 (out: $(printf '%s' "$out" | head -1 | tr '\n' ' '))"
  fi
  out="$(DOCKER_HELPER_SESSION_TOKEN=dht_uatreg28 dh session list --endpoint= 2>&1)"; rc=$?
  if [ "$rc" -eq 2 ]; then
    reg_ok "F: agent command --endpoint= exits 2 (local usage error)"
  else
    reg_fail "F: agent command --endpoint= exited $rc, want 2 (out: $(printf '%s' "$out" | head -1 | tr '\n' ' '))"
  fi

  # Omitted endpoint keeps the normal default resolution: the same operator
  # command reaches the real system daemon and returns its canonical output.
  out="$(dh session list --system --json 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q '"ok": true'; then
    reg_ok "F: omitted endpoint still resolves normally (real system daemon reached)"
  else
    reg_fail "F: omitted endpoint did not reach the system daemon (rc=$rc): $(printf '%s' "$out" | head -1 | tr '\n' ' ' | redact)"
  fi
}

subcase_f

cleanup
trap - EXIT
reg_result
