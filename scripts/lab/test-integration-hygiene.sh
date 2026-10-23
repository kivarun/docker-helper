#!/usr/bin/env bash
#
# test-integration-hygiene.sh — source-level hygiene regression tests for
# scripts/lab/integration-agent-vm.sh.
#
# The integration script itself runs only inside the lab VM (its guard refuses
# anywhere else and it needs the real daemon), so its RUNTIME hygiene is proven
# at VM acceptance. These tests lock the SOURCE-level invariants that make that
# runtime hygiene possible, so a regression cannot silently reintroduce
# predictable global temp paths, world-writable evidence files, or leaked
# credential modes.
#
# What this protects (one invariant per test):
#   1. restrictive umask (077) is set for the whole run;
#   2. the per-run workspace comes from mktemp -d (unpredictable, 0700);
#   3. no predictable global /tmp path is used for any artifact;
#   4. credential material is written to a root-owned 0700 subdirectory;
#   5. credential files are explicitly 0600;
#   6. the agent-writable recorder area is a dedicated agent-owned 0750
#      directory (no world-writable evidence file, no chmod 0666);
#   7. cleanup traps cover EXIT, INT and TERM and remove only this run's
#      directory (no global /tmp/itest-* glob);
#   8. the shim and runner stay executable/readable by the agent user;
#   9. no shell tracing is enabled (bearers must never enter a trace);
#  10. the moved default credential is restored by the cleanup.
#
# Usage: scripts/lab/test-integration-hygiene.sh

# Assertion helpers accumulate failures; unhandled shell errors abort.
set -eu

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INTEG="$SRC_DIR/lab/integration-agent-vm.sh"
[ -f "$INTEG" ] || { echo "missing $INTEG" >&2; exit 1; }

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
check() { # description expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2', got '$3')"; fi
}
# Bash may invoke this handler in a subshell; changing FAIL inside it would
# be lost. Return a hard error and let errexit refuse a green suite.
command_not_found_handle() {
  printf 'FATAL - unknown test command or helper: %s\n' "$1" >&2
  return 127
}

has() { # desc pattern (extended regex)
  if grep -Eq -- "$2" "$INTEG"; then ok "$1"; else bad "$1 (pattern absent: $2)"; fi
}
lacks() { # desc pattern (fixed string)
  if grep -qF -- "$2" "$INTEG"; then bad "$1 (forbidden pattern present: $2)"; else ok "$1"; fi
}

has "umask 077 is set" '^umask 077$'
has "workspace comes from mktemp -d" 'ITEST_DIR="\$\(mktemp -d\)"'
lacks "no predictable global /tmp/itest path" "/tmp/itest-"
has "secrets live in a 0700 subdirectory" 'mkdir -m 0700 "\$SECRETS_DIR"'
has "credential files are explicitly 0600" 'chmod 0600 "\$SECRETS_DIR/'
has "recorder area is agent-owned 0750" 'install -d -m 0750 -o "\$AGENT_USER"'
lacks "no world-writable evidence file (chmod 0666)" 'chmod 0666'
has "cleanup trap on EXIT" 'trap cleanup EXIT'
has "cleanup trap on INT" "trap 'cleanup; exit 130' INT"
has "cleanup trap on TERM" "trap 'cleanup; exit 143' TERM"
has "cleanup removes only this run's directory" 'rm -rf -- "\$ITEST_DIR"'
lacks "no global itest glob removal" 'rm -rf /tmp/itest-'
has "shim stays agent-readable (0755)" 'chmod 0755 "\$SHIM/docker-helper"'
has "runner stays agent-readable (0755)" 'chmod 0755 "\$RUNNER"'
lacks "no shell tracing" 'set -x'
has "moved default credential is restored" 'mv -f "\$CRED_MOVED" "\$CRED"'

# --- C7/F3. the integration suite tracks the current launcher contract -------
# 3.1: `oc` is a Bash function; GNU timeout cannot exec it. Every time-bounded
# launch must run inside a fresh initialized Bash (aliases + docker recorder).
oc_calls="$(grep -cE 'timeout [0-9]+ +oc ' "$INTEG" || true)"
check "no direct 'timeout oc' invocation (oc is a function)" "0" "$oc_calls"
has "time-bounded oc launches run in an initialized Bash"   'timeout 60 bash -c'
has "the version probe is also time-bounded (oc_t)"          'oc_t --version'
lacks "no un-timed direct oc invocation in the runner"       '^oc '
has "the wrapper sources the launcher aliases"              'source "\$HOME/.bash_aliases"'
has "the initialized Bash keeps the docker recorder" \
  'docker\(\) \{ printf "%s.n" "\$\*" >> "\$ARGV_REC"; command docker "\$@"; \}'
# 3.2: the ssh-agent mount assertion follows the per-launch run directory.
has "ssh-agent mount assertion checks the run.<suffix> structure" \
  'agent-ssh/run\\\.\[A-Za-z0-9]\{6\}:/ssh-agent:ro'
has "exactly one ssh-agent run dir may be mounted" \
  'exactly one ssh-agent run dir is mounted'
# F6: the NODE_EXTRA_CA_CERTS assertion carries the .crt naming contract.
has "NODE_EXTRA_CA_CERTS assertion uses the .crt contract" \
  '"/etc/opencode-ca/\$ca_name.crt"'
lacks "no suffix-less NODE_EXTRA_CA_CERTS assertion" '"/etc/opencode-ca/\$ca_name" \'

# --- UAT-8. the TLS probe: framed output, bash-invoked verdict, no masking ---
# The real-VM findings: tls-verdict.sh was invoked directly although it is
# installed at /opt/lab with mode 0644 (the refusal then surfaced as an
# empty verdict and became a SKIP); the launcher's `Agent pid` line landed
# on stdout and was read as NODE_EXTRA_CA_CERTS from the first line; and
# `|| true` masked a failed launcher as an inconclusive probe.
has "tls-verdict.sh is invoked through bash (0644-safe)" \
  'bash "\$SCRIPT_DIR/tls-verdict\.sh"'
has "the verdict helper's own failure is a FAIL, not a skip" \
  'the TLS verdict helper failed'
has "the TLS probe output is framed (TLS_BEGIN)" "printf '%s.n' TLS_BEGIN"
has "NODE_EXTRA_CA_CERTS is framed behind its own markers" "CA_ENV_BEGIN"
has "NODE_EXTRA_CA_CERTS is parsed from its markers, not the first line" \
  'sed -n ./\^CA_ENV_BEGIN\$/,'
lacks "no first-line split of the launcher output" 'head -1)" > "\$CA_ENV_OUT"'
lacks "no masked TLS launcher exit status" '2>&1 || true)"'
has "the TLS launcher exit status is recorded separately" 'tls-launch.rc'
has "a TLS connection failure is a FAIL (mandatory negative evidence)" \
  'bad "the TLS probe ended in a connection failure'
has "an unexpected TLS outcome is a FAIL, not a skip" \
  'bad "the TLS probe ended in an unexpected outcome'
has "an unframed TLS output is a FAIL" 'no TLS_BEGIN/TLS_END'
has "the negative TLS check runs through the exec path" "oc-probe \"\\\$TLS_PROBE_CMD\""

# --- UAT-8. the Session bearer probes: the exec path, explicit outcomes ------
# The image ENTRYPOINT is `opencode`: `oc docker-helper self --json` and
# `oc sh -c ...` handed their words to the OpenCode CLI and never ran
# docker-helper or sh. The empty `self_channel` string also passed the old
# `!= "none"` check.
has "the access path runs through oc-probe (exec)" "oc-probe \"\\\$OC_PROBE_PAYLOAD\""
lacks "no bare-argv self channel remains" 'oc_t docker-helper self'
lacks "no sh -c self channel remains" "oc_t sh -c 'docker-helper"
lacks "no empty-accepting channel check" 'self_channel'
has "the probe result is framed (PROBE_BEGIN)" "printf 'PROBE_BEGIN.n'"
has "the in-container rc is recorded per probe" 'PROBE_RC=%s'
lacks "no masked probe record" '"\$out" > "\$OC_SELF_OUT"'
has "a valid Session bearer is confirmed from one probe run" 'docker-helper self executed inside the container'
has "the missing-bearer refusal is attributed to Docker Helper" \
  'DOCKER_HELPER_SESSION_TOKEN is not set'
has "a wrong bearer is refused" 'self with a wrong bearer is denied'
has "the principal credential cannot substitute the Session bearer" \
  'the principal credential cannot substitute the Session bearer'
has "docker.sock absence is asserted inside the container" 'PROBE_SOCK=absent'
has "ADMIN* env absence is asserted inside the container" 'PROBE_ADMIN_ENV=0'
has "the probe launches are recorded for posture assertions" 'ARGV_PROBE='
has "the probe posture is asserted from the probe record" \
  'the probe container runs as the agent uid'

# --- UAT-8. the launch-failure diagnostics -----------------------------------
# A failed (e.g. timeout 124) launch must produce factor-separated bounded
# diagnostic evidence — not just a longer timeout or a bare failure.
has "a failed launch runs the bounded diagnostic ladder" \
  'the model launch failed with rc'
has "the ladder separates the container-exec factor" 'DIAG_L1_RC='
has "the ladder separates the mounted-HOME factor" 'DIAG_L2_RC='
has "the ladder separates the HOME=/tmp factor (the operator experiment)" 'DIAG_L3_RC='
has "missing diagnostic evidence is a FAIL" \
  'the launch failed but the diagnostics produced no factor evidence'
has "every ladder step is time-bounded" 'probe_run diag_l1'

# --- UAT-8. the explicit integration mode ------------------------------------
has "the integration mode is explicit" 'INTEGRATION_NETWORKED'
has "the networked mode claims no isolation" \
  'this run makes no VM isolation claims'
has "an invalid mode value fails closed" 'INTEGRATION_NETWORKED must be 0 or 1'
has "the LLM check is provider-gated inside the container" 'PROVIDER_CONFIGURED'
has "a missing provider is a skip, never a pass" \
  'no provider configured in the launch env'
has "a configured provider that does not answer is a FAIL" \
  'the configured provider did not answer'
has "the isolated mode records the explicit no-provider decision" 'ISOLATED_MODE'


# --- UAT-8 follow-up. PTY framing and authoritative authentication rc -------
# The actual integration runs inside script(1) and docker -it. PTY output
# carries CRLF, so line-anchored markers and numerical rc need normalization.
pty_normalizations="$(grep -Fc 'raw="${raw//' "$INTEG" || true)"
if [ "$pty_normalizations" = 2 ]; then
  ok "both probe and TLS PTY outputs normalize CRLF"
else
  bad "PTY CRLF normalization must occur in both paths (found $pty_normalizations)"
fi
if command -v script >/dev/null 2>&1; then
  pty_fixture="$(script -qec "printf 'PROBE_BEGIN\nPROBE_RC=0\nPROBE_END\n'" /dev/null </dev/null)"
else
  pty_fixture="$(printf 'PROBE_BEGIN\r\nPROBE_RC=0\r\nPROBE_END\r\n')"
fi
pty_fixture="${pty_fixture//$'\r'/}"
pty_rc="$(printf '%s\n' "$pty_fixture" | sed -n 's/^PROBE_RC=//p')"
if [ "$pty_rc" = 0 ] \
   && printf '%s\n' "$pty_fixture" | grep -q '^PROBE_BEGIN$' \
   && printf '%s\n' "$pty_fixture" | grep -q '^PROBE_END$'; then
  ok "CRLF-framed probe markers and rc parse after normalization"
else
  bad "CRLF-framed probe markers or rc cannot be parsed"
fi
has "self checks only docker-helper self, without trailing success printf" \
  "^probe_run self 'docker-helper self --json'$"
has "boundary diagnostics do not mask the self exit" \
  '^probe_run boundary '
has "principal credential refusal retains the docker-helper exit code" \
  '^probe_run princred .*[(]exit "\$rc"[)]'
lacks "the self result cannot be masked by trailing boundary printfs" \
  "probe_run self 'docker-helper self --json; printf"
lacks "mandatory negative TLS evidence cannot be skipped for missing curl" \
  'skip "in-container TLS check (curl is not available inside the image)"'

# --- UAT-8b: the real VM exposed a Docker argv and verdict false-positive -----
has "the model launch status is recorded independently of probe results" \
  'VERSION_RC=%s'
has "runner propagates the version launch rc after all probes" \
  'exit "\$version_rc"'
has "probe posture checks stop before the shell payload" \
  'pargv_opts='
has "probe mount absence checks examine options, not probe source code" \
  '^not_contains "the probe container has no docker.sock".*"\$pargv_opts"'
has "probe admin-token absence checks examine options" \
  '^not_contains "the probe container has no admin token".*"\$pargv_opts"'
has "probe principal credential absence checks examine options" \
  '^not_contains "the probe container has no principal credential".*"\$pargv_opts"'

# --- UAT-8c. the bounded execution owner -------------------------------------
# Every probe's timeout, stderr capture, elapsed time and outcome
# classification come from lab-diag-lib.sh (one implementation); the
# launcher's stderr is diagnostic evidence and is never suppressed.
has "the runner loads the bounded-execution owner" 'source /opt/lab/lab-diag-lib\.sh'
has "probe_run executes through diag_exec" 'diag_exec "\$name" "\$bound"'
has "the probe's exit status is read back from diag_exec evidence" \
  'cat "\$PROBE_DIR/\$name.rc"'
has "the TLS probe executes through diag_exec" 'diag_exec tls-probe 90'
has "the TLS evidence directory is private" 'install -d -m 0750 -o "\$AGENT_USER"'

# --- UAT-8d. provable ownership and fail-closed diagnostics ------------------
# Ownership evidence, never global diffs: the diagnostic containers carry a
# unique run identity plus labels, the forced removal verifies them first,
# the Sessions are registered by the daemon's own workspace attribution, and
# a failed session list refuses the cleanup instead of proceeding empty.
LAB_LIB="$SRC_DIR/lab"
fhas() { # desc pattern file (extended regex against one file)
  if grep -Eq -- "$2" "$3"; then ok "$1"; else bad "$1 (pattern absent: $2)"; fi
}
flacks() { # desc pattern file (fixed string forbidden in one file)
  if grep -qF -- "$2" "$3"; then bad "$1 (forbidden pattern present: $2)"; else ok "$1"; fi
}

fhas "the diagnostic containers carry a run-identity label" \
  'lab\.diagnostic\.runid=\$DIAG_RUNID' "$LAB_LIB/lab-diag-lib.sh"
fhas "the owned-removal verification reads the runid label" \
  'index \.Config\.Labels "lab\.diagnostic\.runid"' "$LAB_LIB/lab-diag-lib.sh"
fhas "the forced removal happens only after verification" \
  'diag_bounded "rm" docker rm -f' "$LAB_LIB/lab-diag-lib.sh"
flacks "no image-ancestor diff cleanup remains" 'ancestor=' "$LAB_LIB/lab-diag-lib.sh"
fhas "sessions are registered through the daemon's own list" \
  'docker-helper session list --json' "$LAB_LIB/lab-diag-lib.sh"
fhas "the registration filters by the run's own workspace" \
  'select\(\.workspace == \$ws\)' "$LAB_LIB/lab-diag-lib.sh"
fhas "a failed session list refuses the cleanup" 'refused-list-error' \
  "$LAB_LIB/lab-diag-lib.sh"
flacks "the session registration never hides list errors" \
  'session list --json 2>/dev/null) || true' "$LAB_LIB/lab-diag-lib.sh"
fhas "the canonical argv carries the LLM provider flags" \
  'out\+=\(-e LLM_SERVER -e LLM_KEY\)' "$LAB_LIB/agent-aliases.sh"
fhas "the evidence print path is sanitized" \
  'diag_sanitize "\$line"' "$LAB_LIB/lab-diag-lib.sh"
fhas "observability failures are recorded explicitly" \
  'UNAVAILABLE \(the docker inspect/ps evidence could not be collected\)' \
  "$LAB_LIB/lab-diag-lib.sh"

# --- UAT-8e. image-ID ownership, provenance, bounded recovery, deadlines -----
# Ownership compares the LOCAL image ID resolved from the pinned reference
# (never the reference itself), is anchored on the immutable container ID,
# and the canonical steps request the provenance explicitly through the
# launcher's diagnostic knobs.
fhas "the pinned reference is resolved to the local image ID" \
  'diag_expected_image_id' "$LAB_LIB/lab-diag-lib.sh"
fhas "the removal decision is anchored on the immutable container ID" \
  'diag_reap_verified_container "\$cid"' "$LAB_LIB/lab-diag-lib.sh"
fhas "the proven absence of an --rm-removed container is a normal outcome" \
  'printf .clean.' "$LAB_LIB/lab-diag-lib.sh"
fhas "the launcher applies diagnostic provenance only when all knobs are set" \
  'OPENCODE_DIAGNOSTIC_RUNID' "$LAB_LIB/agent-aliases.sh"
fhas "a partial diagnostic configuration refuses the launch" \
  'incomplete diagnostic provenance configuration' "$LAB_LIB/agent-aliases.sh"
fhas "every bounded recovery goes through the shared bounded owner" \
  'diag_bounded "rm" docker rm -f' "$LAB_LIB/lab-diag-lib.sh"
fhas "the session list runs through the bounded owner" \
  'diag_bounded "session-list" docker-helper session list' "$LAB_LIB/lab-diag-lib.sh"
fhas "the canonical cleanup verdict is part of the step result" \
  'diag_cleanup_ok' "$LAB_LIB/lab-diag-lib.sh"
fhas "a mandatory-cleanup failure fails the diagnostic explicitly" \
  'DIAGNOSTIC FAIL reason=cleanup-' "$LAB_LIB/lab-diag-lib.sh"
fhas "the diagnostic stage carries an external deadline with a finite kill budget" \
  'timeout --kill-after="\$DIAG_DEADLINE_KILL" "\$DIAG_DEADLINE"' "$LAB_LIB/provision-lab-vm.sh"
fhas "the deadline path attempts no fallback cleanup" \
  'no fallback cleanup was attempted' "$LAB_LIB/provision-lab-vm.sh"
fhas "the root driver sources the single sanitization owner" \
  'source /opt/lab/lab-diag-lib.sh' "$LAB_LIB/diagnose-launch.sh"
fhas "the sanitizer redacts registered secret values" \
  'diag_register_secret_value' "$LAB_LIB/lab-diag-lib.sh"
fhas "the sanitizer refuses to degrade into a passthrough" \
  'SANITIZE-FAILURE' "$LAB_LIB/lab-diag-lib.sh"
fhas "the evidence summary is the single allowlisted print path" \
  'diag_print_evidence_summary "\$EVID"' "$LAB_LIB/diagnose-launch.sh"

echo
printf 'integration hygiene tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
