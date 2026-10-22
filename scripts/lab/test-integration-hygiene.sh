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

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INTEG="$SRC_DIR/lab/integration-agent-vm.sh"
[ -f "$INTEG" ] || { echo "missing $INTEG" >&2; exit 1; }

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }

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
  pty_fixture="$(script -qec "printf 'PROBE_BEGIN\\nPROBE_RC=0\\nPROBE_END\\n'" /dev/null </dev/null)"
else
  pty_fixture="$(printf 'PROBE_BEGIN\r\nPROBE_RC=0\r\nPROBE_END\r\n')"
fi
pty_fixture="${pty_fixture//[ "$FAIL" = 0 ]
\r'/}"
pty_rc="$(printf '%s\n' "$pty_fixture" | sed -n 's/^PROBE_RC=//p')"
if [ "$pty_rc" = 0 ] \
   && printf '%s\n' "$pty_fixture" | grep -q '^PROBE_BEGIN[ "$FAIL" = 0 ]
 \
   && printf '%s\n' "$pty_fixture" | grep -q '^PROBE_END[ "$FAIL" = 0 ]
; then
  ok "CRLF-framed probe markers and rc parse after normalization"
else
  bad "CRLF-framed probe markers or rc cannot be parsed"
fi
has "self checks only docker-helper self, without trailing success printf" \
  "^probe_run self 'docker-helper self --json'$"
has "boundary diagnostics do not mask the self exit" \
  "^probe_run boundary "
has "principal credential refusal retains the docker-helper exit code" \
  '^probe_run princred .*[(]exit "\$rc"[)]'
lacks "the self result cannot be masked by trailing boundary printfs" \
  "probe_run self 'docker-helper self --json; printf"
lacks "mandatory negative TLS evidence cannot be skipped for missing curl" \
  'skip "in-container TLS check (curl is not available inside the image)"'

echo
printf 'integration hygiene tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
