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

echo
printf 'integration hygiene tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
