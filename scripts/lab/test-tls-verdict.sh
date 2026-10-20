#!/usr/bin/env bash
#
# test-tls-verdict.sh — CI tests for scripts/lab/tls-verdict.sh: the REAL
# verdict implementation used by the VM integration suite's negative TLS
# check, executed against recorded fixtures (not pattern matching in tests).
#
# Usage: scripts/lab/test-tls-verdict.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERDICT="$SRC_DIR/lab/tls-verdict.sh"
[ -f "$VERDICT" ] || { echo "missing tls-verdict.sh" >&2; exit 1; }

PASS=0
FAIL=0
check() { # NAME WANT GOT
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"
  else FAIL=$((FAIL+1)); printf 'FAIL - %s (want %s got %s)\n' "$1" "$2" "$3"; fi
}

# fixture: rc, output, expected verdict line, expected corroboration line
fixture() { # NAME RC OUTPUT WANT_VERDICT WANT_CORROB
  local out
  out="$("$VERDICT" "$2" "$3")"
  check "F6/$1 verdict" "$4" "$(printf '%s' "$out" | head -1)"
  check "F6/$1 corroboration" "$5" "$(printf '%s' "$out" | tail -1)"
}

# --- verification failures (the negative-test success class) ------------------
fixture "self-signed-cert" 60 "curl: (60) SSL certificate problem: self-signed certificate" \
  VERIFICATION_FAILURE CORROBORATED
fixture "unknown-ca" 60 "curl: (60) SSL certificate problem: unable to get local issuer certificate" \
  VERIFICATION_FAILURE CORROBORATED

# --- accepted (the negative-test failure class) -------------------------------
fixture "accepted-quietly" 0 "" ACCEPTED UNCORROBORATED
fixture "accepted-with-body" 0 "<html>ok</html>" ACCEPTED UNCORROBORATED

# --- connection failures are inconclusive, never a pass -----------------------
fixture "conn-refused" 7 "curl: (7) Failed to connect to 172.17.0.1" CONNECTION_FAILURE UNCORROBORATED
fixture "timeout" 28 "curl: (28) Operation timed out" CONNECTION_FAILURE UNCORROBORATED
fixture "ssl-connect" 35 "curl: (35) SSL connect error" CONNECTION_FAILURE UNCORROBORATED
fixture "recv-error" 56 "curl: (56) Recv failure" CONNECTION_FAILURE UNCORROBORATED

# --- anything else is inconclusive --------------------------------------------
fixture "weird-code" 1 "curl: (1) unsupported protocol" OTHER_ERROR UNCORROBORATED
fixture "no-output" 2 "" OTHER_ERROR UNCORROBORATED

# a verification failure WITHOUT the corroborating text stays a verification
# failure but is flagged uncorroborated (the integration layer decides)
fixture "bare-60" 60 "" VERIFICATION_FAILURE UNCORROBORATED

echo
printf 'tls-verdict tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
