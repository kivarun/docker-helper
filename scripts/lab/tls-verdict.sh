#!/usr/bin/env bash
#
# tls-verdict.sh — classify one TLS probe outcome. This is the single owner
# of the verdict logic used by the VM integration suite's negative TLS test;
# the CI suite executes THIS implementation against recorded fixtures instead
# of re-implementing pattern matching.
#
# usage: tls-verdict.sh RC OUTPUT_TEXT
# prints exactly one of:
#   ACCEPTED             the TLS handshake completed (the endpoint is trusted)
#   VERIFICATION_FAILURE the handshake was rejected by certificate validation
#   CONNECTION_FAILURE   the endpoint was not reachable (inconclusive)
#   OTHER_ERROR          any other outcome (inconclusive)
set -u

rc="$1"
out="${2:-}"

case "$rc" in
  0) printf 'ACCEPTED' ;;
  # curl(1): 60 = peer certificate cannot be authenticated with the known CA
  # certificates (validation rejected the endpoint).
  60)
    printf 'VERIFICATION_FAILURE' ;;
  # curl(1): 7 = could not connect, 28 = timeout, 35 = SSL connect error,
  # 56 = receive error — transport-level, NOT a certificate verdict.
  7|28|35|56)
    printf 'CONNECTION_FAILURE' ;;
  *) printf 'OTHER_ERROR' ;;
esac

# corroboration hint: a verification failure should mention certificates in
# the observed output; exported as a separate line for evidence checks.
if [ "$rc" = 60 ] && printf '%s' "$out" | grep -qi 'certificate'; then
  printf '\nCORROBORATED'
else
  printf '\nUNCORROBORATED'
fi
