#!/usr/bin/env bash
#
# release-2.4-p5s2-verdict-gate.sh — the ONE owner of the P5-S2 guest-proof
# verdict predicate (external review F4).
#
# The guest proof reports its terminal outcome as exactly one
# `P5S2-P4B-RESULT=<verdict>` line (the guest script's finish() is the
# single emitter). This gate decides what the host workflow accepts:
#
#   Release gate mode (PHASE4B_RELEASE_GATE=1, default):
#     the workflow succeeds only when the guest exited 0, the log carries
#     EXACTLY ONE terminal verdict, and that verdict is PASS. A missing
#     verdict, a FAIL, an INCOMPLETE, or two conflicting verdict lines
#     fails the gate. The exact candidate composition manifest must be
#     present and must record the candidate SHA and the binary hash
#     (external review F3: the tested artifacts are the candidate's).
#
#   Historical experiment mode (PHASE4B_RELEASE_GATE=0):
#     the pinned-proof investigation keeps its measured-outcome contract:
#     every terminal outcome (PASS/FAIL/INCOMPLETE) is a valid measured
#     result; the host requires guest exit 0 and at least one terminal
#     verdict line, and the report assigns the verdict.
#
# Usage: release-2.4-p5s2-verdict-gate.sh <guest-log> <guest-rc> <manifest>
set -u

MODE="${PHASE4B_RELEASE_GATE:-1}"
LOG="${1:-}"
RC="${2:-}"
MANIFEST="${3:-}"

if [ -z "$LOG" ] || [ ! -f "$LOG" ]; then
  printf 'verdict-gate: guest log %q is missing\n' "$LOG" >&2
  exit 1
fi

# The terminal verdicts are the exact RESULT= lines of the guest log.
# grep -c always prints a count (0 included), so the count itself is the
# truth source; the guard keeps an absent pattern from tripping -e shells.
VERDICT_COUNT="$(grep -c 'P5S2-P4B-RESULT=' "$LOG" || true)"
VERDICTS="$(grep 'P5S2-P4B-RESULT=' "$LOG" || true)"

if [ "$RC" != "0" ]; then
  printf 'verdict-gate: guest exit %s is not 0\n' "$RC" >&2
  exit 1
fi

if [ "$MODE" = "1" ]; then
  if [ "$VERDICT_COUNT" != "1" ]; then
    printf 'verdict-gate: expected exactly one terminal verdict, found %s\n' "$VERDICT_COUNT" >&2
    printf '%s\n' "$VERDICTS" >&2
    exit 1
  fi
  VERDICT="${VERDICTS#*P5S2-P4B-RESULT=}"
  if [ "$VERDICT" != "PASS" ]; then
    printf 'verdict-gate: the terminal verdict is %s, want PASS\n' "$VERDICT" >&2
    exit 1
  fi
  if [ -z "$MANIFEST" ] || [ ! -s "$MANIFEST" ]; then
    printf 'verdict-gate: the candidate composition manifest %q is missing or empty\n' "$MANIFEST" >&2
    exit 1
  fi
  if ! grep -q '^candidate_sha=[0-9a-f]\{40\}$' "$MANIFEST"; then
    printf 'verdict-gate: the manifest does not record a full candidate SHA\n' >&2
    exit 1
  fi
  if ! grep -q '^binary_sha256=[0-9a-f]\{64\}$' "$MANIFEST"; then
    printf 'verdict-gate: the manifest does not record the candidate binary hash\n' >&2
    exit 1
  fi
  exit 0
fi

# Historical experiment mode: a terminal measured outcome is required;
# its value belongs to the report, not to the job verdict.
if [ "$VERDICT_COUNT" -lt 1 ]; then
  printf 'verdict-gate: the guest log carries no terminal measured outcome\n' >&2
  exit 1
fi
exit 0
