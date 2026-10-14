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
#     (external review F3: the tested artifacts are the candidate's), and
#     it must bind the tested binary hash to the canonical candidate
#     artifact hash (re-review R3: the PASS belongs to the exact bytes
#     intended for release — the release version, the candidate
#     tarball/DEB/RPM hashes, and tested binary == candidate binary).
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
  # Re-review R3: the PASS must belong to the exact bytes intended for
  # release. The manifest must bind the release version, the candidate
  # set's own artifact hashes (tarball/DEB/RPM), and the candidate binary
  # hash, and the tested binary hash must EQUAL the candidate binary hash.
  for key in release_version candidate_tarball_sha256 candidate_deb_sha256 candidate_rpm_sha256; do
    if ! grep -q "^${key}=." "$MANIFEST"; then
      printf 'verdict-gate: the manifest does not record %s (the tested bytes are not bound to the candidate set)\n' "$key" >&2
      exit 1
    fi
  done
  TESTED_BIN="$(sed -n 's/^binary_sha256=//p' "$MANIFEST")"
  CANDIDATE_BIN="$(sed -n 's/^candidate_binary_sha256=//p' "$MANIFEST")"
  if [ -z "$CANDIDATE_BIN" ]; then
    printf 'verdict-gate: the manifest does not record candidate_binary_sha256\n' >&2
    exit 1
  fi
  if [ "$TESTED_BIN" != "$CANDIDATE_BIN" ]; then
    printf 'verdict-gate: the tested binary %s is not the candidate artifact binary %s\n' "$TESTED_BIN" "$CANDIDATE_BIN" >&2
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
