#!/usr/bin/env bash
#
# Required live workload proof runner for Release 2.2.
#
# Runs the compiled production live proof binary in required mode
# (DOCKER_HELPER_LIVE_WORKLOAD_PROOF=1) and enforces the required-mode
# contract on top of the go test exit code:
#
#   - any --- SKIP among the matched tests fails the run (a required proof
#     must never pass through a skip);
#   - the expected evidence artifacts must exist and be non-empty;
#   - the test binary must exit zero.
#
# Usage:
#   release-2.2-live-proof-runner.sh \
#     --binary PATH -run FILTER --evidence DIR FILE [FILE ...]
#   release-2.2-live-proof-runner.sh --check LOGFILE --evidence DIR FILE ...
#
# The --check form validates a captured -test.v output against the evidence
# contract; it exists so the runner checks are deterministically testable.

set -Eeuo pipefail

PREFIX='[release-2.2-live-proof-runner]'

say() {
  printf '%s %s\n' "$PREFIX" "$*"
}

fail() {
  printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2
  exit 1
}

usage() {
  fail "usage: $0 --binary PATH -run FILTER --evidence DIR FILE... | --check LOGFILE --evidence DIR FILE..."
}

BINARY=''
FILTER=''
LOGFILE=''
EVIDENCE_DIR=''
FILES=()

while [ $# -gt 0 ]; do
  case "$1" in
    --binary)
      [ $# -ge 2 ] || usage
      BINARY="$2"
      shift 2
      ;;
    -run)
      [ $# -ge 2 ] || usage
      FILTER="$2"
      shift 2
      ;;
    --check)
      [ $# -ge 2 ] || usage
      LOGFILE="$2"
      shift 2
      ;;
    --evidence)
      [ $# -ge 2 ] || usage
      EVIDENCE_DIR="$2"
      shift 2
      while [ $# -gt 0 ]; do
        case "$1" in
          --*) break ;;
          *) FILES+=("$1"); shift ;;
        esac
      done
      ;;
    *)
      usage
      ;;
  esac
done

[ -n "$EVIDENCE_DIR" ] || usage
[ "${#FILES[@]}" -ge 1 ] || usage

check_output() {
  local logfile="$1"
  if grep -q -- '--- SKIP' "$logfile"; then
    grep -- '--- SKIP' "$logfile" >&2 || true
    fail 'required live proof tests must not skip in required mode'
  fi
  if ! grep -q -- '--- PASS' "$logfile"; then
    fail 'no required live proof test ran or passed'
  fi
  local file
  for file in "${FILES[@]}"; do
    if [ ! -s "$EVIDENCE_DIR/$file" ]; then
      fail "required live proof evidence artifact is missing or empty: $file"
    fi
  done
}

if [ -n "$LOGFILE" ]; then
  [ -f "$LOGFILE" ] || fail "captured test output not found: $LOGFILE"
  check_output "$LOGFILE"
  say 'captured required live proof output closed'
  exit 0
fi

[ -n "$BINARY" ] && [ -n "$FILTER" ] || usage
[ -x "$BINARY" ] || fail "proof binary is not executable: $BINARY"
mkdir -p "$EVIDENCE_DIR"

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

if ! env \
  DOCKER_HELPER_LIVE_WORKLOAD_PROOF=1 \
  WORKLOAD_EVIDENCE_DIR="$EVIDENCE_DIR" \
  "$BINARY" -test.run "$FILTER" -test.v | tee "$LOG"; then
  fail "required live proof binary exited non-zero: $BINARY"
fi
check_output "$LOG"
say "required live proof closed: $FILTER"
