#!/usr/bin/env bash
#
# check-nonlinux-compile.sh — compile-only gate for the non-Linux staging
# ownership contract (CI-only extra; the product itself is Linux-only).
#
# The staging surface is shared by untagged daemon code: build.go and app.go
# (untagged) consume the typed staging ceiling refusal and the staged-context
# type, while the Linux ceilings/budget/walker mechanics live in
# staging_linux.go under //go:build linux and the non-Linux runtime contract
# stays "staging unsupported" (staging_stub.go). An untagged file must never
# reference a staging symbol that only exists under //go:build linux — that
# is exactly the defect class this gate proves closed.
#
# The gate runs two fail-closed checks:
#
#   1. The untagged staging surface is self-contained: staging.go plus the
#      non-Linux stub compile together as a standalone package for a
#      non-Linux GOOS (GOOS=darwin compile-only).
#
#   2. A whole-package GOOS=darwin compile-only build reports EXACTLY the
#      documented pre-existing non-Linux debt (workload_selinux.go and
#      selinux_fcontext.go use Linux-only syscall surfaces; see the debt
#      note below). Any additional compile error — in particular any error
#      in a staging file or in an untagged consumer of the staging surface
#      (build.go, app.go, operation.go, staging.go) — fails the gate.
#      When the pre-existing debt is paid, this check must be updated to
#      assert a fully clean non-Linux build.
#
# Exit 0 = gate passed; exit 1 = gate failed.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- check 1: the untagged staging surface compiles for a non-Linux GOOS ------
TMPDIR_CHECK="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_CHECK"' EXIT
cp staging.go staging_stub.go "$TMPDIR_CHECK/" || fail "cannot stage the untagged staging surface"
(cd "$TMPDIR_CHECK" \
  && printf 'module stagingcompilecheck\n\ngo 1.23\n' > go.mod \
  && GOOS=darwin go vet ./...) \
  || fail "the untagged staging surface (staging.go + staging_stub.go) does not type-check for GOOS=darwin"
echo "ok: untagged staging surface compiles for GOOS=darwin (staging.go + staging_stub.go)"

# --- check 2: whole-package non-Linux compile debt is bounded and documented --
# The debt files use Linux-only syscall surfaces (unix.MS_BIND / unix.MNT_DETACH
# in workload_selinux.go; unix.PROC_SUPER_MAGIC in selinux_fcontext.go). They
# are pre-existing, unrelated to the staging surface, and owned by the MAC
# layer; an untagged fix would restructure the shipped SELinux backend.
DEBT_FILES="workload_selinux.go selinux_fcontext.go"

OUT="$(GOOS=darwin go build -o /dev/null . 2>&1 || true)"

# Fail on any undefined symbol outside the documented debt.
UNDEFINED="$(printf '%s\n' "$OUT" | grep -oE 'undefined: [A-Za-z_.]+' | sed 's/^undefined: //' | sort -u)"
if [ -n "$UNDEFINED" ]; then
  for sym in $UNDEFINED; do
    case "$sym" in
      unix.PROC_SUPER_MAGIC|unix.MS_BIND|unix.MNT_DETACH) : ;; # documented debt
      *) fail "new non-Linux (GOOS=darwin) undefined symbol '$sym' — the non-Linux compile ownership contract is broken" ;;
    esac
  done
fi

# Fail on any error line that does not belong to the documented debt files.
BAD_LINE="$(printf '%s\n' "$OUT" | grep -E '^\./[A-Za-z0-9_]+\.go:[0-9]+' | grep -vE '^\./('"$(printf '%s' "$DEBT_FILES" | tr ' ' '|')"'):[0-9]+' || true)"
if [ -n "$BAD_LINE" ]; then
  fail "new non-Linux (GOOS=darwin) compile error outside the documented debt files ($DEBT_FILES):
$BAD_LINE"
fi

echo "ok: GOOS=darwin compile limited to the documented non-Linux debt ($DEBT_FILES)"
