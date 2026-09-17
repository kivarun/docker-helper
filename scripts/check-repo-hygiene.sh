#!/usr/bin/env bash
#
# check-repo-hygiene.sh — the ONE canonical repository hygiene gate for the
# tracked tree. Unlike a change-vs-HEAD `git diff --check`, it runs on the
# whole tracked tree of a clean checkout and actually catches:
#
#   1. accidental trailing whitespace on any tracked text file;
#   2. a tracked text file that does not end with a final newline
#      (repository rule: text files must end with a newline).
#
# Explicit, narrow byte exception (never widen it):
#
#   testdata/semanage-fcontext-producer-capture.txt
#
#     The byte-exact capture of a real `semanage fcontext -l -C -n` producer
#     run (release-2.2-security-closure.md, M12 evidence). Its column
#     padding, including the captured trailing spaces, is part of the
#     captured producer bytes; "cleaning" them would silently invalidate the
#     byte-verified fixture.
#
# Exit 0 = gate passed; exit 1 = gate failed.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

EXCEPTION="testdata/semanage-fcontext-producer-capture.txt"
EXCLUSION_PATHSPEC=":!$EXCEPTION"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  fail "must run inside the docker-helper git work tree"
fi

# --- check 1: no accidental trailing whitespace on tracked text files --------
# git grep searches exactly the tracked paths and skips binary content; the
# pathspec exclusion is the only intentional byte exception above. Both
# hygiene classes are reported in one run before the gate fails.
FAILED=0
TRAILING="$(git grep -nE '[[:blank:]]$' -- . "$EXCLUSION_PATHSPEC" 2>/dev/null || true)"
if [ -n "$TRAILING" ]; then
  printf 'error: tracked text files carry trailing whitespace:\n%s\n' "$TRAILING" >&2
  FAILED=1
else
  echo "ok: no trailing whitespace on tracked text files"
fi

# --- check 2: every tracked text file ends with a final newline --------------
# One git grep -I pass enumerates exactly the tracked text files (binary
# content is skipped; a zero-byte tracked file carries nothing to terminate
# and is skipped naturally). The same single exception applies.
FINAL_LF_MISSING=""
while IFS= read -r -d '' f; do
  [ -z "$f" ] && continue
  [ "$f" = "$EXCEPTION" ] && continue
  # tail -c1 of a file ending in LF prints exactly the newline, which the
  # command substitution strips: empty output means the final LF is present.
  if [ -n "$(tail -c 1 -- "$f" 2>/dev/null)" ]; then
    FINAL_LF_MISSING="$FINAL_LF_MISSING$f
"
  fi
done < <(git grep -zIl -e '' -- . "$EXCLUSION_PATHSPEC")

if [ -n "$FINAL_LF_MISSING" ]; then
  printf 'error: tracked text files must end with a final newline:\n%s' "$FINAL_LF_MISSING" >&2
  FAILED=1
else
  echo "ok: every tracked text file ends with a final newline"
fi

if [ "$FAILED" -eq 0 ]; then
  echo "repository hygiene gate passed"
fi
exit "$FAILED"
