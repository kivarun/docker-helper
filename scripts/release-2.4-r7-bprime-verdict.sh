#!/usr/bin/env bash
#
# release-2.4-r7-bprime-verdict.sh — the R7 B′ gate evaluator.
#
# Pure file-based evaluation of a B′ evidence directory (no VM, no policy
# access): classifies every AVC that references the experimental type with
# a precise identity check (audit serial/timestamp/pid/comm, source and
# target contexts, dev/ino, decoded memfd path, and the memfd_create/strace
# FD identity), deduplicates audit records across overlapping windows, and
# decides the fail-closed ten-check gate.
#
# Usage:
#   release-2.4-r7-bprime-verdict.sh <evidence-dir>
#     Emits one machine-readable verdict line on stdout and writes the
#     per-record classification to <evidence-dir>/bprime-classification.log.
#     Exit codes: 0 = BPRIME-VIABLE, 1 = BPRIME-FAIL, 2 = BPRIME-BLOCKED.
#   release-2.4-r7-bprime-verdict.sh --gate <verdict-line>
#     Exit 0 iff the line's DECISION is BPRIME-VIABLE (the workflow gate).
#
# Classification (the object is what is classified, never the subject):
#   runc-write     — comm=buildkit-runc, write-denied, object is a
#                    /memfd:… inode: the proven runc memfd (expected).
#   strace-getattr — a /memfd:… object whose (dev,ino) is anchored by a
#                    runc-write record: diagnostic observation of the SAME
#                    memfd (expected; e.g. strace -y fd decoding).
#   unmatched      — a /memfd:…-shaped object with no runc-write anchor
#                    (unknown inode identity) — fails closed.
#   other          — any non-memfd object (a real pathname or unnamed
#                    object) carrying the type — other-object relabeling,
#                    fails closed.
# Expected runc-memfd records are NOT other-object relabeling.
#
# Verdict precedence: FAIL (a positive violation was proven) beats BLOCKED
# (required evidence missing or unreadable) beats VIABLE. A missing, empty,
# or unreadable required file can never produce VIABLE. The distro's own
# unrelated named transition on the same pair (ica_tmpfs_t, name
# "icastats_0") is tolerated and never matches the unnamed memfd path.

set -uo pipefail

MEMFD_HEX='2F6D656D66643A'   # hex encoding of "/memfd:"
NEWTYPE='docker_helper_runc_memfd_t'
BASETYPE='tmpfs_t'

if [ "${1:-}" = "--gate" ]; then
  case "${2:-}" in
    *DECISION=BPRIME-VIABLE*) exit 0 ;;
    *) exit 1 ;;
  esac
fi

EV="${1:?usage: release-2.4-r7-bprime-verdict.sh <evidence-dir>}"
if [ ! -d "$EV" ]; then
  printf 'R7-BPRIME-VERDICT=DECISION=BPRIME-BLOCKED;CHECKS=;CLASSIFICATION=;AUDIT-DEDUP=;LIVE-LABEL=none;MEMFD-CREATE-TRACE=missing;OTHER-RELABEL=evidence-dir-missing\n'
  exit 2
fi

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
have() { [ -s "$EV/$1" ]; }

hexdecode() { printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')" 2>/dev/null; }

# parse one AVC record into R_* fields (best-effort; empty when absent)
parse_record() {
  R_SERIAL="$(printf '%s' "$1" | sed -n 's/.*msg=audit([0-9.]*:\([0-9]*\)).*/\1/p')"
  R_TS="$(printf '%s' "$1" | sed -n 's/.*msg=audit(\([0-9.]*\):[0-9]*).*/\1/p')"
  R_PID="$(printf '%s' "$1" | sed -n 's/.*[ ,]pid=\([0-9]*\).*/\1/p')"
  R_COMM="$(printf '%s' "$1" | sed -n 's/.*comm="\([^"]*\)".*/\1/p')"
  R_PERMS="$(printf '%s' "$1" | sed -n 's/.*denied  { \([^}]*\) }.*/\1/p')"
  R_DEV="$(printf '%s' "$1" | sed -n 's/.*dev="\([^"]*\)".*/\1/p')"
  R_INO="$(printf '%s' "$1" | sed -n 's/.*ino=\([0-9]*\).*/\1/p')"
  R_SCTX="$(printf '%s' "$1" | sed -n 's/.*scontext=\([^ ]*\).*/\1/p')"
  R_TCTX="$(printf '%s' "$1" | sed -n 's/.*tcontext=\([^ ]*\).*/\1/p')"
  R_PATHHEX="$(printf '%s' "$1" | sed -n 's/.*[ ,]path=\([0-9A-F][0-9A-F]*\).*/\1/p')"
  R_PATHQ="$(printf '%s' "$1" | sed -n 's/.*[ ,]path="\([^"]*\)".*/\1/p')"
  R_NAME="$(printf '%s' "$1" | sed -n 's/.*[ ,]name="\([^"]*\)".*/\1/p')"
}

# deduplicate records by audit serial (overlapping ausearch/raw-log windows
# repeat records verbatim; the serial is unique per kernel audit message)
dedup_records() { # files... -> deduped `type=AVC` records on stdout
  cat "$@" 2>/dev/null | grep -a 'type=AVC' | awk '
    { if (match($0, /msg=audit\([0-9.]+:[0-9]+\)/)) {
        key = substr($0, RSTART, RLENGTH)
        if (!(key in seen)) { seen[key] = 1; print }
      } else { print } }'
}

# ---------------------------------------------------------------------------
# classification pass 1: collect the runc-write anchors (dev/ino pairs the
# runc itself wrote to) over the deduplicated loaded-window records
# ---------------------------------------------------------------------------
: > "$EV/bprime-classification.log"
RAW="$(dedup_records "$EV/bprime-avc-c1.log" "$EV/bprime-avc-c2.log" "$EV/bprime-avc-probe.log")"
NEWTYPE_RECORDS="$(printf '%s\n' "$RAW" | grep -a "$NEWTYPE" || true)"
TOTAL_RAW="$( { cat "$EV"/bprime-avc-c1.log "$EV"/bprime-avc-c2.log "$EV"/bprime-avc-probe.log 2>/dev/null; } | grep -ac 'type=AVC' || true)"
DEDUP_TOTAL="$(printf '%s\n' "$RAW" | grep -ac 'type=AVC' || true)"

ANCHORS=" "
while IFS= read -r rec; do
  [ -n "$rec" ] || continue
  parse_record "$rec"
  if printf '%s' "$R_COMM" | grep -q '^buildkit-runc$' \
     && printf '%s' "$R_PERMS" | grep -qw write \
     && [ -n "$R_PATHHEX" ] && [ "${R_PATHHEX#"$MEMFD_HEX"}" != "$R_PATHHEX" ]; then
    ANCHORS="$ANCHORS$R_DEV/$R_INO "
  fi
done <<EOF
$NEWTYPE_RECORDS
EOF

# ---------------------------------------------------------------------------
# classification pass 2: classify every new-type record
# ---------------------------------------------------------------------------
EXPECTED=0; N_OTHER=0; N_UNMATCHED=0
OTHER_SERIALS=""; UNMATCHED_SERIALS=""
LIVE_LABEL_PROVEN=0
MEMFD_INO_IDENTITIES=""

while IFS= read -r rec; do
  [ -n "$rec" ] || continue
  parse_record "$rec"
  decoded=""
  [ -n "$R_PATHHEX" ] && decoded="$(hexdecode "$R_PATHHEX")"

  if [ -n "$R_PATHHEX" ] && [ "${R_PATHHEX#"$MEMFD_HEX"}" != "$R_PATHHEX" ]; then
    # an object under the /memfd: anon-inode namespace
    if printf '%s' "$ANCHORS" | grep -q " $R_DEV/$R_INO "; then
      case "$R_COMM" in
        buildkit-runc) cls="runc-write" ;;
        *)             cls="strace-getattr" ;;
      esac
    else
      cls="unmatched"
      N_UNMATCHED=$((N_UNMATCHED + 1))
      UNMATCHED_SERIALS="$UNMATCHED_SERIALS$R_SERIAL($R_DEV/$R_INO) "
    fi
    MEMFD_INO_IDENTITIES="$MEMFD_INO_IDENTITIES $R_DEV/$R_INO"
    if [ "$cls" = "runc-write" ] && printf '%s' "$R_TCTX" | grep -q "$NEWTYPE"; then
      LIVE_LABEL_PROVEN=1
    fi
  elif [ -n "$R_PATHHEX" ] || [ -n "$R_PATHQ" ] || [ -n "$R_NAME" ]; then
    # a real (named/pathed) object carrying the experimental type
    cls="other"
    N_OTHER=$((N_OTHER + 1))
    OTHER_SERIALS="$OTHER_SERIALS$R_SERIAL(${R_PATHQ:-${R_NAME:-hex:$R_PATHHEX}}) "
  else
    cls="unmatched"
    N_UNMATCHED=$((N_UNMATCHED + 1))
    UNMATCHED_SERIALS="$UNMATCHED_SERIALS$R_SERIAL(no-path) "
  fi
  if [ "$cls" = "runc-write" ] || [ "$cls" = "strace-getattr" ]; then
    EXPECTED=$((EXPECTED + 1))
  fi
  markline="$R_SERIAL $R_TS $R_PID $R_COMM {$R_PERMS} dev=$R_DEV ino=$R_INO path=${decoded:-${R_PATHQ:-${R_NAME:-<none>}}} class=$cls"
  markline="$markline scontext=$R_SCTX tcontext=$R_TCTX"
  printf '%s\n' "$markline" >>"$EV/bprime-classification.log"
done <<EOF
$NEWTYPE_RECORDS
EOF

# the memfd_create / strace FD identity (required for the live-label check:
# a label whose creation syscall was never traced cannot silently pass)
MEMFD_CREATE_LINES="$(grep -ah 'memfd_create(' "$EV"/bprime-strace-c1.log "$EV"/bprime-strace-c2.log 2>/dev/null | head -4 || true)"
MEMFD_CREATE_OK=0
printf '%s\n' "$MEMFD_CREATE_LINES" | grep -q 'memfd_create("runc_cloned:' && MEMFD_CREATE_OK=1

# a loaded-window runc write denial on a memfd that stayed at tmpfs_t means
# the label did not move for that memfd (the transition is loaded but the
# mechanism did not engage) — scanned over ALL records, not only the
# new-type ones, precisely because such a record carries the OLD type
LABEL_NO_MOVE="$(printf '%s\n' "$RAW" \
  | grep -a 'comm="buildkit-runc"' \
  | grep -a "$MEMFD_HEX" \
  | grep -a "object_r:$BASETYPE:" \
  | grep -a 'tclass=file' \
  | sed -n 's/.*msg=audit([0-9.]*:\([0-9]*\)).*/\1/p')"
{
  printf 'memfd-create trace lines (strace FD identity):\n'
  printf '%s\n' "$MEMFD_CREATE_LINES"
  printf 'anchored memfd inodes (dev/ino):%s\n' "$MEMFD_INO_IDENTITIES"
} >>"$EV/bprime-classification.log"

# ---------------------------------------------------------------------------
# the ten fail-closed checks
# ---------------------------------------------------------------------------
declare -a CHECKS=()
chk() { CHECKS+=("$1=$2"); }

# 1. the exact experimental transition is loaded (the distro's unrelated
#    named ica_tmpfs_t transition on the same pair is tolerated)
if have loaded-transition.log \
   && grep -aq "type_transition docker_helper_buildkitd_t tmpfs_t:file $NEWTYPE;" "$EV/loaded-transition.log"; then
  chk 1 pass
else
  chk 1 blocked
fi

# 2. the new type has no unintended attributes or allows
if have newtype-allows.log && have newtype-attrs.log; then
  if grep -aq '^allow ' "$EV/newtype-allows.log"; then
    chk 2 fail
  elif grep -aqE "^ *type $NEWTYPE," "$EV/newtype-attrs.log"; then
    chk 2 fail
  else
    chk 2 pass
  fi
else
  chk 2 blocked
fi

# 3. the live runc memfd receives the new type (AVC + creation-trace
#    identity); a loaded-window runc write that stayed on tmpfs_t means the
#    label did not move for that memfd — decisive FAIL regardless of any
#    other window's success
if [ -n "$LABEL_NO_MOVE" ]; then
  chk 3 fail
elif [ "$LIVE_LABEL_PROVEN" -eq 1 ] && [ "$MEMFD_CREATE_OK" -eq 1 ]; then
  chk 3 pass
else
  chk 3 blocked
fi

# 4. no unexplained non-memfd object received the type
if [ "$N_OTHER" -gt 0 ]; then
  chk 4 fail
elif ! have bprime-avc-c1.log || ! have bprime-avc-c2.log; then
  chk 4 blocked
else
  chk 4 pass
fi

# 5. before/after create matrices show EXACTLY the expected change
#    (byte comparison via sha256sum digests: the guest environment has no
#    diffutils — diff/cmp are not guaranteed to exist)
if command -v sha256sum >/dev/null 2>&1; then
  if have create-matrix-before.log && have create-matrix-after.log; then
    PAIR1="system_u:system_r:docker_helper_buildkitd_t:s0:c1 x system_u:object_r:tmpfs_t:s0 x file"
    PAIR2="system_u:system_r:docker_helper_buildkitd_t:s0:c2 x system_u:object_r:tmpfs_t:s0 x file"
    ok=1
    for pair in "$PAIR1" "$PAIR2"; do
      before="$(grep -aF "$pair" "$EV/create-matrix-before.log" | sed 's/.*-> //')"
      after="$(grep -aF "$pair" "$EV/create-matrix-after.log" | sed 's/.*-> //')"
      [ "$before" = "system_u:object_r:tmpfs_t:s0" ] || ok=0
      [ "$after" = "system_u:object_r:$NEWTYPE:s0" ] || ok=0
    done
    h_before="$(grep -avF -e "$PAIR1" -e "$PAIR2" "$EV/create-matrix-before.log" | sha256sum | sed -n 's/^\([0-9a-f][0-9a-f]*\) .*/\1/p')"
    h_after="$(grep -avF -e "$PAIR1" -e "$PAIR2" "$EV/create-matrix-after.log" | sha256sum | sed -n 's/^\([0-9a-f][0-9a-f]*\) .*/\1/p')"
    if [ "$ok" -eq 1 ] && [ -n "$h_before" ] && [ "$h_before" = "$h_after" ]; then
      chk 5 pass
    else
      chk 5 fail
    fi
  else
    chk 5 blocked
  fi
else
  chk 5 blocked
fi

# 6. the cross-category decision matrix records the shared s0 result
if have av-matrix-loaded.log \
   && grep -aq 's0:c1 -> system_u:object_r:docker_helper_runc_memfd_t' "$EV/av-matrix-loaded.log" \
   && grep -aq 's0:c2 -> system_u:object_r:docker_helper_runc_memfd_t' "$EV/av-matrix-loaded.log" \
   && ! grep -aq ' ALLOW ' "$EV/av-matrix-loaded.log"; then
  chk 6 pass
elif have av-matrix-loaded.log; then
  chk 6 fail
else
  chk 6 blocked
fi

# 7. semodule -r removed the experimental module AND its transition
if have rollback-module-list.log && have rollback-transition.log; then
  if grep -aq 'module-still-loaded' "$EV/rollback-module-list.log" \
     || grep -aq "$NEWTYPE" "$EV/rollback-transition.log"; then
    chk 7 fail
  elif grep -aq 'module-removed' "$EV/rollback-module-list.log"; then
    chk 7 pass
  else
    chk 7 blocked
  fi
else
  chk 7 blocked
fi

# 8. the loaded policy SHA returns byte-identically to baseline
if have policy-sha-before.log && have policy-sha-after-rollback.log; then
  if [ "$(cat "$EV/policy-sha-before.log")" = "$(cat "$EV/policy-sha-after-rollback.log")" ]; then
    chk 8 pass
  else
    chk 8 fail
  fi
else
  chk 8 blocked
fi

# 9. the post-rollback create matrix is byte-identical to the baseline
#    (sha256 digests; no cmp/diff in the guest environment)
if command -v sha256sum >/dev/null 2>&1; then
  if have create-matrix-before.log && have create-matrix-rollback.log; then
    s_before="$(sha256sum "$EV/create-matrix-before.log" | sed -n 's/^\([0-9a-f][0-9a-f]*\) .*/\1/p')"
    s_roll="$(sha256sum "$EV/create-matrix-rollback.log" | sed -n 's/^\([0-9a-f][0-9a-f]*\) .*/\1/p')"
    if [ -n "$s_before" ] && [ "$s_before" = "$s_roll" ]; then
      chk 9 pass
    else
      chk 9 fail
    fi
  else
    chk 9 blocked
  fi
else
  chk 9 blocked
fi

# 10. the post-rollback build reproduces the ORIGINAL tmpfs_t:file terminal
if have bprime-rollback-avc.log \
   && grep -aq 'comm="buildkit-runc"' "$EV/bprime-rollback-avc.log" \
   && grep -aq "$MEMFD_HEX" "$EV/bprime-rollback-avc.log" \
   && grep -aq "object_r:$BASETYPE:s0 tclass=file" "$EV/bprime-rollback-avc.log" \
   && grep -aq 'denied  { write }' "$EV/bprime-rollback-avc.log"; then
  chk 10 pass
elif have bprime-rollback-avc.log \
   && grep -aq 'comm="buildkit-runc"' "$EV/bprime-rollback-avc.log" \
   && grep -aq "$MEMFD_HEX" "$EV/bprime-rollback-avc.log" \
   && grep -aq "object_r:$NEWTYPE" "$EV/bprime-rollback-avc.log"; then
  chk 10 fail
else
  chk 10 blocked
fi

# ---------------------------------------------------------------------------
# decision assembly (fail-closed precedence: FAIL > BLOCKED > VIABLE)
# ---------------------------------------------------------------------------
DECISION="BPRIME-VIABLE"
for c in "${CHECKS[@]}"; do
  case "$c" in *=fail) DECISION="BPRIME-FAIL"; break ;; esac
done
if [ "$DECISION" = "BPRIME-VIABLE" ]; then
  for c in "${CHECKS[@]}"; do
    case "$c" in *=blocked) DECISION="BPRIME-BLOCKED"; break ;; esac
  done
fi
# An unanchored memfd-shaped object means the identity of at least one
# new-type object is unknown: the scope claim cannot be made. Fail closed.
if [ "$DECISION" = "BPRIME-VIABLE" ] && [ "$N_UNMATCHED" -gt 0 ]; then
  DECISION="BPRIME-BLOCKED"
fi

CHECKS_STR="$(printf '%s,' "${CHECKS[@]}")"; CHECKS_STR="${CHECKS_STR%,}"
CLASS="expected=$EXPECTED,other=$N_OTHER,unmatched=$N_UNMATCHED"
[ -n "$OTHER_SERIALS" ] && CLASS="$CLASS,other-serials=$OTHER_SERIALS"
[ -n "$UNMATCHED_SERIALS" ] && CLASS="$CLASS,unmatched-serials=$UNMATCHED_SERIALS"
DEDUP_NOTE="raw=$TOTAL_RAW,deduped=$DEDUP_TOTAL"
LIVE="none"
[ "$EXPECTED" -gt 0 ] && LIVE="proven"
[ -n "$LABEL_NO_MOVE" ] && LIVE="no-move"

printf 'R7-BPRIME-VERDICT=DECISION=%s;CHECKS=%s;CLASSIFICATION=%s;AUDIT-DEDUP=%s;LIVE-LABEL=%s;MEMFD-CREATE-TRACE=%s;OTHER-RELABEL=%s\n' \
  "$DECISION" "$CHECKS_STR" "$CLASS" "$DEDUP_NOTE" "$LIVE" \
  "$([ "$MEMFD_CREATE_OK" -eq 1 ] && echo present || echo missing)" \
  "$([ "$N_OTHER" -gt 0 ] && echo "yes:$OTHER_SERIALS" || echo none)"

case "$DECISION" in
  BPRIME-VIABLE) exit 0 ;;
  BPRIME-FAIL)   exit 1 ;;
  *)             exit 2 ;;
esac
