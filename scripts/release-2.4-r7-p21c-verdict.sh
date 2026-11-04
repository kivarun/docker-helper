#!/usr/bin/env bash
#
# release-2.4-r7-p21c-verdict.sh — the R7 P21-C gate evaluator (revision 2,
# r7-p21c-corrective-1: fail-closed per-operation runtime-window
# attribution).
#
# Pure file-based evaluation of a P21-C evidence directory (no VM, no policy
# access). Fail-closed: missing, duplicated, corrupted, or ambiguous
# evidence can never produce a passing decision, and grep-match COUNTING is
# never used as a substitute for checking the specific records — every
# required kernel-decision row and every required per-operation record is
# validated individually, exactly once, against its exact expected result.
#
# Usage:
#   release-2.4-r7-p21c-verdict.sh <evidence-dir>
#     Emits one machine-readable verdict line on stdout and writes the
#     per-row classification to <evidence-dir>/p21c-classification.log.
#     Exit codes: 0 = P21C-MEASURED, 1 = P21C-FAIL, 2 = P21C-BLOCKED.
#   release-2.4-r7-p21c-verdict.sh --gate <verdict-line>
#     Exit 0 iff the argument is EXACTLY ONE correctly formed
#     R7-P21C-VERDICT line whose FIRST field is the single
#     DECISION=P21C-MEASURED — no second DECISION field, no DECISION
#     substring inside another field's value, no malformed prefix, no
#     truncated or empty fields, summary fields exactly at their
#     MEASURED-consistent values (SCOPE=six-names-ok,
#     OPEN-COMPLETION=eliminated, MEMFD=intact, CROSSOP-CONTENT=closed),
#     and a real NEXT-TERMINAL record (the workflow gate).
#
# Decision precedence (mirrors the P21-B evaluator): FAIL (a positive
# violation was proven) beats BLOCKED (required evidence missing, empty,
# unparseable, or ambiguous) beats MEASURED.
#
# The evidence checked (all produced by release-2.4-r7-p21c-guest.sh):
#   create-matrix-before.log / av-matrix-before.log — the UNCHANGED
#     transition surface and the P21-C permission matrix (identical to
#     revision 1).
#   p21c-terminals.log — TWO INDEPENDENT per-operation sections, each of
#     which must ALONE prove that its own operation:
#       - is a DISTINCT operation (distinct daemon operation id and
#         distinct session id; one window or one operation id can never
#         serve as the evidence for both);
#       - was captured inside EXACT, non-overlapping audit.log line-offset
#         windows (before/after/captured consistent; rotation or an
#         inconsistent boundary decides BLOCKED; overlapping windows are a
#         positive violation);
#       - really reached the runc:[2:INIT] runtime stage on records
#         ATTRIBUTED to it (path-carried ops/op_<own-id>/ records, or
#         pathless records whose pid is proven by an op-attributed record
#         of the same window — MCS category is NEVER an attribution key);
#       - carries NO record of the ELIMINATED P21-B terminal shape
#         (devnode_t:file { read open }) anywhere in its whole window —
#         reappearance is a FAIL (OPEN-COMPLETION=live);
#       - has its OWN next-terminal record: a full-structure denied AVC
#         (permissive=0, scontext=buildkitd_t:s0:cX, comm="runc:[2:INIT]")
#         attributed to THAT operation, NOT the granted shape and NOT the
#         measured pre-boundary cap_userns self-denials. The exact
#         permission is OBSERVED, never pre-classified by this evaluator;
#         absence of AVCs alone is never a passing outcome (BLOCKED);
#       - violates NO regression control anywhere in its window (P20
#         runc_memfd_t:file create, pre-B' tmpfs_t:file write, associate);
#       - carries NO misattributed record (a record whose path names a
#         DIFFERENT operation id inside this operation's window) and NO
#         unattributed runc:[2:INIT] record (ambiguous attribution —
#         BLOCKED, never assumed).

set -uo pipefail

if [ "${1:-}" = "--gate" ]; then
  line="${2:-}"
  case "$line" in
    *"'"*|*$'\n'*) exit 1 ;;
    R7-P21C-VERDICT=DECISION=P21C-MEASURED\;*) : ;;
    *) exit 1 ;;
  esac
  tail="${line#R7-P21C-VERDICT=DECISION=P21C-MEASURED;}"
  case "$tail" in *DECISION=*) exit 1 ;; esac
  case "$tail" in *';;'*) exit 1 ;; esac
  case "$tail" in *';') exit 1 ;; esac
  GATE_RE='^SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<type=AVC [^;]*>$'
  [[ "$tail" =~ $GATE_RE ]] || exit 1
  exit 0
fi

DIR="${1:-}"
[ -n "$DIR" ] && [ -d "$DIR" ] || { printf 'R7-P21C-VERDICT=DECISION=P21C-BLOCKED;REASON=no-evidence-dir\n'; exit 2; }

C1='system_u:system_r:docker_helper_buildkitd_t:s0:c1'
C2='system_u:system_r:docker_helper_buildkitd_t:s0:c2'
UN='unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023'
DEV='system_u:object_r:docker_helper_devnode_t:s0'
MEM='system_u:object_r:docker_helper_runc_memfd_t:s0'
UNRES='unconfined_u:object_r:user_tmp_t:s0'
TMP='system_u:object_r:tmpfs_t:s0'

CLASS_LOG="$DIR/p21c-classification.log"
: > "$CLASS_LOG" 2>/dev/null || { printf 'R7-P21C-VERDICT=DECISION=P21C-BLOCKED;REASON=classification-log-unwritable\n'; exit 2; }

DECISION="P21C-MEASURED"
note() { # <severity> <detail> — FAIL beats BLOCKED beats MEASURED
  printf '%s\t%s\n' "$1" "$2" >> "$CLASS_LOG"
  case "$1" in
    FAIL) DECISION="P21C-FAIL" ;;
    BLOCKED) [ "$DECISION" = "P21C-FAIL" ] || DECISION="P21C-BLOCKED" ;;
  esac
}

require_file() { # <name>
  if [ ! -r "$DIR/$1" ] || [ ! -s "$DIR/$1" ]; then
    note BLOCKED "required evidence file missing or empty: $1"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 1. The create-decision matrix: the UNCHANGED P21-B transition surface,
#    every required row checked individually, exactly once, against its
#    exact FULL expected structure.
# ---------------------------------------------------------------------------
MATRIX="$DIR/create-matrix-before.log"
if require_file create-matrix-before.log; then
  SCOPE_ROW_FAILS="$(awk -v C1="$C1" -v C2="$C2" -v UN="$UN" -v DEV="$DEV" -v MEM="$MEM" -v UNRES="$UNRES" -v TMP="$TMP" '
    BEGIN {
      split("null zero full random urandom tty", NAMES, " ")
      for (i = 1; i <= 6; i++) {
        req[C1 "|" NAMES[i]] = DEV; req[C2 "|" NAMES[i]] = DEV
      }
      req[C1 "|someothername"] = MEM; req[C2 "|someothername"] = MEM
      req[C1 "|-"] = MEM;             req[C2 "|-"] = MEM
      req[UN "|null"] = UNRES;        req[UN "|-"] = UNRES
    }
    {
      line = $0
      if (line == "") next
      if (line !~ /^CREATE [^ ]+ x [^ ]+ x file \[[^]]+\] -> [^ ]+$/) {
        printf "UNPARSEABLE\t%s\n", line
        viol = 1
        next
      }
      n = split(line, f, " ")
      if (f[3] != "x" || f[4] != TMP || f[5] != "x" || f[6] != "file") {
        printf "STRUCTURE-ROW\t%s (parent=%s class=%s)\n", line, f[4], f[6]
        viol = 1
        next
      }
      name = f[7]; gsub(/^\[/, "", name); gsub(/\]$/, "", name)
      key = f[2] "|" name
      cnt[key]++
      res[key] = f[9]
    }
    END {
      for (k in cnt) {
        if (!(k in req)) {
          printf "UNEXPECTED-ROW\t%s -> %s (count %d)\n", k, res[k], cnt[k]
          viol = 1
        } else if (cnt[k] > 1) {
          printf "DUPLICATE-ROW\t%s -> %s (count %d)\n", k, res[k], cnt[k]
          viol = 1
        }
      }
      for (k in req) {
        if (!(k in cnt)) {
          printf "MISSING-ROW\t%s -> expected %s\n", k, req[k]
          miss = 1
        } else if (res[k] != req[k]) {
          printf "WRONG-RESULT\t%s -> %s (expected %s)\n", k, res[k], req[k]
          viol = 1
        } else {
          printf "ROW-OK\t%s -> %s\n", k, res[k]
        }
      }
      exit viol ? 1 : (miss ? 2 : 0)
    }' "$MATRIX")"
  MATRIX_RC=$?
  printf '%s\n' "$SCOPE_ROW_FAILS" >> "$CLASS_LOG"
  case "$MATRIX_RC" in
    0) ;;
    1) note FAIL "create-matrix: a required transition row is wrong, duplicated, unexpected, or unparseable (see p21c-classification.log)" ;;
    *) note BLOCKED "create-matrix: required transition rows are missing (see p21c-classification.log)" ;;
  esac
fi

# ---------------------------------------------------------------------------
# 2. The AV matrix: per-permission decisions checked individually. The
#    P21-C expectation: create AND the { read open } pair ALLOW for both
#    operation categories; EVERY other permission DENIED; unconfined
#    all-DENY; associate rows unchanged.
# ---------------------------------------------------------------------------
AV="$DIR/av-matrix-before.log"
if require_file av-matrix-before.log; then
  AV_OUT="$(awk -v C1="$C1" -v C2="$C2" -v UN="$UN" '
    BEGIN {
      split("create write append setattr execute execute_no_trans map open read getattr unlink rename link ioctl lock", PERMS, " ")
      for (i = 1; i <= 15; i++) {
        expect["c1|" PERMS[i]] = (PERMS[i] == "create" || PERMS[i] == "read" || PERMS[i] == "open") ? "ALLOW" : "DENY"
        expect["c2|" PERMS[i]] = (PERMS[i] == "create" || PERMS[i] == "read" || PERMS[i] == "open") ? "ALLOW" : "DENY"
        expect["un|" PERMS[i]] = "DENY"
      }
      expect["assoc-dev|associate"] = "ALLOW"
      expect["assoc-mem|associate"] = "DENY"
      expect["assoc-ctl|associate"] = "ALLOW"
    }
    {
      line = $0
      if (line == "" || line ~ /^$/) next
      if (line ~ /^== buildkitd_t:s0:c1 -> docker_helper_devnode_t:s0 ==$/) { sec = "c1"; next }
      if (line ~ /^== CROSS-OP: buildkitd_t:s0:c2 -> docker_helper_devnode_t:s0 ==$/) { sec = "c2"; next }
      if (line ~ /^== unconfined_t -> docker_helper_devnode_t:s0 ==$/) { sec = "un"; next }
      if (line ~ /^== /) { next }
      if (line ~ /^-- devnode_t -> tmpfs_t /) { sec = "assoc-dev"; next }
      if (line ~ /^-- runc_memfd_t -> tmpfs_t /) { sec = "assoc-mem"; next }
      if (line ~ /^-- tmpfs_t -> tmpfs_t /) { sec = "assoc-ctl"; next }
      if (sec == "") { printf "ROW-OUTSIDE-SECTION\t%s\n", line; viol = 1; next }
      if (line !~ /^  [a-z_]+ +(ALLOW|DENY) \(allowed=0x[0-9a-f]+ decided=0x[0-9a-f]+\)$/) {
        printf "UNPARSEABLE\t%s\n", line
        viol = 1
        next
      }
      gsub(/^ +/, "", line)
      split(line, f, " ")
      perm = f[1]; verd = f[2]
      key = sec "|" perm
      cnt[key]++
      res[key] = verd
    }
    END {
      for (k in cnt) {
        if (!(k in expect)) { printf "UNEXPECTED-ROW\t%s -> %s\n", k, res[k]; viol = 1 }
        else if (cnt[k] > 1) { printf "DUPLICATE-ROW\t%s -> %s\n", k, res[k]; viol = 1 }
      }
      for (k in expect) {
        if (!(k in cnt)) { printf "MISSING-ROW\t%s -> expected %s\n", k, expect[k]; miss = 1 }
        else if (res[k] != expect[k]) { printf "WRONG-VERDICT\t%s -> %s (expected %s)\n", k, res[k], expect[k]; viol = 1 }
        else { printf "ROW-OK\t%s -> %s\n", k, res[k] }
      }
      exit viol ? 1 : (miss ? 2 : 0)
    }' "$AV")"
  AV_RC=$?
  printf '%s\n' "$AV_OUT" >> "$CLASS_LOG"
  case "$AV_RC" in
    0) ;;
    1) note FAIL "av-matrix: a permission decision is wrong, duplicated, unexpected, or unparseable (see p21c-classification.log)" ;;
    *) note BLOCKED "av-matrix: required permission rows are missing (see p21c-classification.log)" ;;
  esac
fi

# ---------------------------------------------------------------------------
# 3. The two independent per-operation runtime windows.
# ---------------------------------------------------------------------------
TERM="$DIR/p21c-terminals.log"
NEXT_TERMINAL="(none)"

# The exact section-header lines. Header recognition and the AWK section
# anchoring below share THESE EXACT strings, so header presence and section
# boundaries can never diverge: a prefixed/suffixed/corrupted header line
# matches neither the whole-line header counts NOR the AWK section anchors.
OP_HDR_RE='^== operation [a-z0-9]+ op_[0-9a-f]+ session dhs_[0-9a-f]+ ==$'
P20_HDR='-- P20 terminal (runc_memfd_t:file create) --'
PREB_HDR='-- pre-B terminal (tmpfs_t:file write) --'
ASSOC_HDR='-- associate denials (must be EMPTY — the singleton is granted) --'
OLDSHAPE_HDR='-- P21-B terminal (devnode_t:file { read open }; the ELIMINATED shape) --'

if require_file p21c-terminals.log; then
  # --- operation section headers: EXACTLY TWO, distinct ids ---------------
  OP_HEADERS="$(grep -Ec "$OP_HDR_RE" "$TERM" || true)"
  OP_HEADERS_LIST="$(grep -E "$OP_HDR_RE" "$TERM" || true)"
  if [ "$OP_HEADERS" -lt 2 ]; then
    note BLOCKED "terminals: two independent per-operation sections are required (found $OP_HEADERS whole-line operation headers)"
  elif [ "$OP_HEADERS" -gt 2 ]; then
    note FAIL "terminals: more than two operation sections ($OP_HEADERS) — ambiguous evidence"
  else
    OP1_HDR="$(printf '%s\n' "$OP_HEADERS_LIST" | sed -n 1p)"
    OP2_HDR="$(printf '%s\n' "$OP_HEADERS_LIST" | sed -n 2p)"
    OP1_ID="$(printf '%s' "$OP1_HDR" | sed -n 's/^== operation [a-z0-9]* op_\([0-9a-f]*\) session .*/\1/p')"
    OP2_ID="$(printf '%s' "$OP2_HDR" | sed -n 's/^== operation [a-z0-9]* op_\([0-9a-f]*\) session .*/\1/p')"
    OP1_SESSION="$(printf '%s' "$OP1_HDR" | sed -n 's/^== operation [a-z0-9]* op_[0-9a-f]* session \(dhs_[0-9a-f]*\) ==$/\1/p')"
    OP2_SESSION="$(printf '%s' "$OP2_HDR" | sed -n 's/^== operation [a-z0-9]* op_[0-9a-f]* session \(dhs_[0-9a-f]*\) ==$/\1/p')"
    if [ -z "$OP1_ID" ] || [ -z "$OP2_ID" ] || [ -z "$OP1_SESSION" ] || [ -z "$OP2_SESSION" ]; then
      note BLOCKED "terminals: operation header grammar carries no parseable operation/session identity"
    elif [ "$OP1_ID" = "$OP2_ID" ]; then
      note FAIL "terminals: the SAME operation id appears in both windows (one window can never serve as the evidence for both operations): op_$OP1_ID"
    elif [ "$OP1_SESSION" = "$OP2_SESSION" ]; then
      note FAIL "terminals: the SAME session id appears in both windows: $OP1_SESSION"
    else
      printf 'OPS-DISTINCT\top_%s/%s and op_%s/%s\n' "$OP1_ID" "$OP1_SESSION" "$OP2_ID" "$OP2_SESSION" >> "$CLASS_LOG"
    fi
  fi

  # --- per-operation section evaluation ------------------------------------
  eval_op_section() { # <section-header-line> <opid> <first(1)|second(2)>
    local hdr="$1" opid="$2" pos="$3"
    # The section body: from this header to the next header-shaped line.
    local BODY
    BODY="$(awk -v hdr="$hdr" '
      $0 == hdr { sec = 1; next }
      /^== / { if (sec) exit }
      sec { print }
    ' "$TERM")"
    [ -n "$BODY" ] || { note BLOCKED "terminals: the section for op_$opid is empty"; return; }

    # (a) window boundaries: EXACT, consistent, and non-overlapping.
    local BOUND
    BOUND="$(printf '%s\n' "$BODY" | grep -E '^before=[0-9]+ after=[0-9]+ captured=[0-9]+$' | head -1)"
    local BEFORE AFTER CAPTURED
    BEFORE="$(printf '%s' "$BOUND" | sed -n 's/^before=\([0-9]*\) .*/\1/p')"
    AFTER="$(printf '%s' "$BOUND" | sed -n 's/^.* after=\([0-9]*\) .*/\1/p')"
    CAPTURED="$(printf '%s' "$BOUND" | sed -n 's/^.* captured=\([0-9]*\)$/\1/p')"
    if [ -z "$BEFORE" ] || [ -z "$AFTER" ] || [ -z "$CAPTURED" ]; then
      note BLOCKED "terminals: op_$opid has no consistent whole-line audit window boundary (before=<n> after=<m> captured=<k>) — truncated or rotated capture cannot be measured"
      return
    fi
    if [ "$AFTER" -lt "$BEFORE" ] || [ "$CAPTURED" -ne $((AFTER - BEFORE)) ] || [ "$CAPTURED" -eq 0 ]; then
      note BLOCKED "terminals: op_$opid window boundary inconsistent (before=$BEFORE after=$AFTER captured=$CAPTURED) — truncated or rotated capture cannot be measured"
      return
    fi
    printf 'WINDOW-OK\top_%s before=%s after=%s captured=%s\n' "$opid" "$BEFORE" "$AFTER" "$CAPTURED" >> "$CLASS_LOG"

    # (b) the whole-window attributed record sets.
    local OPATT PIDC MIS UNATT
    OPATT="$(printf '%s\n' "$BODY" | awk -v hdr='-- op-attributed runc-init records --' '
      $0 == hdr { sec = 1; next }
      /^-- / || /^== / { if (sec) exit }
      sec && NF { print }')"
    PIDC="$(printf '%s\n' "$BODY" | awk -v hdr='-- pid-correlated runc-init records --' '
      $0 == hdr { sec = 1; next }
      /^-- / || /^== / { if (sec) exit }
      sec && NF { print }')"
    MIS="$(printf '%s\n' "$BODY" | awk -v hdr='-- misattributed records (a path carries a DIFFERENT operation id) --' '
      $0 == hdr { sec = 1; next }
      /^-- / || /^== / { if (sec) exit }
      sec && NF { print }')"
    UNATT="$(printf '%s\n' "$BODY" | awk -v hdr='-- unattributed runc-init records --' '
      $0 == hdr { sec = 1; next }
      /^-- / || /^== / { if (sec) exit }
      sec && NF { print }')"

    # (c) attribution re-validation: every op-attributed record must carry
    # THIS operation's own path; every pid-correlated record must be
    # pathless and its pid must be proven by an op-attributed record.
    local BAD_OWN
    BAD_OWN="$(printf '%s\n' "$OPATT" | grep -av "ops/op_${opid}/" || true)"
    if [ -n "$BAD_OWN" ]; then
      note FAIL "ATTRIBUTION-VIOLATION op_$opid: an op-attributed record does not carry this operation's own path: $BAD_OWN"
    fi
    local OWN_PIDS BAD_PIDC
    OWN_PIDS="$(printf '%s\n' "$OPATT" | grep -aoE 'pid=[0-9]+' | sed 's/pid=//' | sort -u)"
    BAD_PIDC="$(printf '%s\n' "$PIDC" | while IFS= read -r rec; do
      [ -n "$rec" ] || continue
      if printf '%s' "$rec" | grep -qaE 'ops/op_[0-9a-f]+/'; then
        printf '%s\n' "$rec"
        continue
      fi
      rpid="$(printf '%s' "$rec" | grep -aoE 'pid=[0-9]+' | sed 's/pid=//' | head -1)"
      if [ -z "$rpid" ] || ! printf '%s\n' "$OWN_PIDS" | grep -qx "$rpid"; then
        printf '%s\n' "$rec"
      fi
    done)"
    if [ -n "$BAD_PIDC" ]; then
      note BLOCKED "terminals: op_$opid carries pid-correlated records whose pid is not proven by any op-attributed record (ambiguous attribution): $BAD_PIDC"
    fi
    if [ -n "$MIS" ]; then
      note FAIL "ATTRIBUTION-VIOLATION op_$opid: a record of ANOTHER operation appears in this operation's window: $MIS"
    fi
    if [ -n "$UNATT" ]; then
      note BLOCKED "terminals: op_$opid carries runc:[2:INIT] records that cannot be attributed to any operation (ambiguous evidence — never assumed): $UNATT"
    fi

    # (d) the eliminated P21-B terminal shape: absent from this
    # operation's attributed+correlated runtime records.
    local OLD_HERE
    OLD_HERE="$(printf '%s\n' "$OPATT" "$PIDC" | grep -a 'tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file' | grep -a 'denied  { read open }' | head -1)"
    if [ -n "$OLD_HERE" ]; then
      note FAIL "OPEN-COMPLETION-LIVE op_$opid: the P21-B measured devnode { read open } terminal reappeared in this operation's window: $OLD_HERE"
    fi

    # (e) THIS operation's own next terminal: a full-structure denied
    # record attributed to it, NOT the granted shape, NOT the measured
    # pre-boundary cap_userns self-denials. The permission is observed,
    # never pre-classified; absence is BLOCKED (AVC absence alone is
    # never a passing outcome).
    local NEW_HERE
    NEW_HERE="$(printf '%s\n' "$OPATT" "$PIDC" | awk '
      /avc:  denied  / &&
      /permissive=0/ &&
      /scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c[0-9]+ / &&
      /comm="runc:\[2:INIT\]"/ {
        if ($0 ~ /tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file / &&
            $0 ~ /denied  \{ read open \} /) next
        if ($0 ~ /tclass=cap_userns /) next
        print; exit
      }')"
    if [ -z "$NEW_HERE" ]; then
      note BLOCKED "terminals: op_$opid has NO attributed next-terminal record (the flow must be observed advancing past the open-completion boundary IN THIS OPERATION — absence of AVCs alone is never a passing outcome)"
    else
      printf 'OP-TERMINAL-OK\top_%s %s\n' "$opid" "$NEW_HERE" >> "$CLASS_LOG"
      if [ "$pos" = "1" ]; then
        NEXT_TERMINAL="$NEW_HERE"
        TERMINAL_1="$NEW_HERE"
      else
        TERMINAL_2="$NEW_HERE"
      fi
    fi

    # (f) the regression controls for THIS operation's whole window. Each
    # control section must exist EXACTLY once inside this section (a
    # missing header is damaged evidence — BLOCKED; a duplicated one is
    # ambiguous — FAIL) and be EMPTY.
    for sechdr in "$P20_HDR" "$PREB_HDR" "$ASSOC_HDR" "$OLDSHAPE_HDR"; do
      local SEC_BODY N_HEADS
      N_HEADS="$(printf '%s\n' "$BODY" | grep -Fxc -- "$sechdr" || true)"
      case "$N_HEADS" in
        1) ;;
        0) note BLOCKED "terminals: op_$opid is missing the control section header '$sechdr' (damaged or truncated evidence)"; continue ;;
        *) note FAIL "terminals: op_$opid carries the control section header '$sechdr' $N_HEADS times (ambiguous evidence)"; continue ;;
      esac
      SEC_BODY="$(printf '%s\n' "$BODY" | awk -v hdr="$sechdr" '
        $0 == hdr { sec = 1; next }
        /^-- / { if (sec) exit }
        sec && NF { print }')"
      local secname
      secname="${sechdr#-- }"; secname="${secname%% (*}"
      if [ -n "$SEC_BODY" ]; then
        note FAIL "REGRESSION-CONTROL-REAPPEARED op_$opid ${secname}: $SEC_BODY"
      else
        printf 'CONTROL-OK\top_%s %s (empty)\n' "$opid" "$secname" >> "$CLASS_LOG"
      fi
    done

    # Window-boundary ordering: the SECOND window must begin AT OR AFTER
    # the first window's end (an overlap would make records attributable
    # to both operations — a positive violation). Records BETWEEN the
    # windows are accounted by the separate inter-window section (host
    # audit noise is expected there; any runc-init record in it is
    # ambiguous).
    if [ "$pos" = "1" ]; then
      FIRST_WINDOW_END="$AFTER"
    elif [ -z "$FIRST_WINDOW_END" ]; then
      note BLOCKED "terminals: the first window was never bounded; the second window's boundary cannot be checked"
    else
      SECOND_WINDOW_BEGIN="$BEFORE"
      if [ "$BEFORE" -lt "$FIRST_WINDOW_END" ]; then
        note FAIL "WINDOW-OVERLAP: the second window (before=$BEFORE) overlaps the first window (after=$FIRST_WINDOW_END) — records would be attributable to both operations"
      fi
    fi
  }
  FIRST_WINDOW_END=""
  SECOND_WINDOW_BEGIN=""
  TERMINAL_1=""
  TERMINAL_2=""
  if [ "$OP_HEADERS" -eq 2 ] && [ -n "$OP1_ID" ] && [ -n "$OP2_ID" ] \
     && [ "$OP1_ID" != "$OP2_ID" ] && [ -n "$OP1_SESSION" ] && [ -n "$OP2_SESSION" ] \
     && [ "$OP1_SESSION" != "$OP2_SESSION" ]; then
    eval_op_section "$OP1_HDR" "$OP1_ID" 1
    eval_op_section "$OP2_HDR" "$OP2_ID" 2
    # The two operations' terminal records must be DISTINCT records: one
    # AVC can never serve as the evidence for both operations.
    if [ -n "$TERMINAL_1" ] && [ -n "$TERMINAL_2" ] && [ "$TERMINAL_1" = "$TERMINAL_2" ]; then
      note FAIL "TERMINAL-NOT-DISTINCT: both operations cite the SAME AVC record as their next terminal (one window can never serve both operations)"
    fi

    # --- the inter-window region: attributable to NEITHER operation ------
    INTER_HDR='== inter-window records (attributable to NEITHER operation) =='
    N_INTER="$(grep -Fxc -- "$INTER_HDR" "$TERM" || true)"
    case "$N_INTER" in
      1) ;;
      0) note BLOCKED "terminals: the inter-window region section is missing (the capture region between the two windows must be accounted for)"; ;;
      *) note FAIL "terminals: the inter-window section header appears $N_INTER times (ambiguous evidence)"; ;;
    esac
    if [ "$N_INTER" = "1" ]; then
      INTER_BODY="$(awk -v hdr="$INTER_HDR" '
        $0 == hdr { sec = 1; next }
        /^== / { if (sec) exit }
        sec { print }' "$TERM")"
      INTER_GAPA="$(printf '%s\n' "$INTER_BODY" | sed -n 's/^gap-after=\([0-9]*\) .*/\1/p' | head -1)"
      INTER_GAPB="$(printf '%s\n' "$INTER_BODY" | sed -n 's/^.* gap-before=\([0-9]*\) .*/\1/p' | head -1)"
      INTER_CAP="$(printf '%s\n' "$INTER_BODY" | sed -n 's/^.* captured=\([0-9]*\)$/\1/p' | head -1)"
      if [ -z "$INTER_GAPA" ] || [ -z "$INTER_GAPB" ] || [ -z "$INTER_CAP" ]; then
        note BLOCKED "terminals: the inter-window section carries no consistent whole-line gap boundary (gap-after=<n> gap-before=<m> captured=<k>)"
      elif [ "$INTER_GAPB" -lt "$INTER_GAPA" ] || [ "$INTER_CAP" -ne $((INTER_GAPB - INTER_GAPA)) ]; then
        note BLOCKED "terminals: the inter-window gap boundary is inconsistent (gap-after=$INTER_GAPA gap-before=$INTER_GAPB captured=$INTER_CAP)"
      elif [ "$INTER_GAPB" -lt "$FIRST_WINDOW_END" ] 2>/dev/null; then
        note FAIL "WINDOW-OVERLAP: the inter-window region (gap-before=$INTER_GAPB) reaches into the first window (after=$FIRST_WINDOW_END)"
      elif [ "$INTER_GAPA" -gt "$FIRST_WINDOW_END" ] 2>/dev/null; then
        note BLOCKED "terminals: the inter-window region (gap-after=$INTER_GAPA) does not start at the first window's end ($FIRST_WINDOW_END) — records between them are unaccounted"
      elif [ -n "$SECOND_WINDOW_BEGIN" ] && [ "$INTER_GAPB" -ne "$SECOND_WINDOW_BEGIN" ]; then
        note BLOCKED "terminals: the inter-window region (gap-before=$INTER_GAPB) does not end at the second window's begin ($SECOND_WINDOW_BEGIN) — records between them are unaccounted"
      fi
      INTER_RUNC="$(printf '%s\n' "$INTER_BODY" | awk -v hdr='-- records --' '
        $0 == hdr { sec = 1; next }
        sec && /comm="runc:\[2:INIT\]"/ && NF { print }')"
      if [ -n "$INTER_RUNC" ]; then
        note BLOCKED "terminals: runc:[2:INIT] records exist in the inter-window region where they are attributable to NEITHER operation (ambiguous evidence — never assumed): $INTER_RUNC"
      fi
      for sechdr_shape in 'docker_helper_runc_memfd_t.*tclass=file.*\{ create \}' 'tcontext=system_u:object_r:tmpfs_t:s0 tclass=file.*\{ write \}' 'denied  { associate }'; do
        INTER_CTRL="$(printf '%s\n' "$INTER_BODY" | grep -aE "$sechdr_shape" | head -2 || true)"
        if [ -n "$INTER_CTRL" ]; then
          note FAIL "REGRESSION-CONTROL-REAPPEARED inter-window: $INTER_CTRL"
        fi
      done
      INTER_OLD="$(printf '%s\n' "$INTER_BODY" | grep -a 'tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file' | grep -a 'denied  { read open }' | head -1 || true)"
      if [ -n "$INTER_OLD" ]; then
        note FAIL "OPEN-COMPLETION-LIVE: the eliminated devnode { read open } shape appears in the inter-window region: $INTER_OLD"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Fields for the verdict line (summaries of the classification above).
# ---------------------------------------------------------------------------
SCOPE="six-names-ok"
[ "$DECISION" = "P21C-MEASURED" ] || SCOPE="not-established"
# OPEN-COMPLETION summarizes the former terminal's state: live (its exact
# shape reappeared in ANY operation's window — a positive violation),
# eliminated (BOTH independently attributed windows were checked and the
# shape is absent), not-established (the windows were missing, ambiguous,
# or never fully evaluated).
if grep -q 'OPEN-COMPLETION-LIVE' "$CLASS_LOG" 2>/dev/null \
  || grep -q 'REGRESSION-CONTROL-REAPPEARED op_[0-9a-f]* P21-B terminal' "$CLASS_LOG" 2>/dev/null; then
  OPEN_COMPLETION="live"
elif [ "$(grep -c '^WINDOW-OK' "$CLASS_LOG" 2>/dev/null || true)" -ge 2 ]; then
  # Both windows were bounded and their attributed/correlated record sets
  # were checked against the eliminated shape (the per-operation check
  # runs for every bounded window), and no window found it live.
  OPEN_COMPLETION="eliminated"
else
  OPEN_COMPLETION="not-established"
fi
MEMFD="intact"
grep -q 'REGRESSION-CONTROL-REAPPEARED' "$CLASS_LOG" 2>/dev/null \
  && grep -q 'P20 terminal' "$CLASS_LOG" 2>/dev/null && MEMFD="regressed"
CROSSOP="closed"
if grep -q $'^WRONG-VERDICT\tc2|' "$CLASS_LOG" 2>/dev/null; then CROSSOP="open"; fi

printf 'R7-P21C-VERDICT=DECISION=%s;SCOPE=%s;OPEN-COMPLETION=%s;MEMFD=%s;CROSSOP-CONTENT=%s;NEXT-TERMINAL=<%s>\n' \
  "$DECISION" "$SCOPE" "$OPEN_COMPLETION" "$MEMFD" "$CROSSOP" "$NEXT_TERMINAL"

case "$DECISION" in
  P21C-MEASURED) exit 0 ;;
  P21C-FAIL) exit 1 ;;
  *) exit 2 ;;
esac
