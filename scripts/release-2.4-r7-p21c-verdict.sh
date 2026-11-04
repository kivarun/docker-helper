#!/usr/bin/env bash
#
# release-2.4-r7-p21c-verdict.sh — the R7 P21-C gate evaluator.
#
# Pure file-based evaluation of a P21-C evidence directory (no VM, no policy
# access). Fail-closed: missing, duplicated, corrupted, or ambiguous
# evidence can never produce a passing decision, and grep-match COUNTING is
# never used as a substitute for checking the specific records — every
# required kernel-decision row is validated individually, exactly once,
# against its exact expected result.
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
# unparseable, or unreadable) beats MEASURED.
#
# The evidence checked (all produced by release-2.4-r7-p21c-guest.sh):
#   create-matrix-before.log — the security_compute_create(_name)_raw
#     decision matrix. Required rows are the UNCHANGED P21-B transition
#     surface (each EXACTLY once, each with the EXACT expected result; any
#     other row or any unparseable line fails):
#       (buildkitd_t:s0:c1, {null,zero,full,random,urandom,tty}) -> devnode_t:s0
#       (buildkitd_t:s0:c2, {null,zero,full,random,urandom,tty}) -> devnode_t:s0
#       (buildkitd_t:s0:cX, someothername)                       -> runc_memfd_t:s0
#       (buildkitd_t:s0:cX, name=NULL)                           -> runc_memfd_t:s0
#       (unconfined_t,      null / name=NULL)                    -> user_tmp_t:s0
#   av-matrix-before.log — the kernel-AV matrix on the candidate policy.
#     Required rows (each EXACTLY once per section): for BOTH operation
#     categories the devnode_t:file surface must be create=ALLOW,
#     read=ALLOW, open=ALLOW (the ONE P21-C rung) and every other
#     permission DENIED — the pair must never ride a wider grant; unconfined
#     must be DENIED for all fifteen; the associate rows must be
#     devnode_t=ALLOW, runc_memfd_t=DENY, control=ALLOW.
#   p21c-terminals.log — the live-flow windows:
#     - the devnode-terminal section must contain NO record matching the
#       P21-B measured terminal shape (the exact "denied  { read open }"
#       pair on docker_helper_devnode_t, permissive=0, comm="runc:[2:INIT]"):
#       the former terminal is ELIMINATED; its reappearance is a FAIL;
#     - the next-terminal section must contain at least one further
#       full-structure denied record (permissive=0,
#       scontext=buildkitd_t:s0:cX, comm="runc:[2:INIT]") that is NOT the
#       granted devnode { read open } shape — the flow advanced past the
#       open-completion boundary and hit a NEW kernel decision. The exact
#       permission is OBSERVED, never pre-classified by this evaluator.
#       Absence of AVCs alone is never a passing outcome (BLOCKED);
#     - the three regression-control sections EMPTY (no runc_memfd_t:file
#       create denial, no tmpfs_t:file write denial, no associate denial).

set -uo pipefail

if [ "${1:-}" = "--gate" ]; then
  line="${2:-}"
  # The gate accepts EXACTLY ONE correctly formed R7-P21C-VERDICT line:
  #   - the fixed prefix R7-P21C-VERDICT=DECISION=P21C-MEASURED; — a
  #     different decision, a malformed prefix, or a truncated line never
  #     passes, and the MEASURED literal appearing as a substring of
  #     another field's value does not satisfy the prefix;
  #   - no second DECISION field;
  #   - no empty or trailing field, no apostrophe, no newline;
  #   - exactly the evaluator's field grammar, in the evaluator's field
  #     order — SCOPE, OPEN-COMPLETION, MEMFD, CROSSOP-CONTENT — followed
  #     by a real NEXT-TERMINAL record (never the empty or "(none)"
  #     placeholder, never a value corrupted across a field separator).
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
#    exact FULL expected structure — source context, parent (target)
#    context, class, name, AND result.
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
#    operation categories; EVERY other permission DENIED (the pair must
#    never ride a wider grant); unconfined all-DENY; associate rows
#    unchanged.
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
      if (line ~ /^== /) { next }   # a structural banner, not evidence
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
# 3. The live-flow windows: the P21-B measured terminal must be ELIMINATED
#    from the devnode-terminal section, a NEW full-structure record must be
#    present in the next-terminal section, and the mandatory
#    regression-control sections must be EMPTY.
# ---------------------------------------------------------------------------
TERM="$DIR/p21c-terminals.log"
NEXT_TERMINAL="(none)"
# The exact section-header lines. Header recognition and the AWK section
# anchoring below share THESE EXACT strings, so header presence and section
# boundaries can never diverge: a prefixed/suffixed/corrupted header line
# is not counted by check_header AND is not recognized by the AWK parsers.
DEV_HDR='== devnode-terminal runc-init AVCs (both windows) =='
NEXT_HDR='== next-terminal runc-init AVCs (both windows) =='
CTRL_HDR='== regression controls (must be EMPTY) =='
P20_HDR='-- P20 terminal (runc_memfd_t:file create) --'
PREB_HDR='-- pre-B terminal (tmpfs_t:file write) --'
ASSOC_HDR='-- associate denials (must be EMPTY — the singleton is granted) --'
if require_file p21c-terminals.log; then
  # Section headers are mandatory and must be unambiguous, and must match
  # the WHOLE line (grep -Fxc): a header embedded as a substring of a
  # longer/corrupted line is a damaged header, not a present one. A missing
  # header is incomplete evidence (BLOCKED); a duplicated header is
  # ambiguous evidence (FAIL).
  check_header() { # <header-line> <label>
    local n
    n="$(grep -Fxc -- "$1" "$TERM" || true)"
    case "$n" in
      1) return 0 ;;
      0) note BLOCKED "terminals: the required section header for '$2' is missing, corrupted, or not a whole line (damaged or truncated evidence)"; return 1 ;;
      *) note FAIL "terminals: the section header for '$2' appears $n times (ambiguous evidence)"; return 1 ;;
    esac
  }
  DEV_HEADER_OK=1
  check_header "$DEV_HDR" 'devnode terminal' || DEV_HEADER_OK=0
  NEXT_HEADER_OK=1
  check_header "$NEXT_HDR" 'next terminal' || NEXT_HEADER_OK=0
  CTRL_HEADERS_OK=1
  check_header "$CTRL_HDR" 'regression controls' || CTRL_HEADERS_OK=0
  check_header "$P20_HDR" 'P20 terminal' || CTRL_HEADERS_OK=0
  check_header "$PREB_HDR" 'pre-B terminal' || CTRL_HEADERS_OK=0
  check_header "$ASSOC_HDR" 'associate denials' || CTRL_HEADERS_OK=0

  if [ "$DEV_HEADER_OK" = 1 ]; then
    # The P21-B measured terminal shape must be GONE from both live
    # windows: the exact "denied  { read open }" permission pair on the
    # devnode_t target, permissive=0, the buildkitd_t:s0:cX source, and
    # the runc:[2:INIT] comm. Its reappearance is a positive violation
    # (the rung did not take effect).
    OLD_TERMINAL="$(awk -v hdr="$DEV_HDR" '
      $0 == hdr { sec = 1; next }
      /^== / || /^-- / { if (sec) exit }
      sec &&
        /avc:  denied  \{ read open \} / &&
        /permissive=0/ &&
        /scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c[0-9]+ tcontext=/ &&
        /tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file / &&
        /comm="runc:\[2:INIT\]"/ { print; exit }
    ' "$TERM")"
    if [ -n "$OLD_TERMINAL" ]; then
      note FAIL "OPEN-COMPLETION-LIVE: the P21-B measured devnode { read open } terminal reappeared in the enforcing windows: $OLD_TERMINAL"
    else
      printf 'TERMINAL-ELIMINATED\tthe P21-B { read open } devnode terminal is absent from both windows\n' >> "$CLASS_LOG"
    fi
  fi

  if [ "$NEXT_HEADER_OK" = 1 ]; then
    # The flow must have advanced to a NEW kernel boundary: at least one
    # further full-structure denied record from the same runtime stage,
    # NOT the granted devnode { read open } shape. The exact permission
    # is observed, never pre-classified here; absence of AVCs alone is
    # never a passing outcome.
    NEW_TERMINAL="$(awk -v hdr="$NEXT_HDR" '
      $0 == hdr { sec = 1; next }
      /^== / || /^-- / { if (sec) exit }
      sec &&
        /avc:  denied  / &&
        /permissive=0/ &&
        /scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c[0-9]+ / &&
        /comm="runc:\[2:INIT\]"/ {
          # Only the EXACT granted shape is excluded (the P21-B measured
          # terminal: the { read open } pair on the devnode_t file object);
          # every other denial — including a new denial on the SAME
          # devnode_t object with a different permission (e.g. a file-class
          # mounton) — is a legitimate observed next terminal.
          if ($0 ~ /tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file / &&
              $0 ~ /denied  \{ read open \} /) next
          # The cap_userns self-denials (setuid/setgid, scontext ==
          # tcontext) are the MEASURED PRE-BOUNDARY non-fatal records of
          # the same P21-B windows (serials 1188/1189 BEFORE the 1190
          # terminal): they cannot prove the flow advanced past the
          # open-completion boundary, so they are never selected. A
          # cap_userns-shaped TRUE boundary yields BLOCKED and is
          # reviewed, never silently accepted.
          if ($0 ~ /tclass=cap_userns /) next
          print; exit
        }
    ' "$TERM")"
    if [ -n "$NEW_TERMINAL" ]; then
      NEXT_TERMINAL="$NEW_TERMINAL"
      printf 'TERMINAL-OK\t%s\n' "$NEW_TERMINAL" >> "$CLASS_LOG"
    else
      note BLOCKED "terminals: no further full-structure runc:[2:INIT] denial record (the flow must be observed advancing past the open-completion boundary — absence of AVCs alone is never a passing outcome)"
    fi
  fi

  # Each regression-control section must be present (checked above) and
  # EMPTY: a non-empty section is a positive violation (the exact denial
  # family reappeared). The section body is anchored on the same exact
  # header line check_header verified, and ends at the next header-shaped
  # line.
  if [ "$CTRL_HEADERS_OK" = 1 ]; then
    for sechdr in "$P20_HDR" "$PREB_HDR" "$ASSOC_HDR"; do
      SEC_BODY="$(awk -v hdr="$sechdr" '
        $0 == hdr { sec = 1; next }
        /^== / || /^-- / { if (sec) exit }
        sec && NF { print }
      ' "$TERM")"
      secname="${sechdr#-- }"; secname="${secname%% (*}"
      if [ -n "$SEC_BODY" ]; then
        note FAIL "REGRESSION-CONTROL-REAPPEARED ${secname}: $SEC_BODY"
      else
        printf 'CONTROL-OK\t%s (empty)\n' "$secname" >> "$CLASS_LOG"
      fi
    done
  fi
fi

# ---------------------------------------------------------------------------
# Fields for the verdict line (summaries of the classification above).
# ---------------------------------------------------------------------------
SCOPE="six-names-ok"
[ "$DECISION" = "P21C-MEASURED" ] || SCOPE="not-established"
# OPEN-COMPLETION summarizes the former terminal's state: live (its exact
# shape reappeared — a positive violation), eliminated (the windows were
# checked and the shape is absent), not-established (the windows were
# missing/unreadable, so nothing can be said).
if grep -q 'OPEN-COMPLETION-LIVE' "$CLASS_LOG" 2>/dev/null; then
  OPEN_COMPLETION="live"
elif grep -q '^TERMINAL-ELIMINATED' "$CLASS_LOG" 2>/dev/null; then
  OPEN_COMPLETION="eliminated"
else
  OPEN_COMPLETION="not-established"
fi
MEMFD="intact"
grep -q 'REGRESSION-CONTROL-REAPPEARED P20 terminal' "$CLASS_LOG" 2>/dev/null && MEMFD="regressed"
CROSSOP="closed"
if grep -q $'^WRONG-VERDICT\tc2|' "$CLASS_LOG" 2>/dev/null; then CROSSOP="open"; fi

printf 'R7-P21C-VERDICT=DECISION=%s;SCOPE=%s;OPEN-COMPLETION=%s;MEMFD=%s;CROSSOP-CONTENT=%s;NEXT-TERMINAL=<%s>\n' \
  "$DECISION" "$SCOPE" "$OPEN_COMPLETION" "$MEMFD" "$CROSSOP" "$NEXT_TERMINAL"

case "$DECISION" in
  P21C-MEASURED) exit 0 ;;
  P21C-FAIL) exit 1 ;;
  *) exit 2 ;;
esac
