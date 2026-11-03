#!/usr/bin/env bash
#
# release-2.4-r7-p21b-verdict.sh — the R7 P21-B gate evaluator.
#
# Pure file-based evaluation of a P21-B evidence directory (no VM, no policy
# access). Fail-closed: missing, duplicated, corrupted, or ambiguous
# evidence can never produce a passing decision, and grep-match COUNTING is
# never used as a substitute for checking the specific transitions — every
# required kernel-decision row is validated individually, exactly once,
# against its exact expected result.
#
# Usage:
#   release-2.4-r7-p21b-verdict.sh <evidence-dir>
#     Emits one machine-readable verdict line on stdout and writes the
#     per-row classification to <evidence-dir>/p21b-classification.log.
#     Exit codes: 0 = P21B-MEASURED, 1 = P21B-FAIL, 2 = P21B-BLOCKED.
#   release-2.4-r7-p21b-verdict.sh --gate <verdict-line>
#     Exit 0 iff the argument is EXACTLY ONE correctly formed
#     R7-P21B-VERDICT line whose FIRST field is the single
#     DECISION=P21B-MEASURED — no second DECISION field, no DECISION
#     substring inside another field's value, no malformed prefix, no
#     truncated or empty fields, and (for a MEASURED decision) a real
#     NEXT-TERMINAL record (the workflow gate).
#
# Decision precedence (mirrors the B′ evaluator): FAIL (a positive
# violation was proven) beats BLOCKED (required evidence missing, empty,
# unparseable, or unreadable) beats MEASURED.
#
# The evidence checked (all produced by release-2.4-r7-p21b-guest.sh):
#   create-matrix-before.log — the security_compute_create(_name)_raw
#     decision matrix. Required rows (each EXACTLY once, each with the
#     EXACT expected result; any other row or any unparseable line fails):
#       (buildkitd_t:s0:c1, {null,zero,full,random,urandom,tty}) -> devnode_t:s0
#       (buildkitd_t:s0:c2, {null,zero,full,random,urandom,tty}) -> devnode_t:s0
#       (buildkitd_t:s0:cX, someothername)                       -> runc_memfd_t:s0
#       (buildkitd_t:s0:cX, name=NULL)                           -> runc_memfd_t:s0
#       (unconfined_t,      null / name=NULL)                    -> user_tmp_t:s0
#   av-matrix-before.log — the kernel-AV matrix. Required rows (each
#     EXACTLY once per section): for BOTH operation categories the
#     devnode_t:file surface must be create=ALLOW and every content
#     permission DENIED; unconfined must be DENIED for all fifteen;
#     the associate rows must be devnode_t=ALLOW, runc_memfd_t=DENY,
#     control=ALLOW.
#   p21b-terminals.log — the live-flow windows: at least one
#     comm="runc:[2:INIT]" tclass=file record carrying
#     tcontext=docker_helper_devnode_t:s0 (the recorded next terminal and,
#     by process existence, the proof the sealed memfd clone exec
#     completed), and the three regression-control sections EMPTY (no
#     runc_memfd_t:file create denial, no tmpfs_t:file write denial, no
#     associate denial).

set -uo pipefail

if [ "${1:-}" = "--gate" ]; then
  line="${2:-}"
  # The gate accepts EXACTLY ONE correctly formed R7-P21B-VERDICT line:
  #   - the fixed prefix R7-P21B-VERDICT=DECISION=P21B-MEASURED; — a
  #     different decision, a malformed prefix, or a truncated line never
  #     passes, and the MEASURED literal appearing as a substring of
  #     another field's value does not satisfy the prefix;
  #   - no second DECISION field;
  #   - no empty or trailing field, no apostrophe, no newline;
  #   - exactly the evaluator's field grammar, in the evaluator's field
  #     order — SCOPE, ARBITRARY-NAME-KEEPS-MEMFD, MEMFD, CROSSOP-CONTENT —
  #     followed by a real NEXT-TERMINAL record (never the empty or
  #     "(none)" placeholder, never a value corrupted across a field
  #     separator).
  case "$line" in
    *"'"*|*$'\n'*) exit 1 ;;
    R7-P21B-VERDICT=DECISION=P21B-MEASURED\;*) : ;;
    *) exit 1 ;;
  esac
  tail="${line#R7-P21B-VERDICT=DECISION=P21B-MEASURED;}"
  case "$tail" in *DECISION=*) exit 1 ;; esac
  case "$tail" in *';;'*) exit 1 ;; esac
  case "$tail" in *';') exit 1 ;; esac
  # The evaluator's fixed field grammar, in its fixed field order, ending
  # in a real NEXT-TERMINAL record whose value contains no field separator.
  GATE_RE='^SCOPE=[a-z-]+;ARBITRARY-NAME-KEEPS-MEMFD=(yes|no);MEMFD=(intact|regressed);CROSSOP-CONTENT=(closed|open);NEXT-TERMINAL=<type=AVC [^;]*>$'
  [[ "$tail" =~ $GATE_RE ]] || exit 1
  exit 0
fi

DIR="${1:-}"
[ -n "$DIR" ] && [ -d "$DIR" ] || { printf 'R7-P21B-VERDICT=DECISION=P21B-BLOCKED;REASON=no-evidence-dir\n'; exit 2; }

C1='system_u:system_r:docker_helper_buildkitd_t:s0:c1'
C2='system_u:system_r:docker_helper_buildkitd_t:s0:c2'
UN='unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023'
DEV='system_u:object_r:docker_helper_devnode_t:s0'
MEM='system_u:object_r:docker_helper_runc_memfd_t:s0'
UNRES='unconfined_u:object_r:user_tmp_t:s0'
TMP='system_u:object_r:tmpfs_t:s0'

CLASS_LOG="$DIR/p21b-classification.log"
: > "$CLASS_LOG" 2>/dev/null || { printf 'R7-P21B-VERDICT=DECISION=P21B-BLOCKED;REASON=classification-log-unwritable\n'; exit 2; }

DECISION="P21B-MEASURED"
note() { # <severity> <detail> — FAIL beats BLOCKED beats MEASURED
  printf '%s\t%s\n' "$1" "$2" >> "$CLASS_LOG"
  case "$1" in
    FAIL) DECISION="P21B-FAIL" ;;
    BLOCKED) [ "$DECISION" = "P21B-FAIL" ] || DECISION="P21B-BLOCKED" ;;
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
# 1. The create-decision matrix: every required transition checked
#    individually, exactly once, against its exact FULL expected structure —
#    source context, parent (target) context, class, name, AND result. A
#    row whose RESULT alone would look right is still rejected when its
#    source, parent context, or class is wrong.
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
      # The FULL structure is part of the requirement: the row grammar
      # already fixed f[1]="CREATE", f[8]="->", f[9]=result; the parent
      # context, the "x" separators, and the file class are checked here.
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
      # 0 = all rows OK; 1 = a positive violation (wrong, duplicated,
      # unexpected, or unparseable — beats missing evidence); 2 = missing
      # rows only.
      exit viol ? 1 : (miss ? 2 : 0)
    }' "$MATRIX")"
  MATRIX_RC=$?
  printf '%s\n' "$SCOPE_ROW_FAILS" >> "$CLASS_LOG"
  case "$MATRIX_RC" in
    0) ;;
    1) note FAIL "create-matrix: a required transition row is wrong, duplicated, unexpected, or unparseable (see p21b-classification.log)" ;;
    *) note BLOCKED "create-matrix: required transition rows are missing (see p21b-classification.log)" ;;
  esac
fi

# ---------------------------------------------------------------------------
# 2. The AV matrix: per-permission decisions checked individually.
# ---------------------------------------------------------------------------
AV="$DIR/av-matrix-before.log"
if require_file av-matrix-before.log; then
  AV_OUT="$(awk -v C1="$C1" -v C2="$C2" -v UN="$UN" '
    BEGIN {
      split("create write append setattr execute execute_no_trans map open read getattr unlink rename link ioctl lock", PERMS, " ")
      for (i = 1; i <= 15; i++) {
        expect["c1|" PERMS[i]] = (PERMS[i] == "create") ? "ALLOW" : "DENY"
        expect["c2|" PERMS[i]] = (PERMS[i] == "create") ? "ALLOW" : "DENY"
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
    1) note FAIL "av-matrix: a permission decision is wrong, duplicated, unexpected, or unparseable (see p21b-classification.log)" ;;
    *) note BLOCKED "av-matrix: required permission rows are missing (see p21b-classification.log)" ;;
  esac
fi

# ---------------------------------------------------------------------------
# 3. The live-flow windows: the recorded next terminal (FULL record
#    structure required — the exact { read open } permission pair,
#    permissive=0, the buildkitd_t:s0:cX source context, the devnode_t:s0
#    target context, the file class, and a per-operation-tree
#    /rootfs/dev/null path) and the mandatory regression-control sections.
# ---------------------------------------------------------------------------
TERM="$DIR/p21b-terminals.log"
NEXT_TERMINAL="(none)"
if require_file p21b-terminals.log; then
  # Section headers are mandatory and must be unambiguous: a missing header
  # is incomplete evidence (BLOCKED); a duplicated header is ambiguous
  # evidence (FAIL).
  check_header() { # <header-line> <label>
    local n
    n="$(grep -Fc -- "$1" "$TERM" || true)"
    case "$n" in
      1) return 0 ;;
      0) note BLOCKED "terminals: the required section header for '$2' is missing (damaged or truncated evidence)"; return 1 ;;
      *) note FAIL "terminals: the section header for '$2' appears $n times (ambiguous evidence)"; return 1 ;;
    esac
  }
  DEV_HEADER_OK=1
  check_header '== devnode-terminal runc-init AVCs (both windows) ==' 'devnode terminal' || DEV_HEADER_OK=0
  CTRL_HEADERS_OK=1
  check_header '== regression controls (must be EMPTY) ==' 'regression controls' || CTRL_HEADERS_OK=0
  check_header '-- P20 terminal (runc_memfd_t:file create) --' 'P20 terminal' || CTRL_HEADERS_OK=0
  check_header '-- pre-B terminal (tmpfs_t:file write) --' 'pre-B terminal' || CTRL_HEADERS_OK=0
  check_header '-- associate denials (must be EMPTY — the singleton is granted) --' 'associate denials' || CTRL_HEADERS_OK=0

  if [ "$DEV_HEADER_OK" = 1 ]; then
    # The terminal record must match the FULL measured shape (the real
    # serials 1190/1817 of run 41648049864 define the format): the exact
    # "denied  { read open }" permission pair, permissive=0, the
    # buildkitd_t:s0:cX source context, the devnode_t:s0 target context,
    # tclass=file, and a per-operation-tree /rootfs/dev/null path. An
    # arbitrary AVC on the same type is NOT accepted as the terminal.
    DEV_TERMINAL="$(awk '
      /^== devnode-terminal runc-init AVCs/ { sec = 1; next }
      /^== / || /^-- / { if (sec) exit }
      sec &&
        /avc:  denied  \{ read open \} / &&
        /permissive=0/ &&
        /scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c[0-9]+ tcontext=/ &&
        /tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file / &&
        /comm="runc:\[2:INIT\]"/ &&
        /path="[^"]*\/ops\/op_[^"]*\/rootfs\/dev\/null"/ { print; exit }
    ' "$TERM")"
    if [ -n "$DEV_TERMINAL" ]; then
      NEXT_TERMINAL="$DEV_TERMINAL"
      printf 'TERMINAL-OK\t%s\n' "$DEV_TERMINAL" >> "$CLASS_LOG"
    else
      note BLOCKED "terminals: no record matching the FULL measured terminal shape (denied { read open }, permissive=0, scontext=buildkitd_t:s0:cX, tcontext=docker_helper_devnode_t:s0, tclass=file, comm=runc:[2:INIT], per-op rootfs/dev/null path) — an arbitrary same-type AVC is not accepted"
    fi
  fi
  # Each regression-control section must be present (checked above) and
  # EMPTY: a non-empty section is a positive violation (the exact denial
  # family reappeared).
  if [ "$CTRL_HEADERS_OK" = 1 ]; then
    for secname in 'P20 terminal' 'pre-B terminal' 'associate denials'; do
      SEC_BODY="$(awk -v want="$secname" '
        index($0, "-- " want " ") == 1 { sec = 1; next }
        /^== / || /^-- / { if (sec) exit }
        sec && NF { print }
      ' "$TERM")"
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
[ "$DECISION" = "P21B-MEASURED" ] || SCOPE="not-established"
ARBITRARY="yes"
if ! grep -q '^ROW-OK.*|someothername -> system_u:object_r:docker_helper_runc_memfd_t:s0$' "$CLASS_LOG" 2>/dev/null \
   || ! grep -q '^ROW-OK.*|- -> system_u:object_r:docker_helper_runc_memfd_t:s0$' "$CLASS_LOG" 2>/dev/null; then
  ARBITRARY="no"
fi
MEMFD="intact"
grep -q 'REGRESSION-CONTROL-REAPPEARED P20 terminal' "$CLASS_LOG" 2>/dev/null && MEMFD="regressed"
CROSSOP="closed"
if grep -q $'^WRONG-VERDICT\tc2|' "$CLASS_LOG" 2>/dev/null; then CROSSOP="open"; fi

printf 'R7-P21B-VERDICT=DECISION=%s;SCOPE=%s;ARBITRARY-NAME-KEEPS-MEMFD=%s;MEMFD=%s;CROSSOP-CONTENT=%s;NEXT-TERMINAL=<%s>\n' \
  "$DECISION" "$SCOPE" "$ARBITRARY" "$MEMFD" "$CROSSOP" "$NEXT_TERMINAL"

case "$DECISION" in
  P21B-MEASURED) exit 0 ;;
  P21B-FAIL) exit 1 ;;
  *) exit 2 ;;
esac
