#!/usr/bin/env bash
#
# release-2.4-r7-p21d-verdict.sh — the R7 P21-D gate evaluator: the P21-C
# revision-3 fail-closed classification (per-operation runtime-window
# attribution + audit-capture integrity) extended with the P21-D stage
# deltas — the devnode mounton decision row is EXPECTED ALLOW for both
# operation categories on the candidate policy, BOTH measured devnode
# terminals (the P21-B { read open } shape AND the P21-C { mounton } shape)
# are ELIMINATED shapes whose reappearance decides FAIL, and the
# next-terminal matcher rejects both granted shapes and the pre-boundary
# cap_userns self-denials.
#
# Revision 3 addition: the capture itself is now part of the proof. The
# producer reads every window through ONE pinned read descriptor on the
# audit source and records, per capture: the identity checkpoints around
# every drain (path st_dev:st_ino == pinned st_dev:st_ino; pinned size
# never below the consumed cursor), the drain outcomes, and a MEASURED
# accounting (before/after/expected/actual, actual = the extracted file's
# own line count, not the boundary arithmetic). The evaluator accepts
# MEASURED only when every checkpoint is proven, both drains are ok, the
# accounting is internally consistent, and the RAW window artifacts
# (avc-window-<tag>.log, inter-window.log) independently corroborate the
# section: same line count as `actual`, every cited record present
# verbatim, every runc:[2:INIT] record in the raw bytes accounted for by
# the section's classification, and no regression-control shape anywhere
# in the raw bytes.
#
# Pure file-based evaluation of a P21-D evidence directory (no VM, no policy
# access). Fail-closed: missing, duplicated, corrupted, or ambiguous
# evidence can never produce a passing decision, and grep-match COUNTING is
# never used as a substitute for checking the specific records — every
# required kernel-decision row and every required per-operation record is
# validated individually, exactly once, against its exact expected result.
#
# Usage:
#   release-2.4-r7-p21d-verdict.sh <evidence-dir>
#     Emits one machine-readable verdict line on stdout and writes the
#     per-row classification to <evidence-dir>/p21d-classification.log.
#     Exit codes: 0 = P21D-MEASURED, 1 = P21D-FAIL, 2 = P21D-BLOCKED.
#   release-2.4-r7-p21d-verdict.sh --gate <verdict-line>
#     Exit 0 iff the argument is EXACTLY ONE correctly formed
#     R7-P21D-VERDICT line whose FIRST field is the single
#     DECISION=P21D-MEASURED — no second DECISION field, no DECISION
#     substring inside another field's value, no malformed prefix, no
#     truncated or empty fields, summary fields exactly at their
#     MEASURED-consistent values (SCOPE=six-names-ok,
#     OPEN-COMPLETION=eliminated, MEMFD=intact, CROSSOP-CONTENT=closed),
#     per-operation result fields, and a real NEXT-TERMINAL record — or
#     the explicit NEXT-TERMINAL=none token, admissible ONLY when BOTH
#     operations proved their own completion (the P21-D alternative form
#     of runtime advancement) (the workflow gate).
#   release-2.4-r7-p21d-verdict.sh --cx <evidence-dir>
#     The CONCURRENT negative-scenario classifier (r7-p21d-corrective-1):
#     evaluates p21d-cx-terminals.log — two operations built
#     CONCURRENTLY, so a foreign pathless runc-init AVC lands inside a
#     PROVEN window while the window's own operation completes with an
#     error. Every runc:[2:INIT] record of each proven window is
#     classified by its pid-proof binding (own / foreign / unproven); a
#     foreign record is EXCLUDED WITH PROOF, never misattributed; an
#     unproven record decides BLOCKED. OVERLAP=measured requires the
#     second window's begin strictly inside the first window's span and
#     FOREIGN-EXCLUDED>=1 requires the negative scenario to have actually
#     been realized. Emits
#     R7-P21D-CX-VERDICT=DECISION=P21D-CX-PROVEN|P21D-CX-FAIL|\
#     P21D-CX-BLOCKED;OVERLAP=...;FOREIGN-EXCLUDED=...;[REASON=...]
#   release-2.4-r7-p21d-verdict.sh --cx-gate <cx-verdict-line>
#     Exit 0 iff the argument is exactly
#     DECISION=P21D-CX-PROVEN;OVERLAP=measured;FOREIGN-EXCLUDED=<n>=1.. .
#
# Decision precedence (mirrors the P21-B evaluator): FAIL (a positive
# violation was proven) beats BLOCKED (required evidence missing, empty,
# unparseable, or ambiguous) beats MEASURED.
#
# The evidence checked (all produced by release-2.4-r7-p21d-guest.sh):
#   create-matrix-before.log / av-matrix-before.log — the UNCHANGED
#     transition surface and the P21-C permission matrix (identical to
#     revision 1).
#   p21d-terminals.log — TWO INDEPENDENT per-operation sections, each of
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
#         DIFFERENT operation id inside this operation's window — FAIL).
#         PATHLESS runc:[2:INIT] records (the P21-D post-rung shape: the
#         observed terminals of the device-bind stage carry name=/no-path
#         forms) are attributed by the PROVEN window — the window opened
#         before THIS operation's POST and closed at THIS operation's
#         terminal, the windows are proven non-overlapping, and the
#         pid-singleton invariant pins every runc:[2:INIT] record of the
#         window to ONE container init whose pid the OTHER window never
#         shares (the same pid in both windows decides FAIL). A window
#         carrying runc:[2:INIT] records of MULTIPLE container inits is
#         ambiguous evidence (BLOCKED, never assumed).

set -uo pipefail

if [ "${1:-}" = "--gate" ]; then
  line="${2:-}"
  case "$line" in
    *"'"*|*$'\n'*) exit 1 ;;
    R7-P21D-VERDICT=DECISION=P21D-MEASURED\;*) : ;;
    *) exit 1 ;;
  esac
  tail="${line#R7-P21D-VERDICT=DECISION=P21D-MEASURED;}"
  case "$tail" in *DECISION=*) exit 1 ;; esac
  case "$tail" in *';;'*) exit 1 ;; esac
  case "$tail" in *';') exit 1 ;; esac
  GATE_RE='^SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=(none|<type=AVC [^;]*>);OP1-RESULT=(terminal|completed);OP2-RESULT=(terminal|completed)$'
  [[ "$tail" =~ $GATE_RE ]] || exit 1
  # NEXT-TERMINAL=none is admissible ONLY when BOTH operations proved
  # completion (no terminal record may be cited anywhere); a terminal
  # record form must never carry the none token.
  case "$tail" in
    *'NEXT-TERMINAL=none'*)
      case "$tail" in *'OP1-RESULT=completed;OP2-RESULT=completed'*) : ;; *) exit 1 ;; esac
      ;;
    *)
      case "$tail" in *'NEXT-TERMINAL=none'*) exit 1 ;; esac
      ;;
  esac
  exit 0
fi

if [ "${1:-}" = "--cx-gate" ]; then
  line="${2:-}"
  case "$line" in
    *"'"*|*$'\n'*|*';;'*|*';') exit 1 ;;
    R7-P21D-CX-VERDICT=DECISION=P21D-CX-PROVEN\;*) : ;;
    *) exit 1 ;;
  esac
  tail="${line#R7-P21D-CX-VERDICT=DECISION=P21D-CX-PROVEN;}"
  case "$tail" in *DECISION=*|*OVERLAP=absent*) exit 1 ;; esac
  [[ "$tail" =~ ^OVERLAP=measured\;FOREIGN-EXCLUDED=[1-9][0-9]*$ ]] || exit 1
  exit 0
fi

CX_MODE=0
DIR="${1:-}"
if [ "${1:-}" = "--cx" ]; then
  CX_MODE=1
  DIR="${2:-}"
fi
[ -n "$DIR" ] && [ -d "$DIR" ] || {
  if [ "$CX_MODE" = 1 ]; then
    printf 'R7-P21D-CX-VERDICT=DECISION=P21D-CX-BLOCKED;OVERLAP=absent;FOREIGN-EXCLUDED=0;REASON=no-evidence-dir\n'
  else
    printf 'R7-P21D-VERDICT=DECISION=P21D-BLOCKED;REASON=no-evidence-dir\n'
  fi
  exit 2
}

C1='system_u:system_r:docker_helper_buildkitd_t:s0:c1'
C2='system_u:system_r:docker_helper_buildkitd_t:s0:c2'
UN='unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023'
DEV='system_u:object_r:docker_helper_devnode_t:s0'
MEM='system_u:object_r:docker_helper_runc_memfd_t:s0'
UNRES='unconfined_u:object_r:user_tmp_t:s0'
TMP='system_u:object_r:tmpfs_t:s0'

if [ "$CX_MODE" = 1 ]; then
  CLASS_LOG="$DIR/p21d-cx-classification.log"
else
  CLASS_LOG="$DIR/p21d-classification.log"
fi
: > "$CLASS_LOG" 2>/dev/null || {
  if [ "$CX_MODE" = 1 ]; then
    printf 'R7-P21D-CX-VERDICT=DECISION=P21D-CX-BLOCKED;OVERLAP=absent;FOREIGN-EXCLUDED=0;REASON=classification-log-unwritable\n'
  else
    printf 'R7-P21D-VERDICT=DECISION=P21D-BLOCKED;REASON=classification-log-unwritable\n'
  fi
  exit 2
}

DECISION="P21D-MEASURED"
note() { # <severity> <detail> — FAIL beats BLOCKED beats MEASURED; the
  # decision token follows the mode (the cx classifier carries the
  # P21D-CX- tokens)
  printf '%s\t%s\n' "$1" "$2" >> "$CLASS_LOG"
  if [ "$CX_MODE" = 1 ]; then
    case "$1" in
      FAIL) DECISION="P21D-CX-FAIL" ;;
      BLOCKED) [ "$DECISION" = "P21D-CX-FAIL" ] || DECISION="P21D-CX-BLOCKED" ;;
    esac
    return 0
  fi
  case "$1" in
    FAIL) DECISION="P21D-FAIL" ;;
    BLOCKED) [ "$DECISION" = "P21D-FAIL" ] || DECISION="P21D-BLOCKED" ;;
  esac
}

require_file() { # <name>
  if [ ! -r "$DIR/$1" ] || [ ! -s "$DIR/$1" ]; then
    note BLOCKED "required evidence file missing or empty: $1"
    return 1
  fi
  return 0
}

# Positive-violation scans on the RAW captured bytes. These are valid
# regardless of capture soundness: a recorded violation in the drained
# bytes proves the policy allowed it, even when the capture cannot prove
# completeness. (The raw window is the bytes actually read through the
# pinned descriptor — the section cannot be more authoritative than it.)
raw_policy_scans() { # <opid> <raw> — the policy-level positive-violation
  # scans over a raw window: the regression controls and BOTH eliminated
  # devnode terminal shapes. Shared by the sequential acceptance path and
  # the concurrent (cx) classifier; the attribution scan below is the
  # sequential-only addition (in cx, records of the OTHER concurrently
  # running operation inside a proven window are the EXPECTED shape the
  # pid proof must exclude — never a policy violation).
  local opid="$1" raw="$2" hit
  hit="$(grep -a 'docker_helper_runc_memfd_t' "$raw" | grep -a 'tclass=file' | grep -a '{ create }' | head -1 || true)"
  if [ -n "$hit" ]; then
    note FAIL "REGRESSION-CONTROL-REAPPEARED op_$opid P20 terminal (raw window): $hit"
  fi
  hit="$(grep -a 'tcontext=system_u:object_r:tmpfs_t:s0 tclass=file' "$raw" | grep -a '{ write }' | head -1 || true)"
  if [ -n "$hit" ]; then
    note FAIL "REGRESSION-CONTROL-REAPPEARED op_$opid pre-B terminal (raw window): $hit"
  fi
  hit="$(grep -aF -e 'denied  { associate }' "$raw" | head -1 || true)"
  if [ -n "$hit" ]; then
    note FAIL "REGRESSION-CONTROL-REAPPEARED op_$opid associate (raw window): $hit"
  fi
  hit="$(grep -a 'tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file' "$raw" | grep -a 'denied  { read open }' | head -1 || true)"
  if [ -n "$hit" ]; then
    note FAIL "OPEN-COMPLETION-LIVE op_$opid (raw window): $hit"
  fi
  hit="$(grep -a 'tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file' "$raw" | grep -a 'denied  { mounton }' | head -1 || true)"
  if [ -n "$hit" ]; then
    note FAIL "MOUNTON-TERMINAL-LIVE op_$opid (raw window): the P21-C measured devnode mounton terminal reappeared: $hit"
  fi
  return 0
}

raw_positive_scans() { # <opid> <raw> — the sequential acceptance scans:
  # the policy-level scans PLUS the sequential attribution violation (a
  # record of ANOTHER operation inside this operation's raw window).
  local opid="$1" raw="$2" hit
  raw_policy_scans "$opid" "$raw"
  hit="$(grep -a 'comm="runc:\[2:INIT\]"' "$raw" | grep -aE 'ops/op_[0-9a-f]+/' | grep -av "ops/op_${opid}/" | head -1 || true)"
  if [ -n "$hit" ]; then
    note FAIL "ATTRIBUTION-VIOLATION op_$opid (raw window): a record of ANOTHER operation appears in this operation's raw window: $hit"
  fi
  return 0
}

  # The strict next-terminal matcher: a full-structure denied record
  # (permissive=0, buildkitd_t:s0:cX source, comm="runc:[2:INIT]"), NOT the
  # granted devnode { read open } shape, NOT the granted devnode { mounton }
  # shape, NOT the measured pre-boundary cap_userns self-denials. The
  # permission is observed, never pre-classified. Records on stdin; prints
  # the FIRST matching record.
  next_terminal_matcher() {
    awk '
      /avc:  denied  / &&
      /permissive=0/ &&
      /scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c[0-9]+ / &&
      /comm="runc:\[2:INIT\]"/ {
        if ($0 ~ /tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file / &&
            $0 ~ /denied  \{ read open \} /) next
        if ($0 ~ /tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file / &&
            $0 ~ /denied  \{ mounton \} /) next
        if ($0 ~ /tclass=cap_userns /) next
        print; exit
      }'
  }

  # verify_capture <opid> <tag> — the (a)/(a2) capture-integrity contract,
  # shared verbatim by the sequential acceptance path and the concurrent
  # (cx) classifier. Requires the section BODY. Emits the notes itself and
  # runs the policy-level raw scans on every unsound path; returns 0 only
  # when the capture is proven AND the raw artifact corroborates the
  # section. Sets CAP_BEFORE/CAP_AFTER/CAP_EXPECTED/CAP_ACTUAL/CAP_SOUND.
  verify_capture() { # <opid> <tag>
    local opid="$1" tag="$2" key total prov val badcap=0
    CAP_SOUND=0; CAP_BEFORE=""; CAP_AFTER=""; CAP_EXPECTED=""; CAP_ACTUAL=""
    local RAW="$DIR/avc-window-$tag.log"
    for key in identity-begin-pre identity-begin-post identity-extract-pre identity-extract-post; do
      total="$(printf '%s\n' "$BODY" | grep -Ecx -- "^$key=.+" || true)"
      prov="$(printf '%s\n' "$BODY" | grep -Ecx -- "^$key=proven" || true)"
      if [ "$total" -ne 1 ] || [ "$prov" -ne 1 ]; then
        note BLOCKED "terminals: op_$opid capture checkpoint '$key' is missing, duplicated, or not proven (records=$total proven=$prov)"
        badcap=1
      fi
    done
    for key in pre-drain window-drain; do
      total="$(printf '%s\n' "$BODY" | grep -Ecx -- "^$key=.+" || true)"
      prov="$(printf '%s\n' "$BODY" | grep -Ecx -- "^$key=ok" || true)"
      if [ "$total" -ne 1 ] || [ "$prov" -ne 1 ]; then
        note BLOCKED "terminals: op_$opid drain outcome '$key' is missing, duplicated, or not ok (records=$total ok=$prov)"
        badcap=1
      fi
    done
    for key in before after expected actual; do
      total="$(printf '%s\n' "$BODY" | grep -Ecx -- "^$key=[0-9]+\$" || true)"
      if [ "$total" -ne 1 ]; then
        note BLOCKED "terminals: op_$opid capture accounting key '$key' is missing, duplicated, or not a plain number (records=$total)"
        badcap=1
        continue
      fi
      val="$(printf '%s\n' "$BODY" | sed -n "s/^$key=//p" | head -1)"
      case "$key" in
        before) CAP_BEFORE="$val" ;;
        after) CAP_AFTER="$val" ;;
        expected) CAP_EXPECTED="$val" ;;
        actual) CAP_ACTUAL="$val" ;;
      esac
    done
    total="$(printf '%s\n' "$BODY" | grep -Ecx -- '^source=.+' || true)"
    prov="$(printf '%s\n' "$BODY" | grep -Ecx -- '^source=proven' || true)"
    if [ "$total" -ne 1 ] || [ "$prov" -ne 1 ]; then
      note BLOCKED "terminals: op_$opid capture source state is missing, duplicated, or not proven (records=$total proven=$prov)"
      badcap=1
    fi
    if [ "$badcap" = 1 ]; then
      # The capture is not proven — it can never measure. Positive
      # violations recorded in the raw captured bytes are still detected.
      [ -r "$RAW" ] && raw_positive_scans "$opid" "$RAW"
      return 1
    fi
    if [ "$CAP_EXPECTED" -ne $((CAP_AFTER - CAP_BEFORE)) ]; then
      note BLOCKED "terminals: op_$opid capture accounting inconsistent (expected=$CAP_EXPECTED, but after=$CAP_AFTER - before=$CAP_BEFORE)"
      badcap=1
    fi
    if [ "$CAP_ACTUAL" -ne "$CAP_EXPECTED" ]; then
      note BLOCKED "terminals: op_$opid captured line count does not match the boundary arithmetic (actual=$CAP_ACTUAL expected=$CAP_EXPECTED) — the extraction is not the measured window"
      badcap=1
    fi
    if [ "$CAP_ACTUAL" -eq 0 ]; then
      note BLOCKED "terminals: op_$opid window captured 0 records — absence of AVCs alone is never a passing outcome"
      badcap=1
    fi
    if [ "$badcap" = 1 ]; then
      [ -r "$RAW" ] && raw_positive_scans "$opid" "$RAW"
      return 1
    fi
    # (a2) the raw window artifact must independently corroborate the
    # section: EXACTLY the measured line count.
    if [ ! -r "$RAW" ]; then
      note BLOCKED "terminals: op_$opid raw window artifact avc-window-$tag.log is missing"
      return 1
    fi
    local RAW_LINES
    RAW_LINES="$(wc -l <"$RAW" 2>/dev/null || printf 0)"
    if [ "$RAW_LINES" -ne "$CAP_ACTUAL" ]; then
      note BLOCKED "terminals: op_$opid raw window artifact holds $RAW_LINES lines but the capture accounting claims actual=$CAP_ACTUAL"
      [ -s "$RAW" ] && raw_positive_scans "$opid" "$RAW"
      return 1
    fi
    printf 'WINDOW-OK\top_%s before=%s after=%s expected=%s actual=%s capture=proven\n' \
      "$opid" "$CAP_BEFORE" "$CAP_AFTER" "$CAP_EXPECTED" "$CAP_ACTUAL" >> "$CLASS_LOG"
    CAP_SOUND=1
    return 0
  }

  # The pid-proof sampler binding (r7-p21d-corrective-1). Reads a sampler
  # log and binds each operation id to its container-init pid from the
  # kernel-provided /proc facts ALONE:
  #   OWNER(op): sampled processes whose comm contains "runc" and whose
  #     cmdline/cwd/root carries THIS operation's ops/op_<id>/
  #     .../runc-native/executor/ bundle path (the runc CLI invocation of
  #     THIS operation);
  #   INIT(op): sampled comm="runc:[2:INIT]" processes whose ppid is an
  #     OWNER(op) process, or whose own cmdline/cwd/root carries the op's
  #     bundle path.
  # Ancestry (ppid) is a kernel fact, never a timing heuristic; the audit
  # windows are NOT an input to the binding. Sets S_VALID (ok | missing |
  # invalid:<detail>), S_INIT1/S_INIT2 (a single pid | none |
  # ambiguous:<pids>) and S_CONFLICTS (pids bound to BOTH operations).
  sampler_bindings() { # <sampler-file> <op1-id> <op2-id>
    local f="$1" out
    S_VALID=""; S_INIT1=""; S_INIT2=""; S_CONFLICTS=""
    if [ ! -r "$f" ]; then
      S_VALID="missing"
      return 0
    fi
    out="$(awk -v OP1="$2" -v OP2="$3" '
      BEGIN { FS = "\t" }
      $1 == "DONE" { done++; sw = $2; next }
      $1 == "SAMPLE" {
        if (NF != 8) { bad++; next }
        if ($2 !~ /^[0-9]+(\.[0-9]+)?$/) { bad++; next }
        if ($3 !~ /^[0-9]+$/ || $4 !~ /^-?[0-9]+$/) { bad++; next }
        if ($5 == "") { bad++; next }
        n++; L[n] = $0; next
      }
      { bad++ }
      END {
        if (bad > 0) { printf "INVALID\tunparseable-lines=%d\n", bad; exit }
        if (done != 1) { printf "INVALID\tdone-records=%d\n", done + 0; exit }
        if (sw !~ /^sweeps=[0-9]+$/) { print "INVALID\tdone-grammar"; exit }
        sub(/^sweeps=/, "", sw)
        if (sw + 0 < 1) { print "INVALID\tzero-sweeps"; exit }
        if (n < 1) { print "INVALID\tno-samples"; exit }
        m1 = "ops/op_" OP1 "/"
        m2 = "ops/op_" OP2 "/"
        for (i = 1; i <= n; i++) {
          split(L[i], f, "\t")
          if (f[5] ~ /runc/) {
            if (f[6] ~ m1 || f[7] ~ m1 || f[8] ~ m1) own1[f[3]] = 1
            if (f[6] ~ m2 || f[7] ~ m2 || f[8] ~ m2) own2[f[3]] = 1
          }
        }
        for (i = 1; i <= n; i++) {
          split(L[i], f, "\t")
          if (f[5] != "runc:[2:INIT]") continue
          if ((f[4] in own1) || f[6] ~ m1 || f[7] ~ m1 || f[8] ~ m1) i1[f[3]] = 1
          if ((f[4] in own2) || f[6] ~ m2 || f[7] ~ m2 || f[8] ~ m2) i2[f[3]] = 1
        }
        c1 = 0; s1 = ""
        for (p in i1) { c1++; s1 = s1 (c1 > 1 ? "," : "") p }
        c2 = 0; s2 = ""
        for (p in i2) { c2++; s2 = s2 (c2 > 1 ? "," : "") p }
        print "VALID"
        printf "BIND1\t%s\n", (c1 == 0 ? "none" : (c1 > 1 ? "ambiguous:" s1 : s1))
        printf "BIND2\t%s\n", (c2 == 0 ? "none" : (c2 > 1 ? "ambiguous:" s2 : s2))
        for (p in i1) if (p in i2) printf "CONFLICT\t%s\n", p
      }' "$f")"
    case "$out" in
      VALID*)
        S_VALID="ok"
        S_INIT1="$(printf '%s\n' "$out" | sed -n 's/^BIND1\t//p')"
        S_INIT2="$(printf '%s\n' "$out" | sed -n 's/^BIND2\t//p')"
        S_CONFLICTS="$(printf '%s\n' "$out" | sed -n 's/^CONFLICT\t//p' | sort -u | tr '\n' ' ')"
        ;;
      *) S_VALID="invalid:$(printf '%s\n' "$out" | head -1 | tr '\t' ' ')" ;;
    esac
    return 0
  }

  # pid_proof_check <opid> <pos> <window-pid> — the fail-closed decision
  # for WINDOW-SCOPED pathless attribution: the window's container-init
  # pid must be the sampler-proven init pid of THIS operation. A
  # contradiction is a positive violation (FAIL): the window claims
  # records the kernel ancestry assigns elsewhere. An unavailable proof
  # (sampler missing/invalid, no init bound, ambiguous binding) is
  # BLOCKED — window membership alone is never accepted as pid ownership.
  pid_proof_check() { # <opid> <pos> <window-pid>
    local opid="$1" pos="$2" wpid="$3" mine others
    if [ "$S_VALID" != "ok" ]; then
      note BLOCKED "terminals: op_$opid attributes pathless runc:[2:INIT] records to the proven window, but the pid-proof sampler evidence is $S_VALID"
      return 0
    fi
    if [ "$pos" = "1" ]; then mine="$S_INIT1"; others="$S_INIT2"; else mine="$S_INIT2"; others="$S_INIT1"; fi
    case "$mine" in
      none)
        note BLOCKED "terminals: op_$opid has NO container-init pid proven by the sampler (the /proc ancestry binding found no init for op_$opid) — window membership alone is never pid ownership"
        return 0
        ;;
      ambiguous:*)
        note BLOCKED "terminals: the sampler binds MULTIPLE container inits to op_$opid (${mine#ambiguous:}) — ambiguous evidence"
        return 0
        ;;
    esac
    if [ "$wpid" != "$mine" ]; then
      case ",$others," in
        *",$wpid,"*)
          note FAIL "PID-PROOF-CONTRADICTION op_$opid: the window's container-init pid $wpid is proven by the sampler to belong to the OTHER operation — the window-scoped attribution is affirmatively wrong"
          ;;
        *)
          note FAIL "PID-PROOF-CONTRADICTION op_$opid: the window's container-init pid $wpid is not the operation's sampler-proven init pid $mine"
          ;;
      esac
      return 0
    fi
    printf 'PID-PROOF\top_%s window container-init pid %s is the sampler-proven init (kernel ancestry: the runc parent whose /proc identity carries ops/op_%s/)\n' \
      "$opid" "$wpid" "$opid" >> "$CLASS_LOG"
    return 0
  }


# The exact section-header lines. Header recognition and the AWK section
# anchoring below share THESE EXACT strings, so header presence and section
# boundaries can never diverge: a prefixed/suffixed/corrupted header line
# matches neither the whole-line header counts NOR the AWK section anchors.
OP_HDR_RE='^== operation [a-z0-9]+ op_[0-9a-f]+ session dhs_[0-9a-f]+ ==$'
P20_HDR='-- P20 terminal (runc_memfd_t:file create) --'
PREB_HDR='-- pre-B terminal (tmpfs_t:file write) --'
ASSOC_HDR='-- associate denials (must be EMPTY — the singleton is granted) --'
OLDSHAPE_HDR='-- P21-B terminal (devnode_t:file { read open }; the ELIMINATED shape) --'
OLDMOUNTON_HDR='-- P21-C terminal (devnode_t:file mounton; the ELIMINATED shape) --'

# ---------------------------------------------------------------------------
# The CONCURRENT negative-scenario classifier (--cx, r7-p21d-corrective-1).
# Two operations are built CONCURRENTLY: a foreign pathless runc-init AVC
# lands inside a PROVEN window while the window's own operation completes
# with an error. Every runc:[2:INIT] record of each proven window is
# classified by its pid-proof binding — OWN (the operation's sampler-proven
# init pid), FOREIGN (the other operation's proven init pid — excluded WITH
# proof, never misattributed), UNPROVEN (BLOCKED). The record-based
# attribution of the sequential path is replaced by the per-pid binding:
# under concurrency the window can prove only WHERE bytes were drained,
# never WHOSE records they are.
# ---------------------------------------------------------------------------
if [ "$CX_MODE" = 1 ]; then
  DECISION="P21D-CX-PROVEN"
  OVERLAP="absent"
  FOREIGN_EXCLUDED=0
  CX1_AFTER=""
  CX2_BEFORE=""

  eval_cx_section() { # <hdr> <opid> <pos>
    local hdr="$1" opid="$2" pos="$3"
    local TAG="${hdr#== operation }"
    TAG="${TAG%% *}"
    local RAW="$DIR/avc-window-$TAG.log"
    BODY="$(awk -v hdr="$hdr" '
      $0 == hdr { sec = 1; next }
      /^== / { if (sec) exit }
      sec { print }
    ' "$DIR/p21d-cx-terminals.log")"
    [ -n "$BODY" ] || { note BLOCKED "cx: the section for op_$opid is empty"; return 1; }
    if ! verify_capture "$opid" "$TAG"; then
      return 1
    fi
    if [ "$pos" = "1" ]; then CX1_AFTER="$CAP_AFTER"; else CX2_BEFORE="$CAP_BEFORE"; fi
    # The premise: the window's own operation completed with an error.
    local OPRESULT
    OPRESULT="$(printf '%s\n' "$BODY" | awk -v hdr='-- operation result --' '
      $0 == hdr { sec = 1; next }
      /^-- / || /^== / { if (sec) exit }
      sec { print }')"
    if ! printf '%s' "$OPRESULT" | grep -q '"status": *"failed"'; then
      note BLOCKED "cx: op_$opid did not complete with an error — the negative scenario premise is not met: $OPRESULT"
    fi
    # The sampler-proven init pid of THIS operation and of the other one.
    local mine others
    if [ "$pos" = "1" ]; then mine="$S_INIT1"; others="$S_INIT2"; else mine="$S_INIT2"; others="$S_INIT1"; fi
    case "$mine" in
      none)
        note BLOCKED "cx: no container-init pid is proven to belong to op_$opid (sampler binding: none)"
        return 1
        ;;
      ambiguous:*)
        note BLOCKED "cx: the sampler binds MULTIPLE container inits to op_$opid (${mine#ambiguous:}) — ambiguous evidence"
        return 1
        ;;
    esac
    # Per-record pid classification of the raw window's runc-init records.
    local rec rpid ownn=0 foreignn=0 terminal=""
    while IFS= read -r rec; do
      [ -n "$rec" ] || continue
      rpid="$(printf '%s' "$rec" | grep -aoE 'pid=[0-9]+' | sed 's/pid=//' | head -1)"
      if [ "$rpid" = "$mine" ]; then
        ownn=$((ownn + 1))
        if printf '%s' "$rec" | grep -qaE "ops/op_[0-9a-f]+/" && ! printf '%s' "$rec" | grep -qa "ops/op_${opid}/"; then
          note FAIL "ATTRIBUTION-VIOLATION cx op_$opid: a record of THIS operation's own init pid carries ANOTHER operation's path: $rec"
        fi
        if [ -z "$terminal" ] && printf '%s\n' "$rec" | next_terminal_matcher | grep -qa .; then
          terminal="$rec"
        fi
      elif [ "$rpid" = "$others" ]; then
        foreignn=$((foreignn + 1))
      else
        note BLOCKED "cx: an UNPROVEN container-init pid ($rpid) inside op_$opid's proven window — the pid proof binds neither operation: $rec"
      fi
    done <<<"$(grep -a 'comm="runc:\[2:INIT\]"' "$RAW" || true)"
    if [ "$ownn" -eq 0 ]; then
      note BLOCKED "cx: op_$opid's own container init (pid $mine) has NO records in its proven window"
      return 1
    fi
    if [ -z "$terminal" ]; then
      note BLOCKED "cx: op_$opid has NO next-terminal record among its own pid's records — absence of AVCs alone is never a passing outcome"
    fi
    printf 'CX-OWN-RECORDS\top_%s init=%s own=%d foreign-excluded=%d\n' "$opid" "$mine" "$ownn" "$foreignn" >> "$CLASS_LOG"
    FOREIGN_EXCLUDED=$((FOREIGN_EXCLUDED + foreignn))
    raw_policy_scans "$opid" "$RAW"
    return 0
  }

  if require_file p21d-cx-terminals.log; then
    OP_HEADERS="$(grep -Ec "$OP_HDR_RE" "$DIR/p21d-cx-terminals.log" || true)"
    OP_HEADERS_LIST="$(grep -E "$OP_HDR_RE" "$DIR/p21d-cx-terminals.log" || true)"
    if [ "$OP_HEADERS" -lt 2 ]; then
      note BLOCKED "cx: two concurrent per-operation sections are required (found $OP_HEADERS)"
    elif [ "$OP_HEADERS" -gt 2 ]; then
      note FAIL "cx: more than two operation sections ($OP_HEADERS) — ambiguous evidence"
    else
      OP1_HDR="$(printf '%s\n' "$OP_HEADERS_LIST" | sed -n 1p)"
      OP2_HDR="$(printf '%s\n' "$OP_HEADERS_LIST" | sed -n 2p)"
      OP1_ID="$(printf '%s' "$OP1_HDR" | sed -n 's/^== operation [a-z0-9]* op_\([0-9a-f]*\) session .*/\1/p')"
      OP2_ID="$(printf '%s' "$OP2_HDR" | sed -n 's/^== operation [a-z0-9]* op_\([0-9a-f]*\) session .*/\1/p')"
      OP1_SESSION="$(printf '%s' "$OP1_HDR" | sed -n 's/^== operation [a-z0-9]* op_[0-9a-f]* session \(dhs_[0-9a-f]*\) ==$/\1/p')"
      OP2_SESSION="$(printf '%s' "$OP2_HDR" | sed -n 's/^== operation [a-z0-9]* op_[0-9a-f]* session \(dhs_[0-9a-f]*\) ==$/\1/p')"
      if [ -z "$OP1_ID" ] || [ -z "$OP2_ID" ] || [ -z "$OP1_SESSION" ] || [ -z "$OP2_SESSION" ]; then
        note BLOCKED "cx: operation header grammar carries no parseable operation/session identity"
      elif [ "$OP1_ID" = "$OP2_ID" ]; then
        note FAIL "cx: the SAME operation id in both concurrent windows: op_$OP1_ID"
      elif [ "$OP1_SESSION" = "$OP2_SESSION" ]; then
        note FAIL "cx: the SAME session id in both concurrent windows: $OP1_SESSION"
      else
        printf 'CX-OPS-DISTINCT\top_%s/%s and op_%s/%s\n' "$OP1_ID" "$OP1_SESSION" "$OP2_ID" "$OP2_SESSION" >> "$CLASS_LOG"
        S_VALID="missing"
        if require_file pid-sampler-cx.log; then
          sampler_bindings "$DIR/pid-sampler-cx.log" "$OP1_ID" "$OP2_ID"
          if [ "$S_VALID" != "ok" ]; then
            note BLOCKED "cx: the pid-proof sampler evidence is $S_VALID"
          elif [ -n "$S_CONFLICTS" ]; then
            note FAIL "PID-PROOF-CONFLICT: the sampler binds the SAME container-init pid to BOTH concurrent operations ($S_CONFLICTS)"
          else
            eval_cx_section "$OP1_HDR" "$OP1_ID" 1 || true
            eval_cx_section "$OP2_HDR" "$OP2_ID" 2 || true
          fi
        fi
      fi
    fi
    # The overlap IS the negative scenario: the second proven window must
    # begin strictly inside the first proven window's span — otherwise the
    # foreign record never entered a proven window and the demonstration
    # did not take place.
    if [ -n "$CX1_AFTER" ] && [ -n "$CX2_BEFORE" ] && [ "$CX2_BEFORE" -lt "$CX1_AFTER" ]; then
      OVERLAP="measured"
      printf 'CX-OVERLAP\tmeasured (second window begin=%s < first window end=%s)\n' "$CX2_BEFORE" "$CX1_AFTER" >> "$CLASS_LOG"
    elif [ "$DECISION" = "P21D-CX-PROVEN" ]; then
      note BLOCKED "cx: the proven windows do not overlap (first end=$CX1_AFTER, second begin=$CX2_BEFORE) — the foreign record never entered a proven window and the negative scenario was NOT realized"
    fi
    # The demonstration requires at least one foreign record actually
    # excluded WITH proof inside a proven window.
    if [ "$FOREIGN_EXCLUDED" -lt 1 ] && [ "$DECISION" = "P21D-CX-PROVEN" ]; then
      note BLOCKED "cx: NO foreign runc-init record was excluded inside a proven window — the negative scenario was NOT realized"
    fi
  fi

  if [ "$DECISION" = "P21D-CX-PROVEN" ]; then
    printf 'R7-P21D-CX-VERDICT=DECISION=P21D-CX-PROVEN;OVERLAP=%s;FOREIGN-EXCLUDED=%d\n' "$OVERLAP" "$FOREIGN_EXCLUDED"
    exit 0
  fi
  CX_REASON="$(grep -m1 -E $'^(FAIL|BLOCKED)\t' "$CLASS_LOG" 2>/dev/null | cut -f2- | tr ';:' '__' | tr -c '[:alnum:]_=._ -' '_' | sed 's/ *$//')"
  printf 'R7-P21D-CX-VERDICT=DECISION=%s;OVERLAP=%s;FOREIGN-EXCLUDED=%d;REASON=%s\n' \
    "$DECISION" "$OVERLAP" "$FOREIGN_EXCLUDED" "$CX_REASON"
  case "$DECISION" in
    P21D-CX-FAIL) exit 1 ;;
    *) exit 2 ;;
  esac
fi

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
    1) note FAIL "create-matrix: a required transition row is wrong, duplicated, unexpected, or unparseable (see p21d-classification.log)" ;;
    *) note BLOCKED "create-matrix: required transition rows are missing (see p21d-classification.log)" ;;
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
      split("create write append setattr execute execute_no_trans map mounton open read getattr unlink rename link ioctl lock", PERMS, " ")
      for (i = 1; i <= 16; i++) {
        expect["c1|" PERMS[i]] = (PERMS[i] == "create" || PERMS[i] == "read" || PERMS[i] == "open" || PERMS[i] == "mounton") ? "ALLOW" : "DENY"
        expect["c2|" PERMS[i]] = (PERMS[i] == "create" || PERMS[i] == "read" || PERMS[i] == "open" || PERMS[i] == "mounton") ? "ALLOW" : "DENY"
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
    1) note FAIL "av-matrix: a permission decision is wrong, duplicated, unexpected, or unparseable (see p21d-classification.log)" ;;
    *) note BLOCKED "av-matrix: required permission rows are missing (see p21d-classification.log)" ;;
  esac
fi

# ---------------------------------------------------------------------------
# 3. The two independent per-operation runtime windows.
# ---------------------------------------------------------------------------
TERM="$DIR/p21d-terminals.log"
NEXT_TERMINAL="(none)"
OP1_RESULT=""
OP2_RESULT=""
WINDOW_PID_1=""
WINDOW_PID_2=""


if require_file p21d-terminals.log; then
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
    # BODY is global: the shared verify_capture helper reads it.
    BODY="$(awk -v hdr="$hdr" '
      $0 == hdr { sec = 1; next }
      /^== / { if (sec) exit }
      sec { print }
    ' "$TERM")"
    [ -n "$BODY" ] || { note BLOCKED "terminals: the section for op_$opid is empty"; return; }

    # (a)/(a2) capture integrity — the shared verify_capture contract
    # (the pinned-source identity checkpoints, the MEASURED extraction
    # accounting, and the raw-artifact corroboration).
    local TAG="${hdr#== operation }"
    TAG="${TAG%% *}"
    local RAW="$DIR/avc-window-$TAG.log"
    verify_capture "$opid" "$TAG" || return
    local BEFORE="$CAP_BEFORE" AFTER="$CAP_AFTER"

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

    # The operation's own terminal state: succeeded changes how the
    # attribution contract treats pathless runc:[2:INIT] records (see the
    # UNATT/RAW_UNACCT checks below): under a PROVEN completion the proven
    # non-overlapping window IS the attribution for pathless records
    # (typically the pre-boundary cap_userns self-denials of a run that
    # finished), while any record carrying ANOTHER operation's path stays
    # a positive violation.
    local OPRESULT
    OPRESULT="$(printf '%s\n' "$BODY" | awk -v hdr='-- operation result --' '
      $0 == hdr { sec = 1; next }
      /^-- / || /^== / { if (sec) exit }
      sec { print }')"
    local OP_SUCCEEDED=0
    if printf '%s' "$OPRESULT" | grep -q '"status": *"succeeded"'; then
      OP_SUCCEEDED=1
    fi

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
    # Pathless runc:[2:INIT] records are attributed by the PROVEN window:
    # the window opened before THIS operation's POST and closed at THIS
    # operation's terminal, the windows are proven non-overlapping, and
    # the pid-singleton invariant below pins every runc:[2:INIT] record of
    # the window to ONE container init whose pid the OTHER window never
    # shares. A record carrying ANOTHER operation's path stays a positive
    # violation (the misattribution checks above and the raw scan).
    local RAW_RUNCPIDS WINDOW_PID
    RAW_RUNCPIDS="$(grep -a 'comm="runc:\[2:INIT\]"' "$RAW" | grep -aoE 'pid=[0-9]+' | sed 's/pid=//' | sort -u || true)"
    if [ "$(printf '%s\n' "$RAW_RUNCPIDS" | grep -c . || true)" -gt 1 ]; then
      note BLOCKED "terminals: op_$opid window carries runc:[2:INIT] records of MULTIPLE container inits (pid set: $(printf '%s ' $RAW_RUNCPIDS)) — ambiguous evidence"
      RAW_RUNCPIDS=""
    fi
    WINDOW_PID="$(printf '%s' "$RAW_RUNCPIDS" | head -1)"
    if [ "$pos" = "1" ]; then WINDOW_PID_1="$WINDOW_PID"; else WINDOW_PID_2="$WINDOW_PID"; fi
    if [ -n "$UNATT" ]; then
      local FOREIGN_UNATT
      FOREIGN_UNATT="$(printf '%s\n' "$UNATT" | grep -a 'ops/op_' || true)"
      if [ -n "$FOREIGN_UNATT" ]; then
        note BLOCKED "terminals: op_$opid unattributed section carries a PATH-carrying record (the classifier contract is broken): $FOREIGN_UNATT"
      elif [ -z "$WINDOW_PID" ]; then
        note BLOCKED "terminals: op_$opid carries pathless runc:[2:INIT] records but the window's container-init pid is ambiguous"
      else
        # Window-scoped attribution (r7-p21d-corrective-1): the proven
        # window alone is no longer accepted as the pid owner — the
        # sampler must independently bind the window's container-init pid
        # to THIS operation via /proc ancestry.
        pid_proof_check "$opid" "$pos" "$WINDOW_PID"
      fi
    fi

    # (c2) the section must be a faithful view of the raw captured bytes:
    # every cited record present verbatim, and every runc:[2:INIT] record
    # in the raw bytes accounted for by the classification (own path, a
    # misattributed FAIL, or a pid proven by an op-attributed record).
    local MISSING_RECS=""
    while IFS= read -r rec; do
      [ -n "$rec" ] || continue
      grep -aqF -- "$rec" "$RAW" || MISSING_RECS="$MISSING_RECS$rec"$'\n'
    done <<<"$(printf '%s\n' "$OPATT" "$PIDC")"
    if [ -n "$MISSING_RECS" ]; then
      note BLOCKED "terminals: op_$opid cites records that are NOT in its raw window artifact avc-window-$TAG.log (the section is not the captured bytes): $MISSING_RECS"
    fi
    local RAW_UNACCT="" rpid
    while IFS= read -r rec; do
      [ -n "$rec" ] || continue
      case "$rec" in *"ops/op_${opid}/"*) continue ;; esac
      if printf '%s' "$rec" | grep -qaE 'ops/op_[0-9a-f]+/'; then
        continue  # another operation's path — the raw misattribution scan
      fi
      # pathless: window-scoped under the pid-singleton invariant above
      rpid="$(printf '%s' "$rec" | grep -aoE 'pid=[0-9]+' | sed 's/pid=//' | head -1)"
      if [ -n "$rpid" ] && printf '%s\n' "$OWN_PIDS" | grep -qx "$rpid"; then
        continue
      fi
      RAW_UNACCT="$RAW_UNACCT$rec"$'\n'
    done <<<"$(grep -a 'comm="runc:\[2:INIT\]"' "$RAW" || true)"
    if [ -n "$RAW_UNACCT" ] && [ -z "$WINDOW_PID" ]; then
      note BLOCKED "terminals: op_$opid raw window carries runc:[2:INIT] records the section classification does not account for (ambiguous evidence — never assumed): $RAW_UNACCT"
    fi
    raw_positive_scans "$opid" "$RAW"

    # (d) BOTH eliminated devnode terminal shapes ({ read open } AND the
    # P21-C mounton): absent from this operation's attributed+correlated
    # runtime records.
    local OLD_HERE
    OLD_HERE="$(printf '%s\n' "$OPATT" "$PIDC" "$UNATT" | grep -a 'tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file' | grep -a 'denied  { read open }' | head -1)"
    if [ -n "$OLD_HERE" ]; then
      note FAIL "OPEN-COMPLETION-LIVE op_$opid: the P21-B measured devnode { read open } terminal reappeared in this operation's window: $OLD_HERE"
    fi
    OLD_HERE="$(printf '%s\n' "$OPATT" "$PIDC" "$UNATT" | grep -a 'tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file' | grep -a 'denied  { mounton }' | head -1)"
    if [ -n "$OLD_HERE" ]; then
      note FAIL "MOUNTON-TERMINAL-LIVE op_$opid: the P21-C measured devnode mounton terminal reappeared in this operation's window: $OLD_HERE"
    fi

    # (e) THIS operation's own next terminal: a full-structure denied
    # record attributed to it, NOT the granted shape, NOT the measured
    # pre-boundary cap_userns self-denials. The permission is observed,
    # never pre-classified; absence is BLOCKED (AVC absence alone is
    # never a passing outcome).
    local NEW_HERE
    NEW_HERE="$(printf '%s\n' "$OPATT" "$PIDC" "$UNATT" | next_terminal_matcher)"
    if [ -z "$NEW_HERE" ]; then
      # The P21-D alternative: the rung lets runc COMPLETE the device
      # binds, so the operation may run to its OWN terminal state with no
      # further denial at all. Proven completion of THIS operation is the
      # second form of runtime advancement (a failed operation with no
      # observed boundary still decides BLOCKED).
      if [ "$OP_SUCCEEDED" = 1 ]; then
        printf 'OP-COMPLETED-OK\top_%s %s\n' "$opid" "$OPRESULT" >> "$CLASS_LOG"
        if [ "$pos" = "1" ]; then OP1_RESULT="completed"; else OP2_RESULT="completed"; fi
      else
        note BLOCKED "terminals: op_$opid has NO attributed next-terminal record and NO proven operation completion (the flow must be observed advancing past the open-completion boundary IN THIS OPERATION — absence of AVCs alone is never a passing outcome)"
      fi
    else
      if printf '%s' "$NEW_HERE" | grep -qa 'ops/op_'; then
        printf 'OP-TERMINAL-OK\top_%s %s\n' "$opid" "$NEW_HERE" >> "$CLASS_LOG"
      else
        printf 'OP-TERMINAL-OK\top_%s (window-scoped attribution) %s\n' "$opid" "$NEW_HERE" >> "$CLASS_LOG"
      fi
      if [ "$pos" = "1" ]; then OP1_RESULT="terminal"; else OP2_RESULT="terminal"; fi
      if [ -z "$NEXT_TERMINAL" ] || [ "$NEXT_TERMINAL" = "(none)" ]; then
        NEXT_TERMINAL="$NEW_HERE"
      fi
      if [ "$pos" = "1" ]; then
        TERMINAL_1="$NEW_HERE"
      else
        TERMINAL_2="$NEW_HERE"
      fi
    fi

    # (f) the regression controls for THIS operation's whole window. Each
    # control section must exist EXACTLY once inside this section (a
    # missing header is damaged evidence — BLOCKED; a duplicated one is
    # ambiguous — FAIL) and be EMPTY.
    for sechdr in "$P20_HDR" "$PREB_HDR" "$ASSOC_HDR" "$OLDSHAPE_HDR" "$OLDMOUNTON_HDR"; do
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
  OP1_RESULT=""
  OP2_RESULT=""
  WINDOW_PID_1=""
  WINDOW_PID_2=""
  if [ "$OP_HEADERS" -eq 2 ] && [ -n "$OP1_ID" ] && [ -n "$OP2_ID" ] \
     && [ "$OP1_ID" != "$OP2_ID" ] && [ -n "$OP1_SESSION" ] && [ -n "$OP2_SESSION" ] \
     && [ "$OP1_SESSION" != "$OP2_SESSION" ]; then
    # The pid-proof sampler (r7-p21d-corrective-1): the /proc ancestry
    # binding of each operation id to its container-init pid. The evidence
    # contract requires the sampler artifact for EVERY live flow; a
    # missing or unparseable sampler is an evidence gap (BLOCKED), a
    # binding contradiction is a positive violation (FAIL).
    S_VALID="missing"
    if require_file pid-sampler.log; then
      sampler_bindings "$DIR/pid-sampler.log" "$OP1_ID" "$OP2_ID"
      if [ "$S_VALID" != "ok" ]; then
        note BLOCKED "terminals: the pid-proof sampler evidence is $S_VALID"
      fi
      if [ -n "$S_CONFLICTS" ]; then
        note FAIL "PID-PROOF-CONFLICT: the sampler binds the SAME container-init pid to BOTH operations ($S_CONFLICTS) — one container init can never serve two operations"
      fi
    fi
    eval_op_section "$OP1_HDR" "$OP1_ID" 1
    eval_op_section "$OP2_HDR" "$OP2_ID" 2
    # The two operations' terminal records must be DISTINCT records: one
    # AVC can never serve as the evidence for both operations.
    if [ -n "$TERMINAL_1" ] && [ -n "$TERMINAL_2" ] && [ "$TERMINAL_1" = "$TERMINAL_2" ]; then
      note FAIL "TERMINAL-NOT-DISTINCT: both operations cite the SAME AVC record as their next terminal (one window can never serve both operations)"
    fi
    # The two operations' container-init pids must be DISTINCT: one
    # runc:[2:INIT] process can never serve two operations.
    if [ -n "$WINDOW_PID_1" ] && [ -n "$WINDOW_PID_2" ] && [ "$WINDOW_PID_1" = "$WINDOW_PID_2" ]; then
      note FAIL "PID-NOT-DISTINCT: both windows carry runc:[2:INIT] records of the SAME container init (pid=$WINDOW_PID_1) — one container init can never serve two operations"
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
      # capture integrity for the inter-window capture: the same pinned-
      # source requirements as the operation windows.
      ikey=""; itotal=""; iprov=""
      for ikey in identity-gap-pre identity-gap-post; do
        itotal="$(printf '%s\n' "$INTER_BODY" | grep -Ecx -- "^$ikey=.+" || true)"
        iprov="$(printf '%s\n' "$INTER_BODY" | grep -Ecx -- "^$ikey=proven" || true)"
        if [ "$itotal" -ne 1 ] || [ "$iprov" -ne 1 ]; then
          note BLOCKED "terminals: the inter-window capture checkpoint '$ikey' is missing, duplicated, or not proven (records=$itotal proven=$iprov)"
        fi
      done
      itotal="$(printf '%s\n' "$INTER_BODY" | grep -Ecx -- '^inter-drain=.+' || true)"
      iprov="$(printf '%s\n' "$INTER_BODY" | grep -Ecx -- '^inter-drain=ok' || true)"
      if [ "$itotal" -ne 1 ] || [ "$iprov" -ne 1 ]; then
        note BLOCKED "terminals: the inter-window drain outcome is missing, duplicated, or not ok (records=$itotal ok=$iprov)"
      fi
      itotal="$(printf '%s\n' "$INTER_BODY" | grep -Ecx -- '^source=.+' || true)"
      iprov="$(printf '%s\n' "$INTER_BODY" | grep -Ecx -- '^source=proven' || true)"
      if [ "$itotal" -ne 1 ] || [ "$iprov" -ne 1 ]; then
        note BLOCKED "terminals: the inter-window capture source state is missing, duplicated, or not proven (records=$itotal proven=$iprov)"
      fi
      INTER_GAPA=""; INTER_GAPB=""; INTER_EXP=""; INTER_ACT=""
      for ikey in gap-after gap-before expected actual; do
        itotal="$(printf '%s\n' "$INTER_BODY" | grep -Ecx -- "^$ikey=[0-9]+\$" || true)"
        if [ "$itotal" -ne 1 ]; then
          note BLOCKED "terminals: the inter-window capture accounting key '$ikey' is missing, duplicated, or not a plain number (records=$itotal)"
          continue
        fi
        case "$ikey" in
          gap-after) INTER_GAPA="$(printf '%s\n' "$INTER_BODY" | sed -n 's/^gap-after=//p' | head -1)" ;;
          gap-before) INTER_GAPB="$(printf '%s\n' "$INTER_BODY" | sed -n 's/^gap-before=//p' | head -1)" ;;
          expected) INTER_EXP="$(printf '%s\n' "$INTER_BODY" | sed -n 's/^expected=//p' | head -1)" ;;
          actual) INTER_ACT="$(printf '%s\n' "$INTER_BODY" | sed -n 's/^actual=//p' | head -1)" ;;
        esac
      done
      if [ -z "$INTER_GAPA" ] || [ -z "$INTER_GAPB" ] || [ -z "$INTER_EXP" ] || [ -z "$INTER_ACT" ]; then
        note BLOCKED "terminals: the inter-window capture accounting is incomplete"
      elif [ "$INTER_EXP" -ne $((INTER_GAPB - INTER_GAPA)) ]; then
        note BLOCKED "terminals: the inter-window capture accounting is inconsistent (expected=$INTER_EXP, but gap-before=$INTER_GAPB - gap-after=$INTER_GAPA)"
      elif [ "$INTER_ACT" -ne "$INTER_EXP" ]; then
        note BLOCKED "terminals: the inter-window captured line count does not match the boundary arithmetic (actual=$INTER_ACT expected=$INTER_EXP) — the extraction is not the measured window"
      elif [ "$INTER_GAPB" -lt "$INTER_GAPA" ]; then
        note BLOCKED "terminals: the inter-window gap boundary is inconsistent (gap-after=$INTER_GAPA gap-before=$INTER_GAPB)"
      elif [ "$INTER_GAPB" -lt "$FIRST_WINDOW_END" ] 2>/dev/null; then
        note FAIL "WINDOW-OVERLAP: the inter-window region (gap-before=$INTER_GAPB) reaches into the first window (after=$FIRST_WINDOW_END)"
      elif [ "$INTER_GAPA" -gt "$FIRST_WINDOW_END" ] 2>/dev/null; then
        note BLOCKED "terminals: the inter-window region (gap-after=$INTER_GAPA) does not start at the first window's end ($FIRST_WINDOW_END) — records between them are unaccounted"
      elif [ -n "$SECOND_WINDOW_BEGIN" ] && [ "$INTER_GAPB" -ne "$SECOND_WINDOW_BEGIN" ]; then
        note BLOCKED "terminals: the inter-window region (gap-before=$INTER_GAPB) does not end at the second window's begin ($SECOND_WINDOW_BEGIN) — records between them are unaccounted"
      fi
      # The raw inter-window artifact must independently corroborate the
      # section: EXACTLY the measured line count.
      INTER_RAW="$DIR/inter-window.log"
      if [ ! -r "$INTER_RAW" ]; then
        note BLOCKED "terminals: the raw inter-window artifact inter-window.log is missing"
      else
        INTER_RAW_LINES=""
        INTER_RAW_LINES="$(wc -l <"$INTER_RAW" 2>/dev/null || printf 0)"
        if [ -n "$INTER_ACT" ] && [ "$INTER_RAW_LINES" -ne "$INTER_ACT" ]; then
          note BLOCKED "terminals: the raw inter-window artifact holds $INTER_RAW_LINES lines but the capture accounting claims actual=$INTER_ACT"
        fi
      fi
      INTER_RUNC="$(printf '%s\n' "$INTER_BODY" | awk -v hdr='-- records --' '
        $0 == hdr { sec = 1; next }
        sec && /comm="runc:\[2:INIT\]"/ && NF { print }')"
      if [ -n "$INTER_RUNC" ]; then
        note BLOCKED "terminals: runc:[2:INIT] records exist in the inter-window region where they are attributable to NEITHER operation (ambiguous evidence — never assumed): $INTER_RUNC"
      fi
      if [ -r "$INTER_RAW" ]; then
        INTER_RUNC="$(grep -a 'comm="runc:\[2:INIT\]"' "$INTER_RAW" | head -2 || true)"
        if [ -n "$INTER_RUNC" ]; then
          note BLOCKED "terminals: runc:[2:INIT] records exist in the raw inter-window artifact where they are attributable to NEITHER operation (ambiguous evidence — never assumed): $INTER_RUNC"
        fi
      fi
      for sechdr_shape in 'docker_helper_runc_memfd_t.*tclass=file.*\{ create \}' 'tcontext=system_u:object_r:tmpfs_t:s0 tclass=file.*\{ write \}' 'denied  \{ associate \}'; do
        INTER_CTRL="$(printf '%s\n' "$INTER_BODY" | grep -aE "$sechdr_shape" | head -2 || true)"
        if [ -n "$INTER_CTRL" ]; then
          note FAIL "REGRESSION-CONTROL-REAPPEARED inter-window: $INTER_CTRL"
        fi
        if [ -r "$INTER_RAW" ]; then
          INTER_CTRL="$(grep -aE "$sechdr_shape" "$INTER_RAW" | head -2 || true)"
          if [ -n "$INTER_CTRL" ]; then
            note FAIL "REGRESSION-CONTROL-REAPPEARED inter-window (raw): $INTER_CTRL"
          fi
        fi
      done
      INTER_OLD="$(printf '%s\n' "$INTER_BODY" | grep -a 'tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file' | grep -a 'denied  { read open }' | head -1 || true)"
      if [ -n "$INTER_OLD" ]; then
        note FAIL "OPEN-COMPLETION-LIVE: the eliminated devnode { read open } shape appears in the inter-window region: $INTER_OLD"
      fi
      INTER_OLD="$(printf '%s\n' "$INTER_BODY" | grep -a 'tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file' | grep -a 'denied  { mounton }' | head -1 || true)"
      if [ -n "$INTER_OLD" ]; then
        note FAIL "MOUNTON-TERMINAL-LIVE: the eliminated devnode mounton shape appears in the inter-window region: $INTER_OLD"
      fi
      if [ -r "$INTER_RAW" ]; then
        INTER_OLD="$(grep -a 'tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file' "$INTER_RAW" | grep -a 'denied  { read open }' | head -1 || true)"
        if [ -n "$INTER_OLD" ]; then
          note FAIL "OPEN-COMPLETION-LIVE: the eliminated devnode { read open } shape appears in the raw inter-window artifact: $INTER_OLD"
        fi
        INTER_OLD="$(grep -a 'tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file' "$INTER_RAW" | grep -a 'denied  { mounton }' | head -1 || true)"
        if [ -n "$INTER_OLD" ]; then
          note FAIL "MOUNTON-TERMINAL-LIVE: the eliminated devnode mounton shape appears in the raw inter-window artifact: $INTER_OLD"
        fi
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Fields for the verdict line (summaries of the classification above).
# ---------------------------------------------------------------------------
SCOPE="six-names-ok"
[ "$DECISION" = "P21D-MEASURED" ] || SCOPE="not-established"
# OPEN-COMPLETION summarizes the former terminal's state: live (its exact
# shape reappeared in ANY operation's window — a positive violation),
# eliminated (BOTH independently attributed windows were checked and the
# shape is absent), not-established (the windows were missing, ambiguous,
# or never fully evaluated).
if grep -q 'OPEN-COMPLETION-LIVE' "$CLASS_LOG" 2>/dev/null \
  || grep -q 'MOUNTON-TERMINAL-LIVE' "$CLASS_LOG" 2>/dev/null \
  || grep -q 'REGRESSION-CONTROL-REAPPEARED op_[0-9a-f]* P21-B terminal' "$CLASS_LOG" 2>/dev/null \
  || grep -q 'REGRESSION-CONTROL-REAPPEARED op_[0-9a-f]* P21-C terminal' "$CLASS_LOG" 2>/dev/null; then
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

NEXT_TERMINAL_OUT="<$NEXT_TERMINAL>"
if [ "$NEXT_TERMINAL" = "(none)" ] && [ "$OP1_RESULT" = "completed" ] && [ "$OP2_RESULT" = "completed" ]; then
  NEXT_TERMINAL_OUT="none"
fi
printf 'R7-P21D-VERDICT=DECISION=%s;SCOPE=%s;OPEN-COMPLETION=%s;MEMFD=%s;CROSSOP-CONTENT=%s;NEXT-TERMINAL=%s;OP1-RESULT=%s;OP2-RESULT=%s\n' \
  "$DECISION" "$SCOPE" "$OPEN_COMPLETION" "$MEMFD" "$CROSSOP" "$NEXT_TERMINAL_OUT" "$OP1_RESULT" "$OP2_RESULT"

case "$DECISION" in
  P21D-MEASURED) exit 0 ;;
  P21D-FAIL) exit 1 ;;
  *) exit 2 ;;
esac
