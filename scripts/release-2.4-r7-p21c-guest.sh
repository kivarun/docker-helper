#!/usr/bin/env bash
#
# release-2.4-r7-p21c-guest.sh — the R7 P21-C devnode open-completion rung
# verification on a disposable ENFORCING openSUSE Tumbleweed VM (candidate
# RPM built at the P21-C SHA; the policy IS the candidate — no diagnostic
# module is loaded anywhere).
#
# MODE: acceptance evidence for the ONE sanctioned P21-C rung. NO production
# change, NO diagnostic grant, NO merge/RC/tag. The candidate policy carries
# the P21-B devnode shape PLUS exactly one new rule:
#
#   type docker_helper_devnode_t;                                   (bare)
#   type_transition docker_helper_buildkitd_t tmpfs_t:file
#         docker_helper_devnode_t "null"|"zero"|"full"|"random"|
#         "urandom"|"tty";                                          (six)
#   allow docker_helper_buildkitd_t docker_helper_devnode_t:file create;
#   allow docker_helper_buildkitd_t docker_helper_devnode_t:file
#         { read open };                          (the P21-C rung — ONE rule)
#   allow docker_helper_devnode_t tmpfs_t:filesystem associate;
#
# and NOTHING else changed relative to the P21-B policy (the bare memfd
# transition and the six P1-P6 runc_memfd allows are untouched).
#
# THE QUESTIONS (P21-C acceptance):
#   1. Authority delta: the compiled/loaded devnode_t surface is EXACTLY the
#      three reviewed rules (create toward it, the { read open }
#      open-completion pair toward it, associate from it); the pair is the
#      open-completion check's own shape (P4 memfd precedent), NOT a
#      content authority — every write-class permission stays denied for
#      EVERY subject, so every object of the type stays a zero-length
#      content-dead placeholder.
#   2. Cross-operation: the created placeholders carry NO categories
#      (measured s0), so MCS never separated them; the file-read
#      constraint admits read/open for BOTH operation categories; the
#      shared tmpfs venue (e.g. /dev/shm) is NOT the isolation relied on —
#      the channel is closed at the POLICY level because no subject can
#      write content into the type (the open-completion check maps
#      FMODE_WRITE -> FILE__WRITE, so even a writable creation openat
#      fails; setattr/truncate and PROT_WRITE mmap need ungranted
#      authority). A cross-operation reader reads an EMPTY object:
#      name-presence only, the surface the P21-B create rung already
#      carried. The guest records the constraint text, the venue
#      inventory, and the kernel-AV write-class rows (c1/c2/unconfined
#      DENY) as the evidence; a live in-domain probe attempt is recorded
#      with its expected BLOCKED outcome.
#   3. Former terminal eliminated: the P21-B measured terminal
#      (denied { read open }, comm="runc:[2:INIT]", tcontext=
#      docker_helper_devnode_t:s0, permissive=0, per-op
#      .../rootfs/dev/null path) must be ABSENT from both live windows.
#   4. Runtime advanced: the flow reaches the same runc:[2:INIT] stage and
#      stops at a NEW kernel boundary — at least one further full-structure
#      denied AVC record (permissive=0, scontext=buildkitd_t:s0:cX,
#      comm="runc:[2:INIT]") that is NOT the granted devnode { read open }
#      shape. The exact next terminal is OBSERVED, never pre-granted: the
#      evaluator accepts any real new-flow record and the REPORT names it.
#      Absence of AVCs alone is NEVER a passing outcome (BLOCKED).
#   5. Capture integrity (r7-p21c-corrective-2): every window is read
#      through ONE pinned read descriptor opened once on the audit source,
#      so a rename/replacement/rotation of the path can never alter what a
#      drain sees. Identity checkpoints (path dev:ino == pinned dev:ino,
#      pinned size never below the consumed cursor) wrap every drain;
#      torn trailing records and read errors fail the capture. The
#      evidence stores before/after/expected/actual measured independently
#      (cursor arithmetic vs the extracted file's own line count) plus the
#      identity state; an unproven capture is capture=unavailable and the
#      evaluator decides BLOCKED — never a partial MEASURED.
#   6. Regression controls: the P20 runc_memfd_t:file create terminal, the
#      pre-B' tmpfs_t:file write terminal, and the associate denial stay
#      absent from both windows; the six filename transitions, the
#      arbitrary-basename control, and the memfd P1-P6 surface stay
#      byte-intact on the loaded policy.
#   5. Regression controls: the P20 runc_memfd_t:file create terminal, the
#      pre-B' tmpfs_t:file write terminal, and the associate denial stay
#      absent from both windows; the six filename transitions, the
#      arbitrary-basename control, and the memfd P1-P6 surface stay
#      byte-intact on the loaded policy.
#
# Machine verdict contract (the evaluator is scripts/
# release-2.4-r7-p21c-verdict.sh — fail-closed, row-by-row; the P21-B
# evaluator remains untouched as the historical P21-B instrument):
#   R7-P21C-VERDICT=DECISION=P21C-MEASURED|P21C-FAIL|P21C-BLOCKED;\
#     SCOPE=<six-names-ok|not-established>;\
#     OPEN-COMPLETION=<eliminated|live|not-established>;\
#     MEMFD=<intact|regressed>;CROSSOP-CONTENT=<closed|open>;\
#     NEXT-TERMINAL=<...>

set -uo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log()  { printf '[r7-p21c] %s\n' "$*"; }
fail() { printf '[r7-p21c] FAILED: %s\n' "$*" >&2; exit 1; }

# The audit source path is parameterized ONLY for the capture selftest
# (--capture-selftest exercises the real capture functions against
# synthetic sources under a scratch workdir); the VM flow always uses the
# real audit log.
AUDIT_LOG_PATH="${R7_P21C_AUDIT_LOG_PATH:-/var/log/audit/audit.log}"

SELFTEST_WORKDIR=""
if [ "${1:-}" = "--capture-selftest" ]; then
  SELFTEST_WORKDIR="${2:-}"
  [ -n "$SELFTEST_WORKDIR" ] || fail "usage: $0 --capture-selftest <workdir>"
  EVIDENCE_DIR="$SELFTEST_WORKDIR/evidence-scratch"
  STATE_DIR="$SELFTEST_WORKDIR/state-scratch"
else
  ARTIFACT="${R7_ARTIFACT:?R7_ARTIFACT required}"
  ARTIFACT_SHA="${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"
  EVIDENCE_DIR="${R7_EVIDENCE_DIR:-/tmp/r7-p21c-evidence}"
  STATE_DIR=/tmp/r7-p21c-state
fi
mkdir -p "$EVIDENCE_DIR" "$STATE_DIR"
DH_SOCK=/run/docker-helper/docker-helper.sock

cap() { # <name> <max-lines> <cmd...>
  local name="$1" maxn="$2" rc; shift 2
  "$@" >"$EVIDENCE_DIR/$name.log" 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || printf 'capture rc=%d\n' "$rc" >>"$EVIDENCE_DIR/$name.log"
  log "--- $name (evidence: $EVIDENCE_DIR/$name.log, first $maxn lines) ---"
  head -n "$maxn" "$EVIDENCE_DIR/$name.log"
  return 0
}

avc_tail() { # <label>
  : > "$EVIDENCE_DIR/$1.log"
  if command -v ausearch >/dev/null 2>&1 && pgrep -x auditd >/dev/null 2>&1; then
    ausearch -m AVC -m USER_AVC --start recent 2>/dev/null >> "$EVIDENCE_DIR/$1.log" || true
  fi
  if [ -f /var/log/audit/audit.log ]; then
    tail -n 800 /var/log/audit/audit.log >> "$EVIDENCE_DIR/$1.log" 2>/dev/null || true
  fi
  {
    command -v auditctl >/dev/null 2>&1 && auditctl -s 2>&1 | head -3
    wc -l /var/log/audit/audit.log 2>/dev/null || echo "audit.log: absent"
  } > "$EVIDENCE_DIR/$1-audit-state.log" 2>&1 || true
  if [ ! -s "$EVIDENCE_DIR/$1.log" ]; then
    printf '(no AVC records captured)\n' > "$EVIDENCE_DIR/$1.log"
  fi
  log "avc capture [$1]: $(wc -l < "$EVIDENCE_DIR/$1.log") lines"
}

# ============================================================================
# Audit capture core (r7-p21c-corrective-2). IDENTITY MODEL:
#   1. ONE pinned O_RDONLY descriptor is opened ONCE on the audit source;
#      every window byte is read THROUGH this descriptor, so a rename,
#      replacement, or rotation of the path can never alter what a drain
#      reads (the descriptor is bound to the inode, not the name).
#   2. At every capture checkpoint (immediately before and after every
#      drain) the PATH's st_dev:st_ino must equal the PINNED descriptor's
#      st_dev:st_ino — a replacement/rotation between checkpoints fails
#      the capture. During the pinned interval an st_dev:st_ino match
#      means the path IS the pinned inode (a replacement cannot reuse the
#      inode while this descriptor holds it open), so the check detects
#      replacement; it is NOT the content authority — the pinned stream is.
#   3. The pinned inode's size must never be smaller than the bytes already
#      consumed through the descriptor — truncate is detected. Normal
#      append-only growth stays valid (no size-equality requirement).
#   4. Every drained region must be newline-terminated — a torn trailing
#      record (a record split across a drain boundary) fails the capture.
#   5. A read error through the descriptor fails the capture.
#   DOCUMENTED LIMITATION: a same-inode in-place rewrite that never lets
#   the file size drop below the consumed cursor (truncate-to-0 is caught
#   by (3)) is outside this model — the pinned content stream is the
#   authority and such a rewrite requires direct write access to the audit
#   source itself, outside the diagnostic threat model. Under this model an
#   undetected anomaly can only ever REMOVE records from a window (a
#   false-negative capture the evaluator decides BLOCKED on), never
#   fabricate records into one.
# ============================================================================
AUD_FD=""
AUD_LINES=0   # complete records consumed through the pinned descriptor
AUD_BYTES=0   # bytes consumed through the pinned descriptor
AUD_BROKEN="" # set once source continuity can no longer be proven

audit_close() {
  [ -n "$AUD_FD" ] || return 0
  eval "exec ${AUD_FD}<&-" 2>/dev/null || true
  AUD_FD=""
}

audit_open() {
  audit_close
  AUD_LINES=0
  AUD_BYTES=0
  AUD_BROKEN=""
  exec {AUD_FD}<"$AUDIT_LOG_PATH" 2>/dev/null || { AUD_FD=""; return 1; }
  return 0
}

audit_identity() { # prints proven, or unproven:<reason> (rc 1 when unproven)
  local pin path size
  if [ -z "$AUD_FD" ]; then
    printf 'unproven:no-pinned-descriptor'
    return 1
  fi
  if [ -n "$AUD_BROKEN" ]; then
    printf 'unproven:session-broken(%s)' "$AUD_BROKEN"
    return 1
  fi
  pin="$(stat -Lc '%d:%i' "/proc/self/fd/$AUD_FD" 2>/dev/null)" || {
    printf 'unproven:descriptor-stat-error'
    return 1
  }
  path="$(stat -c '%d:%i' "$AUDIT_LOG_PATH" 2>/dev/null)" || {
    printf 'unproven:path-stat-error'
    return 1
  }
  if [ "$pin" != "$path" ]; then
    printf 'unproven:path-replaced(pinned=%s,path=%s)' "$pin" "$path"
    return 1
  fi
  size="$(stat -Lc '%s' "/proc/self/fd/$AUD_FD" 2>/dev/null)" || {
    printf 'unproven:descriptor-size-error'
    return 1
  }
  if [ "$size" -lt "$AUD_BYTES" ]; then
    printf 'unproven:truncated(size=%s,consumed=%s)' "$size" "$AUD_BYTES"
    return 1
  fi
  printf 'proven'
}

audit_drain() { # <outfile> — appends EXACTLY the bytes appended to the
  # pinned source since the previous drain; rc 0 iff the drain is sound
  local out="$1" tmp lines bytes tailnl
  if [ -z "$AUD_FD" ] || [ -n "$AUD_BROKEN" ]; then
    AUD_BROKEN="${AUD_BROKEN:-drain-after-broken}"
    return 1
  fi
  tmp="$(mktemp "$STATE_DIR/drain.XXXXXX")" || { AUD_BROKEN="drain-temp-error"; return 1; }
  if ! cat <&"$AUD_FD" >"$tmp" 2>/dev/null; then
    rm -f "$tmp"
    AUD_BROKEN="read-error"
    return 1
  fi
  if [ -s "$tmp" ]; then
    tailnl="$(tail -c 1 "$tmp" | wc -l)"
    if [ "$tailnl" -eq 0 ]; then
      rm -f "$tmp"
      AUD_BROKEN="partial-record"
      return 1
    fi
  fi
  lines="$(wc -l <"$tmp")"
  bytes="$(wc -c <"$tmp")"
  if ! cat "$tmp" >>"$out" 2>/dev/null; then
    rm -f "$tmp"
    AUD_BROKEN="drain-output-error"
    return 1
  fi
  rm -f "$tmp"
  AUD_LINES=$((AUD_LINES + lines))
  AUD_BYTES=$((AUD_BYTES + bytes))
  return 0
}

# capture_begin <tag> [inter] — the pre-build identity checks and drain.
# The records consumed here precede THIS build and are excluded from its
# window. For the SECOND operation (mode=inter) the same drain IS the
# inter-window evidence: those records are attributable to NEITHER
# operation, and they get their own full integrity accounting.
capture_begin() { # <tag> [inter]
  local tag="$1" mode="${2:-}"
  local BOUND="$EVIDENCE_DIR/window-boundaries-$tag.log"
  local out="$EVIDENCE_DIR/pre-drain-$tag.log"
  local i1 i2 drainstat ok=1 gap_after
  : > "$BOUND"
  i1="$(audit_identity)"
  [ "$i1" = "proven" ] || ok=0
  printf 'identity-begin-pre=%s\n' "$i1" >>"$BOUND"
  if [ "$mode" = "inter" ]; then
    out="$EVIDENCE_DIR/inter-window.log"
    : > "$out"
    gap_after="$AUD_LINES"
  fi
  if audit_drain "$out"; then
    drainstat="ok"
  else
    drainstat="failed:$AUD_BROKEN"
    ok=0
  fi
  printf 'pre-drain=%s\n' "$drainstat" >>"$BOUND"
  i2="$(audit_identity)"
  [ "$i2" = "proven" ] || ok=0
  printf 'identity-begin-post=%s\n' "$i2" >>"$BOUND"
  printf 'before=%s\n' "$AUD_LINES" >>"$BOUND"
  if [ "$mode" = "inter" ]; then
    local gap_before="$AUD_LINES" gexp=0 gact=0 gsrc="unproven"
    if [ -n "$gap_after" ]; then
      gexp=$((gap_before - gap_after))
    fi
    gact="$(wc -l <"$out" 2>/dev/null || printf 0)"
    if [ "$ok" = 1 ] && [ -n "$gap_after" ]; then
      gsrc="proven"
    fi
    {
      printf 'identity-gap-pre=%s\n' "$i1"
      printf 'identity-gap-post=%s\n' "$i2"
      printf 'inter-drain=%s\n' "$drainstat"
      printf 'gap-after=%s\n' "$gap_after"
      printf 'gap-before=%s\n' "$gap_before"
      printf 'expected=%s\n' "$gexp"
      printf 'actual=%s\n' "$gact"
      printf 'source=%s\n' "$gsrc"
    } >"$EVIDENCE_DIR/inter-boundaries.log"
  fi
  return 0
}

# capture_end <tag> — the post-operation identity check, the window drain
# through the pinned descriptor (THE extraction), the post-extract identity
# check, and the MEASURED accounting: expected is the cursor arithmetic,
# actual is the extracted file's own line count, and source is proven only
# when every identity checkpoint and both drains were sound.
capture_end() { # <tag>
  local tag="$1"
  local BOUND="$EVIDENCE_DIR/window-boundaries-$tag.log"
  local WIN="$EVIDENCE_DIR/avc-window-$tag.log"
  local i1 i2 drainstat ok=1
  local BEFORE AFTER EXPECTED=0 ACTUAL=0 SOURCE="unproven"
  : > "$WIN"
  i1="$(audit_identity)"
  [ "$i1" = "proven" ] || ok=0
  printf 'identity-extract-pre=%s\n' "$i1" >>"$BOUND"
  if audit_drain "$WIN"; then
    drainstat="ok"
  else
    drainstat="failed:$AUD_BROKEN"
    ok=0
  fi
  printf 'window-drain=%s\n' "$drainstat" >>"$BOUND"
  i2="$(audit_identity)"
  [ "$i2" = "proven" ] || ok=0
  printf 'identity-extract-post=%s\n' "$i2" >>"$BOUND"
  BEFORE="$(sed -n 's/^before=//p' "$BOUND" | head -1)"
  AFTER="$AUD_LINES"
  printf 'after=%s\n' "$AFTER" >>"$BOUND"
  if [ -n "$BEFORE" ]; then
    EXPECTED=$((AFTER - BEFORE))
  fi
  ACTUAL="$(wc -l <"$WIN" 2>/dev/null || printf 0)"
  if [ "$ok" = 1 ] && [ -n "$BEFORE" ]; then
    SOURCE="proven"
  fi
  printf 'expected=%s\n' "$EXPECTED" >>"$BOUND"
  printf 'actual=%s\n' "$ACTUAL" >>"$BOUND"
  printf 'source=%s\n' "$SOURCE" >>"$BOUND"
  return 0
}

# ============================================================================
# Capture selftest (--capture-selftest <workdir>): exercises the REAL
# capture functions (audit_open/audit_identity/audit_drain/capture_begin/
# capture_end — the exact production path) against synthetic audit sources
# under the workdir, and records each scenario's measured accounting under
# <workdir>/results/ for the Go tests to assert. NO assertions here: the
# outcomes are the evidence; the Go tests are the judge. Scenario 9 of the
# review battery (actual != expected) is evaluator-side by construction:
# the producer measures both values from the same drained bytes, so a
# mismatch can only exist as fabricated evidence — covered by the
# evaluator tests.
# ============================================================================
SELFTEST_COUNTER=0

selftest_scrub() { # <scenario>
  audit_close
  AUD_LINES=0
  AUD_BYTES=0
  AUD_BROKEN=""
  EVIDENCE_DIR="$SELFTEST_WORKDIR/evidence-$1"
  STATE_DIR="$SELFTEST_WORKDIR/state-$1"
  mkdir -p "$EVIDENCE_DIR" "$STATE_DIR"
}

selftest_emit() { # <file> <count> — append <count> synthetic audit records
  local i=1
  while [ "$i" -le "$2" ]; do
    SELFTEST_COUNTER=$((SELFTEST_COUNTER + 1))
    printf 'type=SYNTH msg=audit(1000000.000:%d): synthetic record %d\n' \
      "$SELFTEST_COUNTER" "$SELFTEST_COUNTER" >>"$1"
    i=$((i + 1))
  done
}

selftest_keep() { # <scenario> <src> <kind>
  cp "$2" "$SELFTEST_WORKDIR/results/$1.$3" 2>/dev/null || true
}

p21c_capture_selftest() { # <workdir>
  local work="$1" logf other replacement_count replacement_path i1 i2 dstat
  mkdir -p "$work/results"

  # 1. append-only green: 3 pre-existing records, the "build" appends 5,
  #    the window is EXACTLY those 5, proven.
  logf="$work/audit-s1.log"
  : > "$logf"
  selftest_emit "$logf" 3
  AUDIT_LOG_PATH="$logf"
  selftest_scrub s1
  audit_open || printf 'open-failed\n' >"$work/results/append-only-green.open"
  capture_begin s1
  selftest_emit "$logf" 5
  capture_end s1
  selftest_keep append-only-green "$EVIDENCE_DIR/window-boundaries-s1.log" boundaries

  # 1b. inter-window green: the SAME pinned flow continues; the next
  #     pre-build drain IS the inter-window capture (4 records appended).
  selftest_emit "$logf" 4
  capture_begin s1b inter
  selftest_keep inter-window-green "$EVIDENCE_DIR/inter-boundaries.log" inter

  # 2. torn record: the build's last record was never completed (no
  #    trailing newline) — the drain must fail the capture.
  logf="$work/audit-s2.log"
  : > "$logf"
  selftest_emit "$logf" 2
  AUDIT_LOG_PATH="$logf"
  selftest_scrub s2
  audit_open || true
  capture_begin s2
  selftest_emit "$logf" 4
  printf 'type=SYNTH msg=audit(1000000.999:999): torn record no newline' >>"$logf"
  capture_end s2
  selftest_keep torn-record "$EVIDENCE_DIR/window-boundaries-s2.log" boundaries

  # 3. read error: the source cannot be read through the descriptor.
  AUDIT_LOG_PATH="$work/audit-s3.dir"
  mkdir -p "$AUDIT_LOG_PATH"
  selftest_scrub s3
  audit_open || true
  capture_begin s3
  capture_end s3
  selftest_keep read-error "$EVIDENCE_DIR/window-boundaries-s3.log" boundaries

  # 4. truncate WITHOUT an inode change: the pinned source shrinks below
  #    the consumed cursor and is rewritten.
  logf="$work/audit-s4.log"
  : > "$logf"
  selftest_emit "$logf" 3
  AUDIT_LOG_PATH="$logf"
  selftest_scrub s4
  audit_open || true
  capture_begin s4
  selftest_emit "$logf" 5
  truncate -s 0 "$logf"
  selftest_emit "$logf" 1
  capture_end s4
  selftest_keep truncate-same-inode "$EVIDENCE_DIR/window-boundaries-s4.log" boundaries

  # 5/6/7. rename/replacement with FEWER / SAME / MORE lines than the
  #        original source carried: the inode mismatch must decide, never
  #        the line count. The replacement fixtures are verified BEFORE
  #        the replacement (record count + newline termination) and the
  #        counts are recorded for the Go tests.
  for scenario in replace-fewer replace-same replace-more; do
    case "$scenario" in
      replace-fewer) replacement_count=1 ;;
      replace-same) replacement_count=8 ;;
      replace-more) replacement_count=12 ;;
    esac
    logf="$work/audit-$scenario.log"
    : > "$logf"
    selftest_emit "$logf" 3
    replacement_path="$work/other-$scenario.log"
    : > "$replacement_path"
    selftest_emit "$replacement_path" "$replacement_count"
    {
      printf 'replacement-records=%s\n' "$(wc -l <"$replacement_path")"
      if [ -s "$replacement_path" ] \
        && [ "$(tail -c 1 "$replacement_path" | wc -l)" -ge 1 ]; then
        printf 'replacement-newline-terminated=yes\n'
      else
        printf 'replacement-newline-terminated=no\n'
      fi
    } >"$work/results/$scenario.fixture"
    AUDIT_LOG_PATH="$logf"
    selftest_scrub "$scenario"
    audit_open || true
    capture_begin "$scenario"
    selftest_emit "$logf" 5
    mv "$replacement_path" "$logf"
    capture_end "$scenario"
    selftest_keep "$scenario" "$EVIDENCE_DIR/window-boundaries-$scenario.log" boundaries
  done

  # 8. replacement DURING the extraction: capture_end's exact internal
  #    order (identity check, window drain, identity check), driven
  #    stepwise with the replacement injected between the checkpoints.
  logf="$work/audit-replace-during-extract.log"
  : > "$logf"
  selftest_emit "$logf" 3
  other="$work/other-replace-during-extract.log"
  : > "$other"
  selftest_emit "$other" 9
  AUDIT_LOG_PATH="$logf"
  selftest_scrub replace-during-extract
  audit_open || true
  capture_begin replace-during-extract
  selftest_emit "$logf" 5
  i1="$(audit_identity)"
  mv "$other" "$logf"
  if audit_drain "$EVIDENCE_DIR/avc-window-replace-during-extract.log"; then
    dstat="ok"
  else
    dstat="$AUD_BROKEN"
  fi
  i2="$(audit_identity)"
  {
    printf 'identity-extract-pre=%s\n' "$i1"
    printf 'window-drain=%s\n' "$dstat"
    printf 'identity-extract-post=%s\n' "$i2"
  } >"$work/results/replace-during-extract.steps"

  # 10. incomplete inter-window: the source is replaced between the first
  #     operation's window and the inter-window capture.
  logf="$work/audit-inter-unsound.log"
  : > "$logf"
  selftest_emit "$logf" 3
  other="$work/other-inter-unsound.log"
  : > "$other"
  selftest_emit "$other" 7
  AUDIT_LOG_PATH="$logf"
  selftest_scrub inter-unsound
  audit_open || true
  capture_begin inter-unsound
  selftest_emit "$logf" 5
  capture_end inter-unsound
  mv "$other" "$logf"
  capture_begin inter-unsound-b inter
  selftest_keep inter-window-unsound "$EVIDENCE_DIR/inter-boundaries.log" inter

  # 11/12. early-AVC ordering: an AVC raised AFTER the POST is sent but
  #        BEFORE the HTTP 201 response exists must land in THIS
  #        operation's window — never in the pre-build drain, never in
  #        the inter-window region. The transport is a controlled mock
  #        curl seam (deterministic; no sleeps); capture_begin,
  #        capture_end, classify_window, and the terminals composition
  #        are the production path verbatim. <perms> chooses the emitted
  #        denial: the eliminated "read open" shape (the evaluator must
  #        decide FAIL) or the observed next-terminal shape (MEASURED).
  selftest_early_avc() { # <scenario> <denied-perms>
    local scenario="$1" perms="$2"
    local work="$SELFTEST_WORKDIR"
    local logf="$work/audit-$scenario.log"
    local op1="1a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b" \
          op2="3c3c4c4c5c5c6c6c7c7c8c8c9c9c0c0c" \
          sid1="dhs_d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1" \
          sid2="dhs_e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2" \
          mock_serial=4700
    selftest_scrub "$scenario"
    : > "$logf"
    selftest_emit "$logf" 2
    AUDIT_LOG_PATH="$logf"
    audit_open || true
    mock_curl() {
      local url="${@: -1}" out="" body="" i
      for ((i = 1; i < $#; i++)); do
        if [ "${!i}" = "-o" ]; then
          out="${@: $((i + 1)):1}"
        elif [ "${!i}" = "-d" ]; then
          body="${@: $((i + 1)):1}"
        fi
      done
      case "$url" in
        */logs*)
          ;;
        http://localhost/build)
          local opid pid
          case "$body" in
            *uat-p21c:c1*) opid="$op1"; pid=4701 ;;
            *) opid="$op2"; pid=4702 ;;
          esac
          # THE ORDERING UNDER TEST: the kernel denial is appended to the
          # audit source BEFORE the HTTP response exists.
          mock_serial=$((mock_serial + 1))
          printf 'type=AVC msg=audit(1793799999.001:%d): avc:  denied  { %s } for  pid=%d comm="runc:[2:INIT]" path="/var/lib/docker-helper-builder/ops/op_%s/root/runc-native/executor/mockexecutor/rootfs/dev/null" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0\n' \
            "$mock_serial" "$perms" "$pid" "$opid" >>"$AUDIT_LOG_PATH"
          if [ -n "$out" ]; then
            printf '{"operation_id": "op_%s"}\n' "$opid" >"$out"
          fi
          printf '201'
          ;;
        *)
          printf '{"status": "failed", "result_code": "docker_build_failed"}'
          ;;
      esac
    }
    curl() { mock_curl "$@"; }
    printf '%s\n' "$sid1" >"$EVIDENCE_DIR/session-id-c1.log"
    printf '%s\n' "$sid2" >"$EVIDENCE_DIR/session-id-c2.log"
    run_one_build c1 mock-token || true
    classify_window c1 "$op1"
    # Host noise between the operations: the second capture_begin IS the
    # inter-window capture and must close this region BEFORE the second
    # POST is sent — the second operation's early AVC can never appear here.
    selftest_emit "$logf" 1
    run_one_build c2 mock-token inter || true
    classify_window c2 "$op2"
    compose_terminals_log
    unset -f curl
    {
      printf 'op1=%s\n' "$op1"
      printf 'op2=%s\n' "$op2"
      printf 'perms=%s\n' "$perms"
    } >"$work/results/$scenario.summary"
  }
  selftest_early_avc early-avc-old "read open"
  selftest_early_avc early-avc-next "mounton"
}

classify_window() { # <tag> <operation-id (with or without the op_ prefix)>
  local tag="$1" opid="$2"
  # The HTTP operation id carries the op_ prefix; the per-op tree path is
  # /var/lib|/run/.../ops/op_<hex>/... — normalize once.
  opid="${opid#op_}"
  local W="$EVIDENCE_DIR/avc-window-$tag.log"
  local OPATT="$EVIDENCE_DIR/op-attributed-$tag.log"
  local PIDC="$EVIDENCE_DIR/pid-correlated-$tag.log"
  local MIS="$EVIDENCE_DIR/misattributed-$tag.log"
  local UNATT="$EVIDENCE_DIR/unattributed-$tag.log"
  : > "$OPATT"; : > "$PIDC"; : > "$MIS"; : > "$UNATT"
  # op-attributed: the path carries THIS operation's id (any comm).
  grep -a "ops/op_${opid}/" "$W" > "$OPATT" 2>/dev/null || true
  # The pid set proven by op-attributed records.
  local PIDS
  PIDS="$(grep -aoE 'pid=[0-9]+' "$OPATT" | sed 's/pid=//' | sort -u | tr '\n' '|' | sed 's/|$//')"
  local rec rpid
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    if grep -aq "ops/op_${opid}/" <<<"$rec"; then
      continue  # already op-attributed
    fi
    if grep -qaE 'ops/op_[0-9a-f]+/' <<<"$rec"; then
      printf '%s\n' "$rec" >> "$MIS"   # a DIFFERENT operation's path
      continue
    fi
    # pid-correlated: pathless record whose pid is in the op-attributed set.
    rpid="$(grep -aoE 'pid=[0-9]+' <<<"$rec" | sed 's/pid=//' | head -1)"
    if [ -n "$rpid" ] && printf '%s' "$PIDS" | tr '|' '\n' | grep -qx "$rpid"; then
      printf '%s\n' "$rec" >> "$PIDC"
    else
      printf '%s\n' "$rec" >> "$UNATT"
    fi
  done < "$W"
}

run_one_build() { # <tag> <session-token> [inter]
  local tag="$1" token="$2"
  # The audit window opens BEFORE the build is admitted (r7-p21c-corrective-3):
  # POST /build is asynchronous, and AVCs raised between the operation's
  # admission and the HTTP 201 response belong to THIS operation's window.
  # They must never be absorbed by the pre-build drain (that would silently
  # weaken the eliminated-shape proof), and for the second operation they
  # must never leak into the inter-window region — this capture_begin closes
  # the inter-window region BEFORE the second POST is sent.
  capture_begin "$tag" "${3:-}" || true
  # The build goes through the HTTP API so the daemon operation id is
  # captured verbatim in the evidence (the CLI streams logs only). The
  # HTTP status is recorded next to the response.
  local RESP="$EVIDENCE_DIR/build-start-$tag.json"
  local CODE
  CODE="$(curl --silent --max-time 10 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    -d '{"context":"ctx","dockerfile":"Dockerfile","image":"uat-p21c:'"$tag"'"}' \
    -o "$RESP" -w '%{http_code}' http://localhost/build)" || true
  printf '%s\n' "$CODE" > "$EVIDENCE_DIR/build-start-$tag.http.log"
  local OP
  OP="$(grep -oE '"operation_id": *"[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"operation_id": *"//;s/"$//')"
  printf '%s\n' "$OP" > "$EVIDENCE_DIR/operation-id-$tag.log"
  log "build $tag http=$CODE operation_id=$OP"
  if [ -z "$OP" ]; then
    # The POST did not admit an operation (or its id is unparseable): the
    # window is closed here and the evaluator decides BLOCKED — a failed
    # admission can never produce MEASURED.
    log "build $tag: no operation id (http $CODE); closing the capture window"
    capture_end "$tag" || true
    return 1
  fi
  local STATUS=""
  for _ in $(seq 1 400); do
    STATUS="$(curl --silent --max-time 2 \
      --unix-socket "$DH_SOCK" -H "Authorization: Bearer $token" \
      "http://localhost/operations/$OP" 2>/dev/null || true)"
    case "$STATUS" in
      *'"succeeded"'*|*'"failed"'*) break ;;
    esac
    sleep 0.05
  done
  printf '%s\n' "$STATUS" > "$EVIDENCE_DIR/build-status-$tag.json"
  capture_end "$tag" || true
  curl --silent --max-time 2 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $token" \
    "http://localhost/operations/$OP/logs?offset=0" \
    > "$EVIDENCE_DIR/build-$tag.log" 2>&1 || true
  log "build $tag status: $(printf '%s' "$STATUS" | grep -oE '"(status|result_code)":"[^"]*"' | tr '\n' ' ')"
  return 0
}

make_session_build() { # <tag> [inter]
  local tag="$1"
  local WS="$PRINCIPAL_HOME/r7-p21c-ws-$tag"
  rm -rf "$WS"; mkdir -p "$WS/ctx"
  printf 'FROM alpine:3.24\nRUN true\n' > "$WS/ctx/Dockerfile"
  chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
  docker-helper principal show "$PRINCIPAL" >/dev/null 2>&1 \
    || docker-helper principal create --no-credential "$PRINCIPAL" >/dev/null 2>&1 || true
  docker-helper principal allowed-root add "$PRINCIPAL" "$PRINCIPAL_HOME" >/dev/null 2>&1 || true
  local RESP="$EVIDENCE_DIR/session-response-$tag.json"
  local CODE
  CODE="$(curl --silent --max-time 5 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"workspace\":\"$WS\",\"principal\":\"$PRINCIPAL\"}" \
    -o "$RESP" -w '%{http_code}' http://localhost/sessions)" || true
  local TOKEN SID
  TOKEN="$(grep -oE '"token": *"[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"token": *"//;s/"$//')"
  SID="$(grep -oE '"id": *"dhs_[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"id": *"//;s/"$//')"
  printf '%s\n' "$SID" > "$EVIDENCE_DIR/session-id-$tag.log"
  if [ -z "$TOKEN" ]; then
    log "session create failed for $tag (HTTP $CODE); skipping this build"
    return 1
  fi
  docker-helper pull alpine:3.24 >"$EVIDENCE_DIR/pull-$tag.log" 2>&1 || true
  run_one_build "$tag" "$TOKEN" "${2:-}" || true
  return 0
}

compose_op_section() { # <tag>
  local tag="$1"
  local OPID SID
  OPID="$(cat "$EVIDENCE_DIR/operation-id-$tag.log" 2>/dev/null)"
  SID="$(cat "$EVIDENCE_DIR/session-id-$tag.log" 2>/dev/null)"
  printf '== operation %s %s session %s ==\n' "$tag" "$OPID" "$SID"
  printf -- '-- window boundaries (pinned-source capture integrity) --\n'
  cat "$EVIDENCE_DIR/window-boundaries-$tag.log" 2>/dev/null || true
  printf -- '-- operation result --\n'
  grep -oE '"(status|result_code|exit_code)": *("[^"]*"|[0-9]+)' \
    "$EVIDENCE_DIR/build-status-$tag.json" 2>/dev/null | tr '\n' ' ' || true
  printf '\n'
  printf -- '-- op-attributed runc-init records --\n'
  grep -a 'comm="runc:\[2:INIT\]"' "$EVIDENCE_DIR/op-attributed-$tag.log" 2>/dev/null || true
  printf -- '-- pid-correlated runc-init records --\n'
  grep -a 'comm="runc:\[2:INIT\]"' "$EVIDENCE_DIR/pid-correlated-$tag.log" 2>/dev/null || true
  printf -- '-- misattributed records (a path carries a DIFFERENT operation id) --\n'
  cat "$EVIDENCE_DIR/misattributed-$tag.log" 2>/dev/null || true
  printf -- '-- unattributed runc-init records --\n'
  grep -a 'comm="runc:\[2:INIT\]"' "$EVIDENCE_DIR/unattributed-$tag.log" 2>/dev/null || true
  printf -- '-- regression controls (the WHOLE window; must be EMPTY) --\n'
  printf -- '-- P20 terminal (runc_memfd_t:file create) --\n'
  grep -ah 'docker_helper_runc_memfd_t.*tclass=file' "$EVIDENCE_DIR/avc-window-$tag.log" 2>/dev/null | grep -a '{ create }' || true
  printf -- '-- pre-B terminal (tmpfs_t:file write) --\n'
  grep -ah 'tcontext=system_u:object_r:tmpfs_t:s0 tclass=file' "$EVIDENCE_DIR/avc-window-$tag.log" 2>/dev/null | grep -a '{ write }' || true
  printf -- '-- associate denials (must be EMPTY — the singleton is granted) --\n'
  grep -ah 'denied  { associate }' "$EVIDENCE_DIR/avc-window-$tag.log" 2>/dev/null || true
  printf -- '-- P21-B terminal (devnode_t:file { read open }; the ELIMINATED shape) --\n'
  grep -ah 'runc:\[2:INIT\]' "$EVIDENCE_DIR/avc-window-$tag.log" 2>/dev/null | grep -a 'tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file' | grep -a 'denied  { read open }' || true
}

# The terminals-log composition is the single owner of the evidence
# grammar shape: two per-operation sections followed by the inter-window
# region (used by the live flow AND by the early-AVC selftest scenarios).
compose_terminals_log() {
  {
    compose_op_section c1
    compose_op_section c2
    printf '== inter-window records (attributable to NEITHER operation) ==\n'
    printf -- '-- window boundaries (pinned-source capture integrity) --\n'
    cat "$EVIDENCE_DIR/inter-boundaries.log" 2>/dev/null || true
    printf -- '-- records --\n'
    cat "$EVIDENCE_DIR/inter-window.log" 2>/dev/null
  } > "$EVIDENCE_DIR/p21c-terminals.log" 2>&1
}

if [ -n "$SELFTEST_WORKDIR" ]; then
  p21c_capture_selftest "$SELFTEST_WORKDIR"
  exit 0
fi

[ "$(id -u)" = "0" ] || fail "must run as root"
[ -f "$ARTIFACT" ] || fail "artifact missing: $ARTIFACT"
now_sha="$(sha256sum "$ARTIFACT" | awk '{print $1}')"
[ "$now_sha" = "$ARTIFACT_SHA" ] || fail "artifact SHA mismatch (expected $ARTIFACT_SHA, got $now_sha)"



# ============================================================================
# Section 1: platform + SELinux enforcing proof
# ============================================================================
if [ -f "$STATE_DIR/sec1" ]; then log "phase marker: section 1 done; skipping"; else
log "=== section 1: platform + SELinux state ==="
ENF="$(getenforce 2>/dev/null || echo absent)"
[ "$ENF" = "Enforcing" ] || fail "SELinux not enforcing (getenforce='$ENF')"
cat /sys/kernel/security/lsm >"$EVIDENCE_DIR/lsm.txt" 2>&1 || true
grep -qw selinux "$EVIDENCE_DIR/lsm.txt" || fail "selinux not an active LSM"
cap p21c-se-status 14 bash -c 'sestatus; echo ---; getenforce; id -Z'
cat /etc/os-release >"$EVIDENCE_DIR/os-release.txt" 2>&1
grep -qi 'opensuse tumbleweed' "$EVIDENCE_DIR/os-release.txt" || fail "not openSUSE Tumbleweed"
cap p21c-platform 8 bash -c 'uname -a'
touch "$STATE_DIR/sec1"
fi

# ============================================================================
# Section 2: exact candidate install (never rebuilds)
# ============================================================================
if [ -f "$STATE_DIR/sec2" ]; then log "phase marker: section 2 done; skipping"; else
log "=== section 2: candidate install (rpm) ==="
rpm -q docker-helper >/dev/null 2>&1 && rpm -e docker-helper >/dev/null 2>&1 || true
rpm -i "$ARTIFACT" || fail "rpm -i failed"
log "RPM installed: $(rpm -q docker-helper)"
sha256sum "$ARTIFACT" > "$EVIDENCE_DIR/candidate-rpm-sha256.log"
log "candidate RPM sha256: $(cat "$EVIDENCE_DIR/candidate-rpm-sha256.log")"
PRINCIPAL="${SUDO_USER:-}"
[ -n "$PRINCIPAL" ] && [ "$PRINCIPAL" != "root" ] || fail "cannot derive non-root principal"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
[ -n "$PRINCIPAL_HOME" ] && [ -d "$PRINCIPAL_HOME" ] || fail "principal home not found"
docker-helper init --allowed-root "$PRINCIPAL_HOME" || fail "docker-helper init failed"
systemctl daemon-reload
systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
systemctl enable --now docker-helper-builder.service >/dev/null 2>&1 || true
READY=0
for _ in $(seq 1 50); do
  if [ -S "$DH_SOCK" ] && curl --silent --fail --max-time 1 \
      --unix-socket "$DH_SOCK" http://localhost/health >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 0.2
done
[ "$READY" = 1 ] || fail "daemon API socket not ready"
log "daemon ready on $DH_SOCK"
touch "$STATE_DIR/sec2"
fi

PRINCIPAL="${SUDO_USER:-}"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"

# ============================================================================
# Section 3: tooling + the LOADED candidate-policy inventory
# ============================================================================
if [ -f "$STATE_DIR/sec3" ]; then log "phase marker: section 3 done; skipping"; else
log "=== section 3: tooling + loaded-policy inventory (candidate policy) ==="
command -v sesearch >/dev/null 2>&1 || { timeout 180 zypper --non-interactive install -y setools-console >/dev/null 2>&1 || true; }
if ! command -v gcc >/dev/null 2>&1; then
  cap p21c-toolchain 6 timeout 300 zypper --non-interactive install -y gcc libselinux-devel
fi
command -v gcc >/dev/null 2>&1 || fail "gcc unavailable"

# (1) TRANSITION SCOPE: the loaded transitions keyed on (buildkitd_t, tmpfs_t).
cap p21c-transitions 30 bash -c 'sesearch -T -s docker_helper_buildkitd_t -t tmpfs_t'
# (2) MEMFD REGRESSION (static): the memfd surface must be EXACTLY the six
# P1-P6 rules with NO create.
cap p21c-memfd-allows 20 bash -c 'sesearch -A -s docker_helper_buildkitd_t -t docker_helper_runc_memfd_t'
# (3) AUTHORITY AUDIT: the FULL surface of the type — every subject, every
# direction, no attribute expansion possible (attribute-free). After the
# P21-C rung: as TARGET exactly the create singleton and the { read open }
# open-completion pair; as SOURCE exactly the associate singleton.
cap p21c-devnode-subj 20 bash -c 'echo "# sesearch -A -s docker_helper_devnode_t (the associate singleton is the ONLY subject authority)"; sesearch -A -s docker_helper_devnode_t'
cap p21c-devnode-target 20 bash -c 'echo "# sesearch -A -t docker_helper_devnode_t (the create singleton and the P21-C { read open } pair are the ONLY target authorities)"; sesearch -A -t docker_helper_devnode_t'
cap p21c-devnode-attrs 10 seinfo -x -t docker_helper_devnode_t
cap p21c-devnode-fs 20 bash -c 'echo "# sesearch -A -s docker_helper_devnode_t -c filesystem"; sesearch -A -s docker_helper_devnode_t -c filesystem'
# The standing tmpfs_t surface must be unchanged (no tmpfs_t:file grant).
cap p21c-bkd-tmpfs 40 bash -c 'sesearch -A -s docker_helper_buildkitd_t -t tmpfs_t'
# Constraints for the record (the cross-operation read constraint lives here).
cap p21c-constraints-file 20 seinfo --constrain file
cap p21c-constraints-fs 20 seinfo --constrain filesystem
cap p21c-fsuse 12 bash -c 'seinfo --fs_use | grep -E "tmpfs|shm|mqueue"'
cap p21c-defaults 8 seinfo --default file
sha256sum /sys/fs/selinux/policy | awk '{print $1}' > "$EVIDENCE_DIR/policy-sha.log"
log "candidate loaded policy sha256: $(cat "$EVIDENCE_DIR/policy-sha.log")"
touch "$STATE_DIR/sec3"
fi

# ============================================================================
# Section 4: kernel-decision helpers
# ============================================================================
if [ ! -x "$EVIDENCE_DIR/p21c_create_probe" ]; then
log "=== section 4: kernel-decision helpers build ==="
cat > "$EVIDENCE_DIR/p21c_create_probe.c" <<'CEOF'
/* p21c_create_probe.c — security_compute_create(_name)_raw on the LOADED
 * candidate policy: the would-be label of a creation transition, with the
 * exact basename (filename transitions) and with name=NULL (the memfd
 * lazy-labeling route). PRELIMINARY evidence only. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <selinux/selinux.h>

typedef int (*compute_create_name_fn)(const char *, const char *,
                                      security_class_t, const char *, char **);

int main(int argc, char **argv)
{
	compute_create_name_fn compute_name = NULL;
	void *h = dlopen(NULL, RTLD_LAZY);
	if (h)
		compute_name = (compute_create_name_fn)dlsym(
			h, "security_compute_create_name_raw");
	if (argc < 4) {
		fprintf(stderr,
			"usage: p21c_create_probe <source-ctx> <target-ctx> <class> [name [more triples]]\n");
		return 2;
	}
	for (int i = 1; i + 3 <= argc; i += 4) {
		char *out = NULL;
		security_class_t cl = string_to_security_class(argv[i + 2]);
		const char *name = argv[i + 3];
		int rc;
		if (!cl) {
			printf("CREATE %s x %s x %s [%s] -> CLASS-UNKNOWN\n",
			       argv[i], argv[i + 1], argv[i + 2], name);
			continue;
		}
		if (strcmp(name, "-") == 0 || !compute_name) {
			rc = security_compute_create_raw(argv[i], argv[i + 1], cl, &out);
		} else {
			rc = compute_name(argv[i], argv[i + 1], cl, name, &out);
		}
		if (rc == 0 && out)
			printf("CREATE %s x %s x %s [%s] -> %s\n",
			       argv[i], argv[i + 1], argv[i + 2], name, out);
		else
			printf("CREATE %s x %s x %s [%s] -> ERR rc=%d errno=%d (%s)\n",
			       argv[i], argv[i + 1], argv[i + 2], name, rc, errno,
			       strerror(errno));
		free(out);
	}
	return 0;
}
CEOF
gcc -O2 -o "$EVIDENCE_DIR/p21c_create_probe" "$EVIDENCE_DIR/p21c_create_probe.c" -lselinux -ldl \
  || fail "p21c_create_probe build failed"

cat > "$EVIDENCE_DIR/p21c_av_probe.c" <<'CEOF'
/* p21c_av_probe.c — kernel-decision matrix via security_compute_av_raw. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>

static const char *file_perms[] = {
	"create", "write", "append", "setattr", "execute",
	"execute_no_trans", "map", "open", "read", "getattr",
	"unlink", "rename", "link", "ioctl", "lock", NULL
};

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "usage: p21c_av_probe <source-ctx> <target-ctx> <class>\n");
		return 2;
	}
	security_class_t cl = string_to_security_class(argv[3]);
	if (!cl) { fprintf(stderr, "unknown class %s\n", argv[3]); return 2; }
	struct av_decision avd;
	if (strcmp(argv[3], "file") == 0) {
		for (int p = 0; file_perms[p]; p++) {
			access_vector_t bit = string_to_av_perm(cl, file_perms[p]);
			if (!bit) { printf("  %-16s UNKNOWN-PERM\n", file_perms[p]); continue; }
			int rc = security_compute_av_raw(argv[1], argv[2], cl, bit, &avd);
			if (rc)
				printf("  %-16s ERR rc=%d errno=%d\n", file_perms[p], rc, errno);
			else
				printf("  %-16s %s (allowed=0x%x decided=0x%x)\n",
				       file_perms[p],
				       (avd.allowed & bit) ? "ALLOW" : "DENY",
				       (unsigned)avd.allowed, (unsigned)avd.decided);
		}
	} else {
		access_vector_t bit = string_to_av_perm(cl, "associate");
		if (!bit) { printf("  associate UNKNOWN-PERM\n"); return 1; }
		int rc = security_compute_av_raw(argv[1], argv[2], cl, bit, &avd);
		if (rc)
			printf("  associate ERR rc=%d errno=%d\n", rc, errno);
		else
			printf("  associate %s (allowed=0x%x decided=0x%x)\n",
			       (avd.allowed & bit) ? "ALLOW" : "DENY",
			       (unsigned)avd.allowed, (unsigned)avd.decided);
	}
	return 0;
}
CEOF
gcc -O2 -o "$EVIDENCE_DIR/p21c_av_probe" "$EVIDENCE_DIR/p21c_av_probe.c" -lselinux \
  || fail "p21c_av_probe build failed"
log "kernel-decision helpers built"
touch "$STATE_DIR/sec4"
fi

BKD_CTX="system_u:system_r:docker_helper_buildkitd_t:s0:c1"
BKD_C2="system_u:system_r:docker_helper_buildkitd_t:s0:c2"
TMPFS_CTX="system_u:object_r:tmpfs_t:s0"
UNCONF_CTX="unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
DEVNODE="system_u:object_r:docker_helper_devnode_t:s0"
MEMFD="system_u:object_r:docker_helper_runc_memfd_t:s0"

create_matrix() { # <suffix>
  # The matrix the gate evaluator validates row-by-row (16 required rows):
  # all six basenames for BOTH operation categories (the diversion), the
  # arbitrary-basename control and the name=NULL (memfd) control for BOTH
  # categories (the bare transition), and the unconfined controls.
  "$EVIDENCE_DIR/p21c_create_probe" \
    "$BKD_CTX" "$TMPFS_CTX" file null \
    "$BKD_CTX" "$TMPFS_CTX" file zero \
    "$BKD_CTX" "$TMPFS_CTX" file full \
    "$BKD_CTX" "$TMPFS_CTX" file random \
    "$BKD_CTX" "$TMPFS_CTX" file urandom \
    "$BKD_CTX" "$TMPFS_CTX" file tty \
    "$BKD_C2" "$TMPFS_CTX" file null \
    "$BKD_C2" "$TMPFS_CTX" file zero \
    "$BKD_C2" "$TMPFS_CTX" file full \
    "$BKD_C2" "$TMPFS_CTX" file random \
    "$BKD_C2" "$TMPFS_CTX" file urandom \
    "$BKD_C2" "$TMPFS_CTX" file tty \
    "$BKD_CTX" "$TMPFS_CTX" file someothername \
    "$BKD_CTX" "$TMPFS_CTX" file - \
    "$BKD_C2" "$TMPFS_CTX" file someothername \
    "$BKD_C2" "$TMPFS_CTX" file - \
    "$UNCONF_CTX" "$TMPFS_CTX" file null \
    "$UNCONF_CTX" "$TMPFS_CTX" file - \
    > "$EVIDENCE_DIR/create-matrix-$1.log" 2>&1
  cat "$EVIDENCE_DIR/create-matrix-$1.log"
}

av_matrix() { # <suffix>
  {
    echo "== buildkitd_t:s0:c1 -> docker_helper_devnode_t:s0 =="
    "$EVIDENCE_DIR/p21c_av_probe" "$BKD_CTX" "$DEVNODE" file
    echo "== CROSS-OP: buildkitd_t:s0:c2 -> docker_helper_devnode_t:s0 =="
    "$EVIDENCE_DIR/p21c_av_probe" "$BKD_C2" "$DEVNODE" file
    echo "== unconfined_t -> docker_helper_devnode_t:s0 =="
    "$EVIDENCE_DIR/p21c_av_probe" "$UNCONF_CTX" "$DEVNODE" file
    echo "== FILESYSTEM ASSOCIATE rows =="
    echo "-- devnode_t -> tmpfs_t (the granted singleton) --"
    "$EVIDENCE_DIR/p21c_av_probe" "system_u:object_r:docker_helper_devnode_t:s0" "$TMPFS_CTX" filesystem
    echo "-- runc_memfd_t -> tmpfs_t (must stay denied) --"
    "$EVIDENCE_DIR/p21c_av_probe" "$MEMFD" "$TMPFS_CTX" filesystem
    echo "-- tmpfs_t -> tmpfs_t (control) --"
    "$EVIDENCE_DIR/p21c_av_probe" "system_u:object_r:tmpfs_t:s0" "$TMPFS_CTX" filesystem
  } > "$EVIDENCE_DIR/av-matrix-$1.log" 2>&1
  cat "$EVIDENCE_DIR/av-matrix-$1.log"
}

# ============================================================================
# Section 5: decision matrices on the candidate policy
# ============================================================================
if [ -f "$STATE_DIR/sec5" ]; then log "phase marker: section 5 done; skipping"; else
log "=== section 5: create + AV matrices (candidate policy) ==="
create_matrix before
av_matrix before
touch "$STATE_DIR/sec5"
fi

# ============================================================================
# Section 6: cross-operation channel evidence (policy-level, not namespace)
# ============================================================================
if [ -f "$STATE_DIR/sec6" ]; then log "phase marker: section 6 done; skipping"; else
log "=== section 6: cross-operation channel evidence ==="
# The venues a same-named creation could land in (the filename transitions
# are name-keyed, not path-keyed — the recorded E1 limitation).
cap p21c-host-venues 20 bash -c 'ls -ldZ /dev/shm /dev/mqueue /run/initramfs /tmp /var/tmp 2>&1'
# The file-class constraint text (the read/open admission for both
# categories over an s0 object is the constraint's own decision; the
# kernel-AV matrix rows above carry the c1/c2 verdicts).
cap p21c-crossop-constraint 40 bash -c 'seinfo --constrain file | sed -n 1,40p'
# The kernel-AV write-class rows for the SHARED-CHANNEL question: every
# subject that could write content into a devnode_t object. Already
# captured in av-matrix-before.log; restate the write-class subset with an
# explicit section banner so the evidence file is self-contained.
{
  echo "== CROSS-OP CHANNEL: write-class kernel decisions (c1, c2, unconfined) =="
  echo "-- buildkitd_t:s0:c1 -> devnode_t (write/append/setattr/map must be DENY) --"
  "$EVIDENCE_DIR/p21c_av_probe" "$BKD_CTX" "$DEVNODE" file | grep -E '  (write|append|setattr|map) '
  echo "-- CROSS-OP buildkitd_t:s0:c2 -> devnode_t (write/append/setattr/map must be DENY) --"
  "$EVIDENCE_DIR/p21c_av_probe" "$BKD_C2" "$DEVNODE" file | grep -E '  (write|append|setattr|map) '
  echo "-- unconfined_t -> devnode_t (ALL must be DENY) --"
  "$EVIDENCE_DIR/p21c_av_probe" "$UNCONF_CTX" "$DEVNODE" file | grep -E '  (write|append|setattr|map) '
} > "$EVIDENCE_DIR/p21c-crossop-write.log" 2>&1
cat "$EVIDENCE_DIR/p21c-crossop-write.log"
# Live in-domain probe attempt (the mcs-audit precedent): a test process in
# the ACTUAL buildkitd domain is expected BLOCKED; the attempt and its
# denial are recorded, never a pass condition.
if OUT="$(runcon -r system_r -t docker_helper_buildkitd_t -l s0:c2 id -Z 2>"$EVIDENCE_DIR/runcon-bkd.err")"; then
  log "live probe: buildkitd-domain test process started ($OUT) — recording, not relying on it"
  printf '%s\n' "$OUT" > "$EVIDENCE_DIR/runcon-bkd.ok"
else
  log "live probe: buildkitd-domain test process DENIED (expected; the kernel-AV matrix carries the proof)"
fi
avc_tail p21c-runcon-avc || true
touch "$STATE_DIR/sec6"
fi

# ============================================================================
# Section 7: live flow probes (the enforcing runtime; two operations)
#
# ATTRIBUTION CONTRACT (r7-p21c-corrective-1): each operation's evidence is
# captured and classified INDEPENDENTLY:
#   1. Session ID + daemon Operation ID recorded per operation (the HTTP
#      /build response and the /sessions response).
#   2. EXACT audit capture boundaries: the window is EXACTLY the bytes
#      appended to the pinned audit source between the pre-build drain and
#      the post-operation drain, read THROUGH one pinned descriptor (no
#      tail window, no ausearch "recent", no arbitrary head -N truncation,
#      no re-read from the path). The identity checkpoints around every
#      drain and the measured before/after/expected/actual accounting are
#      recorded; an unproven capture is capture-unavailable.
#   3. Per-record attribution inside each window (MCS category is NEVER the
#      attribution key — both runtimes may share one category):
#        - op-attributed: the record's path carries THIS operation's
#          ops/op_<id>/ prefix (the per-operation tree path is unique);
#        - pid-correlated: a pathless record whose pid equals the pid of an
#          op-attributed record of the SAME window (audit serial/time
#          adjacency within the strict window bounds pid reuse);
#        - misattributed: a record whose path carries a DIFFERENT
#          operation's id — recorded as a positive attribution violation;
#        - unattributed: everything else. A runc:[2:INIT] record that
#          cannot be attributed is AMBIGUOUS evidence (the evaluator
#          decides BLOCKED — it is never assumed to belong to an
#          operation).
#   4. The final operation status is recorded verbatim; the runtime stage
#      reached is evidenced by the attributed records themselves (the
#      presence of the runc:[2:INIT] comm and of the boundary records).
# ============================================================================

if [ -f "$STATE_DIR/sec7" ]; then log "phase marker: section 7 done; skipping"; else
log "=== section 7: live flow probes (candidate policy; independent windows) ==="
for _ in $(seq 1 50); do
  [ -S "$DH_SOCK" ] && curl --silent --fail --max-time 1 \
    --unix-socket "$DH_SOCK" http://localhost/health >/dev/null 2>&1 && break
  sleep 0.2
done
[ -n "$ADMIN_TOKEN" ] || fail "admin token unreadable; the live proof cannot run"
[ -f "$AUDIT_LOG_PATH" ] || fail "audit source unavailable; per-operation windows cannot be bounded"
audit_open || fail "cannot open the pinned audit-source descriptor"
log "pinned audit-source descriptor: fd=$AUD_FD identity=$(audit_identity || true)"
make_session_build c1
classify_window c1 "$(cat "$EVIDENCE_DIR/operation-id-c1.log" 2>/dev/null)"
# The SECOND operation's pre-build drain IS the inter-window capture: the
# records consumed between the two operations are attributable to NEITHER
# operation by position; unrelated host audit noise is expected there. Any
# runc:[2:INIT] record in this region is AMBIGUOUS evidence (the evaluator
# decides BLOCKED — it is never assumed to belong to an operation).
make_session_build c2 inter
classify_window c2 "$(cat "$EVIDENCE_DIR/operation-id-c2.log" 2>/dev/null)"
compose_terminals_log
cat "$EVIDENCE_DIR/p21c-terminals.log"
touch "$STATE_DIR/sec7"
fi

# ============================================================================
# Machine verdict — the standalone fail-closed evaluator is the single
# authority (mirrors the P21-B guest/driver contract): the guest only runs
# it and records its verdict; the driver gates on DECISION=P21C-MEASURED.
# The P21-B evaluator stays untouched (the historical P21-B instrument).
# ============================================================================
if [ -r /tmp/r7-diag/release-2.4-r7-p21c-verdict.sh ]; then
  bash /tmp/r7-diag/release-2.4-r7-p21c-verdict.sh "$EVIDENCE_DIR" \
    > "$EVIDENCE_DIR/p21c-verdict.log" 2>&1
  VERDICT_RC=$?
  log "p21c evaluator exit=$VERDICT_RC"
  cat "$EVIDENCE_DIR/p21c-verdict.log"
else
  log "verdict evaluator missing from /tmp/r7-diag; recording BLOCKED"
  printf 'R7-P21C-VERDICT=DECISION=P21C-BLOCKED;REASON=evaluator-script-missing\n' \
    > "$EVIDENCE_DIR/p21c-verdict.log"
  cat "$EVIDENCE_DIR/p21c-verdict.log"
fi
exit 0
