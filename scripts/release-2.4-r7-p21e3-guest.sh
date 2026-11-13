#!/usr/bin/env bash
#
# release-2.4-r7-p21e3-guest.sh — the R7 P21-E-R4-P3-P3 FIRST ENFORCING
# integration measurement: one bounded build on a disposable ENFORCING
# openSUSE Tumbleweed VM with the exact freshly produced candidate RPM and
# its UNCHANGED packaged policy, tracing the wrapper chain end to end.
#
# MODE: diagnostic evidence only. NO grants, NO policy edits/reloads
# outside the ordinary candidate installation, NO relabeling outside the
# installer contract, NO chmod/chown workarounds, NO fallback to a distro
# runc, NO speculative retries. The build is ALLOWED to fail: the round
# measures the first execution, which checks pass, and the FIRST observed
# failure boundary.
#
# Evidence per boundary of the accepted chain
# (POST /build → manager START → rootlesskit/buildkitd → exec
# buildkit-runc (wrapper) → own-context read → prepared-tree inspection →
# spec rewrite + rename commit → execve(runtime/buildkit-runc) → runc
# container init → /dev bind / subsequent mounts):
#
#   * a /proc sampler records, for every relevant process, pid/ppid/comm/
#     exe/cmdline and the KERNEL CONTEXT (/proc/<pid>/attr/current). The
#     wrapper and the REAL RUNTIME are distinguished by /proc/<pid>/exe
#     (…/buildkit-runc vs …/runtime/buildkit-runc) across the execve —
#     never by comm alone (both are comm="buildkit-runc").
#   * strace -f is attached to the live buildkitd at boot and follows the
#     whole subtree: the wrapper's own syscalls (the OBL-7 own-context
#     procattr read via open + read), the spec rewrite (open/create/rename),
#     the execve handoff, and the real runtime's container-init syscalls
#     (mounted/mkdir/symlink — the OBL-1′ bind surface) with decoded paths.
#     The syscall filter deliberately excludes write/close to bound output;
#     the build cache is pre-warmed so IO noise stays small. A hard
#     timeout bounds the trace.
#   * the audit window uses ONE pinned descriptor on the audit source:
#     the start offset is aligned to a REAL record boundary by NUMERIC
#     byte inspection (a genuinely empty log starts at 0; a nonempty
#     newline-terminated log starts at its exact size; a mid-record or
#     unreadable boundary is REFUSED — the shell-string check it replaces
#     confused newline-terminated logs with empty logs, silently opening
#     the window over the historical records), and every window record is
#     read THROUGH that descriptor after the build, with a
#     path-vs-descriptor identity check (dev:ino) at both checkpoints and
#     a torn trailing record dropped and recorded.
#   * pre-build HARD GATES: the installed wrapper byte-identity and the
#     relocated runtime MANIFEST digest decide the round — a mismatch or a
#     label outside the three exact-path .fc rules records the evidence
#     (OBL-4 for labels) and the measurement refuses to start.
#   * capture ordering: tools + session + image prewarm FIRST, the audit
#     window opened IMMEDIATELY before the measured operation, and the
#     /proc sampler STARTED AND CONFIRMED before POST /build (early
#     rootlesskit/launcher capture), with the builder-manager service
#     journal bounded to the same window. Teardown is by construction on
#     terminal, refusal and aborted paths.
#
# Machine verdict contract: R7-P21E3-VERDICT=MEASURED when the one build
# operation ran and the evidence parts exist (the build itself may fail —
# the verdict records the actual failure shape separately via
# R7-P21E3-BUILD=<failed|succeeded>). An aborted measurement decides
# BLOCKED, never success. A "MEASURED" verdict records that the diagnostic
# ran; it is NOT evidence that any downstream boundary was reached.

set -uo pipefail

log()  { printf '[r7-p21e3] %s\n' "$*"; }
fail() { printf '[r7-p21e3] FAILED: %s\n' "$*" >&2; exit 1; }


cap() { # <name> <max-lines> <cmd...>
  local name="$1" maxn="$2" rc; shift 2
  "$@" >"$EVIDENCE_DIR/$name.log" 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || printf 'capture rc=%d\n' "$rc" >>"$EVIDENCE_DIR/$name.log"
  log "--- $name (evidence: $EVIDENCE_DIR/$name.log, first $maxn lines) ---"
  head -n "$maxn" "$EVIDENCE_DIR/$name.log"
  return 0
}


# ---------------------------------------------------------------------------
# Audit-window boundary machinery (shared by the pinned window in section 5
# and by --audit-window-selftest, which exercises the SAME functions against
# synthetic audit sources; the Go tests judge the recorded outcomes).
# ---------------------------------------------------------------------------
AUD_FD=""
AUD_START=""
AUD_SIZE=""
AUD_LASTBYTE=""
AUD_PATH=""
AUD_PATH_DEVINO=""
AUD_FD_DEVINO=""
AUD_TORN=no

# probe_lastbyte_code <fd> <size>: prints the NUMERIC code (0..255) of the
# pinned source's last byte, or nothing when unreadable. Numeric-only, by
# construction: bash command substitution strips trailing newlines, so a
# nonempty newline-terminated log takes the empty-log branch under any
# string comparison with "$(printf '\n')" — the boundary bug this
# implementation replaces.
probe_lastbyte_code() { # <fd> <size>
  dd if=/proc/self/fd/$1 bs=1 skip=$(($2 - 1)) count=1 2>/dev/null \
    | od -An -v -tu1 | awk 'NF { print $1; exit }'
}

# audit_boundary_open <path>: opens the ONE pinned descriptor on the audit
# source and aligns AUD_START to a real record boundary: 0 for a genuinely
# empty log; the EXACT current size for a nonempty newline-terminated log;
# refusal (rc 1) otherwise — a mid-record boundary, an unreadable size/last
# byte, or a descriptor/path identity mismatch is unprovable and the
# window must not start there. Preserves the pinned-descriptor continuity
# checks (path-vs-descriptor dev:ino at open).
audit_boundary_open() {
  local p="$1" i size last
  exec {AUD_FD}<"$p" 2>/dev/null || { AUD_FD=""; return 1; }
  AUD_SIZE=""; AUD_LASTBYTE=""; AUD_START=""
  for i in $(seq 1 20); do
    size="$(stat -L -c '%s' /proc/self/fd/$AUD_FD 2>/dev/null || true)"
    case "$size" in '' | *[!0-9]*) sleep 0.1; continue ;; esac
    if [ "$size" -eq 0 ]; then
      AUD_START=0; AUD_SIZE=0; AUD_LASTBYTE=none
      break
    fi
    last="$(probe_lastbyte_code "$AUD_FD" "$size" 2>/dev/null)" || last=""
    if [ -z "$last" ]; then sleep 0.1; continue; fi
    AUD_SIZE="$size"; AUD_LASTBYTE="$last"
    if [ "$last" = 10 ]; then AUD_START="$size"; break; fi
    sleep 0.1
  done
  if [ -z "$AUD_START" ]; then
    exec {AUD_FD}<&- 2>/dev/null || true
    AUD_FD=""
    return 1
  fi
  AUD_PATH="$p"
  AUD_PATH_DEVINO="$(stat -c '%d:%i' "$p" 2>/dev/null)" || AUD_PATH_DEVINO=""
  AUD_FD_DEVINO="$(stat -L -c '%d:%i' /proc/self/fd/$AUD_FD 2>/dev/null)" || AUD_FD_DEVINO=""
  if [ -z "$AUD_PATH_DEVINO" ] || [ "$AUD_PATH_DEVINO" != "$AUD_FD_DEVINO" ]; then
    exec {AUD_FD}<&- 2>/dev/null || true
    AUD_FD=""
    return 1
  fi
  return 0
}

# audit_window_identity: prints proven, or broken(...); rc 1 when the
# pinned descriptor no longer matches the source path (replaced/rotated
# log) — the window must not be attributed to an unproven source.
audit_window_identity() {
  local path fd
  [ -n "${AUD_FD:-}" ] || { printf 'broken:no-pinned-descriptor'; return 1; }
  path="$(stat -c '%d:%i' "$AUD_PATH" 2>/dev/null)" \
    || { printf 'broken:path-stat-error'; return 1; }
  fd="$(stat -L -c '%d:%i' /proc/self/fd/$AUD_FD 2>/dev/null)" \
    || { printf 'broken:descriptor-stat-error'; return 1; }
  if [ "$path" = "$fd" ]; then printf 'proven'; return 0; fi
  printf 'broken(pinned=%s,path=%s)' "$fd" "$path"
  return 1
}

# audit_window_drain <outfile>: appends EXACTLY the bytes [AUD_START,
# current EOF) through the pinned descriptor, then drops an incomplete
# trailing record (numeric last-byte check, never a string comparison) and
# records the fact in AUD_TORN (complete|dropped).
audit_window_drain() {
  local out="$1" n lastbyte
  dd if=/proc/self/fd/$AUD_FD bs=1M skip="$AUD_START" iflag=fullblock,skip_bytes \
    >>"$out" 2>/dev/null || true
  AUD_TORN=complete
  n="$(wc -c <"$out" 2>/dev/null)" || n=0
  case "$n" in '' | *[!0-9]*) n=0 ;; esac
  [ "$n" -gt 0 ] || return 0
  lastbyte="$(tail -c 1 "$out" | wc -l)" # 1 iff the last byte is 0x0a
  if [ "$lastbyte" != 1 ]; then
    head -n -1 "$out" >"$out.tmp" && mv "$out.tmp" "$out"
    AUD_TORN=dropped
  fi
}

# ---------------------------------------------------------------------------
# --audit-window-selftest <workdir>: exercises the REAL boundary functions
# (probe_lastbyte_code / audit_boundary_open / audit_window_identity /
# audit_window_drain) against SYNTHETIC audit sources and records each
# scenario's measured facts under <workdir>/results/ for the Go tests to
# assert. NO assertions here: the recorded facts are the evidence; the Go
# tests are the judge.
# ---------------------------------------------------------------------------
SELFTEST_COUNTER=0

selftest_emit() { # <file> <count>
  local i=1
  while [ "$i" -le "$2" ]; do
    SELFTEST_COUNTER=$((SELFTEST_COUNTER + 1))
    printf 'type=SYNTH msg=audit(1000000.000:%d): synthetic record %d\n' \
      "$SELFTEST_COUNTER" "$SELFTEST_COUNTER" >>"$1"
    i=$((i + 1))
  done
}

p21e3_audit_window_selftest() { # <workdir>
  local work="$1" logf
  mkdir -p "$work/results"

  # 1. history-green: 3 complete historical records, then the boundary is
  #    opened, then 2 complete current-window records. The drain must
  #    exclude ALL history and include exactly the 2 new records.
  logf="$work/audit-history.log"
  selftest_emit "$logf" 3
  audit_boundary_open "$logf" || printf 'boundary=refused\n' >"$work/results/history-green.boundary"
  if [ -n "$AUD_START" ]; then
    {
      printf 'start=%s\n' "$AUD_START"
      printf 'size=%s\n' "$AUD_SIZE"
      printf 'lastbyte=%s\n' "$AUD_LASTBYTE"
      printf 'pinned=%s\n' "$AUD_FD_DEVINO"
    } >"$work/results/history-green.boundary"
    selftest_emit "$logf" 2
    audit_window_drain "$work/results/history-green.window"
    printf 'torn=%s\n' "$AUD_TORN" >"$work/results/history-green.drain"
    exec {AUD_FD}<&- 2>/dev/null || true
    AUD_FD=""
  fi

  # 2. torn-trailing: complete records, then an incomplete final record
  #    (no trailing newline) still being written at drain time. The drain
  #    must drop exactly the torn bytes and keep the complete ones.
  logf="$work/audit-torn.log"
  selftest_emit "$logf" 2
  audit_boundary_open "$logf" || printf 'boundary=refused\n' >"$work/results/torn-trailing.boundary"
  if [ -n "$AUD_START" ]; then
    selftest_emit "$logf" 2
    printf 'type=SYNTH msg=audit(1000000.999:%d): torn' "$((SELFTEST_COUNTER + 1))" >>"$logf"
    audit_window_drain "$work/results/torn-trailing.window"
    printf 'torn=%s\n' "$AUD_TORN" >"$work/results/torn-trailing.drain"
    exec {AUD_FD}<&- 2>/dev/null || true
    AUD_FD=""
  fi

  # 3. empty: a genuinely zero-length log must open at offset 0.
  : >"$work/audit-empty.log"
  audit_boundary_open "$work/audit-empty.log" \
    || printf 'boundary=refused\n' >"$work/results/empty.boundary"
  if [ -n "$AUD_START" ]; then
    printf 'start=%s\nsize=%s\nlastbyte=%s\n' "$AUD_START" "$AUD_SIZE" "$AUD_LASTBYTE" \
      >"$work/results/empty.boundary"
    exec {AUD_FD}<&- 2>/dev/null || true
    AUD_FD=""
  fi

  # 4. partial-trailing: the log ends mid-record — starting the window
  #    there is UNPROVABLE and must be refused, never approximated.
  printf 'type=SYNTH msg=audit(0.1:1): complete\npartial-trailing-record' >"$work/audit-partial.log"
  if audit_boundary_open "$work/audit-partial.log" 2>/dev/null; then
    printf 'boundary=wrongly-provisional\n' >"$work/results/partial-trailing.boundary"
    exec {AUD_FD}<&- 2>/dev/null || true
    AUD_FD=""
  else
    printf 'boundary=refused\nsize-lastbyte=%s\n' "$AUD_LASTBYTE" \
      >"$work/results/partial-trailing.boundary"
  fi

  # 5. rotated: the path is replaced with a new inode between open and the
  #    identity check — the close-time check must decide broken.
  logf="$work/audit-rotated.log"
  selftest_emit "$logf" 2
  if audit_boundary_open "$logf" && [ -n "$AUD_START" ]; then
    printf 'replacement\n' >"$logf.new"
    mv "$logf.new" "$logf"
    audit_window_identity >"$work/results/rotated.identity" || true
    exec {AUD_FD}<&- 2>/dev/null || true
    AUD_FD=""
  else
    printf 'identity=boundary-refused\n' >"$work/results/rotated.identity"
  fi
}

# ---------------------------------------------------------------------------
# Sesearch result classification — FAIL-CLOSED, aware of the real installed
# sesearch grammar for CONDITIONAL rules:
#   allow <source> <target>:<class> <perms>; [ <boolean> ]:True|False
# Permissions come ONLY from the rule's permission field; conditional
# metadata is kept SEPARATE: an ACTIVE conditional ([..​]:True) contributes
# its tokens to the effective set; an INACTIVE one ([..​]:False) contributes
# NOTHING (its rules do not fire) and is recorded as inactive; any unknown
# conditional form or malformed line is UNTRUSTED — never an effective
# grant and never an authoritative absence. Any nonzero exit (including
# timeout 124) is UNTRUSTED, never an authoritative empty result.
# Exercised by --policy-semantics-selftest; the Go tests judge the recorded
# verdicts. classify_sesearch_query <rc> <output> prints exactly one verdict:
#   trusted:perms=<tokens, deduped, sorted, space-joined>|cond-active=<b=True,...|none>|cond-inactive=<b=False,...|none>
#   untrusted:nonzero-exit-<rc>
#   untrusted:malformed-line(<line>)
classify_sesearch_query() { # <rc> <output>
  local rc="$1" out="$2" line rule p cond state cname tok
  local parts="" active="" inactive=""
  if [ -z "$rc" ] || [ "$rc" -ne 0 ] 2>/dev/null; then
    printf 'untrusted:nonzero-exit-%s\n' "${rc:-none}"
    return 0
  fi
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in
      'allow '*\ *:*) : ;;
      *) printf 'untrusted:malformed-line(%s)\n' "$line"; return 0 ;;
    esac
    rule="${line%%;*}"  # the rule itself, up to the FIRST ';'
    cond="${line#*;}"   # the conditional suffix (may be empty)
    p="${rule#allow * *:}"
    p="${p#* }"         # strip the class token
    p="${p#\{}"
    p="${p%\}}"
    p="${p% }"
    [ -n "${p// /}" ] || { printf 'untrusted:malformed-line(%s)\n' "$line"; return 0; }
    if [ -n "$cond" ]; then
      cond="$(printf '%s' "$cond" | sed 's/^ *//;s/ *$//')"
      case "$cond" in
        '['*']':True | '['*']':False) : ;;
        *) printf 'untrusted:malformed-line(%s)\n' "$line"; return 0 ;;
      esac
      state="${cond##*:}"
      head="${cond%:*}"     # "[ boolean ]"
      cname="${head#\[}"
      cname="${cname%]}"
      cname="${cname# }"
      cname="${cname% }"
      [ -n "$cname" ] || { printf 'untrusted:malformed-line(%s)\n' "$line"; return 0; }
      if [ "$state" = True ]; then
        active="${active:+$active,}$cname=True"
        for tok in $p; do
          parts="$parts $tok"
        done
      else
        inactive="${inactive:+$inactive,}$cname=False"
      fi
    else
      for tok in $p; do
        parts="$parts $tok"
      done
    fi
  done <<EOF
$out
EOF
  local perms ca ci
  perms="$(printf '%s' "$parts" | tr ' \t' '\n\n' | sed '/^$/d' | sort -u | tr '\n' ' ' | sed 's/^ //;s/ $//')"
  ca="${active:-none}"; ci="${inactive:-none}"
  ca="${ca#,}"; ci="${ci#,}"
  printf 'trusted:perms=%s|cond-active=%s|cond-inactive=%s\n' "$perms" "$ca" "$ci"
}

# classify_pp_extraction <rpm2cpio_rc> <cpio_rc> <member-present> — the
# EXACT stage classifier the policy gate calls, distinguishing the four
# required outcomes (all failure classes block):
#   blocked:rpm-conversion-failed(rc=<n>)  — rpm2cpio itself failed
#   blocked:cpio-extraction-failed(rc=<n>) — the cpio stage failed
#   blocked:member-missing                 — extraction succeeded, no member
#   member-found                           — the member is available for the
#                                            byte comparison
classify_pp_extraction() { # <rpm2cpio_rc> <cpio_rc> <member-present>
  local rc1="$1" rc2="$2" found="$3"
  case "$rc1" in '' | *[!0-9]*)
    printf 'blocked:rpm-conversion-failed(rc=%s)\n' "${rc1:-none}"; return 0 ;;
  esac
  # rpm2cpio 4.18 can return 1 with a complete payload. The extraction
  # stage runs in that case only if a stream was written.
  if [ "$rc1" != 0 ] && { [ "$rc1" != 1 ] || [ "$rc2" = none ]; }; then
    printf 'blocked:rpm-conversion-failed(rc=%s)\n' "$rc1"; return 0
  fi
  case "$rc2" in '' | *[!0-9]*)
    printf 'blocked:cpio-extraction-failed(rc=%s)\n' "${rc2:-none}"; return 0 ;;
  esac
  if [ "$rc2" != 0 ]; then
    printf 'blocked:cpio-extraction-failed(rc=%s)\n' "$rc2"; return 0
  fi
  case "$found" in
    0) printf 'blocked:member-missing\n' ;;
    1) printf 'member-found\n' ;;
    *) printf 'blocked:member-missing\n' ;;
  esac
}

# The stage decision vocabulary above keeps every extraction failure
# BLOCKED; the policy gate maps each reason into POLICY-GATE: FAIL with the
# named stage and records the separate rpm2cpio/cpio exit statuses and
# unpolluted stderr tails in the evidence log.

extract_p21e3_rpm_members() { # <rpmfile> <private workdir>
  local rpm="$1" work="$2" stage
  RPM2CPIO_RC=none
  CPIO_RC=none
  mkdir -p "$work/extract" || return 1
  if command -v rpm2cpio >/dev/null 2>&1 && command -v cpio >/dev/null 2>&1; then
    rpm2cpio "$rpm" >"$work/payload.cpio" 2>"$work/rpm2cpio.err" \
      && RPM2CPIO_RC=0 || RPM2CPIO_RC=$?
    if [ "$RPM2CPIO_RC" = 0 ] || { [ "$RPM2CPIO_RC" = 1 ] && [ -s "$work/payload.cpio" ]; }; then
      # nFPM uses absolute archive names. Match those explicitly, then
      # strip the leading slash on extraction into the private directory.
      (cd "$work/extract" && cpio -id --no-absolute-filenames \
        /usr/bin/docker-helper usr/bin/docker-helper ./usr/bin/docker-helper \
        /usr/share/selinux/docker_helper.pp usr/share/selinux/docker_helper.pp \
        ./usr/share/selinux/docker_helper.pp <"$work/payload.cpio") \
        >"$work/cpio.out" 2>"$work/cpio.err" && CPIO_RC=0 || CPIO_RC=$?
    fi
  fi
  printf 'rpm2cpio rc=%s cpio rc=%s\n' "$RPM2CPIO_RC" "$CPIO_RC" >&2
  for stage in rpm2cpio cpio; do
    if [ -s "$work/$stage.err" ]; then
      printf '%s\n' "--- $stage stderr (tail; no tokens) ---" >&2
      sed 's/dht_[A-Za-z0-9]*/[REDACTED-TOKEN]/g' "$work/$stage.err" | tail -5 >&2
    fi
  done
  [ "$CPIO_RC" = 0 ]
}

compare_p21e3_digests() {
  if ! [[ "$1" =~ ^[0-9a-f]{64}$ && "$2" =~ ^[0-9a-f]{64}$ ]]; then
    echo UNPROVABLE
  elif [ "$1" = "$2" ]; then
    echo MATCH
  else
    echo MISMATCH
  fi
}

p21e3_policy_semantics_selftest() { # <workdir>
  local work="$1"
  mkdir -p "$work/results"
  # 1. Valid policy with the three accepted slirp4netns permissions.
  classify_sesearch_query 0 \
    'allow docker_helper_slirp4netns_t docker_helper_slirp4netns_t:cap_userns { sys_ptrace sys_admin net_admin };' \
    >"$work/results/valid-three.classify"
  # 2. Valid query, but the required net_admin member is missing.
  classify_sesearch_query 0 \
    'allow docker_helper_slirp4netns_t docker_helper_slirp4netns_t:cap_userns { sys_ptrace sys_admin };' \
    >"$work/results/missing-netadmin.classify"
  # 3. Generic bin_t execute PRESENT (quarantine violated).
  classify_sesearch_query 0 \
    'allow docker_helper_rootlesskit_t bin_t:file execute;' \
    >"$work/results/quarantine-present.classify"
  # 4. Generic bin_t execute GENUINELY absent: a successful query with ZERO
  #    allow lines is the authoritative empty result.
  classify_sesearch_query 0 '' >"$work/results/quarantine-absent.classify"
  # 4b. Trusted query with a NON-execute allow (e.g. a read) — the set does
  #     not carry the execute token, so the quarantine still holds.
  classify_sesearch_query 0 \
    'allow docker_helper_rootlesskit_t bin_t:file { getattr read };' \
    >"$work/results/quarantine-read-only.classify"
  # 8..10: the ACTUAL R2 live sesearch response shapes (conditional rules),
  #        which the previous grammar smeared into permission tokens.
  # 8. The exact live conditional rule from the R2 gate log: an ACTIVE
  #    (domain_can_mmap_files=True) bin_t:file map allow — map is in the
  #    effective set and the condition is metadata, never a token.
  classify_sesearch_query 0 \
    'allow domain file_type:file map; [ domain_can_mmap_files ]:True' \
    >"$work/results/live-conditional-active.classify"
  # 9. An INACTIVE conditional: the rule does not fire, so its token is NOT
  #    an effective grant and is recorded separately.
  classify_sesearch_query 0 \
    'allow docker_helper_rootlesskit_t bin_t:file execute; [ example_boolean ]:False' \
    >"$work/results/live-conditional-inactive.classify"
  # 10. An unknown conditional suffix form is UNTRUSTED (not an effective
  #     grant and not an authoritative absence).
  classify_sesearch_query 0 \
    'allow docker_helper_rootlesskit_t bin_t:file execute; [ example_boolean ]:MAYBE' \
    >"$work/results/conditional-unknown-form.classify"
  # 5. sesearch execution error (nonzero exit, error text on output).
  classify_sesearch_query 1 'Error: SELinux policy is not managed or store cannot be reached.' \
    >"$work/results/exec-error.classify"
  # 6. sesearch timeout (timeout(1) exit 124; possibly truncated/no output).
  classify_sesearch_query 124 '' >"$work/results/timeout.classify"
  # 7. Unreadable/malformed response (rc 0 but not an allow response).
  classify_sesearch_query 0 'error: cannot open /sys/fs/selinux/policy: No such file' \
    >"$work/results/malformed.classify"

  # The extraction-stage classifier: the four required outcomes.
  classify_pp_extraction 0 0 1 >"$work/results/extract-member-found.classify"
  classify_pp_extraction 0 0 0 >"$work/results/extract-member-missing.classify"
  classify_pp_extraction 0 2 1 >"$work/results/extract-cpio-failed.classify"
  classify_pp_extraction 1 none 0 >"$work/results/extract-conversion-failed.classify"
  classify_pp_extraction 1 0 1 >"$work/results/extract-conversion-rc1-member-found.classify"
  classify_pp_extraction 1 2 1 >"$work/results/extract-conversion-rc1-cpio-failed.classify"
  classify_pp_extraction 124 0 1 >"$work/results/extract-conversion-timeout.classify"
}

# --pp-extract-selftest <workdir> [<rpmfile>]: exercises the REAL staged
# extraction used by the policy gate. With rpm2cpio+cpio available AND a
# real RPM provided, the full gate path runs (conversion -> cpio -> member
# presence -> sha) and both member digests land in results/.
# Without rpm tooling, the cpio stage is exercised on a self-synthesized
# fixture (member present / member missing / truncated cpio) and the
# tool-unavailability branch is recorded instead of guessed.
p21e3_pp_extract_selftest() { # <workdir> [<rpmfile>]
  local work="$1" rpm="${2:-}"
  local dir="$work/pp-check"
  mkdir -p "$work/results" "$dir/extract"
  {
    printf 'rpm2cpio=%s\n' "$(command -v rpm2cpio || echo missing)"
    printf 'cpio=%s (%s)\n' "$(command -v cpio || echo missing)" \
      "$(cpio --version 2>/dev/null | head -1 || echo 'version unknown')"
  } >"$work/results/tools.ident"
  if [ -n "$rpm" ]; then
    extract_p21e3_rpm_members "$rpm" "$dir" 2>"$work/results/extract.stages" || return 1
    [ -s "$dir/extract/usr/bin/docker-helper" ] && \
      [ -s "$dir/extract/usr/share/selinux/docker_helper.pp" ] || return 1
    sha256sum "$dir/extract/usr/bin/docker-helper" >"$work/results/member.binary.sha256" || return 1
    sha256sum "$dir/extract/usr/share/selinux/docker_helper.pp" >"$work/results/member.pp.sha256" || return 1
    cp "$dir/extract/usr/share/selinux/docker_helper.pp" "$work/results/member.pp"
    return $?
  fi
  # cpio-stage fixtures (no rpm2cpio here): synthesize a minimal archive.
  if command -v cpio >/dev/null 2>&1; then
    mkdir -p "$dir/src/usr/share/selinux" "$dir/src/usr/share/doc" \
      "$dir/extract-found" "$dir/extract-miss" "$dir/extract-trunc" \
      "$dir/src-miss/usr/share/doc"
    printf 'fixture-module-content\n' >"$dir/src/usr/share/selinux/docker_helper.pp"
    printf 'other\n' >"$dir/src/usr/share/doc/other"
    # Paths include their parent dirs so plain `cpio -id` recreates them.
    (cd "$dir/src" && printf 'usr/share/selinux/docker_helper.pp\nusr/share/doc/other\n' \
      | cpio -o -H newc 2>/dev/null) >"$dir/fixture.cpio" || true
    (cd "$dir/extract-found" && cpio -id <"$dir/fixture.cpio" 2>/dev/null)
    printf 'other\n' >"$dir/src-miss/usr/share/doc/other"
    (cd "$dir/src-miss" && printf 'usr/share/doc/other\n' | cpio -o -H newc 2>/dev/null) >"$dir/fixture-missing.cpio" || true
    (cd "$dir/extract-miss" && cpio -id <"$dir/fixture-missing.cpio" 2>/dev/null)
    head -c 100 "$dir/fixture.cpio" >"$dir/fixture-truncated.cpio" 2>/dev/null || true
    (cd "$dir/extract-trunc" && cpio -id <"$dir/fixture-truncated.cpio" 2>/dev/null); TRUNC_RC=$?
    if [ -f "$dir/extract-found/usr/share/selinux/docker_helper.pp" ]; then
      sha256sum "$dir/extract-found/usr/share/selinux/docker_helper.pp" >"$work/results/fixture.member-found.sha256"
      cp "$dir/extract-found/usr/share/selinux/docker_helper.pp" "$work/results/fixture.member.pp"
    else
      echo "FIXTURE-DEFECT: the member-found fixture did not extract the member" >"$work/results/fixture.member-found.sha256"
    fi
    if [ -f "$dir/extract-miss/usr/share/selinux/docker_helper.pp" ]; then
      echo "fixture MISSING-membership: wrongly extracted" >"$work/results/fixture.member-missing.txt"
    else
      # Either cpio refuses a member-less archive or succeeds extracting
      # nothing — both classify as blocked (member-missing is decisive).
      printf 'fixture member-missing: confirmed absent (cpio rc=%s)\n' "$?" \
        >"$work/results/fixture.member-missing.txt"
    fi
    if (cd "$dir/extract-trunc" && [ -f usr/share/selinux/docker_helper.pp ]); then
      echo "fixture truncated: wrongly extracted" >"$work/results/fixture.cpio-failed.txt"
    else
      printf 'fixture truncated-extraction: cpio rc=%s — no member; the gate blocks (cpio-failed or member-missing, both fail-closed)\n' "${TRUNC_RC:-none}" \
        >"$work/results/fixture.cpio-failed.txt"
    fi
  else
    echo "no cpio available; the cpio-stage fixtures cannot run" >"$work/results/tools-unavailable.txt"
  fi
}

if [ "${1:-}" = "--policy-semantics-selftest" ]; then
  [ -n "${2:-}" ] || fail "usage: $0 --policy-semantics-selftest <workdir>"
  p21e3_policy_semantics_selftest "$2"
  exit $?
fi

if [ "${1:-}" = "--pp-extract-selftest" ]; then
  [ -n "${2:-}" ] || fail "usage: $0 --pp-extract-selftest <workdir> [<rpmfile>]"
  p21e3_pp_extract_selftest "$2" "${3:-}"
  exit $?
fi

if [ "${1:-}" = "--audit-window-selftest" ]; then
  [ -n "${2:-}" ] || fail "usage: $0 --audit-window-selftest <workdir>"
  p21e3_audit_window_selftest "$2"
  exit $?
fi

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

ARTIFACT="${R7_ARTIFACT:?R7_ARTIFACT required}"
ARTIFACT_SHA="${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"
EVIDENCE_DIR="${R7_EVIDENCE_DIR:-/tmp/r7-p21e3-evidence}"
STATE_DIR=/tmp/r7-p21e3-state
mkdir -p "$EVIDENCE_DIR" "$STATE_DIR"
DH_SOCK=/run/docker-helper/docker-helper.sock
BUILDER_STATE_ROOT=/var/lib/docker-helper-builder
AUDIT_LOG_PATH=/var/log/audit/audit.log
STRACE_TIMEOUT=120

# ---------------------------------------------------------------------------
# Section 1: platform + SELinux enforcing proof
# ---------------------------------------------------------------------------
if [ -f "$STATE_DIR/sec1" ]; then log "phase marker: section 1 done; skipping"; else
log "=== section 1: platform + enforcing ==="
ENF="$(getenforce 2>/dev/null || echo absent)"
[ "$ENF" = "Enforcing" ] || fail "SELinux not enforcing (getenforce='$ENF')"
cat /sys/kernel/security/lsm >"$EVIDENCE_DIR/lsm.txt" 2>&1 || true
grep -qw selinux "$EVIDENCE_DIR/lsm.txt" || fail "selinux not an active LSM"
cap p21e3-se-status 8 bash -c 'sestatus; echo ---; getenforce; id -Z'
cat /etc/os-release >"$EVIDENCE_DIR/os-release.txt" 2>&1
grep -qi 'opensuse tumbleweed' "$EVIDENCE_DIR/os-release.txt" || fail "not openSUSE Tumbleweed"
cap p21e3-platform 4 bash -c 'uname -a'
touch "$STATE_DIR/sec1"
fi

# ---------------------------------------------------------------------------
# Section 2: exact candidate install (never rebuilds)
# ---------------------------------------------------------------------------
if [ -f "$STATE_DIR/sec2" ]; then log "phase marker: section 2 done; skipping"; else
log "=== section 2: candidate install (rpm) ==="
[ -f "$ARTIFACT" ] || fail "artifact missing: $ARTIFACT"
now_sha="$(sha256sum "$ARTIFACT" | awk '{print $1}')"
[ "$now_sha" = "$ARTIFACT_SHA" ] || fail "artifact SHA mismatch (expected $ARTIFACT_SHA, got $now_sha)"
rpm -q docker-helper >/dev/null 2>&1 && rpm -e docker-helper >/dev/null 2>&1 || true
rpm -i "$ARTIFACT" || fail "rpm -i failed"
log "RPM installed: $(rpm -q docker-helper)"
sha256sum "$ARTIFACT" > "$EVIDENCE_DIR/candidate-rpm-sha256.log"
# No unexpected package/runtime fallback: record the distro runtime
# package state (informational; the flow never selects it — the shipped
# policy denies the bin_t exec from the daemon domain).
rpm -q runc >"$EVIDENCE_DIR/distro-runc-package.log" 2>&1 || true
command -v runc >"$EVIDENCE_DIR/distro-runc-path.log" 2>&1 || true
PRINCIPAL="${SUDO_USER:-}"
[ -n "$PRINCIPAL" ] && [ "$PRINCIPAL" != "root" ] || fail "cannot derive non-root principal"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
[ -n "$PRINCIPAL_HOME" ] && [ -d "$PRINCIPAL_HOME" ] || fail "principal home not found"
# SECURITY — the generated admin token must never reach the guest
# console or the workflow artifact: docker-helper init prints it to
# stdout on success. The output is captured to a private file that is
# NOT part of the evidence set; only a token-free indication (whether
# the init succeeded) is logged, and the token itself is read from
# /etc/docker-helper/admin.token below.
INIT_OUT="$STATE_DIR/init.out"
if docker-helper init --allowed-root "$PRINCIPAL_HOME" >"$INIT_OUT" 2>&1; then
  rm -f "$INIT_OUT"
  echo "docker-helper init: success (admin token withheld from the evidence set)"
else
  rc=$?
  sed -e 's/dht_[A-Za-z0-9]*/[REDACTED-TOKEN]/g' "$INIT_OUT" | tail -5
  rm -f "$INIT_OUT"
  fail "docker-helper init failed (rc=$rc)"
fi
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
cap p21e3-services 12 systemctl --no-pager --full status docker-helper.service docker-helper-builder.service
log "daemon ready on $DH_SOCK"
touch "$STATE_DIR/sec2"
fi

PRINCIPAL="${SUDO_USER:-}"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"

# ---------------------------------------------------------------------------
# Section 3: installed payload identity + executable labels (OBL-4)
# ---------------------------------------------------------------------------
if [ -f "$STATE_DIR/sec3" ]; then log "phase marker: section 3 done; skipping"; else
log "=== section 3: installed identity + labels (HARD GATE) ==="
# Byte identity: the wrapper payload member IS the product binary; the
# relocated pinned runtime matches the shipped MANIFEST digest. A
# mismatch is an explicit PRE-BUILD refusal: the measurement never runs
# on unproven candidate identity.
P_BIN=/usr/bin/docker-helper
P_WRAP=/usr/libexec/docker-helper/buildkit/buildkit-runc
P_RUNTIME=/usr/libexec/docker-helper/buildkit/runtime/buildkit-runc
MANIFEST=/usr/share/doc/docker-helper/buildkit/MANIFEST
IDENTITY_OK=1
RPM_MEMBERS_DIR=""
RPM_MEMBERS_OK=0
{
  echo "== byte identity (sha256, mode, inode) =="
  for p in "$P_BIN" "$P_WRAP" "$P_RUNTIME"; do
    printf '%s sha256=%s mode=%s inode=%s\n' "$p" \
      "$(sha256sum "$p" | awk '{print $1}')" \
      "$(stat -c '%a' "$p")" "$(stat -c '%d:%i' "$p")"
  done
  iw="$(sha256sum "$P_BIN" | awk '{print $1}')"
  gw="$(sha256sum "$P_WRAP" | awk '{print $1}')"
  gr="$(sha256sum "$P_RUNTIME" | awk '{print $1}')"
  mw="$(sed -n 's/^buildkit-runc-sha256=//p' "$MANIFEST")"
  wrapper_verdict="$(compare_p21e3_digests "$iw" "$gw")"
  if [ "$wrapper_verdict" = MATCH ]; then
    echo "wrapper==product: MATCH"
  else
    echo "wrapper==product: $wrapper_verdict ($iw vs $gw)"
    echo "IDENTITY-GATE: FAIL (installed wrapper is not the candidate product bytes)"
    IDENTITY_OK=0
  fi
  runtime_verdict="$(compare_p21e3_digests "$gr" "$mw")"
  if [ "$runtime_verdict" = MATCH ]; then
    echo "runtime==pinned-manifest: MATCH"
  else
    echo "runtime==pinned-manifest: $runtime_verdict (runtime=$gr manifest=${mw:-<unreadable>})"
    echo "IDENTITY-GATE: FAIL (the relocated runtime does not carry the pinned MANIFEST digest)"
    IDENTITY_OK=0
  fi

  # R4-P3-P6 run contract: the RUNNING daemon and builder manager must run
  # the candidate RPM's own binary member — the same bytes the RPM will be
  # measured against. Extracted member vs installed path vs live
  # /proc/<pid>/exe, all three sha256, every verdict recorded.
  rpm_file_sha="$(sha256sum "$ARTIFACT" | awk '{print $1}')"
  echo "rpm-file-sha256=$rpm_file_sha"
  if ! command -v rpm2cpio >/dev/null 2>&1; then
    timeout 300 zypper --non-interactive install -y rpm 2>&1 | tail -3
  fi
  if ! command -v cpio >/dev/null 2>&1; then
    timeout 300 zypper --non-interactive install -y cpio 2>&1 | tail -3
  fi
  printf 'rpm2cpio=%s\n' "$(command -v rpm2cpio || echo missing)"
  printf 'cpio=%s (%s)\n' "$(command -v cpio || echo missing)" \
    "$(cpio --version 2>/dev/null | head -1 || echo 'version unknown')"
  member_sha=""
  RPM2CPIO_RC=none
  CPIO_RC=none
  if [ "$rpm_file_sha" != "$ARTIFACT_SHA" ]; then
    printf 'candidate RPM digest differs from expected %s\n' "$ARTIFACT_SHA"
  elif RPM_MEMBERS_DIR="$(mktemp -d "$STATE_DIR/rpm-members.XXXXXX")" \
      && extract_p21e3_rpm_members "$ARTIFACT" "$RPM_MEMBERS_DIR"; then
    RPM_MEMBERS_OK=1
    if [ -s "$RPM_MEMBERS_DIR/extract/usr/bin/docker-helper" ]; then
      member_sha="$(sha256sum "$RPM_MEMBERS_DIR/extract/usr/bin/docker-helper" | awk '{print $1}')"
    fi
  fi

  echo "rpm-binary-member sha256=${member_sha:-<unavailable>}"
  installed_verdict="$(compare_p21e3_digests "$member_sha" "$iw")"
  printf 'rpm-member==installed: %s\n' "$installed_verdict"
  live_verdict="$installed_verdict"
  for service in daemon:docker-helper.service manager:docker-helper-builder.service; do
    who="${service%%:*}"
    unit="${service#*:}"
    p="$(systemctl show -p MainPID --value "$unit" 2>/dev/null)"
    live_sha=""
    if [[ "$p" =~ ^[1-9][0-9]*$ ]]; then
      live_sha="$(sha256sum "/proc/$p/exe" | awk '{print $1}')"
      printf 'live pid=%s exe=%s sha256=%s\n' "$p" "$(readlink "/proc/$p/exe")" \
        "${live_sha:-<unavailable>}"
    fi
    verdict="$(compare_p21e3_digests "$member_sha" "$live_sha")"
    printf '%s exe==rpm-member: %s (pid=%s)\n' "$who" "$verdict" "${p:-<unavailable>}"
    if [ "$verdict" = MISMATCH ] || [ "$live_verdict" = MATCH ]; then
      live_verdict="$verdict"
    fi
  done
  echo "R7-P21E3-RPM-PROCESS-IDENTITY=$live_verdict"
  if [ "$live_verdict" != MATCH ]; then
    echo "IDENTITY-GATE: FAIL (candidate RPM process identity: $live_verdict)"
    IDENTITY_OK=0
  fi
} > "$EVIDENCE_DIR/p21e3-byte-identity.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-byte-identity.log"
# Actual labels vs the exact .fc expectations (OBL-4: live labels, never
# closed from compilation). The THREE dedicated exact-path rules of the
# D-2 layout are a HARD GATE: a mismatch is recorded as OBL-4 evidence
# and the measurement refuses to start — never repaired by hand, no
# additional policy loaded.
EXPECT_TYPE=docker_helper_buildkitd_exec_t
LABEL_OK=1
{
  echo "== the three expected exact-path .fc rules (actual vs policy) =="
  for p in "$P_WRAP" "$P_RUNTIME" /usr/libexec/docker-helper/buildkit/buildkitd; do
    actual="$(stat -L -c '%C' "$p" 2>/dev/null)"
    expected="$(matchpathcon -n "$p" 2>/dev/null)"
    if [ -z "$actual" ]; then
      printf '%s actual=<stat-failed> expected=%s => MISMATCH\n' "$p" "$expected"
      LABEL_OK=0
    elif [ "$actual" = "$expected" ]; then
      printf '%s actual=%s expected-label=%s => MATCH\n' "$p" "$actual" "${expected#*:object_r:}"
    elif [ -z "$expected" ]; then
      printf '%s actual=%s expected=<matchpathcon-failed> => MISMATCH\n' "$p" "$actual"
      LABEL_OK=0
    elif [ "${expected#*:object_r:}" = "$EXPECT_TYPE:s0" ] \
      && [ "${actual#*:object_r:}" = "$EXPECT_TYPE:s0" ]; then
      printf '%s actual=%s expected=%s => MATCH (type identical; identity fields differ)\n' "$p" "$actual" "$expected"
    else
      printf '%s actual=%s expected=%s => MISMATCH (OBL-4)\n' "$p" "$actual" "$expected"
      LABEL_OK=0
    fi
  done
  echo "== other payload/product members (recorded; not gated) =="
  stat -c '%N %C mode=%a inode=%d:%i' "$P_BIN" \
    /usr/libexec/docker-helper/buildkit/buildctl
  echo "== symlink/loop check =="
  find /usr/libexec/docker-helper/buildkit -type l -print
  echo "(no output above = no symlinks in the payload tree)"
  if [ "$LABEL_OK" != 1 ]; then
    echo "LABEL-GATE: FAIL — an exact-path payload member does not carry its .fc label (OBL-4 evidence)"
  else
    echo "LABEL-GATE: PASS"
  fi
} > "$EVIDENCE_DIR/p21e3-labels.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-labels.log"
cap p21e3-payload-manifest 12 cat /usr/share/doc/docker-helper/buildkit/MANIFEST
# Installed module identity.
{
  semodule -l 2>/dev/null | grep -i docker || true
  echo "---"
  sha256sum /usr/share/selinux/docker_helper.pp 2>/dev/null || true
  sha256sum /sys/fs/selinux/policy 2>/dev/null || true
} > "$EVIDENCE_DIR/p21e3-module.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-module.log"
# --- policy identity + loaded-policy semantics (the accepted widening's
# --- live effectiveness; a mismatch aborts the round as BLOCKED rather
# --- than being repaired). The CI-produced .pp is NOT required to equal
# --- any locally compiled digest: the source .pp is verified against the
# --- RPM MEMBER and the INSTALLED bytes, and the LOADED policy is read
# --- through sesearch.
PP_EXPECTED=1
{
  echo "== rpm member vs installed .pp bytes (staged, fail-closed) =="
  PP_MEMBER=""
  if [ "$RPM_MEMBERS_OK" = 1 ] && [ -s "$RPM_MEMBERS_DIR/extract/usr/share/selinux/docker_helper.pp" ]; then
    PP_MEMBER="$RPM_MEMBERS_DIR/extract/usr/share/selinux/docker_helper.pp"
  fi
  if [ -n "$PP_MEMBER" ]; then
    EXTRACT_VERDICT="$(classify_pp_extraction "$RPM2CPIO_RC" "$CPIO_RC" 1)"
  else
    EXTRACT_VERDICT="$(classify_pp_extraction "$RPM2CPIO_RC" "$CPIO_RC" 0)"
  fi
  echo "extraction verdict: $EXTRACT_VERDICT"
  echo "rpm2cpio/cpio stage diagnostics: p21e3-byte-identity.log"
  case "$EXTRACT_VERDICT" in
    member-found)
      rpm_pp="$(sha256sum "$PP_MEMBER" | awk '{print $1}')"
      inst_pp="$(sha256sum /usr/share/selinux/docker_helper.pp 2>/dev/null | awk '{print $1}')"
      echo "rpm-member  sha256=$rpm_pp"
      echo "installed   sha256=${inst_pp:-<missing>}"
      pp_verdict="$(compare_p21e3_digests "$rpm_pp" "$inst_pp")"
      if [ "$pp_verdict" = MATCH ]; then
        echo "rpm==installed: MATCH"
      else
        echo "rpm==installed: $pp_verdict"
        echo "POLICY-GATE: FAIL (installed module identity: $pp_verdict)"
        PP_EXPECTED=0
      fi
      ;;
    blocked:member-missing)
      echo "POLICY-GATE: FAIL (the payload extracted cleanly but carries no usr/share/selinux/docker_helper.pp member)"
      PP_EXPECTED=0
      ;;
    blocked:rpm-conversion-failed*)
      echo "POLICY-GATE: FAIL (the rpm2cpio conversion stage failed)"
      PP_EXPECTED=0
      ;;
    blocked:cpio-extraction-failed*)
      echo "POLICY-GATE: FAIL (the cpio extraction stage failed)"
      PP_EXPECTED=0
      ;;
    *)
      echo "POLICY-GATE: FAIL (the extraction verdict is not member-found)"
      PP_EXPECTED=0
      ;;
  esac
  if [ -n "$RPM_MEMBERS_DIR" ]; then
    rm -rf -- "$RPM_MEMBERS_DIR"
  fi
  echo "== loaded-policy semantics (fail-closed sesearch classification) =="
  if ! command -v sesearch >/dev/null 2>&1; then
    timeout 300 zypper --non-interactive install -y setools 2>&1 | tail -3
    command -v sesearch >/dev/null 2>&1 || echo "sesearch unavailable (the loaded-policy semantics cannot be verified manually)"
  fi
  if command -v sesearch >/dev/null 2>&1; then
    echo "--- slirp4netns self:cap_userns (expect exactly sys_ptrace sys_admin net_admin) ---"
    SLIRP_CAPS="$(timeout 60 sesearch -A -s docker_helper_slirp4netns_t \
      -t docker_helper_slirp4netns_t -c cap_userns 2>&1)"
    SLIRP_RC=$?
    printf 'query-rc=%s\n' "$SLIRP_RC"
    printf '%s\n' "$SLIRP_CAPS"
    SLIRP_VERDICT="$(classify_sesearch_query "$SLIRP_RC" "$SLIRP_CAPS")"
    echo "classify=$SLIRP_VERDICT"
    case "$SLIRP_VERDICT" in
      'trusted:perms=net_admin sys_admin sys_ptrace|cond-active=none|cond-inactive=none')
        echo "slirp4netns cap_userns: EXACT-MATCH (the accepted R4-P3-P4 widening is loaded and effective, unconditional)"
        ;;
      'trusted:'*)
        echo "slirp4netns cap_userns: WRONG-SHAPE (a TRUSTED response decided the classification, expected exactly net_admin sys_admin sys_ptrace with no conditionals)"
        echo "POLICY-GATE: FAIL (loaded policy does not carry precisely the accepted widening)"
        PP_EXPECTED=0
        ;;
      *)
        echo "slirp4netns cap_userns: QUERY-UNTRUSTED (error/timeout/malformed — never an authoritative absence)"
        echo "POLICY-GATE: FAIL (the loaded-policy query cannot be trusted)"
        PP_EXPECTED=0
        ;;
    esac
    echo "--- rootlesskit_t -> bin_t:file execute (the quarantine) ---"
    QUAR_CAPS="$(timeout 60 sesearch -A -s docker_helper_rootlesskit_t -t bin_t -c file 2>&1)"
    QUAR_RC=$?
    printf 'query-rc=%s\n' "$QUAR_RC"
    printf '%s\n' "$QUAR_CAPS"
    QUAR_VERDICT="$(classify_sesearch_query "$QUAR_RC" "$QUAR_CAPS")"
    echo "classify=$QUAR_VERDICT"
    case "$QUAR_VERDICT" in
      'trusted:'*)
        # Effective-permission tokens ONLY (active conditionals contribute;
        # inactive ones never fire and live in cond-inactive).
        QUAR_SET=" ${QUAR_VERDICT#trusted:perms=} "
        QUAR_SET="${QUAR_SET%%|cond-*} "
        case "$QUAR_SET" in
          *' execute '*)
            echo "rootlesskit bin_t quarantine: VIOLATED (a trusted response carries an effective execute grant)"
            echo "POLICY-GATE: FAIL (the deliberate bin_t quarantine was not preserved)"
            PP_EXPECTED=0
            ;;
          *)
            echo "rootlesskit bin_t quarantine: PRESERVED (trusted response; the execute token is genuinely absent from the effective set)"
            echo "conditionals: $QUAR_VERDICT"
            ;;
        esac
        ;;
      *)
        echo "rootlesskit bin_t quarantine: QUERY-UNTRUSTED (error/timeout/malformed — this is BLOCKED, never PRESERVED)"
        echo "POLICY-GATE: FAIL (the loaded-policy query cannot be trusted)"
        PP_EXPECTED=0
        ;;
    esac
    echo "--- buildkitd self:cap_userns (expect { sys_admin chown } and the P11 sys_chroot singleton) ---"
    BKD_CAPS="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t \
      -t docker_helper_buildkitd_t -c cap_userns 2>&1)"
    BKD_RC=$?
    printf 'query-rc=%s (informational)\nclassify=%s\n' "$BKD_RC" \
      "$(classify_sesearch_query "$BKD_RC" "$BKD_CAPS")"
    printf '%s\n' "$BKD_CAPS"
  else
    echo "POLICY-GATE: FAIL (loaded-policy semantics unverifiable: no sesearch)"
    PP_EXPECTED=0
  fi
} > "$EVIDENCE_DIR/p21e3-policy-semantics.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-policy-semantics.log"
# The gates decide BEFORE the measured build: an identity, label or
# loaded-policy mismatch aborts the round as BLOCKED (an aborted
# measurement decides BLOCKED, never success). Nothing is repaired by
# hand and no policy is loaded or reloaded.
if [ "$IDENTITY_OK" != 1 ] || [ "$LABEL_OK" != 1 ] || [ "$PP_EXPECTED" != 1 ]; then
  if [ "$IDENTITY_OK" != 1 ]; then
    GATE_REASON=identity
  elif [ "$LABEL_OK" != 1 ]; then
    GATE_REASON=label-obl4
  else
    GATE_REASON=policy-semantics
  fi
  printf 'R7-P21E3-VERDICT=BLOCKED\nR7-P21E3-BLOCKED-REASON=%s\n' "$GATE_REASON"
  fail "pre-build $GATE_REASON gate failed; the measurement refuses to start"
fi
touch "$STATE_DIR/sec3"
fi

# ---------------------------------------------------------------------------
# Section 4: the measurement tooling (sampler + strace + audit window)
# ---------------------------------------------------------------------------
if [ ! -x "$EVIDENCE_DIR/p21e3_proc_sampler" ] || [ ! -f "$STATE_DIR/sec4" ]; then
log "=== section 4: tooling build ==="
if ! command -v gcc >/dev/null 2>&1 || ! command -v strace >/dev/null 2>&1; then
  cap p21e3-toolchain 6 timeout 300 zypper --non-interactive install -y gcc strace acl
fi
command -v gcc >/dev/null 2>&1 || fail "gcc unavailable"
command -v strace >/dev/null 2>&1 || fail "strace unavailable"

cat > "$EVIDENCE_DIR/p21e3_proc_sampler.c" <<'CEOF'
/* p21e3_proc_sampler.c — the integration-measurement process sampler.
 *
 * Every SLEEP_MS, walks /proc and appends one TSVT line per relevant
 * process (comm/exe mentions runc, buildkit, or docker-helper): pid,
 * ppid, comm, exe (/proc/<pid>/exe readlink — the wrapper vs real-runtime
 * distinction across the execve: …/buildkit-runc vs
 * …/runtime/buildkit-runc), argv0, and the kernel context
 * (/proc/<pid>/attr/current — the OBL-6 execution contexts). Runs until
 * the stop file appears; output is bounded by the caller's build window.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>

static void wallstamp(char *b, size_t n) {
    struct timespec ts; struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts); gmtime_r(&ts.tv_sec, &tm);
    snprintf(b, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec/1000000);
}
static void monostamp(long long *ms) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    *ms = ts.tv_sec*1000LL + ts.tv_nsec/1000000;
}
static void perms(unsigned bits, char *out) {
    out[0] = (bits & 4) ? 'r' : '-';
    out[1] = (bits & 2) ? 'w' : '-';
    out[2] = (bits & 1) ? 'x' : '-';
    out[3] = '\0';
}
static void decode_acl(const unsigned char *raw, size_t n, char *acl, size_t acln) {
    size_t off = 0;
    if (n < 4 || raw[0] != 0x02 || raw[1] != 0x00) {
        snprintf(acl, acln, "acl=<malformed ver=%u.%u bytes=%zu>", raw[0], raw[1], n);
        return;
    }
#define SAMPAPPEND(...) do { \
    if (off < acln) off += snprintf(acl + off, acln - off, __VA_ARGS__); \
} while (0)
    SAMPAPPEND("acl=v2");
    for (size_t i = 4; i + 8 <= n; i += 8) {
        unsigned tag = raw[i] | (raw[i+1] << 8);
        unsigned perm = raw[i+2] | (raw[i+3] << 8);
        unsigned id = raw[i+4] | (raw[i+5] << 8) | (raw[i+6] << 16) | ((unsigned)raw[i+7] << 24);
        char p[4]; perms(perm, p);
        switch (tag) {
        case 0x0001: SAMPAPPEND(" user::%s", p); break;
        case 0x0002: SAMPAPPEND(" user:%u:%s", id, p); break;
        case 0x0004: SAMPAPPEND(" group::%s", p); break;
        case 0x0008: SAMPAPPEND(" group:%u:%s", id, p); break;
        case 0x0010: SAMPAPPEND(" mask::%s", p); break;
        case 0x0020: SAMPAPPEND(" other::%s", p); break;
        default:     SAMPAPPEND(" tag%x:%u:%s", tag, id, p); break;
        }
    }
#undef SAMPAPPEND
}
/* One read-only DAC snapshot record (born from R4-P3-P5-R1 step 2): for
 * each captured path: timestamp, path, dev:ino, mode, UID/GID, raw
 * access-ACL presence (xattr size), decoded full ACL, SELinux label. */
static void snapline(FILE *lg, const char *tag, const char *ts, long long t,
                     int pid, const char *path) {
    struct stat st; memset(&st, 0, sizeof st);
    int rc = lstat(path, &st);
    char sel[256] = "-";
    ssize_t xr = lgetxattr(path, "security.selinux", sel, sizeof sel - 1);
    if (xr > 0) sel[xr] = '\0'; else snprintf(sel, sizeof sel, "<lc=%ld>", (long)xr);
    char acl[1024] = "acl=<absent>";
    ssize_t ar = lgetxattr(path, "system.posix_acl_access", NULL, 0);
    if (ar > 0) {
        unsigned char raw[8192];
        size_t n = (size_t)ar <= sizeof raw ? (size_t)ar : sizeof raw;
        if (lgetxattr(path, "system.posix_acl_access", raw, n) == (ssize_t)n)
            decode_acl(raw, n, acl, sizeof acl);
        else
            snprintf(acl, sizeof acl, "acl=<read-fail bytes=%zu>", n);
    } else if (ar == 0) snprintf(acl, sizeof acl, "acl=<empty>");
    else snprintf(acl, sizeof acl, "acl=<xattr-rc=%ld errno=%d>", (long)ar, errno);
    if (rc == 0)
        fprintf(lg, "%s %s t=%lld pid=%d path=%s dev=%lu ino=%lu mode=%o uid=%u gid=%u size=%ld selinux=%s %s\n",
                tag, ts, t, pid, path, (unsigned long)st.st_dev, (unsigned long)st.st_ino,
                st.st_mode & 07777, st.st_uid, st.st_gid, (long)st.st_size, sel, acl);
    else
        fprintf(lg, "%s %s t=%lld pid=%d path=%s lstat=<rc=%d errno=%d> selinux=%s %s\n",
                tag, ts, t, pid, path, rc, errno, sel, acl);
}
/* The near-wrapper chain snapshot: the traverse chain the wrapper's
 * newfstatat crosses, snapshotted by the ROOT sampler in the same sweep
 * that first observes the wrapper (0700 parents cannot hide the chain
 * from root), as close to wrapper execution as the sweep allows. */
static void chain_snap(FILE *lg, const char *ts, long long t, int pid, const char *opid) {
    static const char *chain[2] = {
        "/var/lib/docker-helper",
        "/var/lib/docker-helper/dev-prep",
    };
    char opdir[256];
    for (int i = 0; i < 2; i++) snapline(lg, "WRAPPER-SNAP", ts, t, pid, chain[i]);
    if (opid[0]) {
        snprintf(opdir, sizeof opdir, "/var/lib/docker-helper/dev-prep/%s", opid);
        snapline(lg, "WRAPPER-SNAP", ts, t, pid, opdir);
    }
}
static int readline(const char *path, char *buf, size_t n) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t r;
    if (fd < 0) return -1;
    r = read(fd, buf, n - 1);
    close(fd);
    if (r < 0) return -1;
    buf[r > 0 ? r : 0] = '\0';
    while (r > 0 && (buf[r-1] == '\n' || buf[r-1] == '\0')) buf[--r] = '\0';
    return (int)r;
}
static int readlinkstr(const char *path, char *buf, size_t n) {
    ssize_t r = readlink(path, buf, n - 1);
    if (r < 0) { buf[0] = '\0'; return -1; }
    buf[r] = '\0';
    return (int)r;
}
static int relevant(const char *s) {
    return strstr(s, "runc") || strstr(s, "buildkit") ||
           strstr(s, "docker-helper");
}
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <logfile> <stopfile>\n", argv[0]); return 2; }
    FILE *lg = fopen(argv[1], "a");
    if (!lg) return 2;
    long long t = 0;
    char ts[40], comm[256], exe[PATH_MAX], argv0[2048], ctx[512], statline[2048];
    /* The SAMPLER-START banner is the deterministic confirmation signal the
     * caller checks BEFORE POST /build: the sampler is running, its first
     * sweep is imminent or done.
     */
    wallstamp(ts, sizeof ts);
    monostamp(&t);
    fprintf(lg, "SAMPLER-START %s t=%lld\n", ts, t);
    fflush(lg);
    for (;;) {
        FILE *stopf;
        DIR *d;
        struct dirent *e;
        monostamp(&t);
        stopf = fopen(argv[2], "r");
        if (stopf) { fclose(stopf); break; }
        d = opendir("/proc");
        if (!d) break;
        while ((e = readdir(d)) != NULL) {
            char pcomm[64], pexe[64], pcmd[128], pctx[64], pstat[64];
            pid_t pid;
            if (strspn(e->d_name, "0123456789") != strlen(e->d_name)) continue;
            pid = (pid_t)atoi(e->d_name);
            snprintf(pcomm, sizeof pcomm, "/proc/%s/comm", e->d_name);
            if (readline(pcomm, comm, sizeof comm) < 0) continue;
            snprintf(pexe, sizeof pexe, "/proc/%s/exe", e->d_name);
            readlinkstr(pexe, exe, sizeof exe);
            snprintf(pcmd, sizeof pcmd, "/proc/%s/cmdline", e->d_name);
            if (readline(pcmd, argv0, sizeof argv0) < 0) argv0[0] = '\0';
            /* replacing NUL separators with spaces for one-line records */
            for (size_t i = 0; argv0[i]; i++) if (argv0[i] == '\0') argv0[i] = ' ';
            snprintf(pctx, sizeof pctx, "/proc/%s/attr/current", e->d_name);
            if (readline(pctx, ctx, sizeof ctx) < 0) ctx[0] = '\0';
            snprintf(pstat, sizeof pstat, "/proc/%s/stat", e->d_name);
            long long ppid = -1;
            if (readline(pstat, statline, sizeof statline) >= 0) {
                char *cl = strrchr(statline, ')');
                if (cl) sscanf(cl + 2, " %*c %*d %lld", &ppid);
            }
            if (!relevant(comm) && !relevant(exe) && !relevant(argv0)) continue;
            wallstamp(ts, sizeof ts);
            fprintf(lg, "PROC %s t=%lld pid=%d ppid=%lld comm=%s exe=%s argv0=%s ctx=%s\n",
                    ts, t, pid, ppid, comm, exe, argv0, ctx);
            /* The wrapper-credential capture (R4-P3-P5): for every observed
             * process whose exe names the wrapper/real-runtime, read the
             * real DAC credentials and namespace mapping ONCE per pid (the
             * ladder evidence needs host-uid vs the ACL's named builder
             * entry). A sample as short as ~20ms still lands: the read
             * happens in the SAME sweep that observed the process.
             */
            if (strstr(exe, "buildkit-runc") != NULL) {
                /* The near-wrapper DAC chain snapshot (R4-P3-P5-R1 step 2):
                 * the sampler runs as root, so the 0700 state root cannot
                 * hide the chain; the op id is derived from the wrapper's
                 * own bundle argument, never guessed. */
                char opid[48] = "";
                char *ops = strstr(argv0, "/op_");
                if (ops) {
                    size_t oi = 0;
                    char c;
                    ops += 1; /* skip the '/', leaving "op_..." */
                    while (oi + 1 < sizeof opid && (c = ops[oi]) != '\0' &&
                           (c == '_' || (c >= '0' && c <= '9') ||
                            (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
                        opid[oi++] = c;
                    opid[oi] = '\0';
                }
                chain_snap(lg, ts, t, pid, opid);
                char umap[256], gmap[256], pline[64], lb[512], nsline[128], nsid[256];
                FILE *mf;
                snprintf(umap, sizeof umap, "/proc/%s/uid_map", e->d_name);
                snprintf(gmap, sizeof gmap, "/proc/%s/gid_map", e->d_name);
                mf = fopen(umap, "r");
                if (mf) {
                    if (fgets(lb, sizeof lb, mf))
                        fprintf(lg, "PROCDETAIL %s t=%lld pid=%d uid_map=%s", ts, t, pid, lb);
                    else
                        fprintf(lg, "PROCDETAIL %s t=%lld pid=%d uid_map=<empty>\n", ts, t, pid);
                    fclose(mf);
                }
                mf = fopen(gmap, "r");
                if (mf) {
                    if (fgets(lb, sizeof lb, mf))
                        fprintf(lg, "PROCDETAIL %s t=%lld pid=%d gid_map=%s", ts, t, pid, lb);
                    else
                        fprintf(lg, "PROCDETAIL %s t=%lld pid=%d gid_map=<empty>\n", ts, t, pid);
                    fclose(mf);
                }
                snprintf(pline, sizeof pline, "/proc/%s/status", e->d_name);
                mf = fopen(pline, "r");
                if (mf) {
                    char ppidline[512] = "";
                    int have_uid = 0;
                    while (fgets(lb, sizeof lb, mf)) {
                        if (strncmp(lb, "Uid:", 4) == 0) {
                            lb[strcspn(lb, "\n")] = 0;
                            fprintf(lg, "PROCDETAIL %s t=%lld pid=%d status_uid=\"%s\"\n", ts, t, pid, lb);
                            have_uid = 1;
                            break;
                        }
                        if (strncmp(lb, "PPid:", 5) == 0) {
                            lb[strcspn(lb, "\n")] = 0;
                            snprintf(ppidline, sizeof ppidline, "%s", lb);
                        }
                    }
                    if (!have_uid && ppidline[0])
                        fprintf(lg, "PROCDETAIL %s t=%lld pid=%d %s (uid line not reached)\n", ts, t, pid, ppidline);
                    fclose(mf);
                }
                /* Namespace identity for the same pid: user = the userns
                 * mapping carrier, mnt = the mount namespace the mapped
                 * IDs resolve against. Both are directly observed, never
                 * inferred. */
                snprintf(nsline, sizeof nsline, "/proc/%s/ns/user", e->d_name);
                if (readlinkstr(nsline, nsid, sizeof nsid) > 0)
                    fprintf(lg, "PROCDETAIL %s t=%lld pid=%d ns_user=%s\n", ts, t, pid, nsid);
                snprintf(nsline, sizeof nsline, "/proc/%s/ns/mnt", e->d_name);
                if (readlinkstr(nsline, nsid, sizeof nsid) > 0)
                    fprintf(lg, "PROCDETAIL %s t=%lld pid=%d ns_mnt=%s\n", ts, t, pid, nsid);
            }
            /* The buildkitd credential capture (R4-P3-P5-R1 step 3): the
             * live buildkitd's uid_map/gid_map/status and namespace
             * identities, ONCE per pid (dedup; buildkitd is long-lived). */
            else if (strstr(comm, "buildkitd") != NULL || strstr(exe, "buildkitd") != NULL ||
                     strstr(argv0, "buildkitd") != NULL) {
                static int seen_pids[128];
                static int seen_n;
                int was_seen = 0;
                for (int i = 0; i < seen_n; i++)
                    if (seen_pids[i] == pid) { was_seen = 1; break; }
                if (!was_seen && seen_n < 128) {
                    seen_pids[seen_n++] = pid;
                    char umap[256], gmap[256], pline[64], lb[512], nsline[128], nsid[256];
                    FILE *mf;
                    /* Gid too: the full status output, both identity lines
                     * plus the namespace ids, all directly observed. */
                    snprintf(umap, sizeof umap, "/proc/%s/uid_map", e->d_name);
                    snprintf(gmap, sizeof gmap, "/proc/%s/gid_map", e->d_name);
                    if ((mf = fopen(umap, "r")) != NULL) {
                        while (fgets(lb, sizeof lb, mf))
                            fprintf(lg, "PROCDETAIL-BUILDKITD %s t=%lld pid=%d uid_map=%s", ts, t, pid, lb);
                        fclose(mf);
                    }
                    if ((mf = fopen(gmap, "r")) != NULL) {
                        while (fgets(lb, sizeof lb, mf))
                            fprintf(lg, "PROCDETAIL-BUILDKITD %s t=%lld pid=%d gid_map=%s", ts, t, pid, lb);
                        fclose(mf);
                    }
                    snprintf(pline, sizeof pline, "/proc/%s/status", e->d_name);
                    if ((mf = fopen(pline, "r")) != NULL) {
                        while (fgets(lb, sizeof lb, mf)) {
                            if (strncmp(lb, "Uid:", 4) == 0 || strncmp(lb, "Gid:", 4) == 0) {
                                lb[strcspn(lb, "\n")] = 0;
                                fprintf(lg, "PROCDETAIL-BUILDKITD %s t=%lld pid=%d status_%s\n",
                                        ts, t, pid, lb);
                            }
                        }
                        fclose(mf);
                    }
                    snprintf(nsline, sizeof nsline, "/proc/%s/ns/user", e->d_name);
                    if (readlinkstr(nsline, nsid, sizeof nsid) > 0)
                        fprintf(lg, "PROCDETAIL-BUILDKITD %s t=%lld pid=%d ns_user=%s\n", ts, t, pid, nsid);
                    snprintf(nsline, sizeof nsline, "/proc/%s/ns/mnt", e->d_name);
                    if (readlinkstr(nsline, nsid, sizeof nsid) > 0)
                        fprintf(lg, "PROCDETAIL-BUILDKITD %s t=%lld pid=%d ns_mnt=%s\n", ts, t, pid, nsid);
                }
            }
        }
        closedir(d);
        fflush(lg);
        struct timespec slp = {0, 20 * 1000 * 1000};
        nanosleep(&slp, NULL);
    }
    wallstamp(ts, sizeof ts);
    fprintf(lg, "SAMPLER-DONE %s t=%lld\n", ts, t);
    fclose(lg);
    return 0;
}
CEOF
gcc -O2 -Wall -o "$EVIDENCE_DIR/p21e3_proc_sampler" "$EVIDENCE_DIR/p21e3_proc_sampler.c" \
  || fail "sampler compile failed"
log "sampler compiled"

# The prepared-tree event watcher (R4-P3-P5): the per-operation directory
# under /var/lib/docker-helper/dev-prep lives only for the length of the
# operation, so its owner/mode/label/ACL state must be captured AT THE
# EVENTS. READ-ONLY: inotify watch + stat + getxattr — never a write,
# chmod, chown or relabel.
cat > "$EVIDENCE_DIR/p21e3_devprep_watcher.c" <<'WCEOF'
/* p21e3_devprep_watcher.c — the R4-P3-P5-R1 prepared-tree event watcher.
 *
 * Watches the EXISTING canonical state root (/var/lib/docker-helper, the
 * traverse-chain root, argv[1]) read-only via inotify, and adaptively
 * attaches secondary watches as the dev-prep subtree is created during a
 * build. For every relevant event it records a read-only snapshot:
 * timestamp, path, dev:ino, mode, UID/GID, raw access-ACL presence and
 * decoded named-user ACL/mask, and the SELinux label. The watcher never
 * writes, chmods, chowns or relabels anything. Runs until the stop file
 * (argv[2]) appears.
 *
 * Observed event kinds (all reported explicitly, including limitations):
 *   WATCHER-START     watcher started and the root watch attached
 *   WATCHER-ATTACH    a secondary watch was (or could not be) attached
 *   DEVSNAP           a read-only snapshot of a path
 *   DEVEVENT          an inotify event on a watched path
 *   WATCHER-OVERFLOW  the inotify queue overflowed (events missed)
 *   WATCHER-DONE      watcher stopped
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#define MAXWATCH 64
#define WALTSZ 40

static int watches[MAXWATCH];
static char wdpaths[MAXWATCH][512];
static int nwatch = 0;
static const char *wdpath(int wd) {
    for (int i = 0; i < nwatch; i++)
        if (watches[i] == wd) return wdpaths[i];
    return "";
}

static void wallstamp(char *b, size_t n) {
    struct timespec ts; struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts); gmtime_r(&ts.tv_sec, &tm);
    snprintf(b, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec/1000000);
}

/* Format three permission bits read-only. */
static void perms(unsigned bits, char *out) {
    out[0] = (bits & 4) ? 'r' : '-';
    out[1] = (bits & 2) ? 'w' : '-';
    out[2] = (bits & 1) ? 'x' : '-';
    out[3] = '\0';
}

/* Decode one access-ACL body (getxattr("system.posix_acl_access")) into
 * acl: "acl=v2 user::<p> user:<uid>:<p> ... mask::<p>|<nomask> other::<p>".
 * Covers named users AND named groups; the named-uid search entry the
 * preparer's contract installs is therefore directly visible. */
static void decode_acl(const unsigned char *raw, size_t n, char *acl, size_t acln) {
    size_t off = 0;
    if (n < 4 || raw[0] != 0x02 || raw[1] != 0x00) {
        snprintf(acl, acln, "acl=<malformed ver=%u.%u bytes=%zu>", raw[0], raw[1], n);
        return;
    }
#define APPEND(...) do { \
    if (off < acln) off += snprintf(acl + off, acln - off, __VA_ARGS__); \
} while (0)
    APPEND("acl=v2");
    for (size_t i = 4; i + 8 <= n; i += 8) {
        unsigned tag = raw[i] | (raw[i+1] << 8);
        unsigned perm = raw[i+2] | (raw[i+3] << 8);
        unsigned id = raw[i+4] | (raw[i+5] << 8) | (raw[i+6] << 16) | ((unsigned)raw[i+7] << 24);
        char p[4]; perms(perm, p);
        switch (tag) {
        case 0x0001: APPEND(" user::%s", p); break;
        case 0x0002: APPEND(" user:%u:%s", id, p); break;
        case 0x0004: APPEND(" group::%s", p); break;
        case 0x0008: APPEND(" group:%u:%s", id, p); break;
        case 0x0010: APPEND(" mask::%s", p); break;
        case 0x0020: APPEND(" other::%s", p); break;
        default:     APPEND(" tag%x:%u:%s", tag, id, p); break;
        }
    }
#undef APPEND
}

/* Snapshot ONE path read-only: lstat + security.selinux + access ACL. */
static void snap(FILE *lg, char *ts, const char *path) {
    struct stat st; memset(&st, 0, sizeof st);
    int rc = lstat(path, &st);
    char sel[256] = "-";
    ssize_t xr = lgetxattr(path, "security.selinux", sel, sizeof sel - 1);
    if (xr > 0) sel[xr] = '\0'; else snprintf(sel, sizeof sel, "<lc=%ld>", (long)xr);
    char acl[1024] = "acl=<absent>";
    ssize_t ar = lgetxattr(path, "system.posix_acl_access", NULL, 0);
    if (ar > 0) {
        unsigned char raw[8192];
        size_t n = (size_t)ar <= sizeof raw ? (size_t)ar : sizeof raw;
        if (lgetxattr(path, "system.posix_acl_access", raw, n) == (ssize_t)n)
            decode_acl(raw, n, acl, sizeof acl);
        else
            snprintf(acl, sizeof acl, "acl=<read-fail bytes=%zu>", n);
    } else if (ar == 0) {
        snprintf(acl, sizeof acl, "acl=<empty>");
    } else {
        snprintf(acl, sizeof acl, "acl=<xattr-rc=%ld errno=%d>", (long)ar, errno);
    }
    wallstamp(ts, WALTSZ);
    if (rc == 0)
        fprintf(lg, "DEVSNAP %s path=%s dev=%lu ino=%lu mode=%o uid=%u gid=%u size=%ld selinux=%s %s\n",
                ts, path, (unsigned long)st.st_dev, (unsigned long)st.st_ino,
                st.st_mode & 07777, st.st_uid, st.st_gid, (long)st.st_size, sel, acl);
    else
        fprintf(lg, "DEVSNAP %s path=%s lstat=<rc=%d errno=%d> selinux=%s %s\n",
                ts, path, rc, errno, sel, acl);
    fflush(lg);
}

static int attach_watch(int fd, FILE *lg, char *ts, const char *path) {
    int wd = inotify_add_watch(fd, path,
                               IN_ATTRIB | IN_CREATE | IN_DELETE |
                               IN_MOVED_FROM | IN_MOVED_TO);
    if (wd < 0) {
        fprintf(lg, "WATCHER-ATTACH %s path=%s attach=fail errno=%d\n", ts, path, errno);
        return -1;
    }
    if (nwatch < MAXWATCH) {
        watches[nwatch] = wd;
        snprintf(wdpaths[nwatch], sizeof wdpaths[nwatch], "%s", path);
        nwatch++;
    }
    fprintf(lg, "WATCHER-ATTACH %s path=%s attach=ok wd=%d\n", ts, path, wd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <root-dir> <stopfile>\n", argv[0]); return 2; }
    FILE *lg = fopen(getenv("WATCHER_LOG") ? getenv("WATCHER_LOG") : "/tmp/watcher.log", "a");
    if (!lg) return 2;
    int fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (fd < 0) { fprintf(lg, "WATCHER-ERROR inotify_init\n"); fclose(lg); return 1; }
    char ts[40];
    wallstamp(ts, sizeof ts);
    if (attach_watch(fd, lg, ts, argv[1]) < 0) { fclose(lg); return 1; }
    snap(lg, ts, argv[1]); /* baseline snapshot of the traverse-chain root */
    fprintf(lg, "WATCHER-START %s dir=%s\n", ts, argv[1]);
    fflush(lg);
    char buf[8192] __attribute__((aligned(8)));
    for (;;) {
        FILE *sf = fopen(argv[2], "r");
        if (sf) { fclose(sf); break; }
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EAGAIN) { struct timespec slp={0,20*1000*1000}; nanosleep(&slp,NULL); continue; }
            break;
        }
        if (n == 0) break;
        if (n == (ssize_t)sizeof buf) {
            fprintf(lg, "WATCHER-OVERFLOW %s\n", ts);
            fflush(lg);
        }
        for (char *p = buf; p < buf + n; ) {
            struct inotify_event *ev = (struct inotify_event *)p;
            char namebuf[512];
            if (ev->len > 0 && ev->len < sizeof namebuf) {
                memcpy(namebuf, ev->name, ev->len);
                namebuf[ev->len] = '\0';
            } else { namebuf[0] = '\0'; }
            wallstamp(ts, sizeof ts);
            if (ev->mask & IN_Q_OVERFLOW) {
                fprintf(lg, "WATCHER-OVERFLOW %s queue overflow\n", ts);
                fflush(lg);
            }
            if (ev->mask & (IN_ATTRIB | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO)) {
                char path[1024];
                snprintf(path, sizeof path, "%s/%s", wdpath(ev->wd), namebuf);
                fprintf(lg, "DEPEVENT %s wd=%d mask=%#x name=%s\n", ts, ev->wd, ev->mask, namebuf);
                if (ev->mask & IN_ATTRIB) {
                    snap(lg, ts, path);
                }
                if (ev->mask & IN_CREATE) {
                    /* Adaptive attach: when dev-prep is created under the root,
                     * watch it; when an op dir is created under dev-prep, watch it. */
                    if (strcmp(namebuf, "dev-prep") == 0) {
                        attach_watch(fd, lg, ts, path);
                    } else if (strncmp(namebuf, "op_", 3) == 0) {
                        attach_watch(fd, lg, ts, path);
                    }
                    snap(lg, ts, path);
                }
                if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
                    snap(lg, ts, path);
                }
                fflush(lg);
            }
            p += sizeof(struct inotify_event) + ev->len;
        }
    }
    wallstamp(ts, sizeof ts);
    fprintf(lg, "WATCHER-DONE %s\n", ts);
    fclose(lg);
    return 0;
}
WCEOF
gcc -O2 -Wall -o "$EVIDENCE_DIR/p21e3_devprep_watcher" "$EVIDENCE_DIR/p21e3_devprep_watcher.c" \
  || fail "dev-prep watcher compile failed"
log "dev-prep watcher compiled"
touch "$STATE_DIR/sec4"
fi

# ---------------------------------------------------------------------------
# Section 5: the ONE bounded measurement build
# ---------------------------------------------------------------------------
if [ -f "$STATE_DIR/sec5" ]; then log "phase marker: section 5 done; skipping"; else
log "=== section 5: one bounded enforcing build ==="
[ -n "$ADMIN_TOKEN" ] || fail "admin token unreadable; the measurement cannot run"

# Abandonment bookkeeping: everything started in this section below is
# stopped BY CONSTRUCTION on any exit path (terminal, refusal, aborted
# invocation) — the sampler stop file is created and the pinned audit
# descriptor is closed, never left running behind the measurement.
measure_abandon() {
  if [ -n "${SAMPLER_PID:-}" ]; then
    touch "${STOPSAMP:-}" 2>/dev/null || true
    wait "$SAMPLER_PID" 2>/dev/null || true
    SAMPLER_PID=""
  fi
  if [ -n "${WATCHER_PID:-}" ]; then
    touch "${WATCHER_STOP:-/nonexistent}" 2>/dev/null || true
    wait "$WATCHER_PID" 2>/dev/null || true
    WATCHER_PID=""
  fi
  if [ -n "${AUD_FD:-}" ]; then
    exec {AUD_FD}<&- 2>/dev/null || true
    AUD_FD=""
  fi
  rm -f "${PULL_RAW:-}" 2>/dev/null || true
}

# --- workspace + session (prepared BEFORE the window/sampler/POST) ---
WS="$PRINCIPAL_HOME/r7-p21e3-ws"
rm -rf "$WS"; mkdir -p "$WS/ctx"
printf 'FROM alpine:3.24\nRUN true\n' > "$WS/ctx/Dockerfile"
chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
docker-helper principal show "$PRINCIPAL" >/dev/null 2>&1 \
  || docker-helper principal create --no-credential "$PRINCIPAL" >/dev/null 2>&1 || true
docker-helper principal allowed-root add "$PRINCIPAL" "$PRINCIPAL_HOME" >/dev/null 2>&1 || true
# SECURITY — the Session bearer response must never reach the evidence
# set or the workflow artifact (the R1 round published it): the create
# response is written OUTSIDE the evidence dir, its token extracted, and
# the raw body removed; only the token-free session identity is recorded.
RESP="$STATE_DIR/session-response.json"
CODE="$(curl --silent --max-time 5 \
  --unix-socket "$DH_SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"workspace\":\"$WS\",\"principal\":\"$PRINCIPAL\"}" \
  -o "$RESP" -w '%{http_code}' http://localhost/sessions)" || true
TOKEN="$(grep -oE '"token": *"[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"token": *"//;s/"$//')"
SID="$(grep -oE '"id": *"dhs_[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"id": *"//;s/"$//')"
printf '%s\n' "$SID" > "$EVIDENCE_DIR/session-id.log"
if [ -z "$TOKEN" ]; then
  # SECURITY — the failure path prints NO response body at all: the raw
  # body stays exclusively in the unpublished state dir and is removed
  # here (both paths remove it). Only the HTTP status, a token-free error
  # classification, and the fact of refusal are recorded.
  REFUSAL_CLASS=unknown
  case "$CODE" in
    0) REFUSAL_CLASS=transport-unreachable ;;
    4??) REFUSAL_CLASS=request-refused ;;
    5??) REFUSAL_CLASS=server-error ;;
  esac
  printf 'session-create refused: http_status=%s class=%s (response body withheld)\n' \
    "$CODE" "$REFUSAL_CLASS" | tee -a "$EVIDENCE_DIR/session-refusal.log"
  rm -f "$RESP"
  fail "session create failed (HTTP $CODE)"
fi
rm -f "$RESP"
# Pre-warm the image COMPLETELY before the measured operation so the
# traced build window carries minimal IO noise (the strace filter keeps
# read but bounds output this way). The pull runs with the established
# SESSION token through the intended environment mechanism; a swallowed
# error is a FAILED prewarm, never a successful cache warmup (recorded
# verbatim and never fatal for the measurement itself).
#
# SECURITY — the RAW pull diagnostics (the CLI can print the request
# context and stderr on failure) are captured OUTSIDE the published
# evidence tree (the state dir is never collected), and only a SANITIZED
# copy — verified to contain neither the session token nor the admin
# token — is published. The abort paths cannot publish the raw file:
# it is inside the unpublished tree and removed by the section-5
# abandonment handler regardless of the outcome.
PULL_RAW="$STATE_DIR/pull.raw.log"
measure_abandon_raw_pull() { rm -f "$PULL_RAW"; }
if DOCKER_HELPER_SESSION_TOKEN="$TOKEN" docker-helper pull alpine:3.24 \
    >"$PULL_RAW" 2>&1; then
  PREWARM=success
else
  PREWARM=failed
fi
sed -e 's/dht_[A-Za-z0-9]*/[REDACTED-TOKEN]/g' -e 's/^Authorization: Bearer .*/[REDACTED-AUTH]/' \
  "$PULL_RAW" >"$EVIDENCE_DIR/pull.log" || true
# The sanitized copy MUST carry neither live token; a residual token
# fails loudly instead of being published by accident.
if [ -n "$TOKEN" ] && grep -aqF -- "$TOKEN" "$EVIDENCE_DIR/pull.log" 2>/dev/null; then
  rm -f "$EVIDENCE_DIR/pull.log" "$PULL_RAW"
  fail "the sanitized pull log still carries the session token; nothing was published"
fi
if [ -n "$ADMIN_TOKEN" ] && grep -aqF -- "$ADMIN_TOKEN" "$EVIDENCE_DIR/pull.log" 2>/dev/null; then
  rm -f "$EVIDENCE_DIR/pull.log" "$PULL_RAW"
  fail "the sanitized pull log still carries the admin token; nothing was published"
fi
rm -f "$PULL_RAW"
log "session ready ($SID); image prewarm: $PREWARM"
printf 'prewarm=%s\n' "$PREWARM" > "$EVIDENCE_DIR/prewarm.result"

# --- DAC-state captures taken while the prepared trees exist (R4-P3-P5).
# READ-ONLY throughout: stat/ls -Z/getfacl/uid_map reads; no chmod/chown/
# relabel/repair of any kind.
{
  echo "== builder account =="
  getent passwd docker-helper-builder || true
  id docker-helper-builder || true
  echo "== canonical traversal dirs (stat / ls -Zd / getfacl) =="
  for pd in /var/lib/docker-helper /var/lib/docker-helper/dev-prep; do
    echo "--- $pd ---"
    stat -c 'stat: mode=%a uid=%u gid=%g inode=%d:%i' "$pd" 2>&1
    ls -Zd "$pd" 2>&1
    getfacl -p --absolute-names "$pd" 2>&1 || echo "(getfacl unavailable)"
  done
  echo "== per-operation dev-prep dirs (as they exist now) =="
  ls -laZ --time-style=full-iso /var/lib/docker-helper/dev-prep 2>&1 || true
  for od in /var/lib/docker-helper/dev-prep/op_*; do
    [ -e "$od" ] || continue
    echo "--- $od ---"
    stat -c 'stat: mode=%a uid=%u gid=%g inode=%d:%i' "$od" 2>&1
    getfacl -p --absolute-names "$od" 2>&1 | sed -n '1,12p'
  done
  echo "== live buildkitd process mappings =="
  BKD_OBSERVED="$(pgrep -u "$(id -u docker-helper-builder 2>/dev/null || echo 0)" -x buildkitd 2>/dev/null | head -1 || true)"
  if [ -n "$BKD_OBSERVED" ]; then
    printf 'buildkitd pid=%s\n' "$BKD_OBSERVED"
    for f in uid_map gid_map; do
      echo "--- /proc/$BKD_OBSERVED/$f ---"
      cat "/proc/$BKD_OBSERVED/$f" 2>&1
    done
    grep -E '^(Uid|Gid|NSpid|NSuid|NSgid):' "/proc/$BKD_OBSERVED/status" 2>&1
    readlink "/proc/$BKD_OBSERVED/ns/user" 2>&1
    readlink "/proc/$BKD_OBSERVED/ns/mnt" 2>&1
  else
    echo "no live buildkitd observed at capture time"
  fi
} > "$EVIDENCE_DIR/p21e3-dac-state.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-dac-state.log"

# --- dontaudit visibility toggle (diagnostic ONLY; enforcement unchanged)
# --- — the established disposable-VM discipline (uat-diag-selinux-utab):
# --- record the loaded-policy identity, disable dontaudit rules with a
# --- policy rebuild, restore with semodule -B on EVERY path, verify the
# --- restoration independently. If the toggle or restore cannot be proven,
# --- the round decides the distinct infrastructure verdict, never a pass.
SE_POLICY_SHA_PRE="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
printf 'policy sha before: %s\n' "$SE_POLICY_SHA_PRE" > "$EVIDENCE_DIR/p21e3-dontaudit.log"
DB_OUT="$(semodule -DB 2>&1)" || {
  printf 'semodule -DB failed: %s\n' "$DB_OUT" >> "$EVIDENCE_DIR/p21e3-dontaudit.log"
  fail "dontaudit visibility toggle failed; the inspection attribution cannot run"
}
SE_POLICY_SHA_DB="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
p21e3_dontaudit_restore() {
  local out restored rc
  out="$(semodule -B 2>&1)"
  rc=$?
  printf 'semodule -B rc=%d %s\n' "$rc" "$out" >> "$EVIDENCE_DIR/p21e3-dontaudit.log"
  restored="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
  printf 'policy sha restored: %s (before=%s)\n' "$restored" "${SE_POLICY_SHA_PRE:-none}" \
    >> "$EVIDENCE_DIR/p21e3-dontaudit.log"
  if [ "$rc" = 0 ] && [ -n "$restored" ] && [ "$restored" = "${SE_POLICY_SHA_PRE:-}" ]; then
    printf 'R7-P21E3-DONTAUDIT-RESTORED=verified\n'
    return 0
  fi
  printf 'R7-P21E3-BUILD=aborted(policy-restore-unverified)\nR7-P21E3-VERDICT=BLOCKED\n'
  printf 'R7-P21E3-DONTAUDIT-RESTORED=BLOCKED (rc=%d restored-sha=%s)\n' "$rc" "${restored:-none}"
  return 1
}
if [ "$SE_POLICY_SHA_DB" != "$SE_POLICY_SHA_PRE" ] && [ -n "$SE_POLICY_SHA_DB" ]; then
  printf 'policy sha with -DB: %s (visibility ENABLED: the rebuild differs)\n' "$SE_POLICY_SHA_DB" \
    >> "$EVIDENCE_DIR/p21e3-dontaudit.log"
  log "dontaudit visibility enabled (policy rebuild differs from the baseline)"
else
  printf 'policy sha with -DB: %s — the rebuild did NOT change the loaded policy\n' "$SE_POLICY_SHA_DB" \
    >> "$EVIDENCE_DIR/p21e3-dontaudit.log"
  p21e3_dontaudit_restore
  fail "dontaudit visibility could NOT be established (identical policy after -DB); distinct infrastructure verdict"
fi
trap 'p21e3_dontaudit_restore; measure_abandon' EXIT

# --- the pinned audit window, opened IMMEDIATELY before the measured op ---
if audit_boundary_open "$AUDIT_LOG_PATH"; then
  printf 'window-open offset=%s size=%s lastbyte=%s path_devino=%s fd_devino=%s empty-log=%s\n' \
    "$AUD_START" "$AUD_SIZE" "$AUD_LASTBYTE" "$AUD_PATH_DEVINO" "$AUD_FD_DEVINO" \
    "$( [ "$AUD_SIZE" = 0 ] && echo yes || echo no )" \
    > "$EVIDENCE_DIR/p21e3-window.log"
  log "audit window open: offset=$AUD_START size=$AUD_SIZE lastbyte=$AUD_LASTBYTE dev:ino=$AUD_PATH_DEVINO"
else
  printf 'window-open refused size=%s lastbyte=%s path_devino=%s fd_devino=%s\n' \
    "$AUD_SIZE" "$AUD_LASTBYTE" "$AUD_PATH_DEVINO" "$AUD_FD_DEVINO" \
    > "$EVIDENCE_DIR/p21e3-window.log"
  fail "audit boundary unprovable (size=$AUD_SIZE lastbyte=$AUD_LASTBYTE); the window must not start unaligned"
fi
JSTART="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# --- the /proc sampler: STARTED AND CONFIRMED before POST /build so the
# --- short-lived launch chain (rootlesskit/launcher, early buildkitd) is
# --- sampled from birth; the sampler writes a SAMPLER-START banner as its
# --- first output, which is the deterministic confirmation signal.
STOPSAMP="$STATE_DIR/sampler.stop"
rm -f "$STOPSAMP"
SAMPLER_PID=""
"$EVIDENCE_DIR/p21e3_proc_sampler" "$EVIDENCE_DIR/p21e3-sampler.log" "$STOPSAMP" &
SAMPLER_PID=$!
trap 'p21e3_dontaudit_restore; measure_abandon' EXIT
SAMPLER_CONFIRMED=0
for _ in $(seq 1 100); do
  grep -aq '^SAMPLER-START' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null \
    && { SAMPLER_CONFIRMED=1; break; }
  if ! kill -0 "$SAMPLER_PID" 2>/dev/null; then break; fi
  sleep 0.1
done
if [ "$SAMPLER_CONFIRMED" = 1 ]; then
  log "sampler confirmed running before POST /build (pid $SAMPLER_PID)"
else
  printf 'sampler: NOT-CONFIRMED (process-alive=%s) before POST /build\n' \
    "$(kill -0 "$SAMPLER_PID" 2>/dev/null && echo yes || echo no)" \
    >> "$EVIDENCE_DIR/p21e3-window.log"
  fail "sampler not confirmed before POST /build; the window is unmeasurable"
fi

# --- the prepared-tree event watcher: started BEFORE the measured op, so
# --- the short-lived per-operation dev-prep directory's creation/deletion
# --- events carry its immediate lstat/label/ACL presence (R4-P3-P5).
WATCHER_STOP="$STATE_DIR/watcher.stop"
rm -f "$WATCHER_STOP"
WATCHER_LOG="$EVIDENCE_DIR/p21e3-devprep-events.log"
WATCHER_PID=""
WATCHER_ENV="WATCHER_LOG=$WATCHER_LOG"
# R4-P3-P5-R1: start on the EXISTING canonical state root (the traverse
# chain's first hop) and let the watcher attach the dev-prep and op watches
# adaptively as they are created; watching dev-prep directly failed in P5
# (the directory does not exist before a build).
env "$WATCHER_ENV" "$EVIDENCE_DIR/p21e3_devprep_watcher" \
  /var/lib/docker-helper "$WATCHER_STOP" &
WATCHER_PID=$!
for _ in $(seq 1 100); do
  grep -aq '^WATCHER-START' "$WATCHER_LOG" 2>/dev/null && break
  if ! kill -0 "$WATCHER_PID" 2>/dev/null; then break; fi
  sleep 0.05
done
if grep -aq '^WATCHER-START' "$WATCHER_LOG" 2>/dev/null; then
  log "state-root event watcher START confirmed (root watch attached; pid $WATCHER_PID)"
  log "watcher start SUCCESS is distinct from watch-attachment SUCCESS: the adaptive dev-prep/op attachments report on WATCHER-ATTACH lines during the build; any attach failure is an explicit limitation, not a missed start"
else
  log "state-root event watcher NOT confirmed (process-alive=$(kill -0 "$WATCHER_PID" 2>/dev/null && echo yes || echo no)); the prepared-tree event evidence will be absent"
fi

# --- the measured operation: POST /build ---
RESP2="$EVIDENCE_DIR/build-start.json"
CODE2="$(curl --silent --max-time 10 \
  --unix-socket "$DH_SOCK" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"context":"ctx","dockerfile":"Dockerfile","image":"uat-p21e3"}' \
  -o "$RESP2" -w '%{http_code}' http://localhost/build)" || true
printf '%s\n' "$CODE2" > "$EVIDENCE_DIR/build-start.http.log"
OP="$(grep -oE '"operation_id": *"[^"]+"' "$RESP2" 2>/dev/null | head -1 | sed 's/.*"operation_id": *"//;s/"$//')"
printf '%s\n' "$OP" > "$EVIDENCE_DIR/operation-id.log"
log "build http=$CODE2 operation_id=$OP"
if [ -z "$OP" ]; then
  printf 'refusal: POST /build delivered HTTP %s with no operation id\n' "$CODE2" \
    >> "$EVIDENCE_DIR/p21e3-window.log"
  fail "no operation id (http $CODE2); the refusal path releases the sampler and closes the window"
fi

# --- early-chain capture: the BUILDER MANAGER is traced from BEFORE the
# --- post when available (it spawns the rootlesskit/launcher chain), and
# --- the buildkitd attach polls for the daemon child as before.
# --- attach=none is recorded as NOT-ATTACHED: a sampling/tracing miss is
# --- never evidence that the process did not exist.
STRACE_PID=""
STRACE_ALL_PIDS=""
if MGR_PID="$(systemctl show -p MainPID --value docker-helper-builder.service 2>/dev/null)" \
  && [ -n "$MGR_PID" ] && [ "$MGR_PID" != 0 ]; then
  timeout "$STRACE_TIMEOUT" strace -f -qq -tt -s 100 -y -yy -p "$MGR_PID" \
    -e trace=fork,vfork,clone,clone3,execve,execveat,kill,pidfd_open,pidfd_send_signal \
    -o "$EVIDENCE_DIR/p21e3-manager-strace.log" 2>"$EVIDENCE_DIR/p21e3-manager-strace.err" &
  STRACE_MGR_PID=$!
  STRACE_ALL_PIDS="$STRACE_ALL_PIDS $STRACE_MGR_PID"
  echo "manager-attach=$MGR_PID" > "$EVIDENCE_DIR/p21e3-manager-strace-attach.log"
else
  echo "manager-attach=none (MainPID unresolved; the launch chain rests on the sampler)" \
    > "$EVIDENCE_DIR/p21e3-manager-strace-attach.log"
fi

# The buildkitd attach: poll for the first freshly recorded buildkitd pid
# (the sampler sees it; a plain pgrep over the builder uid is equivalent)
# and attach immediately — the wrapper exec happens later, after buildkitd
# boot and workspace preparation.
BKD_PID=""
for _ in $(seq 1 300); do
  BKD_PID="$(pgrep -u "$(id -u docker-helper-builder 2>/dev/null || echo 0)" -x buildkitd 2>/dev/null | head -1 || true)"
  [ -n "$BKD_PID" ] && break
  sleep 0.1
done
if [ -n "$BKD_PID" ]; then
  log "attaching strace to buildkitd pid $BKD_PID (timeout ${STRACE_TIMEOUT}s)"
  timeout "$STRACE_TIMEOUT" strace -f -qq -tt -s 100 -y -yy -p "$BKD_PID" \
    -e trace=execve,execveat,open,openat,openat2,read,newfstatat,statx,statfs,getxattr,lgetxattr,fgetxattr,rename,renameat,renameat2,mount,umount2,mkdir,mkdirat,symlink,symlinkat \
    -o "$EVIDENCE_DIR/p21e3-strace.log" 2>"$EVIDENCE_DIR/p21e3-strace.err" &
  STRACE_PID=$!
  STRACE_ALL_PIDS="$STRACE_ALL_PIDS $STRACE_PID"
else
  STRACE_PID=""
  log "no buildkitd pid observed to attach; recorded as NOT-ATTACHED for this boundary (NOT evidence of non-existence)"
fi
[ -n "$BKD_PID" ] && echo "attach=$BKD_PID" > "$EVIDENCE_DIR/p21e3-strace-attach.log" \
  || echo "attach=none (never attached; NOT evidence of non-existence)" > "$EVIDENCE_DIR/p21e3-strace-attach.log"

# The bounded wait for the operation terminal.
STATUS=""
for _ in $(seq 1 600); do
  STATUS="$(curl --silent --max-time 2 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $TOKEN" \
    "http://localhost/operations/$OP" 2>/dev/null || true)"
  case "$STATUS" in
    *'"succeeded"'*|*'"failed"'*) break ;;
  esac
  sleep 0.1
done
printf '%s\n' "$STATUS" > "$EVIDENCE_DIR/build-status.json"
JEND="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
case "$STATUS" in
  *'"succeeded"'*|*'"failed"'*) : ;;
  *) printf 'aborted: the operation produced no terminal within the bounded wait\n' \
    >> "$EVIDENCE_DIR/p21e3-window.log" ;;
esac

# Reliable teardown on EVERY path: sampler first, then the traces (the
# strace wrappers are signaled before the wait so the teardown never
# depends on the timeout budget).
touch "$STOPSAMP"
for s in $STRACE_ALL_PIDS; do
  kill -TERM "$s" 2>/dev/null || true
done
for s in $STRACE_ALL_PIDS; do
  wait "$s" 2>/dev/null || true
done
wait "$SAMPLER_PID" 2>/dev/null || true
SAMPLER_PID=""
if [ -n "${WATCHER_PID:-}" ]; then
  touch "$WATCHER_STOP" 2>/dev/null || true
  wait "$WATCHER_PID" 2>/dev/null || true
  WATCHER_PID=""
fi
# Explicit watcher evidence triage (R4-P3-P5-R1): overflow, failed
# attachment, and missed lifecycle are recorded as limitation markers at
# capture time, not reconstructed afterward.
{
  echo "== watcher triage (limitations are facts, not silences) =="
  printf 'watcher-start-records=%s\n' "$(grep -c '^WATCHER-START' "$WATCHER_LOG" 2>/dev/null || echo 0)"
  printf 'dev-prep-attach-records=%s\n' "$(grep -c 'WATCHER-ATTACH.*docker-helper/dev-prep' "$WATCHER_LOG" 2>/dev/null || echo 0)"
  printf 'op-flagged-attach-failures=%s\n' "$(grep -c 'WATCHER-ATTACH.*attach=fail' "$WATCHER_LOG" 2>/dev/null || echo 0)"
  printf 'overflow-records=%s\n' "$(grep -c '^WATCHER-OVERFLOW' "$WATCHER_LOG" 2>/dev/null || echo 0)"
  printf 'attrib-records=%s\n' "$(grep -c 'DEPEVENT.*IN_ATTRIB\|mask=0x.*ATTRIB' "$WATCHER_LOG" 2>/dev/null || echo 0)"
  if grep -aq 'name=dev-prep' "$WATCHER_LOG" 2>/dev/null; then
    echo "dev-prep lifecycle OBSERVED by the watcher"
  else
    echo "MISSED-LIFECYCLE dev-prep was never observed by the watcher (no creation/removal event; if the tree existed before start, only its IN_ATTRIB events would appear)"
  fi
  if grep -aq '^DEPEVENT' "$WATCHER_LOG" 2>/dev/null; then
    echo "prepare-lifecycle events OBSERVED"
  else
    echo "MISSED-LIFECYCLE no prepare-lifecycle event was observed at all; the watcher saw only its own start"
  fi
  echo "-- event timeline (first 40 lines) --"
  sed -n '1,40p' "$WATCHER_LOG"
} > "$EVIDENCE_DIR/p21e3-watcher-triage.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-watcher-triage.log"
trap - EXIT
# The prepared-tree state AT THE TERMINAL (R4-P3-P5) is captured FIRST (the
# teardown may remove the per-op dir at any moment); the policy restore
# follows immediately after the capture.
{
  echo "== post-terminal traverse-chain state (R4-P3-P5-R1: the state root once more after the build terminal) =="
  for pd in /var/lib/docker-helper /var/lib/docker-helper/dev-prep; do
    echo "--- $pd (at the terminal) ---"
    stat -c 'stat: mode=%a uid=%u gid=%g inode=%d:%i' "$pd" 2>&1
    ls -Zd "$pd" 2>&1
    getfacl -p --absolute-names "$pd" 2>&1 || echo "(getfacl unavailable)"
  done
  echo "== per-operation dev-prep dirs at the terminal =="
  ls -laZ --time-style=full-iso /var/lib/docker-helper/dev-prep 2>&1 || true
  found_op=0
  for od in /var/lib/docker-helper/dev-prep/op_*; do
    [ -e "$od" ] || continue
    found_op=1
    echo "--- $od (still present) ---"
    stat -c 'stat: mode=%a uid=%u gid=%g inode=%d:%i' "$od" 2>&1
    getfacl -p --absolute-names "$od" 2>&1 | sed -n '1,12p'
    getfattr -n security.selinux --only-values "$od" 2>/dev/null; echo
  done
  [ "$found_op" = 1 ] || echo "(no per-op dir present at the terminal — removed by the operation teardown; the watcher's event captures hold the ladder's state)"
} > "$EVIDENCE_DIR/p21e3-devprep-terminal-state.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-devprep-terminal-state.log"
# The normal-path restore: the verdict must be independently verified; an
# unverified restoration decides the distinct infrastructure/policy-state
# verdict and stops the round.
if ! p21e3_dontaudit_restore; then
  fail "the dontaudit restoration could not be verified (distinct infrastructure/policy-state verdict)"
fi

# The bounded builder-manager service journal covering EXACTLY the
# operation window (JSTART was taken at window open, JEND at terminal).
journalctl --no-pager --since "$JSTART" --until "$JEND" \
  -u docker-helper-builder.service \
  > "$EVIDENCE_DIR/p21e3-builder-journal.log" 2>&1 || true
MAXJOURNAL=$((8*1024*1024))
jz="$(wc -c < "$EVIDENCE_DIR/p21e3-builder-journal.log" 2>/dev/null || echo 0)"
if [ "$jz" -gt "$MAXJOURNAL" ]; then
  log "journal log $jz > cap $MAXJOURNAL; head-truncating (raw preserved as .over)"
  mv "$EVIDENCE_DIR/p21e3-builder-journal.log" "$EVIDENCE_DIR/p21e3-builder-journal.log.over"
  head -c "$MAXJOURNAL" "$EVIDENCE_DIR/p21e3-builder-journal.log.over" \
    > "$EVIDENCE_DIR/p21e3-builder-journal.log"
  printf '\n[truncated at %d bytes; full log: p21e3-builder-journal.log.over]\n' "$MAXJOURNAL" \
    >> "$EVIDENCE_DIR/p21e3-builder-journal.log"
fi

# Truncate-bounded evidence: the strace log is capped in the artifact by
# size (the raw file is preserved up to the cap; a cap notice is appended).
MAXSTRACE=$((8*1024*1024))
sz="$(wc -c < "$EVIDENCE_DIR/p21e3-strace.log" 2>/dev/null || echo 0)"
if [ "$sz" -gt "$MAXSTRACE" ]; then
  log "strace log $sz > cap $MAXSTRACE; head-truncating (raw preserved as .over)"
  mv "$EVIDENCE_DIR/p21e3-strace.log" "$EVIDENCE_DIR/p21e3-strace.log.over"
  head -c "$MAXSTRACE" "$EVIDENCE_DIR/p21e3-strace.log.over" > "$EVIDENCE_DIR/p21e3-strace.log"
  printf '\n[truncated at %d bytes; full log: p21e3-strace.log.over]\n' "$MAXSTRACE" >> "$EVIDENCE_DIR/p21e3-strace.log"
fi
msz="$(wc -c < "$EVIDENCE_DIR/p21e3-manager-strace.log" 2>/dev/null || echo 0)"
if [ "$msz" -gt "$MAXSTRACE" ]; then
  log "manager strace log $msz > cap $MAXSTRACE; head-truncating (raw preserved as .over)"
  mv "$EVIDENCE_DIR/p21e3-manager-strace.log" "$EVIDENCE_DIR/p21e3-manager-strace.log.over"
  head -c "$MAXSTRACE" "$EVIDENCE_DIR/p21e3-manager-strace.log.over" \
    > "$EVIDENCE_DIR/p21e3-manager-strace.log"
  printf '\n[truncated at %d bytes; full log: p21e3-manager-strace.log.over]\n' "$MAXSTRACE" \
    >> "$EVIDENCE_DIR/p21e3-manager-strace.log"
fi

# The operation log (the build's own log through the API; token-free).
curl --silent --max-time 2 \
  --unix-socket "$DH_SOCK" -H "Authorization: Bearer $TOKEN" \
  "http://localhost/operations/$OP/logs?offset=0" \
  > "$EVIDENCE_DIR/build.log" 2>&1 || true
log "build status: $(printf '%s' "$STATUS" | grep -oE '"(status|result_code)":"[^"]*"' | tr '\n' ' ')"

# --- the audit window drain (through the pinned descriptor, boundary
# --- checked; torn trailing records dropped and recorded) ---
AUD_WINDOW_IDENTITY="$(audit_window_identity || true)"
close_size="$(stat -L -c '%s' /proc/self/fd/$AUD_FD 2>/dev/null || echo '?')"
printf 'window-close identity=%s size_at_close=%s journal-window=%s..%s\n' \
  "$AUD_WINDOW_IDENTITY" "$close_size" "$JSTART" "$JEND" \
  >> "$EVIDENCE_DIR/p21e3-window.log"
if [ "$AUD_WINDOW_IDENTITY" != "proven" ]; then
  printf 'R7-P21E3-VERDICT=BLOCKED\nR7-P21E3-BUILD=aborted(no-proven-window)\n'
  measure_abandon
  fail "audit window identity unproven ($AUD_WINDOW_IDENTITY); the measurement decides BLOCKED"
fi
audit_window_drain "$EVIDENCE_DIR/p21e3-window-records.log" || true
{
  echo "window identity: $AUD_WINDOW_IDENTITY"
  echo "window start offset: $AUD_START (aligned to lastbyte=$AUD_LASTBYTE size=$AUD_SIZE)"
  echo "torn trailing record: $AUD_TORN"
  echo "records: $(wc -l < "$EVIDENCE_DIR/p21e3-window-records.log" 2>/dev/null || echo 0)"
} >> "$EVIDENCE_DIR/p21e3-window.log"
measure_abandon

# The per-op executor root state at the terminal (the post-terminal tree).
ROOTDIR="$BUILDER_STATE_ROOT/ops/$OP/root/runc-native"
ls -laZR "$ROOTDIR" > "$EVIDENCE_DIR/p21e3-executor-tree.log" 2>&1 || true

# Machine verdicts: the measurement itself ran; the BUILD result is
# recorded separately (failing is a measurement outcome, not a harness
# failure).
case "$STATUS" in
  *'"succeeded"'*) BUILD_RESULT=succeeded ;;
  *'"failed"'*) BUILD_RESULT=failed ;;
  *) BUILD_RESULT="aborted(no-terminal)" ;;
esac
printf 'R7-P21E3-BUILD=%s\n' "$BUILD_RESULT"
printf 'R7-P21E3-VERDICT=MEASURED\n'
touch "$STATE_DIR/sec5"
fi

# ---------------------------------------------------------------------------
# Section 6: chain inventory (what the evidence shows, machine-readable
# orientation for the report; the ANALYSIS stays with the round report)
# ---------------------------------------------------------------------------
log "=== section 6: chain inventory ==="
# R4-P3-P6 cleanup proof: the daemon's internal stage diagnostics carry
# the trusted dev-prep lifecycle (dev_prep success before buildctl and
# dev_prep_cleanup after the proven STOP) with the operation id. The
# prepared-tree terminal absence is ALSO probed on the exact op path from
# an identity with confirmed parent traversal (the builder account's ACL
# row covers exactly that hop in the capturing script's position too).
{
  echo "== daemon operational stage diagnostics (dev-prep lifecycle) =="
  journalctl -u docker-helper.service -o short-iso --no-pager 2>/dev/null \
    | grep -aE 'dev_prep|build stage|operation_id' | tail -80 || echo "(journalctl unavailable)"
} > "$EVIDENCE_DIR/p21e3-daemon-journal.log" 2>&1
{
  op_now="$(cat "$EVIDENCE_DIR/operation-id.log" 2>/dev/null || true)"
  case "$op_now" in
    op_*)
      op_path="/var/lib/docker-helper/dev-prep/$op_now"
      echo "== exact prepared-tree path probe at the terminal =="
      echo "probe id: $op_now"
      stat -c 'stat: mode=%a uid=%u gid=%g' "$op_path" 2>&1
      getfacl -p --absolute-names "$op_path" 2>&1 || true
      ;;
    *) echo "no operation id recorded; the exact-path probe is skipped" ;;
  esac
  echo "-- probe identity: uid=$(id -u) selinux=$(id -Z 2>/dev/null || echo '<unavailable>')"
  echo "-- parent chain access: the state-root ACL covers only the named builder uid by contract; the probe result is interpreted against that access, and the daemon journal's dev_prep_cleanup diagnostic is the primary absence proof"
} > "$EVIDENCE_DIR/p21e3-devprep-terminal-probe.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-devprep-terminal-probe.log"
{
  echo "== wrapper vs runtime observations (by /proc/<pid>/exe) =="
  grep -oE 'exe=[^ ]+' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | sort | uniq -c || true
  echo "== observed docker-helper/buildkit process contexts =="
  grep -oE 'ctx=[^ ]+' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | sort | uniq -c || true
  echo "== observed pid chains (last 40 distinct sampled procs) =="
  grep -a '^PROC ' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | awk '!seen[$4]++' | tail -40 || true
  echo "== strace key boundary lines (orientation only) =="
  grep -aE 'attr/current|config\.json|dev-prep|/dev"|execve|"mount"|symlinkat.*ptmx' \
    "$EVIDENCE_DIR/p21e3-strace.log" 2>/dev/null | head -120 || echo "(no strace evidence)"
  echo "== manager launch-chain key lines (orientation only) =="
  grep -aE 'clone|execve' "$EVIDENCE_DIR/p21e3-manager-strace.log" 2>/dev/null | head -120 \
    || echo "(no manager strace evidence)"
  echo "== AVC records in the pinned window =="
  grep -a "avc:  denied" "$EVIDENCE_DIR/p21e3-window-records.log" 2>/dev/null | head -60 \
    || echo "(no denied AVC records)"
  echo "== AVC attribution (window pid -> FIRST sampler observation of the same pid) =="
  for avcid in $(grep -a "avc:" "$EVIDENCE_DIR/p21e3-window-records.log" 2>/dev/null \
    | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -un); do
    obs="$(grep -a " pid=$avcid " "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | head -1 || true)"
    if [ -n "$obs" ]; then
      printf 'avc-pid=%s observed: %s\n' "$avcid" "$obs"
    else
      printf 'avc-pid=%s NOT-OBSERVED-BY-SAMPLER (no attribution: short-lived before a sweep, or unrelated to the build flow)\n' "$avcid"
    fi
  done || true
} > "$EVIDENCE_DIR/p21e3-inventory.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-inventory.log"
log "inventory written; the report analyzes the boundaries"
