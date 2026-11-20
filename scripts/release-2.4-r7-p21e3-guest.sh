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
# MNB30 tracer-free mode: strace is NOT a required tool (the exec boundary
# is measured WITHOUT ptrace — the /proc sampler and the audit window are
# the instruments). The build-time necessity stays gcc-only.
if [ "${R7_MNB30:-0}" != 1 ]; then
  if ! command -v gcc >/dev/null 2>&1 || ! command -v strace >/dev/null 2>&1; then
    cap p21e3-toolchain 6 timeout 300 zypper --non-interactive install -y gcc strace acl
  fi
  command -v strace >/dev/null 2>&1 || fail "strace unavailable"
else
  if ! command -v gcc >/dev/null 2>&1; then
    cap p21e3-toolchain 6 timeout 300 zypper --non-interactive install -y gcc acl
  fi
fi
command -v gcc >/dev/null 2>&1 || fail "gcc unavailable"

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
            if (!relevant(comm) && !relevant(exe) && !relevant(argv0) &&
                strstr(ctx, "docker_helper_builder_workload_t") == NULL)
                continue;
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
            /* MNB30: the TRANSITIONED workload process — its kernel context
             * carries the composed workload domain (docker_helper_builder_
             * workload_t). No ptrace: the /proc snapshot below reads the
             * process OWN status file, once per pid, in the same sweep that
             * first observed it (the context itself is in every PROC row). */
            else if (strstr(ctx, "docker_helper_builder_workload_t") != NULL) {
                static int w_seen[128];
                static int w_seen_n;
                int was_seen = 0;
                for (int i = 0; i < w_seen_n; i++)
                    if (w_seen[i] == pid) { was_seen = 1; break; }
                if (!was_seen && w_seen_n < 128) {
                    w_seen[w_seen_n++] = pid;
                    char pline[64], lb[512], nsline[128], nsid[256];
                    FILE *mf;
                    snprintf(pline, sizeof pline, "/proc/%s/status", e->d_name);
                    if ((mf = fopen(pline, "r")) != NULL) {
                        while (fgets(lb, sizeof lb, mf)) {
                            if (strncmp(lb, "Uid:", 4) == 0 || strncmp(lb, "Gid:", 4) == 0 ||
                                strncmp(lb, "Cap", 3) == 0 ||
                                strncmp(lb, "NoNewPrivs:", 11) == 0 ||
                                strncmp(lb, "Seccomp:", 8) == 0) {
                                lb[strcspn(lb, "\n")] = 0;
                                fprintf(lg, "PROCDETAIL-WORKLOAD %s t=%lld pid=%d %s\n",
                                        ts, t, pid, lb);
                            }
                        }
                        fclose(mf);
                    }
                    snprintf(pline, sizeof pline, "/proc/%s/uid_map", e->d_name);
                    if ((mf = fopen(pline, "r")) != NULL) {
                        if (fgets(lb, sizeof lb, mf))
                            fprintf(lg, "PROCDETAIL-WORKLOAD %s t=%lld pid=%d uid_map=%s",
                                    ts, t, pid, lb);
                        fclose(mf);
                    }
                    snprintf(pline, sizeof pline, "/proc/%s/ns/user", e->d_name);
                    if (readlinkstr(pline, nsid, sizeof nsid) > 0)
                        fprintf(lg, "PROCDETAIL-WORKLOAD %s t=%lld pid=%d ns_user=%s\n", ts, t, pid, nsid);
                    snprintf(pline, sizeof pline, "/proc/%s/ns/mnt", e->d_name);
                    if (readlinkstr(pline, nsid, sizeof nsid) > 0)
                        fprintf(lg, "PROCDETAIL-WORKLOAD %s t=%lld pid=%d ns_mnt=%s\n", ts, t, pid, nsid);
                }
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

# R7 MNB24: the user-namespace/capability-survival watch. Every ~3ms walks
# /proc; for each process whose user namespace differs from the host
# observer's (or whose comm names the runc helper chain) records the first
# arrival and every comm change (runc:[1:CHILD] -> runc:[2:INIT] -> the
# workload on exec) with: pid, ppid, comm, exe, ns/user and ns/mnt inodes
# (the userns binding), /proc/<pid>/attr/current, and the capability state
# from /proc/<pid>/status (CapInh/CapPrm/CapEff/CapBnd/CapAmb, NoNewPrivs).
# Runs on the SAME stop file as the sampler; output is bounded.
cat > "$EVIDENCE_DIR/p21e3_capwatch.c" <<'CEOF'
/* p21e3_capwatch.c - R7 MNB24 userns/capability watch (pure observer). */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#define MAXROWS 20000

static long long now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec*1000LL + ts.tv_nsec/1000000;
}
static void wallstamp(char *b, size_t n) {
    struct timespec ts; struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts); gmtime_r(&ts.tv_sec, &tm);
    snprintf(b, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec/1000000);
}
static void readlinkstr(const char *p, char *out, size_t n) {
    ssize_t r = readlink(p, out, n - 1);
    if (r < 0) { out[0] = '\0'; return; }
    out[r] = '\0';
}
static pid_t selfpid;
static char host_userns[256];

/* The MNB25 bounded namespace-file readout: uid_map/gid_map/setgroups
 * are short single-line-per-entry files; newlines inside the token are
 * flattened to spaces so the TSV row stays one line. */
static void readsmall(int pid, const char *name, char *out, size_t n) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/%s", pid, name);
    FILE *f = fopen(p, "r");
    if (!f) {
        snprintf(out, n, "<rc=%d>", errno);
        return;
    }
    size_t off = 0;
    out[0] = '\0';
    char lb[256];
    while (off + 1 < n && fgets(lb, sizeof lb, f)) {
        lb[strcspn(lb, "\n")] = ' ';
        off += snprintf(out + off, n - off, "%s", lb);
    }
    if (out[0] == '\0') snprintf(out, n, "<empty>");
    fclose(f);
}

static int targeted(int pid, const char *comm) {
    char p[64], ns[256];
    snprintf(p, sizeof p, "/proc/%d/ns/user", pid);
    readlinkstr(p, ns, sizeof ns);
    if (host_userns[0] != '\0' && ns[0] != '\0' && strcmp(ns, host_userns) != 0)
        return 1;
    return strncmp(comm, "runc:", 5) == 0;
}
/* One bounded /proc/<pid>/status capability read. MNB26: the field
 * selector covers CapEff AND CapBnd — the post-drop bounding snapshot is
 * tied to the PR_CAPBSET_DROP series by its own state-change row. */
static void readcap(int pid, const char *field, char *out, size_t n) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/status", pid);
    FILE *f = fopen(p, "r");
    if (!f) {
        snprintf(out, n, "<rc=%d>", errno);
        return;
    }
    size_t flen = strlen(field);
    char lb[512];
    out[0] = '\0';
    while (fgets(lb, sizeof lb, f)) {
        if (strncmp(lb, field, flen) == 0 && lb[flen] == ':') {
            char *v = strchr(lb, ':');
            if (v) {
                v++;
                while (*v == ' ' || *v == '\t') v++;
                lb[strcspn(lb, "\n")] = 0;
                snprintf(out, n, "%s", v);
            }
            break;
        }
    }
    fclose(f);
    if (out[0] == '\0') snprintf(out, n, "<absent>");
}
static void readeff(int pid, char *out, size_t n) {
    readcap(pid, "CapEff", out, n);
}
static void emit(FILE *lg, const char *event, int pid, int ppid,
                 const char *comm, const char *exe) {
    char ts[64]; wallstamp(ts, sizeof ts);
    char nsuser[256], nsmnt[256], p[64], ctx[512] = "<unresolvable>";
    char capinh[128] = "-", capprm[128] = "-", capeff[128] = "-",
         capbnd[128] = "-", capamb[128] = "-", nnp[32] = "-";
    char uidmap[128] = "-", gidmap[128] = "-", sgfile[32] = "-";
    (void)event; (void)ppid;
    readsmall(pid, "uid_map", uidmap, sizeof uidmap);
    readsmall(pid, "gid_map", gidmap, sizeof gidmap);
    readsmall(pid, "setgroups", sgfile, sizeof sgfile);
    snprintf(p, sizeof p, "/proc/%d/ns/user", pid);
    readlinkstr(p, nsuser, sizeof nsuser);
    snprintf(p, sizeof p, "/proc/%d/ns/mnt", pid);
    readlinkstr(p, nsmnt, sizeof nsmnt);
    snprintf(p, sizeof p, "/proc/%d/attr/current", pid);
    FILE *f = fopen(p, "r");
    if (f) {
        size_t r = fread(ctx, 1, sizeof ctx - 1, f);
        if (r == 0) snprintf(ctx, sizeof ctx, "<empty>");
        else { if (ctx[r-1] == '\n') r--; ctx[r] = '\0'; }
        fclose(f);
    } else snprintf(ctx, sizeof ctx, "<rc=%d>", errno);
    snprintf(p, sizeof p, "/proc/%d/status", pid);
    f = fopen(p, "r");
    if (f) {
        char lb[512];
        while (fgets(lb, sizeof lb, f)) {
            char *v = strchr(lb, ':');
            if (!v) continue;
            lb[strcspn(lb, "\n")] = 0;
            *v = '\0'; v++;
            while (*v == ' ' || *v == '\t') v++;
            if (!strcmp(lb, "CapInh")) snprintf(capinh, sizeof capinh, "%s", v);
            else if (!strcmp(lb, "CapPrm")) snprintf(capprm, sizeof capprm, "%s", v);
            else if (!strcmp(lb, "CapEff")) snprintf(capeff, sizeof capeff, "%s", v);
            else if (!strcmp(lb, "CapBnd")) snprintf(capbnd, sizeof capbnd, "%s", v);
            else if (!strcmp(lb, "CapAmb")) snprintf(capamb, sizeof capamb, "%s", v);
            else if (!strcmp(lb, "NoNewPrivs")) snprintf(nnp, sizeof nnp, "%s", v);
        }
        fclose(f);
    }
    fprintf(lg, "CAPWATCH %s t=%lld pid=%d ppid=%d comm=%s exe=%s nsuser=%s nsmnt=%s ctx=%s capinh=%s capprm=%s capeff=%s capbnd=%s capamb=%s nnp=%s uidmap=%s gidmap=%s setgroups=%s\n",
            ts, now_ms(), pid, ppid, comm, exe[0] ? exe : "-", nsuser, nsmnt,
            ctx, capinh, capprm, capeff, capbnd, capamb, nnp, uidmap, gidmap, sgfile);
    fflush(lg);
}
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: capwatch LOG STOPFILE\n"); return 2; }
    FILE *lg = fopen(argv[1], "w");
    if (!lg) return 1;
    selfpid = getpid();
    readlinkstr("/proc/self/ns/user", host_userns, sizeof host_userns);
    {
        char ts[64]; wallstamp(ts, sizeof ts);
        fprintf(lg, "CAPWATCH-START %s host_userns=%s\n", ts, host_userns);
        fflush(lg);
    }
    struct { pid_t pid; char comm[64]; char capeff[64]; char capbnd[64]; char gidmap[64]; } seen[MAXROWS];
    size_t nseen = 0;
    long long rows = 0;
    while (1) {
        int stop = 0;
        FILE *sf = fopen(argv[2], "r");
        if (sf) { fclose(sf); stop = 1; }
        if (stop) break;
        DIR *d = opendir("/proc");
        if (!d) { usleep(3000); continue; }
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            long pid = strtol(e->d_name, NULL, 10);
            if (pid <= 0 || (pid_t)pid == selfpid) continue;
            char p[64], comm[64] = "", exe[PATH_MAX] = "";
            snprintf(p, sizeof p, "/proc/%s/comm", e->d_name);
            FILE *f = fopen(p, "r");
            if (!f) continue;
            if (!fgets(comm, sizeof comm, f)) { fclose(f); continue; }
            fclose(f);
            comm[strcspn(comm, "\n")] = 0;
            if (!targeted((int)pid, comm)) continue;
            snprintf(p, sizeof p, "/proc/%s/exe", e->d_name);
            readlinkstr(p, exe, sizeof exe);
            size_t i;
            for (i = 0; i < nseen; i++)
                if (seen[i].pid == (pid_t)pid) break;
            if (i == nseen) {
                if (nseen < MAXROWS) {
                    seen[nseen].pid = (pid_t)pid;
                    snprintf(seen[nseen].comm, sizeof seen[nseen].comm, "%s", comm);
                    readeff((int)pid, seen[nseen].capeff, sizeof seen[nseen].capeff);
                    readcap((int)pid, "CapBnd", seen[nseen].capbnd, sizeof seen[nseen].capbnd);
                    readsmall((int)pid, "gid_map", seen[nseen].gidmap, sizeof seen[nseen].gidmap);
                    nseen++;
                }
                if (++rows > MAXROWS) goto done;
                emit(lg, "arrival", (int)pid, 0, comm, exe);
            } else {
                int evict = 0;
                if (strcmp(seen[i].comm, comm) != 0) {
                    snprintf(seen[i].comm, sizeof seen[i].comm, "%s", comm);
                    evict = 1;
                }
                /* MNB26: the caps and gid state between arrival and
                 * setgroups are the decision state; CapBnd changes when
                 * the PR_CAPBSET_DROP series lands — its own row is the
                 * time-bound post-drop snapshot. */
                char ce[64], cb[64], gm[64];
                readeff((int)pid, ce, sizeof ce);
                readcap((int)pid, "CapBnd", cb, sizeof cb);
                readsmall((int)pid, "gid_map", gm, sizeof gm);
                if (strcmp(seen[i].capeff, ce) != 0 ||
                    strcmp(seen[i].gidmap, gm) != 0) {
                    snprintf(seen[i].capeff, sizeof seen[i].capeff, "%s", ce);
                    snprintf(seen[i].gidmap, sizeof seen[i].gidmap, "%s", gm);
                    evict = 1;
                }
                if (strcmp(seen[i].capbnd, cb) != 0) {
                    snprintf(seen[i].capbnd, sizeof seen[i].capbnd, "%s", cb);
                    evict = 1;
                }
                if (evict) {
                    if (++rows > MAXROWS) goto done;
                    emit(lg, "state-change", (int)pid, 0, comm, exe);
                }
            }
        }
        closedir(d);
        struct timespec slp = {0, 3 * 1000 * 1000};
        nanosleep(&slp, NULL);
    }
done:
    {
        char ts[64]; wallstamp(ts, sizeof ts);
        fprintf(lg, "CAPWATCH-DONE %s t=%lld rows=%lld pidervals-tracked=%zu\n",
                ts, now_ms(), rows, nseen);
    }
    fclose(lg);
    return 0;
}
CEOF
gcc -O2 -Wall -o "$EVIDENCE_DIR/p21e3_capwatch" "$EVIDENCE_DIR/p21e3_capwatch.c" \
  || fail "capwatch compile failed"
log "capwatch compiled"

# The process-mountinfo snapshotter (R4-P3-P6-MNB diagnostic rung): for
# every NEW buildkitd or runc container-init pid, ONE read-only snapshot
# of its mountinfo (mount ids, major:minor, root, propagation tags),
# SELinux context, ns identities, and the observer-readonly /proc and
# /proc/bus lookups through the pid's own root. Nothing is mutated.
cat > "$EVIDENCE_DIR/p21e3_procns_snap.c" <<'PNSCEOF'
/* p21e3_procns_snap.c — the process-mountinfo snapshotter. Polls /proc
 * read-only; for every NEW pid whose comm names buildkitd or a runc
 * container-init ("runc:[...]") it records one snapshot:
 *   RPNS-BEGIN/CTX/NS/MOUNT(INFO)/LOOKUP/GAP/END records
 * The observer's EACCES is a recorded gap, never a negative result.
 * The tool never writes, mounts, or signals anything but its log.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

/* Self-contained statx surface (linux/statx.h may be absent on some
 * toolchains): the offset layout is the UAPI contract of
 * linux/statx.h; STATX_MNT_ID requires kernel >= 5.8, where the field
 * exists at offset 0x90. */
#ifndef STATX_BASIC_STATS
#define STATX_BASIC_STATS 0x000007ffU
#endif
#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x1000
#endif
struct statx_mind {
    unsigned int stx_mask;
    unsigned int stx_blksize;
    unsigned long long stx_attributes;
    unsigned int stx_nlink;
    unsigned int stx_uid;
    unsigned int stx_gid;
    unsigned short stx_mode;
    unsigned short __spare0;
    unsigned long long stx_ino;
    unsigned long long stx_size;
    unsigned long long stx_blocks;
    unsigned long long stx_attributes_mask;
    unsigned long long stx_atime_sec;
    unsigned int stx_atime_nsec;
    int __pad1;
    unsigned long long stx_btime_sec;
    unsigned int stx_btime_nsec;
    int __pad2;
    unsigned long long stx_ctime_sec;
    unsigned int stx_ctime_nsec;
    int __pad3;
    unsigned long long stx_mtime_sec;
    unsigned int stx_mtime_nsec;
    int __pad4;
    unsigned int stx_rdev_major;
    unsigned int stx_rdev_minor;
    unsigned int stx_dev_major;
    unsigned int stx_dev_minor;
    unsigned long long stx_mnt_id;
};
#ifndef SYS_statx
#define SYS_statx 332
#endif

#define MAXSEEN 256

static void wallstamp(char *b, size_t n) {
    struct timespec ts; struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts); gmtime_r(&ts.tv_sec, &tm);
    snprintf(b, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec/1000000);
}

static int seen_pids[MAXSEEN];
static int seen_n;

static int was_seen(int pid) {
    for (int i = 0; i < seen_n; i++) if (seen_pids[i] == pid) return 1;
    return 0;
}

static void mark_seen(int pid) {
    if (seen_n < MAXSEEN) seen_pids[seen_n++] = pid;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <logfile> <stopfile>\n", argv[0]); return 2; }
    FILE *lg = fopen(argv[1], "a");
    if (!lg) return 2;
    char ts[40], path[256], buf[65536], nsid[256];
    wallstamp(ts, sizeof ts);
    fprintf(lg, "PNS-START %s\n", ts);
    fflush(lg);
    for (;;) {
        FILE *sf = fopen(argv[2], "r");
        if (sf) { fclose(sf); break; }
        DIR *d = opendir("/proc");
        if (!d) break;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strspn(e->d_name, "0123456789") != strlen(e->d_name)) continue;
            snprintf(path, sizeof path, "/proc/%s/comm", e->d_name);
            int fd = open(path, O_RDONLY);
            if (fd < 0) continue;
            ssize_t r = read(fd, buf, sizeof buf - 1);
            close(fd);
            if (r <= 0) continue;
            buf[r] = '\0'; buf[strcspn(buf, "\n")] = '\0';
            int is_init = strstr(buf, "runc:[") != NULL;
            int is_bkd = strstr(buf, "buildkitd") != NULL;
            if (!is_init && !is_bkd) continue;
            int pid = atoi(e->d_name);
            /* The container init is short-lived and MUTATES its own view
             * (pivot_root, fresh proc mount, the failing self-bind): it is
             * RE-SNAPSHOTTED on every sweep so the failing mount() has a
             * bounded bracket of post-pivot views tied to the syscall
             * timeline (rep=0 only on the first observation). buildkitd
             * is stable: one snapshot per pid (rep stays 0). */
            if (!is_init && was_seen(pid)) continue;
            int first = !was_seen(pid);
            if (first) mark_seen(pid);
            int rep = first ? 0 : 1;
            wallstamp(ts, sizeof ts);
            fprintf(lg, "RPNS-BEGIN %s pid=%d comm=%s rep=%d\n", ts, pid, buf, rep);
            /* SELinux context */
            snprintf(path, sizeof path, "/proc/%d/attr/current", pid);
            fd = open(path, O_RDONLY);
            if (fd >= 0) {
                r = read(fd, buf, sizeof buf - 1);
                close(fd);
                if (r > 0) {
                    buf[r] = '\0'; buf[strcspn(buf, "\n")] = '\0';
                    fprintf(lg, "RPNS-CTX pid=%d selinux_context=%s\n", pid, buf);
                }
            }
            /* namespace identities: the process's own ns/user readlink IS
             * the userns of the mountns creator on the fresh
             * unshare/clone chains recorded here (recorded verbatim) */
            const char *nss[3] = {"user", "pid", "mnt"};
            for (int i = 0; i < 3; i++) {
                snprintf(path, sizeof path, "/proc/%d/ns/%s", pid, nss[i]);
                ssize_t lr = readlink(path, nsid, sizeof nsid - 1);
                if (lr > 0) {
                    nsid[lr] = '\0';
                    fprintf(lg, "RPNS-NS pid=%d ns=%s target=%s\n", pid, nss[i], nsid);
                }
            }
            /* raw mountinfo: every line verbatim (major:minor, root,
             * mountpoint and propagation tags stay in the raw text); a
             * failed or empty read is an explicit GAP record */
            snprintf(path, sizeof path, "/proc/%d/mountinfo", pid);
            fd = open(path, O_RDONLY);
            if (fd >= 0) {
                fprintf(lg, "RPNS-MOUNTINFO-BEGIN pid=%d\n", pid);
                size_t off = 0;
                int read_err = 0;
                for (ssize_t rr = 0; (rr = read(fd, buf + off, sizeof buf - 1 - off)) > 0; off += (size_t)rr) {
                }
                read_err = errno;
                if (off >= sizeof buf - 1) read_err = 0;
                if (off == 0) {
                    fprintf(lg, "RPNS-GAP pid=%d mountinfo=empty errno=%d\n", pid, read_err);
                }
                close(fd);
                buf[off] = '\0';
                char *ls = buf;
                for (char *nl = strchr(ls, '\n'); nl; ls = nl + 1, nl = strchr(ls, '\n')) {
                    *nl = '\0';
                    fprintf(lg, "RPNS-MOUNT pid=%d %s\n", pid, ls);
                }
                fprintf(lg, "RPNS-MOUNTINFO-END pid=%d\n", pid);
            } else {
                fprintf(lg, "RPNS-MOUNTINFO-BEGIN pid=%d\nRPNS-GAP pid=%d mountinfo errno=%d\n", pid, pid, errno);
            }
            /* Observer-readonly lookups through the pid's own root DFS,
             * each carrying STATX_MNT_ID so the resolved target binds to
             * a mountinfo line by mount id (the failing self-bind's target
             * correlation); an impossible read is a GAP, not a verdict. */
            const char *lookups[3] = {"proc", "proc/bus", "proc/sys"};
            for (int i = 0; i < 3; i++) {
                snprintf(path, sizeof path, "/proc/%d/root/%s", pid, lookups[i]);
                /* The kernel copies the FULL UAPI struct statx (264+
                 * bytes on current kernels) into the buffer: over-allocate
                 * and zero a generous fixed area, then read the fields by
                 * their own offsets. */
                unsigned char sxb[320];
                memset(sxb, 0, sizeof sxb);
                struct statx_mind *sx = (struct statx_mind *)sxb;
                long sxr = syscall(SYS_statx, AT_FDCWD, path, 0,
                                   STATX_BASIC_STATS | STATX_MNT_ID, sxb);
                if (sxr == 0 && (sx->stx_mask & STATX_MNT_ID)) {
                    fprintf(lg,
                            "RPNS-STATX pid=%d path=/proc/%s mnt_id=%llu dev=%u:%u ino=%llu mode=%o mask=%#x\n",
                            pid, lookups[i],
                            (unsigned long long)sx->stx_mnt_id,
                            sx->stx_dev_major, sx->stx_dev_minor,
                            (unsigned long long)sx->stx_ino,
                            sx->stx_mode & 07777, sx->stx_mask);
                    struct stat st;
                    if (stat(path, &st) == 0) {
                        char lbl[256];
                        ssize_t xr = lgetxattr(path, "security.selinux", lbl, sizeof lbl - 1);
                        if (xr > 0) { lbl[xr] = '\0'; } else { snprintf(lbl, sizeof lbl, "<rc=%ld>", (long)xr); }
                        fprintf(lg, "RPNS-LOOKUP pid=%d path=/proc/%s stat=ok dev=%lu ino=%lu mode=%o label=%s\n",
                                pid, lookups[i], (unsigned long)st.st_dev,
                                (unsigned long)st.st_ino, st.st_mode & 07777, lbl);
                    } else {
                        fprintf(lg, "RPNS-LOOKUP pid=%d path=/proc/%s GAP errno=%d\n", pid, lookups[i], errno);
                    }
                } else {
                    fprintf(lg, "RPNS-STATX pid=%d path=/proc/%s GAP errno=%d mask=%#x\n",
                            pid, lookups[i], sxr < 0 ? errno : ENODATA,
                            STATX_BASIC_STATS | STATX_MNT_ID);
                    snprintf(path, sizeof path, "/proc/%d/root/%s", pid, lookups[i]);
                    struct stat st;
                    if (stat(path, &st) == 0) {
                        fprintf(lg, "RPNS-LOOKUP pid=%d path=/proc/%s stat=ok dev=%lu ino=%lu mode=%o statx=<unavailable>\n",
                                pid, lookups[i], (unsigned long)st.st_dev,
                                (unsigned long)st.st_ino, st.st_mode & 07777);
                    } else {
                        fprintf(lg, "RPNS-LOOKUP pid=%d path=/proc/%s GAP errno=%d\n", pid, lookups[i], errno);
                    }
                }
            }
            wallstamp(ts, sizeof ts);
            fprintf(lg, "RPNS-END %s pid=%d\n", ts, pid);
            fflush(lg);
        }
        closedir(d);
        fflush(lg);
        struct timespec slp = {0, 5 * 1000 * 1000};
        nanosleep(&slp, NULL);
    }
    wallstamp(ts, sizeof ts);
    fprintf(lg, "PNS-DONE %s\n", ts);
    fclose(lg);
    return 0;
}
PNSCEOF
gcc -O2 -Wall -o "$EVIDENCE_DIR/p21e3_procns_snap" "$EVIDENCE_DIR/p21e3_procns_snap.c" \
  || fail "procns snapshotter compile failed"
log "procns snapshotter compiled"
cat > "$EVIDENCE_DIR/p21e3_nsier.c" <<'NIROF'
/* p21e3_nsier.c — the namespace-instance resolver (R4-P3-P6-MNB12).
 *
 * READ-ONLY: enters the TARGET's mount namespace (setns of its own procns
 * fd), resolves through the inherited /proc instance:
 *   NSR-TARGET-MNTNS   — the target's mount ns (readlink, before setns)
 *   NSR-ENTERED-MNTNS  — our mount ns after setns (should equal the target)
 *   NSR-PROBE-USERNS   — our (probe) user ns
 *   NSR-PROC-MOUNT     — the /proc line: RUN-LOCAL mount id + major:minor
 *   NSR-SERVING-PIDNS  — readlink /proc/1/ns/pid THROUGH the instance: the
 *                        PID namespace that services exactly this procfs
 *   NSR-SERVING-USERNS — NS_GET_USERNS on the opened serving-pidns fd
 *   NSR-INSTANCE-INIT  — /proc/1's comm THROUGH the instance
 *   NSR-TASKC          — the task count visible through the instance
 * No mount/unmount/remount/write of any kind; every fd opened O_RDONLY|
 * O_CLOEXEC and closed. The NS_GET_USERNS numbers are defined locally so
 * no <linux/nsfs.h> dependency is needed.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#ifndef NSIO
#define NSIO 0xb7
#endif
#ifndef NS_GET_USERNS
#define NS_GET_USERNS _IO(NSIO, 0x1)
#endif
#ifndef NS_GET_NSPID
#define NS_GET_NSPID _IO(NSIO, 0x2)
#endif
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <target-pid>\n", argv[0]); return 2; }
    char path[128], buf[256];
    ssize_t n;

    snprintf(path, sizeof(path), "/proc/%s/ns/mnt", argv[1]);
    int mfd = open(path, O_RDONLY | O_CLOEXEC);
    if (mfd < 0) { perror("open target mntns"); return 3; }
    n = readlink(path, buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = '\0'; printf("NSR-TARGET-MNTNS %s\n", buf); }
    if (setns(mfd, CLONE_NEWNS) != 0) { perror("setns CLONE_NEWNS"); close(mfd); return 4; }
    n = readlink("/proc/self/ns/mnt", buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = '\0'; printf("NSR-ENTERED-MNTNS %s\n", buf); }
    n = readlink("/proc/self/ns/user", buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = '\0'; printf("NSR-PROBE-USERNS %s\n", buf); }
    close(mfd);

    FILE *mi = fopen("/proc/self/mountinfo", "r");
    if (!mi) { perror("mountinfo"); return 5; }
    char line[8192];
    while (fgets(line, sizeof(line), mi)) {
        if (strstr(line, " - proc proc ")) {
            char id[32] = "", parent[32] = "", dev[64] = "";
            sscanf(line, "%31s %31s %63s", id, parent, dev);
            printf("NSR-PROC-MOUNT id=%s %s\n", id, line);
            printf("NSR-PROC-DEV dev=%s\n", dev);
            break;
        }
    }
    fclose(mi);

    n = readlink("/proc/1/ns/pid", buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = '\0'; printf("NSR-SERVING-PIDNS %s\n", buf); }
    else perror("readlink /proc/1/ns/pid");

    int pfd = open("/proc/1/ns/pid", O_RDONLY | O_CLOEXEC);
    if (pfd >= 0) {
        int ufd = ioctl(pfd, NS_GET_USERNS, 0);
        if (ufd >= 0) {
            char fdpath[64];
            snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", ufd);
            n = readlink(fdpath, buf, sizeof(buf) - 1);
            if (n > 0) { buf[n] = '\0'; printf("NSR-SERVING-USERNS %s\n", buf); }
            else perror("readlink userns fd");
            close(ufd);
        } else {
            printf("NSR-SERVING-USERNS-GAP errno=%d (%s)\n", errno, strerror(errno));
        }
        close(pfd);
    }

    FILE *c = fopen("/proc/1/comm", "r");
    if (c) {
        char cm[128] = "";
        if (fgets(cm, sizeof(cm), c)) { char *nl = strchr(cm, '\n'); if (nl) *nl = 0;
            printf("NSR-INSTANCE-INIT %s\n", cm); }
        fclose(c);
    }
    DIR *d = opendir("/proc");
    if (d) {
        long tc = 0;
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] >= '0' && e->d_name[0] <= '9') tc++;
        }
        closedir(d);
        printf("NSR-TASKC %ld\n", tc);
    }
    printf("NSR-DONE\n");
    return 0;
}
NIROF
if ! command -v gcc >/dev/null 2>&1; then
  timeout 300 zypper --non-interactive install -y gcc 2>&1 | tail -2
fi
gcc -O2 -Wall -o "$EVIDENCE_DIR/p21e3_nsier" "$EVIDENCE_DIR/p21e3_nsier.c" \
  || fail "namespace-instance resolver compile failed"
log "namespace-instance resolver compiled"

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
  if [ -n "${PROC_INVENTORY_PID:-}" ]; then
    touch "$STOPSAMP" 2>/dev/null || true
    wait "$PROC_INVENTORY_PID" 2>/dev/null || true
    PROC_INVENTORY_PID=""
  fi
  if [ -n "${CAPWATCH_PID:-}" ]; then
    touch "$STOPSAMP" 2>/dev/null || true
    wait "$CAPWATCH_PID" 2>/dev/null || true
    CAPWATCH_PID=""
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

# The fixed diag-module rung (R4-P3-P6-MNB9..MNB22): a temporary loadable
# module carrying EXACTLY the reviewed rows (currently the seven MNB18 rows:
# proc_t:dir mounton, proc_t:filesystem remount, sysctl_irq_t:dir mounton,
# sysctl_t:dir mounton, sysctl_t:file mounton, proc_kcore_t:file getattr, proc_kcore_t:file mounton), plus —
# in the dedicated-type diagnostic mode only — a second, purely CIL module carrying
# dedicated types for /keys and /timer_list with the proc_t attribute
# memberships and their reviewed permissions. It loads AFTER the row module and
# BEFORE the measured build, so the genfscon decision applies at the
# initialization of every procfs inode created from then on (fresh container
# procfs instances included). Both are removed and verified independently at
# the teardown. The release policy bytes are never touched.
# p21e3_diag_remove is idempotent (once-guard) and
# must be paired with the policy RESTORE in that order on every exit path:
# a removal rebuild discards the disable-dontaudit build flag, so removing
# the module first lets the subsequent semodule -B restoration verify
# against the true pre-toggle baseline.
DIAG_MODULE=docker_helper_diag_mounton
DIAG_ACTIVE=0
DIAG_REMOVED=0
DIAG_MODULES=""
if [ "${R7_MNB30:-0}" = 1 ]; then
  # MNB30: the ONLY temporary policy state is the three-rule capability module
  # (the MNB24/26/27 grants; temporary exactly as before).
  DIAG_MODULES="docker_helper_diag_cap"
elif [ "${R7_P21E3_DIAG_KEYS:-0}" = 1 ]; then
  DIAG_MODULES="$DIAG_MODULE docker_helper_diag_keys docker_helper_diag_cap"
else
  DIAG_MODULES="$DIAG_MODULE"
fi
p21e3_diag_remove() {
  [ "${DIAG_ACTIVE:-0}" = 1 ] || return 0
  [ "${DIAG_REMOVED:-0}" = 1 ] && return 0
  local out rc mod all
  all=ok
  # A diagnostic round may carry MORE THAN ONE temporary module (the
  # dedicated-type CIL block rides next to the fixed row module). Every
  # removal is performed and logged; the round is marked removed ONLY when
  # every `semodule -r` exits 0 — a failed removal keeps retrying on the
  # next call (the failure is visible in the log and the terminal unload
  # gate stays fail-closed on the sesearch/store/policy-sha checks).
  for mod in $DIAG_MODULES; do
    out="$(semodule -r "$mod" 2>&1)"
    rc=$?
    printf 'p21e3_diag_remove: semodule -r %s rc=%d %s\n' "$mod" "$rc" "$out" \
      >> "${DIAG_LOG:-$EVIDENCE_DIR/p21e3-diag-mounton.log}"
    if [ "$rc" != 0 ]; then
      all=fail
    fi
  done
  if [ "$all" = ok ]; then
    DIAG_REMOVED=1
  fi
  return 0
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

# R4-P3-P6-MNB14: read-only /proc/sys preflight (no diag module, no build,
# no session usage). Reads genfscon from the loaded policy and the /proc/sys
# mountinfo view from builder, init and (if present) rootfs/proc views. Read
# only: no mount/automount triggering, no policy change.
if [ "${R7_P21E3_PROC_SYS:-0}" = 1 ]; then
  SYS_LOG="$EVIDENCE_DIR/p21e3-proc-sys.log"
  : > "$SYS_LOG"
  {
    echo "== /proc/sys preflight (R4-P3-P6-MNB14), read-only, no policy change =="
    echo "enforcement: $(getenforce 2>&1 || echo unknown)"
    echo "loaded-policy sha256: $(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
    echo "-- genfscon from the loaded policy (seinfo --genfscon -- /sys/fs/selinux/policy) =="
    if command -v seinfo >/dev/null 2>&1; then
      seinfo --genfscon -- /sys/fs/selinux/policy 2>&1 | grep -iE 'proc|sysctl|irq' || true
    else
      echo "seinfo unavailable: genfscon not captured"
    fi
    echo "-- /proc/sys label: policy prediction vs the live inode (stat of /proc/sys itself only) =="
    if command -v matchpathcon >/dev/null 2>&1; then
      echo "matchpathcon /proc/sys: $(matchpathcon /proc/sys 2>&1 || true)"
    else
      echo "matchpathcon unavailable: label not captured"
    fi
    ls -Zd /proc/sys 2>&1
    echo "-- /proc and /proc/sys mountinfo in the harness (init) mount namespace (fstype parsed after the '-') =="
    awk '$5=="/proc" || $5=="/proc/sys" || $5 ~ /^\/proc\/sys\// { fstype=""; for (i=6;i<=NF;i++) if ($i=="-") { fstype=$(i+1); break } print "INIT-MOUNT fstype=" fstype " " $0 }' /proc/self/mountinfo 2>/dev/null || true
    echo "-- /proc/sys resolved mount entry (findmnt -T /proc/sys; stat of /proc/sys only; binfmt_misc is NOT traversed) =="
    if command -v findmnt >/dev/null 2>&1; then
      findmnt -T /proc/sys -n -o ID,MAJ:MIN,FSTYPE,TARGET,OPTIONS,PROPAGATION 2>&1 || true
    else
      echo "findmnt unavailable: mount id/propagation not captured"
    fi
    echo "-- /proc/sys mountinfo in the builder mount namespace (same fstype parsing; mountinfo read only) =="
    BKD_PID="$(pgrep -u "$(id -u docker-helper-builder 2>/dev/null || echo 0)" -x buildkitd 2>/dev/null | head -1 || true)"
    if [ -n "$BKD_PID" ]; then
      echo "builder pid=$BKD_PID"
      awk '$5=="/proc" || $5=="/proc/sys" || $5 ~ /^\/proc\/sys\// { fstype=""; for (i=6;i<=NF;i++) if ($i=="-") { fstype=$(i+1); break } print "BUILDER-MOUNT pid='$BKD_PID' fstype=" fstype " " $0 }' "/proc/$BKD_PID/mountinfo" 2>/dev/null || true
      echo "builder mountns=$(readlink "/proc/$BKD_PID/ns/mnt" 2>/dev/null)"
      echo "builder userns=$(readlink "/proc/$BKD_PID/ns/user" 2>/dev/null)"
    else
      echo "no live buildkitd observed: builder /proc/sys view not captured here (the builder view is bound through the MNB14 build-window procns snapshots in its report)"
    fi
    echo "-- rootfs/proc view =="
    echo "GAP: rootfs/proc is only present during a build; this preflight runs without a build, so the rootfs/proc /proc/sys view is not captured here (the rootfs/proc view is bound through the MNB14 build-window procns snapshots in its report)"
    echo "-- propagation / nested mounts check (mountinfo read only; the propagation tags are inside the full lines above; binfmt_misc is NOT path-traversed, no automount triggered) =="
    awk '$5=="/proc" || $5=="/proc/sys" || $5 ~ /^\/proc\/sys\// { opts=""; for (i=6;i<=NF && $i!="-"; i++) opts=opts (opts==""?"":",") $i; print "PROP " $5 " opts=" opts }' /proc/self/mountinfo 2>/dev/null || true
    SUBMOUNTS="$(awk '$5 ~ /^\/proc\/sys\//' /proc/self/mountinfo 2>/dev/null | wc -l)"
    echo "submounts under /proc/sys in the init view: $SUBMOUNTS (each is listed above as an INIT-MOUNT row; reading mountinfo does not touch the autofs mountpoint)"
    echo "== preflight end =="
  } > "$SYS_LOG" 2>&1
  cat "$SYS_LOG"
  printf 'R7-P21E3-BUILD=skipped(proc-sys-preflight)\n'
  printf 'R7-P21E3-VERDICT=MEASURED\n'
  touch "$STATE_DIR/sec5"
  exit 0
fi

# R4-P3-P6-MNB15proc: read-only preflight for the sysctl_t:file rung
# (/proc/sysrq-trigger and the full procfs sysctl_t coverage). No diag
# module, no build, no session usage. METADATA ONLY: no file writes, and
# binfmt_misc is never path-traversed (no automount triggering anywhere).
if [ "${R7_P21E3_PROC_FILE:-0}" = 1 ]; then
  FILE_LOG="$EVIDENCE_DIR/p21e3-proc-file.log"
  : > "$FILE_LOG"
  {
    echo "== sysctl_t:file preflight (R4-P3-P6-MNB15proc), read-only, metadata only =="
    echo "enforcement: $(getenforce 2>&1 || echo unknown)"
    echo "loaded-policy sha256: $(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
    echo "-- genfscon from the loaded policy: the FULL proc section (no filter) =="
    if command -v seinfo >/dev/null 2>&1; then
      seinfo --genfscon -- /sys/fs/selinux/policy 2>&1 | grep -a '^ *genfscon proc ' || true
    else
      echo "seinfo unavailable: genfscon not captured"
    fi
    echo "-- the sysrq-trigger genfscon rows (the direct coverage answer) =="
    if command -v seinfo >/dev/null 2>&1; then
      seinfo --genfscon -- /sys/fs/selinux/policy 2>&1 | grep -a 'sysrq' || true
    fi
    echo "-- every genfscon row typed sysctl_t (whole policy, every fs) =="
    if command -v seinfo >/dev/null 2>&1; then
      seinfo --genfscon -- /sys/fs/selinux/policy 2>&1 | grep -aE 'object_r:sysctl_t:s0' || true
    fi
    echo "-- policy capabilities (read-only cat; genfs_seclabel_wildcard decides genfscon path matching) =="
    ls /sys/fs/selinux/policy_capabilities 2>&1 || echo "policy_capabilities listing unavailable"
    for f in /sys/fs/selinux/policy_capabilities/*; do
      [ -e "$f" ] || continue
      printf '%s=%s\n' "$(basename "$f")" "$(cat "$f" 2>&1)"
    done
    echo "-- nested mounts under /proc/sys in the init view (excluded BEFORE any traversal; mountinfo read only) =="
    EXC_PATHS="$(awk '$5 ~ /^\/proc\/sys\// {print $5}' /proc/self/mountinfo 2>/dev/null || true)"
    if [ -n "$EXC_PATHS" ]; then
      printf 'EXCLUDED-MOUNT %s\n' $EXC_PATHS
    else
      echo "EXCLUDED-MOUNT none"
    fi
    awk '$5=="/proc" { fstype=""; for (i=6;i<=NF;i++) if ($i=="-") { fstype=$(i+1); break } print "INIT-MOUNT fstype=" fstype " " $0 }' /proc/self/mountinfo 2>/dev/null || true
    echo "-- top-level /proc entries NOT labeled proc_t (the reachable non-proc_t inventory, metadata only; no recursion, no binfmt_misc) =="
    ls -Zd /proc/* 2>/dev/null | grep -avE ' /proc/[0-9]+$' | grep -av ' proc_t ' || echo "(all top-level procfs entries carry the fs default type)"
    echo "-- guest init namespace: every path INSIDE /proc/sys with the live label sysctl_t (metadata only: find listing + ls -Zd + findmnt stat; nested mounts from mountinfo pruned BEFORE the walk; no writes, no content reads) =="
    PRUNE_ARGS=()
    for m in $EXC_PATHS; do PRUNE_ARGS+=( -path "$m" -prune -o ); done
    SYS_INVENTORY="$(find /proc/sys "${PRUNE_ARGS[@]}" \( -type f -printf 'FILE %p\n' -o -type d -printf 'DIR %p\n' \) 2>/dev/null)"
    SYS_HITS=0
    while IFS= read -r row; do
      [ -n "$row" ] || continue
      kind="${row%% *}"; p="${row#* }"
      lbl="$(ls -Zd "$p" 2>&1)"
      case "$lbl" in
        *sysctl_t:s0*)
          SYS_HITS=$((SYS_HITS + 1))
          bind="(findmnt unavailable)"
          if command -v findmnt >/dev/null 2>&1; then
            bind="$(findmnt -T "$p" -n -o ID,MAJ:MIN,FSTYPE,TARGET,OPTIONS,PROPAGATION 2>&1 || true)"
          fi
          printf 'SYSTL-TARGET %s %s -> %s | mount: %s\n' "$kind" "$p" "$lbl" "$bind"
          ;;
      esac
    done <<EOF
$SYS_INVENTORY
EOF
    echo "SYSTL-TARGET-COUNT inside /proc/sys: $SYS_HITS"
    echo "-- representation notes (metadata probes ran in the guest init/harness namespace) =="
    echo "INIT-NAMESPACE: the labels and mount bindings above are direct measurements of the guest init (harness) namespace."
    echo "GAP-BUILDER: no live buildkitd in this build-free preflight; no direct builder-namespace measurement of the /proc/sys subtree targets here. The builder binding is carried by the build-window procns snapshots (MNB14/MNB15: the /proc subtree resolves through the same proc superblock instance; MNB15 pid=3523/4738: proc mount 338/0:46; post-pivot runc: 457/0:52)."
    echo "GAP-RUNC: no direct runc-namespace measurement of the individual targets in this build-free preflight; the runc binding is carried by MNB15 (RPNS 457/0:52 post-pivot pre-self-bind; strace 7036-7038 for /proc/sys; AVC 1233 for /proc/sysrq-trigger)."
    echo "-- rootfs/proc view =="
    echo "GAP: rootfs/proc is only present during a build; this preflight runs without a build. The rootfs/proc binding is carried by the MNB15 evidence: RPNS resolved /proc at 457/0:52 post-pivot (pre-self-bind of /proc/sys) and AVC serial 1233 gave the kernel binding tcontext=sysctl_t (tclass=file, ino=4026532086) at the bind attempt."
    echo "== preflight end =="
  } > "$FILE_LOG" 2>&1
  cat "$FILE_LOG"
  printf 'R7-P21E3-BUILD=skipped(proc-file-preflight)\n'
  printf 'R7-P21E3-VERDICT=MEASURED\n'
  touch "$STATE_DIR/sec5"
  exit 0
fi

# R4-P3-P6-MNB18proc: read-only policy/label analysis for a dedicated
# /proc/keys type. No diag module, no build, no relabel, no session usage.
# Metadata + loaded-policy queries only; the later-mounton bind check stays
# a hypothesis (explicitly marked, never measured here).
if [ "${R7_P21E3_PROC_KEYS:-0}" = 1 ]; then
  KEYS_LOG="$EVIDENCE_DIR/p21e3-proc-keys.log"
  : > "$KEYS_LOG"
  {
    echo "== /proc/keys dedicated-type preflight (R4-P3-P6-MNB18proc), read-only, no policy change, no relabel =="
    echo "enforcement: $(getenforce 2>&1 || echo unknown)"
    echo "loaded-policy sha256: $(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
    echo "-- genfscon: the proc rows that decide the /proc/keys label =="
    if command -v seinfo >/dev/null 2>&1; then
      seinfo --genfscon -- /sys/fs/selinux/policy 2>&1 | grep -a '^ *genfscon proc ' | grep -aE ' / | /keys' || true
      seinfo --genfscon -- /sys/fs/selinux/policy 2>&1 | grep -a 'keys' | grep -av sysctl || true
    fi
    echo "-- /proc/keys live label + binding in the harness (init) view (metadata only) =="
    ls -Zd /proc/keys /proc/timer_list 2>&1
    stat -c 'stat: mode=%a ino=%i' /proc/keys 2>&1 || true
    if command -v findmnt >/dev/null 2>&1; then
      findmnt -T /proc/keys -n -o ID,MAJ:MIN,FSTYPE,TARGET,OPTIONS,PROPAGATION 2>&1 || true
    fi
    awk '$5=="/proc" { fstype=""; for (i=6;i<=NF;i++) if ($i=="-") { fstype=$(i+1); break } print "INIT-MOUNT fstype=" fstype " " $0 }' /proc/self/mountinfo 2>/dev/null || true
    echo "INIT-ROW-COUNT: $(awk '$5 ~ /^\/proc\/keys/' /proc/self/mountinfo 2>/dev/null | wc -l) separate /proc/keys mounts"
    echo "-- xattr confirmation on the host procfs instance (read-only) =="
    if command -v python3 >/dev/null 2>&1; then
      python3 - <<'PYEOF' 2>&1
import os
for p in ("/proc/keys", "/proc/sysrq-trigger"):
    try:
        lab = os.getxattr(p, "security.selinux")
        print("xattr security.selinux on %s: %r" % (p, lab))
    except OSError as e:
        print("xattr security.selinux on %s: OSError errno=%d" % (p, e.errno))
PYEOF
    fi
    echo "-- proc_t type membership (attributes; the carrier of attribute-based rules) =="
    if command -v seinfo >/dev/null 2>&1; then
      seinfo -xt proc_t 2>&1 || seinfo -x proc_t 2>&1 || echo "seinfo -x unavailable"
    fi
    echo "-- DIRECT allow rules on proc_t:file (exact target proc_t; these STOP matching /proc/keys after a relabel) — all domains =="
    sesearch -A -t proc_t -c file > "$EVIDENCE_DIR/p21e3-proc-file-rules-full.log" 2>&1 || true
    wc -l < "$EVIDENCE_DIR/p21e3-proc-file-rules-full.log"
    grep -aE '^allow [a-z_0-9]+ proc_t:file' "$EVIDENCE_DIR/p21e3-proc-file-rules-full.log" | head -60
    echo "-- domains with DIRECT proc_t:file rules (the candidate losers; perm detail in the full capture) =="
    grep -aE '^allow [a-z_0-9]+ proc_t:file' "$EVIDENCE_DIR/p21e3-proc-file-rules-full.log" \
      | awk '{print $2}' | sort | uniq -c | sort -rn | head -30
    echo "-- docker_helper domains: DIRECT proc_t:file rules =="
    grep -aE '^allow docker_helper[a-z_0-9]* proc_t:file' "$EVIDENCE_DIR/p21e3-proc-file-rules-full.log" || echo "(none)"
    echo "-- ATTRIBUTE-based rules that cover proc_t files (persist for a new type ONLY if the new type carries the same attribute memberships) =="
    ATTR_LIST="$(seinfo -xt proc_t 2>/dev/null | sed -n 's/^ *type proc_t, *\(.*\);$/\1/p' | tr ',' '\n' | awk '{$1=$1;print}')"
    echo "proc_t attributes: $(echo "$ATTR_LIST" | tr '\n' ' ')"
    for attr in $ATTR_LIST; do
      [ "$attr" = proc_t ] && continue
      n="$(sesearch -A -t "$attr" -c file 2>/dev/null | wc -l)"
      echo "attr=$attr rules=-t $attr -c file count=$n"
      sesearch -A -t "$attr" -c file 2>/dev/null | grep -aE '^allow docker_helper[a-z_0-9]*' | head -8
    done
    echo "-- the docker_helper_buildkitd_t namespace: sesearch -A -s buildkitd_t -t proc_t -c file (direct AND attribute expansion) =="
    sesearch -A -s docker_helper_buildkitd_t -t proc_t -c file 2>&1 || true
    echo '-- hypothesis (NOT measured here, explicit per review):'
    echo 'If the mask ladder proceeds past the dedicated-getattr rule, the later bind /dev/null over the relabeled /proc/keys would need <new-type>:file mounton — the same class-of-target rung measured for /proc/kcore (MNB17 AVC 1237 -> MNB18 mount = 0). AVC 1217 (MNB18) proves only the getattr/fstat refusal.'
    echo "-- representation matrix for a relabel (metadata-based reasoning; no change performed) =="
    echo "HOST-procfs instance: the container's /proc/keys bind lives on the SAME host superblock as the harness init view (mount 52/0:27 = MNB15 builder/parent 338/0:46 at same mnt-ns 4026532281) — an xattr relabel of the HOST /proc/keys changes the label in the init AND builder views; matchpathcon-based tools then see the new type."
    echo "CONTAINER procfs instance: post-pivot rootfs/proc is a SEPARATE procfs superblock (MNB15: 457/0:52; AVC 1217 tcontext=proc_t reflects THAT instance under the same genfscon default) — a host-side relabel does NOT change the container instance; a dedicated type created with a genfscon row would label BOTH instances at inode creation."
    echo "== preflight end =="
  } > "$KEYS_LOG" 2>&1
  cat "$KEYS_LOG"
  printf 'R7-P21E3-BUILD=skipped(proc-keys-preflight)\n'
  printf 'R7-P21E3-VERDICT=MEASURED\n'
  touch "$STATE_DIR/sec5"
  exit 0
fi

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
# R4-P3-P6-MNB12: in the read-only baseline probe mode the toggle is
# SKIPPED — policy bytes must not move at all on that round.
if [ "${R7_P21E3_PROBE:-0}" != 1 ] && [ "${R7_P21E3_PROC_SYS:-0}" != 1 ] && [ "${R7_P21E3_PROC_FILE:-0}" != 1 ] && [ "${R7_P21E3_PROC_KEYS:-0}" != 1 ]; then
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
fi  # end of the dontaudit-toggle probe guard (policy bytes untouched in probe mode)

# --- the whole diagnostic-module machinery (load, unload, verification) is
# --- guarded: in the read-only probe mode nothing is loaded or (re)built.
# --- The guard REPLACES the module section with an explicit skip note.
DIAG_LOG="$EVIDENCE_DIR/p21e3-diag-mounton.log"
if [ "${R7_P21E3_PROBE:-0}" = 1 ]; then
  log "probe mode: no diagnostic module is loaded (the baseline policy stays in place)"
  {
    echo "probe mode: the fixed single-row module was NOT loaded; the baseline policy stayed in place for the whole round"
    printf 'R7-P21E3-DIAG-UNLOADED=not-applicable\n'
  } > "$DIAG_LOG"
  cat "$DIAG_LOG"
else
# --- the fixed single-row diagnostic module (R4-P3-P6-MNB9 rung): compiled
# --- from a one-rule source, loaded through `semodule -i` ONLY, removed and
# --- independently verified at the teardown (trap + explicit sequence). The
# --- DELTA is exactly the reviewed row; nothing else is ever loaded.
if ! command -v checkmodule >/dev/null 2>&1 || ! command -v semodule_package >/dev/null 2>&1; then
  timeout 300 zypper --non-interactive install -y checkpolicy policycoreutils 2>&1 | tail -3
fi
command -v checkmodule >/dev/null 2>&1 || fail "checkmodule unavailable; the diagnostic module cannot be compiled"
command -v semodule_package >/dev/null 2>&1 || fail "semodule_package unavailable; the diagnostic module cannot be packaged"
DIAG_PP="$EVIDENCE_DIR/docker_helper_diag_mounton.pp"
# checkmodule validates the OUTPUT base filename against the module name in
# the source header; the exact comparison form differs between checkmodule
# versions (with or without the .pp extension stripped). Naming the
# checkmodule output EXACTLY the module name (no extension) satisfies every
# observed version; the packager output keeps the .pp name for `semodule -i`.
DIAG_COMPILE_OUT="$EVIDENCE_DIR/docker_helper_diag_mounton"
DIAG_RELEASE_PP_SHA_PRE="$(sha256sum /usr/share/selinux/docker_helper.pp 2>/dev/null | awk '{print $1}')"
{
  echo "== fixed single-row diagnostic module: $DIAG_MODULE (temporary) =="
  echo "committed-policy delta: NONE (temporary module only; unload verified at the teardown)"
  echo "release-policy .pp sha (must not change): $DIAG_RELEASE_PP_SHA_PRE"
} > "$DIAG_LOG"
# Residual self-heal: a crashed previous attempt could leave the module
# registered; the removal attempt is logged, and the baseline check below
# decides fail-closed whether the rule is REALLY absent.
semodule -r "$DIAG_MODULE" >> "$DIAG_LOG" 2>&1 \
  || printf 'no residue to remove (semodule -r rc=%d)\n' "$?" >> "$DIAG_LOG"
echo "-- module store (before; docker-helper entries) --" >> "$DIAG_LOG"
semodule -l 2>/dev/null | grep -i docker >> "$DIAG_LOG" 2>&1 || true
DIAG_SHA_BASE="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
echo "policy sha baseline (pre-diag): $DIAG_SHA_BASE" >> "$DIAG_LOG"
echo "-- baseline sesearch (fail-closed: NO mounton/remount rule may exist) --" >> "$DIAG_LOG"
DIAG_BASE_Q="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t proc_t -c dir -p mounton 2>&1)"
DIAG_BASE_RC=$?
DIAG_BASE_V="$(classify_sesearch_query "$DIAG_BASE_RC" "$DIAG_BASE_Q")"
printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_BASE_RC" "$DIAG_BASE_V" "$DIAG_BASE_Q" >> "$DIAG_LOG"
if [ "$DIAG_BASE_V" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
  p21e3_diag_remove
  p21e3_dontaudit_restore
  p21e3_diag_remove
  fail "baseline sesearch is not an authoritative absence ($DIAG_BASE_V); the diagnostic rule must not pre-exist"
fi
DIAG_BASE_Q2="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t proc_t -c filesystem -p remount 2>&1)"
DIAG_BASE_RC2=$?
DIAG_BASE_V2="$(classify_sesearch_query "$DIAG_BASE_RC2" "$DIAG_BASE_Q2")"
printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_BASE_RC2" "$DIAG_BASE_V2" "$DIAG_BASE_Q2" >> "$DIAG_LOG"
if [ "$DIAG_BASE_V2" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
  p21e3_diag_remove
   p21e3_dontaudit_restore
    p21e3_diag_remove
    fail "baseline sesearch is not an authoritative absence for remount ($DIAG_BASE_V2); the diagnostic rule must not pre-exist"
fi
DIAG_BASE_Q3="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t sysctl_irq_t -c dir -p mounton 2>&1)"
DIAG_BASE_RC3=$?
DIAG_BASE_V3="$(classify_sesearch_query "$DIAG_BASE_RC3" "$DIAG_BASE_Q3")"
printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_BASE_RC3" "$DIAG_BASE_V3" "$DIAG_BASE_Q3" >> "$DIAG_LOG"
if [ "$DIAG_BASE_V3" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
  p21e3_diag_remove
  p21e3_dontaudit_restore
  p21e3_diag_remove
  fail "baseline sesearch is not an authoritative absence for sysctl_irq_t mounton ($DIAG_BASE_V3); the diagnostic rule must not pre-exist"
fi
# R4-P3-P6-MNB15: fail-closed baseline check for the FOURTH reviewed rule:
# sysctl_t:dir mounton must not pre-exist (the MNB14 AVC proved it denied).
DIAG_BASE_Q4="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t sysctl_t -c dir -p mounton 2>&1)"
DIAG_BASE_RC4=$?
DIAG_BASE_V4="$(classify_sesearch_query "$DIAG_BASE_RC4" "$DIAG_BASE_Q4")"
printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_BASE_RC4" "$DIAG_BASE_V4" "$DIAG_BASE_Q4" >> "$DIAG_LOG"
if [ "$DIAG_BASE_V4" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
  p21e3_diag_remove
  p21e3_dontaudit_restore
  p21e3_diag_remove
  fail "baseline sesearch is not an authoritative absence for sysctl_t mounton ($DIAG_BASE_V4); the diagnostic rule must not pre-exist"
fi
# R4-P3-P6-MNB16: fail-closed baseline check for the FIFTH reviewed rule:
# sysctl_t:file mounton must not pre-exist (the MNB15 AVC proved it denied).
DIAG_BASE_Q5="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t sysctl_t -c file -p mounton 2>&1)"
DIAG_BASE_RC5=$?
DIAG_BASE_V5="$(classify_sesearch_query "$DIAG_BASE_RC5" "$DIAG_BASE_Q5")"
printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_BASE_RC5" "$DIAG_BASE_V5" "$DIAG_BASE_Q5" >> "$DIAG_LOG"
if [ "$DIAG_BASE_V5" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
  p21e3_diag_remove
  p21e3_dontaudit_restore
  p21e3_diag_remove
  fail "baseline sesearch is not an authoritative absence for sysctl_t file mounton ($DIAG_BASE_V5); the diagnostic rule must not pre-exist"
fi
# R4-P3-P6-MNB17: fail-closed baseline check for the SIXTH reviewed rule:
# proc_kcore_t:file getattr must not pre-exist (the MNB16 AVC proved it denied).
DIAG_BASE_Q6="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t proc_kcore_t -c file -p getattr 2>&1)"
DIAG_BASE_RC6=$?
DIAG_BASE_V6="$(classify_sesearch_query "$DIAG_BASE_RC6" "$DIAG_BASE_Q6")"
printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_BASE_RC6" "$DIAG_BASE_V6" "$DIAG_BASE_Q6" >> "$DIAG_LOG"
if [ "$DIAG_BASE_V6" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
  p21e3_diag_remove
  p21e3_dontaudit_restore
  p21e3_diag_remove
  fail "baseline sesearch is not an authoritative absence for proc_kcore_t file getattr ($DIAG_BASE_V6); the diagnostic rule must not pre-exist"
fi
# R4-P3-P6-MNB18: fail-closed baseline check for the SEVENTH reviewed rule:
# proc_kcore_t:file mounton must not pre-exist (the MNB17 AVC proved it denied).
DIAG_BASE_Q7="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t proc_kcore_t -c file -p mounton 2>&1)"
DIAG_BASE_RC7=$?
DIAG_BASE_V7="$(classify_sesearch_query "$DIAG_BASE_RC7" "$DIAG_BASE_Q7")"
printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_BASE_RC7" "$DIAG_BASE_V7" "$DIAG_BASE_Q7" >> "$DIAG_LOG"
if [ "$DIAG_BASE_V7" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
  p21e3_diag_remove
  p21e3_dontaudit_restore
  p21e3_diag_remove
  fail "baseline sesearch is not an authoritative absence for proc_kcore_t file mounton ($DIAG_BASE_V7); the diagnostic rule must not pre-exist"
fi
# Require successful queries against the running policy before reporting absence.
p21e3_diag_proc_types_absent() {
  local listing target
  if ! listing="$(seinfo -xt proc_t 2>&1)" || ! grep -aq 'type proc_t' <<< "$listing"; then
    printf 'seinfo could not resolve proc_t: %s\n' "$listing"
    return 1
  fi
  for target in proc_keys_t proc_timer_list_t; do
    if ! listing="$(seinfo -xt "$target" 2>&1)" || ! grep -aqx 'Types: 0' <<< "$listing"; then
      printf 'seinfo did not prove %s absent: %s\n' "$target" "$listing"
      return 1
    fi
    printf 'seinfo: %s absent\n' "$target"
  done
  if ! listing="$(seinfo --genfscon -- /sys/fs/selinux/policy 2>&1)"; then
    printf 'the genfscon enumeration query failed: %s\n' "$listing"
    return 1
  fi
  if grep -aE '^[[:space:]]*genfscon[[:space:]]+proc[[:space:]]+/(keys|timer_list)([[:space:]]|$)' <<< "$listing"; then
    echo "an explicit proc genfscon for /keys or /timer_list is present"
    return 1
  fi
  echo "genfscon: /keys and /timer_list absent (successful seinfo --genfscon query first)"
}
if [ "${R7_MNB30:-0}" = 1 ]; then
  # MNB30: the mounton module rows are NOT part of this round — nothing is
  # compiled or installed here. The ONLY temporary policy state is the
  # three-rule capability module below (the MNB24/26/27 grants, temporary
  # exactly as before; the unload is verified at the teardown).
  log "mnb30 mode: the seven-row mounton module is not loaded (tracer-free transition round)"
  DIAG_RELEASE_PP_SHA_PRE="$(sha256sum /usr/share/selinux/docker_helper.pp 2>/dev/null | awk '{print $1}')"
fi
if [ "${R7_MNB30:-0}" != 1 ]; then
if [ "${R7_P21E3_DIAG_KEYS:-0}" = 1 ]; then
  echo "-- baseline pre-check (R4-P3-P6-MNB22): dedicated types and genfscon rows --" >> "$DIAG_LOG"
  if ! p21e3_diag_proc_types_absent >> "$DIAG_LOG"; then
    p21e3_diag_remove
    p21e3_dontaudit_restore
    fail "the diagnostic proc types and genfscon rows must be absent before load; BLOCKED"
  fi
fi
# R4-P3-P6-MNB14: pre-load check of sysctl_irq_t and the /proc/irq instance.
echo "-- pre-load check: sysctl_irq_t assignment in the active policy --" >> "$DIAG_LOG"
IRQ_MATCH="$(matchpathcon /proc/irq 2>&1 || true)"
printf 'matchpathcon /proc/irq: %s\n' "$IRQ_MATCH" >> "$DIAG_LOG"
IRQ_SEARCH="$(timeout 60 sesearch -A -t sysctl_irq_t 2>&1 || true)"
printf 'sesearch -t sysctl_irq_t:\n%s\n' "$IRQ_SEARCH" >> "$DIAG_LOG"
echo "-- pre-load check: /proc/irq mount info in the harness (init) mount ns --" >> "$DIAG_LOG"
awk '$5=="/proc/irq" && $10=="proc" {print "IRQ-MOUNT " $0}' /proc/self/mountinfo >> "$DIAG_LOG" 2>/dev/null || true
# The builder and rootfs/proc views are captured by the RPNS snapshots running in the
# same window; their mount IDs are cross-referenced in the MNB14 report.
cat > "$EVIDENCE_DIR/p21e3-diag-mounton.te" <<'EOF'
module docker_helper_diag_mounton 1.0;

require {
	type docker_helper_buildkitd_t;
	type proc_t;
	type sysctl_irq_t;
	type sysctl_t;
	type proc_kcore_t;
	class dir mounton;
	class file { mounton getattr };
	class filesystem remount;
}

# The reviewed seven rows (R4-P3-P6-MNB18): exactly these, nothing else.
allow docker_helper_buildkitd_t proc_t:dir mounton;
allow docker_helper_buildkitd_t proc_t:filesystem remount;
allow docker_helper_buildkitd_t sysctl_irq_t:dir mounton;
allow docker_helper_buildkitd_t sysctl_t:dir mounton;
allow docker_helper_buildkitd_t sysctl_t:file mounton;
allow docker_helper_buildkitd_t proc_kcore_t:file getattr;
allow docker_helper_buildkitd_t proc_kcore_t:file mounton;
EOF
{
  echo "-- module source (exactly the seven reviewed allow rows) --"
  cat "$EVIDENCE_DIR/p21e3-diag-mounton.te"
  echo "-- compile --"
  checkmodule -M -m -o "$DIAG_COMPILE_OUT" "$EVIDENCE_DIR/p21e3-diag-mounton.te"
  semodule_package -o "$DIAG_PP" -m "$DIAG_COMPILE_OUT"
  echo "-- install (temporary module only) --"
  semodule -i "$DIAG_PP"
} >> "$DIAG_LOG" 2>&1 || {
  DIAG_INSTALL_RC=$?
  printf 'diagnostic module build/install failed (rc=%d); nothing is loaded beyond the residue\n' "$DIAG_INSTALL_RC" >> "$DIAG_LOG"
  p21e3_diag_remove
  p21e3_dontaudit_restore
  fail "the diagnostic module could not be built or installed; BLOCKED"
}
  DIAG_ACTIVE=1
DIAG_LOAD_OK=1
  {
    echo "-- post-install sesearch (fail-closed: EXACTLY the seven reviewed rows) --"
    DIAG_LOADED_Q="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t proc_t -c dir -p mounton 2>&1)"
    DIAG_LOADED_RC=$?
    DIAG_LOADED_V="$(classify_sesearch_query "$DIAG_LOADED_RC" "$DIAG_LOADED_Q")"
    printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_LOADED_RC" "$DIAG_LOADED_V" "$DIAG_LOADED_Q"
    if [ "$DIAG_LOADED_V" != 'trusted:perms=mounton|cond-active=none|cond-inactive=none' ]; then
      echo "DIAG-LOAD-GATE: FAIL (the loaded rule set is not exactly the seven reviewed rows: $DIAG_LOADED_V)"
      DIAG_LOAD_OK=0
    fi
    DIAG_LOADED_Q2="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t proc_t -c filesystem -p remount 2>&1)"
    DIAG_LOADED_RC2=$?
    DIAG_LOADED_V2="$(classify_sesearch_query "$DIAG_LOADED_RC2" "$DIAG_LOADED_Q2")"
    printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_LOADED_RC2" "$DIAG_LOADED_V2" "$DIAG_LOADED_Q2"
    if [ "$DIAG_LOADED_V2" != 'trusted:perms=mount remount|cond-active=none|cond-inactive=none' ]; then
      echo "DIAG-LOAD-GATE: FAIL (the loaded rule set is not exactly the seven reviewed rows: $DIAG_LOADED_V2)"
      DIAG_LOAD_OK=0
    fi
    DIAG_LOADED_Q3="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t sysctl_irq_t -c dir -p mounton 2>&1)"
    DIAG_LOADED_RC3=$?
    DIAG_LOADED_V3="$(classify_sesearch_query "$DIAG_LOADED_RC3" "$DIAG_LOADED_Q3")"
    printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_LOADED_RC3" "$DIAG_LOADED_V3" "$DIAG_LOADED_Q3"
    if [ "$DIAG_LOADED_V3" != 'trusted:perms=mounton|cond-active=none|cond-inactive=none' ]; then
      echo "DIAG-LOAD-GATE: FAIL (the loaded rule set is not exactly the seven reviewed rows: $DIAG_LOADED_V3)"
      DIAG_LOAD_OK=0
    fi
    # R4-P3-P6-MNB15: the fourth reviewed row.
    DIAG_LOADED_Q4="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t sysctl_t -c dir -p mounton 2>&1)"
    DIAG_LOADED_RC4=$?
    DIAG_LOADED_V4="$(classify_sesearch_query "$DIAG_LOADED_RC4" "$DIAG_LOADED_Q4")"
    printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_LOADED_RC4" "$DIAG_LOADED_V4" "$DIAG_LOADED_Q4"
    if [ "$DIAG_LOADED_V4" != 'trusted:perms=mounton|cond-active=none|cond-inactive=none' ]; then
      echo "DIAG-LOAD-GATE: FAIL (the loaded rule set is not exactly the seven reviewed rows: $DIAG_LOADED_V4)"
      DIAG_LOAD_OK=0
    fi
    # R4-P3-P6-MNB16: the fifth reviewed row.
    DIAG_LOADED_Q5="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t sysctl_t -c file -p mounton 2>&1)"
    DIAG_LOADED_RC5=$?
    DIAG_LOADED_V5="$(classify_sesearch_query "$DIAG_LOADED_RC5" "$DIAG_LOADED_Q5")"
    printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_LOADED_RC5" "$DIAG_LOADED_V5" "$DIAG_LOADED_Q5"
    if [ "$DIAG_LOADED_V5" != 'trusted:perms=mounton|cond-active=none|cond-inactive=none' ]; then
      echo "DIAG-LOAD-GATE: FAIL (the loaded rule set is not exactly the seven reviewed rows: $DIAG_LOADED_V5)"
      DIAG_LOAD_OK=0
    fi
    # R4-P3-P6-MNB17: the sixth reviewed row.
    DIAG_LOADED_Q6="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t proc_kcore_t -c file -p getattr 2>&1)"
    DIAG_LOADED_RC6=$?
    DIAG_LOADED_V6="$(classify_sesearch_query "$DIAG_LOADED_RC6" "$DIAG_LOADED_Q6")"
    printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_LOADED_RC6" "$DIAG_LOADED_V6" "$DIAG_LOADED_Q6"
    # R4-P3-P6-MNB18: the seventh reviewed row. Rows 6 and 7 share the
    # proc_kcore_t:file class, so both loaded-gate checks expect the UNION
    # of the two allow rules' permissions (getattr mounton) — the exact
    # merged pair for that (source,target,class) proves both rows and
    # nothing else.
    DIAG_LOADED_Q7="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t proc_kcore_t -c file -p mounton 2>&1)"
    DIAG_LOADED_RC7=$?
    DIAG_LOADED_V7="$(classify_sesearch_query "$DIAG_LOADED_RC7" "$DIAG_LOADED_Q7")"
    printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_LOADED_RC7" "$DIAG_LOADED_V7" "$DIAG_LOADED_Q7"
    if [ "$DIAG_LOADED_V6" != 'trusted:perms=getattr mounton|cond-active=none|cond-inactive=none' ]; then
      echo "DIAG-LOAD-GATE: FAIL (the loaded rule set is not exactly the seven reviewed rows: $DIAG_LOADED_V6)"
      DIAG_LOAD_OK=0
    fi
    if [ "$DIAG_LOADED_V7" != 'trusted:perms=getattr mounton|cond-active=none|cond-inactive=none' ]; then
      echo "DIAG-LOAD-GATE: FAIL (the loaded rule set is not exactly the seven reviewed rows: $DIAG_LOADED_V7)"
      DIAG_LOAD_OK=0
    fi
    if [ "$DIAG_LOAD_OK" = 1 ]; then
      echo "DIAG-LOAD-GATE: PASS (exactly the seven reviewed rows are loaded, unconditional)"
    fi
  DIAG_SHA_LOADED="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
  echo "policy sha with the diagnostic module: $DIAG_SHA_LOADED"
  echo "-- release-policy .pp sha (post-install; must be unchanged) --"
  sha256sum /usr/share/selinux/docker_helper.pp 2>/dev/null || true
} >> "$DIAG_LOG" 2>&1
DIAG_LOAD_OK=1
grep -aq '^DIAG-LOAD-GATE: FAIL' "$DIAG_LOG" && DIAG_LOAD_OK=0
if [ "$DIAG_LOAD_OK" != 1 ]; then
  p21e3_diag_remove
  p21e3_dontaudit_restore
  fail "the diagnostic module load gate failed; BLOCKED"
fi
log "diagnostic module loaded: $DIAG_MODULE (exactly the seven reviewed allow rules; removal verified at the teardown)"
fi  # end of the mnb30 mandatory skip of the seven-row module

# --- the R4-P3-P6-MNB22 dedicated-type CIL block (diag-keys mode only) ---
# Keep the measured /keys rules and add a dedicated type for /timer_list
# with the reviewed getattr and mounton pair. Genfscon applies at inode
# initialization in fresh procfs.
# `semodule -i` consumes the CIL source directly (no TE compilation). The
# store entry is named docker_helper_diag_keys and is removed+verified
# together with the row module at the teardown.
if [ "${R7_P21E3_DIAG_KEYS:-0}" = 1 ] || [ "${R7_MNB30:-0}" = 1 ]; then
  # --- R4-P3-P6-MNB22 dedicated-type CIL module: diag-keys mode only ---
  if [ "${R7_P21E3_DIAG_KEYS:-0}" = 1 ]; then
  DIAG_KEYS_LOG="$EVIDENCE_DIR/p21e3-diag-keys.log"
  DIAG_KEYS_CIL="$EVIDENCE_DIR/docker_helper_diag_keys.cil"
  DIAG_KEYS_PRELOAD_SHA="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
  {
    echo "== the dedicated-type CIL diagnostic module: docker_helper_diag_keys (temporary) =="
    echo "committed-policy delta: NONE (temporary module only; unload verified at the teardown)"
    echo "release-policy .pp sha (must not change): $DIAG_RELEASE_PP_SHA_PRE"
    echo "guest version: $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME ($VERSION_ID)")"
    echo "policy sha before dedicated-module load: $DIAG_KEYS_PRELOAD_SHA"
  } > "$DIAG_KEYS_LOG"
  cat > "$DIAG_KEYS_CIL" <<'EOF'
; R4-P3-P6-MNB22: dedicated procfs file types for docker-helper.
; The genfscon rows use the
; explicit class + explicit MLS-range form: run 44125639504 rejected the
; class-less/range-less forms and run 44284343854 showed the context must
; also be role-authorized ("Type proc_keys_t is invalid for role object_r"
; at the CIL verify stage), so the roletype line is the enabling statement
; for the genfscon context. The range is (lo (s0)) (hi (s0)).
(type proc_keys_t)
(roletype object_r proc_keys_t)
(typeattributeset file_type (proc_keys_t))
(typeattributeset filesystem_type (proc_keys_t))
(typeattributeset mountpoint (proc_keys_t))
(typeattributeset non_auth_file_type (proc_keys_t))
(typeattributeset non_security_file_type (proc_keys_t))
(typeattributeset proc_type (proc_keys_t))
(genfscon "proc" "/keys" file (system_u object_r proc_keys_t ((s0) (s0))))
(allow docker_helper_buildkitd_t proc_keys_t (file (getattr mounton)))
(type proc_timer_list_t)
(roletype object_r proc_timer_list_t)
(typeattributeset file_type (proc_timer_list_t))
(typeattributeset filesystem_type (proc_timer_list_t))
(typeattributeset mountpoint (proc_timer_list_t))
(typeattributeset non_auth_file_type (proc_timer_list_t))
(typeattributeset non_security_file_type (proc_timer_list_t))
(typeattributeset proc_type (proc_timer_list_t))
(genfscon "proc" "/timer_list" file (system_u object_r proc_timer_list_t ((s0) (s0))))
(allow docker_helper_buildkitd_t proc_timer_list_t (file (getattr mounton)))
EOF
  {
    echo "-- module source (exactly the dedicated-type CIL block) --"
    cat "$DIAG_KEYS_CIL"
    echo "-- install (temporary module only; semodule -i accepts CIL) --"
    semodule -i "$DIAG_KEYS_CIL"
  } >> "$DIAG_KEYS_LOG" 2>&1 || {
    DIAG_KEYS_INSTALL_RC=$?
    printf 'the dedicated-type CIL module install failed (rc=%d); nothing of the block is loaded\n' \
      "${DIAG_KEYS_INSTALL_RC:-?}" >> "$DIAG_KEYS_LOG"
    cat "$DIAG_KEYS_LOG"
    p21e3_diag_remove
    p21e3_dontaudit_restore
    fail "the dedicated-type CIL module could not be installed; BLOCKED"
  }
  {
    echo "-- post-install policy readouts (fail-closed check of direct permissions + orientation) --"
    # Each direct grant must be the exact reviewed, unconditional pair.
    for DIAG_PROC_TYPE in proc_keys_t proc_timer_list_t; do
      DIAG_PROC_Q="$(timeout 60 sesearch -A -ds -dt -s docker_helper_buildkitd_t -t "$DIAG_PROC_TYPE" -c file 2>&1)"
      DIAG_PROC_RC=$?
      DIAG_PROC_V="$(classify_sesearch_query "$DIAG_PROC_RC" "$DIAG_PROC_Q")"
      printf 'type=%s query-rc=%s\nclassify=%s\n%s\n' "$DIAG_PROC_TYPE" "$DIAG_PROC_RC" "$DIAG_PROC_V" "$DIAG_PROC_Q"
      if [ "$DIAG_PROC_V" != 'trusted:perms=getattr mounton|cond-active=none|cond-inactive=none' ]; then
        echo "DIAG-LOAD-GATE: FAIL ($DIAG_PROC_TYPE direct permissions differ from the reviewed pair: $DIAG_PROC_V)"
      else
        echo "DIAG-LOAD-GATE: PASS ($DIAG_PROC_TYPE has exactly the reviewed direct getattr and mounton)"
      fi
    done
    if semodule -l 2>/dev/null | grep -aq docker_helper_diag_keys; then
      echo "module store: docker_helper_diag_keys registered"
    else
      echo "DIAG-LOAD-GATE: FAIL (docker_helper_diag_keys is not registered despite the successful install)"
    fi
    echo "-- orientation (NOT a gate): /proc/keys and /proc/timer_list labels in the existing guest init view --"
    ls -Zd /proc/keys /proc/timer_list 2>&1 || true
    DIAG_SHA_KEYS="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
    echo "policy sha with the dedicated-type module: $DIAG_SHA_KEYS"
    echo "release-policy .pp sha (post block-install; must be unchanged): $(sha256sum /usr/share/selinux/docker_helper.pp 2>/dev/null | awk '{print $1}')"
  } >> "$DIAG_KEYS_LOG" 2>&1
  cat "$DIAG_KEYS_LOG"
  if grep -aq '^DIAG-LOAD-GATE: FAIL' "$DIAG_KEYS_LOG"; then
    p21e3_diag_remove
    p21e3_dontaudit_restore
    fail "the dedicated-type module load gate failed; BLOCKED"
  fi
  log "dedicated-type module loaded: docker_helper_diag_keys (/proc/keys getattr and mounton, /proc/timer_list getattr and mounton)"
  fi  # end of the diag-keys-only dedicated-type module

  # --- R7 MNB27: the three-rule capability diagnostic module ---
  # MNB24 setpcap + MNB26 setgid (both self cap_userns) are kept; MNB27
  # adds the reviewed self process setcap (the capset EACCES tie of
  # audit 1260). The module carries EXACTLY the three reviewed rules;
  # the load gate proves the source absence (both cap tokens in both
  # setpcap-bearing classes, the setcap token on self process), the
  # exact deltas at load per class, and the SHA restoration at unload.
  # dac_override/fsetid/setuid/relabelfrom stay WITNESSED only (no rules).
  DIAG_CAP_LOG="$EVIDENCE_DIR/p21e3-diag-cap.log"
  DIAG_CAP_CIL="$EVIDENCE_DIR/docker_helper_diag_cap.cil"
  DIAG_CAP_PRELOAD_SHA="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
  {
    echo "== the three-rule capability diagnostic module: docker_helper_diag_cap (temporary) =="
    echo "committed-policy delta: NONE (temporary module only; unload verified at the teardown)"
    echo "reviewed rules (exactly three): self cap_userns setpcap (MNB24); self cap_userns setgid (MNB26); self process setcap (MNB27)"
    echo "witness-only tokens (no rule): dac_override fsetid setuid setfcap; relabelfrom state tree"
    echo "release-policy .pp sha (must not change): $DIAG_RELEASE_PP_SHA_PRE"
    echo "policy sha before cap-module load: $DIAG_CAP_PRELOAD_SHA"
    echo "-- baseline sesearch (fail-closed: setpcap AND setgid absent for buildkitd self in BOTH setpcap-bearing classes; setcap absent on self process) --"
  } > "$DIAG_CAP_LOG"
  DIAG_CAP_ALL_ABSENT=1
  for DIAG_CAP_CLASS in cap_userns capability; do
    for DIAG_CAP_TOKEN in setpcap setgid; do
      DIAG_CAP_Q="$(timeout 60 sesearch -A -ds -dt -s docker_helper_buildkitd_t \
        -t docker_helper_buildkitd_t -c "$DIAG_CAP_CLASS" -p "$DIAG_CAP_TOKEN" 2>&1)"
      DIAG_CAP_RC=$?
      DIAG_CAP_V="$(classify_sesearch_query "$DIAG_CAP_RC" "$DIAG_CAP_Q")"
      printf 'class=%s token=%s query-rc=%s\nclassify=%s\n%s\n' \
        "$DIAG_CAP_CLASS" "$DIAG_CAP_TOKEN" "$DIAG_CAP_RC" "$DIAG_CAP_V" "$DIAG_CAP_Q" >> "$DIAG_CAP_LOG"
      if [ "$DIAG_CAP_V" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
        echo "DIAG-CAP-GATE: FAIL (baseline $DIAG_CAP_TOKEN on self $DIAG_CAP_CLASS is not an authoritative absence: $DIAG_CAP_V)" >> "$DIAG_CAP_LOG"
        DIAG_CAP_ALL_ABSENT=0
      else
        echo "DIAG-CAP-BASE: PASS (class=$DIAG_CAP_CLASS authoritative absence of $DIAG_CAP_TOKEN from buildkitd self)" >> "$DIAG_CAP_LOG"
      fi
    done
  done
  # MNB27: the self process setcap baseline (fail-closed token absence)
  # and the full pre-set process perm set (the delta anchor).
  DIAG_PROC_Q="$(timeout 60 sesearch -A -ds -dt -s docker_helper_buildkitd_t \
    -t docker_helper_buildkitd_t -c process -p setcap 2>&1)"
  DIAG_PROC_V="$(classify_sesearch_query "$?" "$DIAG_PROC_Q")"
  printf 'class=process token=setcap query (baseline absence)\nclassify=%s\n%s\n' \
    "$DIAG_PROC_V" "$DIAG_PROC_Q" >> "$DIAG_CAP_LOG"
  if [ "$DIAG_PROC_V" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
    echo "DIAG-CAP-GATE: FAIL (baseline setcap on self process is not an authoritative absence: $DIAG_PROC_V)" >> "$DIAG_CAP_LOG"
    DIAG_CAP_ALL_ABSENT=0
  else
    echo "DIAG-CAP-BASE: PASS (class=process authoritative absence of setcap from buildkitd self)" >> "$DIAG_CAP_LOG"
  fi
  DIAG_PROCBASE_Q="$(timeout 60 sesearch -A -ds -dt -s docker_helper_buildkitd_t \
    -t docker_helper_buildkitd_t -c process 2>&1)"
  DIAG_PROCBASE_PERMS="$(classify_sesearch_query 0 "$DIAG_PROCBASE_Q" | sed -n 's/^trusted:perms=\([^|]*\)|.*/\1/p')"
  printf 'process-baseline-perms=%s\n' "${DIAG_PROCBASE_PERMS:-<unresolvable>}" >> "$DIAG_CAP_LOG"
  {
    echo "-- baseline buildkitd self cap_userns full perm set (the delta anchor) --"
    echo "QUERY: $(echo 'sesearch -A -ds -dt -s docker_helper_buildkitd_t -t docker_helper_buildkitd_t -c cap_userns')"
    DIAG_CAP_BASE_Q="$(timeout 60 sesearch -A -ds -dt -s docker_helper_buildkitd_t \
      -t docker_helper_buildkitd_t -c cap_userns 2>&1)"
    printf 'query-rc=%s\nclassify=%s\n%s\n' "$?" \
      "$(classify_sesearch_query 0 "$DIAG_CAP_BASE_Q")" "$DIAG_CAP_BASE_Q"
  } >> "$DIAG_CAP_LOG" 2>&1
  DIAG_CAP_BASE_PERMS="$(classify_sesearch_query 0 "$DIAG_CAP_BASE_Q" | sed -n 's/^trusted:perms=\([^|]*\)|.*/\1/p')"
  printf 'baseline-perms=%s\n' "${DIAG_CAP_BASE_PERMS:-<unresolvable>}" >> "$DIAG_CAP_LOG"
  cat > "$DIAG_CAP_CIL" <<'EOF'
(allow docker_helper_buildkitd_t self (cap_userns (setpcap)))
(allow docker_helper_buildkitd_t self (cap_userns (setgid)))
(allow docker_helper_buildkitd_t self (process (setcap)))
EOF
  DIAG_ACTIVE=1
  {
    echo "-- module source (exactly the three reviewed rules) --"
    cat "$DIAG_CAP_CIL"
    echo "-- install (temporary module only; semodule -i accepts CIL) --"
    semodule -i "$DIAG_CAP_CIL"
  } >> "$DIAG_CAP_LOG" 2>&1 || {
    cat "$DIAG_CAP_LOG"
    p21e3_diag_remove
    p21e3_dontaudit_restore
    fail "the three-rule capability diagnostic module could not be installed; BLOCKED"
  }
  {
    echo "-- post-install delta (fail-closed: exactly the two reviewed tokens on cap_userns, exactly setcap on the pre-set self process anchor; capability class must remain unchanged) --"
    DIAG_CAP_POST_Q="$(timeout 60 sesearch -A -ds -dt -s docker_helper_buildkitd_t \
      -t docker_helper_buildkitd_t -c cap_userns 2>&1)"
    printf 'query-rc=%s\nclassify=%s\n%s\n' "$?" \
      "$(classify_sesearch_query 0 "$DIAG_CAP_POST_Q")" "$DIAG_CAP_POST_Q"
    DIAG_CAP_POST_PERMS="$(classify_sesearch_query 0 "$DIAG_CAP_POST_Q" | sed -n 's/^trusted:perms=\([^|]*\)|.*/\1/p')"
    printf 'post-perms=%s\n' "${DIAG_CAP_POST_PERMS:-<unresolvable>}"
    DIAG_CAP_CAPPOST_Q="$(timeout 60 sesearch -A -ds -dt -s docker_helper_buildkitd_t \
      -t docker_helper_buildkitd_t -c capability 2>&1)"
    printf 'capability-class query-rc=%s\nclassify=%s\n%s\n' "$?" \
      "$(classify_sesearch_query 0 "$DIAG_CAP_CAPPOST_Q")" "$DIAG_CAP_CAPPOST_Q"
    DIAG_CAP_CAPPOST_PERMS="$(classify_sesearch_query 0 "$DIAG_CAP_CAPPOST_Q" | sed -n 's/^trusted:perms=\([^|]*\)|.*/\1/p')"
    printf 'capability-post-perms=%s\n' "${DIAG_CAP_CAPPOST_PERMS:-<unresolvable>}"
    if [ -z "$DIAG_CAP_BASE_PERMS" ] || [ -z "$DIAG_CAP_POST_PERMS" ]; then
      echo "DIAG-CAP-GATE: FAIL (the baseline or post perm set could not be resolved from the trusted classification)"
    else
      DIAG_CAP_WANT="$(printf '%s\n' "$DIAG_CAP_BASE_PERMS" setpcap setgid | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ' | sed 's/ $//')"
      DIAG_CAP_GOT="$(printf '%s\n' "$DIAG_CAP_POST_PERMS" | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ' | sed 's/ $//')"
      if [ "$DIAG_CAP_GOT" = "$DIAG_CAP_WANT" ]; then
        echo "DIAG-CAP-GATE: PASS (the load delta is exactly {setpcap setgid} on self cap_userns: $DIAG_CAP_GOT)"
      else
        echo "DIAG-CAP-GATE: FAIL (post cap_userns set differs from baseline+{setpcap setgid}: want=[$DIAG_CAP_WANT] got=[$DIAG_CAP_GOT])"
      fi
      DIAG_PROCPOST_Q="$(timeout 60 sesearch -A -ds -dt -s docker_helper_buildkitd_t \
        -t docker_helper_buildkitd_t -c process 2>&1)"
      DIAG_PROCPOST_PERMS="$(classify_sesearch_query 0 "$DIAG_PROCPOST_Q" | sed -n 's/^trusted:perms=\([^|]*\)|.*/\1/p')"
      printf 'process-post-perms=%s\n' "${DIAG_PROCPOST_PERMS:-<unresolvable>}"
      if [ -z "$DIAG_PROCBASE_PERMS" ] || [ -z "$DIAG_PROCPOST_PERMS" ]; then
        echo "DIAG-CAP-GATE: FAIL (the process baseline or post perm set could not be resolved from the trusted classification)"
      else
        DIAG_PROC_WANT="$(printf '%s\n' "$DIAG_PROCBASE_PERMS" setcap | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ' | sed 's/ $//')"
        DIAG_PROC_GOT="$(printf '%s\n' "$DIAG_PROCPOST_PERMS" | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ' | sed 's/ $//')"
        if [ "$DIAG_PROC_GOT" = "$DIAG_PROC_WANT" ]; then
          echo "DIAG-CAP-GATE: PASS (the load delta is exactly {setcap} on self process: $DIAG_PROC_GOT)"
        else
          echo "DIAG-CAP-GATE: FAIL (post self process set differs from baseline+{setcap}: want=[$DIAG_PROC_WANT] got=[$DIAG_PROC_GOT])"
        fi
      fi
      if [ -n "$DIAG_CAP_CAPPOST_PERMS" ]; then
        echo "DIAG-CAP-GATE: FAIL (the capability class carries rules after the load; expected none: $DIAG_CAP_CAPPOST_PERMS)"
      else
        echo "DIAG-CAP-GATE: PASS (the capability class is unchanged: still no rules)"
      fi
    fi
    if semodule -l 2>/dev/null | grep -aq docker_helper_diag_cap; then
      echo "module store: docker_helper_diag_cap registered"
    else
      echo "DIAG-CAP-GATE: FAIL (docker_helper_diag_cap is not registered despite the successful install)"
    fi
    DIAG_SHA_CAP="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
    echo "policy sha with the cap module loaded: $DIAG_SHA_CAP (pre-load: $DIAG_CAP_PRELOAD_SHA; must differ)"
    echo "release-policy .pp sha (post install; must be unchanged): $(sha256sum /usr/share/selinux/docker_helper.pp 2>/dev/null | awk '{print $1}')"
  } >> "$DIAG_CAP_LOG" 2>&1
  cat "$DIAG_CAP_LOG"
  if [ "$DIAG_SHA_CAP" = "$DIAG_CAP_PRELOAD_SHA" ]; then
    echo "DIAG-CAP-GATE: FAIL (policy sha unchanged after the install; the module load is unproven)" >> "$DIAG_CAP_LOG"
  fi
  if grep -aq '^DIAG-CAP-GATE: FAIL' "$DIAG_CAP_LOG" || [ "$DIAG_CAP_ALL_ABSENT" != 1 ]; then
    p21e3_diag_remove
    p21e3_dontaudit_restore
    fail "the three-rule capability module load gate failed; BLOCKED"
  fi
  log "three-rule capability module loaded: docker_helper_diag_cap (self cap_userns setpcap+setgid, self process setcap; deltas {setpcap setgid} and {setcap} verified)"

  # --- R7 MNB30: the temporary WORKLOAD-DOMAIN module (diagnostic; the
  # --- MNB28 scheme (b) row set, temporary exactly like the cap module).
  # --- The wrapper's OWN production rolecheck (seinfo --role_types) needs
  # --- the workload type to exist and be authorized for system_r in the
  # --- LOADED policy; without this module the composed transition cannot
  # --- be measured at all. The rows are exactly the MNB28/R2 decision-row
  # --- set (b): the two allow rows on the state-tree files, the kernel
  # --- necessities for the explicit (runtime SetExecLabel) exec — the
  # --- MNB27-measured execute denial (AVC 1246: buildkitd_t -> busybox
  # --- state_t:s0:c1) narrowed to the same-op snapshot files, the
  # --- entrypoint face of the NEW domain, and the buildkitd->workload
  # --- process transition permission — NO type_transition (variant (b),
  # --- the runtime composes the label), NO map-less widening, NO
  # --- signal/tty/other anticipation (MNB28 section 6: follow-up surfaces
  # --- surface as measured denials first). The domain joins the
  # --- mcs_constrained_type attribute so the cross-operation rootfs
  # --- denial is carried by the MCS layer itself.
  if [ "${R7_MNB30:-0}" = 1 ]; then
  DIAG_WL_LOG="$EVIDENCE_DIR/p21e3-mnb30-workload-module.log"
  DIAG_WL_CIL="$EVIDENCE_DIR/docker_helper_diag_workload.cil"
  DIAG_WL_PRELOAD_SHA="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
  DIAG_MODULES="$DIAG_MODULES docker_helper_diag_workload"
  # The rolecheck's own seinfo face: the wrapper runs inside buildkitd_t
  # and the measured consumer denials are (1) the fork/exec of the
  # installed seinfo binary (`fork/exec /usr/bin/seinfo: permission
  # denied`) — the row targets EXACTLY the observed label type of that
  # binary, plus the no-transition exec face the kernel checks; and (2)
  # the on-runtime reads seinfo (python) performs under buildkitd_t: the
  # explicit-policy operand read (/sys/fs/selinux/policy), and the
  # startup reads measured as denials in the MNB29/MNB30 evidence
  # (tmpfs_t lnk_file reads of ld.so.cache and localtime). The rows are
  # narrow, measured denials only; no relabel and no tool domain is
  # involved (an interpreter relabel was measured DENIED by the kernel
  # for the unconfined admin subject even after explicit relabel rows,
  # so the tools stay in buildkitd_t, confined by exactly these rows).
  WL_SEINFO_TYPE="$(matchpathcon -n /usr/bin/seinfo 2>/dev/null | awk -F: '{print $3}')"
  case "$WL_SEINFO_TYPE" in
    [a-z_]*_t) : ;;
    *) WL_SEINFO_TYPE=bin_t ;;
  esac
  # The explicit-policy operand: the wrapper's production roletype query
  # pins seinfo to /sys/fs/selinux/policy (the LOADED policy, no /etc
  # chain reads), so the module also carries the selinuxfs read faces the
  # operand read performs under the buildkitd_t subject.
  WL_POLICY_TYPE="$(ls -ZN /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}' | awk -F: '{print $3}')"
  case "$WL_POLICY_TYPE" in
    [a-z_]*_t) : ;;
    *) WL_POLICY_TYPE=security_t ;;
  esac
  # seinfo on this distro is a python script (the measured response format
  # "[Errno 13] …" is python). The ON-RUNTIME file reads the script
  # performs (the interpreter startup, the loader cache, the local-time
  # link) were measured as denials under buildkitd_t; the rows below
  # grant exactly those measured reads to the wrapper's subject, which
  # keeps the rolecheck inside the confined domain (permissive tool
  # domain attempts were abandoned: the interpreter relabel is denied).
  DIAG_WL_POLICY_ROWS="(allow docker_helper_buildkitd_t ${WL_POLICY_TYPE} (dir (search)))
(allow docker_helper_buildkitd_t ${WL_POLICY_TYPE} (file (read open getattr map)))
(allow docker_helper_buildkitd_t ${WL_POLICY_TYPE} (security (read_policy)))
(allow docker_helper_buildkitd_t tmpfs_t (lnk_file (read getattr)))
(allow docker_helper_buildkitd_t tmpfs_t (file (read open getattr)))"
  {
    echo '(type docker_helper_builder_workload_t)'
    echo '(roletype system_r docker_helper_builder_workload_t)'
    echo '(typeattributeset domain (docker_helper_builder_workload_t))'
    echo '(typeattributeset mcs_constrained_type (docker_helper_builder_workload_t))'
    echo '(allow docker_helper_buildkitd_t docker_helper_builder_state_t (file (execute)))'
    echo '(allow docker_helper_builder_workload_t docker_helper_builder_state_t (file (execute entrypoint map open read getattr)))'
    echo '(allow docker_helper_builder_workload_t docker_helper_builder_state_t (dir (search)))'
    echo '(allow docker_helper_buildkitd_t docker_helper_builder_workload_t (process (transition)))'
    printf '(allow docker_helper_buildkitd_t %s (file (execute execute_no_trans)))\n' "$WL_SEINFO_TYPE"
    echo "$DIAG_WL_POLICY_ROWS"
  } > "$DIAG_WL_CIL"
  DIAG_WL_SEINFO_LABEL_PRE="$(ls -ZN /usr/bin/seinfo 2>/dev/null | awk '{print $1}')"
  {
    echo "== the MNB30 temporary workload-domain module: docker_helper_diag_workload =="
    echo "committed-policy delta: NONE (temporary module only; unload verified at the teardown)"
    echo "reviewed scheme: MNB28 decision row (b) + the kernel necessities for the explicit exec (the measured AVC 1246 execute denial surface) + the measured rolecheck seinfo exec/read denials granted as narrow read rows on the buildkitd_t subject itself (the interpreter relabel was kernel-denied; no relabel, no tool domain)"
    echo "seinfo label type for the rolecheck row: $WL_SEINFO_TYPE"
    echo "seinfo script original label: $DIAG_WL_SEINFO_LABEL_PRE"
    echo "selinuxfs policy label type for the explicit operand rows: $WL_POLICY_TYPE"
    echo "released-policy .pp sha (must not change): $DIAG_RELEASE_PP_SHA_PRE"
    echo "guest version: $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME ($VERSION_ID)")"
    echo "policy sha before workload-module load: $DIAG_WL_PRELOAD_SHA"
    echo "-- module source (bytes: $(wc -c < "$DIAG_WL_CIL")) --"
    cat "$DIAG_WL_CIL"
    echo "-- install (temporary module only; semodule -i accepts CIL) --"
    if [ ! -s "$DIAG_WL_CIL" ]; then
      echo "WL-GATE: FAIL (the module source file is empty; the install refuses)"
      false
    fi
    semodule -i "$DIAG_WL_CIL"
  } > "$DIAG_WL_LOG" 2>&1 || {
    cat "$DIAG_WL_LOG"
    p21e3_diag_remove
    p21e3_dontaudit_restore
    fail "the MNB30 workload-domain module could not be installed; BLOCKED"
  }
  DIAG_WL_SHA="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
  {
    echo "-- post-install verification (fail-closed; the wrapper's own rolecheck and the exec face) --"
    echo "policy sha with the workload module loaded: $DIAG_WL_SHA (pre-load: $DIAG_WL_PRELOAD_SHA; must differ)"
    echo "-- rolecheck surface (the EXACT production reading: seinfo --role_types) --"
    seinfo --role_types docker_helper_builder_workload_t 2>&1 || true
    WL_ROLE_RC=0
    seinfo --role_types docker_helper_builder_workload_t 2>/dev/null | grep -aqw system_r || WL_ROLE_RC=1
    if [ "$WL_ROLE_RC" = 0 ]; then
      echo "WL-GATE: PASS (seinfo --role_types carries the system_r authorization entry)"
    else
      echo "WL-GATE: FAIL (no system_r roletype entry for the workload domain)"
    fi
    echo "-- attribute membership (the MCS layer must constrain the workload domain) --"
    if seinfo -a mcs_constrained_type -x 2>/dev/null | grep -aq docker_helper_builder_workload_t; then
      echo "WL-GATE: PASS (docker_helper_builder_workload_t is an mcs_constrained_type member)"
    else
      echo "WL-GATE: FAIL (the workload domain does not join mcs_constrained_type; the cross-op denial would not be carried by MCS)"
    fi
    echo "-- TE row surface (the MNB28 (b) row set + the kernel necessities) --"
    for WL_ROW in \
      'docker_helper_buildkitd_t.docker_helper_builder_state_t:file:execute' \
      'docker_helper_builder_workload_t.docker_helper_builder_state_t:file:execute' \
      'docker_helper_builder_workload_t.docker_helper_builder_state_t:file:entrypoint' \
      'docker_helper_builder_workload_t.docker_helper_builder_state_t:file:map' \
      'docker_helper_builder_workload_t.docker_helper_builder_state_t:file:open' \
      'docker_helper_builder_workload_t.docker_helper_builder_state_t:file:read' \
      'docker_helper_builder_workload_t.docker_helper_builder_state_t:file:getattr' \
      'docker_helper_builder_workload_t.docker_helper_builder_state_t:dir:search' \
      'docker_helper_buildkitd_t.docker_helper_builder_workload_t:process:transition'; do
      WL_S="${WL_ROW%%.*}"
      WL_REST="${WL_ROW#*.}"
      WL_T="$(printf '%s\n' "$WL_REST" | cut -d: -f1)"
      WL_CLASS="$(printf '%s\n' "$WL_REST" | cut -d: -f2)"
      WL_P="$(printf '%s\n' "$WL_REST" | cut -d: -f3)"
      WL_Q="$(timeout 60 sesearch -A -s "$WL_S" -t "$WL_T" -c "$WL_CLASS" -p "$WL_P" 2>&1)"
      WL_RC=$?
      WL_V="$(classify_sesearch_query "$WL_RC" "$WL_Q")"
      case "$WL_V" in
        trusted:*|'trusted...')
          echo "WL-GATE: PASS ($WL_ROW: $WL_V)" ;;
        *)
          echo "WL-GATE: FAIL ($WL_ROW: $WL_V)" ;;
      esac
    done
    echo "-- release-policy .pp sha (post install; must be unchanged): $(sha256sum /usr/share/selinux/docker_helper.pp 2>/dev/null | awk '{print $1}')"
  } >> "$DIAG_WL_LOG" 2>&1
  cat "$DIAG_WL_LOG"
  if [ "$DIAG_WL_SHA" = "$DIAG_WL_PRELOAD_SHA" ]; then
    echo "WL-GATE: FAIL (policy sha unchanged after the install; the module load is unproven)" >> "$DIAG_WL_LOG"
  fi
  if grep -aq '^WL-GATE: FAIL' "$DIAG_WL_LOG" || [ "$DIAG_WL_SHA" = "$DIAG_WL_PRELOAD_SHA" ]; then
    p21e3_diag_remove
    p21e3_dontaudit_restore
    fail "the MNB30 workload-domain module load gate failed; BLOCKED"
  fi
  log "MNB30 workload-domain module loaded: docker_helper_diag_workload (rolecheck surface, mcs attribute, and the exact MNB28 (b) row set verified)"
  fi  # end of the MNB30 temporary workload-domain module

  # --- fresh-procfs orientation probe (private mount namespace) ---
  # genfscon decides the label at inode initialization, so a FRESH procfs
  # instance created after the policy load must show the dedicated type.
  # This probe is a read-only ORIENTATION check in a private mount
  # namespace (the init mount namespace is never touched); its failure is
  # recorded as a limitation. The post-pivot syscall trace is the authority
  # on whether runc reaches and completes the mask.
  # (diag-keys mode only; the MNB30 round loads no dedicated procfs type.)
  if [ "${R7_P21E3_DIAG_KEYS:-0}" = 1 ]; then
  PROBE_LOG="$EVIDENCE_DIR/p21e3-keys-freshproc.log"
  {
    echo "== fresh procfs instance label probe (private mnt namespace) =="
    echo "loaded-policy sha256: $(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
    rm -rf /tmp/r7-p21e3-procprobe
    mkdir -p /tmp/r7-p21e3-procprobe
    if unshare --mount --pid --fork sh -c '
      mount -t proc proc /tmp/r7-p21e3-procprobe || exit 90
      ls -Zd /tmp/r7-p21e3-procprobe/keys /tmp/r7-p21e3-procprobe/timer_list
      ls -Zd /tmp/r7-p21e3-procprobe | head -1
      umount /tmp/r7-p21e3-procprobe
    ' 2>&1; then
      echo "probe: DONE (the fresh instance label is above)"
    else
      echo "probe: FAILED-PROBE rc=$? (limitation, not a gate)"
    fi
    rm -rf /tmp/r7-p21e3-procprobe 2>/dev/null || true
  } > "$PROBE_LOG" 2>&1
  cat "$PROBE_LOG"
  DIAG_KEYS_PROBE_LABEL="$(grep -aoE 'system_u:object_r:proc_keys_t:s0 [^ ]*/keys|object_r:proc_keys_t' "$PROBE_LOG" | head -1 || true)"
  DIAG_TIMER_PROBE_LABEL="$(grep -aoE 'system_u:object_r:proc_timer_list_t:s0 [^ ]*/timer_list' "$PROBE_LOG" | head -1 || true)"
  if [ -n "$DIAG_KEYS_PROBE_LABEL" ] && [ -n "$DIAG_TIMER_PROBE_LABEL" ]; then
    log "fresh-procfs probe: both dedicated labels are live (orientation)"
  else
    log "fresh-procfs probe: at least one dedicated label is unconfirmed (orientation)"
  fi

  else
    log "fresh-procfs probe: not part of this round mode (no dedicated procfs type loaded)"
  fi  # end of the diag-keys-only fresh-procfs probe

  # --- R7 MNB23: the runc-state kernel-decision matrix (the candidate's
  # --- own production grants; the loaded policy bytes decide) --- (diag-keys mode only)
  if [ "${R7_P21E3_DIAG_KEYS:-0}" = 1 ]; then
  # security_compute_av_raw over the categorized contexts for the
  # dedicated type created by the candidate's own type_transition: the
  # same-category pairs must resolve ALLOW for the file cycle's
  # constrained perms and DENY for both cross-category directions (the
  # state-tree matrix precedent), the runtime-tree dir hooks keep their
  # proven cross-category closure, and every row must be a DECIDED
  # kernel evaluation with no permissive-domain exception. A mismatch
  # is the BLOCKED shape, never a report note.
  if ! command -v gcc >/dev/null 2>&1 || [ ! -e /usr/include/selinux/selinux.h ]; then
    timeout 300 zypper --non-interactive install -y gcc libselinux-devel >/dev/null 2>&1 || true
  fi
  command -v gcc >/dev/null 2>&1 || fail "gcc unavailable; the kernel-decision matrix cannot run"
  [ -e /usr/include/selinux/selinux.h ] || fail "libselinux headers unavailable; the kernel-decision matrix cannot run"
  KC_LOG="$EVIDENCE_DIR/p21e3-runcstate-av-matrix.log"
  cat > "$EVIDENCE_DIR/p21e3_runcstate_avdec.c" <<'CEOF'
/* R7 MNB23: security_compute_av_raw over the categorized contexts for
 * the dedicated runc-state type (the candidate's own production grants).
 * Columns: scon tcon class perm allowed decided auditallow auditdeny
 * permissive expect; expect=allow|deny is checked by the shell verdict;
 * expect=report rows are recorded, never asserted. */
#include <selinux/selinux.h>
#include <stdio.h>
#include <string.h>

static const char *S_C1 = "system_u:system_r:docker_helper_buildkitd_t:s0:c1";
static const char *S_C2 = "system_u:system_r:docker_helper_buildkitd_t:s0:c2";
static const char *T_STATE_C1 = "system_u:object_r:docker_helper_builder_runc_state_t:s0:c1";
static const char *T_STATE_C2 = "system_u:object_r:docker_helper_builder_runc_state_t:s0:c2";
static const char *T_RUNTIME_C1 = "system_u:object_r:docker_helper_builder_runtime_t:s0:c1";
static const char *T_RUNTIME_C2 = "system_u:object_r:docker_helper_builder_runtime_t:s0:c2";
static const char *T_RUNC_C1 = "system_u:object_r:docker_helper_builder_runc_dir_t:s0:c1";
static const char *T_RUNC_C2 = "system_u:object_r:docker_helper_builder_runc_dir_t:s0:c2";


static struct q { const char *scon, *tcon, *cls, *perm, *expect; } ROWS[256];
static size_t NROWS;
static void add(const char *s, const char *t, const char *c, const char *p, const char *e) {
  ROWS[NROWS].scon = s; ROWS[NROWS].tcon = t; ROWS[NROWS].cls = c;
  ROWS[NROWS].perm = p; ROWS[NROWS].expect = e; NROWS++;
}

static char *create_context(const char *parent, const char *object_class,
                            const char *name, const char *expected) {
  security_class_t cls = string_to_security_class(object_class);
  char *computed = NULL;
  if (!cls || security_compute_create_name_raw(S_C1, parent, cls, name, &computed) < 0) {
    fprintf(stderr, "ERR\tcreate-context %s %s\n", object_class, name);
    return NULL;
  }
  printf("CREATE-LABEL\t%s\t%s\t%s\t%s\n", parent, object_class, name, computed);
  if (strcmp(computed, expected) != 0) {
    fprintf(stderr, "ERR\tunexpected context for %s, expected %s\n", name, expected);
    freecon(computed);
    return NULL;
  }
  return computed;
}

int main(void) {
  /* the file cycle on the dedicated type: same-category ALLOW (the
   * candidate's own MNB23 grant), both cross directions DENY for the
   * constrained set. The loaded file constraint sets (recorded in the
   * matrix log via seinfo --constrain file) cover
   *   { create relabelfrom relabelto } (same-user),
   *   { append link rename setattr unlink write },
   *   { execute execute_no_trans ioctl lock read } — so open is NOT
   * mcs-constrained at the object layer (the cross-category open row
   * carries expect=report; the cross-operation isolation stays owned
   * by the cross-category dir traversal denial, exactly as the
   * exec.fifo setattr precedent records it). getattr likewise carries
   * expect=report. */
  static const char *constrained[] = { "create", "read", "write", "rename", "unlink" };
  for (size_t i = 0; i < 5; i++) {
    add(S_C1, T_STATE_C1, "file", constrained[i], "allow");
    add(S_C2, T_STATE_C2, "file", constrained[i], "allow");
    add(S_C1, T_STATE_C2, "file", constrained[i], "deny");
    add(S_C2, T_STATE_C1, "file", constrained[i], "deny");
  }
  add(S_C1, T_STATE_C1, "file", "open", "allow");
  add(S_C2, T_STATE_C2, "file", "open", "allow");
  add(S_C1, T_STATE_C2, "file", "open", "report");
  add(S_C2, T_STATE_C1, "file", "open", "report");
  add(S_C1, T_STATE_C1, "file", "getattr", "report");
  add(S_C1, T_STATE_C2, "file", "getattr", "report");
  /* Use the kernel-computed child contexts, then check the create
   * decision from the same source category for both parent types. */
  char *inside = create_context(T_RUNC_C1, "file", "state-diagnostic", T_STATE_C1);
  char *outside = create_context(T_RUNTIME_C1, "file", "state-diagnostic", T_RUNTIME_C1);
  char *bundle = create_context(T_RUNC_C1, "dir", "diagnostic-bundle", T_RUNC_C1);
  char *fifo = create_context(T_RUNC_C1, "fifo_file", "exec.fifo", T_RUNTIME_C1);
  if (!inside || !outside || !bundle || !fifo)
    return 1;
  add(S_C1, inside, "file", "create", "allow");
  add(S_C1, outside, "file", "create", "deny");
  add(S_C1, bundle, "dir", "create", "allow");
  add(S_C1, fifo, "fifo_file", "create", "allow");
  static const char *dperms[] = { "search", "write", "add_name", "remove_name" };
  for (size_t i = 0; i < 4; i++) {
    add(S_C1, T_RUNC_C1, "dir", dperms[i], "allow");
    add(S_C1, T_RUNC_C2, "dir", dperms[i], "deny");
    add(S_C2, T_RUNC_C1, "dir", dperms[i], "deny");
    add(S_C1, T_RUNTIME_C2, "dir", dperms[i], "deny");
    add(S_C2, T_RUNTIME_C1, "dir", dperms[i], "deny");
  }
  for (size_t i = 0; i < NROWS; i++) {
    struct q *r = &ROWS[i];
    security_class_t cls = string_to_security_class(r->cls);
    if (!cls) { printf("ERR\tclass %s unknown\n", r->cls); return 1; }
    access_vector_t bit = string_to_av_perm(cls, r->perm);
    if (!bit) { printf("ERR\tperm %s %s unknown\n", r->cls, r->perm); return 1; }
    struct av_decision avd;
    memset(&avd, 0, sizeof(avd));
    if (security_compute_av_raw(r->scon, r->tcon, cls, bit, &avd) < 0) {
      printf("ERR\tcompute_av failed\n");
      return 1;
    }
    printf("%s\t%s\t%s\t%s\t%u\t%u\t%u\t%u\t%u\t%s\n",
           r->scon, r->tcon, r->cls, r->perm,
           (avd.allowed & bit) ? 1 : 0,
           (avd.decided & bit) ? 1 : 0,
           (avd.auditallow & bit) ? 1 : 0,
           (avd.auditdeny & bit) ? 1 : 0,
           (avd.flags & SELINUX_AVD_FLAGS_PERMISSIVE) ? 1 : 0,
           r->expect);
  }
  freecon(inside);
  freecon(outside);
  freecon(bundle);
  freecon(fifo);
  return 0;
}
CEOF
  {
    echo "== MNB23 runc-state kernel-decision matrix (loaded policy = candidate + temp diag rows) =="
    echo "policy sha: $(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
    echo "-- file mlsconstrain sets (constraint provenance for the expectations) --"
    seinfo --constrain file 2>&1 | head -30 || true
  } > "$KC_LOG" 2>&1
  gcc -O2 -o "$EVIDENCE_DIR/p21e3_runcstate_avdec" "$EVIDENCE_DIR/p21e3_runcstate_avdec.c" -lselinux \
    >> "$KC_LOG" 2>&1 || { cat "$KC_LOG"; fail "the MNB23 kernel-decision helper build failed; BLOCKED"; }
  "$EVIDENCE_DIR/p21e3_runcstate_avdec" >> "$KC_LOG" 2>&1 \
    || { cat "$KC_LOG"; fail "the MNB23 kernel-decision helper failed; BLOCKED"; }
  BADS="$(awk -F'\t' '$1=="ERR" { print "ERRROW " $0; next } NF>=10 && $10!="" {
    if ($6 != 1) { print "UNDECIDED " $0 }
    if ($9 != 0) { print "PERMISSIVE " $0 }
    if ($10=="allow" && $5!=1) { print "MISMATCH-ALLOW " $0 }
    if ($10=="deny" && $5!=0) { print "MISMATCH-DENY " $0 }
  }' "$KC_LOG")"
  if [ -n "$BADS" ]; then
    printf '%s\n' "$BADS" >> "$KC_LOG"
    cat "$KC_LOG"
    fail "the MNB23 kernel-decision matrix reached an unexpected resolution; BLOCKED (privacy/correctness invariant refusal)"
  fi
  echo "R7-P21E3-RUNCSTATE-MATRIX=PASS" >> "$KC_LOG"
  cat "$KC_LOG"
  log "MNB23 kernel-decision matrix: PASS (same-category cycle allow; cross-category deny; all rows decided, no permissive)"
  fi  # end of the diag-keys-only MNB23 matrix

  # --- R7 MNB30 preflight: the pinned runtime byte-pin and the seinfo
  # --- roletype calibration, both HARD gates on the tracer-free
  # --- transition round. The four loader checks run against the runtime
  # --- binary EXTRACTED FROM THE CANDIDATE RPM (not the installed path),
  # --- binding the payload bytes to the loader contract before the round
  # --- measures the real managed run.
  if [ "${R7_MNB30:-0}" = 1 ]; then
  # gr is computed in the state-gated section 3; a same-boot re-entry that
  # skipped section 3 doesn't set it — re-derive from the installed bytes
  # instead of relying on the marker.
  gr="${gr:-$(sha256sum /usr/libexec/docker-helper/buildkit/runtime/buildkit-runc | awk '{print $1}')}"
  # The member extraction is also state-gated (section 3); re-extract for a
  # same-boot re-entry so the byte-pin never reads an older, unrelated tree.
  # The runtime member needs its OWN cpio pass: section 3's extraction pulls
  # only the product binary and the policy package members.
  MNB30_RUNTIME="$RPM_MEMBERS_DIR/extract/usr/libexec/docker-helper/buildkit/runtime/buildkit-runc"
  if [ ! -s "$MNB30_RUNTIME" ]; then
    RPM_MEMBERS_DIR="$(mktemp -d "$STATE_DIR/mnb30-members.XXXXXX")"
    MNB30_RUNTIME="$RPM_MEMBERS_DIR/extract/usr/libexec/docker-helper/buildkit/runtime/buildkit-runc"
    mkdir -p "$RPM_MEMBERS_DIR/extract" "$RPM_MEMBERS_DIR/rtwork" \
      || { printf 'MNB30-RUNTIME-EXTRACT: FAIL (workdir)\n'; }
    if command -v rpm2cpio >/dev/null 2>&1 && command -v cpio >/dev/null 2>&1; then
      rpm2cpio "$ARTIFACT" > "$RPM_MEMBERS_DIR/rtwork/payload.cpio" \
        && RPM2CPIO_RC=0 || RPM2CPIO_RC=$?
      if [ "$RPM2CPIO_RC" = 0 ] || { [ "$RPM2CPIO_RC" = 1 ] && [ -s "$RPM_MEMBERS_DIR/rtwork/payload.cpio" ]; }; then
        (cd "$RPM_MEMBERS_DIR/extract" && cpio -id --no-absolute-filenames \
          /usr/libexec/docker-helper/buildkit/runtime/buildkit-runc \
          usr/libexec/docker-helper/buildkit/runtime/buildkit-runc \
          ./usr/libexec/docker-helper/buildkit/runtime/buildkit-runc \
          <"$RPM_MEMBERS_DIR/rtwork/payload.cpio") \
          >"$RPM_MEMBERS_DIR/rtwork/cpio.out" 2>"$RPM_MEMBERS_DIR/rtwork/cpio.err" \
          && CPIO_RC=0 || CPIO_RC=$?
      fi
    else
      CPIO_RC=none
    fi
    if [ "$CPIO_RC" = 0 ] && [ -s "$MNB30_RUNTIME" ]; then
      RPM_MEMBERS_OK=1
    else
      RPM_MEMBERS_OK=0
      printf 'MNB30-RUNTIME-EXTRACT: FAIL (rpm2cpio rc=%s cpio rc=%s)\n' \
        "${RPM2CPIO_RC:-none}" "${CPIO_RC:-none}"
    fi
  fi
  MNB30_LOG="$EVIDENCE_DIR/p21e3-mnb30-preflight.log"
  {
    echo "== MNB30 preflight: extracted-RPM runtime pin + loader harness + seinfo roletype =="
    if [ "$RPM_MEMBERS_OK" != 1 ] || [ ! -s "$MNB30_RUNTIME" ]; then
      echo "MNB30-RUNTIME-EXTRACT: FAIL (the runtime member is not extracted from the candidate RPM)"
      echo "MNB30-RUNTIME-PIN=FAIL"
      echo "MNB30-SEINFO=FAIL"
      echo "MNB30-HARNESS=FAIL"
      printf 'R7-MNB30-VERDICT=BLOCKED:runtime-extract\n'
    else
      extracted="$(sha256sum "$MNB30_RUNTIME" | awk '{print $1}')"
      printf 'extracted-runtime-sha256=%s\n' "$extracted"
      installed="$(sha256sum /usr/libexec/docker-helper/buildkit/runtime/buildkit-runc | awk '{print $1}')"
      printf 'installed-runtime-sha256=%s\n' "$installed"
      OWNER_PIN=""
      if [ -s /tmp/r7-diag/build-buildkit-payload.sh ]; then
        OWNER_PIN="$(sed -n 's/^BUILDKIT_RUNC_SHA256="\([0-9a-f]\{64\}\)"/\1/p' /tmp/r7-diag/build-buildkit-payload.sh | head -1)"
      fi
      if [ -n "$OWNER_PIN" ]; then
        if [ "$OWNER_PIN" = "$extracted" ]; then
          echo "MNB30-OWNER-PIN=MATCH (the staged-owner pin equals the RPM-extracted runtime bytes)"
        else
          echo "MNB30-OWNER-PIN=FAIL (owner pin=$OWNER_PIN extracted=$extracted)"
        fi
      fi
      if [ "$extracted" = "$installed" ] && [ "$extracted" = "$gr" ] && [ -n "$OWNER_PIN" ] && [ "$OWNER_PIN" = "$extracted" ]; then
        echo "MNB30-RUNTIME-PIN=MATCH (extracted==installed==manifest==owner pin)"
      else
        echo "MNB30-RUNTIME-PIN=FAIL (extracted=$extracted installed=$installed manifest=$gr owner-pin=${OWNER_PIN:-<unreadable>})"
      fi
      echo "-- the four loader checks + the create probe on the EXTRACTED binary --"
      if [ -s /tmp/r7-diag/payload-runc-loader-harness.sh ]; then
        the_4c=$(/bin/bash /tmp/r7-diag/payload-runc-loader-harness.sh \
          "$MNB30_RUNTIME" 2>&1)
        rc=$?
        printf '%s\n' "$the_4c"
        case "$the_4c" in
          *HANDOFF-HARNESS-EXIT=0*) echo "MNB30-HARNESS=PASS" ;;
          *) echo "MNB30-HARNESS=FAIL (rc=$rc)" ;;
        esac
      else
        echo "MNB30-HARNESS=FAIL (harness script not transferred)"
      fi
      echo "-- seinfo --role_types calibration (the wrapperRoleCheck production reading) --"
      if command -v seinfo >/dev/null 2>&1; then
        seinfo --role_types docker_helper_builder_workload_t > "$EVIDENCE_DIR/p21e3-mnb30-seinfo-role-types.txt" 2>&1
        sinfo_rc=$?
        cat "$EVIDENCE_DIR/p21e3-mnb30-seinfo-role-types.txt"
        if [ "$sinfo_rc" = 0 ] && grep -aqw system_r "$EVIDENCE_DIR/p21e3-mnb30-seinfo-role-types.txt"; then
          echo "MNB30-SEINFO=PASS (rc=0, the workload role authorization entry system_r is present)"
        else
          echo "MNB30-SEINFO=FAIL (rc=$sinfo_rc; output above)"
        fi
      else
        echo "MNB30-SEINFO=FAIL (seinfo is not installed in the target guest)"
      fi
    fi
  } > "$MNB30_LOG" 2>&1
  cat "$MNB30_LOG"
  if ! grep -aq 'MNB30-RUNTIME-PIN=MATCH' "$MNB30_LOG" \
     || ! grep -aq 'MNB30-HARNESS=PASS' "$MNB30_LOG" \
     || ! grep -aq 'MNB30-SEINFO=PASS' "$MNB30_LOG"; then
    fail "MNB30 preflight gate failed (pin/harness/seinfo); the transition round refuses to start"
  fi
  # The remained live neighbor-label snapshot runs BEFORE the build window.
  MNB30_NEIGHBOR_LOG="$EVIDENCE_DIR/p21e3-mnb30-neighbor-labels.log"
  ls -Zd /var/lib/docker-helper/ops/*/root/runc-native/executor/*/rootfs \
    > "$MNB30_NEIGHBOR_LOG" 2>&1 || true
  fi  # end of the mnb30 preflight

fi  # end of the diag-module-load probe guard (probe mode loaded nothing)

  # --- R7 MNB30: the WORKLOAD kernel-decision matrix — the transition
  # --- result decision over the live observed categories, including the
  # --- CROSS-OPERATION rootfs denial (tracer-free: security_compute_av_raw
  # --- on the loaded policy; the row inputs are the kernel-derived own
  # --- workload category cN and the LIVE labels of a neighboring
  # --- operation's executor tree, captured below). Every row must be a
  # --- decided non-permissive evaluation matching its expectation.
  if [ "${R7_MNB30:-0}" = 1 ]; then
  if ! command -v gcc >/dev/null 2>&1 || [ ! -e /usr/include/selinux/selinux.h ]; then
    timeout 300 zypper --non-interactive install -y gcc libselinux-devel >/dev/null 2>&1 || true
  fi
  command -v gcc >/dev/null 2>&1 || fail "gcc unavailable; the workload kernel-decision matrix cannot run"
  [ -e /usr/include/selinux/selinux.h ] || fail "libselinux headers unavailable"
  MNB30_MATRIX_LOG="$EVIDENCE_DIR/p21e3-mnb30-workload-av-matrix.log"
  MNB30_WORKLOAD_CAT="c1"
  MNB30_NEIGHBOR_CON=""
  MNB30_OWN_CON=""
  # The workload subject context/carhibers: derived from the LIVE sampler
  # evidence when available, else the verified own-context category the
  # wrapper composes from (the kernel-derived cN carried by the sampler).
  WORKLOAD_CTX_ROW="$(grep -a 'PROCDETAIL-WORKLOAD' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | head -1 || true)"
  PROC_SAMPLE="$(grep -a 'workload_t' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | head -1 || true)"
  if [ -n "$PROC_SAMPLE" ]; then
    MNB30_OWN_CON="$(printf '%s\n' "$PROC_SAMPLE" | grep -aoE 'system_u:system_r:docker_helper_builder_workload_t:s0(:c[0-9]+)?' | head -1)"
  fi
  # The neighboring operation: the ops tree currently present beside the
  # measured op (per-op categories are canonical unit state; the neighbor's
  # LABELS are read live, never assumed).
  for nb in $(ls -d /var/lib/docker-helper/ops/* 2>/dev/null || true); do
    name="$(basename "$nb")"
    [ "$name" != "op_$(cat "$EVIDENCE_DIR/operation-id.log" 2>/dev/null)" ] && [ -n "$name" ] && MNB30_OPS_OTHER=1 || true
  done
  # Live labels under the measured and neighboring ops (recorded; the
  # matrix targets the state-tree extra types below with BOTH categories).
  ls -Zd /var/lib/docker-helper/ops/*/root/runc-native/executor/*/rootfs \
    > "$EVIDENCE_DIR/p21e3-mnb30-neighbor-labels.log" 2>&1 || true
  {
    echo "== MNB30 workload kernel-decision matrix (loaded policy = candidate + the three temporary cap rules) =="
    echo "policy sha: $(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
    echo "-- live sampler workload rows (the observed transition contexts) --"
    grep -a 'workload_t' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | head -12 || echo "(no sampler workload row yet)"
    echo "-- live executor-tree labels --"
    cat "$EVIDENCE_DIR/p21e3-mnb30-neighbor-labels.log"
  } > "$MNB30_MATRIX_LOG" 2>&1
  grep -a 'workload_t' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | head -1 >/dev/null || true
  fi  # end of the mnb30-first pass (completed after the build below)

fi  # end of the diag-module-load probe guard (probe mode loaded nothing)

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
# The process-mountinfo snapshotter runs beside the sampler on the SAME
# stop file; its snapshots are the MNB rung's per-context evidence.
PNS_PID=""
"$EVIDENCE_DIR/p21e3_procns_snap" "$EVIDENCE_DIR/p21e3-procns.log" "$STOPSAMP" &
PNS_PID=$!
# The MNB24 userns/capability watch rides the SAME stop file: it observes
# the whole short-lived chain where PR_CAPBSET_DROP decisions are made.
CAPWATCH_PID=""
"$EVIDENCE_DIR/p21e3_capwatch" "$EVIDENCE_DIR/p21e3-capwatch.log" "$STOPSAMP" &
CAPWATCH_PID=$!
# HOST (initial mount namespace) snapshot: the /proc view, its labels and
# the observer's lookups; the propagation tags stay in the raw lines.
{
  echo "== HOST (init mount namespace, pid 1 view) =="
  echo "procfs-instance: pidns=$(readlink /proc/1/ns/pid) mntns=$(readlink /proc/1/ns/mnt) userns=$(readlink /proc/1/ns/user)"
  echo "probe identity: uid=$(id -u) context=$(id -Z 2>/dev/null || echo '<unavailable>')"
  ls -Zd /proc /proc/bus 2>&1
  echo ":: /proc and submounts from /proc/1/mountinfo (raw; mount ids, major:minor, root, propagation)"
  grep -aE '[[:space:]]/proc([[:space:]/]|\b|$)|/proc/' /proc/1/mountinfo || cat /proc/1/mountinfo
} > "$EVIDENCE_DIR/p21e3-procns-host.log" 2>&1
trap 'p21e3_diag_remove; p21e3_dontaudit_restore; measure_abandon' EXIT
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

# Capture only the hardening lists and target metadata in the live OCI view.
# The sampler runs before POST and shares the measurement's stop marker.
PROC_INVENTORY_PID=""
PROC_INVENTORY_SCRIPT=/opt/uat/scripts/release-2.4-r7-proc-inventory.py
PROC_INVENTORY_CAPTURE="$EVIDENCE_DIR/p21e3-proc-inventory.jsonl"
if [ "${R7_P21E3_DIAG_KEYS:-0}" = 1 ]; then
  python3 "$PROC_INVENTORY_SCRIPT" capture "$BUILDER_STATE_ROOT" "$STOPSAMP" \
    > "$PROC_INVENTORY_CAPTURE" 2>"$EVIDENCE_DIR/p21e3-proc-inventory.err" &
  PROC_INVENTORY_PID=$!
  for _ in $(seq 1 40); do
    grep -Fq '"event": "ready"' "$PROC_INVENTORY_CAPTURE" && break
    if ! kill -0 "$PROC_INVENTORY_PID" 2>/dev/null; then break; fi
    sleep 0.05
  done
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
# --- MNB30 tracer-free mode attaches NO tracer at any boundary: the /proc
# --- sampler and the audit window are the instruments (the exec boundary
# --- is measured without ptrace).
STRACE_PID=""
STRACE_ALL_PIDS=""
BKD_PID=""
if [ "${R7_MNB30:-0}" != 1 ]; then
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
    -e trace=execve,execveat,open,openat,openat2,read,newfstatat,fstat,statx,statfs,getxattr,lgetxattr,fgetxattr,rename,renameat,renameat2,mount,umount2,mkdir,mkdirat,symlink,symlinkat,prctl,capset,setgroups,setgid,setregid,setresgid \
    -o "$EVIDENCE_DIR/p21e3-strace.log" 2>"$EVIDENCE_DIR/p21e3-strace.err" &
  STRACE_PID=$!
  STRACE_ALL_PIDS="$STRACE_ALL_PIDS $STRACE_PID"
else
  STRACE_PID=""
  log "no buildkitd pid observed to attach; recorded as NOT-ATTACHED for this boundary (NOT evidence of non-existence)"
fi
[ -n "$BKD_PID" ] && echo "attach=$BKD_PID" > "$EVIDENCE_DIR/p21e3-strace-attach.log" \
  || echo "attach=none (never attached; NOT evidence of non-existence)" > "$EVIDENCE_DIR/p21e3-strace-attach.log"

fi  # end of the buildkitd attach (skipped in the MNB30 tracer-free mode)

# --- R4-P3-P6-MNB12: the read-only baseline probe INSIDE the live build
# --- window: the family (and, transiently, the per-op runc tree) is alive
# --- here; the resolver enters the buildkitd mount namespace READ-ONLY,
# --- resolves the inherited /proc instance (RUN-LOCAL mount id +
# --- major:minor), the SERVICING pidns and its owning user ns via
# --- NS_GET_USERNS, then inventories the same-superblock carriers and the
# --- live family. No policy or mount-state change: the build below runs on
# --- the untouched baseline (its expected /proc/bus mounton EACCES outcome
# --- is the standing measured behavior, not a probe effect).
NSR_LOG="$EVIDENCE_DIR/p21e3-nsr-probe.log"
NSR_DEV=""
if [ -n "$BKD_PID" ]; then
  log "probe: resolver enters the buildkitd mount namespace (pid $BKD_PID) read-only"
  : > "$NSR_LOG"
  "$EVIDENCE_DIR/p21e3_nsier" "$BKD_PID" >> "$NSR_LOG" 2>&1 \
    || printf 'nsier rc=%d\n' "$?" >> "$NSR_LOG"
  NSR_DEV="$(grep -a '^NSR-PROC-DEV ' "$NSR_LOG" | awk '{print $2}' | sed 's/^dev=//' | head -1)"
  {
    echo "== carriers of the builder procfs superblock (per live process, same window) =="
    if [ -n "${NSR_DEV:-}" ]; then
      for pd in /proc/[0-9]*; do
        pn="$(cat "$pd/comm" 2>/dev/null || true)"
        case "$pn" in
          buildkitd|rootlesskit|slirp4netns|*runc*) : ;;
          *) continue ;;
        esac
        cp="${pd#/proc/}"
        ln="$(awk -v d="$NSR_DEV" '$3==d && $7=="-" && $8=="proc" {print "mount_id="$1" parent="$2" dev="$3" root="$4" mntpoint="$5}' "$pd/mountinfo" 2>/dev/null | head -2)"
        if [ -n "$ln" ]; then
          echo "--- carrier pid=$cp comm=$pn mntns=$(readlink "$pd/ns/mnt" 2>/dev/null)"
          printf 'context=%s\n' "$(cat "$pd/attr/current" 2>/dev/null || echo unknown)"
          printf '%s\n' "$ln"
        fi
      done
    else
      echo "GAP: the probe did not resolve the procfs instance line; carrier inventory aborted"
    fi
    echo "== the same-window live family inventory =="
    for pd in /proc/[0-9]*; do
      pn="$(cat "$pd/comm" 2>/dev/null || true)"
      case "$pn" in
        buildkitd|rootlesskit|slirp4netns|*runc*) printf 'pid=%s comm=%s mnt=%s user=%s pidns=%s\n' \
          "${pd#/proc/}" "$pn" "$(readlink "$pd/ns/mnt" 2>/dev/null)" \
          "$(readlink "$pd/ns/user" 2>/dev/null)" "$(readlink "$pd/ns/pid" 2>/dev/null)" ;;
      esac
    done
    echo "== enforcement state (must be untouched) =="
    getenforce 2>&1
  } >> "$NSR_LOG" 2>&1
  cat "$NSR_LOG"
else
  echo "GAP: no buildkitd attached in this window; the probe target is absent" > "$NSR_LOG"
  cat "$NSR_LOG"
fi

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
# The op log is the wrapper's own refusal/error surface; it is captured
# IMMEDIATELY at the terminal so a mid-diagnosis reboot cannot lose the
# precise refused reason behind the BUILD=failed result. The audit window
# is drained at the same point for the same reason: the window records are
# the kernel-decision evidence (e.g. the measured seinfo read denial) a
# reboot would otherwise lose.
curl --silent --max-time 5 --unix-socket "$DH_SOCK" -H "Authorization: Bearer $TOKEN" \
  "http://localhost/operations/$OP/logs?offset=0" > "$EVIDENCE_DIR/operation-terminal.log" 2>&1 || true
audit_window_drain "$EVIDENCE_DIR/p21e3-window-records.log" || true
touch "$EVIDENCE_DIR/window-drained-at-terminal"
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
if [ -n "${CAPWATCH_PID:-}" ]; then
  wait "$CAPWATCH_PID" 2>/dev/null || true
  CAPWATCH_PID=""
fi
if [ -n "${PNS_PID:-}" ]; then
  wait "$PNS_PID" 2>/dev/null || true
  PNS_PID=""
fi
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
if [ -n "$PROC_INVENTORY_PID" ]; then
  wait "$PROC_INVENTORY_PID" 2>/dev/null || true
  PROC_INVENTORY_PID=""
  timeout 25 python3 "$PROC_INVENTORY_SCRIPT" report "$OP" "$PROC_INVENTORY_CAPTURE" \
    > "$EVIDENCE_DIR/p21e3-proc-inventory-policy.jsonl" 2>>"$EVIDENCE_DIR/p21e3-proc-inventory.err" \
    || log "OCI path policy inventory was incomplete; see the inventory evidence"
fi

# --- R7 MNB30: the transition result (tracer-free; the policy is still
# --- carrying the temporary cap module — exactly the state the build ran
# --- under). The instruments: the /proc sampler records (live kernel
# --- contexts, Cap*, NoNewPrivs — no ptrace anywhere) and the libselinux
# --- kernel-decision matrix over the observed categories, including the
# --- CROSS-OPERATION rootfs denial for the workload domain.
if [ "${R7_MNB30:-0}" = 1 ]; then
  MNB30_TRANS_LOG="$EVIDENCE_DIR/p21e3-mnb30-transition.log"
  if ! command -v gcc >/dev/null 2>&1 || [ ! -e /usr/include/selinux/selinux.h ]; then
    timeout 300 zypper --non-interactive install -y gcc libselinux-devel >/dev/null 2>&1 || true
  fi
  command -v gcc >/dev/null 2>&1 || fail "gcc unavailable; the MNB30 kernel-decision matrix cannot run"
  [ -e /usr/include/selinux/selinux.h ] || fail "libselinux headers unavailable"
  cat > "$EVIDENCE_DIR/p21e3_mnb30_workload_avdec.c" <<'CEOF'
/* R7 MNB30: the workload kernel-decision matrix. Invoked as
 *   mnb30_avdec <workload-own-context> <neighbor-category>
 * The own context is the LIVE observed workload context (sampled from
 * /proc, never assumed); the neighbor exercises the cross-operation
 * rootfs denial through the state-tree type with a DIFFERENT category.
 * Columns: scon tcon class perm allowed decided auditallow auditdeny
 * permissive expect; expect=allow|deny is checked by the shell verdict.
 */
#include <selinux/selinux.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static struct q { const char *scon, *tcon, *cls, *perm, *expect; } ROWS[256];
static size_t NROWS;
static void add(const char *s, const char *t, const char *c, const char *p, const char *e) {
  ROWS[NROWS].scon = s; ROWS[NROWS].tcon = t; ROWS[NROWS].cls = c;
  ROWS[NROWS].perm = p; ROWS[NROWS].expect = e; NROWS++;
}

#define ST_TYPE "docker_helper_builder_state_t"

int main(int argc, char **argv) {
  if (argc != 3) { fprintf(stderr, "usage: %s <workload own context> <neighbor category>\n", argv[0]); return 2; }
  const char *own = argv[1];
  const char *ncat = argv[2];
  /* Derive the own-category twin (the same subject at the neighbor's
   * category) and the neighbor target contexts by textual category
   * substitution of the LAST colon field suffix. */
  static char own_neighbor[256], state_own[256], state_neighbor[256], ns_own[256], ns_neighbor[256];
  const char *mcs = strstr(own, ":s0");
  if (!mcs) { fprintf(stderr, "ERR\town context carries no sensitivity field\n"); return 1; }
  snprintf(ns_own, sizeof ns_own, "%.*s", (int)(mcs - own + 3), own);
  snprintf(ns_neighbor, sizeof ns_neighbor, "%s:%s", ns_own, ncat);
  /* Build the targets textually: object role + type + sensitivity:category */
  snprintf(state_own, sizeof state_own, "system_u:object_r:%s%s", ST_TYPE, mcs);
  snprintf(state_neighbor, sizeof state_neighbor, "system_u:object_r:%s:s0:%s", ST_TYPE, ncat);
  /* Keep the subject contexts verbatim: the own row replays the sampled
   * workload context; the neighbor row is the WORKLOAD domain at the
   * neighbor category (the transition-target authority rule stays owned
   * by the policy; the matrix measures the MCS layer on file/dir). */
  snprintf(own_neighbor, sizeof own_neighbor, "%s:%s", ns_own, ncat);
  /* The MNB28 (b) grant face is the allowed set; the same-op rows must
   * ALLOW it, the cross-op rows must DENY it by the MCS layer (the same
   * TE rows are type-wide, so a cross-category allow would expose an
   * MCS escape). NOT-GRANTED rows (write/append on file,
   * write/add_name/remove_name on dir) must DENY in BOTH categories:
   * the measured-increment principle keeps them un-granted. */
  static const char *gperms[] = { "execute", "entrypoint", "map", "open", "read", "getattr" };
  for (size_t i = 0; i < 6; i++) {
    add(own, state_own, "file", gperms[i], "allow");
    add(own, state_neighbor, "file", gperms[i], "deny");
    add(own_neighbor, state_neighbor, "file", gperms[i], "allow");
    add(own_neighbor, state_own, "file", gperms[i], "deny");
  }
  static const char *nperms[] = { "write", "append" };
  for (size_t i = 0; i < 2; i++) {
    add(own, state_own, "file", nperms[i], "deny");
    add(own, state_neighbor, "file", nperms[i], "deny");
  }
  static const char *gdperms[] = { "search" };
  for (size_t i = 0; i < 1; i++) {
    add(own, state_own, "dir", gdperms[i], "allow");
    add(own, state_neighbor, "dir", gdperms[i], "deny");
    add(own_neighbor, state_neighbor, "dir", gdperms[i], "allow");
    add(own_neighbor, state_own, "dir", gdperms[i], "deny");
  }
  static const char *ndperms[] = { "write", "add_name", "remove_name" };
  for (size_t i = 0; i < 3; i++) {
    add(own, state_own, "dir", ndperms[i], "deny");
    add(own, state_neighbor, "dir", ndperms[i], "deny");
  }
  for (size_t i = 0; i < NROWS; i++) {
    struct q *r = &ROWS[i];
    security_class_t cls = string_to_security_class(r->cls);
    if (!cls) { printf("ERR\tclass %s unknown\n", r->cls); return 1; }
    access_vector_t bit = string_to_av_perm(cls, r->perm);
    if (!bit) { printf("ERR\tperm %s %s unknown\n", r->cls, r->perm); return 1; }
    struct av_decision avd;
    memset(&avd, 0, sizeof(avd));
    if (security_compute_av_raw(r->scon, r->tcon, cls, bit, &avd) < 0) {
      printf("ERR\tcompute_av failed\n");
      return 1;
    }
    printf("%s\t%s\t%s\t%s\t%u\t%u\t%u\t%u\t%u\t%s\n",
           r->scon, r->tcon, r->cls, r->perm,
           (avd.allowed & bit) ? 1 : 0,
           (avd.decided & bit) ? 1 : 0,
           (avd.auditallow & bit) ? 1 : 0,
           (avd.auditdeny & bit) ? 1 : 0,
           (avd.flags & SELINUX_AVD_FLAGS_PERMISSIVE) ? 1 : 0,
           r->expect);
  }
  return 0;
}
CEOF
  MNB30_MATRIX_LOG="$EVIDENCE_DIR/p21e3-mnb30-workload-av-matrix.log"
  WORKLOAD_ROW="$(grep -a 'workload_t' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | grep -a 'ctx=system_u:system_r:' | head -1 || true)"
  OWN_CON="$(printf '%s\n' "$WORKLOAD_ROW" | grep -aoE 'system_u:system_r:docker_helper_builder_workload_t:s0(:c[0-9]+)?' | head -1)"
  # The MCS category pool: the measured op's category and the canonical
  # next-pool category as the neighbor (the per-op pool assignment is the
  # unit's own behavior; the matrix uses the observed own category LIVE).
  OWN_CAT="$(printf '%s\n' "$OWN_CON" | grep -aoE 'c[0-9]+' | head -1 || true)"
  NEIGHBOR_CAT="c2"; [ "$OWN_CAT" = "c2" ] && NEIGHBOR_CAT="c1"
  {
    echo "== MNB30 transition + kernel-decision evidence =="
    echo "policy sha: $(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
    echo "-- live workload rows (sampler, /proc only) --"
    grep -a 'workload_t' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | head -30 || echo "(no workload row; the transition is NOT confirmed)"
    echo "-- distinct workload pids and their Cap*/NoNewPrivs captures --"
    grep -a 'PROCDETAIL-WORKLOAD' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | head -60 || echo "(no PROCDETAIL-WORKLOAD rows)"
    echo "-- the sampler's live buildkitd category (the wrapper's own pool) --"
    grep -a 'ctx=.*buildkitd_t' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | head -3 || true
    echo "-- live executor-tree labels (the measured op + any neighbor) --"
    cat "$EVIDENCE_DIR/p21e3-mnb30-neighbor-labels.log" 2>/dev/null || true
  } > "$MNB30_TRANS_LOG" 2>&1
  if [ -z "$OWN_CON" ]; then
    echo "R7-MNB30-TRANSITION=REFUSED (no workload context observed in the sampler; the composed transition did not land)" >> "$MNB30_TRANS_LOG"
    echo "R7-MNB30-WORKLOAD-MATRIX=NOT-RUN" >> "$MNB30_TRANS_LOG"
  else
    echo "own-workload-context=$OWN_CON neighbor-category=$NEIGHBOR_CAT" >> "$MNB30_TRANS_LOG"
    gcc -O2 -o "$EVIDENCE_DIR/p21e3_mnb30_workload_avdec" "$EVIDENCE_DIR/p21e3_mnb30_workload_avdec.c" -lselinux \
      >> "$MNB30_TRANS_LOG" 2>&1 \
      || { cat "$MNB30_TRANS_LOG"; fail "the MNB30 kernel-decision helper build failed; BLOCKED"; }
    "$EVIDENCE_DIR/p21e3_mnb30_workload_avdec" "$OWN_CON" "$NEIGHBOR_CAT" >> "$MNB30_TRANS_LOG" 2>&1 \
      || { cat "$MNB30_TRANS_LOG"; fail "the MNB30 kernel-decision helper failed; BLOCKED"; }
    BADS="$(awk -F'\t' '$1=="ERR" { print "ERRROW " $0; next } NF>=10 && $10!="" {
      if ($6 != 1) { print "UNDECIDED " $0 }
      if ($9 != 0) { print "PERMISSIVE " $0 }
      if ($10=="allow" && $5!=1) { print "MISMATCH-ALLOW " $0 }
      if ($10=="deny" && $5!=0) { print "MISMATCH-DENY " $0 }
    }' "$MNB30_TRANS_LOG")"
    if [ -n "$BADS" ]; then
      printf '%s\n' "$BADS" >> "$MNB30_TRANS_LOG"
      cat "$MNB30_TRANS_LOG"
      printf 'R7-MNB30-WORKLOAD-MATRIX=FAIL\n'
      fail "the MNB30 workload kernel-decision matrix reached an unexpected resolution; BLOCKED"
    fi
    echo "R7-MNB30-WORKLOAD-MATRIX=PASS" >> "$MNB30_TRANS_LOG"
    # The transition verdict: a workload process observed in the composed
    # context (workload domain + the own category) with single-category
    # coherence across every workload row.
    CATS="$(grep -a 'workload_t' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null \
      | grep -aoE 'ctx=system_u:system_r:docker_helper_builder_workload_t:s0(:c[0-9]+)?' \
      | sort -u | wc -l)"
    COUNT="$(grep -a 'workload_t' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | grep -ac 'ctx=system_u:system_r:docker_helper_builder_workload_t' || true)"
    if [ "$CATS" = 1 ] && [ "${COUNT:-0}" -ge 1 ]; then
      echo "R7-MNB30-TRANSITION=CONFIRMED (single composed context across $COUNT sampler rows)" >> "$MNB30_TRANS_LOG"
    else
      echo "R7-MNB30-TRANSITION=REFUSED (distinct composed contexts=$CATS, rows=$COUNT)" >> "$MNB30_TRANS_LOG"
    fi
  fi
  cat "$MNB30_TRANS_LOG"
  grep -aoE 'R7-MNB30-TRANSITION=[A-Z]+' "$MNB30_TRANS_LOG" | tail -1
  grep -aoE 'R7-MNB30-WORKLOAD-MATRIX=[A-Z-]+' "$MNB30_TRANS_LOG" | tail -1
fi
# --- the fixed single-row diagnostic module: removal and unload
# --- verification BEFORE the dontaudit restore (the removal's own rebuild
# --- PRESERVES the disable-dontaudit build state, so the policy-shape
# --- check below runs only AFTER the restore has returned the baseline).
if [ "${R7_P21E3_PROBE:-0}" = 1 ]; then
  log "probe mode: nothing was loaded; no unload is needed (the baseline policy never moved)"
  printf 'R7-P21E3-DIAG-UNLOADED=probe-not-loaded' >> "$DIAG_LOG"
else
p21e3_diag_remove
DIAG_UNLOAD_OK=1
{
  echo "-- diagnostic module unload verification --"
  if semodule -l 2>/dev/null | grep -aq docker_helper_diag_mounton; then
    echo "DIAG-UNLOAD-GATE: FAIL (the module is still registered in the store)"
    DIAG_UNLOAD_OK=0
  else
    echo "module store: docker_helper_diag_mounton absent => OK"
  fi
  DIAG_UNLOAD_Q="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t proc_t -c dir -p mounton 2>&1)"
  DIAG_UNLOAD_RC=$?
  DIAG_UNLOAD_V="$(classify_sesearch_query "$DIAG_UNLOAD_RC" "$DIAG_UNLOAD_Q")"
  printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_UNLOAD_RC" "$DIAG_UNLOAD_V" "$DIAG_UNLOAD_Q"
  if [ "$DIAG_UNLOAD_V" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
    echo "DIAG-UNLOAD-GATE: FAIL (the mounton rule is still present: $DIAG_UNLOAD_V)"
    DIAG_UNLOAD_OK=0
  fi
  DIAG_UNLOAD_Q2="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t proc_t -c filesystem -p remount 2>&1)"
  DIAG_UNLOAD_RC2=$?
  DIAG_UNLOAD_V2="$(classify_sesearch_query "$DIAG_UNLOAD_RC2" "$DIAG_UNLOAD_Q2")"
  printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_UNLOAD_RC2" "$DIAG_UNLOAD_V2" "$DIAG_UNLOAD_Q2"
  if [ "$DIAG_UNLOAD_V2" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
    echo "DIAG-UNLOAD-GATE: FAIL (the remount rule is still present: $DIAG_UNLOAD_V2)"
    DIAG_UNLOAD_OK=0
  fi
  DIAG_UNLOAD_Q3="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t sysctl_irq_t -c dir -p mounton 2>&1)"
  DIAG_UNLOAD_RC3=$?
  DIAG_UNLOAD_V3="$(classify_sesearch_query "$DIAG_UNLOAD_RC3" "$DIAG_UNLOAD_Q3")"
  printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_UNLOAD_RC3" "$DIAG_UNLOAD_V3" "$DIAG_UNLOAD_Q3"
  if [ "$DIAG_UNLOAD_V3" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
    echo "DIAG-UNLOAD-GATE: FAIL (the sysctl_irq_t mounton rule is still present: $DIAG_UNLOAD_V3)"
    DIAG_UNLOAD_OK=0
  fi
  # R4-P3-P6-MNB15: the fourth reviewed row must also be gone.
  DIAG_UNLOAD_Q4="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t sysctl_t -c dir -p mounton 2>&1)"
  DIAG_UNLOAD_RC4=$?
  DIAG_UNLOAD_V4="$(classify_sesearch_query "$DIAG_UNLOAD_RC4" "$DIAG_UNLOAD_Q4")"
  printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_UNLOAD_RC4" "$DIAG_UNLOAD_V4" "$DIAG_UNLOAD_Q4"
  if [ "$DIAG_UNLOAD_V4" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
    echo "DIAG-UNLOAD-GATE: FAIL (the sysctl_t mounton rule is still present: $DIAG_UNLOAD_V4)"
    DIAG_UNLOAD_OK=0
  fi
  # R4-P3-P6-MNB16: the fifth reviewed row must also be gone.
  DIAG_UNLOAD_Q5="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t sysctl_t -c file -p mounton 2>&1)"
  DIAG_UNLOAD_RC5=$?
  DIAG_UNLOAD_V5="$(classify_sesearch_query "$DIAG_UNLOAD_RC5" "$DIAG_UNLOAD_Q5")"
  printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_UNLOAD_RC5" "$DIAG_UNLOAD_V5" "$DIAG_UNLOAD_Q5"
  if [ "$DIAG_UNLOAD_V5" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
    echo "DIAG-UNLOAD-GATE: FAIL (the sysctl_t file mounton rule is still present: $DIAG_UNLOAD_V5)"
    DIAG_UNLOAD_OK=0
  fi
  # R4-P3-P6-MNB17: the sixth reviewed row must also be gone.
  DIAG_UNLOAD_Q6="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t proc_kcore_t -c file -p getattr 2>&1)"
  DIAG_UNLOAD_RC6=$?
  DIAG_UNLOAD_V6="$(classify_sesearch_query "$DIAG_UNLOAD_RC6" "$DIAG_UNLOAD_Q6")"
  printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_UNLOAD_RC6" "$DIAG_UNLOAD_V6" "$DIAG_UNLOAD_Q6"
  if [ "$DIAG_UNLOAD_V6" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
    echo "DIAG-UNLOAD-GATE: FAIL (the proc_kcore_t file getattr rule is still present: $DIAG_UNLOAD_V6)"
    DIAG_UNLOAD_OK=0
  fi
  # R4-P3-P6-MNB18: the seventh reviewed row must also be gone.
  DIAG_UNLOAD_Q7="$(timeout 60 sesearch -A -s docker_helper_buildkitd_t -t proc_kcore_t -c file -p mounton 2>&1)"
  DIAG_UNLOAD_RC7=$?
  DIAG_UNLOAD_V7="$(classify_sesearch_query "$DIAG_UNLOAD_RC7" "$DIAG_UNLOAD_Q7")"
  printf 'query-rc=%s\nclassify=%s\n%s\n' "$DIAG_UNLOAD_RC7" "$DIAG_UNLOAD_V7" "$DIAG_UNLOAD_Q7"
  if [ "$DIAG_UNLOAD_V7" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
    echo "DIAG-UNLOAD-GATE: FAIL (the proc_kcore_t file mounton rule is still present: $DIAG_UNLOAD_V7)"
    DIAG_UNLOAD_OK=0
  fi
} >> "$DIAG_LOG" 2>&1
if [ "$DIAG_UNLOAD_OK" != 1 ]; then
  cat "$DIAG_LOG"
  p21e3_dontaudit_restore
  fail "the diagnostic module rule-level unload could not be verified; BLOCKED"
fi
# Exact policy restoration is verified below. Record live inode labels
# independently of the policy checks.
if [ "${R7_P21E3_DIAG_KEYS:-0}" = 1 ]; then
  {
    echo "-- R4-P3-P6-MNB22 dedicated-type unload corroboration --"
    if semodule -l 2>/dev/null | grep -aq docker_helper_diag_keys; then
      echo "DIAG-UNLOAD-GATE: FAIL (the dedicated-type module is still registered in the store)"
    else
      echo "module store: docker_helper_diag_keys absent => OK"
    fi
    echo "-- dedicated types and genfscon absence --"
    if ! p21e3_diag_proc_types_absent; then
      echo "DIAG-UNLOAD-GATE: FAIL (dedicated-type and genfscon absence could not be verified)"
    fi
  } >> "$DIAG_LOG" 2>&1
fi
# The three-rule capability module unload corroboration: DIAG-KEYS mode and
# the MNB30 tracer-free round both end with the MNB24/26/27 grants removed.
if [ "${R7_P21E3_DIAG_KEYS:-0}" = 1 ] || [ "${R7_MNB30:-0}" = 1 ]; then
  {
    echo "-- R7 MNB26: the two-rule capability module unload corroboration --"
    if semodule -l 2>/dev/null | grep -aq docker_helper_diag_cap; then
      echo "DIAG-UNLOAD-GATE: FAIL (the cap module is still registered in the store)"
    else
      echo "module store: docker_helper_diag_cap absent => OK"
    fi
    for DIAG_CAP_CLASS in cap_userns capability; do
      for DIAG_CAP_TOKEN in setpcap setgid; do
        DIAG_CAP_UQ="$(timeout 60 sesearch -A -ds -dt -s docker_helper_buildkitd_t \
          -t docker_helper_buildkitd_t -c "$DIAG_CAP_CLASS" -p "$DIAG_CAP_TOKEN" 2>&1)"
        DIAG_CAP_UV="$(classify_sesearch_query "$?" "$DIAG_CAP_UQ")"
        if [ "$DIAG_CAP_UV" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
          echo "DIAG-UNLOAD-GATE: FAIL ($DIAG_CAP_TOKEN on self $DIAG_CAP_CLASS is still present: $DIAG_CAP_UV)"
        else
          echo "DIAG-UNLOAD-GATE: PASS (class=$DIAG_CAP_CLASS $DIAG_CAP_TOKEN absence restored)"
        fi
      done
    done
    DIAG_PROC_UQ="$(timeout 60 sesearch -A -ds -dt -s docker_helper_buildkitd_t \
      -t docker_helper_buildkitd_t -c process -p setcap 2>&1)"
    DIAG_PROC_UV="$(classify_sesearch_query "$?" "$DIAG_PROC_UQ")"
    if [ "$DIAG_PROC_UV" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
      echo "DIAG-UNLOAD-GATE: FAIL (setcap on self process is still present: $DIAG_PROC_UV)"
    else
      echo "DIAG-UNLOAD-GATE: PASS (class=process setcap absence restored)"
    fi
    if [ "${R7_MNB30:-0}" = 1 ]; then
      echo "-- MNB30: the workload-domain module unload corroboration --"
      if semodule -l 2>/dev/null | grep -aq docker_helper_diag_workload; then
        echo "DIAG-UNLOAD-GATE: FAIL (the workload-domain module is still registered in the store)"
      else
        echo "module store: docker_helper_diag_workload absent => OK"
      fi
      WL_SEINFO_TYPE="$(matchpathcon -n /usr/bin/seinfo 2>/dev/null | awk -F: '{print $3}')"
      case "$WL_SEINFO_TYPE" in
        [a-z_]*_t) : ;;
        *) WL_SEINFO_TYPE=bin_t ;;
      esac
      WL_POLICY_TYPE="$(ls -ZN /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}' | awk -F: '{print $3}')"
      case "$WL_POLICY_TYPE" in
        [a-z_]*_t) : ;;
        *) WL_POLICY_TYPE=security_t ;;
      esac
      for WL_ROW in \
        'docker_helper_builder_workload_t.docker_helper_builder_state_t:file:execute' \
        'docker_helper_builder_workload_t.docker_helper_builder_state_t:file:entrypoint' \
        'docker_helper_builder_workload_t.docker_helper_builder_state_t:dir:search' \
        'docker_helper_buildkitd_t.docker_helper_builder_workload_t:process:transition' \
        "docker_helper_buildkitd_t.${WL_SEINFO_TYPE}:file:execute" \
        "docker_helper_buildkitd_t.${WL_POLICY_TYPE}:file:read" ; do
        WL_S="${WL_ROW%%.*}"
        WL_REST="${WL_ROW#*.}"
        WL_T="$(printf '%s\n' "$WL_REST" | cut -d: -f1)"
        WL_CLASS="$(printf '%s\n' "$WL_REST" | cut -d: -f2)"
        WL_P="$(printf '%s\n' "$WL_REST" | cut -d: -f3)"
        WL_UQ="$(timeout 60 sesearch -A -s "$WL_S" -t "$WL_T" -c "$WL_CLASS" -p "$WL_P" 2>&1)"
        WL_UV="$(classify_sesearch_query "$?" "$WL_UQ")"
        if [ "$WL_UV" != 'trusted:perms=|cond-active=none|cond-inactive=none' ]; then
          echo "DIAG-UNLOAD-GATE: FAIL ($WL_ROW still present after the unload: $WL_UV)"
        else
          echo "DIAG-UNLOAD-GATE: PASS ($WL_ROW absence restored)"
        fi
      done
      echo "-- the workload type itself must be gone again (the wrapper's rolecheck refuses it) --"
      if seinfo --role_types docker_helper_builder_workload_t 2>/dev/null | grep -aqw system_r; then
        echo "DIAG-UNLOAD-GATE: FAIL (the workload roletype survives the unload)"
      else
        echo "DIAG-UNLOAD-GATE: PASS (the workload roletype authorization is gone)"
      fi
    fi
  } >> "$DIAG_LOG" 2>&1
  grep -aq '^DIAG-UNLOAD-GATE: FAIL' "$DIAG_LOG" && DIAG_UNLOAD_OK=0
fi
if [ "${R7_P21E3_DIAG_KEYS:-0}" = 1 ]; then
  {
    DIAG_SHADERE="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
    echo "policy sha at unload-check time (post-removal, pre-restore): $DIAG_SHADERE"
    echo "policy sha before dedicated-module load (for comparison): $DIAG_KEYS_PRELOAD_SHA"
    echo "policy sha before cap-module load (for comparison): $DIAG_CAP_PRELOAD_SHA"
    echo "-- proc inode labels in the remaining guest (init) view --"
    echo "-- (observed inode label; policy restoration is verified separately) --"
    ls -Zd /proc/keys /proc/timer_list 2>&1 || true
    stat -c 'stat: mode=%a ino=%i' /proc/keys 2>&1 || true
    python3 - <<'PYEOF' 2>&1 || true
import os
try:
    lab = os.getxattr("/proc/keys", "security.selinux")
    print("xattr security.selinux on /proc/keys: %r" % lab)
except OSError as e:
    print("xattr security.selinux on /proc/keys: OSError errno=%d" % e.errno)
PYEOF
  } >> "$DIAG_LOG" 2>&1
  grep -aq '^DIAG-UNLOAD-GATE: FAIL' "$DIAG_LOG" && DIAG_UNLOAD_OK=0
fi
# The normal-path restore: the verdict must be independently verified; an
# unverified restoration decides the distinct infrastructure/policy-state
# verdict and stops the round.
if ! p21e3_dontaudit_restore; then
  fail "the dontaudit restoration could not be verified (distinct infrastructure/policy-state verdict)"
fi
# --- diagnostic module unload, policy-shape leg: the restored policy must
# --- equal the pre-toggle baseline exactly, and the release policy bytes
# --- must be unchanged; only then the removal may be pronounced verified.
{
  DIAG_SHA_UNLOAD="$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
  echo "policy sha after removal+restore: $DIAG_SHA_UNLOAD (pre-toggle baseline: ${SE_POLICY_SHA_PRE:-none})"
  if [ -z "$DIAG_SHA_UNLOAD" ] || [ "$DIAG_SHA_UNLOAD" != "${SE_POLICY_SHA_PRE:-}" ]; then
    echo "DIAG-UNLOAD-GATE: FAIL (the loaded policy did not return to the pre-toggle baseline shape)"
    DIAG_UNLOAD_OK=0
  else
    echo "policy shape: baseline restored => OK"
  fi
  DIAG_RELEASE_PP_SHA_POST="$(sha256sum /usr/share/selinux/docker_helper.pp 2>/dev/null | awk '{print $1}')"
  echo "release-policy .pp sha (post; must equal $DIAG_RELEASE_PP_SHA_PRE): $DIAG_RELEASE_PP_SHA_POST"
  if [ "$DIAG_RELEASE_PP_SHA_POST" != "$DIAG_RELEASE_PP_SHA_PRE" ]; then
    echo "DIAG-UNLOAD-GATE: FAIL (the release policy bytes changed)"
    DIAG_UNLOAD_OK=0
  else
    echo "release-policy .pp sha unchanged => OK"
  fi
  if [ "$DIAG_UNLOAD_OK" = 1 ]; then
    echo "R7-P21E3-DIAG-UNLOADED=verified"
  fi
} >> "$DIAG_LOG" 2>&1
cat "$DIAG_LOG"
if [ "$DIAG_UNLOAD_OK" != 1 ]; then
  fail "the diagnostic module unload could not be verified (policy-shape leg); BLOCKED"
fi
log "diagnostic module unloaded and verified ($DIAG_MODULE)"
if [ "${R7_P21E3_DIAG_KEYS:-0}" = 1 ]; then
  {
    echo "-- final policy state after removal+restore (R4-P3-P6-MNB22) --"
    echo "policy sha after removal+restore (final): $DIAG_SHA_UNLOAD"
    echo "-- proc inode labels after policy restore, guest init view --"
    ls -Zd /proc/keys /proc/timer_list 2>&1 || true
    echo "release-policy .pp sha (final): $DIAG_RELEASE_PP_SHA_POST"
    echo "R7-P21E3-DIAG-UNLOADED=verified"
  } >> "$DIAG_KEYS_LOG" 2>&1
  cat "$DIAG_KEYS_LOG"
fi
fi  # end of the diag-module-unload probe guard

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
if [ -f "$EVIDENCE_DIR/window-drained-at-terminal" ]; then
  log "audit window drained already at the build terminal (the reboot-proof capture); no second drain"
else
  audit_window_drain "$EVIDENCE_DIR/p21e3-window-records.log" || true
fi
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
# Runtime-tree absence is separate from the prepared /dev tree.
if [[ "$OP" =~ ^op_[a-f0-9]{32}$ ]]; then
  python3 - "$OP" > "$EVIDENCE_DIR/p21e3-runc-runtime-terminal.log" <<'PYEOF'
import errno
import os
import sys

op = sys.argv[1]
parent = "/run/docker-helper-builder/ops"
try:
    fd = os.open(parent, os.O_PATH | os.O_DIRECTORY)
except OSError as exc:
    print(f"probe=gap parent={parent} errno={exc.errno}")
    raise SystemExit(0)
try:
    os.stat(op, dir_fd=fd, follow_symlinks=False)
except OSError as exc:
    status = "absent" if exc.errno == errno.ENOENT else "gap"
    print(f"probe={status} path={parent}/{op} errno={exc.errno}")
else:
    print(f"probe=present path={parent}/{op}")
finally:
    os.close(fd)
PYEOF
  cat "$EVIDENCE_DIR/p21e3-runc-runtime-terminal.log"
fi
# R7 MNB24: the bounding-set evidence extraction. Pure post-processing of
# the captured surfaces (strace prctl/capset lines joined with the capwatch
# userns rows and the inventory's OCI capability block); no live reads.
if [ "${R7_P21E3_DIAG_KEYS:-0}" = 1 ]; then
  python3 - "$EVIDENCE_DIR" > "$EVIDENCE_DIR/p21e3-capbset-evidence.log" <<'PYEOF'
import json
import re
import sys
from pathlib import Path

EV = Path(sys.argv[1])
strace = EV / "p21e3-strace.log"
capwatch = EV / "p21e3-capwatch.log"
inventory = EV / "p21e3-proc-inventory.jsonl"

print("== MNB24 bounding-set evidence ==")
# R7 MNB26: the per-call cap_userns denial inventory (dac_override, fsetid,
# setfcap, ... stay witnessed, not acted on) and the time-bound CapBnd tie.
import collections
avc_rows = []
window = EV / "p21e3-window-records.log"
if window.exists():
    for line in window.read_text(errors="replace").splitlines():
        m = re.match(
            r".*audit\((\d+\.\d+):\d+\).*avc:\s+denied\s+\{ ([^}]+) \}.*?pid=(\d+) "
            r'.*?capability=(\d+)*.*scontext=(\S+) tcontext=(\S+) tclass=(\S+)', line)
        if not m:
            continue
        ts, perms, pid, capid, sctx, tctx, tclass = m.groups()
        avc_rows.append({
            "t": float(ts), "perms": perms.strip(), "pid": int(pid),
            "cap": capid, "sctx": sctx, "tctx": tctx, "tclass": tclass,
        })
capu = [r for r in avc_rows if r["tclass"] == "cap_userns"]
if capu:
    print("== cap_userns denial inventory (per pid+perm, first..last) ==")
    groups = collections.OrderedDict()
    for r in capu:
        key = (r["pid"], r["perms"])
        groups.setdefault(key, []).append(r)
    for (pidv, permsv), rr in groups.items():
        first = rr[0]
        print(f"  pid={pidv} perm={permsv} count={len(rr)}"
              f" first={rr[0]['t']:.3f} last={rr[-1]['t']:.3f}"
              f" sctx={first['sctx']}")
else:
    print("cap_userns denial inventory: no rows")
prctl_rows, capset_rows = [], []
if strace.exists():
    # strace paints two shapes here: "[pid N] TS call" for -f forks in the
    # attach window and "N TS call" for the interleaved per-tid lines; the
    # PR_CAPBSET_DROP argument is a symbolic CAP_* name or a numeric bit.
    line_re = re.compile(r"^(?:\[pid +(\d+)\]|(\d+)) +([0-9:.]+) +prctl\(PR_CAPBSET_DROP, +(CAP_[A-Z0-9_]+|[0-9xXa-fA-F]+)\)\s*(?:\)\s*)?= +(-?\d+)(.*)$")
    capset_re = re.compile(r"^(?:\[pid +(\d+)\]|(\d+)) +([0-9:.]+) +capset\(")
    for line in strace.read_text(errors="replace").splitlines():
        if "PR_CAPBSET_DROP" in line:
            m = line_re.match(line)
            if m:
                pid = int(m.group(1) or m.group(2))
                prctl_rows.append((pid, m.group(4), int(m.group(5)),
                                   "EPERM" if "EPERM" in line else "",
                                   m.group(3)))
            else:
                prctl_rows.append((None, None, None, "UNPARSED " + line.strip()[:200], None))
        elif "capset(" in line:
            m = capset_re.match(line)
            pid = int(m.group(1) or m.group(2)) if m else None
            rc = re.search(r"= +(-?\d+)", line)
            capset_rows.append((pid, int(rc.group(1)) if rc else None,
                                line.strip()[:160]))
else:
    print("strace log absent (NOT evidence of absence)")

if prctl_rows:
    ok = sum(1 for r in prctl_rows if r[2] == 0)
    fail = sum(1 for r in prctl_rows if r[2] not in (0, None))
    print(f"prctl PR_CAPBSET_DROP rows: {len(prctl_rows)} rc=0 {ok} rc!=0 {fail}"
          f" first={prctl_rows[0][4]} last={prctl_rows[-1][4]}")
    for r in prctl_rows[-80:]:
        print(f"  drop pid={r[0]} cap={r[1]} rc={r[2]} {r[3]} t={r[4]}")
else:
    print("no PR_CAPBSET_DROP rows captured")
if capset_rows:
    print(f"capset rows: {len(capset_rows)} rc=0 {sum(1 for r in capset_rows if r[1] == 0)}")
    for r in capset_rows[-12:]:
        print(f"  capset pid={r[0]} rc={r[1]} {r[2]}")
else:
    print("no capset rows captured")

rows = []
transitions = []
if capwatch.exists():
    for line in capwatch.read_text(errors="replace").splitlines():
        if not line.startswith("CAPWATCH "):
            continue
        row = {}
        for tok in line.split(" ")[2:]:
            if "=" in tok:
                k, v = tok.split("=", 1)
                row[k] = v
        row["event"] = line.split(" ")[1]
        rows.append(row)
if not rows:
    print("capwatch: no rows")
else:
    firstiglie = {}
    for r in rows:
        firstiglie.setdefault(int(r["pid"]), r)
    print(f"capwatch rows: {len(rows)}; distinct pids: {len(firstiglie)}")
    runcpids = sorted(
        int(r["pid"]) for r in rows
        if r.get("comm", "").startswith("runc:"))
    print("runc-chain pids observed: %s" % ",".join(map(str, runcpids)))
    userns = sorted({r.get("nsuser", "-") for r in rows if r.get("nsuser")})
    print(f"distinct user namespaces seen: {len(userns)}")
    for u in userns[:8]:
        pids_x = sorted(dict.fromkeys(r["pid"] for r in rows if r.get("nsuser") == u))
        print(f"  ns_user={u} pids(first14)={','.join(pids_x[:14])}")
    print("== exec ladder (only pids that were ever in the runc chain; exe fully left the runc surfaces) ==")
    ever_runc = {int(r["pid"]) for r in rows if r.get("comm", "").startswith("runc:")}
    transitions = [
        r for r in rows
        if int(r["pid"]) in ever_runc
        and not r.get("comm", "").startswith("runc:")
        and "runc" not in r.get("exe", "")
    ]
    for r in transitions[-20:]:
        print(f"  {r.get('event')} pid={r['pid']} comm={r.get('comm','-')} exe={r.get('exe','-')}"
              f" ctx={r.get('ctx','-')} eff={r.get('capeff','-')} bnd={r.get('capbnd','-')}"
              f" amb={r.get('capamb','-')} inh={r.get('capinh','-')} prm={r.get('capprm','-')}")
    if transitions:
        print("workload-exec OBSERVED (the runc-chain pid now carries a non-runc exe)")
    else:
        print("workload-exec NOT-OBSERVED (no tracked pid left the runc surfaces)")
    # R7 MNB26: the FULL CapBnd from the pre-drop arrival row must not be
    # read as the post-drop snapshot: bind by time — print every row of
    # the dropping pids in order so each CapBnd state carries its own
    # event row between the DROP series timestamps.
    if prctl_rows:
        drop_p = sorted({r[0] for r in prctl_rows if r[0]})
        print(f"== CapBnd binding: rows of the dropping pids {','.join(map(str, drop_p))} (drop series {prctl_rows[0][4]}..{prctl_rows[-1][4]}) ==")
        for r in rows:
            if int(r["pid"]) in drop_p:
                print(f"  {r.get('event')} t={r.get('t')} pid={r['pid']}"
                      f" comm={r.get('comm','-')} capeff={r.get('capeff','-')}"
                      f" capbnd={r.get('capbnd','-')} nnp={r.get('nnp','-')}"
                      f" uidmap={r.get('uidmap','-')} setgroups={r.get('setgroups','-')}")

# R7 MNB25: the setgroups stage. The syscall lines come from the strace
# filter (setgroups/setgid/setregid/setresgid now traced with errno); the
# capwatch rows carry the same pids' CapEff/uid_map/gid_map/setgroups
# readback right until the stop; the OCI cross-reference closes the loop.
sg_rows = []
if strace.exists():
    # strace splits syscalls that straddle a fork ("call <unfinished ...>"
    # then "<... call resumed>) = rc"); join them before matching so the
    # measured line carries the real return code instead of an UNPARSED
    # fragment. The resumed form carries no pid, so a call joins with the
    # most recent unfinished invocation of the same call name.
    pending, joined_lines = {}, []
    for line in strace.read_text(errors="replace").splitlines():
        m_unf = re.match(
            r"^((?:\[pid +(\d+)\]|(\d+)) +[0-9:.]+ +(\S+)\(.*)<unfinished \.\.\.>\s*$", line)
        m_res = re.match(
            r"^(?:(?:\[pid +(\d+)\]|(\d+)) +[0-9:.]+ +)?<\.\.\. +(\S+) resumed>(.*=\s+-?\d+.*)?$", line)
        if m_unf:
            pid_k = m_unf.group(2) or m_unf.group(3)
            pending[(pid_k, m_unf.group(4))] = line
            continue
        if m_res:
            cand = [k for k in pending if k[1] == m_res.group(3)]
            if cand:
                prior = pending.pop(cand[-1])
                tail = m_res.group(4) or ""
                if tail.startswith(")"):
                    joined_lines.append(prior.split("<unfinished")[0].rstrip() + tail)
                else:
                    joined_lines.append(prior.split("<unfinished")[0].rstrip() + ")" + tail)
                continue
        joined_lines.append(line)
    for line in joined_lines:
        if not re.match(r"^(?:\[pid +\d+\]|\d+) +[0-9:.]+ +(setgroups|setgid|setregid|setresgid)\(", line):
            continue
        m = re.match(
            r"^(?:\[pid +(\d+)\]|(\d+)) +([0-9:.]+) +(setgroups|setgid|setregid|setresgid)\((.*)\)\s*\)?\s*= +(-?\d+)(?: +([A-Z0-9]+) \(([^)]*)\))?",
            line)
        if m:
            sg_rows.append((int(m.group(1) or m.group(2)), m.group(4), m.group(5),
                            int(m.group(6)), m.group(7) or "",
                            line.strip()[:200]))
        else:
            sg_rows.append((None, "UNPARSED", line.strip()[:200], None, "", ""))
    print("== the group/setgid stage (traced syscalls with errno) ==")
    if sg_rows:
        for r in sg_rows[-20:]:
            if r[1] == "UNPARSED":
                print(f"  UNPARSED {r[2]}")
            else:
                extra = f" errno={r[4]}" if r[3] != 0 else ""
                print(f"  {r[1]}( pid={r[0]} rc={r[3]}{extra} args=[{r[2]}]")
                print(f"    raw=`{r[5]}`")
    else:
        print("no setgroups/setgid-family syscall rows captured")
else:
    print("strace log absent (NOT evidence of absence)")

print("== distinct capability states across the runc chain (decoded) ==")
masks = {}
rows_by_mask = {}
for r in rows:
    effb, bndb = r.get("capeff", "-"), r.get("capbnd", "-")
    if effb in ("-", "") or not re.fullmatch(r"[0-9a-fA-F]{1,16}", effb or ""):
        continue
    mask = int(effb, 16)
    bnd = int(bndb, 16) if re.fullmatch(r"[0-9a-fA-F]{1,16}", bndb or "") else None
    key = (mask, bnd)
    if key not in masks:
        masks[key] = r
        rows_by_mask[key] = set()
    rows_by_mask[key].add(r["pid"])
cap_names = (
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID",
    "KILL", "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE",
    "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW",
    "IPC_LOCK", "IPC_OWNER", "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT",
    "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE",
    "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD", "LEASE",
    "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE",
    "MAC_ADMIN", "SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ",
    "PERFMON", "BPF", "CHECKPOINT_RESTORE",
)
bitname = {1 << b: n for b, n in enumerate(cap_names)}
cap_bits = {"CAP_%s" % name: bit for bit, name in enumerate(cap_names)}
spec_bits = cap_bits
for (mask, bnd) in sorted(masks):
    names = [nm for bit, nm in bitname.items() if mask & bit]
    bnames = [nm for bit, nm in bitname.items() if bnd is not None and bnd & bit]
    row = masks[(mask, bnd)]
    pids = sorted(rows_by_mask[(mask, bnd)])
    print(f"  cap_eff=0x{mask:016x} pids={','.join(pids[:10])}"
          f" first-comm={row.get('comm','-')} setgid={'PRESENT' if mask & (1 << 6) else 'ABSENT'}"
          f" eff={'+'.join(names)}"
          + (f" bnd={'+'.join(bnames)}" if bnd is not None else ""))
    print(f"    uid_map={row.get('uidmap','-')}")
    print(f"    gid_map={row.get('gidmap','-')}")
    print(f"    setgroups-file={row.get('setgroups','-')}")
    print(f"    nsuser={row.get('nsuser','-')} ctx={row.get('ctx','-')}")

# OCI capability cross-reference (from the inventory's spec block).
spec_caps = None
if inventory.exists():
    for line in inventory.read_text(errors="replace").splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("event") == "spec" and d.get("caps") is not None:
            spec_caps = d["caps"]
if spec_caps:
    print("== OCI config capabilities (from the live spec capture) ==")
    for k in ("inheritable", "permitted", "effective", "bounding", "ambient"):
        v = spec_caps.get(k)
        if not isinstance(v, list):
            print(f"  {k}: <absent-in-config>")
            continue
        mask = 0
        unresolved = []
        for entry in v:
            if isinstance(entry, int) and not isinstance(entry, bool) and 0 <= entry < 64:
                mask |= 1 << entry
            elif isinstance(entry, str) and entry in cap_bits:
                mask |= 1 << cap_bits[entry]
            elif isinstance(entry, str):
                unresolved.append(entry)
        suffix = f" unresolved={unresolved}" if unresolved else ""
        print(f"  {k}: 0x{mask:016x} ({len(v)} caps){suffix}")
        if k == "bounding" and unresolved:
            print(f"  bounding-names: {sorted(v)}")
else:
    print("OCI capability block not captured")

# R7 MNB25: workload caps vs the OCI config (measured-vs-spec).
if spec_caps and transitions:
    print("== workload caps vs OCI config (measured-vs-spec) ==")
    for r in transitions[-6:]:
        print(f"  observed pid={r['pid']} comm={r.get('comm')}")
        for field, key in (
            ("CapInh", "inheritable"), ("CapPrm", "permitted"),
            ("CapEff", "effective"), ("CapBnd", "bounding"),
            ("CapAmb", "ambient"),
        ):
            obs_raw = r.get(field.lower(), "-")
            spec_mask = 0
            for entry in spec_caps.get(key, []) or []:
                if isinstance(entry, str) and entry in spec_bits:
                    spec_mask |= 1 << spec_bits[entry]
                elif isinstance(entry, int) and not isinstance(entry, bool):
                    spec_mask |= 1 << entry
            obs_mask = int(obs_raw, 16) if re.fullmatch(r"[0-9a-fA-F]{1,16}", obs_raw or "") else None
            obs_names = [nm for bit, nm in bitname.items() if obs_mask is not None and obs_mask & bit]
            spec_names = [nm for nm, b in spec_bits.items() if spec_mask & b]
            mark = "MATCH" if obs_mask == spec_mask else "DIFF"
            print(f"    {field}: observed={('0x%016x' % obs_mask) if obs_mask is not None else '<unresolved>'} spec=0x{spec_mask:016x} {mark}"
                  f" (observed-names={'+'.join(obs_names) or 'none'}; spec-names={'+'.join(x[4:] for x in spec_names) or 'none'})")
else:
    print("workload-vs-OCI cross-reference not applicable (no exec or no OCI capture)")
PYEOF
  cat "$EVIDENCE_DIR/p21e3-capbset-evidence.log"
fi
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
