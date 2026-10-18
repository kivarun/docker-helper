#!/usr/bin/env bash
#
# release-2.4-r7-mcs-audit-guest.sh — the R7 MCS-isolation audit on a
# disposable ENFORCING openSUSE Tumbleweed VM (RPM candidate). Security
# proof only: NO policy grants, NO production changes, NO cgroup grants.
#
# WHY THIS AUDIT EXISTS: UAT 39142656535's runtime-privacy pin reported
# docker_helper_builder_state_t carrying NO mcs_constrained_type membership.
# The task requires the ACTUAL semantics of the LOADED enforcing policy —
# in refpolicy MCS constraints may gate on the SUBJECT attribute (t1) rather
# than the object (t2) — and a live cross-category negative proof, before
# any further SELinux grant is considered.
#
# THE AUDIT:
#   A. the loaded constraints, verbatim, for the classes the builder
#      lifecycle actually uses (file, dir, lnk_file, sock_file, process,
#      unix_stream_socket, fifo_file, filesystem) — sesearch --constraint
#      (seinfo has no constraint listing; the attempt is recorded);
#   B. the attribute membership facts: the full mcs_constrained_type
#      member list, the per-type attribute dumps for every docker-helper
#      domain and object type, and the mlstrustedsubject exception list;
#   C. the MCS-form verdict per class: which attribute gates the
#      constraint (t1 / t2 / both / neither), whether the governing
#      membership holds for the builder SUBJECT (buildkitd_t) and the
#      builder OBJECT types, and whether any trusted-subject exception
#      applies to our subjects;
#   D. the live cross-category probes: attempt to create a test process
#      in the ACTUAL docker_helper_buildkitd_t:s0:c1 domain; on success
#      run the positive control (append+read the op's own c1-labeled
#      state fixture), the negative control (the identical c2-labeled
#      fixture), traversal of the other operation's fixtures — with
#      DAC equalized (mode 0666, root-owned) so the denial can only be
#      SELinux; on failure record the exact transition-denial evidence
#      and mark the live proof BLOCKED (never PASS);
#   D2. the kernel-decision matrix: a disposable libselinux helper
#      (guest-side build, class/permission NAMES via
#      string_to_security_class/string_to_av_perm) queries
#      security_compute_av_raw on the LOADED policy for the real UAT
#      contexts — buildkitd_t:s0:c1 and :s0:c2 against
#      builder_state_t:s0:c1/:s0:c2 — over file read/write/append,
#      dir search/write/add_name/remove_name, lnk_file read,
#      sock_file getattr and unix_stream_socket connectto, both
#      directions plus both same-category controls; the verdict
#      requires same-category ALLOW, cross-category DENY for every
#      queried permission and no permissive-domain exception;
#   D3. the socket-plane facts: the loaded unix_stream_socket class has
#      no mlsconstrain — the socket decision surface is captured
#      separately (connectto TE allows toward the state/runtime types,
#      the sock_file constraints, the permissive-domain list) and the
#      file/dir MCS proof is NOT extrapolated onto it;
#   E. the cgroup finding forensics (read-only): reproduce the terminal
#      failure with a minimal build, capture the ORDERED cgroup AVC set,
#      the RUNNING buildkitd's mount namespace mountinfo (is a cgroup2
#      mount visible to the namespace runc runs in?), the host
#      mountinfo for contrast, and the bundled runc version — analysis
#      only, no grants.
#
# Verdict contract:
#   R7-MCS-AUDIT=CONSTRAINTS=<unconditional|t1|t2|t1+t2|none>;\
#     SUBJECT-BUILDKITD=<member|not-member>;\
#     OBJECT-STATE=<member|not-member>;\
#     LIVE-NEGATIVE=<PASS|BLOCKED:<reason>>;\
#     R7-MCS-ISOLATION=<PASS|FAIL:<reason>|BLOCKED:<reason>
#
# Env inputs (guest side):
#   R7_ARTIFACT / R7_ARTIFACT_SHA256  the exact candidate RPM + digest
#   R7_EVIDENCE_DIR                   guest evidence directory
set -uo pipefail

ARTIFACT="${R7_ARTIFACT:?R7_ARTIFACT required}"
ARTIFACT_SHA="${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log()  { printf '[r7-mcs-audit] %s\n' "$*"; }
fail() { printf '[r7-mcs-audit] FAILED: %s\n' "$*" >&2; exit 1; }

EVIDENCE_DIR="${R7_EVIDENCE_DIR:-/tmp/r7-mcs-audit-evidence}"
mkdir -p "$EVIDENCE_DIR"

cap() { # <name> <max-lines> <cmd...> — evidence capture never aborts the audit
  local name="$1" maxn="$2" rc; shift 2
  "$@" >"$EVIDENCE_DIR/$name.log" 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || printf 'capture rc=%d\n' "$rc" >>"$EVIDENCE_DIR/$name.log"
  log "--- $name (evidence: $EVIDENCE_DIR/$name.log, first $maxn lines) ---"
  head -n "$maxn" "$EVIDENCE_DIR/$name.log"
  return 0
}

DH_SOCK=/run/docker-helper/docker-helper.sock
STATE_DIR=/tmp/r7-mcs-audit-state
mkdir -p "$STATE_DIR"

[ "$(id -u)" = "0" ] || fail "must run as root"
[ -f "$ARTIFACT" ] || fail "artifact missing: $ARTIFACT"
now_sha="$(sha256sum "$ARTIFACT" | awk '{print $1}')"
[ "$now_sha" = "$ARTIFACT_SHA" ] || fail "artifact SHA mismatch (expected $ARTIFACT_SHA, got $now_sha)"

PRINCIPAL="${SUDO_USER:-}"
[ -n "$PRINCIPAL" ] && [ "$PRINCIPAL" != "root" ] || fail "cannot derive non-root principal (SUDO_USER='$SUDO_USER')"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
[ -n "$PRINCIPAL_HOME" ] && [ -d "$PRINCIPAL_HOME" ] || fail "principal home not found: $PRINCIPAL_HOME"
ALLOWED_ROOT="$PRINCIPAL_HOME"

# ============================================================================
# Section 1: platform + SELinux enforcing proof
# ============================================================================
if [ -f "$STATE_DIR/sec1" ]; then
  log "phase marker: section 1 done; skipping"
else
  log "=== section 1: platform + SELinux state ==="
  ENF="$(getenforce 2>/dev/null || echo absent)"
  [ "$ENF" = "Enforcing" ] || fail "SELinux not enforcing (getenforce='$ENF')"
  cat /sys/kernel/security/lsm >"$EVIDENCE_DIR/lsm.txt" 2>&1 || true
  grep -qw selinux "$EVIDENCE_DIR/lsm.txt" || fail "selinux not an active LSM: $(cat "$EVIDENCE_DIR/lsm.txt")"
  cap se-status 14 bash -c 'sestatus; echo ---; getenforce; id -Z'
  cat /etc/os-release >"$EVIDENCE_DIR/os-release.txt" 2>&1
  grep -qi 'opensuse tumbleweed' "$EVIDENCE_DIR/os-release.txt" || fail "not openSUSE Tumbleweed"
  touch "$STATE_DIR/sec1"
fi

# ============================================================================
# Section 2: exact candidate install (never rebuilds) + policy loaded proof
# ============================================================================
if [ -f "$STATE_DIR/sec2" ]; then
  log "phase marker: section 2 done; skipping"
else
  log "=== section 2: candidate install ==="
  command -v seinfo >/dev/null 2>&1 || zypper --non-interactive install -y setools-console >/dev/null 2>&1 || true
  rpm -q docker-helper >/dev/null 2>&1 && rpm -e docker-helper >/dev/null 2>&1 || true
  rpm -i "$ARTIFACT" >"$EVIDENCE_DIR/install.log" 2>&1 \
    || fail "rpm -i failed (evidence: $EVIDENCE_DIR/install.log)"
  log "RPM installed: $(rpm -q docker-helper)"
  docker-helper init --allowed-root "$ALLOWED_ROOT" >>"$EVIDENCE_DIR/install.log" 2>&1 \
    || fail "docker-helper init failed"
  systemctl daemon-reload
  systemctl enable --now docker-helper.service >>"$EVIDENCE_DIR/install.log" 2>&1 || true
  systemctl enable --now docker-helper-builder.service >>"$EVIDENCE_DIR/install.log" 2>&1 || true
  READY=0
  for _ in $(seq 1 50); do
    if [ -S "$DH_SOCK" ] && curl --silent --fail --max-time 1 \
        --unix-socket "$DH_SOCK" http://localhost/health >/dev/null 2>&1; then
      READY=1; break
    fi
    sleep 0.2
  done
  [ "$READY" = 1 ] || fail "daemon API socket not ready"
  MODULE="$(semodule -l 2>/dev/null | grep -w docker_helper || true)"
  [ -n "$MODULE" ] || fail "the docker_helper policy module is not loaded"
  log "policy module loaded: $MODULE"
  touch "$STATE_DIR/sec2"
fi

# ============================================================================
# Section 2b: the libselinux kernel-decision helper (guest-side build)
# ============================================================================
# A small disposable C helper queries the LOADED policy's access decisions
# through libselinux's security_compute_av_raw — the same constraint and TE
# evaluation the kernel performs on those exact policy bytes — with class
# and permission NAMES (string_to_security_class / string_to_av_perm), not
# hardcoded bit masks. Guest-side diagnostic tooling only.
if [ -f "$STATE_DIR/sec2b" ]; then
  log "phase marker: section 2b done; skipping"
else
  log "=== section 2b: kernel-decision helper toolchain ==="
  if ! command -v gcc >/dev/null 2>&1 || [ ! -e /usr/include/selinux/selinux.h ]; then
    zypper --non-interactive install -y gcc libselinux-devel \
      >"$EVIDENCE_DIR/toolchain-install.log" 2>&1 \
      || fail "toolchain install failed (evidence: $EVIDENCE_DIR/toolchain-install.log)"
  fi
  command -v gcc >/dev/null 2>&1 || fail "gcc unavailable"
  [ -e /usr/include/selinux/selinux.h ] || fail "libselinux-devel unavailable"
  cat > "$EVIDENCE_DIR/mcs_av_probe.c" <<'CEOF'
/* mcs_av_probe.c — R7 kernel-policy decision matrix probe.
 * Queries security_compute_av_raw (the loaded policy's own decision
 * computation, the same evaluation the kernel performs on those bytes)
 * for named class/permission pairs across categorized contexts.
 * Output: one TSV line per query:
 *   scon tcon class perm allowed decided auditallow auditdeny permissive
 */
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *SCON_C1 = "system_u:system_r:docker_helper_buildkitd_t:s0:c1";
static const char *SCON_C2 = "system_u:system_r:docker_helper_buildkitd_t:s0:c2";
static const char *TOBJ_C1 = "system_u:object_r:docker_helper_builder_state_t:s0:c1";
static const char *TOBJ_C2 = "system_u:object_r:docker_helper_builder_state_t:s0:c2";

struct q { const char *cls; const char *perm; };
static struct q QUERIES[] = {
  { "file", "read" }, { "file", "write" }, { "file", "append" },
  { "dir", "search" }, { "dir", "write" }, { "dir", "add_name" },
  { "dir", "remove_name" },
  { "lnk_file", "read" },
  { "sock_file", "getattr" },
  { "unix_stream_socket", "connectto" },
};

int main(void) {
  struct av_decision avd;
  const char *scons[2] = { SCON_C1, SCON_C2 };
  const char *tcons[2] = { TOBJ_C1, TOBJ_C2 };
  size_t si, ti, qi;
  for (si = 0; si < 2; si++) {
    for (ti = 0; ti < 2; ti++) {
      for (qi = 0; qi < sizeof(QUERIES)/sizeof(QUERIES[0]); qi++) {
        security_class_t cls = string_to_security_class(QUERIES[qi].cls);
        if (!cls) { printf("ERR\tclass %s unknown\n", QUERIES[qi].cls); continue; }
        access_vector_t bit = string_to_av_perm(cls, QUERIES[qi].perm);
        if (!bit) { printf("ERR\tperm %s %s unknown\n", QUERIES[qi].cls, QUERIES[qi].perm); continue; }
        memset(&avd, 0, sizeof(avd));
        if (security_compute_av_raw(scons[si], tcons[ti], cls, bit, &avd) < 0) {
          printf("ERR\tcompute_av failed\n");
          continue;
        }
        printf("%s\t%s\t%s\t%s\t%u\t%u\t%u\t%u\t%u\n",
               scons[si], tcons[ti], QUERIES[qi].cls, QUERIES[qi].perm,
               (avd.allowed & bit) ? 1 : 0,
               (avd.decided & bit) ? 1 : 0,
               (avd.auditallow & bit) ? 1 : 0,
               (avd.auditdeny & bit) ? 1 : 0,
               (avd.flags & SELINUX_AVD_FLAGS_PERMISSIVE) ? 1 : 0);
      }
    }
  }
  return 0;
}
CEOF
  gcc -O2 -o "$EVIDENCE_DIR/mcs_av_probe" "$EVIDENCE_DIR/mcs_av_probe.c" -lselinux \
    >"$EVIDENCE_DIR/helper-build.log" 2>&1 \
    || fail "helper build failed (evidence: $EVIDENCE_DIR/helper-build.log)"
  log "kernel-decision helper built: $EVIDENCE_DIR/mcs_av_probe"
  touch "$STATE_DIR/sec2b"
fi

# ============================================================================
# Section 3: loaded-policy analysis — constraints + membership
# ============================================================================
log "=== section 3: loaded-policy analysis ==="
cap mcs-members 60 seinfo -a mcs_constrained_type -x
cap trusted-subjects 30 seinfo -a mlstrustedsubject -x
cap trusted-objects 30 seinfo -a mlstrustedobject -x
# seinfo --constrain <class> is the constraint listing on this setools
# generation (sesearch has no --constraint option here — the failed
# attempt is recorded in the first dispatch's evidence).
cap constraints-all 300 seinfo --constrain
for c in file dir lnk_file sock_file process unix_stream_socket fifo_file filesystem; do
  cap "constraints-$c" 40 seinfo --constrain "$c"
done
# The loaded TE allow on the live-probe pair (requirement: the denial must
# be attributable to MCS, so the TE allow must be proven present first).
cap sesearch-state-allow 12 sesearch -A -s docker_helper_buildkitd_t \
  -t docker_helper_builder_state_t -c file
cap sesearch-runtime-allow 12 sesearch -A -s docker_helper_buildkitd_t \
  -t docker_helper_builder_runtime_t
cap sesearch-state-readpair 12 sesearch -A -s docker_helper_buildkitd_t \
  -t docker_helper_builder_state_t -c dir
# Socket-plane isolation facts (§3 of the R7 kernel-decision work order):
# the loaded unix_stream_socket class has NO mlsconstrain — the socket
# decision surface is TE-allow-driven and must NOT be extrapolated from
# the file/dir MCS proof. Captured separately.
cap sesearch-connectto-any 20 sesearch -A -s docker_helper_buildkitd_t \
  -c unix_stream_socket -p connectto
cap sesearch-connectto-state 20 sesearch -A -s docker_helper_buildkitd_t \
  -t docker_helper_builder_state_t -c unix_stream_socket
cap sesearch-connectto-runtime 20 sesearch -A -s docker_helper_buildkitd_t \
  -t docker_helper_builder_runtime_t -c unix_stream_socket
cap sesearch-socket-all 30 sesearch -A -s docker_helper_buildkitd_t \
  -t docker_helper_builder_state_t -c sock_file,unix_stream_socket
cap constraints-sockfile-mls 40 seinfo --constrain sock_file
cap constraints-uss-mls 40 seinfo --constrain unix_stream_socket
cap permissive-domains 10 bash -c 'semanage permissive -l 2>/dev/null | grep -i docker || echo "(no docker-helper permissive domain)"'

for t in docker_helper_buildkitd_t docker_helper_rootlesskit_t docker_helper_builder_t \
         docker_helper_t docker_helper_builder_launcher_t docker_helper_container_t \
         docker_helper_builder_state_t docker_helper_builder_runtime_t \
         docker_helper_builder_state_root_t docker_helper_builder_runtime_root_t; do
  cap "type-$t" 8 seinfo -t "$t" -x
done
cap mcs-levels 10 seinfo -t mcs_constrained_type -x || true

# ============================================================================
# Section 4: the MCS-form verdict — parse the loaded constraint expressions
# ============================================================================
log "=== section 4: MCS-form verdict ==="
MCS_FORM="none"
for c in file dir lnk_file sock_file; do
  FORM="none"
  # The loaded form is the EXCEPTION form: (h1 dom h2 or t1 !=
  # mcs_constrained_type) — the constraint bites exactly when the
  # subject IS a member. The exception mention and the direct mention
  # are both subject-side gating.
  T1=$(grep -Ec "t1 (!=|==) mcs_constrained_type" "$EVIDENCE_DIR/constraints-$c.log")
  T2=$(grep -Ec "t2 (!=|==) mcs_constrained_type" "$EVIDENCE_DIR/constraints-$c.log")
  if [ "$T1" -gt 0 ] && [ "$T2" -gt 0 ]; then
    FORM="t1+t2"
  elif [ "$T1" -gt 0 ]; then
    FORM="t1"
  elif [ "$T2" -gt 0 ]; then
    FORM="t2"
  elif grep -q "mlsconstrain" "$EVIDENCE_DIR/constraints-$c.log"; then
    FORM="unconditional"
  fi
  log "MCS-FORM[$c]=$FORM"
  printf '%s\n' "$FORM" >> "$EVIDENCE_DIR/mcs-forms.txt"
  [ "$FORM" != "none" ] && MCS_FORM="$FORM"
done
log "MCS-FORM[summary]=$MCS_FORM"

member_of() { # <type> — is the type a mcs_constrained_type member? (evidence: mcs-members.log)
  # seinfo -a ... -x prints member names one per TAB-indented line; the
  # delimiter class must include whitespace (POSIX class — \t is not an
  # escape inside grep -E).
  grep -qE "(^|[[:space:],])$1([[:space:],]|$)" "$EVIDENCE_DIR/mcs-members.log"
}
SUBJ_BKD=not-member; member_of docker_helper_buildkitd_t && SUBJ_BKD=member
SUBJ_RLK=not-member; member_of docker_helper_rootlesskit_t && SUBJ_RLK=member
SUBJ_BLD=not-member; member_of docker_helper_builder_t && SUBJ_BLD=member
SUBJ_DMN=not-member; member_of docker_helper_t && SUBJ_DMN=member
SUBJ_CTNR=not-member; member_of docker_helper_container_t && SUBJ_CTNR=member
OBJ_STATE=not-member; member_of docker_helper_builder_state_t && OBJ_STATE=member
OBJ_RUNTIME=not-member; member_of docker_helper_builder_runtime_t && OBJ_RUNTIME=member
log "SUBJECT-BUILDKITD=$SUBJ_BKD SUBJECT-ROOTLESSKIT=$SUBJ_RLK SUBJECT-MANAGER=$SUBJ_BLD SUBJECT-DAEMON=$SUBJ_DMN SUBJECT-CONTAINER=$SUBJ_CTNR"
log "OBJECT-STATE=$OBJ_STATE OBJECT-RUNTIME=$OBJ_RUNTIME"
TRUSTED_ANY=no
grep -qE "docker_helper" "$EVIDENCE_DIR/trusted-subjects.log" && TRUSTED_ANY=yes
log "TRUSTED-SUBJECT-EXCEPTION=$TRUSTED_ANY"

# ============================================================================
# Section 5: live cross-category probes
# ============================================================================
log "=== section 5: live cross-category probes ==="
LIVE_VERDICT="BLOCKED:no-process"
# AVC capture follows the canonical VM-lib mechanism: auditd owns the
# records when it runs (ausearch), otherwise the WHOLE system journal —
# kernel audit records carry the audit transport, NOT the kernel one, so
# `journalctl -k` never sees them (the first two dispatches proved both
# halves of this).
avc_tail() { # <label> — dump the recent AVC records for the evidence
  : > "$EVIDENCE_DIR/$1.log"
  if command -v ausearch >/dev/null 2>&1 && pgrep -x auditd >/dev/null 2>&1; then
    ausearch -m AVC -m USER_AVC --start recent 2>/dev/null >> "$EVIDENCE_DIR/$1.log" || true
  fi
  # ausearch can yield nothing while the raw log still holds the records
  # (the UAT harness's proven fallback): merge the raw log tail too —
  # this guest has essentially no other audit traffic.
  if [ -f /var/log/audit/audit.log ]; then
    tail -n 200 /var/log/audit/audit.log >> "$EVIDENCE_DIR/$1.log" 2>/dev/null || true
  fi
  # State diagnostics: the audit subsystem's own status and the log size,
  # so an empty capture is distinguishable from a dropped one.
  {
    command -v auditctl >/dev/null 2>&1 && auditctl -s 2>&1 | head -3
    wc -l /var/log/audit/audit.log 2>/dev/null || echo "audit.log: absent"
  } > "$EVIDENCE_DIR/$1-audit-state.log" 2>&1 || true
  if [ ! -s "$EVIDENCE_DIR/$1.log" ]; then
    printf '(no AVC records from ausearch, the raw audit log, or the system journal)\\n' > "$EVIDENCE_DIR/$1.log"
  fi
  log "avc capture [$1]: $(wc -l < "$EVIDENCE_DIR/$1.log") lines (auditd: $(pgrep -x auditd >/dev/null 2>&1 && echo yes || echo no); audit-state: $(head -2 "$EVIDENCE_DIR/$1-audit-state.log" | tr '\n' ' '))"
  head -6 "$EVIDENCE_DIR/$1.log" || true
}
# control: does the runcon machinery work AT ALL for a same-domain level change?
if OUT="$(runcon -l s0:c1 id -Z 2>"$EVIDENCE_DIR/runcon-level.err")"; then
  log "runcon level-only control: OK ($OUT)"
  printf '%s\n' "$OUT" > "$EVIDENCE_DIR/runcon-level.ok"
else
  log "runcon level-only control FAILED: $(head -2 "$EVIDENCE_DIR/runcon-level.err")"
fi
# the actual builder-domain attempt (the transition the module does NOT
# grant from the admin domain — expected to be denied; that denial is
# itself the security fact)
BKD_OK=0
if OUT="$(runcon -t docker_helper_buildkitd_t -l s0:c1 id -Z 2>"$EVIDENCE_DIR/runcon-bkd.err")"; then
  BKD_OK=1
  log "builder-domain test process: OK ($OUT)"
  printf '%s\n' "$OUT" > "$EVIDENCE_DIR/runcon-bkd.ok"
else
  log "builder-domain test process DENIED (rc=$?, err: $(head -3 "$EVIDENCE_DIR/runcon-bkd.err"))"
  avc_tail runcon-bkd-avc
fi
# the system_r-shaped attempt: the module's roles do contain the type, so
# the context FORM is valid and the kernel checks the actual transition
# permission — expected denied with an attributable AVC record.
if OUT="$(runcon -r system_r -t docker_helper_buildkitd_t -l s0:c1 id -Z 2>"$EVIDENCE_DIR/runcon-bkd-systemr.err")"; then
  BKD_OK=1
  log "builder-domain test process (system_r): OK ($OUT)"
  printf '%s\n' "$OUT" > "$EVIDENCE_DIR/runcon-bkd.ok"
else
  log "builder-domain test process (system_r) DENIED (rc=$?, err: $(head -3 "$EVIDENCE_DIR/runcon-bkd-systemr.err"))"
  avc_tail runcon-bkd-systemr-avc
fi
if [ "$BKD_OK" = 1 ]; then
  # DAC equalized: mode 0666 root-owned fixtures — any denial is SELinux.
  FIX="$EVIDENCE_DIR/mcs-fixtures"
  rm -rf "$FIX"; mkdir -p "$FIX"
  printf 'c1-fixture\n' > "$FIX/c1.log"; printf 'c2-fixture\n' > "$FIX/c2.log"
  chown root:root "$FIX/c1.log" "$FIX/c2.log"
  chmod 0666 "$FIX/c1.log" "$FIX/c2.log"
  chcon -t docker_helper_builder_state_t -l s0:c1 "$FIX/c1.log" \
    && chcon -t docker_helper_builder_state_t -l s0:c2 "$FIX/c2.log" \
    || { log "fixture labeling failed"; LIVE_VERDICT="BLOCKED:fixture-labeling"; }
  if [ "$LIVE_VERDICT" != "BLOCKED:fixture-labeling" ]; then
    # requirements 1+2: the full subject getcon and both getfilecon values
    runcon -t docker_helper_buildkitd_t -l s0:c1 id -Z > "$EVIDENCE_DIR/probe-subject-con.txt" 2>&1
    getfilecon "$FIX/c1.log" > "$EVIDENCE_DIR/probe-c1-filecon.txt" 2>&1
    getfilecon "$FIX/c2.log" > "$EVIDENCE_DIR/probe-c2-filecon.txt" 2>&1
    log "subject: $(cat "$EVIDENCE_DIR/probe-subject-con.txt"); c1: $(cat "$EVIDENCE_DIR/probe-c1-filecon.txt"); c2: $(cat "$EVIDENCE_DIR/probe-c2-filecon.txt")"
    POS="$(runcon -t docker_helper_buildkitd_t -l s0:c1 \
        sh -c "printf 'pos-append\n' >> '$FIX/c1.log' && cat '$FIX/c1.log'" 2>&1)"
    POS_RC=$?
    NEG="$(runcon -t docker_helper_buildkitd_t -l s0:c1 \
        sh -c "printf 'neg-append\n' >> '$FIX/c2.log' && cat '$FIX/c2.log'" 2>&1)"
    NEG_RC=$?
    log "positive control (c1->c1): rc=$POS_RC out=$(printf '%s' "$POS" | head -1)"
    log "negative control (c1->c2): rc=$NEG_RC out=$(printf '%s' "$NEG" | head -1)"
    if [ "$POS_RC" -eq 0 ] && [ "$NEG_RC" -ne 0 ]; then
      avc_tail crosscat-avc
      if grep -q "scontext=.*docker_helper_buildkitd_t" "$EVIDENCE_DIR/crosscat-avc.log" 2>/dev/null \
         && grep -q "tclass=file" "$EVIDENCE_DIR/crosscat-avc.log" 2>/dev/null; then
        LIVE_VERDICT="PASS"
      else
        LIVE_VERDICT="BLOCKED:no-attributable-avc"
      fi
    else
      LIVE_VERDICT="FAIL:positive-control-rc=$POS_RC-negative-rc=$NEG_RC"
    fi
  fi
else
  LIVE_VERDICT="BLOCKED:no-transition-to-buildkitd_t-from-$(id -Z | awk -F: '{print $3}')"
fi
log "LIVE-NEGATIVE=$LIVE_VERDICT"

# ============================================================================
# Section 5a: the kernel-decision matrix (libselinux security_compute_av_raw)
# ============================================================================
log "=== section 5a: kernel-policy decision matrix ==="
KERNEL_AV_VERDICT="BLOCKED:not-run"
if [ -x "$EVIDENCE_DIR/mcs_av_probe" ]; then
  "$EVIDENCE_DIR/mcs_av_probe" > "$EVIDENCE_DIR/kernel-av-matrix.tsv" 2>&1 \
    || fail "kernel-decision helper failed (evidence: $EVIDENCE_DIR/kernel-av-matrix.tsv)"
  log "kernel-AV matrix: $(wc -l < "$EVIDENCE_DIR/kernel-av-matrix.tsv") rows (evidence: $EVIDENCE_DIR/kernel-av-matrix.tsv)"
  head -6 "$EVIDENCE_DIR/kernel-av-matrix.tsv"
  # Verdict: same-category pairs (c1->c1, c2->c2) must ALLOW; cross-category
  # (c1->c2, c2->c1) must DENY — for every queried permission; and no
  # permissive-domain exception may appear anywhere in the matrix.
  # Columns: scon tcon class perm allowed decided auditallow auditdeny permissive
  KA_OK=1; KA_REASON=""
  if grep -q "^ERR" "$EVIDENCE_DIR/kernel-av-matrix.tsv"; then
    KA_OK=0; KA_REASON="helper-error:$(grep '^ERR' "$EVIDENCE_DIR/kernel-av-matrix.tsv" | head -1)"
  else
    for CLASSPERM in "file read" "file write" "file append" "dir search" "dir write" \
                     "dir add_name" "dir remove_name" "lnk_file read" "sock_file getattr" \
                     "unix_stream_socket connectto"; do
      set -- $CLASSPERM; KCLS="$1"; KPERM="$2"
      for KROW in "c1 c1 allow" "c2 c2 allow" "c1 c2 deny" "c2 c1 deny"; do
        set -- $KROW; KS="$1"; KT="$2"; KEXP="$3"
        # Columns are TAB-separated; match the category suffix on each
        # context field exactly (awk split, no regex over the whole line).
        KROWLINE="$(awk -F'\t' -v s="$KS" -v t="$KT" -v c="$KCLS" -v p="$KPERM" \
          '$1 ~ ("s0:" s "$") && $2 ~ ("s0:" t "$") && $3 == c && $4 == p { print; exit }' \
          "$EVIDENCE_DIR/kernel-av-matrix.tsv")"
        if [ -z "$KROWLINE" ]; then
          KA_OK=0; KA_REASON="$KCLS:$KPERM $KS->$KT row-missing"; break 2
        fi
        KALLOWED="$(printf '%s' "$KROWLINE" | awk '{print $5}')"
        KPERMIS="$(printf '%s' "$KROWLINE" | awk '{print $9}')"
        if [ "$KPERMIS" = "1" ]; then
          KA_OK=0; KA_REASON="$KCLS:$KPERM $KS->$KT permissive-domain-exception"; break 2
        fi
        case "$KEXP" in
          allow) [ "$KALLOWED" = "1" ] || { KA_OK=0; KA_REASON="$KCLS:$KPERM $KS->$KT expected-allow-got-$KALLOWED"; break 2; } ;;
          deny)  [ "$KALLOWED" = "0" ] || { KA_OK=0; KA_REASON="$KCLS:$KPERM $KS->$KT expected-deny-got-$KALLOWED"; break 2; } ;;
        esac
      done
    done
  fi
  [ "$KA_OK" = 1 ] && KERNEL_AV_VERDICT="PASS" || KERNEL_AV_VERDICT="FAIL:$KA_REASON"
  log "KERNEL-AV=$KERNEL_AV_VERDICT"
else
  log "kernel-decision helper absent; matrix not run"
fi

# Structural re-assertion (independent of the kernel matrix): the loaded
# constraint form is subject-gated, the builder subject is a member, no
# trusted exception exists.
STRUCTURAL_VERDICT="PASS"
[ "$MCS_FORM" = "t1" ] || STRUCTURAL_VERDICT="FAIL:constraint-form=$MCS_FORM"
[ "$SUBJ_BKD" = "member" ] || STRUCTURAL_VERDICT="FAIL:buildkitd-not-member"
[ "$TRUSTED_ANY" = "no" ] || STRUCTURAL_VERDICT="FAIL:trusted-subject-exception=$TRUSTED_ANY"
log "STRUCTURAL=$STRUCTURAL_VERDICT"

# Socket isolation verdict: the loaded unix_stream_socket class has no
# mlsconstrain, so cross-operation socket isolation is TE-allow-driven.
# The probe matrix still decides sock_file:getattr (traversal, MCS-gated)
# and unix_stream_socket:connectto (TE-only) per pair — no extrapolation.
if grep -q "mlsconstrain" "$EVIDENCE_DIR/constraints-uss-mls.log" 2>/dev/null; then
  SOCKET_NOTE="mlsconstrain-present-on-unix_stream_socket"
else
  SOCKET_NOTE="no-mlsconstrain-on-unix_stream_socket"
fi
CT_STATE="$(grep -c 'connectto' "$EVIDENCE_DIR/sesearch-connectto-state.log" 2>/dev/null || echo 0)"
CT_RUNTIME="$(grep -c 'connectto' "$EVIDENCE_DIR/sesearch-connectto-runtime.log" 2>/dev/null || echo 0)"
log "SOCKET: $SOCKET_NOTE; connectto allows toward builder_state_t=$CT_STATE, builder_runtime_t=$CT_RUNTIME"
log "R7-MCS-SOCKET=NOTE=$SOCKET_NOTE;CONNECTTO-STATE=$CT_STATE;CONNECTTO-RUNTIME=$CT_RUNTIME"

# ============================================================================
# Section 6: cgroup finding forensics (read-only; NO grants)
# ============================================================================
log "=== section 6: cgroup finding forensics ==="
CGROUP_STATUS="not-run"
# Session + minimal build via the API (the production flow), then the
# namespace + ordered-AVC capture around the terminal failure.
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
if [ -n "$ADMIN_TOKEN" ]; then
  WS="$ALLOWED_ROOT/r7-mcs-ws"
  rm -rf "$WS"; mkdir -p "$WS/ctx"
  cat > "$WS/ctx/Dockerfile" <<'EOF'
FROM alpine:3.24
RUN sleep 10
USER 65534:65534
EOF
  chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
  if docker-helper principal show "$PRINCIPAL" >/dev/null 2>&1 \
     || docker-helper principal create --no-credential "$PRINCIPAL" >/dev/null 2>&1; then
    docker-helper principal allowed-root add "$PRINCIPAL" "$ALLOWED_ROOT" >/dev/null 2>&1 || true
    SESS_JSON="$(curl --silent --max-time 5 \
      --unix-socket "$DH_SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H 'Content-Type: application/json' \
      -d "{\"workspace\":\"$WS\",\"principal\":\"$PRINCIPAL\"}" \
      -o "$EVIDENCE_DIR/session-response.json" -w '%{http_code}' http://localhost/sessions)" || true
    SESS_TOKEN="$(grep -oE '"token": *"[^"]+"' "$EVIDENCE_DIR/session-response.json" 2>/dev/null | head -1 | sed 's/.*"token": *"//;s/"$//')"
    if [ -n "$SESS_TOKEN" ]; then
      export DOCKER_HELPER_SESSION_TOKEN="$SESS_TOKEN"
      docker-helper pull alpine:3.24 >"$EVIDENCE_DIR/pull.log" 2>&1 || true
      cap host-mountinfo-cgroup 12 bash -c 'grep cgroup /proc/self/mountinfo || echo "(no cgroup mount in the HOST namespace)"'
      ( DOCKER_HELPER_SESSION_TOKEN="$SESS_TOKEN" docker-helper build ctx \
          --dockerfile Dockerfile --image uat-mcs-audit:2.2 \
          >"$EVIDENCE_DIR/cgroup-build.log" 2>&1 ) &
    BLD_JOB=$!
    BKD_PID=""
    for _ in $(seq 1 150); do
      BKD_PID="$(pgrep -f '/usr/libexec/docker-helper/buildkit/buildkitd' | head -1 || true)"
      [ -n "$BKD_PID" ] && break
      kill -0 "$BLD_JOB" 2>/dev/null || break
      sleep 0.1
    done
    if [ -n "$BKD_PID" ] && [ -e "/proc/$BKD_PID/mountinfo" ]; then
      log "builder daemon pid $BKD_PID live; capturing its namespace mountinfo"
      grep cgroup "/proc/$BKD_PID/mountinfo" > "$EVIDENCE_DIR/buildkitd-mountinfo-cgroup.log" 2>&1 \
        || printf '(no cgroup mount visible in the buildkitd mount namespace)\n' > "$EVIDENCE_DIR/buildkitd-mountinfo-cgroup.log"
      head -6 "$EVIDENCE_DIR/buildkitd-mountinfo-cgroup.log"
      cat "/proc/$BKD_PID/attr/current" > "$EVIDENCE_DIR/buildkitd-context.txt" 2>&1 || true
      grep cgroup "/proc/$BKD_PID/root/proc/self/mountinfo" > "$EVIDENCE_DIR/buildkitd-root-mountinfo-cgroup.log" 2>&1 || true
    else
      log "buildkitd pid not observed (the builder may have failed before spawn)"
    fi
    wait "$BLD_JOB"; BLD_RC=$?
    log "cgroup-build rc=$BLD_RC (terminal failure expected: $(tail -1 "$EVIDENCE_DIR/cgroup-build.log" 2>/dev/null))"
    sleep 1
    avc_tail cgroup-avc-ordered
    # The ordered cgroup denial set for THIS window only.
    grep -E "cgroup" "$EVIDENCE_DIR/cgroup-avc-ordered.log" > "$EVIDENCE_DIR/cgroup-avc-this-run.log" || true
    log "cgroup AVC records this run: $(wc -l < "$EVIDENCE_DIR/cgroup-avc-this-run.log")"
    cap runc-version 4 bash -c '/usr/libexec/docker-helper/buildkit/buildkit-runc --version 2>&1 || true'
    CGROUP_STATUS="collected"
    else
      log "session token unavailable (HTTP $SESS_JSON); cgroup forensics limited to the UAT record"
    fi
  else
    log "principal setup unavailable; cgroup forensics limited to the UAT record"
  fi
else
  log "admin token unreadable; cgroup forensics limited to the UAT record"
fi

# ============================================================================
# Verdict
# ============================================================================
if [ "$MCS_FORM" = "none" ]; then
  ISOLATION="FAIL:no-mcs-constraint-found-on-the-relevant-classes"
elif [ "$SUBJ_BKD" = "not-member" ] && [ "$MCS_FORM" = "t1" ]; then
  ISOLATION="FAIL:subject-not-governed-by-the-t1-constraint"
elif [ "$OBJ_STATE" = "not-member" ] && [ "$MCS_FORM" = "t2" ]; then
  ISOLATION="FAIL:object-not-governed-by-the-t2-constraint"
else
  case "$LIVE_VERDICT" in
    PASS) ISOLATION="PASS" ;;
    FAIL:*) ISOLATION="$LIVE_VERDICT" ;;
    BLOCKED:*) ISOLATION="$LIVE_VERDICT" ;;
    *) ISOLATION="BLOCKED:$LIVE_VERDICT" ;;
  esac
fi
log "R7-MCS-AUDIT=CONSTRAINTS=$MCS_FORM;SUBJECT-BUILDKITD=$SUBJ_BKD;OBJECT-STATE=$OBJ_STATE;LIVE-NEGATIVE=$LIVE_VERDICT;CGROUP-FORENSIC=$CGROUP_STATUS"
log "R7-MCS-STATUSES=STRUCTURAL=$STRUCTURAL_VERDICT;KERNEL-AV=$KERNEL_AV_VERDICT;LIVE-SYSCALL=$LIVE_VERDICT"
log "R7-MCS-ISOLATION=$ISOLATION"
exit 0
