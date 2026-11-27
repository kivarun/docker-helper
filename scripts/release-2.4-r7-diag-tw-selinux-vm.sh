#!/usr/bin/env bash
#
# release-2.4-r7-diag-tw-selinux-vm.sh — R7 full-gate corrective diagnosis on
# a disposable ENFORCING openSUSE Tumbleweed VM (RPM candidate). Proves the
# R7-A buildctl execution defect and the builder-chain AVC staircase on the
# exact candidate bytes (R7-C/R7-D evidence), without touching any release
# artifact ownership: the candidate set is consumed exactly as the failed
# full gate produced it.
#
# Reuses the canonical VM machinery (scripts/uat-vm-tumbleweed.sh) and the
# shared SELinux host construction (scripts/uat-vm-opensuse-selinux-lib.sh) —
# no second harness, no second SELinux bootstrap.
#
# Env inputs (host side):
#   UAT_REPO_DIR        host checkout (default: repo root)
#   UAT_RPM             host path to the exact candidate RPM
#   UAT_RPM_SHA256      expected SHA-256 of that RPM
#   R7_DIAG_EVIDENCE_DIR  host evidence directory (default under /tmp)
#   R7_MODE             diag (default) = the R7 red/green diagnosis;
#                       mcs-audit = the R7 MCS-isolation audit (the loaded
#                       policy's constraint semantics + membership + the
#                       live cross-category probe attempt + the cgroup
#                       forensics; NO grants, NO production changes)
#                       p21e = the R7 P21-E OBL-8 live config.json capture
#                       (read-only inotify specimen poller over the
#                       production executor bundles; NO grants, NO
#                       production changes)
#                       p21e3 = the R7 P21-E-R4-P3-P3 first enforcing
#                       wrapper integration measurement (one bounded build
#                       with strace + /proc/context sampling + a pinned
#                       audit window; NO grants, NO policy changes)

set -Eeuo pipefail

PREFIX='[release-2.4-r7-diag-tw-selinux-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${R7_DIAG_EVIDENCE_DIR:-/tmp/release-2.4-r7-diag-selinux-evidence}"
GUEST_EVIDENCE_DIR='/tmp/r7-diag-evidence'
R7_MODE="${R7_MODE:-diag}"
case "$R7_MODE" in
  diag) GUEST_SCRIPT='release-2.4-r7-diag-guest.sh' ;;
  mcs-audit) GUEST_SCRIPT='release-2.4-r7-mcs-audit-guest.sh' ;;
  exeseal) GUEST_SCRIPT='release-2.4-r7-exeseal-guest.sh' ;;
  bprime) GUEST_SCRIPT='release-2.4-r7-bprime-guest.sh' ;;
  p21a) GUEST_SCRIPT='release-2.4-r7-p21a-guest.sh' ;;
  p21b) GUEST_SCRIPT='release-2.4-r7-p21b-guest.sh' ;;
  p21c) GUEST_SCRIPT='release-2.4-r7-p21c-guest.sh' ;;
  p21d) GUEST_SCRIPT='release-2.4-r7-p21d-guest.sh' ;;
  p21e) GUEST_SCRIPT='release-2.4-r7-p21e-guest.sh' ;;
  p21e3) GUEST_SCRIPT='release-2.4-r7-p21e3-guest.sh' ;;
  # p21e3probe = the SAME p21e3 guest script in its read-only baseline probe
  # branch (no diag module, no build, no session); no extra script file.
  p21e3probe) GUEST_SCRIPT='release-2.4-r7-p21e3-guest.sh' ;;
  # p21e3proc-sys = the SAME p21e3 guest script in its read-only /proc/sys
  # preflight branch (no diag module, no build, no session). Reads genfscon
  # from the loaded policy and the /proc/sys mountinfo view.
  p21e3proc-sys) GUEST_SCRIPT='release-2.4-r7-p21e3-guest.sh' ;;
  # p21e3proc-file = the SAME p21e3 guest script in its read-only /proc/sysrq-trigger
  # preflight branch (no diag module, no build; metadata-only coverage capture).
  p21e3proc-file) GUEST_SCRIPT='release-2.4-r7-p21e3-guest.sh' ;;
  # p21e3proc-keys = the SAME p21e3 guest script in its read-only /proc/keys
  # dedicated-type policy/label analysis branch (no diag module, no build,
  # no relabel; metadata + loaded-policy queries only).
  p21e3proc-keys) GUEST_SCRIPT='release-2.4-r7-p21e3-guest.sh' ;;
  # p21e3diag-keys = the SAME p21e3 guest script in its MNB22 measurement
  # branch: the seven reviewed rows PLUS the temporary dedicated-type CIL
  # module (proc_keys_t:file getattr and mounton, proc_timer_list_t:file
  # getattr and mounton), one bounded enforcing build with OCI path
  # inventory, then verified unload.
  p21e3diag-keys) GUEST_SCRIPT='release-2.4-r7-p21e3-guest.sh' ;;
  # mnb30 = the FIRST TRACER-FREE transition round (the same p21e3 guest
  # script, MNB30 branch): NO ptrace at any boundary — the /proc sampler
  # and the audit window are the instruments. Hard preflight gates: the
  # candidate RPM's runtime member extracted and byte-pinned, the four
  # loader checks plus the create probe on the EXTRACTED binary, and the
  # seinfo --role_types workload roletype calibration. The measured build
  # runs under the temporary three-rule capability module only (MNB24/26/27
  # grants, unload verified at the teardown); the transition verdict comes
  # from the live sampler contexts (composed workload domain + MCS
  # category, Cap*, NoNewPrivs) and the libselinux kernel-decision matrix
  # over the observed categories, including the cross-operation rootfs
  # denial.
  mnb30) GUEST_SCRIPT='release-2.4-r7-p21e3-guest.sh' ;;
  # mnb32 = the MNB32 policy-breadth and syscall-boundary review (the same
  # p21e3 guest script, MNB32 branch): the MNB30 pin preflight rides along
  # unchanged (artifact identity), and the round adds the S1 bin_t scope
  # inventory, the P5 proc_t label/mode/DAC inventory, the extended
  # kernel-decision matrix (lock/ioctl/setattr/mmap rows, own+cross), a
  # temporary dedicated-rolecheck-type demonstration module (load, matrix,
  # verified unload), and one bounded build under the MNB31 Tier-A rows
  # MINUS the proc_t read/open rows (the P5 counterfactual) with a static
  # guest-compiled syscall-ladder probe run as the composed workload.
  # No permanent policy change, no relabel, no permissive domain.
  mnb32) GUEST_SCRIPT='release-2.4-r7-p21e3-guest.sh' ;;
  # mnb33 = the R7 MNB33 W7-stdout/stderr-channel round (the same p21e3
  # guest script, MNB33 branch): the unchanged MNB30/MNB32 pin preflight,
  # the measured diagnostic permission set (the MNB31 Tier-A rows WITH the
  # load-bearing P5 proc read/open pair), plus EXACTLY the proposed W7
  # FIFO permissions loaded as a separate, named diagnostic module
  # (docker_helper_diag_w7: workload_t -> buildkitd_t:fifo_file
  # { read write }). The positive test runs a real producing RUN step whose
  # stdout and stderr carry distinct known tokens; the harness FAILS if
  # either token is missing from the operation event stream; the image
  # export must complete. The isolation test queries the kernel decisions
  # for workload c1 against buildkitd FIFO objects in c1 and c2 with the
  # loaded fifo_file constraint captured verbatim; the cross fd-use probe
  #   is attempted only through existing channels and is recorded as a GAP
  # when no channel exists. Unload-verified, policy-sha closure recorded.
  mnb33) GUEST_SCRIPT='release-2.4-r7-p21e3-guest.sh' ;;
  # mnb36 = the R7 MNB36 live CIL constraint-integration gate (the same
  # p21e3 guest script, MNB36 branch, which reuses the MNB33 machinery
  # wholesale): the unchanged MNB30/MNB32/MNB33 pin preflight and the
  # diagnostic module set (cap, workload-with-P5, W7), the guest's policy
  # identity / module store / baseline FIFO constraints, the candidate
  # CIL module (docker-helper-fifo-rw-constraint, priority 400, identity
  # verified from the store), the live four-cell FIFO kernel-decision
  # matrix under the ACTIVE constraint (own ALLOW / cross DENY; baseline
  # cross-ALLOW recorded before the install), the fd:use / open / TE
  # invariance checks, the MNB33 producing-RUN flow with the constraint
  # active, and the verified rollback (module removal, baseline
  # constraint restoration, policy-sha closure, release .pp unchanged,
  # all diagnostic modules unloaded, dontaudit restored). ONE controlled
  # experiment: removal on every path; NO permanent RPM change, NO
  # Release-GO UAT.
  mnb36) GUEST_SCRIPT='release-2.4-r7-p21e3-guest.sh' ;;
  # mnb38 = the MNB38 RPM lifecycle UAT on the enforcing consumer (the
  # dedicated MNB38 guest script, NOT the p21e3 diagnostic stack): the
  # exact candidate RPM through the real package-manager lifecycle —
  # P0 candidate/metadata preflight (Requires carry the conditional
  # container-selinux/bzip2/setools-console SELinux lifecycle deps),
  # P1 fresh install (CIL artifact identity, priority-400 store module
  # with byte-exact blob identity, the exact loaded-policy constraint,
  # release .pp baseline), P2 repeated install/upgrade shape (UNCHANGED
  # store blob inode/mtime/bytes: no absent-constraint window),
  # P3 failed upgrade by a controlled constraint-install failure (both
  # services stopped AND verified, no automatic restart, restart-decision
  # preserved, rpm rc 0 distinguished from scriptlet failure),
  # P4 recovery with no implicit restart plus EXPLICIT activation and
  # MainPID proof, P5 final erase removing only the product-owned
  # modules (no orphans, container policy survives, units removed).
  # Packaging lifecycle only: NO policy grants, NO permissive mode,
  # NO Release-GO UAT.
  mnb38) GUEST_SCRIPT='release-2.4-mnb38-guest.sh' ;;
  # mnb39 = the no-exec wrapper policy verification feasibility on the
  # enforcing consumer (the dedicated MNB39 guest script + the
  # guest-compiled C probe): both wrapper admission-gate checks measured
  # IN-PROCESS under docker_helper_buildkitd_t — (1) the kernel-native
  # security_check_context interface against the exact composed workload
  # context (behavior matrix: valid/unknown-type/unauthorized-role/
  # bad-category/unavailable interface), (2) an in-process parse of the
  # loaded binary policy rendering the fifo_file constraint statements
  # and the roletype relation, compared against the root-run seinfo
  # reference outputs. Separately removable diagnostic modules only
  # (stage 1 parse-only face set; stage 2 adds exactly the
  # security:check_context row); full unload verification (policy sha
  # restored byte-exactly, deny-again proof). NO permanent policy
  # integration, NO product code change, NO Release-GO UAT.
  mnb39) GUEST_SCRIPT='release-2.4-mnb39-guest.sh' ;;
  # mnb40a = the production-wrapper evidence reconciliation on the
  # enforcing consumer (the dedicated MNB40a guest script): the MNB40
  # candidate binary is verified through the REAL managed-run chain —
  # a staged permission ladder of separately removable, mnb40a-named
  # modules — proving per stage (S0..S4): the context-validation gate
  # refuses closed without any selinuxfs faces and moves its denial to
  # security_t:security check_context when the file faces land; the
  # FIFO gate refuses with all file faces present (the security
  # read_policy denial at the policy OPEN — read_policy can NOT be
  # inferred unnecessary from an ordinary file open/read); the positive
  # run admission with the exact canonical fifo_file statement; the
  # missing-constraint case (semodule -X 400 -r) with same-snapshot
  # seinfo parity and the exact remediation refusal plus byte-exact
  # restore; full unload verification, policy sha restored, deny-again
  # refused closed. NO permanent policy integration, NO Release-GO UAT.
  mnb40a) GUEST_SCRIPT='release-2.4-mnb40a-guest.sh' ;;
  # mnb40b = the admission-boundary trace + the minimal authority proof
  # on the enforcing consumer (the dedicated MNB40b guest script): the
  # S0 face trace records the RUN-op path (the system docker engine;
  # no wrapper) against the BUILD-op path (the wrapper gates) with the
  # process-identity samples; M1 removes each of the five previously
  # unproven faces INDEPENDENTLY and records the exact denial
  # ({ search } dir / { getattr open read write } file), the wrapper
  # decision, the affected syscalls via the captured AVCs, and the
  # loaded-policy SHA per arm; M2 enumerates the of the write-bit
  # authority surface; M3 validates the COMBINED minimal set through
  # both faces; verified unload, byte-exact restore, deny-again. NO
  # permanent policy integration, NO Release-GO UAT.
  mnb40b) GUEST_SCRIPT='release-2.4-mnb40b-guest.sh' ;;
  # mnb41 = the enforcing-VM acceptance of the PERMANENT MNB41 promotion
  # (module docker_helper 1.3: the exact MNB40b-measured minimal set on the
  # buildkitd payload domain — file {getattr open read write} and security
  # {check_context read_policy}; dir search stays ungranted, no workload
  # grant). The dedicated guest verifies: the effective compiled-policy
  # delta against the pinned accepted baseline candidate (the byte-identical
  # 1.2 .pp from the accepted MNB40a RPM installed through the same store
  # path, sesearch captures of the whole security_t surface at baseline and
  # after the promoted reinstall, the accepted-baseline BUILD refused
  # closed, the reinstall restoring the loaded sha byte-exactly); the
  # production BUILD admitted through both wrapper gates and the RUN
  # through its independent lane; the exact FIFO constraint recognition
  # plus the fail-closed missing-constraint behavior BEFORE execution commit
  # (semodule -X 400 -r + the exact remediation refusal + byte-exact
  # restore + re-admission); the boundary audit (no workload security_t
  # grant anywhere, no diagnostic module anywhere, the store holds exactly
  # the two product modules); the closure identity (the .pp digest,
  # constraint digest and loaded-policy sha unchanged at closure).
  mnb41) GUEST_SCRIPT='release-2.4-mnb41-guest.sh' ;;
  *) fail "unknown R7_MODE '$R7_MODE' (diag | mcs-audit | exeseal | bprime | p21a | p21b | p21c | p21d | p21e | p21e3 | p21e3probe | p21e3proc-sys | p21e3proc-file | p21e3proc-keys | p21e3diag-keys | mnb30 | mnb32 | mnb33 | mnb36 | mnb38 | mnb39 | mnb40a | mnb40b | mnb41)" ;;
esac

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

: "${UAT_RPM:?UAT_RPM required}"
: "${UAT_RPM_SHA256:?UAT_RPM_SHA256 required}"

# shellcheck source=scripts/uat-vm-tumbleweed.sh
source "$SCRIPT_DIR/uat-vm-tumbleweed.sh"
# shellcheck source=scripts/uat-vm-opensuse-selinux-lib.sh
source "$SCRIPT_DIR/uat-vm-opensuse-selinux-lib.sh"

on_err() { vm_serial_tail || true; }
trap on_err ERR

log '== 1-5. SELinux host construction (canonical bootstrap, enforcing proof)'
vm_selinux_bootstrap

log '== 6. transfer repo + exact candidate RPM into the guest'
vm_selinux_transfer_repo
vm_selinux_transfer_artifact "docker-helper.rpm" "$UAT_RPM"
if [ "$R7_MODE" = "mnb41" ]; then
  # the pinned accepted MNB40a candidate RPM carries the byte-identical
  # pre-promotion docker_helper.pp (module 1.2) — the effective-delta
  # baseline, installed through the same store path in the guest
  : "${MNB41_BASELINE_RPM:?MNB41_BASELINE_RPM required}"
  : "${MNB41_BASELINE_RPM_SHA256:?MNB41_BASELINE_RPM_SHA256 required}"
  vm_selinux_transfer_artifact "docker-helper-baseline.rpm" "$MNB41_BASELINE_RPM"
fi

log '== 6b-7a. two-stage Docker preparation + health gate'
vm_selinux_two_stage_docker

log '== 7. transfer and run the R7 guest diagnostic'
vm_ssh 'rm -rf /tmp/r7-diag && mkdir -p /tmp/r7-diag'
vm_scp "$SCRIPT_DIR/$GUEST_SCRIPT" opc@127.0.0.1:/tmp/r7-diag/release-2.4-r7-diag-guest.sh
if [ "$R7_MODE" = "mnb30" ] || [ "$R7_MODE" = "mnb32" ] || [ "$R7_MODE" = "mnb33" ] || [ "$R7_MODE" = "mnb36" ]; then
  # The loader harness rides along (the guest runs it against the runtime
  # member extracted from the candidate RPM), together with the payload
  # staging owner (the single pins authority for the runtime byte-pin).
  vm_scp "$SCRIPT_DIR/payload-runc-loader-harness.sh" \
    opc@127.0.0.1:/tmp/r7-diag/payload-runc-loader-harness.sh
  vm_scp "$SCRIPT_DIR/../build-buildkit-payload.sh" \
    opc@127.0.0.1:/tmp/r7-diag/build-buildkit-payload.sh
fi
if [ "$R7_MODE" = "bprime" ]; then
  # The B′ gate evaluator rides along: the guest invokes it for the
  # machine-readable verdict; the host re-uses it for the job gate below.
  vm_scp "$SCRIPT_DIR/release-2.4-r7-bprime-verdict.sh" \
    opc@127.0.0.1:/tmp/r7-diag/release-2.4-r7-bprime-verdict.sh
fi
if [ "$R7_MODE" = "p21b" ]; then
  # The P21-B gate evaluator rides along (the same contract as B′).
  vm_scp "$SCRIPT_DIR/release-2.4-r7-p21b-verdict.sh" \
    opc@127.0.0.1:/tmp/r7-diag/release-2.4-r7-p21b-verdict.sh
fi
if [ "$R7_MODE" = "p21c" ]; then
  # The P21-C gate evaluator rides along (the same contract as P21-B).
  vm_scp "$SCRIPT_DIR/release-2.4-r7-p21c-verdict.sh" \
    opc@127.0.0.1:/tmp/r7-diag/release-2.4-r7-p21c-verdict.sh
fi
if [ "$R7_MODE" = "p21d" ]; then
  # The P21-D gate evaluator rides along (the same contract as P21-B).
  vm_scp "$SCRIPT_DIR/release-2.4-r7-p21d-guest.sh" \
    opc@127.0.0.1:/tmp/r7-diag/release-2.4-r7-diag-guest.sh
  vm_scp "$SCRIPT_DIR/release-2.4-r7-p21d-verdict.sh" \
    opc@127.0.0.1:/tmp/r7-diag/release-2.4-r7-p21d-verdict.sh
fi
if [ "$R7_MODE" = "mnb39" ]; then
  # The guest-compiled C probe rides along: the no-exec in-process policy
  # reader (checkctx matrix, loaded-policy constraint render, roletype
  # render) that the mnb39 guest script compiles statically and runs
  # inside docker_helper_buildkitd_t.
  vm_scp "$SCRIPT_DIR/mnb39-probe.c" opc@127.0.0.1:/tmp/r7-diag/mnb39-probe.c
fi

set +e
# The diag VM reboots mid-diagnosis (observed ~55s after boot; runs
# 39006788899+). The guest script is phased with state markers (the
# MNB38 lifecycle matrix keeps its markers on the persistent /var/lib
# because Tumbleweed mounts /tmp as tmpfs) and the evidence lives in a
# tmpfs dir, so each invocation's evidence is collected immediately and
# the invocation is repeated over fresh SSH sessions until the verdict
# appears.
ATTEMPTS=3
if [ "$R7_MODE" = "mnb38" ]; then
  # The lifecycle matrix is six sequential package transactions; with the
  # observed boot-length interruption each attempt reliably completes only
  # a couple of phases, so the re-entry budget must fit the matrix, not a
  # single-shot session.
  ATTEMPTS=8
fi
if [ "$R7_MODE" = "mnb39" ]; then
  # The probe matrix is five phases behind one provisioning install; give
  # the observed boot-length interruption the same treatment as the
  # lifecycle matrix (persistent markers handle the rest).
  ATTEMPTS=6
fi
VERDICT=""
for attempt in $(seq 1 "$ATTEMPTS"); do
  if [ "$attempt" -gt 1 ]; then
    log "re-entry: waiting for SSH after the observed mid-diagnosis reboot"
    vm_wait_ssh
  fi
  vm_ssh 'sudo bash -s' <<RMT >"$RUNNER_TEMP/r7-diag-guest.log" 2>&1
export R7_BACKEND=selinux R7_INSTALL=rpm
export R7_ARTIFACT=/opt/uat-import/docker-helper.rpm
export R7_ARTIFACT_SHA256="$UAT_RPM_SHA256"
export R7_EXPECT=fail
export R7_RUNTIME_DEPS=install
export R7_EVIDENCE_DIR='$GUEST_EVIDENCE_DIR'
# MNB38 pins: the installed CIL artifact identity (the same digest the
# wrapper admission gate and the store-identity acceptance verify).
export MNB38_CIL_SHA256='975490b5701c2d3bb1b59a6023a22d2807e42bfec4934be7c1b2691c704b3ce2'
export R7_P21E3_PROBE=$( [ "$R7_MODE" = p21e3probe ] && echo 1 || echo 0 )
export R7_P21E3_PROC_SYS=$( [ "$R7_MODE" = p21e3proc-sys ] && echo 1 || echo 0 )
export R7_P21E3_PROC_FILE=$( [ "$R7_MODE" = p21e3proc-file ] && echo 1 || echo 0 )
export R7_P21E3_PROC_KEYS=$( [ "$R7_MODE" = p21e3proc-keys ] && echo 1 || echo 0 )
export R7_P21E3_DIAG_KEYS=$( [ "$R7_MODE" = p21e3diag-keys ] && echo 1 || echo 0 )
export R7_MNB30=$( [ "$R7_MODE" = mnb30 ] && echo 1 || echo 0 )
export R7_MNB32=$( [ "$R7_MODE" = mnb32 ] && echo 1 || echo 0 )
export R7_MNB33=$( [ "$R7_MODE" = mnb33 ] && echo 1 || echo 0 )
export R7_MNB36=$( [ "$R7_MODE" = mnb36 ] && echo 1 || echo 0 )
# MNB39 pins: the guest-compiled probe source path and the pin-level
# loaded-policy sha BEFORE any diagnostic module (the unload gate's
# restore identity). The base is recomputed in the guest from the
# provisioned state; the orchestrator export is a cross-check only.
export MNB39_PROBE_SRC='/tmp/r7-diag/mnb39-probe.c'
export MNB41_BASELINE_RPM='/opt/uat-import/docker-helper-baseline.rpm'
export MNB41_BASELINE_RPM_SHA256="${MNB41_BASELINE_RPM_SHA256:-}"
export MNB41_EXPECTED_PP_SHA256="${MNB41_EXPECTED_PP_SHA256:-}"
bash /tmp/r7-diag/release-2.4-r7-diag-guest.sh
RMT
  GUEST_RC=$?
  cat "$RUNNER_TEMP/r7-diag-guest.log"

  # Per-attempt evidence files: each attempt's console log and evidence
  # tarball is preserved under its own suffix (a later attempt never
  # overwrites an earlier attempt's captured evidence).
  log "collect guest evidence (survives the verdict; attempt $attempt)"
  mkdir -p "$EVIDENCE_DIR"
  cp "$RUNNER_TEMP/r7-diag-guest.log" "$EVIDENCE_DIR/guest-attempt$attempt.log"
  if vm_ssh "test -d '$GUEST_EVIDENCE_DIR'" 2>/dev/null; then
    vm_ssh "tar -C '$GUEST_EVIDENCE_DIR' -czf - ." > "$EVIDENCE_DIR/guest-evidence-attempt$attempt.tar.gz" || true
    mkdir -p "$EVIDENCE_DIR/guest-attempt$attempt"
    tar -xzf "$EVIDENCE_DIR/guest-evidence-attempt$attempt.tar.gz" -C "$EVIDENCE_DIR/guest-attempt$attempt" 2>/dev/null || true
  fi

  if [ "$R7_MODE" = "mcs-audit" ]; then
    VERDICT="$(grep -aoE 'R7-MCS-AUDIT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-MCS-AUDIT=*)
        log "R7 MCS audit verdict: $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq 3 ]; then
          fail "the R7 MCS audit produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  elif [ "$R7_MODE" = "exeseal" ]; then
    VERDICT="$(grep -aoE 'R7-EXESEAL-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-EXESEAL-VERDICT=*)
        log "R7 exeseal probe verdict: $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq 3 ]; then
          fail "the R7 exeseal probe produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  elif [ "$R7_MODE" = "bprime" ]; then
    VERDICT="$(grep -aoE 'R7-BPRIME-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-BPRIME-VERDICT=*)
        log "R7 B′ probe verdict: $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq 3 ]; then
          fail "the R7 B′ probe produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  elif [ "$R7_MODE" = "p21b" ]; then
    VERDICT="$(grep -aoE 'R7-P21B-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-P21B-VERDICT=*)
        log "R7 P21-B probe verdict: $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq 3 ]; then
          fail "the R7 P21-B probe produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  elif [ "$R7_MODE" = "p21c" ]; then
    VERDICT="$(grep -aoE 'R7-P21C-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-P21C-VERDICT=*)
        log "R7 P21-C probe verdict: $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq 3 ]; then
          fail "the R7 P21-C probe produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  elif [ "$R7_MODE" = "p21d" ]; then
    VERDICT="$(grep -aoE 'R7-P21D-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-P21D-VERDICT=*)
        log "R7 P21-D probe verdict: $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq 3 ]; then
          fail "the R7 P21-D probe produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  elif [ "$R7_MODE" = "p21e" ]; then
    VERDICT="$(grep -aoE 'R7-P21E-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-P21E-VERDICT=*)
        log "R7 P21-E capture verdict: $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq 3 ]; then
          fail "the R7 P21-E capture produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  elif [ "$R7_MODE" = "mnb38" ]; then
    # The MNB38 lifecycle matrix verdicts on the phase-token summary: PASS
    # only when every phase recorded (the guest pre-req is the whole
    # matrix; the first failing gate otherwise exits with its FAILED line).
    VERDICT="$(grep -aoE 'R7-MNB38-VERDICT=(PASS|FAILED.*)' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-MNB38-VERDICT=PASS)
        log "MNB38 lifecycle matrix verdict: $VERDICT"
        break
        ;;
      R7-MNB38-VERDICT=FAILED*)
        log "MNB38 lifecycle matrix verdict: $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq "$ATTEMPTS" ]; then
          fail "the MNB38 lifecycle matrix produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  elif [ "$R7_MODE" = "mnb39" ]; then
    # The MNB39 feasibility verdict on the phase-token summary (the probe
    # matrix is self-contained; the verdict appears only after every
    # phase marked PASS or the first failing gate exits with its line).
    VERDICT="$(grep -aoE 'R7-MNB39-VERDICT=(PASS|FAILED.*)' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-MNB39-VERDICT=PASS)
        log "MNB39 no-exec feasibility verdict: $VERDICT"
        break
        ;;
      R7-MNB39-VERDICT=FAILED*)
        log "MNB39 no-exec feasibility verdict: $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq "$ATTEMPTS" ]; then
          fail "the MNB39 probe matrix produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  elif [ "$R7_MODE" = "mnb40a" ]; then
    # The MNB40a reconciliation verdict on the phase-token summary (the
    # ladder is self-contained; the verdict appears only after every
    # phase marked PASS or the first failing gate exits with its line).
    VERDICT="$(grep -aoE 'R7-MNB40A-VERDICT=(PASS|FAILED.*)' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-MNB40A-VERDICT=PASS)
        log "MNB40a reconciliation verdict: $VERDICT"
        break
        ;;
      R7-MNB40A-VERDICT=FAILED*)
        log "MNB40a reconciliation verdict: $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq "$ATTEMPTS" ]; then
          fail "the MNB40a reconciliation ladder produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  elif [ "$R7_MODE" = "mnb40b" ]; then
    # The MNB40b reconciliation verdict on the phase-token summary.
    VERDICT="$(grep -aoE 'R7-MNB40B-VERDICT=(PASS|FAILED.*)' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-MNB40B-VERDICT=PASS)
        log "MNB40b authority verdict: $VERDICT"
        break
        ;;
      R7-MNB40B-VERDICT=FAILED*)
        log "MNB40b authority verdict: $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq "$ATTEMPTS" ]; then
          fail "the MNB40b authority ladder produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  elif [ "$R7_MODE" = "mnb41" ]; then
    VERDICT="$(grep -aoE 'R7-MNB41-VERDICT=(PASS|FAILED.*)' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-MNB41-VERDICT=PASS)
        log "MNB41 acceptance verdict: $VERDICT"
        break
        ;;
      R7-MNB41-VERDICT=FAILED*)
        log "MNB41 acceptance verdict: $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq "$ATTEMPTS" ]; then
          fail "the MNB41 acceptance ladder produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  elif [ "$R7_MODE" = "p21e3" ] || [ "$R7_MODE" = "p21e3probe" ] || [ "$R7_MODE" = "p21e3proc-sys" ] || [ "$R7_MODE" = "p21e3proc-file" ] || [ "$R7_MODE" = "p21e3proc-keys" ] || [ "$R7_MODE" = "p21e3diag-keys" ] || [ "$R7_MODE" = "mnb30" ] || [ "$R7_MODE" = "mnb32" ] || [ "$R7_MODE" = "mnb33" ] || [ "$R7_MODE" = "mnb36" ]; then
    # The BUILD result line and the VERDICT line are matched SEPARATELY:
    # the previous tail -2 | tr '\n' ' ' fabrication produced a string
    # PREFIXED with R7-P21E3-BUILD=..., so the case below never matched
    # R7-P21E3-VERDICT=* even when the guest produced a valid verdict
    # (observed on the first p21e3 dispatch: verdict MEASURED, job failure
    # "produced no verdict").
    BUILD="R7-P21E3-BUILD=$(grep -aoE 'R7-P21E3-BUILD=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 | cut -d= -f2- || true)"
    VERDICT="$(grep -aoE 'R7-P21E3-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
    case "$VERDICT" in
      R7-P21E3-VERDICT=*)
        log "R7 P21-E3 measurement verdict: $BUILD $VERDICT"
        break
        ;;
      *)
        if [ "$attempt" -eq 3 ]; then
          fail "the R7 P21-E3 measurement produced no verdict (guest exit $GUEST_RC)"
        fi
        log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
        ;;
    esac
  else
  VERDICT="$(grep -aoE 'R7-DIAG-RESULT=[A-Z-]+' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
  case "$VERDICT" in
    "R7-DIAG-RESULT=REPRODUCED")
      log 'R7 SELinux diagnosis REPRODUCED (the defect is still live on this branch; red evidence captured)'
      break
      ;;
    "R7-DIAG-RESULT=BUILD-OK")
      log 'R7 SELinux diagnosis BUILD-OK (the corrective holds on this branch; green evidence captured)'
      break
      ;;
    *)
      if [ "$attempt" -eq 3 ]; then
        fail "the R7 SELinux diagnosis produced no verdict (guest exit $GUEST_RC)"
      fi
      log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
      ;;
  esac
  fi
done
set -e

# The B′/P21-B job conclusion must REFLECT the machine verdict: a BLOCKED
# or FAIL result is a failed gate (the evidence artifacts still upload; the
# workflow-level upload step runs under `if: always()`).
if [ "$R7_MODE" = "p21b" ]; then
  FINAL_VERDICT="$(grep -aoE 'R7-P21B-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
  if [ -z "$FINAL_VERDICT" ]; then
    fail "the R7 P21-B run produced no machine verdict"
  fi
  if ! bash "$SCRIPT_DIR/release-2.4-r7-p21b-verdict.sh" --gate "$FINAL_VERDICT"; then
    fail "the R7 P21-B gate did not reach P21B-MEASURED: $FINAL_VERDICT"
  fi
  log "R7 P21-B gate: P21B-MEASURED"
fi
if [ "$R7_MODE" = "p21c" ]; then
  FINAL_VERDICT="$(grep -aoE 'R7-P21C-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
  if [ -z "$FINAL_VERDICT" ]; then
    fail "the R7 P21-C run produced no machine verdict"
  fi
  if ! bash "$SCRIPT_DIR/release-2.4-r7-p21c-verdict.sh" --gate "$FINAL_VERDICT"; then
    fail "the R7 P21-C gate did not reach P21C-MEASURED: $FINAL_VERDICT"
  fi
  log "R7 P21-C gate: P21C-MEASURED"
fi

if [ "$R7_MODE" = "p21d" ]; then
  FINAL_VERDICT="$(grep -aoE 'R7-P21D-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
  if [ -z "$FINAL_VERDICT" ]; then
    fail "the R7 P21-D run produced no machine verdict"
  fi
  if ! bash "$SCRIPT_DIR/release-2.4-r7-p21d-verdict.sh" --gate "$FINAL_VERDICT"; then
    fail "the R7 P21-D gate did not reach P21D-MEASURED: $FINAL_VERDICT"
  fi
  log "R7 P21-D gate: P21D-MEASURED"
  # The concurrent negative scenario (r7-p21d-corrective-1) is part of the
  # run's contract: a foreign pathless runc-init AVC inside a proven window
  # must be excluded WITH pid proof, never misattributed.
  CX_VERDICT="$(grep -aoE 'R7-P21D-CX-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
  if [ -z "$CX_VERDICT" ]; then
    fail "the R7 P21-D run produced no concurrent-scenario (cx) machine verdict"
  fi
  if ! bash "$SCRIPT_DIR/release-2.4-r7-p21d-verdict.sh" --cx-gate "$CX_VERDICT"; then
    fail "the R7 P21-D concurrent-scenario gate did not reach P21D-CX-PROVEN: $CX_VERDICT"
  fi
  log "R7 P21-D cx gate: $CX_VERDICT"
fi
if [ "$R7_MODE" = "bprime" ]; then
  FINAL_VERDICT="$(grep -aoE 'R7-BPRIME-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
  if [ -z "$FINAL_VERDICT" ]; then
    fail "the R7 B′ run produced no machine verdict"
  fi
  if ! bash "$SCRIPT_DIR/release-2.4-r7-bprime-verdict.sh" --gate "$FINAL_VERDICT"; then
    fail "the R7 B′ gate did not reach BPRIME-VIABLE: $FINAL_VERDICT"
  fi
  log "R7 B′ gate: BPRIME-VIABLE"
fi
if [ "$R7_MODE" = "p21e" ]; then
  FINAL_VERDICT="$(grep -aoE 'R7-P21E-VERDICT=.*' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
  if [ -z "$FINAL_VERDICT" ]; then
    fail "the R7 P21-E run produced no machine verdict"
  fi
  case "$FINAL_VERDICT" in
    R7-P21E-VERDICT=CAPTURED=[1-9]*) log "R7 P21-E capture gate: $FINAL_VERDICT" ;;
    *) fail "the R7 P21-E capture gate failed: $FINAL_VERDICT" ;;
  esac
  # The host-side specimen validation: every captured config.json must be
  # ONE complete JSON object with no trailing data (the producer's terminal
  # newline allowed), and the extracted MOUNT list (destination/type/source/
  # options only — never the process section) is printed for the report.
  # A zero-valid-specimen outcome fails the gate; the evidence still uploads.
  python3 - "$EVIDENCE_DIR" <<'PYEOF'
import glob, hashlib, json, os, sys

root = sys.argv[1]
paths = sorted(glob.glob(os.path.join(root, "guest-attempt*", "spec-*", "spec-*.json")))
valid = 0
for path in paths:
    with open(path, "rb") as f:
        raw = f.read()
    sha = hashlib.sha256(raw).hexdigest()
    ok = True
    why = ""
    try:
        doc, end = json.JSONDecoder().raw_decode(raw.decode("utf-8"))
        if not isinstance(doc, dict):
            ok, why = False, "not a JSON object"
        elif raw[end:].strip():
            ok, why = False, "trailing data after the JSON object"
    except Exception as exc:  # noqa: BLE001 — the validator reports the reason
        ok, why = False, f"decode failed: {exc}"
    if ok:
        valid += 1
        print(f"VALID {os.path.basename(os.path.dirname(path))}/{os.path.basename(path)} "
              f"size={len(raw)} sha256={sha}")
        for m in doc.get("mounts", []):
            print("  MOUNT dest=%r type=%r source=%r options=%r"
                  % (m.get("destination"), m.get("type"), m.get("source"),
                     m.get("options")))
    else:
        print(f"INVALID {path}: {why}")
if valid == 0:
    print("P21E-SPECIMEN-VALIDATION: FAILED (no complete specimen)")
    sys.exit(1)
print(f"P21E-SPECIMEN-VALIDATION: PASSED ({valid} complete specimen(s))")
PYEOF
fi
