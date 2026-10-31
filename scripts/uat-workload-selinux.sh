#!/usr/bin/env bash
#
# uat-workload-selinux.sh — Release 2.2 SELinux workload-MAC acceptance for
# the exact candidate RPM, running INSIDE the enforcing openSUSE Tumbleweed
# guest of the artifact gate (invoked by scripts/uat-vm-opensuse-selinux.sh;
# the host wrapper owns the VM construction, the guest transfer of the exact
# RPM + candidate manifest + host-compiled live harness, and the harness
# source binding).
#
# This is the ONE full SELinux workload-MAC acceptance matrix of the release
# gate (docs/release-2.2-mac-enforcement.md, SELinux acceptance matrix):
#   1  RW exposure is really writable through the prepared workload state;
#   2  RO exposure is readable;
#   3  RO exposure is immutable (the write is denied, host file unchanged);
#   4  mixed RW + RO exposures work independently in ONE workload;
#   5  a writable parent spanning a nested RO region is refused with the
#      stable read_only_root code BEFORE any MAC/container state exists;
#   6  the backend-only forced-writable RO case is denied by SELinux ITSELF
#      (not the VFS): the host-compiled live harness drives the production
#      bindfs/projection backend from the same source SHA the candidate was
#      built from over a deliberately VFS-writable projection — including
#      the external-source chain (real external root → production
#      mount-pin owner → RO projection owner) — and the matching
#      docker_helper_ro_projection_t AVC is independently verified;
#   7  the workload stays in docker_helper_container_t and Docker-owned MCS
#      confinement is preserved (distinct per-container categories);
#   8  two concurrent Sessions use one host tree with different issued
#      snapshots without interference;
#   9  a regular-file RO exposure works (read ok, write denied);
#  10  the bindfs projection backend is really used on the packaged RPM path
#      (fuse.bindfs projection observed during a live RO exposure, and the
#      run.start audit records workload_mac_backend=selinux);
#  11  the backing source is not broad/recurrently relabeled (contexts
#      unchanged across the whole scenario, no global/Principal/Launcher
#      root relabel);
#  12  generated workload state is cleaned after success AND failure, and
#      restart/reconciliation leaves no stale helper-owned state;
#  13  the bounded audit window carries the attributable
#      docker_helper_ro_projection_t write AVC and no unexpected
#      docker_helper AVC outside the expected negative subcases;
#  14  hostile SUID source image cannot elevate (C1): the server-owned
#      workload privilege floor (no-new-privileges + cap-drop ALL) keeps a
#      root-owned SUID executable in the image at the workload's own
#      execution identity with no capabilities;
#  15  helper-created build staging strips SUID/SGID (C1): privilege bits
#      placed in the workspace never reach the helper-owned staged context,
#      so the built image cannot deliver them to workload execution;
#  16  helper-socket hostile composition (H9): with the runtime projection
#      mounted, the socket transport stays functional, an unauthenticated
#      call is refused, helper-private runtime state (session Docker
#      config, builds/mounts/workload-MAC machinery) stays unreadable, the
#      runtime stays immutable, and the privilege escalation stays dead —
#      the narrow traversal/socket-connect policy is not widened and DAC
#      0700 is not bypassable from the strongest reachable workload
#      privilege (Principal UID, no capabilities, no-new-privileges).
#
# R7 corrective evidence (auxiliary, outside the S-matrix numbering): the
# runtime-privacy section before S15 captures the LIVE evidence for the
# executed bundled OCI runtime's own per-op runtime-dir fixup (the
# buildkitd_t -> builder_runtime_t:dir setattr rung): two concurrent
# operations with distinct per-op categories, each op's runc dir context
# matching its own tree, the fixup's mode/owner tightening, no group/other
# widening on the tree path, post-terminal residue absence, and the
# category-blind loaded-policy grant pin.
#
# Fail-closed contract: PASS -> continue; FAIL -> gate red; BLOCKED -> a
# required dependency/evidence is unavailable -> gate red. Missing AVC or
# projection evidence is never counted as success.
# Exit status: 0 = all PASS, 1 = any FAIL, 2 = any BLOCKED (and none FAIL).
#
# Env inputs (guest paths):
#   UAT_VERSION        candidate version string (required)
#   UAT_RPM            guest path of the exact candidate RPM (required)
#   UAT_RPM_SHA256     expected SHA-256 of the candidate RPM (required)
#   UAT_PROOF_BIN      guest path of the host-compiled live harness (required)
#   UAT_SOURCE_SHA     the gate source SHA bound into candidate.manifest (required)
#   UAT_MANIFEST       guest path of candidate.manifest (required)
#   UAT_PRINCIPAL      OS user mapped to the principal (default opc)
#   UAT_EVIDENCE_DIR   guest evidence dir for the harness (default /tmp/uat-wls-evidence)
#
# Requires: root, enforcing SELinux, systemd, Docker, bindfs + /dev/fuse,
# policy module docker_helper loaded, ausearch (audit). Exits as above.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Shared measurement primitives (fail-closed residue inventory) come from the
# canonical lib owner; the script's own helpers below win.
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

VERSION="${UAT_VERSION:-2.2.0-uat}"
# RPM version field uses "~" for the UAT suffix ("-" separates version from
# release), so the rpm record check must match the transformed string. Bash
# tilde-expands a bare "~" replacement in ${var//pat/rep} ($HOME), so the
# transform goes through tr.
RPM_VERSION="$(printf '%s' "$VERSION" | tr '-' '~')"
# The one global ceiling of this guest matrix: the principal's home must sit
# under it (2.2 principal-home contract), so the acceptance tree, the
# workspace, and the SE external-root launcher all carry this root.
ALLOWED_ROOT="/home/opc"
PRINCIPAL="${UAT_PRINCIPAL:-opc}"
RPM_PATH_IN="${UAT_RPM:-}"
RPM_SHA256_IN="${UAT_RPM_SHA256:-}"
PROOF_BIN_IN="${UAT_PROOF_BIN:-}"
SOURCE_SHA_IN="${UAT_SOURCE_SHA:-}"
MANIFEST_IN="${UAT_MANIFEST:-}"
EVIDENCE_DIR="${UAT_EVIDENCE_DIR:-/tmp/uat-wls-evidence}"

PREFIX="[uat-workload-selinux]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }
info() { printf '%s %s\n' "$PREFIX" "$*"; }

redact() {
  sed -E \
    -e 's/dht_[A-Za-z0-9_-]+/<redacted-token>/g' \
    -e 's/dhc_[A-Za-z0-9_-]+/<redacted-token>/g'
}

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
[ -n "$RPM_PATH_IN" ] && [ -f "$RPM_PATH_IN" ] || { echo "error: UAT_RPM must be an existing file: $RPM_PATH_IN" >&2; exit 1; }
[ -n "$RPM_SHA256_IN" ] || { echo "error: UAT_RPM_SHA256 is required" >&2; exit 1; }
ACTUAL_SHA="$(sha256sum "$RPM_PATH_IN" | awk '{print $1}')"
[ "$ACTUAL_SHA" = "$RPM_SHA256_IN" ] || {
  echo "error: candidate RPM SHA-256 mismatch (expected $RPM_SHA256_IN, got $ACTUAL_SHA)" >&2
  exit 1
}
[ -n "$PROOF_BIN_IN" ] && [ -x "$PROOF_BIN_IN" ] || { echo "error: UAT_PROOF_BIN must be an executable file: $PROOF_BIN_IN" >&2; exit 1; }
[ -n "$SOURCE_SHA_IN" ] || { echo "error: UAT_SOURCE_SHA is required" >&2; exit 1; }
[ -n "$MANIFEST_IN" ] && [ -f "$MANIFEST_IN" ] || { echo "error: UAT_MANIFEST must be an existing file: $MANIFEST_IN" >&2; exit 1; }
MANIFEST_SOURCE_SHA="$(sed -n 's/^source_sha=//p' "$MANIFEST_IN" | head -1)"
[ "$MANIFEST_SOURCE_SHA" = "$SOURCE_SHA_IN" ] || {
  echo "error: candidate.manifest source_sha mismatch (expected $SOURCE_SHA_IN, got ${MANIFEST_SOURCE_SHA:-absent})" >&2
  exit 1
}

FAIL_COUNT=0
BLOCKED_COUNT=0
acc_ok() { printf '  ok:      %s\n' "$*"; }
acc_fail() { printf '  FAIL:    %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
acc_blocked() { printf '  BLOCKED: %s\n' "$*" >&2; BLOCKED_COUNT=$((BLOCKED_COUNT + 1)); }

# rt_priv_log_verdict SURVEY OP OWN_CTX — the R7 privacy runc-log.json
# observation classifier. Survey records have the shape
#
#   runc-log <op> st_rc=<n> st_err=<t> cx_rc=<n> cx_err=<t> <a|U|G>|<ctx>
#
# where st_* covers the stat(-c '%a|%U|%G') read and cx_* the separate
# stat(-c '%C') context read, each with its own exit status and
# newline-flattened stderr. Classification:
#   - COMPLETE observation: st_rc=0 AND cx_rc=0 AND the context field is
#     non-empty and not "?". Decisive: its context MUST equal OWN_CTX.
#   - mode-read failure (st_rc!=0, e.g. ENOENT teardown): incomplete, NOT
#     decisive, counted.
#   - context-read failure (cx_rc!=0 or "?" with the file still present):
#     incomplete, NOT decisive, counted — distinguished from the ENOENT
#     teardown case by cx_rc/cx_err instead of being folded into it.
# Verdict: FAIL foreign-category when any complete observation carries a
# different context; FAIL no-valid-observation when zero complete
# observations exist; otherwise OK. Never decisive from FIRST or LAST
# alone: every complete observation is checked, and incomplete ones are
# surfaced in the verdict so a teardown race cannot silently flip the
# evidence either way.
rt_priv_log_verdict() {
  survey="$1"; op="$2"; own_ctx="$3"
  valid=0; incomplete=0; foreign=""
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    case "$rec" in
      "runc-log $op "*) ;;
      *) continue ;;
    esac
    st_rc="$(printf '%s' "$rec" | sed -n 's/.* st_rc=\([0-9][0-9]*\).*/\1/p')"
    cx_rc="$(printf '%s' "$rec" | sed -n 's/.* cx_rc=\([0-9][0-9]*\).*/\1/p')"
    ctx="$(printf '%s' "$rec" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[^ ]*\|/) { n = split($i, a, "|"); print a[n] } }')"
    if [ "$st_rc" = "0" ] && [ "$cx_rc" = "0" ] && [ -n "$ctx" ] && [ "$ctx" != "?" ]; then
      valid=$((valid + 1))
      if [ "$ctx" != "$own_ctx" ]; then
        foreign="$ctx"
      fi
    else
      incomplete=$((incomplete + 1))
    fi
  done < "$survey"
  if [ -n "$foreign" ]; then
    printf 'VERDICT=FAIL reason=foreign-category valid=%d incomplete=%d foreign=%s\n' "$valid" "$incomplete" "$foreign"
  elif [ "$valid" -eq 0 ]; then
    printf 'VERDICT=FAIL reason=no-valid-observation valid=0 incomplete=%d foreign=none\n' "$incomplete"
  else
    printf 'VERDICT=OK valid=%d incomplete=%d foreign=none\n' "$valid" "$incomplete"
  fi
}
# Two DISTINCT mode invariants, classified on the LAST THREE octal
# digits (any special-bit prefix is ignored — 1700 is sticky+0700):
#   rt_priv_owner_only MODE -> 1 iff group digit == 0 AND other
#   digit == 0 (the owner-only invariant: ANY group/other access,
#   read r-4 / write w-2 / execute x-1, violates);
#   rt_priv_no_write MODE   -> 1 iff neither digit carries the write
#   bit (2,3=w/wx, 6,7=rw/rwx violate; read-only 4,5 does NOT).
# The runc dirs are judged by owner-only; the shared tree path (the
# runtime root, ops/, the op dirs) by no-write only (the flow
# identity must be able to traverse the shared path).
rt_priv_owner_only() {
  local m g o
  m="$(printf '%s' "$1" | awk '{ print substr($0, length($0)-2) }')"
  case "$m" in ???) : ;; *) return 1 ;; esac
  g="$(printf '%s' "$m" | awk '{ print substr($0, 2, 1) }')"
  o="$(printf '%s' "$m" | awk '{ print substr($0, 3, 1) }')"
  [ "$g" = "0" ] && [ "$o" = "0" ]
}
rt_priv_no_write() {
  local m g o
  m="$(printf '%s' "$1" | awk '{ print substr($0, length($0)-2) }')"
  case "$m" in ???) : ;; *) return 1 ;; esac
  g="$(printf '%s' "$m" | awk '{ print substr($0, 2, 1) }')"
  o="$(printf '%s' "$m" | awk '{ print substr($0, 3, 1) }')"
  case "$g" in 2|3|6|7) return 1 ;; esac
  case "$o" in 2|3|6|7) return 1 ;; esac
  return 0
}

rt_priv_watch_error_count() {
  # FILE PREFIX — count watcher registration-error lines whose message
  # carries PREFIX ("/run/docker-helper-builder" or
  # "/var/lib/docker-helper-builder"); with an empty PREFIX count every
  # non-empty error line. The per-tree split matters: an adoption
  # failure in the STATE tree does not blind the RUNTIME-tree runc-dir
  # observation (separate watch chains), and vice versa.
  [ -f "$1" ] || { printf '0'; return 0; }
  if [ -n "$2" ]; then
    n="$(grep -c "Couldn't watch.*$2" "$1" 2>/dev/null)"
  else
    n="$(grep -c . "$1" 2>/dev/null)"
  fi
  [ -n "$n" ] || n=0
  printf '%s' "$n"
}

# rt_priv_capture_desc CAPTURE_MODE DEGRADED_FLAG WATCH_ERRORS — the
# capture-quality display used by the privacy leg messages. The DEGRADED
# flag is printed as its literal value (0 or 1): the previous
# ${var:+-DEGRADED} form was truthy for "0" and mislabeled healthy
# captures in FAIL messages (display-only; the decision path compares
# the flag to "1" and was never affected).
rt_priv_capture_desc() {
  printf 'capture=%s degraded=%s watch-errors=%s' "$1" "$2" "$3"
}

# The fd-pinned runc-attribute reader. The P9 UAT exposed the two-path-
# stat TOCTOU: the capture resolved the pathname once for mode|uid|gid
# and again for the SELinux context, and the short-lived runc dir's
# removal landed between the two resolutions (mode read OK, context read
# lost — the tuple became 1700|...|? and the observation degraded to
# created-but-unreadable for BOTH ops). The fix pins the object's
# identity FIRST: the open of the directory FD is the single
# pathname-dependent step, and every attribute is then read THROUGH the
# open file description — /proc/self/fd/N is a magic link whose kernel
# handler (proc_fd_link, fs/proc/fd.c) hands out the open file's own
# f_path, so stat -L and getfilecon through it operate on the pinned
# inode even after the pathname is unlinked (the fd keeps the dentry
# referenced; the deletion cannot invalidate any subsequent read). The
# technique is never assumed: rt_priv_fd_selftest proves it per-run, as
# the SAME subject that performs the live captures, against a scratch
# dir with the production object type — deletion between open and reads,
# substitution of another inode at the same pathname, and a failed open
# are all exercised deterministically; only an all-green control
# activates the mechanism, otherwise the captures degrade to the legacy
# two-path-stat contract (fail-closed, the P9 evidence shape).
rt_priv_runc_open() {
  # PATH — open the directory O_RDONLY (opening a directory for reading
  # is allowed by the kernel; read(2) is never attempted). On success fd
  # 9 holds the pinned open file description; on failure fd 9 stays
  # closed and the rc is nonzero.
  exec 9<"$1" 2>/dev/null
}
rt_priv_runc_readfd() {
  # Read mode|uid|gid, the inode number and the SELinux context THROUGH
  # the pinned FD (requires fd 9 held by rt_priv_runc_open), then release
  # it. Every read follows /proc/self/fd/9 with stat -L to the open
  # file's own dentry; each read carries its own exit status and stderr.
  # Without an open fd 9 the reads are skipped with explicit statuses
  # (never silently attributed to a stale or foreign descriptor).
  RT_FD_TUPLE=""; RT_FD_INO=""; RT_FD_CTX=""
  RT_FD_ST_RC=2; RT_FD_ST_ERR="skipped-no-open-fd"
  RT_FD_CX_RC=2; RT_FD_CX_ERR="skipped-no-open-fd"
  if [ -e /proc/self/fd/9 ]; then
    RT_FD_TUPLE="$(stat -Lc '%a|%U|%G' /proc/self/fd/9 2>"$RT_SURVEY.sterr")"
    RT_FD_ST_RC=$?
    RT_FD_ST_ERR="$(tr '\n' ' ' <"$RT_SURVEY.sterr" 2>/dev/null | tr ' ' '_')"
    RT_FD_INO="$(stat -Lc '%i' /proc/self/fd/9 2>/dev/null)"
    RT_FD_CTX="$(stat -Lc '%C' /proc/self/fd/9 2>"$RT_SURVEY.cxerr")"
    RT_FD_CX_RC=$?
    RT_FD_CX_ERR="$(tr '\n' ' ' <"$RT_SURVEY.cxerr" 2>/dev/null | tr ' ' '_')"
  fi
  exec 9<&- 2>/dev/null || true
}
rt_priv_runc_read() {
  # PATH PREFIX — the shared runc-attribute evidence reader used by BOTH
  # the immediate per-event capture and the survey sweep. With the fd
  # technique proven (RT_FD_METHOD=proven) the record carries fd_rc /
  # fd_err / ino ahead of the per-read statuses: fd_rc=0 means the
  # pathname was resolved exactly once (at the open) and the tuple and
  # context were read from the pinned inode — a deletion after the open
  # cannot split the tuple anymore. fd_rc nonzero means the dir vanished
  # (or the open was refused) BEFORE the identity could be pinned — an
  # honest incomplete observation, never a validation. When the technique
  # could not be proven on this kernel the reader degrades to the legacy
  # two-path-stat contract (no fd fields), the exact P9 evidence shape.
  if [ "$RT_FD_METHOD" = "proven" ]; then
    RT_R_FD_RC=1; RT_R_FD_ERR="open-failed"; RT_R_TUPLE=""; RT_R_INO=""
    RT_R_ST_RC=2; RT_R_ST_ERR="skipped-no-open-fd"
    RT_R_CX_RC=2; RT_R_CX_ERR="skipped-no-open-fd"
    RT_R_CTX=""
    if rt_priv_runc_open "$1"; then
      RT_R_FD_RC=0; RT_R_FD_ERR="none"
      rt_priv_runc_readfd
      RT_R_TUPLE="$RT_FD_TUPLE"; RT_R_INO="$RT_FD_INO"; RT_R_CTX="$RT_FD_CTX"
      RT_R_ST_RC=$RT_FD_ST_RC; RT_R_ST_ERR="$RT_FD_ST_ERR"
      RT_R_CX_RC=$RT_FD_CX_RC; RT_R_CX_ERR="$RT_FD_CX_ERR"
    else
      # Post-facto labeling only: the open already failed, so the -d
      # probe cannot change the evidence — it just distinguishes a dir
      # that vanished before the open (ENOENT-class) from one that was
      # present but refused (EACCES-class, e.g. a confinement change).
      if [ -d "$1" ]; then
        RT_R_FD_ERR="open-failed-dir-present"
      else
        RT_R_FD_ERR="open-failed-dir-absent"
      fi
    fi
    printf '%s fd_rc=%d fd_err=%s ino=%s st_rc=%d st_err=%s cx_rc=%d cx_err=%s %s|%s\n' \
      "$2" "$RT_R_FD_RC" "$RT_R_FD_ERR" "${RT_R_INO:-}" \
      "$RT_R_ST_RC" "${RT_R_ST_ERR:-none}" \
      "$RT_R_CX_RC" "${RT_R_CX_ERR:-none}" \
      "${RT_R_TUPLE:-}" "${RT_R_CTX:-?}" >> "$RT_SURVEY"
  else
    RT_R_TUPLE="$(stat -c '%a|%U|%G' "$1" 2>"$RT_SURVEY.sterr")"
    RT_R_ST_RC=$?
    RT_R_ST_ERR="$(tr '\n' ' ' <"$RT_SURVEY.sterr" 2>/dev/null | tr ' ' '_')"
    RT_R_CTX="$(stat -c '%C' "$1" 2>"$RT_SURVEY.cxerr")"
    RT_R_CX_RC=$?
    RT_R_CX_ERR="$(tr '\n' ' ' <"$RT_SURVEY.cxerr" 2>/dev/null | tr ' ' '_')"
    printf '%s st_rc=%d st_err=%s cx_rc=%d cx_err=%s %s|%s\n' \
      "$2" "$RT_R_ST_RC" "${RT_R_ST_ERR:-none}" \
      "$RT_R_CX_RC" "${RT_R_CX_ERR:-none}" \
      "${RT_R_TUPLE:-}" "${RT_R_CTX:-?}" >> "$RT_SURVEY"
  fi
}
rt_priv_fd_selftest() {
  # The per-run positive control for the fd-pinned reader, run as the
  # SAME subject (DAC and SELinux) that will perform the live captures.
  # Deterministically reproduces the P9 race shapes against a scratch
  # dir with the production runc-dir object type (chcon'ed away from the
  # tmpfs parent's tmp_t, plus its own MCS category when the relabel is
  # accepted, so a parent- or procfs-substituted context can never pass
  # the context check) and activates the mechanism only on an all-green
  # result:
  #   - open the dir FD; delete the pathname; the link must report
  #     "(deleted)";
  #   - substitute ANOTHER inode at the same pathname (different mode);
  #   - read mode|uid|gid|ino and the context THROUGH the FD: both must
  #     equal the pre-delete reference and the tuple must differ from the
  #     substituted path's (the pinned identity, not the substitution);
  #   - the context read must equal the reference context AND, when the
  #     chcon control succeeded, differ from the parent's context;
  #   - a failed open must leave no FD behind (the reads are skipped).
  RT_FD_METHOD=unavailable
  RT_FD_DELETED=no; RT_FD_SUBSTITUTED=no; RT_FD_OPENFAIL=no; RT_FD_CTX_DISCRIM=no
  RT_FD_BASE=/tmp/uat-wls-privacy-fdselftest
  rm -rf "$RT_FD_BASE"
  mkdir -p "$RT_FD_BASE/parent" || return 0
  RT_FD_PATH="$RT_FD_BASE/parent/target"
  mkdir "$RT_FD_PATH" || return 0
  chmod 1700 "$RT_FD_PATH" "$RT_FD_BASE/parent" 2>/dev/null
  if command -v chcon >/dev/null 2>&1; then
    if chcon -t docker_helper_builder_runtime_t "$RT_FD_PATH" 2>/dev/null; then
      chcon -l c777 "$RT_FD_PATH" 2>/dev/null || true
    else
      chcon -t device_t "$RT_FD_PATH" 2>/dev/null || true
    fi
  fi
  RT_FD_REF="$(stat -c '%a|%U|%G|%i' "$RT_FD_PATH" 2>/dev/null)"
  # The reference carries the pinned inode's number as its fourth field:
  # the tuple comparison strips it (the FD tuple is mode|uid|gid) and
  # the inode comparison uses it explicitly — both must match the
  # pre-delete reference AND differ from the substitute.
  RT_FD_REF_TUPLE="${RT_FD_REF%|*}"
  RT_FD_REF_INO="${RT_FD_REF##*|}"
  RT_FD_REF_CTX="$(stat -c '%C' "$RT_FD_PATH" 2>/dev/null)"
  RT_FD_PARENT_CTX="$(stat -c '%C' "$RT_FD_BASE/parent" 2>/dev/null)"
  if [ -n "$RT_FD_REF_CTX" ] && [ -n "$RT_FD_PARENT_CTX" ] \
      && [ "$RT_FD_REF_CTX" != "$RT_FD_PARENT_CTX" ] && [ "$RT_FD_REF_CTX" != "?" ]; then
    RT_FD_CTX_DISCRIM=yes
  fi
  if [ -n "$RT_FD_REF" ] && rt_priv_runc_open "$RT_FD_PATH"; then
    rmdir "$RT_FD_PATH" 2>/dev/null
    case "$(readlink /proc/self/fd/9 2>/dev/null)" in *" (deleted)") RT_FD_DELETED=yes ;; esac
    if mkdir "$RT_FD_PATH" 2>/dev/null && chmod 0755 "$RT_FD_PATH" 2>/dev/null; then
      RT_FD_SUBSTITUTED=yes
      RT_FD_SUB_TUPLE="$(stat -c '%a|%U|%G|%i' "$RT_FD_PATH" 2>/dev/null)"
    fi
    rt_priv_runc_readfd
    if [ "$RT_FD_DELETED" = yes ] && [ "$RT_FD_SUBSTITUTED" = yes ] \
        && [ "$RT_FD_TUPLE" = "$RT_FD_REF_TUPLE" ] && [ -n "$RT_FD_INO" ] && [ "$RT_FD_INO" = "$RT_FD_REF_INO" ] \
        && [ -n "$RT_FD_SUB_TUPLE" ] && [ "$RT_FD_INO" != "${RT_FD_SUB_TUPLE##*|}" ] \
        && [ -n "$RT_FD_CTX" ] && [ "$RT_FD_CTX" = "$RT_FD_REF_CTX" ] && [ "$RT_FD_REF_CTX" != "?" ] \
        && { [ "$RT_FD_CTX_DISCRIM" != yes ] || [ "$RT_FD_CTX" != "$RT_FD_PARENT_CTX" ]; }; then
      RT_FD_METHOD=proven
    fi
  fi
  if ! rt_priv_runc_open "$RT_FD_BASE/parent/absent"; then
    if [ ! -e /proc/self/fd/9 ]; then
      RT_FD_OPENFAIL=yes
    fi
  fi
  rm -rf "$RT_FD_BASE"
}

# rt_priv_runc_verdict SURVEY OP OWN_TUPLE CAPTURE_QUALITY — the R7
# privacy runc-dir observation classifier. Survey records have the shapes
#
#   runc <op> fd_rc=<n> fd_err=<t> ino=<i> st_rc=<n> st_err=<t> cx_rc=<n> cx_err=<t> <a|U|G>|<ctx>
#   runc-obs <op> ev=<E> fd_rc=<n> fd_err=<t> ino=<i> st_rc=<n> st_err=<t> cx_rc=<n> cx_err=<t> <a|U|G>|<ctx>
#   runc-gone <op> ev=<E> path=<p>
#
# where the runc lines come from the periodic survey sweep and the
# runc-obs lines from the immediate per-event capture (each read carries
# its own exit status and stderr). The fd_* fields are present only when
# the fd-pinned reader produced the record: fd_rc is the open of the
# directory FD — the single pathname-dependent step — and ino the pinned
# inode's number; every attribute was then read THROUGH that open file
# description, so one complete record is guaranteed to describe ONE
# inode (the P9 TOCTOU — mode read OK, context read lost to the removal
# — cannot produce a split tuple anymore). fd_rc present and nonzero
# means the dir vanished (or the open was refused) before the identity
# could be pinned — incomplete evidence. Legacy records (the fallback
# when the fd technique could not be proven on this kernel) carry no fd
# fields and keep the plain two-path-stat contract. OWN_TUPLE is the op's own
# runtime-tree stat tuple (mode|uid|gid|ctx) — it supplies both the
# expected context and the expected flow identity (owner). CAPTURE_QUALITY
# is "full" only when the event capture ran active, survived, observed
# events, suffered no overflow, and the watcher reported NO registration
# errors; anything else is "incomplete". Classification (set-based, never
# FIRST-only or LAST-only):
#   - COMPLETE observation: fd_rc (when present) is 0 AND st_rc=0 AND
#     cx_rc=0 AND a non-empty tuple whose context is readable (not "?").
#     Decisive: its context MUST
#     equal the op tree's own context, its mode MUST be owner-only, and
#     its owner MUST equal the op tree's flow identity. EVERY complete
#     observation is checked.
#   - incomplete observation (either read failed — the dir existed at
#     test time and vanished before the stat): counted, never decisive.
#   - runc-gone: a kernel delete/moved_from event for the dir; counted.
# Verdict for an op with ZERO records of any kind: FAIL
# reason=never-created ONLY under a proven-full observation (a silently
# lost adoption race is not proof of absence); FAIL
# reason=observation-incomplete when the capture quality is incomplete
# (watcher registration errors, overflow, death, zero events, or the
# interval-blind fallback poller). Records without a complete tuple are
# FAIL reason=created-but-unreadable (gone events prove a
# created-and-removed lifetime); any complete observation violating a
# property is FAIL with ctx=/mode= details; otherwise OK. A creation
# event alone never validates anything: only a complete stat tuple can,
# so a delete-before-stat observation stays incomplete and can never
# become a PASS.
rt_priv_runc_verdict() {
  survey="$1"; op="$2"; own="$3"; quality="$4"
  own_ctx="$(printf '%s' "$own" | awk -F'|' '{ print $4 }')"
  own_owner="$(printf '%s' "$own" | awk -F'|' '{ print $2 "|" $3 }')"
  valid=0; incomplete=0; gone=0; ctx_bad=""; mode_bad=""; first=""
  while IFS= read -r rec; do
    [ -n "$rec" ] || continue
    case "$rec" in
      "runc $op "*|"runc-obs $op "*) ;;
      "runc-gone $op "*) gone=$((gone + 1)); continue ;;
      *) continue ;;
    esac
    tuple="$(printf '%s' "$rec" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[^ ]*\|/) { print $i; exit } }')"
    st_rc="$(printf '%s' "$rec" | sed -n 's/.* st_rc=\([0-9][0-9]*\).*/\1/p')"
    cx_rc="$(printf '%s' "$rec" | sed -n 's/.* cx_rc=\([0-9][0-9]*\).*/\1/p')"
    fd_rc="$(printf '%s' "$rec" | sed -n 's/.* fd_rc=\([0-9][0-9]*\).*/\1/p')"
    if [ "$st_rc" = "0" ] && [ "$cx_rc" = "0" ] && [ -n "$tuple" ] \
        && { [ -z "$fd_rc" ] || [ "$fd_rc" = "0" ]; }; then
      mode="${tuple%%|*}"
      owner="$(printf '%s' "${tuple#*|}" | awk -F'|' '{ print $1 "|" $2 }')"
      ctx="$(printf '%s' "$tuple" | awk -F'|' '{ print $4 }')"
      if [ -n "$ctx" ] && [ "$ctx" != "?" ]; then
        valid=$((valid + 1))
        [ -z "$first" ] && first="$tuple"
        if [ "$ctx" != "$own_ctx" ]; then
          ctx_bad="$ctx"
        fi
        if ! rt_priv_owner_only "$mode"; then
          mode_bad="$mode_bad mode=$mode-not-owner-only"
        fi
        if [ "$owner" != "$own_owner" ]; then
          mode_bad="$mode_bad owner=$owner-drifted-from-$own_owner"
        fi
      else
        incomplete=$((incomplete + 1))
      fi
    else
      incomplete=$((incomplete + 1))
    fi
  done < "$survey"
  if [ "$valid" -eq 0 ]; then
    if [ $((incomplete + gone)) -eq 0 ]; then
      if [ "$quality" = "full" ]; then
        printf 'VERDICT=FAIL reason=never-created ctx=FAIL mode=FAIL valid=0 incomplete=0 gone=0\n'
      else
        printf 'VERDICT=FAIL reason=observation-incomplete ctx=FAIL mode=FAIL valid=0 incomplete=0 gone=0\n'
      fi
    else
      printf 'VERDICT=FAIL reason=created-but-unreadable ctx=FAIL mode=FAIL valid=0 incomplete=%d gone=%d\n' "$incomplete" "$gone"
    fi
    return 0
  fi
  ctx_v=OK; [ -n "$ctx_bad" ] && ctx_v="FAIL(seen=$ctx_bad)"
  mode_v=OK; [ -n "$mode_bad" ] && mode_v="FAIL(${mode_bad# })"
  overall=OK
  if [ -n "$ctx_bad" ] || [ -n "$mode_bad" ]; then
    overall=FAIL
  fi
  printf 'VERDICT=%s ctx=%s mode=%s valid=%d incomplete=%d gone=%d first=%s\n' \
    "$overall" "$ctx_v" "$mode_v" "$valid" "$incomplete" "$gone" "$first"
}

# rt_priv_memfd_verdict CAPTURE_FILE CTX_A CTX_B — the R7 P6 exec-boundary
# classifier over the privacy stage's /proc memfd-exe sweep. Sweep records
# have the shape
#
#   memfd-proc pid=<p> comm=6 ctx=<ctx> exe=<exe>
#
# written by the tight /proc sweep that runs while the two concurrent
# builds execute: any live process whose comm equals the basename of the
# exeseal exec path ("6" for /proc/self/fd/6, the kernel sets comm from
# the exec path inside begin_new_exec) is journaled with its SELinux
# context and its /proc/<pid>/exe link. Classification (set-based, every
# record checked, one pid of an operation counted once):
#   - VALID hit: exe starts with /memfd:runc_cloned: and ctx is a
#     docker_helper_buildkitd_t context carrying the operation's own
#     category suffix (execute_no_trans semantics: the exec'd clone
#     inherits the invoking runc parent's domain and per-op category) —
#     the sealed clone demonstrably EXECUTED as a live userspace process
#     in that operation's own domain;
#   - everything else (a foreign category, a non-buildkitd domain, a
#     comm=6 process whose exe is not the memfd clone, or an unreadable
#     field) is FOREIGN — fail-closed;
#   - VERDICT=OK only when BOTH operations carry at least one valid hit
#     and zero foreign hits. Zero hits for an operation mean the exec
#     boundary was never observed crossed for it — absence of observation
#     is never a pass. The verdict is an OBSERVATION line in the privacy
#     stage (the clone is killed sub-millisecond by the failing parent,
#     below any process-lifetime instrument's resolution — the
#     race-free exec-completion leg is the ftrace sys_exit_execve
#     evidence, and this classifier becomes decisive once a future phase
#     lets the clone live long enough to be swept).
rt_priv_memfd_verdict() {
  capture="$1"; ctx_a="$2"; ctx_b="$3"
  cat_a="${ctx_a##*:s0}"; cat_b="${ctx_b##*:s0}"
  if [ -z "$cat_a" ] || [ -z "$cat_b" ]; then
    printf 'VERDICT=FAIL reason=own-context-unobserved A=0 B=0 foreign=0 first_a=never-seen first_b=never-seen\n'
    return 0
  fi
  hits_a=0; hits_b=0; foreign=0; first_a=""; first_b=""; seen_a=" "; seen_b=" "
  if [ -f "$capture" ]; then
    while IFS= read -r rec; do
      [ -n "$rec" ] || continue
      case "$rec" in "memfd-proc "*) ;; *) continue ;; esac
      pid="$(printf '%s' "$rec" | sed -n 's/^memfd-proc pid=\([0-9][0-9]*\) .*/\1/p')"
      ctx="$(printf '%s' "$rec" | sed -n 's/.* ctx=\([^ ]*\).*/\1/p')"
      exe="$(printf '%s' "$rec" | sed -n 's/.* exe=//p')"
      case "$exe" in /memfd:runc_cloned:*) ;; *) foreign=$((foreign + 1)); continue ;; esac
      case "$ctx" in
        *docker_helper_buildkitd_t:s0"$cat_a")
          case " $seen_a " in *" $pid "*) continue ;; esac
          seen_a="$seen_a$pid "
          hits_a=$((hits_a + 1)); [ -z "$first_a" ] && first_a="$rec" ;;
        *docker_helper_buildkitd_t:s0"$cat_b")
          case " $seen_b " in *" $pid "*) continue ;; esac
          seen_b="$seen_b$pid "
          hits_b=$((hits_b + 1)); [ -z "$first_b" ] && first_b="$rec" ;;
        *) foreign=$((foreign + 1)) ;;
      esac
    done < "$capture"
  fi
  if [ "$hits_a" -ge 1 ] && [ "$hits_b" -ge 1 ] && [ "$foreign" -eq 0 ]; then
    overall=OK
  else
    overall=FAIL
  fi
  printf 'VERDICT=%s A=%d B=%d foreign=%d first_a=%s first_b=%s\n' \
    "$overall" "$hits_a" "$hits_b" "$foreign" "${first_a:-never-seen}" "${first_b:-never-seen}"
}
scenario() { say "scenario $1"; }

dh() { /usr/bin/docker-helper "$@"; }
SOCK="/run/docker-helper/docker-helper.sock"

# json_field NAME — extract a JSON string field. The pattern is
# space-tolerant after the colon: the CLI's indented --json output emits
# "field": "value" while the raw HTTP API (writeJSONRaw, compact Go JSON)
# emits "field":"value"; both must parse (the S2M canary terminal status is
# read over raw HTTP).
json_field() { grep -oP "\"$1\":\s*\"\K[^\"]+" | head -1; }

wait_health() {
  local _i=0
  for _i in $(seq 1 100); do
    curl --silent --fail --max-time 1 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1 && return 0
    if ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
      return 1
    fi
    sleep 0.2
  done
  return 1
}

# Fail-closed residue inventory: the three-state ABSENT/PRESENT/UNKNOWN
# contract is owned by the shared primitives in uat-regression-lib.sh
# (helper_container_count, wait_no_helper_containers, inventory_count).
# "Cannot inspect" is never "clean".

residue_state() {
  local containers pins wlmac
  containers="$(helper_container_count)" || return 1
  pins="$(inventory_count /run/docker-helper/mounts)" || return 1
  wlmac="$(inventory_count /run/docker-helper/workload-mac)" || return 1
  printf 'containers=%s pins=%s wlmac=%s\n' "$containers" "$pins" "$wlmac"
}

residue_unchanged() {
  local base="$1" now
  now="$(residue_state)" || { printf '  residue inventory unavailable for the drift check\n' >&2; return 1; }
  [ "$now" = "$base" ] || { printf '  residue drift: before %s after %s\n' "$base" "$now" >&2; return 1; }
}

# workload_residue_clean asserts no transient/durable workload-MAC state
# remains. Exit status: 0 = clean, 1 = residue, 2 = inventory unavailable
# (never clean).
workload_residue_clean() {
  local runtime durable
  runtime="$(inventory_count /run/docker-helper/workload-mac)" || return 2
  durable="$(inventory_count /var/lib/docker-helper/workload-mac)" || return 2
  [ "$runtime" = "0" ] && [ "$durable" = "0" ]
}

create_session() {
  local cred="$1" ws="$2" out id
  out="$(dh session create --token-file "$cred" "$ws" --json 2>&1 || true)"
  id="$(printf '%s' "$out" | json_field id)"
  [ -n "$id" ] || { echo "session create failed for $ws: $(printf '%s' "$out" | redact | tail -2)" >&2; return 1; }
  printf '%s' "$out" | json_field token > "/tmp/uat-wls-tok-$id"; chmod 600 "/tmp/uat-wls-tok-$id"
  printf '%s' "$id"
}

expect_read_only_root() {
  local token="$1" source="$2" target="$3" snippet="$4" base="$5" out ec
  out="$(DOCKER_HELPER_SESSION_TOKEN="$token" \
    dh run --mount "$source:$target" alpine:3.24 -- sh -ec "$snippet" 2>&1)"
  ec=$?
  [ "$ec" -ne 0 ] || { printf '  writable request on %s unexpectedly succeeded\n' "$source" >&2; return 1; }
  printf '%s\n' "$out" | grep -q 'read_only_root' \
    || { printf '  refusal for %s is not read_only_root: %s\n' "$source" "$(printf '%s\n' "$out" | redact)" >&2; return 1; }
  residue_unchanged "$base"
}

# tree_context_snapshot prints the SELinux contexts of the acceptance tree so
# before/after equality is the no-relabel evidence.
tree_context_snapshot() {
  # The live workspace region is relabeled to docker_helper_workspace_t while
  # its Sessions exist (the designed workspace label, restored on delete);
  # the no-broad-relabel invariant therefore compares only the region
  # outside the workspace.
  find "$TREE" -path "$TREE/work" -prune -o -exec stat -c '%n %C' {} \; 2>/dev/null | sort
}

# wait_bindfs_projection PID — waits bounded while the background RO run with
# the given PID is in flight, for the packaged bindfs projection mount under
# the workload MAC runtime root. Prints the first observed projection
# evidence line ("<mountpoint> <context>") or nothing.
wait_bindfs_projection() {
  local bgpid="$1" _i=0 mp ctx
  for _i in $(seq 1 120); do
    mp="$(grep 'fuse.bindfs' /proc/mounts 2>/dev/null \
      | grep '/run/docker-helper/workload-mac/' | awk '{print $2}' | head -1 || true)"
    if [ -n "$mp" ] && [ -d "$mp" ]; then
      ctx="$(stat -c '%C' "$mp" 2>/dev/null | cut -d: -f3 || true)"
      printf '%s %s\n' "$mp" "$ctx"
      return 0
    fi
    if ! kill -0 "$bgpid" 2>/dev/null; then
      return 1
    fi
    sleep 0.25
  done
  return 1
}

# utab_watch BG_PID — pure-observer utab bookkeeping watcher. Runs while the
# canary run process is alive, ticking every 50ms, and records:
#   - every observation tick while a fuse.bindfs workload projection is live
#     (mountpoint observed from /proc/mounts), together with the FULL current
#     /run/mount/utab content;
#   - every /run/mount/utab content change even without a live projection;
#   - one settled capture after the run process exited (the projection
#     teardown completes around run completion).
# Output records:
#   obs tick=N projection_mounts=N mountpoint=<mp|none>   (+ full utab content)
#   settled mountpoint=<mp|none>                          (+ full utab content)
# The watcher NEVER mutates utab and grants no runtime-tree authority.
utab_watch() {
  local bgpid="$1" last="" tick=0 mp proj content
  while kill -0 "$bgpid" 2>/dev/null; do
    tick=$((tick + 1))
    mp="$(grep 'fuse.bindfs' /proc/mounts 2>/dev/null \
      | grep '/run/docker-helper/workload-mac/' | awk '{print $2}' | head -1 || true)"
    proj="$(grep 'fuse.bindfs' /proc/mounts 2>/dev/null | grep -c '/run/docker-helper/workload-mac/' || true)"
    content="$(cat /run/mount/utab 2>/dev/null || true)"
    if [ -n "$mp" ] || [ "$content" != "$last" ]; then
      printf 'obs tick=%s projection_mounts=%s mountpoint=%s\n' "$tick" "$proj" "${mp:-none}"
      if [ -n "$content" ]; then
        printf '%s\n' "$content" | sed 's/^/  utab| /'
      else
        echo "  utab| <empty>"
      fi
      last="$content"
    fi
    sleep 0.05
  done
  sleep 1
  mp="$(grep 'fuse.bindfs' /proc/mounts 2>/dev/null \
    | grep '/run/docker-helper/workload-mac/' | awk '{print $2}' | head -1 || true)"
  content="$(cat /run/mount/utab 2>/dev/null || true)"
  printf 'settled mountpoint=%s\n' "${mp:-none}"
  if [ -n "$content" ]; then
    printf '%s\n' "$content" | sed 's/^/  utab| /'
  else
    echo "  utab| <empty>"
  fi
}

cleanup() {
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  systemctl disable docker-helper.service >/dev/null 2>&1 || true
  rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper "$EVIDENCE_DIR"
}
trap cleanup EXIT

# ==============================================================================
# setup: enforcing SELinux, exact candidate RPM, confined system service
# ==============================================================================
say "setup: enforcing SELinux + exact candidate RPM + confined system service"
if [ "$(getenforce 2>/dev/null || true)" != "Enforcing" ]; then
  echo "error: SELinux is not enforcing (got: $(getenforce 2>/dev/null || true))" >&2
  exit 1
fi
acc_ok "SELinux enforcing"

if semodule -l 2>/dev/null | awk '$1 == "docker_helper" { found=1 } END { exit !found }' \
    && seinfo -t docker_helper_container_t 2>/dev/null | grep -q docker_helper_container_t \
    && seinfo -t docker_helper_ro_projection_t 2>/dev/null | grep -q docker_helper_ro_projection_t; then
  acc_ok "packaged docker_helper policy module loaded (container + ro_projection types)"
else
  echo "error: docker_helper policy module/types not loaded" >&2
  exit 1
fi

# Deterministic clean slate: the previous guest stage can leave the service
# active, failed, or in an auto-restart backoff, and a swallowed erase makes
# the candidate install hit "already installed". Stop, reset, erase, and
# prove the erase happened before installing.
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl reset-failed docker-helper.service >/dev/null 2>&1 || true
if rpm -q docker-helper >/dev/null 2>&1; then
  rpm -e docker-helper >/tmp/uat-wls-erase.log 2>&1 || true
  if rpm -q docker-helper >/dev/null 2>&1; then
    echo "error: candidate erase failed, package still installed: $(redact </tmp/uat-wls-erase.log | tail -3)" >&2
    exit 1
  fi
fi
rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper
# candidate_installed_ok verifies the FULL packaged install state: binary
# version, rpm record, and the loaded policy module. A scriptlet that fails
# late (e.g. a systemd daemon-reload/restart race) leaves a partially valid
# state that this verifier does not silently accept.
candidate_installed_ok() {
  [ "$(docker-helper version)" = "$VERSION" ] \
    && rpm -q docker-helper 2>/dev/null | grep -q "docker-helper-$RPM_VERSION" \
    && semodule -l 2>/dev/null | awk '$1 == "docker_helper" { found=1 } END { exit !found }'
}
# verifier_member_results reports each member's boolean state at the moment
# it is called (runs 7-9 showed the members passing in the evidence dump
# seconds AFTER the verifier had already failed, which cannot distinguish a
# flaky member from a verifier-context defect).
verifier_member_results() {
  local raw qrc prc rpm_out
  raw="$(docker-helper version 2>/dev/null || true)"
  rpm_out="$(rpm -q docker-helper 2>/dev/null || true)"
  rpm -q docker-helper >/dev/null 2>&1
  qrc=$?
  rpm -q docker-helper 2>/dev/null | grep -q "docker-helper-$RPM_VERSION"
  prc=$?
  printf '  verifier members now: version=%s rpm-record=%s(rpmrc=%s) policy-module=%s raw=[%s] piperc=%s\n' \
    "$([ "$raw" = "$VERSION" ] && echo yes || echo NO)" \
    "$(rpm -q docker-helper 2>/dev/null | grep -q "docker-helper-$RPM_VERSION" && echo yes || echo NO)" \
    "$qrc" \
    "$(semodule -l 2>/dev/null | awk '$1 == "docker_helper" { found=1 } END { exit !found }' && echo yes || echo NO)" \
    "$raw" \
    "$prc"
  printf '  verifier rpm detail: RPM_VERSION=[%s] rpm-out=[%s]\n' "$RPM_VERSION" "$rpm_out"
}
# wls_install_evidence dumps the complete bounded failure context for a
# candidate install that did not verify: the FULL non-trivial scriptlet log,
# each candidate_installed_ok member separately, the unit state, leftover
# containers from earlier guest stages, and the systemd journal window. A
# tail fragment of one error line is not enough to separate a scriptlet
# defect from a systemd-state artifact of the preceding guest stage.
wls_install_evidence() {
  echo "  --- install log (full, non-trivial) ---" >&2
  grep -v '^[[:space:]]*$' /tmp/uat-wls-install.log 2>/dev/null | redact | tail -30 >&2 || true
  echo "  --- erase log (tail) ---" >&2
  redact </tmp/uat-wls-erase.log 2>/dev/null | tail -5 >&2 || true
  echo "  --- verifier members: version / rpm -q / semodule ---" >&2
  echo "  version: $(docker-helper version 2>&1 || true)" >&2
  echo "  rpm -q: $(rpm -q docker-helper 2>&1 || true)" >&2
  echo "  semodule: $(semodule -l 2>&1 | grep -w docker_helper || echo '(module not listed)')" >&2
  echo "  --- unit state ---" >&2
  systemctl status docker-helper.service --no-pager 2>&1 | head -15 >&2 || true
  echo "  --- leftover containers ---" >&2
  docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null | tail -5 >&2 || true
  echo "  --- guest journal window (transient/scope/job/docker-helper) ---" >&2
  journalctl --since '-5 min' --no-pager 2>/dev/null \
    | grep -iE 'docker-helper|transient|scope|failed to start|Bad message' \
    | tail -40 | redact >&2 || true
}
if rpm -i "$RPM_PATH_IN" >/tmp/uat-wls-install.log 2>&1 && candidate_installed_ok; then
  acc_ok "exact candidate RPM installed (sha256 verified: $ACTUAL_SHA)"
else
  wls_install_evidence
  echo "  install attempt 1 evidence above" >&2
  # One bounded settle + retry for the known-flaky category: after heavy
  # package churn a systemd job-queue race can surface inside the RPM
  # scriptlet ("Failed to start transient service unit"). A healthy system
  # still installs on the retry; a persistent failure keeps the gate red.
  systemctl daemon-reload >/dev/null 2>&1 || true
  for _ in $(seq 1 15); do
    state="$(systemctl is-system-running 2>/dev/null || true)"
    case "$state" in running|degraded) break ;; esac
    sleep 1
  done
  if ! candidate_installed_ok; then
    verifier_member_results >&2
    rpm -e docker-helper >/dev/null 2>&1 || true
    rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper
    rpm -i "$RPM_PATH_IN" >/tmp/uat-wls-install.log 2>&1 || true
  fi
  # Bounded re-verification: the members' read-only checks (version, rpm
  # record, semodule listing) can transiently fail while the just-finished
  # postinst's policy store commit is still settling; run 7's evidence showed
  # every member passing moments after the verifier reported failure. A
  # stable pass is accepted; a genuinely broken install keeps failing all
  # attempts and the gate stays red.
  candidate_verified=""
  for _ in 1 2 3; do
    if candidate_installed_ok; then
      candidate_verified=yes
      break
    fi
    verifier_member_results >&2
    sleep 2
  done
  if [ -n "$candidate_verified" ]; then
    acc_ok "exact candidate RPM installed (sha256 verified: $ACTUAL_SHA; transient systemd scriptlet hiccup recovered)"
  else
    echo "error: candidate RPM install/version check failed after settle + retry:" >&2
    wls_install_evidence
    echo "error: systemd state: $(systemctl is-system-running 2>&1 || true)" >&2
    exit 1
  fi
fi

# The principal's home must sit under the global allowed root (2.2 contract),
# so this acceptance tree lives under /home/opc. Non-home fcontext lifecycle
# remains owned by the targeted SELinux regression groups.
if dh init --allowed-root "$ALLOWED_ROOT" >/tmp/uat-wls-init.log 2>&1; then
  acc_ok "system init (global ceiling: $ALLOWED_ROOT)"
  dh config allowed-root list 2>/dev/null | sed 's/^/  config-roots: /' >&2 || true
else
  printf '  init output: %s\n' "$(redact </tmp/uat-wls-init.log)" >&2
  echo "error: docker-helper init failed" >&2
  exit 1
fi
systemctl daemon-reload || { echo "error: daemon-reload failed" >&2; exit 1; }
systemctl enable --now docker-helper.service >/dev/null 2>&1 \
  || { echo "error: enable --now failed" >&2; exit 1; }
for _ in $(seq 1 30); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
systemctl is-active --quiet docker-helper.service || { echo "error: service not active" >&2; exit 1; }
DH_PID="$(systemctl show -p MainPID --value docker-helper.service)"
DH_LABEL="$(tr -d '\0' < "/proc/$DH_PID/attr/current" 2>/dev/null || true)"
case "$DH_LABEL" in
  *:docker_helper_t:*) acc_ok "candidate daemon confined (docker_helper_t)" ;;
  docker_helper_t:*) acc_ok "candidate daemon confined (docker_helper_t)" ;;
  *) echo "error: daemon process label is not docker_helper_t: '$DH_LABEL'" >&2; exit 1 ;;
esac
wait_health || { echo "error: API socket not ready" >&2; exit 1; }
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
[ -n "$ADMIN_TOKEN" ] || { echo "error: could not read the admin token" >&2; exit 1; }

docker pull alpine:3.24 >/dev/null 2>&1 || true
docker pull alpine:3.19 >/dev/null 2>&1 || true

# ---- fixture: policy tree with one RO region ---------------------------------
# One global ceiling (dh init takes a single --allowed-root): it must contain
# the principal's home (2.2 principal-home contract), so the tree lives under
# /home/opc. Non-home fcontext lifecycle stays with the targeted regressions.
TREE="/home/opc/uat-wl-tree"
rm -rf "$TREE"
mkdir -p "$TREE/work" "$TREE/work/project" "$TREE/work/pipeline-inputs"
printf 'project-file\n' > "$TREE/work/project/keep.txt"
printf 'ro-input\n' > "$TREE/work/pipeline-inputs/input.txt"
chown -R "$PRINCIPAL:$PRINCIPAL" "$TREE"
chmod -R u+rwX,go+rX "$TREE"
TREE_CTX_BEFORE="$(tree_context_snapshot)"
# Fail-closed inventory contract: the no-relabel baseline must be a
# positively observed context snapshot; an unavailable context inventory
# (stat/find failure) collapses before and after to equal empties and must
# never read as "unchanged".
if [ -z "$TREE_CTX_BEFORE" ]; then
  echo "error: acceptance-tree context inventory is empty (stat/find failed); S11 no-relabel evidence is unavailable" >&2
  exit 2
fi

dh principal create --no-credential "$PRINCIPAL" 2>/tmp/uat-wls-setup.err || {
  echo "error: principal create failed: $(redact </tmp/uat-wls-setup.err | tail -3)" >&2; exit 1; }
dh principal set "$PRINCIPAL" enabled true 2>>/tmp/uat-wls-setup.err || true
dh principal allowed-root add "$PRINCIPAL" "$TREE" 2>>/tmp/uat-wls-setup.err || {
  echo "error: principal TREE root add failed: $(redact </tmp/uat-wls-setup.err | tail -3)" >&2; exit 1; }
dh principal allowed-root add --access read_only "$PRINCIPAL" "$TREE/work/pipeline-inputs" 2>>/tmp/uat-wls-setup.err || {
  echo "error: principal pipeline-inputs root add failed: $(redact </tmp/uat-wls-setup.err | tail -3)" >&2; exit 1; }
MAIN_L_JSON="$(dh launcher create --principal "$PRINCIPAL" main --no-credential --json 2>>/tmp/uat-wls-setup.err || true)"
MAIN_L_ID="$(printf '%s' "$MAIN_L_JSON" | json_field id)"
[ -n "$MAIN_L_ID" ] || { echo "error: launcher create failed: $MAIN_L_JSON ($(redact </tmp/uat-wls-setup.err | tail -10))" >&2; exit 1; }
MAIN_LC_OUT="$(dh launcher credential create --principal "$PRINCIPAL" --json "$MAIN_L_ID" 2>/dev/null || true)"
MAIN_LC_TOKEN="$(printf '%s' "$MAIN_LC_OUT" | json_field token)"
[ -n "$MAIN_LC_TOKEN" ] || { echo "error: launcher credential create failed" >&2; exit 1; }
printf '%s\n' "$MAIN_LC_TOKEN" > /tmp/uat-wls-cred-main; chmod 600 /tmp/uat-wls-cred-main
WSA_ID="$(create_session /tmp/uat-wls-cred-main "$TREE/work")" \
  || { echo "error: acceptance session creation failed" >&2; exit 1; }
WSA_TOKEN="$(cat "/tmp/uat-wls-tok-$WSA_ID")"
acc_ok "acceptance session $WSA_ID with mixed policy tree"

# The audit window starts now.
AUDIT_START_EPOCH="$(date +%s)"

# ==============================================================================
# DIAGNOSTIC S2M (test-harness only; runs BEFORE S1/S2 so the pre-state is
# pristine): libfuse mtab/utab bookkeeping on the shipped policy.
# The shipped policy deliberately does NOT grant mount_var_run_t:file write.
# The Step-7 experiment (branch diag/ro-selinux-utab-write, run 37832314572)
# proved the denied { write } (comm="mount", name=utab, run 37784360967) is
# libmount's WRITABILITY PROBE (try_write(): eaccess(R_OK|W_OK)) and that the
# record write never happens either way: the bindfs projection mount carries
# no userspace mount options, so utab_new_entry() declares the entry
# unnecessary. The shipped policy therefore SUPPRESSES the probe with
#   dontaudit docker_helper_t mount_var_run_t:file write;
# (no authority change; the check stays denied). This block's mandatory
# acceptance:
#   (1) the utab pre-state (existence, label, mode, full content);
#   (2) the live RO projection works with /run/mount/utab present: the canary
#       run exits 0, reads the marker through the bindfs projection, and the
#       terminal status (via the canary session's own bearer) is succeeded;
#   (3) the utab state after the run completed normally (the canary's own
#       record count after the unmount is OBSERVATIONAL evidence, not an
#       error: the bookkeeping writes no entry for this mount);
#   (4) every pre-existing (foreign) utab line survives byte-exact — no
#       corruption by any bookkeeping rewrite;
#   (5) no utab AVC in the canary window (the dontaudit suppression) and no
#       residue: canary session deleted, containers/pins/wlmac unchanged;
#   (6) exact restore of the VM's pre-state: the utab pre-state is captured
#       as a REAL FILE COPY and compared byte-for-byte — a Bash command
#       substitution strips trailing newlines, so byte-exactness is decided
#       on the file, never on a captured string.
# This block only: (1) captures the guest pre-state; (2) creates
# /run/mount/utab with the policy-default label ONLY when absent, seeding one
# syntactically valid foreign utab record (canonical libmount field order, an
# inert marker never acted upon by libmount) so the foreign-integrity proof is
# real rather than vacuous; (3) runs EXACTLY ONE fresh RO canary through the
# production CLI while a pure-observer watcher records the projection
# liveness and the full utab content timeline; (4) dumps synchronized
# evidence; (5) restores exactly what it created. No executable is
# substituted. A reproduced canary failure, corrupted foreign entries, an
# utab AVC, or a failed restore are reported through acc_fail (RED).
# ==============================================================================
say "S2M: mtab/utab pre-state + one fresh RO canary with the utab observation (harness-only diagnostic)"
CANARY_UTAB_CREATED=0
CANARY_MOUNT_DIR_CREATED=0
CANARY_SID=""
CANARY_OP_ID=""
CANARY_ST=""
CANARY_EC=0
UTAB_PRE_EXISTED=0
UTAB_PRE_CONTENT=""
UTAB_POST_CONTENT=""
UTAB_WATCH_LOG=/tmp/uat-wls-utab-watch.log
# Byte-exact restore verification: the pre-state is captured as a REAL FILE
# COPY and compared byte-for-byte on the files — with the cmp-free
# files_identical primitive (sha256sum; cmp is absent from the minimal
# openSUSE Tumbleweed cloud image, the same reason
# scripts/uat-install-tarball.sh owns this primitive). Bash command
# substitution strips trailing newlines, so a captured string can never
# decide byte-exactness.
UTAB_PRE_COPY=/tmp/uat-wls-utab-pre-copy
files_identical() {
  local a="$1" b="$2"
  [ "$(sha256sum "$a" | awk '{print $1}')" = "$(sha256sum "$b" | awk '{print $1}')" ]
}
# Inert foreign utab record in the canonical libmount utab writer field order
# (ID UNIQID SRC TARGET ROOT BINDSRC ATTRS OPTS; the unset fields omitted), so
# the seeded line round-trips libmount's parse+rewrite byte-exactly.
S2M_FOREIGN_UTAB_LINE='ID=4242 UNIQID=20990101 SRC=/uat-s2m-foreign-src TARGET=/uat-s2m-foreign-target OPTS=foreign-opt'
echo "  --- S2M pre-state: packages and linkage ---"
rpm -q bindfs fuse3 fuse3-libs util-linux 2>&1 | sed 's/^/  rpm-q: /' || true
ldd /usr/bin/bindfs 2>&1 | sed 's/^/  ldd: /' || true
echo "  --- S2M pre-state: mtab/utab/mount files ---"
ls -lZ /etc/mtab /run/mount /run/mount/utab /bin/mount 2>&1 | sed 's/^/  ls-lZ: /' || true
stat -c '%F %a %U:%G %n' /etc/mtab /run/mount/utab 2>&1 | sed 's/^/  stat: /' || true
echo "  readlink -f /etc/mtab:  $(readlink -f /etc/mtab 2>&1)"
echo "  readlink -f /bin/mount: $(readlink -f /bin/mount 2>&1)"
echo "  readlink -f /bin/umount: $(readlink -f /bin/umount 2>&1)"
test -w /etc/mtab
CANARY_MTAB_W=$?
echo "  mtab_writable=$CANARY_MTAB_W"
ls -lZ /bin/umount 2>&1 | sed 's/^/  ls-lZ: /' || true
echo "  matchpathcon /run/mount/utab: $(matchpathcon /run/mount/utab 2>&1 || true)"
if [ -e /run/mount/utab ]; then
  echo "  utab: PRE-EXISTING before S2 (the canary leaves it untouched)"
  UTAB_PRE_EXISTED=1
  cp -p /run/mount/utab "$UTAB_PRE_COPY"
  UTAB_PRE_CONTENT="$(cat /run/mount/utab 2>/dev/null || true)"
  UTAB_PRE_LINES="$(printf '%s\n' "$UTAB_PRE_CONTENT" | grep -c . 2>/dev/null || true)"
  [ -n "$UTAB_PRE_LINES" ] || UTAB_PRE_LINES=0
  echo "  utab pre-state content ($UTAB_PRE_LINES non-empty lines; byte-exact copy at $UTAB_PRE_COPY):"
  if [ -n "$UTAB_PRE_CONTENT" ]; then
    printf '%s\n' "$UTAB_PRE_CONTENT" | sed 's/^/  utab| /'
  else
    echo "  utab| <empty>"
  fi
else
  CANARY_UTAB_CREATED=1
  if [ ! -d /run/mount ]; then
    mkdir -p /run/mount && restorecon /run/mount 2>/dev/null || true
    CANARY_MOUNT_DIR_CREATED=1
  fi
  printf '%s\n' "$S2M_FOREIGN_UTAB_LINE" > /run/mount/utab
  chmod 644 /run/mount/utab
  restorecon /run/mount/utab 2>/dev/null || true
  echo "  utab: ABSENT before S2 - created for the canary with one inert foreign record ($(stat -c '%A %U:%G %C' /run/mount/utab 2>&1))"
  echo "  utab| $S2M_FOREIGN_UTAB_LINE"
  UTAB_PRE_CONTENT="$S2M_FOREIGN_UTAB_LINE"
fi
CANARY_SID="$(create_session /tmp/uat-wls-cred-main "$TREE/work")" \
  || { echo "error: canary session creation failed" >&2; exit 1; }
CANARY_TOKEN="$(cat "/tmp/uat-wls-tok-$CANARY_SID")"
mkdir -p "$TREE/work/canary-ro"
printf 'canary-ro-marker\n' > "$TREE/work/canary-ro/marker.txt"
S2M_RESIDUE_BASE="$(residue_state || true)"
: > "$UTAB_WATCH_LOG"
echo "  --- S2M canary: exactly one fresh RO run (fresh session $CANARY_SID) ---"
DOCKER_HELPER_SESSION_TOKEN="$CANARY_TOKEN" \
  dh run --mount canary-ro:/mnt/canary:ro alpine:3.24 -- \
  sh -ec 'cat /mnt/canary/marker.txt' >/tmp/uat-wls-s2m-run.log 2>&1 &
CANARY_BG_PID=$!
utab_watch "$CANARY_BG_PID" >>"$UTAB_WATCH_LOG" 2>&1 &
UTAB_WATCH_PID=$!
CANARY_PROJ_EVIDENCE="$(wait_bindfs_projection "$CANARY_BG_PID" || true)"
wait "$CANARY_BG_PID"
CANARY_EC=$?
wait "$UTAB_WATCH_PID"
echo "  canary run exit code: $CANARY_EC"
echo "  canary projection during run: ${CANARY_PROJ_EVIDENCE:-<none observed>}"
CANARY_OP_ID="$(journalctl --utc -u docker-helper.service --no-pager 2>/dev/null \
  | grep '"event":"run.start"' \
  | grep "\"session_id\":\"$CANARY_SID\"" \
  | tail -1 | grep -oP '"operation_id":"\K[^"]+' || true)"
echo "  canary operation id: ${CANARY_OP_ID:-<none: no admitted run.start for the canary session>}"
if [ -n "$CANARY_OP_ID" ]; then
  # GET /operations/{id} is session-bearer-authorized: the canary's OWN
  # session bearer must be presented, or the call fails with
  # auth.failure/session.parse_failed and the status reads <unreadable>.
  CANARY_ST="$(curl --silent --max-time 2 --unix-socket "$SOCK" \
    -H "Authorization: Bearer $CANARY_TOKEN" \
    "http://localhost/operations/$CANARY_OP_ID" 2>/dev/null | json_field status || true)"
  echo "  canary terminal status: ${CANARY_ST:-<unreadable>}"
fi
echo "  --- S2M canary run output (full, redacted) ---"
redact </tmp/uat-wls-s2m-run.log 2>/dev/null | sed 's/^/  run: /' || true
echo "  --- S2M utab watch: full timeline (projection liveness + every utab content change) ---"
sed 's/^/  watch: /' "$UTAB_WATCH_LOG" 2>/dev/null || true
UTAB_POST_CONTENT="$(cat /run/mount/utab 2>/dev/null || true)"
echo "  --- S2M utab post-state content ---"
if [ -n "$UTAB_POST_CONTENT" ]; then
  printf '%s\n' "$UTAB_POST_CONTENT" | sed 's/^/  utab| /'
else
  echo "  utab| <empty>"
fi
echo "  --- S2M effective policy under test (setuid / mount_exec_t / mount_var_run_t) ---"
sesearch -A -s docker_helper_t -t docker_helper_t -c capability 2>&1 | sed 's/^/  sesearch: /' || true
sesearch -A -s docker_helper_t -t mount_exec_t -c file 2>&1 | sed 's/^/  sesearch: /' || true
sesearch -A -s docker_helper_t -t mount_var_run_t 2>&1 | sed 's/^/  sesearch: /' || true
echo "  sesearch (dontaudit): $(sesearch --dontaudit -s docker_helper_t -t mount_var_run_t 2>&1 || true)"
# semodule -c -E writes the extracted CIL as a REAL FILE (docker_helper.cil)
# in the working directory and only prints a status line on stdout ("Extracting
# at highest existing priority ..."). The exported-CIL check therefore runs in
# a controlled directory and reads that real file; grepping stdout reads only
# the status line and reports a false "no rule in the exported CIL".
CIL_EXPORT_DIR="$(mktemp -d /tmp/uat-wls-cil.XXXXXX)"
( cd "$CIL_EXPORT_DIR" && semodule -c -E docker_helper ) >"$CIL_EXPORT_DIR/export.stdout" 2>"$CIL_EXPORT_DIR/export.stderr" || true
echo "  cil: export stdout: $(tr '\n' ' ' <"$CIL_EXPORT_DIR/export.stdout" 2>/dev/null) stderr: $(tr '\n' ' ' <"$CIL_EXPORT_DIR/export.stderr" 2>/dev/null)"
if [ -f "$CIL_EXPORT_DIR/docker_helper.cil" ]; then
  echo "  cil: exported real CIL file: $CIL_EXPORT_DIR/docker_helper.cil ($(wc -c <"$CIL_EXPORT_DIR/docker_helper.cil") bytes)"
  CIL_HITS="$(grep -E "setuid|mount_exec|mount_var_run" "$CIL_EXPORT_DIR/docker_helper.cil" 2>/dev/null || true)"
  if [ -n "$CIL_HITS" ]; then
    printf '%s\n' "$CIL_HITS" | sed 's/^/  cil: /'
  else
    echo "  cil: no setuid/mount_exec/mount_var_run rule in the exported CIL file"
  fi
else
  echo "  cil: exported CIL file missing in $CIL_EXPORT_DIR:"
  ls -la "$CIL_EXPORT_DIR" 2>&1 | sed 's/^/  cil:   /' || true
fi
rm -rf "$CIL_EXPORT_DIR"
echo "  --- S2M post-run projection/worker/retained-state inventory ---"
grep 'fuse.bindfs' /proc/mounts 2>/dev/null | sed 's/^/  mounts: /' || echo "  mounts: no fuse.bindfs mounts"
ps -eZ 2>/dev/null | grep -E 'bindfs' | sed 's/^/  ps: /' || echo "  ps: no bindfs workers"
ls -la /run/docker-helper/workload-mac 2>&1 | tail -10 | sed 's/^/  wlmac-runtime: /' || true
ls -la /var/lib/docker-helper/workload-mac 2>&1 | tail -10 | sed 's/^/  wlmac-durable: /' || true
residue_state | sed 's/^/  residue: /' || true
echo "  --- S2M journal + AVC window (audit-window start epoch $AUDIT_START_EPOCH) ---"
S2M_AUDIT_START_ISO="$(date -u -d "@${AUDIT_START_EPOCH}" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || true)"
journalctl --utc -u docker-helper.service --no-pager 2>/dev/null \
  | awk -v start="${S2M_AUDIT_START_ISO:-}" '
      /"time":"/ {
        if (match($0, /"time":"[^"]*"/)) {
          t = substr($0, RSTART + 8, RLENGTH - 9)
          if (start == "" || t >= start) print
        }
      }' 2>/dev/null \
  | grep -iE 'bindfs|mount|avc|denied|error|fail|operation' \
  | tail -120 | redact | sed 's/^/  journal: /' || true
S2M_AVC_DATE="$(date -d "@$AUDIT_START_EPOCH" '+%m/%d/%Y %H:%M:%S' 2>/dev/null || true)"
S2M_AVC_WINDOW="$(ausearch -m AVC -ts "$S2M_AVC_DATE" 2>/dev/null || true)"
if [ -z "$S2M_AVC_WINDOW" ] && [ -f /var/log/audit/audit.log ]; then
  S2M_AVC_WINDOW="$(awk -v start="$AUDIT_START_EPOCH" '
    match($0, /audit\(([0-9]+)\./, m) { if (m[1] + 0 >= start + 0) print }
  ' /var/log/audit/audit.log 2>/dev/null || true)"
fi
if [ -n "$S2M_AVC_WINDOW" ]; then
  printf '%s\n' "$S2M_AVC_WINDOW" | redact | sed 's/^/  avc: /' || true
else
  echo "  avc: no AVC records in the canary window"
fi
echo "  --- S2M post-state: mtab/utab after the canary ---"
ls -lZ /etc/mtab /run/mount/utab 2>&1 | sed 's/^/  ls-lZ: /' || true
stat -c '%F %a %U:%G %n' /etc/mtab /run/mount/utab 2>&1 | sed 's/^/  stat: /' || true
echo "  --- S2M utab bookkeeping verdict ---"
CANARY_MP="$(awk '/^obs tick=/ { mp=$0; sub(/^.*mountpoint=/, "", mp); if (mp != "none") { print mp; exit } }' "$UTAB_WATCH_LOG" 2>/dev/null || true)"
echo "  canary projection mountpoint: ${CANARY_MP:-<none observed>}"
UTAB_DURING_HITS="$(awk -v want="TARGET=$CANARY_MP" '
  /^obs tick=/ { live = ($0 ~ /mountpoint=none$/ ? 0 : 1); next }
  /^settled mountpoint=/ { live = ($0 ~ /mountpoint=none$/ ? 0 : 1); next }
  live && want != "TARGET=" && index($0, want) { hits++ }
  END { printf "%d", hits + 0 }
' "$UTAB_WATCH_LOG" 2>/dev/null || echo 0)"
echo "  utab bookkeeping records for the canary mount observed during the live projection: $UTAB_DURING_HITS"
UTAB_STALE_COUNT=0
if [ -n "$CANARY_MP" ]; then
  UTAB_STALE_COUNT="$(printf '%s\n' "$UTAB_POST_CONTENT" | grep -Fc "TARGET=$CANARY_MP" 2>/dev/null || true)"
  [ -n "$UTAB_STALE_COUNT" ] || UTAB_STALE_COUNT=0
fi
echo "  utab canary-entry records after normal completion: $UTAB_STALE_COUNT (0 = removed/never written; >0 = the record persists after the helper-owned unmount)"
UTAB_FOREIGN_LOST=0
if [ "$UTAB_PRE_EXISTED" -eq 1 ]; then
  while IFS= read -r _l; do
    [ -n "$_l" ] || continue
    printf '%s\n' "$UTAB_POST_CONTENT" | grep -Fxq "$_l" || UTAB_FOREIGN_LOST=$((UTAB_FOREIGN_LOST + 1))
  done <<< "$UTAB_PRE_CONTENT"
else
  if [ -n "$UTAB_POST_CONTENT" ]; then
    printf '%s\n' "$UTAB_POST_CONTENT" | grep -Fxq "$S2M_FOREIGN_UTAB_LINE" || UTAB_FOREIGN_LOST=1
  else
    UTAB_FOREIGN_LOST=1
  fi
fi
if [ "$UTAB_FOREIGN_LOST" -eq 0 ]; then
  echo "  ok:      utab foreign entries intact after the canary (no corruption)"
else
  echo "  FAIL:    utab foreign entries lost or changed by the bookkeeping rewrite: $UTAB_FOREIGN_LOST line(s)" >&2
fi
echo "  --- S2M restore: remove exactly what the canary created ---"
CANARY_FAIL_REASON=""
[ "$CANARY_EC" -ne 0 ] && CANARY_FAIL_REASON="run exit $CANARY_EC"
if [ -n "$CANARY_ST" ] && [ "$CANARY_ST" != "succeeded" ]; then
  CANARY_FAIL_REASON="$CANARY_FAIL_REASON terminal-status=$CANARY_ST"
fi
if grep -q 'Permission denied' /tmp/uat-wls-s2m-run.log 2>/dev/null; then
  CANARY_FAIL_REASON="$CANARY_FAIL_REASON 'Permission denied' present in run output"
fi
# The absence of the canary's own utab record is NOT an error: the shipped
# policy deliberately does not grant mount_var_run_t:file write and the
# Step-7 experiment proved the bookkeeping writes no entry for this mount
# either way. The during/stale counts stay observational evidence only.
if [ "$UTAB_FOREIGN_LOST" -ne 0 ]; then
  CANARY_FAIL_REASON="$CANARY_FAIL_REASON utab-foreign-entry-corruption($UTAB_FOREIGN_LOST)"
fi
if [ "$CANARY_UTAB_CREATED" = 1 ]; then
  rm -f /run/mount/utab
  if [ "$CANARY_MOUNT_DIR_CREATED" = 1 ]; then
    rmdir /run/mount 2>/dev/null || true
  fi
  echo "  restore: canary-created /run/mount/utab removed (pre-existing state restored)"
else
  if [ -n "$CANARY_MP" ] && [ "$UTAB_STALE_COUNT" -gt 0 ]; then
    sed -i "\#TARGET=$CANARY_MP#d" /run/mount/utab 2>/dev/null || true
    echo "  restore: the canary's own utab record(s) removed from the pre-existing file ($UTAB_STALE_COUNT line(s))"
  else
    echo "  restore: utab was pre-existing - left untouched"
  fi
fi
rm -rf "$TREE/work/canary-ro"
CANARY_DELETE_RC=0
dh session delete --token-file /tmp/uat-wls-cred-main "$CANARY_SID" >/dev/null 2>&1 || CANARY_DELETE_RC=$?
echo "  restore: canary session $CANARY_SID delete rc=$CANARY_DELETE_RC"
# Restore verification: the VM's utab state must equal the pre-state,
# byte-exact, decided on the real files with files_identical (command
# substitution strips trailing newlines; a captured string can never prove
# byte-exactness).
if [ "$CANARY_UTAB_CREATED" = 1 ]; then
  if [ -e /run/mount/utab ]; then
    CANARY_FAIL_REASON="$CANARY_FAIL_REASON utab-restore-left-the-canary-file-behind"
  else
    echo "  restore: /run/mount/utab absent again (the pre-existing state)"
  fi
else
  if files_identical "$UTAB_PRE_COPY" /run/mount/utab; then
    echo "  restore: utab byte-identical to the pre-state (files_identical)"
  else
    CANARY_FAIL_REASON="$CANARY_FAIL_REASON utab-restore-differs-from-the-pre-state"
  fi
fi
rm -f "$UTAB_PRE_COPY"
# No residue: the helper-owned containers/pins/workload-MAC state must be
# exactly what it was before the canary. An unavailable inventory is never
# "clean" (fail-closed).
if [ -z "$S2M_RESIDUE_BASE" ]; then
  CANARY_FAIL_REASON="$CANARY_FAIL_REASON s2m-residue-inventory-unavailable"
elif residue_unchanged "$S2M_RESIDUE_BASE"; then
  echo "  restore: residue unchanged ($S2M_RESIDUE_BASE)"
else
  CANARY_FAIL_REASON="$CANARY_FAIL_REASON s2m-residue-drift"
fi
residue_state | sed 's/^/  residue-after-restore: /' || true
if [ -n "$CANARY_FAIL_REASON" ]; then
  acc_fail "S2M mtab-path canary RED: $CANARY_FAIL_REASON (full evidence above; hypothesis chain reproduced)"
else
  # The canary is a mandatory acceptance scenario, not an informational
  # note: with the mtab/utab preconditions satisfied, the fresh RO run must
  # succeed through the bindfs projection on the shipped policy (whose
  # dontaudit suppresses the writability probe), the foreign utab entries
  # must survive untouched, and the exact restore must hold. The absence of
  # the canary's own utab record is the proven no-entry behavior, never an
  # error.
  acc_ok "S2M mtab-path canary green: fresh RO exposure readable through the bindfs projection with /run/mount/utab present, no utab AVC (probe suppressed by dontaudit), foreign entries intact, exact restore"
fi

# ==============================================================================
# scenario S1: RW exposure is really writable
# ==============================================================================
say "S1: RW exposure really writable"
if DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
    dh run --mount project:/mnt/project alpine:3.24 -- \
    sh -ec 'echo s1-write > /mnt/project/written.txt && cat /mnt/project/keep.txt' >/tmp/uat-wls-s1.log 2>&1 \
    && [ "$(cat "$TREE/work/project/written.txt" 2>/dev/null)" = "s1-write" ]; then
  acc_ok "S1 RW exposure mounted writable and the write persisted"
else
  acc_fail "S1 RW exposure write failed: $(redact </tmp/uat-wls-s1.log | tail -3)"
fi

# ==============================================================================
# scenario S2: RO exposure is readable
# ==============================================================================
say "S2: RO exposure readable"
S2_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --mount pipeline-inputs:/mnt/inputs:ro alpine:3.24 -- \
  sh -ec 'test "$(cat /mnt/inputs/input.txt)" = "ro-input" && echo S2-RO-READ-OK' 2>&1)"
if printf '%s\n' "$S2_OUT" | grep -q 'S2-RO-READ-OK'; then
  acc_ok "S2 RO exposure readable (bindfs projection path)"
else
  acc_fail "S2 RO read failed: $(printf '%s\n' "$S2_OUT" | redact | tail -3)"
fi

# ==============================================================================
# scenario S3: RO exposure is immutable
# ==============================================================================
say "S3: RO exposure immutable"
DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --mount pipeline-inputs:/mnt/inputs:ro alpine:3.24 -- \
  sh -ec 'echo forbidden > /mnt/inputs/forbidden.txt' >/dev/null 2>&1
S3_EC=$?
if [ "$S3_EC" -ne 0 ] && [ ! -e "$TREE/work/pipeline-inputs/forbidden.txt" ]; then
  acc_ok "S3 RO write denied and the host file was not created"
else
  acc_fail "S3 RO exposure immutability broken (ec=$S3_EC)"
fi

# ==============================================================================
# scenario S4: mixed RW + RO exposures work independently in one workload
# ==============================================================================
say "S4: mixed RW + RO in one workload"
S4_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --mount project:/mnt/project --mount pipeline-inputs:/mnt/inputs:ro alpine:3.24 -- \
  sh -ec 'echo s4-write > /mnt/project/written.txt; test "$(cat /mnt/inputs/input.txt)" = "ro-input" || exit 3; if echo x > /mnt/inputs/forbidden.txt 2>/dev/null; then exit 4; fi; echo S4-MIXED-OK' 2>&1)"
S4_EC=$?
if [ "$S4_EC" -eq 0 ] && printf '%s\n' "$S4_OUT" | grep -q 'S4-MIXED-OK' \
    && [ "$(cat "$TREE/work/project/written.txt" 2>/dev/null)" = "s4-write" ] \
    && [ ! -e "$TREE/work/pipeline-inputs/forbidden.txt" ]; then
  acc_ok "S4 mixed RW+RO exposures independent in one workload"
else
  acc_fail "S4 mixed workload failed (ec=$S4_EC): $(printf '%s\n' "$S4_OUT" | redact | tail -3)"
fi

# ==============================================================================
# scenario S5: writable parent over nested RO refused before workload creation
# ==============================================================================
say "S5: writable parent over nested RO refused before workload creation"
if S5_BASE="$(residue_state)"; then
  if expect_read_only_root "$WSA_TOKEN" . /mnt/tree 'echo x > /mnt/tree/pipeline-inputs/x.txt' "$S5_BASE"; then
    acc_ok "S5 writable parent refused with read_only_root before MAC/container creation"
  else
    acc_fail "S5 writable parent refusal wrong (base: $S5_BASE)"
  fi
else
  acc_blocked "S5 residue inventory unavailable for the no-state baseline"
fi

# ==============================================================================
# scenario SE: external Session filesystem roots under the SELinux backend —
# the Session issues an external read-only root and an external read-write
# root through the absolute --filesystem-root grammar and mounts them through
# the same exposure/pin/projection owners as the workspace itself: the
# external RO root gets the read-only projection (writes denied, readable
# through it), the external RW root stays writable, and cleanup leaves no
# projections/pins/state.
# ==============================================================================
say "SE: external Session filesystem roots under the SELinux backend"

SE_OPT="/opt/$PRINCIPAL"
SE_HELPER="$SE_OPT/repos/helper"
SE_CACHE="$SE_OPT/cache"
rm -rf "$SE_OPT"
mkdir -p "$SE_HELPER" "$SE_CACHE"
printf 'se-helper-src\n' > "$SE_HELPER/main.go"
printf 'seed\n' > "$SE_CACHE/seed.txt"
chown -R "$PRINCIPAL:$PRINCIPAL" "$SE_OPT"
chmod -R u+rwX,go+rX "$SE_OPT"
if dh config allowed-root add --access read_write "$SE_OPT" >/dev/null 2>&1 \
    && dh principal allowed-root add --access read_write "$PRINCIPAL" "$ALLOWED_ROOT" >/dev/null 2>&1 \
    && dh principal allowed-root add --access read_write "$PRINCIPAL" "$SE_OPT" >/dev/null 2>&1; then
  acc_ok "SE setup: second effective root $SE_OPT (global RW + Principal RW)"
else
  acc_fail "SE setup: second effective root setup failed"
fi
SE_L_JSON="$(dh launcher create --principal "$PRINCIPAL" se-multiroot --no-credential --json 2>/dev/null || true)"
SE_L_ID="$(printf '%s' "$SE_L_JSON" | json_field id)"
if [ -n "$SE_L_ID" ] \
    && dh launcher allowed-root add --principal "$PRINCIPAL" "$SE_L_ID" "$ALLOWED_ROOT" >/dev/null 2>&1 \
    && dh launcher allowed-root add --principal "$PRINCIPAL" "$SE_L_ID" "$SE_OPT" >/dev/null 2>&1; then
  acc_ok "SE setup: multiroot launcher carries both effective roots"
else
  acc_fail "SE setup: multiroot launcher setup failed: $SE_L_JSON"
fi
SE_LC_OUT="$(dh launcher credential create --principal "$PRINCIPAL" --json "$SE_L_ID" 2>/dev/null || true)"
SE_LC_TOKEN="$(printf '%s' "$SE_LC_OUT" | json_field token)"
if [ -n "$SE_LC_TOKEN" ]; then
  printf '%s\n' "$SE_LC_TOKEN" > /tmp/uat-wls-cred-multiroot; chmod 600 /tmp/uat-wls-cred-multiroot
else
  echo "error: SE launcher credential create failed" >&2; exit 1
fi
SE_WS="$ALLOWED_ROOT/se-runs/run-123"
rm -rf "$ALLOWED_ROOT/se-runs"
mkdir -p "$SE_WS"
chown -R "$PRINCIPAL:$PRINCIPAL" "$ALLOWED_ROOT/se-runs"
chmod -R u+rwX,go+rX "$ALLOWED_ROOT/se-runs"
SE_OUT="$(dh session create --token-file /tmp/uat-wls-cred-multiroot \
  "$SE_WS" --json \
  --filesystem-root "$SE_HELPER=read_only" \
  --filesystem-root "$SE_CACHE=read_write" 2>&1 || true)"
SE_ID="$(printf '%s' "$SE_OUT" | json_field id)"
if [ -n "$SE_ID" ]; then
  printf '%s' "$SE_OUT" | json_field token > "/tmp/uat-wls-tok-$SE_ID"; chmod 600 "/tmp/uat-wls-tok-$SE_ID"
  SE_TOKEN="$(cat "/tmp/uat-wls-tok-$SE_ID")"
  acc_ok "SE multi-root Session created (external helper RO + cache RW)"
else
  acc_fail "SE multi-root session create failed: $(printf '%s\n' "$SE_OUT" | redact | tail -3)"
fi

# SE-RO: the external RO root is projected read-only (bindfs path): reads
# succeed through the projection and the writable attempt is denied with the
# host file not created. The readonly bind participates in the ordinary run
# (production defense in depth), so the independent backend-only denial of
# the external source — projection VFS writable underneath, the projection
# type itself the refuser — is proven by the S13 external-root live proof.
SE_RO="$(DOCKER_HELPER_SESSION_TOKEN="$SE_TOKEN" \
  dh run --mount "$SE_HELPER:/helper:ro" alpine:3.24 -- \
  sh -ec 'test "$(cat /helper/main.go)" = "se-helper-src" && echo SE-RO-READ-OK' 2>&1)"
if printf '%s\n' "$SE_RO" | grep -q 'SE-RO-READ-OK'; then
  acc_ok "SE external RO root readable through its projection"
else
  acc_fail "SE external RO read failed: $(printf '%s\n' "$SE_RO" | redact | tail -3)"
fi
DOCKER_HELPER_SESSION_TOKEN="$SE_TOKEN" \
  dh run --mount "$SE_HELPER:/helper:ro" alpine:3.24 -- \
  sh -ec 'echo forbidden > /helper/forbidden.txt' >/dev/null 2>&1
SE_EC=$?
if [ "$SE_EC" -ne 0 ] && [ ! -e "$SE_HELPER/forbidden.txt" ]; then
  acc_ok "SE external RO root write denied and the host file was not created"
else
  acc_fail "SE external RO root immutability broken (ec=$SE_EC)"
fi

# SE-RW: the external RW root stays writable; the write persists to the host.
SE_W="$(DOCKER_HELPER_SESSION_TOKEN="$SE_TOKEN" \
  dh run --mount "$SE_CACHE:/cache" alpine:3.24 -- \
  sh -ec 'echo se-write > /cache/written.txt && echo SE-RW-OK' >/tmp/uat-wls-se-w.log 2>&1)"
if [ -f "$SE_CACHE/written.txt" ] && [ "$(cat "$SE_CACHE/written.txt" 2>/dev/null)" = "se-write" ]; then
  acc_ok "SE external RW root writable through the workload owner"
else
  acc_fail "SE external RW write failed: $(redact </tmp/uat-wls-se-w.log | tail -3)"
fi

# SE introspection: session show and self carry the issued external roots.
SE_SHOW="$(dh session show --token-file /tmp/uat-wls-cred-multiroot "$SE_ID" --json 2>/dev/null || true)"
if printf '%s' "$SE_SHOW" | grep -q '"'"$SE_CACHE"'"' \
    && printf '%s' "$SE_SHOW" | grep -q '"'"$SE_HELPER"'"'; then
  acc_ok "SE session show carries the issued external roots (RW cache + RO helper)"
else
  acc_fail "SE session show does not expose the issued external roots: $(printf '%s' "$SE_SHOW" | redact | head -2)"
fi
SE_SELF="$(dh self --token-file "/tmp/uat-wls-tok-$SE_ID" --json 2>/dev/null || true)"
if printf '%s' "$SE_SELF" | grep -q '"'"$SE_CACHE"'"' \
    && printf '%s' "$SE_SELF" | grep -q 'read_write'; then
  acc_ok "SE self carries the issued external RW root"
else
  acc_fail "SE self does not expose the issued external RW root: $(printf '%s' "$SE_SELF" | redact | head -2)"
fi

# SE fcontext coverage: the external issued RW tree carries the helper-owned
# persistent coverage while the session is live; the ceiling parent never
# gets a rule merely by existing.
# SELinux fcontext/label inventory assertions (fail-closed tri-state). The
# tri-state inventory primitives (PRESENT/ABSENT/ERROR) are owned by the
# shared lib (scripts/uat-regression-lib.sh): an unavailable inventory
# (semanage failure, malformed listing, failed context read) is a failure,
# never evidence of absence, of no-residue, or of restoration.
se_rules_dump() {
  selinux_fcontext_patterns 2>/dev/null || printf '(inventory unavailable)'
}
se_expect_rule_present() { # PATTERN OK_LABEL
  local pattern="$1" label="$2" rc
  selinux_rule_state "$pattern"; rc=$?
  case "$rc" in
    0) acc_ok "$label" ;;
    1) acc_fail "$label: rule '$pattern' is ABSENT (rules: $(se_rules_dump | grep -F -- "$pattern" | head -3 || true))" ;;
    *) acc_fail "$label: fcontext inventory unavailable (semanage failed); absence is never assumed" ;;
  esac
}
se_expect_rule_absent() { # PATTERN OK_LABEL FAIL_LABEL
  local pattern="$1" ok_label="$2" fail_label="$3" rc
  selinux_rule_state "$pattern"; rc=$?
  case "$rc" in
    0) acc_fail "$fail_label (rules: $(se_rules_dump | grep -F -- "$pattern" | head -3 || true))" ;;
    1) acc_ok "$ok_label" ;;
    *) acc_fail "$ok_label: fcontext inventory unavailable (semanage failed); absence is never assumed" ;;
  esac
}
se_expect_rule_line_equal() { # PATTERN WANT_LINE OK_LABEL FAIL_LABEL
  local pattern="$1" want="$2" ok_label="$3" fail_label="$4" line rc
  line="$(selinux_rule_line "$pattern")"; rc=$?
  case "$rc" in
    0) if [ "$line" = "$want" ]; then
         acc_ok "$ok_label"
       else
         acc_fail "$fail_label (rule line changed: before '$want' after '$line')"
       fi ;;
    1) acc_fail "$fail_label: rule '$pattern' is ABSENT (byte-for-byte survival unprovable)" ;;
    *) acc_fail "$ok_label: fcontext inventory unavailable (semanage failed)" ;;
  esac
}
se_expect_context_type() { # PATH WANT OK_LABEL FAIL_LABEL
  local path="$1" want="$2" ok_label="$3" fail_label="$4" type rc
  type="$(selinux_context_type "$path")"; rc=$?
  case "$rc" in
    0) if [ "$type" = "$want" ]; then
         acc_ok "$ok_label"
       else
         acc_fail "$fail_label (type '$type', want '$want')"
       fi ;;
    *) acc_fail "$fail_label: SELinux context inventory unavailable for $path (context read failed)" ;;
  esac
}
se_expect_context_type_not() { # PATH UNWANTED OK_LABEL FAIL_LABEL
  local path="$1" unwanted="$2" ok_label="$3" fail_label="$4" type rc
  type="$(selinux_context_type "$path")"; rc=$?
  case "$rc" in
    0) if [ "$type" = "$unwanted" ]; then
         acc_fail "$fail_label (type '$type')"
       else
         acc_ok "$ok_label (type '$type')"
       fi ;;
    *) acc_fail "$ok_label: SELinux context inventory unavailable for $path (context read failed)" ;;
  esac
}
# se_only_rule_for asserts the inventory contains exactly one rule mentioning
# FRAGMENT and that it equals EXPECTED_PATTERN. Inventory failure is a
# failure, never a pass.
se_only_rule_for() { # FRAGMENT EXPECTED_PATTERN OK_LABEL FAIL_LABEL
  local fragment="$1" expected="$2" ok_label="$3" fail_label="$4" rules matches count rc
  rules="$(selinux_fcontext_patterns)"; rc=$?
  case "$rc" in
    0) ;;
    *) acc_fail "$ok_label: fcontext inventory unavailable (semanage failed)"; return ;;
  esac
  matches="$(printf '%s\n' "$rules" | grep -F -- "$fragment" || true)"
  count="$(printf '%s\n' "$matches" | grep -c .)"
  if [ "$count" -eq 1 ] && [ "$matches" = "$expected" ]; then
    acc_ok "$ok_label"
  else
    acc_fail "$fail_label (rules mentioning '$fragment': ${matches:-none})"
  fi
}
se_expect_rule_present "$SE_CACHE(/.*)?" "SE external RW tree carries helper-owned persistent fcontext coverage"
se_expect_rule_absent "$SE_OPT(/.*)?" \
  "SE ceiling parent has no MAC state from authorization alone" \
  "SE the ceiling parent $SE_OPT must not gain coverage merely by being authorized (only issued trees do)"
se_expect_context_type "$SE_CACHE" docker_helper_workspace_t \
  "SE external RW tree actually relabeled to docker_helper_workspace_t" \
  "SE external RW tree label wrong"

# SE share: a second Session issuing the same external tree must prevent
# early release of the coverage when the first Session is deleted.
SE2_OUT="$(dh session create --token-file /tmp/uat-wls-cred-multiroot \
  "$SE_WS" --json \
  --filesystem-root "$SE_CACHE=read_write" 2>&1 || true)"
SE2_ID="$(printf '%s' "$SE2_OUT" | json_field id)"
if [ -n "$SE2_ID" ]; then
  printf '%s\n' "$(printf '%s' "$SE2_OUT" | json_field token)" > "/tmp/uat-wls-tok-$SE2_ID"; chmod 600 "/tmp/uat-wls-tok-$SE2_ID"
  dh session delete --token-file /tmp/uat-wls-cred-multiroot "$SE_ID" >/dev/null 2>&1
  se_expect_rule_present "$SE_CACHE(/.*)?" \
    "SE shared external tree survives the first Session deletion (second Session keeps it)" \
    "SE external fcontext coverage was released while a second Session still issues the tree"
  SE2_W="$(DOCKER_HELPER_SESSION_TOKEN="$(cat "/tmp/uat-wls-tok-$SE2_ID")" \
    dh run --mount "$SE_CACHE:/cache" alpine:3.24 -- \
    sh -ec 'echo se2-write > /cache/se2.txt' >/tmp/uat-wls-se2.log 2>&1; echo $?)"
  if [ "$SE2_W" -eq 0 ] && [ "$(cat "$SE_CACHE/se2.txt" 2>/dev/null)" = "se2-write" ]; then
    acc_ok "SE second Session still writes the shared external tree"
  else
    acc_fail "SE second Session lost write access to the shared tree (ec=$SE2_W)"
  fi
  dh session delete --token-file /tmp/uat-wls-cred-multiroot "$SE2_ID" >/dev/null 2>&1
  se_expect_rule_absent "$SE_CACHE(/.*)?" \
    "SE external fcontext coverage relinquished after the last Session deletion" \
    "SE external fcontext coverage must be relinquished after the last Session released it"
  se_expect_context_type_not "$SE_CACHE" docker_helper_workspace_t \
    "SE external tree labels restored after the last Session deletion" \
    "SE external tree label not restored after the last Session deletion"
  rm -f "$SE_CACHE/se2.txt"
else
  acc_fail "SE share scenario setup failed: $(printf '%s' "$SE2_OUT" | redact | tail -2)"
fi

# SE overlap: issued ancestor/descendant trees survive either deletion order.
SE3_OUT="$(dh session create --token-file /tmp/uat-wls-cred-multiroot \
  "$SE_WS" --json \
  --filesystem-root "$SE_OPT=read_write" \
  --filesystem-root "$SE_CACHE=read_write" 2>&1 || true)"
SE3_ID="$(printf '%s' "$SE3_OUT" | json_field id)"
if [ -n "$SE3_ID" ]; then
  printf '%s\n' "$(printf '%s' "$SE3_OUT" | json_field token)" > "/tmp/uat-wls-tok-$SE3_ID"; chmod 600 "/tmp/uat-wls-tok-$SE3_ID"
  # The projection collapses the descendant into the issued ancestor: only
  # the ancestor boundary is prepared.
  se_expect_rule_present "$SE_OPT(/.*)?" \
    "SE nested issued roots collapse to the single ancestor MAC boundary" \
    "SE nested issued roots did not collapse"
  se_expect_rule_absent "$SE_CACHE(/.*)?" \
    "SE the collapsed descendant carries no independent rule" \
    "SE nested issued roots did not collapse"
  dh session delete --token-file /tmp/uat-wls-cred-multiroot "$SE3_ID" >/dev/null 2>&1
  se_expect_rule_absent "$SE_OPT(/.*)?" \
    "SE ancestor boundary removed after the only session deletion" \
    "SE ancestor boundary must be removed after the only session released it"
  rm -f "$SE_CACHE/written.txt" 2>/dev/null || true
else
  acc_fail "SE overlap scenario setup failed: $(printf '%s' "$SE3_OUT" | redact | tail -2)"
fi

# SE reverse overlap: issue the child first, then the parent; deleting the
# child must keep the parent usable, deleting the parent cleans up.
SE4_OUT="$(dh session create --token-file /tmp/uat-wls-cred-multiroot \
  "$SE_WS" --json \
  --filesystem-root "$SE_CACHE=read_write" 2>&1 || true)"
SE4_ID="$(printf '%s' "$SE4_OUT" | json_field id)"
SE5_OUT="$(dh session create --token-file /tmp/uat-wls-cred-multiroot \
  "$SE_WS" --json \
  --filesystem-root "$SE_OPT=read_write" 2>&1 || true)"
SE5_ID="$(printf '%s' "$SE5_OUT" | json_field id)"
if [ -n "$SE4_ID" ] && [ -n "$SE5_ID" ]; then
  printf '%s\n' "$(printf '%s' "$SE4_OUT" | json_field token)" > "/tmp/uat-wls-tok-$SE4_ID"; chmod 600 "/tmp/uat-wls-tok-$SE4_ID"
  printf '%s\n' "$(printf '%s' "$SE5_OUT" | json_field token)" > "/tmp/uat-wls-tok-$SE5_ID"; chmod 600 "/tmp/uat-wls-tok-$SE5_ID"
  # Both boundaries exist (created in reverse order: child, then parent).
  se_expect_rule_present "$SE_CACHE(/.*)?" \
    "SE reverse-order issuance prepares both disjoint boundaries" \
    "SE reverse-order issuance boundaries missing"
  se_expect_rule_present "$SE_OPT(/.*)?" \
    "SE reverse-order issuance prepares both disjoint boundaries" \
    "SE reverse-order issuance boundaries missing"
  # Delete the child session first: the parent boundary stays.
  dh session delete --token-file /tmp/uat-wls-cred-multiroot "$SE4_ID" >/dev/null 2>&1
  se_expect_rule_present "$SE_OPT(/.*)?" \
    "SE child deletion first keeps the parent boundary" \
    "SE child deletion removed the parent boundary needed by the parent session"
  # Delete the parent session: everything is released and restored.
  dh session delete --token-file /tmp/uat-wls-cred-multiroot "$SE5_ID" >/dev/null 2>&1
  se_expect_rule_absent "$SE_OPT(/.*)?" \
    "SE final deletion relinquishes every external boundary" \
    "SE final deletion leaves fcontext residue"
  se_expect_rule_absent "$SE_CACHE(/.*)?" \
    "SE final deletion relinquishes every external boundary" \
    "SE final deletion leaves fcontext residue"
  se_expect_context_type_not "$SE_OPT" docker_helper_workspace_t \
    "SE parent tree labels restored after final deletion" \
    "SE parent tree label not restored after final deletion"
else
  acc_fail "SE reverse overlap setup failed: $(printf '%s' "$SE4_OUT" "$SE5_OUT" | redact | tail -2)"
fi

# SE regular file: an issued regular-file RW root is writable and its exact
# fcontext coverage is relinquished on deletion.
SE_FILE="$SE_OPT/worker.env"
printf 'se-file-src\n' > "$SE_FILE"
chown "$PRINCIPAL:$PRINCIPAL" "$SE_FILE" 2>/dev/null || true
SE6_OUT="$(dh session create --token-file /tmp/uat-wls-cred-multiroot \
  "$SE_WS" --json \
  --filesystem-root "$SE_FILE=read_write" 2>&1 || true)"
SE6_ID="$(printf '%s' "$SE6_OUT" | json_field id)"
if [ -n "$SE6_ID" ]; then
  printf '%s\n' "$(printf '%s' "$SE6_OUT" | json_field token)" > "/tmp/uat-wls-tok-$SE6_ID"; chmod 600 "/tmp/uat-wls-tok-$SE6_ID"
  SE6_W="$(DOCKER_HELPER_SESSION_TOKEN="$(cat "/tmp/uat-wls-tok-$SE6_ID")" \
    dh run --mount "$SE_FILE:/etc/worker.env" alpine:3.24 -- \
    sh -ec 'echo file-write > /etc/worker.env' >/tmp/uat-wls-se6.log 2>&1; echo $?)"
  if [ "$SE6_W" -eq 0 ] && [ "$(cat "$SE_FILE" 2>/dev/null)" = "file-write" ]; then
    acc_ok "SE issued regular-file RW root is writable through the backend"
  else
    acc_fail "SE regular-file RW write failed (ec=$SE6_W): $(redact </tmp/uat-wls-se6.log | tail -2)"
  fi
  # Unrelated boundary mutation (a second session prepares and releases an
  # unrelated tree) must not disturb the issued file root's usability.
  SE6B_OUT="$(dh session create --token-file /tmp/uat-wls-cred-multiroot \
    "$SE_WS" --json \
    --filesystem-root "$SE_CACHE=read_write" 2>&1 || true)"
  SE6B_ID="$(printf '%s' "$SE6B_OUT" | json_field id)"
  if [ -n "$SE6B_ID" ]; then
    dh session delete --token-file /tmp/uat-wls-cred-multiroot "$SE6B_ID" >/dev/null 2>&1
  fi
  SE6_W2="$(DOCKER_HELPER_SESSION_TOKEN="$(cat "/tmp/uat-wls-tok-$SE6_ID")" \
    dh run --mount "$SE_FILE:/etc/worker.env" alpine:3.24 -- \
    sh -ec 'echo file-write2 > /etc/worker.env' >/tmp/uat-wls-se6.log 2>&1; echo $?)"
  if [ "$SE6_W2" -eq 0 ] && [ "$(cat "$SE_FILE" 2>/dev/null)" = "file-write2" ]; then
    acc_ok "SE regular-file root survives an unrelated boundary mutation"
  else
    acc_fail "SE regular-file root lost write access after an unrelated boundary mutation (ec=$SE6_W2)"
  fi
  dh session delete --token-file /tmp/uat-wls-cred-multiroot "$SE6_ID" >/dev/null 2>&1
  se_expect_rule_absent "$SE_FILE" \
    "SE regular-file boundary relinquished after deletion" \
    "SE regular-file boundary must be relinquished after deletion"
  printf 'se-file-src\n' > "$SE_FILE"
else
  acc_fail "SE regular-file scenario setup failed: $(printf '%s' "$SE6_OUT" | redact | tail -2)"
fi

# SE sibling coverage (review A1 live proof): one operator-owned compatible
# ancestor rule covers two concrete sibling issued trees. BOTH siblings must
# be relabeled and usable; the helper must neither claim nor delete the
# operator rule; the sibling labels are restored on deletion.
SE_SIB="$SE_OPT/sibs"
mkdir -p "$SE_SIB/a" "$SE_SIB/b"
chown -R "$PRINCIPAL:$PRINCIPAL" "$SE_SIB" 2>/dev/null || true
semanage fcontext -a -t docker_helper_workspace_t "$SE_SIB(/.*)?" >/dev/null 2>&1
restorecon -R "$SE_SIB" >/dev/null 2>&1

SE8_OUT="$(dh session create --token-file /tmp/uat-wls-cred-multiroot \
  "$SE_WS" --json \
  --filesystem-root "$SE_SIB/a=read_write" \
  --filesystem-root "$SE_SIB/b=read_write" 2>&1 || true)"
SE8_ID="$(printf '%s' "$SE8_OUT" | json_field id)"
if [ -n "$SE8_ID" ]; then
  printf '%s\n' "$(printf '%s' "$SE8_OUT" | json_field token)" > "/tmp/uat-wls-tok-$SE8_ID"; chmod 600 "/tmp/uat-wls-tok-$SE8_ID"
  se_expect_context_type "$SE_SIB/a" docker_helper_workspace_t \
    "SE both sibling issued trees relabeled under the operator covering rule" \
    "SE sibling coverage skipped the concrete issued tree $SE_SIB/a"
  se_expect_context_type "$SE_SIB/b" docker_helper_workspace_t \
    "SE both sibling issued trees relabeled under the operator covering rule" \
    "SE sibling coverage skipped the concrete issued tree $SE_SIB/b"
  SE8_W="$(DOCKER_HELPER_SESSION_TOKEN="$(cat "/tmp/uat-wls-tok-$SE8_ID")" \
    dh run --mount "$SE_SIB/a:/sib_a" --mount "$SE_SIB/b:/sib_b" alpine:3.24 -- \
    sh -ec 'echo sib-a > /sib_a/a.txt && echo sib-b > /sib_b/b.txt' >/tmp/uat-wls-se8.log 2>&1; echo $?)"
  if [ "$SE8_W" -eq 0 ] && [ "$(cat "$SE_SIB/a/a.txt" 2>/dev/null)" = "sib-a" ] \
      && [ "$(cat "$SE_SIB/b/b.txt" 2>/dev/null)" = "sib-b" ]; then
    acc_ok "SE both sibling issued trees writable through the session"
  else
    acc_fail "SE sibling write failed (ec=$SE8_W): $(redact </tmp/uat-wls-se8.log | tail -2)"
  fi
  se_only_rule_for "$SE_SIB" "$SE_SIB(/.*)?" \
    "SE sibling coverage uses the operator rule without claiming helper state" \
    "SE sibling coverage created or claimed extra state"
  dh session delete --token-file /tmp/uat-wls-cred-multiroot "$SE8_ID" >/dev/null 2>&1
  se_expect_rule_present "$SE_SIB(/.*)?" \
    "SE operator-owned sibling coverage rule survives the session deletion" \
    "SE helper deleted the operator-owned sibling rule"
  # The covering coverage is operator state: the helper must neither delete
  # the rule nor undo the operator's labeling. The trailing script cleanup
  # below restores the environment baseline.
  se_expect_context_type "$SE_SIB/a" docker_helper_workspace_t \
    "SE operator label state untouched by helper cleanup" \
    "SE helper interfered with operator label state after deletion"
  rm -f "$SE_SIB/a/a.txt" "$SE_SIB/b/b.txt" 2>/dev/null || true
else
  acc_fail "SE sibling coverage scenario setup failed: $(printf '%s' "$SE8_OUT" | redact | tail -2)"
fi
semanage fcontext -d "$SE_SIB(/.*)?" >/dev/null 2>&1 || true
restorecon -R "$SE_SIB" >/dev/null 2>&1 || true

# SE operator same-stem ownership (review A2 live proof): a helper-owned rule
# and an operator-owned rule share ONE canonical boundary stem in BOTH legal
# rule shapes — the exact-file form (/path) and the recursive-directory form
# (/path(/.*)?) — and the operator mutates the object kind at that stem before
# cleanup, so cleanup cannot derive the owned shape from mutable current host
# state. Cleanup must delete only the helper's own proven shape; the operator
# rule survives byte-for-byte; an inventory failure is never read as absence.
# Both directions are proven:
#   SE9A helper recursive-directory rule  + operator exact-file rule;
#   SE9B helper exact-file rule           + operator recursive-directory rule.
SE_MIX="$SE_OPT/mix"
rm -rf "$SE_MIX"
mkdir -p "$SE_MIX"
chown -R "$PRINCIPAL:$PRINCIPAL" "$SE_MIX" 2>/dev/null || true
SE9A_OUT="$(dh session create --token-file /tmp/uat-wls-cred-multiroot \
  "$SE_WS" --json \
  --filesystem-root "$SE_MIX=read_write" 2>&1 || true)"
SE9A_ID="$(printf '%s' "$SE9A_OUT" | json_field id)"
if [ -n "$SE9A_ID" ]; then
  # Positively inventory the helper-owned recursive rule AND the absence of
  # any exact-file rule at the same stem before the operator acts.
  se_expect_rule_present "$SE_MIX(/.*)?" \
    "SE9A helper owns the recursive-directory rule at the boundary stem"
  se_expect_rule_absent "$SE_MIX" \
    "SE9A no exact-file rule exists at the stem before the operator acts" \
    "SE9A an exact-file rule already existed at the stem before the operator acted"
  # Operator adds the exact-file rule at the SAME stem (the other legal shape).
  semanage fcontext -a -t docker_helper_workspace_t "$SE_MIX" >/dev/null 2>&1
  se_expect_rule_present "$SE_MIX" \
    "SE9A operator added the exact-file rule at the same stem (both legal shapes, one stem)"
  SE9A_OP_LINE="$(selinux_rule_line "$SE_MIX")"
  # Operator mutates the object kind at the stem: the directory is replaced by
  # a regular file. The fcontext rules are unaffected; only cleanup could
  # mis-derive the helper's owned shape from the mutable kind.
  rm -rf "$SE_MIX"
  printf 'replaced-by-operator\n' > "$SE_MIX"
  chown "$PRINCIPAL:$PRINCIPAL" "$SE_MIX" 2>/dev/null || true
  se_expect_rule_present "$SE_MIX(/.*)?" \
    "SE9A helper recursive rule still inventoried after the operator kind change"
  se_expect_rule_present "$SE_MIX" \
    "SE9A operator exact-file rule still inventoried after the operator kind change"
  dh session delete --token-file /tmp/uat-wls-cred-multiroot "$SE9A_ID" >/dev/null 2>&1
  se_expect_rule_absent "$SE_MIX(/.*)?" \
    "SE9A helper-owned recursive-directory rule removed after the session deletion" \
    "SE9A helper-owned recursive-directory rule survived the session deletion"
  se_expect_rule_line_equal "$SE_MIX" "$SE9A_OP_LINE" \
    "SE9A operator-owned exact-file rule at the same stem survives byte-for-byte" \
    "SE9A helper deleted or mutated the operator-owned exact-file rule"
else
  acc_fail "SE9A same-stem scenario setup failed: $(printf '%s' "$SE9A_OUT" | redact | tail -2)"
fi

SE_MIXF="$SE_OPT/mixfile"
rm -rf "$SE_MIXF"
printf 'mixfile-content\n' > "$SE_MIXF"
chown "$PRINCIPAL:$PRINCIPAL" "$SE_MIXF" 2>/dev/null || true
SE9B_OUT="$(dh session create --token-file /tmp/uat-wls-cred-multiroot \
  "$SE_WS" --json \
  --filesystem-root "$SE_MIXF=read_write" 2>&1 || true)"
SE9B_ID="$(printf '%s' "$SE9B_OUT" | json_field id)"
if [ -n "$SE9B_ID" ]; then
  se_expect_rule_present "$SE_MIXF" \
    "SE9B helper owns the exact-file rule at the boundary stem"
  se_expect_rule_absent "$SE_MIXF(/.*)?" \
    "SE9B no recursive rule exists at the stem before the operator acts" \
    "SE9B a recursive rule already existed at the stem before the operator acted"
  # Operator adds the recursive-directory rule at the SAME stem.
  semanage fcontext -a -t docker_helper_workspace_t "$SE_MIXF(/.*)?" >/dev/null 2>&1
  se_expect_rule_present "$SE_MIXF(/.*)?" \
    "SE9B operator added the recursive-directory rule at the same stem (both legal shapes, one stem)"
  SE9B_OP_LINE="$(selinux_rule_line "$SE_MIXF(/.*)?")"
  # Operator mutates the object kind at the stem: the regular file is replaced
  # by a directory — the exact ambiguity cleanup must survive.
  rm -f "$SE_MIXF"
  mkdir -p "$SE_MIXF"
  chown "$PRINCIPAL:$PRINCIPAL" "$SE_MIXF" 2>/dev/null || true
  se_expect_rule_present "$SE_MIXF" \
    "SE9B helper exact-file rule still inventoried after the operator kind change"
  se_expect_rule_present "$SE_MIXF(/.*)?" \
    "SE9B operator recursive rule still inventoried after the operator kind change"
  dh session delete --token-file /tmp/uat-wls-cred-multiroot "$SE9B_ID" >/dev/null 2>&1
  se_expect_rule_absent "$SE_MIXF" \
    "SE9B helper-owned exact-file rule removed after the session deletion" \
    "SE9B helper-owned exact-file rule survived the session deletion"
  se_expect_rule_line_equal "$SE_MIXF(/.*)?" "$SE9B_OP_LINE" \
    "SE9B operator-owned recursive rule at the same stem survives byte-for-byte" \
    "SE9B helper deleted or mutated the operator-owned recursive rule"
else
  acc_fail "SE9B same-stem scenario setup failed: $(printf '%s' "$SE9B_OUT" | redact | tail -2)"
fi
# Trailing cleanup: remove both operator rules at both stems and restore the
# baseline labels of the fixture trees.
semanage fcontext -d "$SE_MIX" >/dev/null 2>&1 || true
semanage fcontext -d "$SE_MIX(/.*)?" >/dev/null 2>&1 || true
semanage fcontext -d "$SE_MIXF" >/dev/null 2>&1 || true
semanage fcontext -d "$SE_MIXF(/.*)?" >/dev/null 2>&1 || true
restorecon -R "$SE_MIX" "$SE_MIXF" >/dev/null 2>&1 || true
rm -f "/tmp/uat-wls-tok-$SE8_ID" "/tmp/uat-wls-tok-$SE9A_ID" "/tmp/uat-wls-tok-$SE9B_ID" 2>/dev/null || true

# SE restart: a live session's external coverage survives restart and the
# reconciled binding keeps the write path working.
SE7_OUT="$(dh session create --token-file /tmp/uat-wls-cred-multiroot \
  "$SE_WS" --json \
  --filesystem-root "$SE_CACHE=read_write" 2>&1 || true)"
SE7_ID="$(printf '%s' "$SE7_OUT" | json_field id)"
if [ -n "$SE7_ID" ]; then
  printf '%s\n' "$(printf '%s' "$SE7_OUT" | json_field token)" > "/tmp/uat-wls-tok-$SE7_ID"; chmod 600 "/tmp/uat-wls-tok-$SE7_ID"
  systemctl restart docker-helper.service >/dev/null 2>&1 || true
  for _ in $(seq 1 60); do
    systemctl is-active --quiet docker-helper.service || break
    wait_health && break
    sleep 1
  done
  se_expect_rule_present "$SE_CACHE(/.*)?" \
    "SE restart/reconciliation keeps the issued external coverage" \
    "SE restart lost the external coverage"
  if DOCKER_HELPER_SESSION_TOKEN="$(cat "/tmp/uat-wls-tok-$SE7_ID")" \
      dh run --mount "$SE_CACHE:/cache" alpine:3.24 -- \
      sh -ec 'echo restart-write > /cache/restart.txt' >/tmp/uat-wls-se7.log 2>&1 \
      && [ "$(cat "$SE_CACHE/restart.txt" 2>/dev/null)" = "restart-write" ]; then
    acc_ok "SE restart/reconciliation restores live issued external coverage and write access"
  else
    acc_fail "SE restart lost the external coverage or write access: $(redact </tmp/uat-wls-se7.log | tail -2)"
  fi
  dh session delete --token-file /tmp/uat-wls-cred-multiroot "$SE7_ID" >/dev/null 2>&1
  rm -f "$SE_CACHE/restart.txt"
  se_expect_rule_absent "$SE_CACHE(/.*)?" \
    "SE no external fcontext residue after the final cleanup" \
    "SE final cleanup leaves external fcontext residue"
else
  acc_fail "SE restart scenario setup failed: $(printf '%s' "$SE7_OUT" | redact | tail -2)"
fi
rm -f "/tmp/uat-wls-tok-$SE_ID" "/tmp/uat-wls-tok-$SE2_ID" "/tmp/uat-wls-tok-$SE3_ID" \
  "/tmp/uat-wls-tok-$SE4_ID" "/tmp/uat-wls-tok-$SE5_ID" "/tmp/uat-wls-tok-$SE6_ID" \
  "/tmp/uat-wls-tok-$SE7_ID" 2>/dev/null || true

# ==============================================================================
# scenario S7: bindfs projection really used on the packaged RPM path
# ==============================================================================
say "S7: bindfs projection used on the packaged RPM path"
DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --mount pipeline-inputs:/mnt/inputs:ro alpine:3.24 -- \
  sh -ec 'sleep 12; cat /mnt/inputs/input.txt' >/tmp/uat-wls-s7.log 2>&1 &
BG_PID=$!
PROJ_EVIDENCE="$(wait_bindfs_projection "$BG_PID" || true)"
wait "$BG_PID" || true
if [ -n "$PROJ_EVIDENCE" ]; then
  info "S7 projection observed during the live RO exposure: $PROJ_EVIDENCE"
  if printf '%s\n' "$PROJ_EVIDENCE" | grep -q 'docker_helper_ro_projection_t'; then
    acc_ok "S7 live fuse.bindfs projection with docker_helper_ro_projection_t observed"
  else
    acc_fail "S7 projection context wrong: $PROJ_EVIDENCE"
  fi
else
  acc_fail "S7 no bindfs projection observed during the live RO exposure"
  echo "  S7 detail: run-log=$(cat /tmp/uat-wls-s7.log 2>/dev/null | redact | tail -2)" >&2
  grep 'fuse.bindfs' /proc/mounts 2>/dev/null | sed 's/^/  S7 mounts: /' >&2 || echo "  S7 mounts: none" >&2
fi
# The run.start audit stream carries the backend fact for every system-mode
# run. The bounded window conversion uses the same ISO form as the S13 AVC
# window (journalctl's @epoch since-form is not uniformly accepted across
# systemd builds); the window is retried briefly because journald can lag the
# just-finished run, and a failed read is diagnosed instead of failing silent.
S7_AUDIT_START_ISO="$(date -u -d "@${AUDIT_START_EPOCH}" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || true)"
S7_AUDIT_OK=""
for _s7i in 1 2 3 4 5; do
  # Compare the event's own UTC ISO time field against the window start;
  # this avoids every journalctl --since timestamp-parsing variant.
  if journalctl --utc -u docker-helper.service --no-pager 2>/dev/null \
      | awk -v start="${S7_AUDIT_START_ISO:-}" '
          /"event":"run.start"/ {
            if (match($0, /"time":"[^"]*"/)) {
              t = substr($0, RSTART + 8, RLENGTH - 9)
              if (start != "" && t >= start && $0 ~ /"workload_mac_backend":"selinux"/)
                found = 1
            }
          }
          END { exit found ? 0 : 1 }'; then
    S7_AUDIT_OK=1
    break
  fi
  sleep 2
done
if [ -n "$S7_AUDIT_OK" ]; then
  acc_ok "S7 run.start audit records workload_mac_backend=selinux"
else
  acc_fail "S7 run.start audit does not record the SELinux workload backend (window start: epoch ${AUDIT_START_EPOCH})"
  journalctl --utc -u docker-helper.service --no-pager 2>/dev/null \
    | grep '"event":"run.start"' | tail -3 | sed 's/^/  S7 audit detail: /' >&2 || true
fi

# ==============================================================================
# scenario S6: workload stays docker_helper_container_t with distinct MCS
# ==============================================================================
say "S6: docker_helper_container_t + Docker-owned MCS"
S6_L1="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --mount project:/mnt/project alpine:3.24 -- /bin/cat /proc/self/attr/current 2>/dev/null || true)"
S6_L2="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --mount pipeline-inputs:/mnt/inputs:ro alpine:3.24 -- /bin/cat /proc/self/attr/current 2>/dev/null || true)"
case "$S6_L1" in *docker_helper_container_t:*) ;; *)
  acc_fail "S6 RW workload process label wrong: '$S6_L1'" ;;
esac
case "$S6_L2" in *docker_helper_container_t:*) ;; *)
  acc_fail "S6 RO workload process label wrong: '$S6_L2'" ;;
esac
if [ "$S6_L1" != "$S6_L2" ]; then
  acc_ok "S6 both workloads run as docker_helper_container_t with distinct Docker MCS labels"
else
  acc_fail "S6 Docker-owned MCS categories did not differ: '$S6_L1'"
fi

# ==============================================================================
# scenario S8: two concurrent Sessions share one host tree (different snapshots)
# ==============================================================================
say "S8: two concurrent Sessions on one host tree"
WSB_ID="$(create_session /tmp/uat-wls-cred-main "$TREE/work/project")" \
  || { echo "error: second acceptance session creation failed" >&2; exit 1; }
WSB_TOKEN="$(cat "/tmp/uat-wls-tok-$WSB_ID")"
rm -f "$TREE/work/project/a-file" "$TREE/work/project/b-file"
DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --mount project:/mnt/p alpine:3.24 -- \
  sh -ec 'echo session-A > /mnt/p/a-file; sleep 5; cat /mnt/p/a-file' >/tmp/uat-wls-s8a.log 2>&1 &
S8A_PID=$!
DOCKER_HELPER_SESSION_TOKEN="$WSB_TOKEN" \
  dh run --mount .:/mnt/self alpine:3.24 -- \
  sh -ec 'echo session-B > /mnt/self/b-file; sleep 5; cat /mnt/self/b-file' >/tmp/uat-wls-s8b.log 2>&1 &
S8B_PID=$!
S8A_OK=0; S8B_OK=0
wait "$S8A_PID" && S8A_OK=1 || true
wait "$S8B_PID" && S8B_OK=1 || true
if [ "$S8A_OK" = 1 ] && [ "$S8B_OK" = 1 ] \
    && [ "$(cat "$TREE/work/project/a-file" 2>/dev/null)" = "session-A" ] \
    && [ "$(cat "$TREE/work/project/b-file" 2>/dev/null)" = "session-B" ]; then
  acc_ok "S8 concurrent Sessions with different issued snapshots shared the tree (A=$WSA_ID B=$WSB_ID)"
else
  acc_fail "S8 concurrent session use failed (A=$S8A_OK B=$S8B_OK: $(redact </tmp/uat-wls-s8a.log | tail -2) / $(redact </tmp/uat-wls-s8b.log | tail -2))"
fi

# ==============================================================================
# scenario S9: regular-file RO exposure
# ==============================================================================
say "S9: regular-file RO exposure"
S9_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --mount pipeline-inputs/input.txt:/mnt/file:ro alpine:3.24 -- \
  sh -ec 'test "$(cat /mnt/file)" = "ro-input" || exit 3; if echo x > /mnt/file 2>/dev/null; then exit 4; fi; echo S9-FILE-OK' 2>&1)"
S9_EC=$?
if [ "$S9_EC" -eq 0 ] && printf '%s\n' "$S9_OUT" | grep -q 'S9-FILE-OK' \
    && [ "$(cat "$TREE/work/pipeline-inputs/input.txt" 2>/dev/null)" = "ro-input" ]; then
  acc_ok "S9 regular-file RO exposure read works and the write is denied"
else
  acc_fail "S9 regular-file RO exposure failed (ec=$S9_EC): $(printf '%s\n' "$S9_OUT" | redact | tail -3)"
fi

# ==============================================================================
# scenario S11: no broad/recurrent relabel of the acceptance tree
# ==============================================================================
say "S11: no relabel of the backing source"
if [ "$(tree_context_snapshot)" = "$TREE_CTX_BEFORE" ]; then
  acc_ok "S11 acceptance tree contexts unchanged after all scenarios (no broad relabel)"
else
  acc_fail "S11 acceptance tree contexts changed (relabel detected)"
fi

# ==============================================================================
# scenario S12: cleanup after success/failure + restart/reconciliation
# ==============================================================================
say "S12: cleanup after success and failure, restart/reconciliation"
wait_no_helper_containers
S12_WAIT_RC=$?
if [ "$S12_WAIT_RC" -eq 2 ]; then
  acc_blocked "S12 helper container inventory unavailable after the scenarios"
elif [ "$S12_WAIT_RC" -ne 0 ]; then
  acc_fail "S12 helper containers remain after the scenarios"
fi
workload_residue_clean
S12_CLEAN_RC=$?
if [ "$S12_CLEAN_RC" -eq 0 ]; then
  acc_ok "S12 no generated workload state remains after the positive scenarios"
elif [ "$S12_CLEAN_RC" -eq 2 ]; then
  acc_blocked "S12 workload residue inventory unavailable after the positive scenarios"
else
  acc_fail "S12 workload residue after the positive scenarios"
fi
DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --mount project:/mnt/project alpine:3.24 -- sh -ec 'exit 9' >/dev/null 2>&1
S12_FAIL_EC=$?
[ "$S12_FAIL_EC" -ne 0 ] \
  && acc_ok "S12 failing workload propagates the container failure (ec=$S12_FAIL_EC)" \
  || acc_fail "S12 failing workload unexpectedly succeeded"
wait_no_helper_containers
S12_WAIT2_RC=$?
if [ "$S12_WAIT2_RC" -eq 2 ]; then
  acc_blocked "S12 helper container inventory unavailable after the failing run"
elif [ "$S12_WAIT2_RC" -ne 0 ]; then
  acc_fail "S12 helper containers remain after the failing run"
fi
workload_residue_clean
S12_CLEAN2_RC=$?
if [ "$S12_CLEAN2_RC" -eq 0 ]; then
  acc_ok "S12 no generated workload state remains after the failing run"
elif [ "$S12_CLEAN2_RC" -eq 2 ]; then
  acc_blocked "S12 workload residue inventory unavailable after the failing run"
else
  acc_fail "S12 workload residue after the failing run"
fi
systemctl restart docker-helper.service >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
DH_PID2="$(systemctl show -p MainPID --value docker-helper.service)"
DH_LABEL2="$(tr -d '\0' < "/proc/$DH_PID2/attr/current" 2>/dev/null || true)"
if wait_health \
    && case "$DH_LABEL2" in *docker_helper_t:*) true ;; *) false ;; esac; then
  workload_residue_clean
  S12_CLEAN3_RC=$?
  if [ "$S12_CLEAN3_RC" -eq 0 ]; then
    acc_ok "S12 restart/reconciliation: daemon confined again, no stale workload state"
  elif [ "$S12_CLEAN3_RC" -eq 2 ]; then
    acc_blocked "S12 restart left the daemon confined but the workload residue inventory is unavailable"
  else
    acc_fail "S12 restart left stale workload state"
  fi
else
  workload_residue_clean
  S12_CLEAN4_RC=$?
  echo "  S12 restart detail: health=$(wait_health && echo ok || echo FAIL) label='$DH_LABEL2' residue=$( [ "$S12_CLEAN4_RC" -eq 0 ] && echo clean || { [ "$S12_CLEAN4_RC" -eq 2 ] && echo unavail || echo dirty; })" >&2
  acc_fail "S12 restart left confinement or workload residue broken"
fi

# is_expected_projection_denial LINE — the single canonical predicate deciding
# whether a raw audit AVC record is the expected enforcing write denial by a
# docker_helper_container_t workload against the docker_helper_ro_projection_t
# projection. It is used BOTH to select the mandatory attributable S13 evidence
# and to exclude those same expected records from UNEXPECTED, so the two never
# drift into different definitions of "expected projection AVC". Requires (at
# minimum):
#   avc:  denied
#   scontext contains docker_helper_container_t
#   tcontext contains docker_helper_ro_projection_t
#   tclass=dir OR tclass=file
#   write present in the actual raw AVC permission set (denied { write })
#   permissive=0
# A raw AVC record reports its permission set in braces ("denied { write }"),
# NOT as "perm=write", so the write test is anchored to the brace-delimited
# permission set. An unrelated permission, target type, source domain, class,
# or permissive AVC is never accepted as the required enforcing write denial.
is_expected_projection_denial() {
  local line="$1"
  printf '%s\n' "$line" | grep -q 'avc:  *denied' \
    && printf '%s\n' "$line" | grep -q 'scontext=.*docker_helper_container_t' \
    && printf '%s\n' "$line" | grep -q 'tcontext=.*docker_helper_ro_projection_t' \
    && printf '%s\n' "$line" | grep -Eq 'tclass=(dir|file)\b' \
    && printf '%s\n' "$line" | grep -Eq '\{[^}]*\bwrite\b[^}]*\}' \
    && printf '%s\n' "$line" | grep -Eq 'permissive=0'
}

# count_unexpected_helper_avcs WINDOW — counts, within a window of raw AVC
# records, the denials in the docker_helper scope that are not expected:
#   - the enforcing projection write denial (is_expected_projection_denial);
#   - the daemon's own policy-tool fifo artifact: the Session MAC relabel
#     lifecycle executes semanage in the daemon domain and libsemanage runs
#     setfiles/load_policy as their own distro domains; the child policy tool
#     writing the parent's captured-output fifo is denied (scontext
#     setfiles_t or load_policy_t, tcontext docker_helper_t, tclass=fifo_file,
#     denied write). The fcontext rule is nonetheless applied by semanage, so
#     this is the confined execution artifact of the relabel lifecycle, not a
#     docker-helper domain denial; semanage itself stays in docker_helper_t.
# This is the single decision point behind the S13 "no unexpected docker_helper
# AVC" gate; it prints the count on stdout and routes its per-record
# diagnostics to stderr so the count stays machine-readable under command
# substitution. Only AVCs whose source context is in the docker_helper* scope
# are considered for the general case; the policy-tool fifo artifact is
# identified by its tool scontext directly.
count_unexpected_helper_avcs() {
  local window="$1" line count=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    printf '%s\n' "$line" | grep -q 'scontext.*docker_helper' || continue
    if is_expected_projection_denial "$line"; then
      printf '  expected projection write denial: %s\n' "$line" >&2
      continue
    fi
    if printf '%s\n' "$line" | grep -Eq 'scontext=system_u:system_r:(setfiles_t|load_policy_t):' \
        && printf '%s\n' "$line" | grep -q 'tcontext=.*docker_helper_t' \
        && printf '%s\n' "$line" | grep -q 'tclass=fifo_file' \
        && printf '%s\n' "$line" | grep -Eq 'denied.*\{[^}]*\bwrite\b[^}]*\}'; then
      printf '  expected policy-tool fifo artifact: %s\n' "$line" >&2
      continue
    fi
    printf '  UNEXPECTED AVC: %s\n' "$line" >&2
    count=$((count + 1))
  done <<< "$window"
  printf '%s' "$count"
}

# ==============================================================================
# scenario S13: harness proof + bounded audit window evidence
# ==============================================================================
say "S13: forced-writable RO denied by SELinux (harness) + audit evidence"
mkdir -p "$EVIDENCE_DIR"
if DOCKER_HELPER_LIVE_WORKLOAD_PROOF=1 WORKLOAD_EVIDENCE_DIR="$EVIDENCE_DIR" \
    "$PROOF_BIN_IN" -test.run 'TestLiveWorkloadSELinux|TestLiveWorkloadSELinuxRegularFile|TestLiveWorkloadSELinuxExternalRoot|TestLiveWorkloadMCSConcurrentRWRO' -test.v \
    >/tmp/uat-wls-harness.log 2>&1; then
  acc_ok "S13 live harness passed: bindfs projection denies the would-be-RO write (VFS view writable), regular-file RO proven, MCS concurrency proven, external-source backend-only proof proven"
else
  acc_fail "S13 live harness failed: $(tail -10 /tmp/uat-wls-harness.log 2>/dev/null | redact)"
fi

# Required independent evidence: a fresh AVC attributable to the projection
# type. ausearch is bounded to the window; fall back to the raw audit log
# when ausearch yields nothing.
AVC_START_DATE="$(date -d "@$AUDIT_START_EPOCH" '+%m/%d/%Y %H:%M:%S' 2>/dev/null || true)"
AVC_WINDOW="$(ausearch -m AVC -ts "$AVC_START_DATE" 2>/dev/null || true)"
if [ -z "$AVC_WINDOW" ] && [ -f /var/log/audit/audit.log ]; then
  AVC_WINDOW="$(awk -v start="$AUDIT_START_EPOCH" '
    match($0, /audit\(([0-9]+)\./, m) { if (m[1] + 0 >= start + 0) print }
  ' /var/log/audit/audit.log 2>/dev/null || true)"
fi
RO_AVC="$(printf '%s\n' "$AVC_WINDOW" | while IFS= read -r _line; do
  is_expected_projection_denial "$_line" && printf '%s\n' "$_line"
done | head -1 || true)"
if [ -n "$RO_AVC" ]; then
  acc_ok "S13 attributable enforcing projection write-denial AVC present: $RO_AVC"
else
  acc_blocked "S13 no attributable docker_helper_ro_projection_t enforcing write-denial AVC in the window (independent MAC denial evidence impossible)"
fi

# No unexpected AVCs in the docker-helper policy scope: any denied AVC whose
# source context involves docker_helper_* must be the expected projection
# write denials (or the daemon's own policy-tool fifo artifact).
UNEXPECTED="$(count_unexpected_helper_avcs "$AVC_WINDOW")"
if [ "$UNEXPECTED" -eq 0 ]; then
  acc_ok "S13 no unexpected docker_helper AVC outside the expected negative subcases"
else
  acc_fail "S13 unexpected docker_helper AVCs in the window: $UNEXPECTED"
fi

# ==============================================================================
# scenarios S14-S16: hostile C1/H9 privilege and helper-runtime composition
# (placed after the S13 audit-window accounting so the mandatory AVC evidence
# windows stay untouched; every helper-private access below is denied by
# DAC before SELinux is reached, so no new AVC class is introduced)
# ==============================================================================

HOSTILE_DIR="/tmp/uat-wls-sec"
HOSTILE_IMAGE="uat-hostile-suid:2.2"
# The privilege reporter is compiled on the host from the candidate checkout
# (scripts/uat-privilege-reporter) and transferred into the guest with the
# exact-candidate artifacts, the same host-compile/guest-consume pattern as
# the live workload harness; the guest has no Go toolchain on its PATH.
REPORTER_BIN="${UAT_REPORTER_BIN:-/opt/uat-import/workload-privilege-reporter}"

# build_hostile_image builds the hostile source image with plain docker
# build: the image is attacker-controlled material by threat model, never
# helper-mediated. The host-compiled privilege reporter is delivered as a
# root-owned SUID executable, plus curl for the helper-socket probe.
build_hostile_image() {
  rm -rf "$HOSTILE_DIR"
  mkdir -p "$HOSTILE_DIR/image"
  if [ ! -x "$REPORTER_BIN" ]; then
    printf '  privilege reporter unavailable at %s\n' "$REPORTER_BIN" >&2
    return 1
  fi
  cp "$REPORTER_BIN" "$HOSTILE_DIR/image/reporter" || return 1
  cat > "$HOSTILE_DIR/image/Dockerfile" <<'EOF'
FROM alpine:3.24
COPY reporter /usr/local/bin/reporter
COPY hostile-probe.sh /usr/local/bin/hostile-probe.sh
RUN chmod 0755 /usr/local/bin/reporter && chmod u+s /usr/local/bin/reporter
RUN chmod 0755 /usr/local/bin/hostile-probe.sh
RUN apk add --no-cache curl >/dev/null
EOF
  cat > "$HOSTILE_DIR/image/hostile-probe.sh" <<'EOF'
#!/bin/sh
# H9 hostile probe: exits nonzero with a distinct finding marker on any
# violation; prints S16-HOSTILE-CLEAN when every check holds.
fail() { printf 'S16-FINDING:%s\n' "$1"; exit 1; }
# 1. the intended Unix socket transport stays reachable.
out="$(curl -s --unix-socket /run/docker-helper/docker-helper.sock http://localhost/health)" \
  || fail socket-unreachable
case "$out" in *'"ok":true'*) : ;; *) fail health-not-ok ;; esac
# 2. the transport grants no authority: an unauthenticated protected call is
#    refused exactly as for any other API client.
code="$(curl -s -o /dev/null -w '%{http_code}' --unix-socket \
  /run/docker-helper/docker-helper.sock -X POST -H 'Content-Type: application/json' \
  -d '{"image":"alpine:3.24"}' http://localhost/run)" || fail post-unreachable
[ "$code" = "401" ] || fail "unauthenticated-post-code-$code"
# 3. helper-private runtime machinery stays unreadable (type policy keeps the
#    runtime files outside docker_helper_container_t beyond traversal).
for d in sessions builds mounts workload-mac; do
  if ls "/run/docker-helper/$d" >/dev/null 2>&1; then fail "private-dir-readable-$d"; fi
done
# 4. the known per-Session Docker config (registry credential store) stays
#    unreadable even by its exact known path.
if cat "/run/docker-helper/sessions/$TARGET_SESSION/docker/config.json" >/dev/null 2>&1; then
  fail session-config-readable
fi
# 5. helper-owned runtime state stays immutable.
if touch /run/docker-helper/hostile-probe >/dev/null 2>&1; then fail runtime-writable-top; fi
if touch "/run/docker-helper/sessions/$TARGET_SESSION/docker/hostile-probe" >/dev/null 2>&1; then
  fail runtime-writable-sessions
fi
# 6. the privilege escalation stays dead with the projection mounted.
info="$(/usr/local/bin/reporter)" || fail reporter-failed
case "$info" in *euid=0*) fail suid-elevated ;; esac
printf '%s\n' "$info" | grep -q 'capEff=0000000000000000' || fail caps-not-dropped
echo S16-HOSTILE-CLEAN
EOF
  chmod 0755 "$HOSTILE_DIR/image/hostile-probe.sh"
  docker build -q -t "$HOSTILE_IMAGE" "$HOSTILE_DIR/image" >/tmp/uat-wls-sec-build.log 2>&1 || {
    printf '  hostile image build failed: %s\n' "$(tail -3 /tmp/uat-wls-sec-build.log 2>/dev/null | redact)" >&2
    return 1
  }
  return 0
}

WUID="$(id -u "$PRINCIPAL")"

# --- scenario S14: hostile SUID source image cannot elevate (C1) --------------
say "S14: hostile SUID source image cannot elevate"
if build_hostile_image; then
  S14_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
    dh run "$HOSTILE_IMAGE" -- \
    sh -ec '/usr/local/bin/reporter' 2>&1)"
  S14_EC=$?
  if [ "$S14_EC" -eq 0 ] \
      && printf '%s\n' "$S14_OUT" | grep -Fq "uid=$WUID" \
      && printf '%s\n' "$S14_OUT" | grep -Fq "euid=$WUID" \
      && ! printf '%s\n' "$S14_OUT" | grep -Fq 'euid=0' \
      && printf '%s\n' "$S14_OUT" | grep -Fq 'capEff=0000000000000000'; then
    acc_ok "S14 image SUID executable stays at the workload identity (uid/euid=$WUID, no capabilities)"
  else
    acc_fail "S14 hostile source image escalation not fully dead (ec=$S14_EC): $(printf '%s\n' "$S14_OUT" | redact | tail -3)"
  fi
else
  acc_blocked "S14 hostile fixture build failed (source-image escalation proof impossible)"
fi

# --- R7 corrective evidence: the executed OCI runtime's runtime-dir fixup ---
say "R7 runtime privacy: buildkit-runc's per-op runtime-dir fixup (setattr rung)"
# The R7 setattr rung serves the executed bundled buildkit-runc's own
# $XDG_RUNTIME_DIR fixup (chmod on ops/<op_id>/runc inside its OWN
# categorized per-op runtime tree). The rule is type-wide TE authority;
# the cross-operation effect is owned by the MCS category constraints.
# This section captures the LIVE evidence the policy comment requires —
# never one scontext/tcontext category match alone:
#   - the per-op category allocation is real: TWO CONCURRENT builds get
#     two distinct ops/<id> runtime trees with DISTINCT SELinux
#     categories (the lowest-free per-operation pool, G32 r3 §4.1);
#   - each observed ops/<id>/runc dir carries the SAME SELinux context
#     as its own op's runtime tree (live stat, both sides);
#   - the fixup's effect is a TIGHTENING: every complete observation of
#     the runc dir mode is exactly owner-rwx (no group/other access)
#     and its owner matches the op tree's own flow identity; incomplete
#     (vanished-before-stat) and runc-gone (delete event) observations
#     are counted and never decisive;
#   - no group/other write appears anywhere on the observed tree path
#     (the runtime root, ops/, the op dir) — no widening for any other
#     local identity, no writable path toward another operation or the
#     shared runtime root;
#   - after both builds reach terminal, the whole per-op trees are gone
#     (no leftover restricted dirs);
#   - the loaded policy's concrete buildkitd_t -> builder_runtime_t:dir
#     grant is EXACTLY the one canonical rule and carries NO category
#     (the sesearch pin) — the category-blind TE grant documented in
#     the module; the cross-operation denial itself is the MCS
#     constraint's, which the workload plane proves live (S13).
RT_PRIV_CTX="$TREE/work/runtime-privacy"
rm -rf "$RT_PRIV_CTX"
mkdir -p "$RT_PRIV_CTX"
cat > "$RT_PRIV_CTX/Dockerfile" <<'EOF'
FROM alpine:3.24
RUN sleep 15
RUN echo PRIVACY-BUILD-DONE
EOF
RT_SESEARCH_BIN="$(command -v sesearch || true)"
RT_SEINFO_BIN="$(command -v seinfo || true)"
if [ -z "$RT_SESEARCH_BIN" ] || [ -z "$RT_SEINFO_BIN" ]; then
  acc_blocked "R7 runtime privacy: sesearch/seinfo unavailable (the loaded-policy pins cannot run)"
else
  RT_SURVEY=/tmp/uat-wls-privacy-survey.txt
  : > "$RT_SURVEY"
  # The fd-pinned reader's per-run positive control, BEFORE any capture
  # can bind to the mechanism (the control exercises deletion-after-open,
  # inode substitution and the failed-open path as the SAME subject that
  # will perform the live captures; see rt_priv_fd_selftest). The result
  # is journaled in the run log: method=proven activates the fd-pinned
  # records, anything else degrades to the legacy two-path-stat contract
  # (fail-closed, the exact P9 evidence shape).
  rt_priv_fd_selftest
  info "R7-privacy fd-control: method=$RT_FD_METHOD deleted=$RT_FD_DELETED substituted=$RT_FD_SUBSTITUTED openfail=$RT_FD_OPENFAIL ctx-discrim=$RT_FD_CTX_DISCRIM ref=${RT_FD_REF:-none} got=${RT_FD_TUPLE:-none} ino=${RT_FD_INO:-none} ctx=${RT_FD_CTX:-none} parent-ctx=${RT_FD_PARENT_CTX:-none}"
  # The short-lived runc dir and runc-log.json died inside the fixed
  # 0.3s poll window in earlier runs (never-seen). The capture is now
  # EVENT-DRIVEN: a recursive inotify watcher over both op-tree roots
  # feeds a FIFO, and every create/attrib/moved_to/delete/moved_from
  # event is journaled: lifecycle events on an ops/<op>/runc dir fire an
  # IMMEDIATE per-event fd-pinned capture (microseconds after the kernel
  # event — the fixup chmod fires attrib, the runc dir creation fires
  # create) and delete/moved_from events journal the removal itself, so
  # a created-and-removed lifetime is provable instead of silent. The
  # survey sweep stays as the heartbeat sampler. The verdicts are
  # set-based over every captured record: the P2 UAT's B=never-seen
  # regression was a degenerate LAST record (dir vanished between the
  # survey's test and stat) shadowing a complete correct observation —
  # incomplete records are now counted, never decisive. Overflow,
  # watcher death, zero observed events, or the interval-blind fallback
  # poller mark the capture degraded and fail the privacy legs
  # explicitly (never an OK on an unprovable observation window).
  rt_priv_survey_once() {
    for RT_OPDIR in /run/docker-helper-builder/ops/*; do
      [ -d "$RT_OPDIR" ] || continue
      RT_OP="$(basename "$RT_OPDIR")"
      printf 'op %s %s\n' "$RT_OP" "$(stat -c '%a|%U|%G|%C' "$RT_OPDIR" 2>/dev/null)" >> "$RT_SURVEY"
      if [ -d "$RT_OPDIR/runc" ]; then
        # The shared fd-pinned reader (the same contract as the per-event
        # capture and the runc-log lines): with the technique proven, the
        # open is the single pathname-dependent step and the attributes
        # come from the pinned inode; the dir existed at test time but
        # may vanish before the open — that degenerate record is an
        # incomplete observation the classifier counts, never the
        # authoritative one.
        rt_priv_runc_read "$RT_OPDIR/runc" "runc $RT_OP"
      fi
    done
    for RT_STDIR in /var/lib/docker-helper-builder/ops/*; do
      [ -d "$RT_STDIR" ] || continue
      RT_OP="$(basename "$RT_STDIR")"
      printf 'state-op %s %s\n' "$RT_OP" "$(stat -c '%a|%U|%G|%C' "$RT_STDIR" 2>/dev/null)" >> "$RT_SURVEY"
      RT_LOG_PATH="$RT_STDIR/root/runc-native/executor/runc-log.json"
      if [ -f "$RT_LOG_PATH" ]; then
        # Two separate reads with their own exit status and stderr, so the
        # analysis can distinguish a teardown ENOENT (mode read failed,
        # file already gone) from a genuine context-read failure (file
        # present, %C unresolvable). Every observation is recorded, not
        # only the surviving ones.
        RT_LOG_MODE="$(stat -c '%a|%U|%G' "$RT_LOG_PATH" 2>"$RT_SURVEY.sterr")"
        RT_LOG_ST_RC=$?
        RT_LOG_ST_ERR="$(tr '\n' ' ' <"$RT_SURVEY.sterr" 2>/dev/null | tr ' ' '_')"
        RT_LOG_CTX="$(stat -c '%C' "$RT_LOG_PATH" 2>"$RT_SURVEY.cxerr")"
        RT_LOG_CX_RC=$?
        RT_LOG_CX_ERR="$(tr '\n' ' ' <"$RT_SURVEY.cxerr" 2>/dev/null | tr ' ' '_')"
        printf 'runc-log %s st_rc=%d st_err=%s cx_rc=%d cx_err=%s %s|%s\n' \
          "$RT_OP" \
          "$RT_LOG_ST_RC" "${RT_LOG_ST_ERR:-none}" \
          "$RT_LOG_CX_RC" "${RT_LOG_CX_ERR:-none}" \
          "${RT_LOG_MODE:-}" "${RT_LOG_CTX:-?}" >> "$RT_SURVEY"
      fi
    done
  }
  # rt_priv_capture_runc PATH EVENT — the immediate per-event capture:
  # fired by the reader loop the moment inotify reports a lifecycle event
  # (create/attrib/moved_to) on an ops/<op>/runc dir, microseconds after
  # the kernel event instead of at the next survey sweep. Same reader as
  # the survey line: with the fd technique proven, the open pins the
  # inode and every attribute is read through the pinned FD, so the
  # removal racing the capture cannot split the tuple (the P9
  # regression); a dir gone before the open journals an explicit
  # incomplete runc-obs record — evidence, never a silent gap and never
  # a validation.
  rt_priv_capture_runc() {
    RT_CAP_OP="$(basename "$(dirname "$1")")"
    rt_priv_runc_read "$1" "runc-obs $RT_CAP_OP ev=$2"
  }
  RT_EVENT_CAPTURE=unavailable
  RT_INO_PID=""
  if ! command -v inotifywait >/dev/null 2>&1; then
    zypper --non-interactive install -y inotify-tools >/dev/null 2>&1 || true
  fi
  if command -v inotifywait >/dev/null 2>&1; then
    RT_FIFO=/tmp/uat-wls-privacy-events
    rm -f "$RT_FIFO"
    if mkfifo "$RT_FIFO" 2>/dev/null; then
      # The sampler's own functional self-test (fail-closed): a scratch
      # watcher outside the op trees must observe a touch's create and
      # attrib events, or the event capture is recorded unavailable and
      # the fixed poller stays. An empty --format template produced no
      # output lines in the first dispatch (events observed: 0 while the
      # builds lived) — the template emits the event name.
      RT_SELF_FIFO=/tmp/uat-wls-privacy-selftest
      RT_SELF_DIR=/tmp/uat-wls-privacy-selftest-dir
      rm -rf "$RT_SELF_DIR"; mkdir -p "$RT_SELF_DIR"
      if mkfifo "$RT_SELF_FIFO" 2>/dev/null; then
        inotifywait -m -q -e create,attrib --format '%e|%w%f' "$RT_SELF_DIR" \
          > "$RT_SELF_FIFO" 2>/dev/null &
        RT_SELF_PID=$!
        exec 4<"$RT_SELF_FIFO"
        touch "$RT_SELF_DIR/probe"
        RT_SELF_EVENTS=0
        RT_SELF_END=$(( $(date +%s) + 2 ))
        while [ "$(date +%s)" -lt "$RT_SELF_END" ]; do
          if read -t 1 -r -u 4 _; then
            RT_SELF_EVENTS=$((RT_SELF_EVENTS + 1))
          fi
        done
        exec 4<&-
        kill "$RT_SELF_PID" 2>/dev/null || true
        wait "$RT_SELF_PID" 2>/dev/null || true
        rm -rf "$RT_SELF_DIR" "$RT_SELF_FIFO"
      fi
      if [ "${RT_SELF_EVENTS:-0}" -ge 1 ]; then
        RT_EVENT_CAPTURE=active
        RT_CAPTURE_DEGRADED=0
        # Watch the PARENT roots: the ops roots themselves are created
        # (and pruned) by the builder flow, so a watcher armed on them
        # before the builds dies with "No such file or directory" (the
        # 39166421342 dispatch); the parents exist from service start
        # and inotifywait -r adopts newly created subtrees dynamically.
        # The event line carries the event name AND the path (%e|%w%f):
        # the reader loop needs the path to fire the immediate per-event
        # runc-dir capture and to journal delete/moved_from (a created-
        # and-removed lifetime must be provable, not silent). inotify
        # queue overflow is never filterable away — any OVERFLOW event
        # marks the capture degraded (fail-closed, never an OK).
        inotifywait -m -r -q -e create,attrib,moved_to,delete,moved_from --format '%e|%w%f' \
          /run/docker-helper-builder /var/lib/docker-helper-builder \
          > "$RT_FIFO" 2>/tmp/uat-wls-privacy-inotify.err &
        RT_INO_PID=$!
        exec 3<"$RT_FIFO"
        RT_EVENT_EVENTS=0
      else
        info "R7-privacy selftest: the inotify sampler observed no events; falling back to the fixed poller"
      fi
    fi
  fi
  # The R7 P6 exec-boundary instrument (race-free): ftrace with two
  # event groups, each proving one link of the exec completion:
  #   - events/sched/sched_process_exec filtered to
  #     filename == "/proc/self/fd/6": the tracepoint fires in
  #     exec_binprm AFTER search_binary_handler returns success — i.e.
  #     only after begin_new_exec, the ELF segment mapping, the
  #     interpreter load, and start_thread all completed. No record
  #     means the load never finished (a mid-load death never reaches
  #     it; the P5 elf_map SIGSEGV shape produces none).
  #   - events/syscalls filtered to comm == "6": the kernel sets the
  #     task comm from the exec path basename inside begin_new_exec, so
  #     a sys_exit_execve record for a comm=6 task is a successful
  #     execve return, and any sys_enter record is a syscall executed
  #     by the new image itself (ld.so / Go runtime startup).
  # A positive control (a subshell execs its own sleep copy THROUGH
  # /proc/self/fd/6) must produce records in BOTH groups before the
  # window starts, or the instrument is declared void — a zero-record
  # window is then an honest observation, never a silent instrument
  # failure.
  RT_TRACE_DIR=/sys/kernel/debug/tracing
  RT_TRACE_READY=0
  if [ ! -d "$RT_TRACE_DIR" ]; then
    mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
  fi
  if [ -d "$RT_TRACE_DIR" ]; then
    RT_TRACE_ON_PRIOR="$(cat "$RT_TRACE_DIR/tracing_on" 2>/dev/null)"
    echo 0 > "$RT_TRACE_DIR/tracing_on" 2>/dev/null || true
    if printf 'filename == "/proc/self/fd/6"' > "$RT_TRACE_DIR/events/sched/sched_process_exec/filter" 2>/dev/null \
        && echo 1 > "$RT_TRACE_DIR/events/sched/sched_process_exec/enable" 2>/dev/null \
        && { printf 'comm == "6"' > "$RT_TRACE_DIR/events/syscalls/filter" 2>/dev/null \
             || printf 'common_comm == "6"' > "$RT_TRACE_DIR/events/syscalls/filter" 2>/dev/null; } \
        && echo 1 > "$RT_TRACE_DIR/events/syscalls/enable" 2>/dev/null \
        && : > "$RT_TRACE_DIR/trace" 2>/dev/null \
        && echo 1 > "$RT_TRACE_DIR/tracing_on" 2>/dev/null; then
      RT_TRACE_READY=1
      # The P7 cgroup-stage probe: the runc PARENT's openat2 completions
      # (comm is the exec'd binary's basename, no exec happens inside the
      # parent task). The P7 grant removed the TE read denial, yet the
      # parent's supportedControllers() openat2 still fails with EACCES
      # and NO AVC — the per-event probe records every openat2 EXIT of
      # the parent (its ret field exposes the -13 completions) so the
      # failure is proven to be a real syscall outcome, not a cached
      # error, and its unaudited nature becomes decisive alongside the
      # loaded-policy dontaudit introspection in the analysis section.
      printf 'comm == "buildkit-runc"' > "$RT_TRACE_DIR/events/syscalls/sys_exit_openat2/filter" 2>/dev/null \
        && echo 1 > "$RT_TRACE_DIR/events/syscalls/sys_exit_openat2/enable" 2>/dev/null \
        || info "R7-privacy ftrace: the openat2 parent probe could not be armed (continuing without it)"
    fi
  fi
  RT_TRACE_CTRL=0
  if [ "$RT_TRACE_READY" -eq 1 ]; then
    RT_CTRL_DIR=/tmp/uat-wls-comm6-ctl
    rm -rf "$RT_CTRL_DIR"; mkdir -p "$RT_CTRL_DIR"
    if cp /bin/sleep "$RT_CTRL_DIR/6" 2>/dev/null && [ -x "$RT_CTRL_DIR/6" ]; then
      ( exec /proc/self/fd/6 0 ) 6< "$RT_CTRL_DIR/6" 2>/dev/null
      RT_TRACE_CTRL="$(cat "$RT_TRACE_DIR/trace" 2>/dev/null | grep -c 'sched_process_exec\|sys_enter\|sys_exit' || true)"
    fi
    rm -rf "$RT_CTRL_DIR"
    : > "$RT_TRACE_DIR/trace" 2>/dev/null || true
    [ "$RT_TRACE_CTRL" -ge 1 ] || { RT_TRACE_READY=0; info "R7-privacy ftrace: the positive control produced no records (ctrl=$RT_TRACE_CTRL) — the instrument is void"; }
  fi
  [ "$RT_TRACE_READY" -eq 1 ] || info "R7-privacy ftrace: unavailable or void (no usable debugfs tracing / control failed); the exec-boundary leg will be BLOCKED"
  # The R7 P6 exec-boundary instrument: a tight /proc sweep running while
  # the two builds execute. The exeseal init child is SHORT-LIVED (it
  # waits for bootstrap data the failing parent never sends, then the
  # parent's cleanup kills it within the parent's own syscall path —
  # sub-millisecond), so its per-operation attribution (the /proc exe
  # link and the SELinux context carry the op's category) is only
  # observable once the clone survives long enough — the sweep is the
  # instrument for a future state where the clone LIVES, not for the
  # current sub-millisecond window (the race-free completion evidence is
  # the ftrace instrument above). The comm probe uses the read BUILTIN
  # with a stderr redirect (the $(<file) substitution loses its no-fork
  # special case when a second redirection is present and returns EMPTY —
  # the first sweep dispatch observed zero lines because of exactly that
  # shell semantics); the exe/attr reads run only for the rare matches. A
  # per-sweep counter (builtin reads/writes only) proves the sweep was
  # ALIVE during the window, so a zero-hit result is an honest negative
  # observation, never a silent instrument failure.
  RT_MEMFD_CAPTURE=/tmp/uat-wls-privacy-memfd-proc.txt
  RT_MEMFD_SWEEPS=/tmp/uat-wls-privacy-memfd-sweeps.txt
  : > "$RT_MEMFD_CAPTURE"
  printf '0' > "$RT_MEMFD_SWEEPS"
  ( while :; do
      for RT_MP in /proc/[0-9]*; do
        RT_MCOMM=""
        read -r RT_MCOMM < "$RT_MP/comm" 2>/dev/null || true
        [ "$RT_MCOMM" = "6" ] || continue
        RT_MPID="${RT_MP#/proc/}"
        RT_MCTX="$(cat "$RT_MP/attr/current" 2>/dev/null)"
        RT_MEXE="$(readlink "$RT_MP/exe" 2>/dev/null)"
        printf 'memfd-proc pid=%s comm=6 ctx=%s exe=%s\n' \
          "$RT_MPID" "${RT_MCTX:-?}" "${RT_MEXE:-?}" >> "$RT_MEMFD_CAPTURE"
      done
      RT_SWEEPS_N="$( < "$RT_MEMFD_SWEEPS" )"
      printf '%s' "$(( ${RT_SWEEPS_N:-0} + 1 ))" > "$RT_MEMFD_SWEEPS"
    done ) &
  RT_MEMFD_SWEEP_PID=$!
  ( DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" dh build runtime-privacy \
      --dockerfile Dockerfile --image uat-privacy-a:2.2 \
      >/tmp/uat-wls-privacy-a.log 2>&1 ) & RT_PID_A=$!
  ( DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" dh build runtime-privacy \
      --dockerfile Dockerfile --image uat-privacy-b:2.2 \
      >/tmp/uat-wls-privacy-b.log 2>&1 ) & RT_PID_B=$!
  RT_DEADLINE=$(( $(date +%s) + 180 ))
  while kill -0 "$RT_PID_A" 2>/dev/null || kill -0 "$RT_PID_B" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$RT_DEADLINE" ]; then
      break
    fi
    if [ "$RT_EVENT_CAPTURE" = "active" ]; then
      # A 150ms read timeout keeps the heartbeat survey tight when the
      # event stream is quiet, without changing production behavior.
      if read -t 0.15 -r -u 3 RT_EVT; then
        RT_EVENT_EVENTS=$((RT_EVENT_EVENTS + 1))
        case "$RT_EVT" in
          *OVERFLOW*)
            RT_CAPTURE_DEGRADED=1
            printf 'capture-overflow\n' >> "$RT_SURVEY"
            ;;
          *)
            RT_EVT_NAME="${RT_EVT%%|*}"
            RT_EVT_PATH="${RT_EVT#*|}"
            case "$RT_EVT_PATH" in
              */runc)
                case "$RT_EVT_NAME" in
                  *CREATE*|*ATTRIB*|*MOVED_TO*)
                    rt_priv_capture_runc "$RT_EVT_PATH" "$RT_EVT_NAME"
                    ;;
                  *DELETE*|*MOVED_FROM*)
                    printf 'runc-gone %s ev=%s path=%s\n' \
                      "$(basename "$(dirname "$RT_EVT_PATH")")" \
                      "$RT_EVT_NAME" "$RT_EVT_PATH" >> "$RT_SURVEY"
                    ;;
                esac
                ;;
              /run/docker-helper-builder/ops/*)
                # ANY other lifecycle event inside a runtime op tree also
                # fires an immediate runc capture for that op. The runc
                # dir's own create event can be lost to the inotify
                # recursive-adoption race (inotifywait registers the
                # watch on ops/<op> only when it PROCESSES the create
                # event, so children created inside that window are
                # silent), and a failed registration prints the ENOENT
                # adoption error seen in the P5 run — a sibling event
                # while the dir lives is an independent second capture
                # chance. The capture pins the dir through the fd-pinned
                # reader and journals the outcome with its own exit
                # statuses; a vanished dir records an incomplete
                # observation, never a validation.
                RT_CAP_OPDIR="$(printf '%s' "$RT_EVT_PATH" | sed -n 's|^\(/run/docker-helper-builder/ops/[^/]*\).*|\1|p')"
                if [ -n "$RT_CAP_OPDIR" ] && [ -d "$RT_CAP_OPDIR/runc" ]; then
                  rt_priv_capture_runc "$RT_CAP_OPDIR/runc" "$RT_EVT_NAME"
                fi
                ;;
            esac
            ;;
        esac
      fi
      rt_priv_survey_once
    else
      # Fallback poller: the capture is interval-blind (a short-lived dir
      # can live and die between the 0.3s sweeps), so the capture is
      # degraded by construction and the privacy legs must not report OK
      # on it.
      RT_CAPTURE_DEGRADED=1
      rt_priv_survey_once
      sleep 0.3
    fi
  done
  if [ "$RT_EVENT_CAPTURE" = "active" ]; then
    RT_INO_ALIVE=no
    kill -0 "$RT_INO_PID" 2>/dev/null && RT_INO_ALIVE=yes
    [ "$RT_INO_ALIVE" = "no" ] && RT_CAPTURE_DEGRADED=1
    exec 3<&-
    kill "$RT_INO_PID" 2>/dev/null || true
    wait "$RT_INO_PID" 2>/dev/null || true
    [ "${RT_EVENT_EVENTS:-0}" -eq 0 ] && RT_CAPTURE_DEGRADED=1
  fi
  RT_WATCH_ERRORS_RUN="$(rt_priv_watch_error_count /tmp/uat-wls-privacy-inotify.err /run/docker-helper-builder)"
  RT_WATCH_ERRORS_VAR="$(rt_priv_watch_error_count /tmp/uat-wls-privacy-inotify.err /var/lib/docker-helper-builder)"
  # The capture quality is "full" only when the watcher survived, observed
  # events, stayed overflow-free, AND registered every RUNTIME-tree
  # directory without error: an adoption failure means the watcher
  # silently missed part of the tree's lifetime, so absence of records
  # for an op cannot be claimed as proven non-creation.
  RT_CAPTURE_QUALITY=full
  if [ "$RT_CAPTURE_DEGRADED" = "1" ] || [ "$RT_WATCH_ERRORS_RUN" -gt 0 ]; then
    RT_CAPTURE_QUALITY=incomplete
  fi
  RT_CAP_DESC="$(rt_priv_capture_desc "$RT_EVENT_CAPTURE" "$RT_CAPTURE_DEGRADED" "run:$RT_WATCH_ERRORS_RUN/var:$RT_WATCH_ERRORS_VAR")"
  info "R7-privacy capture: event-driven=$RT_EVENT_CAPTURE (events observed: ${RT_EVENT_EVENTS:-0}; watcher survived: ${RT_INO_ALIVE:-n/a}; capture-degraded=${RT_CAPTURE_DEGRADED:-n/a}; watch-errors=run:$RT_WATCH_ERRORS_RUN/var:$RT_WATCH_ERRORS_VAR; watcher stderr: $(head -2 /tmp/uat-wls-privacy-inotify.err 2>/dev/null || echo none))"
  wait "$RT_PID_A"; RT_RC_A=$?
  wait "$RT_PID_B"; RT_RC_B=$?
  kill "$RT_MEMFD_SWEEP_PID" 2>/dev/null || true
  wait "$RT_MEMFD_SWEEP_PID" 2>/dev/null || true
  RT_TRACE_EXEC=0; RT_TRACE_EXECVE=0; RT_TRACE_ENTER=0; RT_TRACE_SAMPLE=""; RT_TRACE_RAW_LINES=0; RT_TRACE_OPENAT2_EACCES=0
  if [ "$RT_TRACE_READY" -eq 1 ]; then
    echo 0 > "$RT_TRACE_DIR/tracing_on" 2>/dev/null || true
    RT_TRACE_RAW="$(cat "$RT_TRACE_DIR/trace" 2>/dev/null || true)"
    echo 0 > "$RT_TRACE_DIR/events/syscalls/enable" 2>/dev/null || true
    echo 0 > "$RT_TRACE_DIR/events/sched/sched_process_exec/enable" 2>/dev/null || true
    printf '0' > "$RT_TRACE_DIR/events/syscalls/filter" 2>/dev/null || true
    printf '0' > "$RT_TRACE_DIR/events/sched/sched_process_exec/filter" 2>/dev/null || true
    [ "${RT_TRACE_ON_PRIOR:-0}" = "1" ] && echo 1 > "$RT_TRACE_DIR/tracing_on" 2>/dev/null || true
    RT_TRACE_EXEC="$(printf '%s\n' "$RT_TRACE_RAW" | grep -c 'sched_process_exec' || true)"
    RT_TRACE_EXECVE="$(printf '%s\n' "$RT_TRACE_RAW" | grep -c 'sys_exit_execve' || true)"
    RT_TRACE_ENTER="$(printf '%s\n' "$RT_TRACE_RAW" | grep -c 'sys_enter_' || true)"
    RT_TRACE_OPENAT2_EACCES="$(printf '%s\n' "$RT_TRACE_RAW" | grep 'sys_exit_openat2' | grep -c 'ret=-13' || true)"
    RT_TRACE_OPENAT2_ALL="$(printf '%s\n' "$RT_TRACE_RAW" | grep -c 'sys_exit_openat2' || true)"
    RT_TRACE_RAW_LINES="$(printf '%s\n' "$RT_TRACE_RAW" | grep -c . || true)"
    RT_TRACE_SAMPLE="$(printf '%s\n' "$RT_TRACE_RAW" | grep 'sched_process_exec\|sys_exit_execve' | head -1)"
    RT_TRACE_O2_SAMPLE="$(printf '%s\n' "$RT_TRACE_RAW" | grep 'sys_exit_openat2' | grep 'ret=-13' | head -1)"
  fi
  info "R7-privacy ftrace: ready=$RT_TRACE_READY sched_process_exec=$RT_TRACE_EXEC sys_exit_execve=$RT_TRACE_EXECVE sys_enter=$RT_TRACE_ENTER openat2_exit=$RT_TRACE_OPENAT2_ALL openat2_eacces=$RT_TRACE_OPENAT2_EACCES raw_lines=$RT_TRACE_RAW_LINES first=${RT_TRACE_SAMPLE:-none} o2=${RT_TRACE_O2_SAMPLE:-none}"
  RT_OPS="$(grep '^op ' "$RT_SURVEY" | awk '{ print $2 }' | awk '!seen[$0]++')"
  RT_OP_COUNT=0
  RT_STAT_A=""; RT_STAT_B=""
  RT_RUNC_VERDICT_A=""; RT_RUNC_VERDICT_B=""
  RT_RUNC_FIRST_A=""; RT_RUNC_FIRST_B=""
  for RT_OP in $RT_OPS; do
    RT_OP_COUNT=$((RT_OP_COUNT + 1))
    RT_STAT="$(grep "^op $RT_OP " "$RT_SURVEY" | awk '$3 != ""' | head -1 | awk '{ print $3 }')"
    RT_VERDICT="$(rt_priv_runc_verdict "$RT_SURVEY" "$RT_OP" "$RT_STAT" "$RT_CAPTURE_QUALITY")"
    RT_RUNC_FIRST="$(grep -h "^runc $RT_OP \|^runc-obs $RT_OP " "$RT_SURVEY" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[^ ]*\|/) { print $i; exit } }' | head -1)"
    if [ "$RT_OP_COUNT" -eq 1 ]; then
      RT_STAT_A="$RT_STAT"; RT_RUNC_VERDICT_A="$RT_VERDICT"; RT_RUNC_FIRST_A="$RT_RUNC_FIRST"
    elif [ "$RT_OP_COUNT" -eq 2 ]; then
      RT_STAT_B="$RT_STAT"; RT_RUNC_VERDICT_B="$RT_VERDICT"; RT_RUNC_FIRST_B="$RT_RUNC_FIRST"
    fi
    info "R7-privacy op=$RT_OP dir=${RT_STAT:-unobserved} runc_first=${RT_RUNC_FIRST:-never-seen} runc_verdict=${RT_VERDICT:-unavailable}"
  done
  # stat tuples are mode|uid|gid|context
  RT_CTX_A="$(printf '%s' "$RT_STAT_A" | awk -F'|' '{ print $4 }')"
  RT_CTX_B="$(printf '%s' "$RT_STAT_B" | awk -F'|' '{ print $4 }')"
  if [ "$RT_OP_COUNT" -ge 2 ] && [ -n "$RT_CTX_A" ] && [ -n "$RT_CTX_B" ] \
      && [ "$RT_CTX_A" != "$RT_CTX_B" ]; then
    acc_ok "R7 runtime privacy: two concurrent operations carried DISTINCT runtime-tree categories (${RT_CTX_A##*:s0} vs ${RT_CTX_B##*:s0})"
  else
    acc_fail "R7 runtime privacy: the per-operation category allocation did not show two distinct concurrent categories (ops seen: $RT_OP_COUNT)"
  fi
  # The R7 P6 exec-boundary observations. The /proc sweep verdict is an
  # OBSERVATION line, not a leg: the clone is killed sub-millisecond by
  # the failing parent, below any process-lifetime instrument's
  # resolution — zero hits here are the expected current-boundary shape,
  # and the sweep becomes decisive once a future phase lets the clone
  # live (per-operation attribution via the process context). The
  # MANDATORY exec-boundary leg is the race-free ftrace evidence: the
  # sys_exit_execve record of the comm=6 task is only producible by a
  # SUCCESSFUL execve return.
  RT_MEMFD_VERDICT="$(rt_priv_memfd_verdict "$RT_MEMFD_CAPTURE" "$RT_CTX_A" "$RT_CTX_B")"
  RT_MEMFD_SWEEPS_N="$( < "$RT_MEMFD_SWEEPS" )"
  info "R7-privacy memfd-proc: ${RT_MEMFD_VERDICT:-unavailable} (capture lines: $(wc -l < "$RT_MEMFD_CAPTURE" 2>/dev/null || echo 0); sweeps: ${RT_MEMFD_SWEEPS_N:-0})"
  if [ "$RT_TRACE_READY" -eq 1 ]; then
    if [ "$RT_TRACE_EXEC" -ge 1 ]; then
      acc_ok "R7 runtime privacy: the exec'd sealed memfd clone COMPLETED its exec — the kernel's sched_process_exec record (filename=/proc/self/fd/6) exists only after the FULL load finished (begin_new_exec, ELF segment mapping, interpreter, start_thread) and the new image started (exec-completion records: $RT_TRACE_EXEC; execve-return records: $RT_TRACE_EXECVE; userspace syscall entries by the new image: $RT_TRACE_ENTER; first: ${RT_TRACE_SAMPLE:-none})"
    elif [ "$RT_TRACE_EXECVE" -ge 1 ]; then
      acc_ok "R7 runtime privacy: the exec'd sealed memfd clone completed its execve (the kernel's sys_exit_execve record for the comm=6 task; sched_process_exec records: $RT_TRACE_EXEC; userspace syscall entries: $RT_TRACE_ENTER)"
    else
      acc_fail "R7 runtime privacy: no completed exec of the /proc/self/fd/6 clone was recorded (sched_process_exec=0, sys_exit_execve=0, userspace entries=$RT_TRACE_ENTER) — the exec never returned into the new image despite zero SELinux denials on the exec path"
    fi
  else
    acc_blocked "R7 runtime privacy: ftrace tracing unavailable or its positive control failed in this guest — the exec-boundary completion evidence is impossible to obtain (sweep observation: ${RT_MEMFD_VERDICT:-unavailable})"
  fi
  # The runc-dir verdicts are set-based (the classifier above): EVERY
  # complete observation (survey sweep or immediate per-event capture)
  # must carry the op's own context, owner-only mode, and the op tree's
  # flow identity. Incomplete records (dir existed at test time, vanished
  # before the stat) and runc-gone delete events are counted, never
  # decisive — the P2 UAT's B=never-seen regression shape was exactly a
  # degenerate LAST record (test-then-stat race) shadowing a complete
  # correct observation. A degraded capture (overflow, watcher death,
  # zero events, or the interval-blind fallback poller) fails the legs
  # explicitly: an unprovable observation window is never an OK.
  RT_CTX_LEG=1
  for RT_V in "$RT_RUNC_VERDICT_A" "$RT_RUNC_VERDICT_B"; do
    case "$RT_V" in *"ctx=OK"*) : ;; *) RT_CTX_LEG=0 ;; esac
  done
  if [ "$RT_CAPTURE_DEGRADED" = "1" ]; then
    RT_CTX_LEG=0
  fi
  if [ "$RT_OP_COUNT" -ge 2 ] && [ "$RT_CTX_LEG" -eq 1 ]; then
    acc_ok "R7 runtime privacy: each observed runc dir's SELinux context equals its own operation's runtime-tree context (the match is per-op, on top of the distinct categories proven above — never one bare s0:c1 match; A=${RT_RUNC_VERDICT_A} B=${RT_RUNC_VERDICT_B})"
  else
    acc_fail "R7 runtime privacy: the runc dir's context leg failed (A=${RT_RUNC_VERDICT_A:-unavailable} B=${RT_RUNC_VERDICT_B:-unavailable}; $RT_CAP_DESC)"
  fi
  # The classifier's own regression table (fail-closed: a classifier
  # that disagrees with this table fails the section, never the UAT
  # silently passing a mis-classified mode). Encoded in shell exit
  # semantics: 0 = the property HOLDS, 1 = the property is VIOLATED.
  #   0700 owner-only HOLDS no-write HOLDS; 1700 (sticky+0700)
  #   owner-only HOLDS no-write HOLDS; 0711 owner-only VIOLATED
  #   (group/other execute is access) no-write HOLDS; 1755 owner-only
  #   VIOLATED no-write HOLDS (group r-x / other r-x is read-only,
  #   never write); 0722 owner-only VIOLATED no-write VIOLATED
  #   (group/other write).
  RT_SELFTEST_RC=0
  for RT_CASE in 0700:0:0 1700:0:0 0711:1:0 1755:1:0 0722:1:1; do
    RT_CASE_M="$(printf '%s' "$RT_CASE" | cut -d: -f1)"
    RT_CASE_OO="$(printf '%s' "$RT_CASE" | cut -d: -f2)"
    RT_CASE_NW="$(printf '%s' "$RT_CASE" | cut -d: -f3)"
    rt_priv_owner_only "$RT_CASE_M"; RT_GOT_OO=$?
    rt_priv_no_write "$RT_CASE_M"; RT_GOT_NW=$?
    [ "$RT_GOT_OO" -eq "$RT_CASE_OO" ] || { RT_SELFTEST_RC=1; info "R7-privacy selftest: owner-only mis-classified $RT_CASE_M (got $RT_GOT_OO want $RT_CASE_OO)"; }
    [ "$RT_GOT_NW" -eq "$RT_CASE_NW" ] || { RT_SELFTEST_RC=1; info "R7-privacy selftest: no-write mis-classified $RT_CASE_M (got $RT_GOT_NW want $RT_CASE_NW)"; }
  done
  if [ "$RT_SELFTEST_RC" -ne 0 ]; then
    acc_fail "R7 runtime privacy: the mode classifier disagrees with its own regression table (owner-only/no-write invariant split)"
  fi
  # The fixup's settled mode is owner-only with no group/other access
  # (observed live: the runtime sets sticky+0700 = 1700); the privacy
  # property is the ABSENCE of group/other access, classified by the
  # owner-only invariant — group/other read or execute is NOT absence
  # of access. The leg is decided by the same set-based verdicts as the
  # context leg: every complete observation must be owner-only with the
  # op tree's flow identity, incomplete and runc-gone observations are
  # counted and never decisive, and a degraded capture fails explicitly.
  RT_MODE_LEG=1
  for RT_V in "$RT_RUNC_VERDICT_A" "$RT_RUNC_VERDICT_B"; do
    case "$RT_V" in *"mode=OK"*) : ;; *) RT_MODE_LEG=0 ;; esac
  done
  if [ "$RT_CAPTURE_DEGRADED" = "1" ]; then
    RT_MODE_LEG=0
  fi
  if [ "$RT_OP_COUNT" -ge 2 ] && [ "$RT_MODE_LEG" -eq 1 ]; then
    acc_ok "R7 runtime privacy: the fixup TIGHTENED the ops' own runc dirs (every complete observation owner-only with the op tree's flow identity; incomplete and runc-gone observations counted, never decisive; A=${RT_RUNC_VERDICT_A} B=${RT_RUNC_VERDICT_B})"
  else
    acc_fail "R7 runtime privacy: the settled runc dir leg failed (A=${RT_RUNC_VERDICT_A:-unavailable} B=${RT_RUNC_VERDICT_B:-unavailable}; $RT_CAP_DESC)"
  fi
  RT_WIDENED=0
  for RT_PATH in /run/docker-helper-builder /run/docker-helper-builder/ops; do
    RT_M="$(stat -c '%a' "$RT_PATH" 2>/dev/null)"
    rt_priv_no_write "$RT_M" || RT_WIDENED=1
  done
  for RT_OP in $RT_OPS; do
    RT_M="$(grep "^op $RT_OP " "$RT_SURVEY" | awk '$3 != ""' | head -1 | awk '{ print $3 }' | awk -F'|' '{ print $1 }')"
    rt_priv_no_write "$RT_M" || RT_WIDENED=1
  done
  if [ "$RT_WIDENED" -eq 0 ] && [ -n "$RT_OPS" ]; then
    acc_ok "R7 runtime privacy: no group/other WRITE anywhere on the observed tree path (the runtime root, ops/, every observed op dir — read-only group/other bits are not write) — no writable path toward another operation or the shared runtime root"
  else
    acc_fail "R7 runtime privacy: unexpected group/other write on the shared runtime path or an op dir"
  fi
  RT_RESIDUE_OK=1
  for RT_OP in $RT_OPS; do
    if [ -d "/run/docker-helper-builder/ops/$RT_OP" ]; then
      RT_RESIDUE_OK=0
    fi
  done
  if [ "$RT_RESIDUE_OK" -eq 1 ] && [ "$RT_OP_COUNT" -ge 1 ]; then
    acc_ok "R7 runtime privacy: after both builds reached terminal, every observed per-op runtime tree is gone (no leftover restricted dirs)"
  else
    acc_fail "R7 runtime privacy: per-op runtime-tree residue survived the terminal convergence"
  fi
  if [ "$RT_RC_A" -eq 0 ] && [ "$RT_RC_B" -eq 0 ]; then
    acc_ok "R7 runtime privacy: both concurrent sleep builds completed the FULL image lifecycle on the enforcing consumer (the bundled OCI runtime executed the RUN steps, then build, load, verify, tag, cleanup)"
  else
    acc_fail "R7 runtime privacy: a concurrent sleep build did not complete (rcA=$RT_RC_A rcB=$RT_RC_B): $(redact </tmp/uat-wls-privacy-a.log | tail -3) | $(redact </tmp/uat-wls-privacy-b.log | tail -3)"
  fi
  # The P7 cgroup-stage introspection: the loaded policy's exact
  # buildkitd_t -> cgroup_t:file authority and ANY dontaudit rule
  # covering the pair. The P7 grant removed the TE read denial, yet the
  # runc parent's supportedControllers() openat2 still fails with EACCES
  # and no AVC; an unaudited SELinux denial is only producible by a
  # dontaudit rule, so this listing decides between a silent TE denial
  # (an open-completion demand suppressed by the distro policy) and a
  # non-SELinux boundary.
  RT_CG_ALLOW="$("$RT_SESEARCH_BIN" --allow -s docker_helper_buildkitd_t -t cgroup_t -c file /sys/fs/selinux/policy 2>/dev/null | grep -v '^#' || true)"
  RT_CG_DONTAUDIT="$("$RT_SESEARCH_BIN" --dontaudit -s docker_helper_buildkitd_t -t cgroup_t /sys/fs/selinux/policy 2>/dev/null | grep -v '^#' || true)"
  RT_CG_DA_DOMAIN="$("$RT_SESEARCH_BIN" --dontaudit -s domain -t cgroup_t /sys/fs/selinux/policy 2>/dev/null | grep -v '^#' || true)"
  info "R7-privacy cgroup introspection: allow=[$RT_CG_ALLOW] dontaudit-targeted=[$RT_CG_DONTAUDIT] dontaudit-domain=[$RT_CG_DA_DOMAIN]"
  RT_SESEARCH_OUT="$("$RT_SESEARCH_BIN" --allow -s docker_helper_buildkitd_t \
    -t docker_helper_builder_runtime_t -c dir /sys/fs/selinux/policy 2>/dev/null | grep -v '^#' || true)"
  RT_SESEARCH_HIT="$(printf '%s\n' "$RT_SESEARCH_OUT" | grep 'docker_helper_buildkitd_t docker_helper_builder_runtime_t:dir' || true)"
  RT_SESEARCH_N="$(printf '%s\n' "$RT_SESEARCH_HIT" | grep -c . || true)"
  RT_SESEARCH_OK=1
  [ "$RT_SESEARCH_N" -eq 1 ] || RT_SESEARCH_OK=0
  if [ "$RT_SESEARCH_OK" -eq 1 ]; then
    for RT_PERM in add_name create getattr mounton remove_name search setattr write; do
      printf '%s\n' "$RT_SESEARCH_HIT" | grep -q "$RT_PERM" || RT_SESEARCH_OK=0
    done
  fi
  if [ "$RT_SESEARCH_OK" -eq 1 ]; then
    acc_ok "R7 runtime privacy: the loaded policy's concrete buildkitd_t -> builder_runtime_t:dir grant is EXACTLY the one canonical rule with NO category (sesearch): $(printf '%s' "$RT_SESEARCH_HIT" | head -1)"
  else
    acc_fail "R7 runtime privacy: the loaded buildkitd_t -> builder_runtime_t:dir grant is not exactly the one category-blind canonical rule (hits=$RT_SESEARCH_N): $(printf '%s' "$RT_SESEARCH_HIT" | head -2)"
  fi
  # The R7 append rung's cross-operation boundary on the categorized
  # STATE tree: the append grant is type-wide TE authority, so the
  # isolation evidence must be the MCS constraint chain, not one
  # category string. Captured live on the same two concurrent builds:
  #   - each op's state-tree dir carries its own category and the two
  #     live operations' state categories are DISTINCT;
  #   - the executor's own runc-log.json (the file the append grant
  #     serves) carries ITS OWN op's state-tree category;
  #   - the loaded policy's concrete buildkitd_t ->
  #     builder_state_t:file grant is EXACTLY the one canonical rule
  #     with NO category (sesearch) — the category-blind TE grant;
  #   - the loaded policy's concrete buildkitd_t ->
  #     builder_state_t:file grant is EXACTLY the one canonical rule
  #     with NO category (sesearch) — the category-blind TE grant;
  #   - the SUBJECT side of the MCS chain: the loaded constraints are
  #     subject-gated exception form (h1 dom h2 or t1 !=
  #     mcs_constrained_type), so the enforcement bites exactly when
  #     the SUBJECT type is a member — the builder subject
  #     (docker_helper_buildkitd_t) IS one (seinfo -a), carries NO
  #     trusted-subject exemption, and the loaded file-class write/read
  #     constraint set names the attribute (seinfo --constrain file) —
  #     the object type carries only file_type BY DESIGN. The module
  #     contract (TestSELinuxPolicyMCSMembership) pins the exact
  #     six-member subject set; this consumer pin asserts the loaded
  #     congruence of the enforcement machinery itself. No harness can
  #     force buildkitd_t:s0:c1 to ATTEMPT another op's state tree; the
  #     constraint chain above is the negative proof surface this
  #     consumer offers (the live cross-category probe in the actual
  #     builder domain is BLOCKED on every consumer: the domain is not
  #     enterable from any admin context — the transition denial is
  #     itself a security fact, R7 MCS-audit evidence).
  RT_ST_A=""; RT_ST_B=""
  RT_LOG_FIRST_A=""; RT_LOG_FIRST_B=""
  RT_LOG_LAST_A=""; RT_LOG_LAST_B=""
  RT_ST_COUNT=0
  RT_LOG_VERDICT_A=""; RT_LOG_VERDICT_B=""
  RT_LOG_FIRST_A=""; RT_LOG_FIRST_B=""
  for RT_OP in $RT_OPS; do
    RT_ST="$(grep "^state-op $RT_OP " "$RT_SURVEY" | awk '$3 != ""' | head -1 | awk '{ print $3 }')"
    RT_LOG_FIRST="$(grep "^runc-log $RT_OP " "$RT_SURVEY" | head -1 | awk '{ v = $7; for (i = 8; i <= NF; i++) v = v "|" $i; print v }')"
    RT_LOG_LAST="$(grep "^runc-log $RT_OP " "$RT_SURVEY" | tail -1 | awk '{ v = $7; for (i = 8; i <= NF; i++) v = v "|" $i; print v }')"
    RT_LOG_CTX="$(rt_priv_log_verdict "$RT_SURVEY" "$RT_OP" "${RT_ST##*|}")"
    RT_ST_COUNT=$((RT_ST_COUNT + 1))
    if [ "$RT_ST_COUNT" -eq 1 ]; then
      RT_ST_A="$RT_ST"; RT_LOG_FIRST_A="$RT_LOG_FIRST"; RT_LOG_LAST_A="$RT_LOG_LAST"
      RT_LOG_VERDICT_A="$RT_LOG_CTX"
    elif [ "$RT_ST_COUNT" -eq 2 ]; then
      RT_ST_B="$RT_ST"; RT_LOG_FIRST_B="$RT_LOG_FIRST"; RT_LOG_LAST_B="$RT_LOG_LAST"
      RT_LOG_VERDICT_B="$RT_LOG_CTX"
    fi
    info "R7-privacy state op=$RT_OP dir=${RT_ST:-unobserved} runc_log_first=${RT_LOG_FIRST:-never-seen} runc_log_last=${RT_LOG_LAST:-never-seen} runc_log_verdict=${RT_LOG_CTX:-unavailable}"
  done
  RT_ST_CTX_A="$(printf '%s' "$RT_ST_A" | awk -F'|' '{ print $4 }')"
  RT_ST_CTX_B="$(printf '%s' "$RT_ST_B" | awk -F'|' '{ print $4 }')"
  if [ "$RT_ST_COUNT" -ge 2 ] && [ -n "$RT_ST_CTX_A" ] && [ -n "$RT_ST_CTX_B" ] \
      && [ "$RT_ST_CTX_A" != "$RT_ST_CTX_B" ]; then
    acc_ok "R7 runtime privacy: the two concurrent operations' categorized STATE trees carried DISTINCT categories (${RT_ST_CTX_A##*:s0} vs ${RT_ST_CTX_B##*:s0})"
  else
    acc_fail "R7 runtime privacy: the concurrent state trees did not show two distinct categories (state trees seen: $RT_ST_COUNT)"
  fi
  # The runc-log.json verdict uses EVERY complete survey observation (the
  # classifier above), not only FIRST or LAST: any complete observation
  # with a foreign category fails, zero complete observations fail, and
  # incomplete teardown-time observations are excluded from the mismatch
  # decision but surfaced in the counts (never silently dropped).
  RT_LOG_VA="$(printf '%s' "$RT_LOG_VERDICT_A" | sed -n 's/^VERDICT=//p')"
  RT_LOG_VB="$(printf '%s' "$RT_LOG_VERDICT_B" | sed -n 's/^VERDICT=//p')"
  if printf '%s\n%s' "$RT_LOG_VA" "$RT_LOG_VB" | grep -q '^FAIL'; then
    acc_fail "R7 runtime privacy: the executor runc-log.json observation set failed (A=${RT_LOG_VA:-unavailable} B=${RT_LOG_VB:-unavailable}; own contexts A=${RT_ST_CTX_A:-never-seen} B=${RT_ST_CTX_B:-never-seen})"
  else
    acc_ok "R7 runtime privacy: each observed executor runc-log.json carries ITS OWN operation's state-tree category (A=${RT_LOG_VA:-unavailable} B=${RT_LOG_VB:-unavailable}; every complete observation matched, incomplete teardown-time observations excluded and counted; first-seen A=${RT_LOG_FIRST_A:-never-seen} B=${RT_LOG_FIRST_B:-never-seen})"
  fi
  RT_ST_SESEARCH_OUT="$("$RT_SESEARCH_BIN" --allow -s docker_helper_buildkitd_t \
    -t docker_helper_builder_state_t -c file /sys/fs/selinux/policy 2>/dev/null | grep -v '^#' || true)"
  RT_ST_SESEARCH_HIT="$(printf '%s\n' "$RT_ST_SESEARCH_OUT" | grep 'docker_helper_buildkitd_t docker_helper_builder_state_t:file' || true)"
  RT_ST_SESEARCH_N="$(printf '%s\n' "$RT_ST_SESEARCH_HIT" | grep -c . || true)"
  RT_ST_SESEARCH_OK=1
  [ "$RT_ST_SESEARCH_N" -eq 1 ] || RT_ST_SESEARCH_OK=0
  if [ "$RT_ST_SESEARCH_OK" -eq 1 ]; then
    for RT_PERM in append create getattr lock open read rename setattr unlink write; do
      printf '%s\n' "$RT_ST_SESEARCH_HIT" | grep -q "$RT_PERM" || RT_ST_SESEARCH_OK=0
    done
    printf '%s\n' "$RT_ST_SESEARCH_HIT" | grep -Eq '\b(map|execute|execmod|link|relabelto|relabelfrom)\b' && RT_ST_SESEARCH_OK=0
  fi
  if [ "$RT_ST_SESEARCH_OK" -eq 1 ]; then
    acc_ok "R7 runtime privacy: the loaded policy's concrete buildkitd_t -> builder_state_t:file grant is EXACTLY the one canonical rule with NO category (sesearch): $(printf '%s' "$RT_ST_SESEARCH_HIT" | head -1)"
  else
    acc_fail "R7 runtime privacy: the loaded buildkitd_t -> builder_state_t:file grant is not exactly the one category-blind canonical rule (hits=$RT_ST_SESEARCH_N): $(printf '%s' "$RT_ST_SESEARCH_HIT" | head -2)"
  fi
  # The single-expression constraint matcher (the pin's core): ONE
  # mlsconstrain file line must carry BOTH the append permission AND the
  # subject-gated mcs_constrained_type gating (t1, the loaded exception
  # form). Grepping 'append' and the attribute independently across the
  # whole listing would accept a base-policy change that moved them into
  # different expressions — a false positive the isolation contract
  # cannot afford.
  rt_mcs_constraint_ok() {
    local l="$1"
    printf '%s' "$l" | grep -q 'mlsconstrain file' || return 1
    printf '%s' "$l" | grep -Eq '\{[^}]*\bappend\b[^}]*\}' || return 1
    printf '%s' "$l" | grep -Eq 't1 != mcs_constrained_type' || return 1
    return 0
  }
  # The membership matcher: the loaded mcs_constrained_type member list
  # must still name the builder subject.
  rt_mcs_member_ok() {
    printf '%s' "$1" | grep -q 'docker_helper_buildkitd_t'
  }
  # The matchers' own regression table (fail-closed: a matcher that
  # disagrees with this table fails the section, never the UAT silently
  # passing a mis-shaped contract). The real loaded form passes; every
  # negative mutant — missing append, t1->t2 substitution, attribute
  # absent, wrong permission set, subject absent from the member list —
  # must FAIL.
  RT_MCS_SELFTEST_RC=0
  RT_MCS_REAL='   mlsconstrain file { append link rename setattr unlink write } (h1 dom h2 or t1 != mcs_constrained_type);'
  rt_mcs_constraint_ok "$RT_MCS_REAL" || { RT_MCS_SELFTEST_RC=1; info "R7-privacy selftest: the real constraint line was rejected"; }
  rt_mcs_constraint_ok '   mlsconstrain file { link rename setattr unlink write } (h1 dom h2 or t1 != mcs_constrained_type);' && { RT_MCS_SELFTEST_RC=1; info "R7-privacy selftest: the missing-append mutant was accepted"; }
  rt_mcs_constraint_ok '   mlsconstrain file { append link rename setattr unlink write } (h1 dom h2 or t2 != mcs_constrained_type);' && { RT_MCS_SELFTEST_RC=1; info "R7-privacy selftest: the t1->t2 mutant was accepted"; }
  rt_mcs_constraint_ok '   mlsconstrain file { append link rename setattr unlink write } (h1 dom h2);' && { RT_MCS_SELFTEST_RC=1; info "R7-privacy selftest: the no-attribute mutant was accepted"; }
  rt_mcs_constraint_ok '   mlsconstrain file { read write } (h1 dom h2 or t1 != mcs_constrained_type);' && { RT_MCS_SELFTEST_RC=1; info "R7-privacy selftest: the wrong-permission-set line was accepted"; }
  RT_MCS_MEMBERS_SAMPLE='attribute mcs_constrained_type; container_t docker_helper_buildkitd_t docker_helper_rootlesskit_t'
  rt_mcs_member_ok "$RT_MCS_MEMBERS_SAMPLE" || { RT_MCS_SELFTEST_RC=1; info "R7-privacy selftest: the real member list was rejected"; }
  rt_mcs_member_ok 'attribute mcs_constrained_type; container_t svirt_t' && { RT_MCS_SELFTEST_RC=1; info "R7-privacy selftest: the subject-absent member list was accepted"; }
  if [ "$RT_MCS_SELFTEST_RC" -ne 0 ]; then
    acc_fail "R7 runtime privacy: the MCS contract matchers disagree with their own regression table (single-expression form, membership)"
  fi
  RT_ST_SEINFO="$("$RT_SEINFO_BIN" -a mcs_constrained_type -x 2>/dev/null || true)"
  if rt_mcs_member_ok "$RT_ST_SEINFO"; then
    acc_ok "R7 runtime privacy: the builder subject docker_helper_buildkitd_t is an mcs_constrained_type member on the loaded policy (seinfo -a mcs_constrained_type -x) — the loaded MCS constraints are subject-gated exception form (t1), so the enforcement bites this subject exactly as the module contract pins it"
  else
    acc_fail "R7 runtime privacy: the builder subject docker_helper_buildkitd_t did not show the mcs_constrained_type membership on the loaded policy (seinfo output: ${RT_ST_SEINFO:-absent})"
  fi
  RT_ST_SEINFO_BKD_ATTRS="$("$RT_SEINFO_BIN" -t docker_helper_buildkitd_t -x 2>/dev/null || true)"
  if printf '%s' "$RT_ST_SEINFO_BKD_ATTRS" | grep -q 'mlstrustedsubject'; then
    acc_fail "R7 runtime privacy: the builder subject docker_helper_buildkitd_t carries a trusted-subject exemption that would bypass the MCS constraints (type attributes: $RT_ST_SEINFO_BKD_ATTRS)"
  else
    acc_ok "R7 runtime privacy: the builder subject docker_helper_buildkitd_t carries no trusted-subject exemption (seinfo -t -x) — no loaded-policy exception releases the MCS enforcement"
  fi
  RT_ST_CONSTRAINTS="$("$RT_SEINFO_BIN" --constrain file 2>/dev/null || true)"
  RT_ST_CONSTRAINT_LINE="$(printf '%s\n' "$RT_ST_CONSTRAINTS" | grep 'mlsconstrain file' | grep 'append' | head -1 || true)"
  if [ -n "$RT_ST_CONSTRAINT_LINE" ] && rt_mcs_constraint_ok "$RT_ST_CONSTRAINT_LINE"; then
    acc_ok "R7 runtime privacy: ONE loaded file-class constraint expression governs the append permission through the subject-gated mcs_constrained_type gating (seinfo --constrain file): $RT_ST_CONSTRAINT_LINE"
  else
    acc_fail "R7 runtime privacy: no single loaded file-class constraint expression carries the append permission with the t1-gated mcs_constrained_type gating (seinfo --constrain file output: ${RT_ST_CONSTRAINTS:-absent})"
  fi
fi

# --- scenario S15: helper-created build staging strips SUID/SGID (C1) ---------
say "S15: helper-created build staging strips SUID/SGID"
# The staged chain must run inside the SESSION WORKSPACE (the context
# authorization is workspace-scoped), not merely inside the Principal tree.
STAGE_CTX="$TREE/work/staged-proof"
rm -rf "$STAGE_CTX"
mkdir -p "$STAGE_CTX"
printf '#!/bin/sh\n' > "$STAGE_CTX/suid-staged"
printf '#!/bin/sh\n' > "$STAGE_CTX/sgid-staged"
chown "$PRINCIPAL:$PRINCIPAL" "$STAGE_CTX/suid-staged" "$STAGE_CTX/sgid-staged"
chmod 0755 "$STAGE_CTX/suid-staged" "$STAGE_CTX/sgid-staged"
chmod u+s "$STAGE_CTX/suid-staged"
chmod g+s "$STAGE_CTX/sgid-staged"
[ -u "$STAGE_CTX/suid-staged" ] && [ -g "$STAGE_CTX/sgid-staged" ] \
  || { acc_blocked "S15 workspace privilege-bit fixture setup failed"; }
cat > "$STAGE_CTX/Dockerfile" <<'EOF'
FROM alpine:3.24
COPY suid-staged /out/suid-staged
COPY sgid-staged /out/sgid-staged
RUN test ! -u /out/suid-staged || (echo STAGED-SUID-DELIVERED; exit 1)
RUN test ! -g /out/sgid-staged || (echo STAGED-SGID-DELIVERED; exit 1)
EOF
S15_BUILD_RC=0
DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh build staged-proof --dockerfile Dockerfile --image uat-staged-proof:2.2 \
  >/tmp/uat-wls-w15-build.log 2>&1 || S15_BUILD_RC=1
S15_RUN_OUT=""
if [ "$S15_BUILD_RC" -eq 0 ]; then
  S15_RUN_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
    dh run uat-staged-proof:2.2 -- \
    sh -ec 'test ! -u /out/suid-staged && test ! -g /out/sgid-staged && echo S15-STAGED-CLEAN' 2>&1)"
fi
if [ "$S15_BUILD_RC" -eq 0 ] \
    && printf '%s\n' "$S15_RUN_OUT" | grep -q 'S15-STAGED-CLEAN'; then
  acc_ok "S15 helper-created staging delivered no privilege bits (build-time and workload tests hold)"
else
  acc_fail "S15 staged privilege-bit chain not dead: build=$(redact </tmp/uat-wls-w15-build.log | tail -3) run=$(printf '%s\n' "${S15_RUN_OUT:-absent}" | redact | tail -3)"
fi

# --- scenario S16: helper-socket hostile runtime composition (H9) -------------
say "S16: helper-socket hostile runtime composition"
if docker image inspect "$HOSTILE_IMAGE" >/dev/null 2>&1; then
  S16_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
    dh run --helper-socket --env TARGET_SESSION="$WSA_ID" "$HOSTILE_IMAGE" -- \
    /bin/sh /usr/local/bin/hostile-probe.sh 2>&1)"
  S16_EC=$?
  if [ "$S16_EC" -eq 0 ] && printf '%s\n' "$S16_OUT" | grep -q 'S16-HOSTILE-CLEAN'; then
    acc_ok "S16 socket reachable + unauthenticated call refused + private runtime unreadable/immutable + escalation dead"
  else
    acc_fail "S16 hostile helper-socket composition broken (ec=$S16_EC): $(printf '%s\n' "$S16_OUT" | redact | tail -4)"
  fi
else
  acc_blocked "S16 hostile image unavailable (helper-socket composition proof impossible)"
fi

# ==============================================================================
# summary
# ==============================================================================
echo
echo "========= RELEASE 2.2 SELINUX WORKLOAD-MAC UAT SUMMARY (Tumbleweed/RPM) ========="
printf '  FAILS:    %d\n' "$FAIL_COUNT"
printf '  BLOCKED:  %d\n' "$BLOCKED_COUNT"
echo "================================================================================="

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory SELinux workload-MAC scenario FAILED" >&2
  exit 1
fi
if [ "$BLOCKED_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory workload-MAC scenario BLOCKED (required evidence not exercised)" >&2
  exit 2
fi
echo "RESULT: Release 2.2 SELinux workload-MAC UAT PASSED"
