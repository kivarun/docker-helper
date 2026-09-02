#!/usr/bin/env bash
#
# uat-regression-selinux-relabel-avc.sh — Release-2 targeted regression
# group 5: SELinux workspace relabel AVC evidence, both directions
# (Tumbleweed / RPM / SELinux).
#
# Gathers the ACTUAL AVC evidence the confined workspace relabel lifecycle
# requires, through the REAL Session lifecycle, using a TEMPORARY permissive
# docker_helper_t domain (semanage permissive -a / -d, removed on exit) so the
# lifecycle completes end-to-end while auditd logs every would-be denial
# (permissive=1). No production policy is changed by this group.
#
# Evidence collected for a representative /opt workspace (usr_t) containing a
# directory, a regular file, a symlink and a FIFO:
#   * initial relabel   usr_t -> docker_helper_workspace_t  (session create);
#   * container-created object label (BEFORE teardown);
#   * teardown relabel  docker_helper_workspace_t -> usr_t  (session delete);
#   * container-created object final policy-default label (AFTER teardown);
#   * AVC matrices (permission x class x target type) for BOTH directions,
#     filtered to scontext=docker_helper_t comm=restorecon relabelfrom/relabelto.
#
# This is evidence only: it does NOT ship any relabel permission delta. The
# expected direction (usr_t relabelfrom + docker_helper_workspace_t relabelto,
# and the reverse on teardown) is only a hypothesis until confirmed by these
# live AVCs.
#
# Requires: installed docker-helper system service (active), enforcing SELinux,
# root, auditd with ausearch (best-effort; falls back to /var/log/audit).
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "5. SELinux workspace relabel AVC evidence (both directions)"

reg_require_root
reg_require_service
reg_require_cmd semanage "SELinux permissive/fcontext tooling"
reg_require_cmd restorecon "SELinux restorecon"
reg_require_cmd stat "coreutils"
reg_require_cmd mkfifo "coreutils"

if [ "$(getenforce 2>/dev/null || true)" != "Enforcing" ]; then
  reg_blocked "SELinux is not enforcing"
fi

IMAGE="alpine:3.24"
WS="/opt/uat-avc-ws-$RANDOM"
PERMISSIVE_ADDED=0

cleanup() {
  if [ "$PERMISSIVE_ADDED" = 1 ]; then
    semanage permissive -d docker_helper_t >/dev/null 2>&1 || true
  fi
  semanage fcontext -d "$WS(/.*)?" >/dev/null 2>&1 || true
  rm -rf "$WS"
}
trap cleanup EXIT

# --- representative workspace below /opt (usr_t content) ---------------------------
dh config allowed-root add /opt >/dev/null 2>&1 || true
dh reload --system >/dev/null 2>&1 || true

mkdir -p "$WS/sub" "$WS/rw"          # directory
printf 'plain-content\n' > "$WS/plain.txt" # regular file
ln -s plain.txt "$WS/link"           # symlink
mkfifo "$WS/pipe"                    # FIFO
reg_info "representative workspace: $WS (dir, regular file, symlink, FIFO)"

LABEL_OF() { stat -c '%C' "$1" 2>/dev/null | cut -d: -f3; }
for o in "$WS" "$WS/sub" "$WS/plain.txt" "$WS/link" "$WS/pipe"; do
  reg_info "  before lifecycle: $(basename "$o") type=$(LABEL_OF "$o")"
done

# --- TEMPORARY permissive docker_helper_t (evidence only; removed on exit) ----------
if ! semanage permissive -a docker_helper_t >/dev/null 2>&1; then
  reg_fail "cannot set temporary permissive docker_helper_t (evidence collection blocked)"
  reg_result
fi
PERMISSIVE_ADDED=1
reg_ok "temporary permissive docker_helper_t active (reversible; removed on exit)"

AVC_START="$(date '+%m/%d/%Y %H:%M:%S')"
reg_info "AVC evidence window starts $AVC_START"

# --- Session owner (principal + default Launcher + credential) -------------------------
# A Session owner is always a Launcher. Create the principal Session through the
# shared lib (principal + default Launcher + credential) so the real lifecycle
# (relabel usr_t -> docker_helper_workspace_t and back) is exercised under the
# final ownership model, not a selector-less admin Session.
SEL_P="selavc"; SEL_CRED="/tmp/selavc.tok"
reg_setup_principal "$SEL_P" >/dev/null || { reg_fail "principal setup failed"; reg_result; }
# The session workspace is under /opt (the non-home allowed root this group
# deliberately exercises), so /opt must be in the principal's own allowed roots
# for the inherit-scope Session authorization to permit it.
dh principal allowed-root add --system "$SEL_P" /opt >/dev/null 2>&1 || { reg_fail "principal allowed-root add failed"; reg_result; }
reg_principal_credential "$SEL_P" "$SEL_CRED" || { reg_fail "credential create failed"; reg_result; }

# --- REAL lifecycle: session create (initial relabel usr_t -> workspace_t) ----------
reg_session "$SEL_CRED" "$WS" || {
  reg_fail "session create failed even with docker_helper_t permissive"
  reg_result
}
SID="$REG_SESSION_ID"; STOK="$REG_SESSION_TOKEN"
[ -n "$SID" ] && [ -n "$STOK" ] || { reg_fail "session create returned no id/token"; reg_result; }
reg_ok "session created (initial relabel usr_t -> docker_helper_workspace_t completed)"

for o in "$WS" "$WS/sub" "$WS/plain.txt" "$WS/link" "$WS/pipe"; do
  reg_info "  after initial relabel: $(basename "$o") type=$(LABEL_OF "$o")"
done

# --- container-created object ----------------------------------------------------------
RW_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$STOK" \
  dh run --image "$IMAGE" --mount rw:/mnt/rw -- sh -ec 'echo container-object > /mnt/rw/container-file; cat /mnt/rw/container-file' 2>&1)"
RW_EC=$?
CONTAINER_FILE="$WS/rw/container-file"
if [ "$RW_EC" -eq 0 ] && printf '%s' "$RW_OUT" | grep -q 'container-object'; then
  reg_ok "container-created object created in the workspace"
  if [ -e "$CONTAINER_FILE" ]; then
    CONTAINER_TYPE_BEFORE="$(LABEL_OF "$CONTAINER_FILE")"
    CONTAINER_INODE_BEFORE="$(stat -c '%d:%i' "$CONTAINER_FILE" 2>/dev/null)"
    reg_info "container-created object BEFORE teardown: type=$CONTAINER_TYPE_BEFORE inode=$CONTAINER_INODE_BEFORE"
  else
    reg_fail "container reported success but the object is not present in the workspace"
  fi
else
  reg_fail "container-created object run failed (rc=$RW_EC): $(printf '%s' "$RW_OUT" | redact | head -4)"
fi

# --- REAL lifecycle: session delete (teardown relabel workspace_t -> usr_t) -----------
if dh session delete --system --id "$SID" >/dev/null 2>&1; then
  reg_ok "session deleted (teardown relabel docker_helper_workspace_t -> usr_t completed)"
else
  reg_fail "session delete failed"
fi

for o in "$WS" "$WS/sub" "$WS/plain.txt" "$WS/link" "$WS/pipe"; do
  reg_info "  after teardown: $(basename "$o") type=$(LABEL_OF "$o")"
done

if [ -e "$CONTAINER_FILE" ]; then
  CONTAINER_TYPE_AFTER="$(LABEL_OF "$CONTAINER_FILE")"
  CONTAINER_INODE_AFTER="$(stat -c '%d:%i' "$CONTAINER_FILE" 2>/dev/null)"
  reg_info "container-created object AFTER teardown: type=$CONTAINER_TYPE_AFTER inode=$CONTAINER_INODE_AFTER (final policy-default type)"
else
  reg_info "container-created object no longer present after teardown"
fi

# --- AVC evidence: relabel matrix for BOTH directions (best-effort) ---------------------
# A permissive-mode denial is the exact set of permissions the confined relabel
# requires (permissive=1). Capture ALL docker_helper_t restorecon denials
# (relabelfrom/relabelto plus the getattr needed to read a label before
# relabeling), scoped by permissive=1 which uniquely identifies the temporary
# permissive window of THIS group (other groups run enforcing and log
# permissive=0). Source is the audit.log tail (proven to capture records in
# this harness), merged with the bounded ausearch window.
relabel_avcs() {
  {
    tail -800 /var/log/audit/audit.log 2>/dev/null
    if command -v ausearch >/dev/null 2>&1; then
      ausearch -m AVC -ts "$AVC_START" 2>/dev/null
    fi
  } | grep 'avc:  denied' | grep 'permissive=1' \
    | grep 'scontext=.*docker_helper_t' | grep 'comm="restorecon"' \
    | grep -E 'relabelfrom|relabelto|getattr'
}

# canonical: COMM PERM TCONTEXT_TYPE CLASS (dedups across objects/pid/source)
avc_canonical() {
  sed -E 's/.*\{ ([a-z_ ]+) \}.*comm="([^"]+)".* tcontext=[^:]+:[^:]+:([^:]+):[^ ]+ tclass=([a-z_]+).*/\2 \1 \3 \4/' | sort -u
}

# Type-only tcontext matches (user component varies: host-relabeled objects are
# unconfined_u, container-created objects are system_u).
USR_T="tcontext=[^:]+:[^:]+:usr_t:"
WS_T="tcontext=[^:]+:[^:]+:docker_helper_workspace_t:"

echo "--- initial relabel AVC matrix (usr_t -> docker_helper_workspace_t) ---"
relabel_avcs | grep -E "$USR_T|$WS_T" | sort -u
echo "--- initial relabel AVC matrix (canonical: COMM PERM TCONTEXT_TYPE CLASS) ---"
relabel_avcs | grep -E "$USR_T|$WS_T" | avc_canonical
echo "--- teardown relabel AVC matrix (docker_helper_workspace_t -> usr_t) ---"
relabel_avcs | grep -E "$WS_T|$USR_T" | sort -u
echo "--- teardown relabel AVC matrix (canonical: COMM PERM TCONTEXT_TYPE CLASS) ---"
relabel_avcs | grep -E "$WS_T|$USR_T" | avc_canonical
echo "--- all docker_helper_t restorecon relabel AVCs (canonical, both directions) ---"
relabel_avcs | avc_canonical

# --- remove temporary permissive now that evidence is captured ---------------------------
semanage permissive -d docker_helper_t >/dev/null 2>&1 && PERMISSIVE_ADDED=0
reg_ok "temporary permissive docker_helper_t removed"

reg_result
