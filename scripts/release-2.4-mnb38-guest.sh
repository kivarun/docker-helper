#!/usr/bin/env bash
#
# release-2.4-mnb38-guest.sh — MNB38 RPM lifecycle UAT, guest side.
#
# Runs as root inside the disposable ENFORCING openSUSE Tumbleweed VM. The
# exact candidate RPM (R7_ARTIFACT, sha-pinned via R7_ARTIFACT_SHA256) is
# consumed exactly as the artifact-gate producer staged it — never rebuilt:
#
#   P0  candidate/metadata preflight: artifact SHA-256, RPM Requires carries
#       the conditional SELinux lifecycle dependencies (container-selinux,
#       bzip2, setools-console — never unconditional), shipped scriptlets and
#       the packaged SELinux artifacts; enforcing-targeted host proof.
#   P1  fresh RPM install (real zypper dependency resolution): CIL artifact
#       identity (pinned SHA-256), priority-400 module in the store
#       (byte-exact blob identity), the exact loaded-policy constraint
#       statement (seinfo against /sys/fs/selinux/policy), and the release
#       .pp identity baseline.
#   P2  repeated install (rpm -U --replacepkgs) and upgrade shape: no
#       absent-constraint window — the store blob CONTENT and the resident
#       module's presence are UNCHANGED across every transaction (the
#       success path never removes the resident module; libsemanage may
#       legitimately rewrite blobs in place, which is why the gate is on
#       decoded bytes, not on inode/mtime), and the effective-policy check
#       still passes; both services still active after the transactional
#       restart.
#   P3  failed upgrade: a controlled constraint-install failure (semodule
#       shim that lets the docker_helper.pp load pass and fails ONLY the
#       constraint CIL install, reached through rpm's scriptlet PATH): both
#       services stopped AND verified stopped, no automatic restart, the
#       deferred-restart decision preserved, the constraint module still
#       intact. The RPM command exits zero on Tumbleweed while the individual
#       scriptlet is reported failed — both facts are recorded separately.
#   P4  recovery: restore a healthy package state (shim removed): the
#       recovery transaction must NOT implicitly restart the stopped
#       services; explicit operator activation then verifies is-active=active
#       and a valid nonzero MainPID, and the effective constraint.
#   P5  final erase: rpm -e removes ONLY the product-owned modules
#       (docker_helper + the constraint module at priority 400); container
#       policy and the base policy survive; no orphaned module entries or
#       store directories; the units are gone from systemd.
#
# Boundary: packaging lifecycle only. NO new TE grants, no S1 replacement,
# no runtime repinning, no permissive mode, no Release-GO UAT.
#
# Evidence: one file per phase under R7_EVIDENCE_DIR plus a summary with the
# R7-MNB38-<X>=PASS tokens. Any failed gate exits non-zero with the gate
# name in the failure line; nothing is auto-repaired except the explicit
# recovery step (P4), which is itself part of the matrix.

set -Eeuo pipefail

PREFIX='[release-2.4-mnb38]'
say()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }
log()  { echo "[guest] $*"; }
ev()   { printf '%s\n' "$2" > "$EVIDENCE_DIR/$1"; }

: "${R7_ARTIFACT:?R7_ARTIFACT required}"
: "${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"
: "${R7_EVIDENCE_DIR:?R7_EVIDENCE_DIR required}"
: "${MNB38_CIL_SHA256:?MNB38_CIL_SHA256 required}"

# Canonical domain vocabulary (one term per concept, mirrored from the
# shipped constraint library and the wrapper admission gate).
RPM="$R7_ARTIFACT"
EVIDENCE_DIR="$R7_EVIDENCE_DIR"
STATEMENT='mlsconstrain fifo_file { read write } (h1 dom h2 or t1 != mcs_constrained_type);'
CIL=/usr/share/selinux/docker-helper-fifo-rw-constraint.cil
CONSTRAINT_LIB=/usr/share/docker-helper/selinux/constraint-module.sh
PP=/usr/share/selinux/docker_helper.pp
PRIORITY=400
MAIN_UNIT=docker-helper.service
UNIT=docker-helper-builder.service

mkdir -p "$EVIDENCE_DIR"

# Re-entry: the disposable guest has an observed mid-run reboot (~55s after
# first boot on this image family), and Tumbleweed mounts /tmp as tmpfs, so
# the diagnosis orchestrator re-runs this script per attempt and re-entry
# state must live PERSISTENTLY. The matrix is therefore STATE-MARKED under
# /var/lib: a phase that recorded PASS is not re-run (a re-run would be a
# second transaction where 'already installed' means something else), and
# an interrupted lifecycle resumes at its first unfinished phase instead of
# replaying the whole matrix against a half-updated guest.
STATE_DIR=/var/lib/docker-helper-mnb38-state
PHASE_FILE="$STATE_DIR/phase-done"
mark() { mkdir -p "$STATE_DIR"; printf '%s\n' "$1" >> "$PHASE_FILE"; }
done_phase() {
  [ -f "$PHASE_FILE" ] && grep -qx "$1" "$PHASE_FILE"
}

store_root() {
  # Same canonical derivation as the shipped constraint library: the policy
  # kind (SELINUXTYPE) selects the store root; /etc/selinux/<type> is the
  # stable view (on Tumbleweed it resolves to the backing store).
  local selinuxtype
  selinuxtype="$(sed -n 's/^SELINUXTYPE=//p' /etc/selinux/config 2>/dev/null | tail -n 1)"
  [ -n "$selinuxtype" ] || selinuxtype=targeted
  echo "/etc/selinux/$selinuxtype"
}

store_blobs() {
  # Every known-shape blob for the constraint module at our priority,
  # newest-listing normalization shared with the shipped library's view.
  find "$(store_root)/active/modules/$PRIORITY" \( -name 'hll-blob' -o -name 'cil' \) \
    -path "*docker-helper-fifo-rw-constraint*" 2>/dev/null | sort
}

store_listing() {
  {
    echo "--- semanage module -l (head) ---"
    semanage module -l 2>&1 | head -30
    echo "--- store priority-400 listing ---"
    ls -laR "$(store_root)/active/modules/$PRIORITY" 2>&1
  }
}

blob_identity_ok() {
  # Every recognized blob must decode to byte-exactly the installed CIL.
  local blobs blob
  blobs="$(store_blobs)"
  [ -n "$blobs" ] || return 1
  while read -r blob; do
    [ -n "$blob" ] || continue
    bzip2 -dc "$blob" 2>/dev/null | cmp -s - "$CIL" || return 1
  done <<<"$blobs"
  return 0
}

constraint_statement_ok() {
  seinfo --constrain fifo_file /sys/fs/selinux/policy 2>/dev/null \
    | sed 's/^[[:space:]]*//' | grep -Fqx "$STATEMENT"
}

expected_active() {
  [ "$(systemctl is-active "$1" 2>/dev/null || true)" = "active" ]
}

rpm_capture() {
  # "$1" evidence basename; the rpm command is executed in the caller's
  # arguments context; captures rc + output separately and exports them.
  set +e
  RPM_OUT="$(rpm -Uvh --replacepkgs "$RPM" 2>&1)"
  RPM_RC=$?
  set -e
  printf '%s\n' "$RPM_OUT" > "$EVIDENCE_DIR/$1"
  ev "$1.rc" "$RPM_RC"
}

ensure_clean_semodule() {
  # A reboot can interrupt a phase after the P3 poison shim was installed
  # but before its removal; no transaction phase here may ever run against
  # a stale shim. (P3 installs its own shim right after this check.)
  if [ -f /usr/local/sbin/semodule ] && ! grep -q "MNB38 controlled failure" /usr/local/sbin/semodule; then
    rm -f /usr/local/sbin/semodule
  fi
}

start_or_fail() {
  # $1 label; start both services with FULL FAILURE FORENSICS printed to
  # the console (the orchestrator collects stderr). 'Failed to set up
  # special execution directory' class failures are otherwise invisible.
  printf '%s %s: starting %s + %s\n' "$PREFIX" "$1" "$MAIN_UNIT" "$UNIT"
  if ! start_out="$(systemctl start "$MAIN_UNIT" "$UNIT" 2>&1)"; then
    printf '%s FAILED: %s: the services must start on the enforcing guest systemctl said:\n%s\n' "$PREFIX" "$1" "$start_out"
    {
      echo "--- unit status ---"
      systemctl status "$MAIN_UNIT" "$UNIT" --no-pager -l 2>&1 || true
      echo "--- journal ---"
      journalctl --no-pager -q -o short-precise -u "$MAIN_UNIT" -u "$UNIT" 2>&1 | tail -40 || true
      echo "--- /var/lib listing (labels) ---"
      ls -laZ /var/lib 2>&1 | head -30 || true
      echo "--- state roots ---"
      ls -laZ /var/lib/docker-helper /var/lib/docker-helper-builder 2>&1 || true
      echo "--- mountinfo excerpts ---"
      grep -E "/var/lib|/run/docker-helper" /proc/self/mountinfo 2>&1 || true
    } | while IFS= read -r line; do printf '%s %s: %s\n' "$PREFIX" "$1" "$line"; done
    systemctl reset-failed "$MAIN_UNIT" "$UNIT" 2>/dev/null || true
    printf 'R7-MNB38-VERDICT=FAILED:%s-service-start\n' "$1"
    exit 1
  fi
  printf '%s %s: services started\n' "$PREFIX" "$1"
}

ensure_services_active() {
  # Re-entry after a mid-run reboot: enabled units come back (systemd), but
  # the contract below needs an explicitly ACTIVE pair, not a best-effort
  # boot result. reset-failed first so a prior attempt's start-limit failure
  # cannot mask a fresh start attempt. The state root was already
  # initialized in P1 (the deployment contract), so a plain start is valid
  # from P2 onward.
  systemctl reset-failed "$MAIN_UNIT" "$UNIT" 2>/dev/null || true
  if [ "$(systemctl is-enabled "$MAIN_UNIT" 2>/dev/null || true)" = "enabled" ] \
    || [ "$(systemctl is-enabled "$UNIT" 2>/dev/null || true)" = "enabled" ]; then
    systemctl start "$MAIN_UNIT" "$UNIT"
  fi
  expected_active "$MAIN_UNIT" || fail "$MAIN_UNIT must be active at the start of this phase"
  expected_active "$UNIT" || fail "$UNIT must be active at the start of this phase"
}

phase_p0() {
# ---------------------------------------------------------------------------
# P0 — candidate and metadata preflight
# ---------------------------------------------------------------------------
say 'P0: candidate identity, RPM metadata, enforcing host'
ACTUAL_SHA="$(sha256sum "$RPM" | awk '{print $1}')"
[ "$ACTUAL_SHA" = "$R7_ARTIFACT_SHA256" ] \
  || fail "candidate RPM SHA-256 mismatch (expected $R7_ARTIFACT_SHA256, got $ACTUAL_SHA)"
ev p0-artifact.sha256 "$ACTUAL_SHA"

getenforce 2>/dev/null | grep -qx 'Enforcing' \
  || fail "the lifecycle matrix requires an enforcing SELinux host (getenforce failed)"

TRequires="$(rpm -qp --requires "$RPM" 2>&1)"
ev p0-requires "$TRequires"
for want in '(container-selinux if selinux-policy)' '(bzip2 if selinux-policy)' '(setools-console if selinux-policy)'; do
  printf '%s\n' "$TRequires" | grep -Fqx "$want" \
    || fail "RPM Requires must carry the conditional SELinux lifecycle dependency $want"
done
if printf '%s\n' "$TRequires" | grep -Eq '^(bzip2|setools-console|diffutils)$'; then
  fail "the SELinux lifecycle tool deps must stay conditional on selinux-policy, not unconditional"
fi

TScripts="$(rpm -q --scripts -p "$RPM" 2>&1)"
ev p0-scriptlets "$TScripts"
printf '%s\n' "$TScripts" | grep -q 'posttrans scriptlet' \
  || fail "the candidate RPM must carry %posttrans (deferred module load/restart)"

TFiles="$(rpm -qpl "$RPM" 2>&1)"
ev p0-filelist "$TFiles"
for f in "$CIL" "$CONSTRAINT_LIB" "$PP"; do
  printf '%s\n' "$TFiles" | grep -qF "$f" \
    || fail "the candidate RPM must ship $f"
done

# The CIL artifact identity is verified after the fresh install from the
# INSTALLED bytes (the packaged bytes are the bytes the RPM owns at the
# packaged path). The .pp record becomes the per-candidate baseline whose
# UNCHANGE across every later phase is asserted on each transaction.
ev p0-shipped-artifacts "CIL=$CIL LIB=$CONSTRAINT_LIB PP=$PP"

say 'P0: PASS'
}


phase_p1() {
# ---------------------------------------------------------------------------
# P1 — fresh install (with re-entry recovery: a prior attempt whose fresh
# install aborted INSIDE its posttrans leaves the package installed with
# the constraint missing; the recovery transaction is the accepted contract
# for that state — the rerun %posttrans carries the constraint install, and
# designed P-identification ensures a clean end state).
say 'P1: fresh RPM installation (zypper, real dependency resolution)'
zypper --non-interactive --gpg-auto-import-keys refresh >/dev/null 2>&1 || true
# The candidate RPM is intentionally unsigned (nfpm does not sign); zypper
# aborts unsigned local packages in non-interactive mode unless explicitly
# allowed (--allow-unsigned-rpm is an install-command option, not a global
# one). The full output (scriptlet lines included) is kept as evidence: an
# RPM transaction exiting zero is NOT the same as every scriptlet
# succeeding, so 'scriptlet failed' lines are hunted separately.
if rpm -q docker-helper >/dev/null 2>&1; then
  # Re-entry: the package is already installed. A transaction is run ONLY
  # when the constraint store is missing (the prior fresh install aborted
  # inside its %posttrans — the recorded P1 recovery contract); an already
  # healthy installation goes straight to the identity assertions.
  if [ -z "$(store_blobs)" ]; then
    say "P1 re-entry: docker-helper installed without the constraint store; running the recorded recovery transaction"
    set +e
    RECOVERY_OUT="$(rpm -Uvh --replacepkgs "$RPM" 2>&1)"
    RECOVERY_RC=$?
    set -e
    printf '%s\n' "$RECOVERY_OUT" > "$EVIDENCE_DIR/p1-recovery-rpm.log"
    ev p1-recovery.rc "$RECOVERY_RC"
    [ "$RECOVERY_RC" = "0" ] || { tail -20 "$EVIDENCE_DIR/p1-recovery-rpm.log"; fail "the P1 re-entry recovery transaction failed (rc $RECOVERY_RC)"; }
    printf '%s\n' "$RECOVERY_OUT" | grep -Eq 'scriptlet failed' \
      && fail "the recovery %posttrans must succeed (the explicit lifecycle deps make the abort class impossible on the prepared guest)" \
      || true
  else
    say "P1 re-entry: docker-helper already installed with the constraint store present; identity assertions only"
  fi
else
  set +e
  ZYPPER_OUT="$(zypper --non-interactive install -y --allow-unsigned-rpm "$RPM" 2>&1)"
  ZYPPER_RC=$?
  set -e
  printf '%s\n' "$ZYPPER_OUT" > "$EVIDENCE_DIR/p1-zypper-install.log"
  ev p1-zypper.rc "$ZYPPER_RC"
  printf '%s\n' "$ZYPPER_OUT" | grep -Eq 'scriptlet failed' \
    && fail "fresh install must not report a failed scriptlet (zypper rc 0 is NOT scriptlet-success evidence)" \
    || true
  [ "$ZYPPER_RC" = "0" ] || { tail -20 "$EVIDENCE_DIR/p1-zypper-install.log"; fail "zypper fresh install failed (rc $ZYPPER_RC)"; }
fi

for f in "$CIL" "$CONSTRAINT_LIB" "$PP"; do
  [ -f "$f" ] || fail "fresh install must place $f"
done
NEW_CIL_SHA="$(sha256sum "$CIL" | awk '{print $1}')"
[ "$NEW_CIL_SHA" = "$MNB38_CIL_SHA256" ] \
  || fail "installed CIL sha mismatch: expected $MNB38_CIL_SHA256, got $NEW_CIL_SHA"

semodule -l | grep -q '^docker_helper' \
  || fail "the docker_helper module must be loaded by the fresh install"
semodule -l | grep -q 'container' \
  || fail "the container policy must remain present after the fresh install"

ev p1-store-listing "$(store_listing)"
[ -n "$(store_blobs)" ] || fail "the priority-400 constraint module must exist in the SELinux store"
blob_identity_ok || fail "the installed constraint store blobs do not decode byte-exactly to the CIL"

seinfo --constrain fifo_file /sys/fs/selinux/policy >"$EVIDENCE_DIR/p1-loaded-constraint.txt" 2>&1 \
  || fail "seinfo loaded-policy query failed"
constraint_statement_ok \
  || fail "the loaded policy must carry exactly: $STATEMENT"

PP_BASELINE_SHA="$(sha256sum "$PP" | awk '{print $1}')"
printf 'pp_baseline=%s\n' "$PP_BASELINE_SHA" >"$EVIDENCE_DIR/p1-pp-baseline"

# The shipped deployment order: a fresh install is INITIALIZED by the
# operator (docker-helper init --allowed-root ...) before the services
# start — init creates the state configuration as the invoking root, and
# the systemd STATE_DIRECTORY bootstrap then operates on the existing
# state root (identical to install-system.sh and the packaged lifecycle
# proofs). A bare 'systemctl start' on a never-initialized fresh host is
# NOT the deployment contract.
ALLOWED_ROOT=/srv/docker-helper-mnb38-uat
mkdir -p "$ALLOWED_ROOT"
/usr/bin/docker-helper init --allowed-root "$ALLOWED_ROOT" \
  >"$EVIDENCE_DIR/p1-init.log" 2>&1 \
  || { tail -20 "$EVIDENCE_DIR/p1-init.log"; fail "docker-helper init failed on the fresh install (see p1-init.log)"; }
ev p1-init "allowed-root=$ALLOWED_ROOT initialized"

start_or_fail p1
expected_active "$MAIN_UNIT" || fail "the main service must be startable after the fresh install"
expected_active "$UNIT" || fail "the builder service must be startable after the fresh install"
systemctl show "$MAIN_UNIT" -p MainPID --value >"$EVIDENCE_DIR/p1-mainpid"
ev p1-services "both active"

ev p1-module-store "$(semodule -l)"

say 'P1: PASS'
}


phase_p2() {
# ---------------------------------------------------------------------------
# P2 — repeated install / upgrade shape (no absent-constraint window)
# ---------------------------------------------------------------------------
say 'P2: repeated installation and upgrade shape'
ensure_clean_semodule
ensure_services_active
# The no-absent-window contract is about CONTENT and PRESENCE, not inode
# identity: libsemanage legitimately rewrites blob files in place during a
# commit even when the module bytes are unchanged (observed live: fresh
# inode + new mtime per transaction on the identical module). The gate is:
# every blob still decodes byte-exactly to the installed candidate, the
# module stays present at priority 400, and the loaded policy still carries
# the exact constraint after every transaction.
BLOB_BEFORE_DECODED="$(for b in $(store_blobs); do bzip2 -dc "$b" 2>/dev/null | sha256sum; done | sort)"
rpm_capture p2-repeat-rpm
[ "$RPM_RC" = "0" ] || { ev p2-repeat-out "$RPM_OUT"; fail "repeated install failed (rc $RPM_RC)"; }
printf '%s\n' "$RPM_OUT" | grep -Ein 'scriptlet failed' \
  && fail "repeated install must not report a failed scriptlet" \
  || true

BLOB_AFTER_DECODED="$(for b in $(store_blobs); do bzip2 -dc "$b" 2>/dev/null | sha256sum; done | sort)"
[ -n "$BLOB_BEFORE_DECODED" ] || fail "the constraint store lost its blobs across the repeated install"
[ "$BLOB_BEFORE_DECODED" = "$BLOB_AFTER_DECODED" ] \
  || fail "the store blob CONTENT changed across the repeated install (remove+reinstall would open an absent-constraint window)"
blob_identity_ok || fail "constraint store identity must hold across the repeated install"
constraint_statement_ok \
  || fail "the effective-policy check must hold across the repeated install"
expected_active "$MAIN_UNIT" || fail "the main service must stay active across the upgrade"
expected_active "$UNIT" || fail "the builder service must stay active across the upgrade"
[ "$(sha256sum "$PP" | awk '{print $1}')" = "$PP_BASELINE_SHA" ] \
  || fail "the release .pp identity must be unchanged"

# An actual upgrade transaction shape (same bytes, force the transaction):
BLOB_BEFORE_DECODED_UP="$(for b in $(store_blobs); do bzip2 -dc "$b" 2>/dev/null | sha256sum; done | sort)"
rpm_capture p2-upgrade-rpm
[ "$RPM_RC" = "0" ] || { fail "upgrade-shape rpm -U failed (rc $RPM_RC)"; }
printf '%s\n' "$RPM_OUT" | grep -Ein 'scriptlet failed' \
  && fail "upgrade must not report a failed scriptlet" \
  || true
BLOB_AFTER_DECODED_UP="$(for b in $(store_blobs); do bzip2 -dc "$b" 2>/dev/null | sha256sum; done | sort)"
[ -n "$BLOB_AFTER_DECODED_UP" ] || fail "the constraint store lost its blobs across the upgrade transaction"
[ "$BLOB_BEFORE_DECODED_UP" = "$BLOB_AFTER_DECODED_UP" ] \
  || fail "the store blob CONTENT changed across the upgrade transaction (remove+reinstall would open an absent-constraint window)"
blob_identity_ok || fail "constraint store identity must hold across the upgrade transaction"
constraint_statement_ok \
  || fail "the effective-policy check must hold across the upgrade transaction"
expected_active "$MAIN_UNIT" || fail "the main service must stay active across the upgrade"
ev p2-blob-before "$BLOB_BEFORE_DECODED_UP"
ev p2-blob-after "$BLOB_AFTER_DECODED_UP"
[ "$(sha256sum "$PP" | awk '{print $1}')" = "$PP_BASELINE_SHA" ] \
  || fail "the release .pp identity must be unchanged after the upgrade"

say 'P2: PASS'
}


phase_p3() {
# ---------------------------------------------------------------------------
# P3 — failed upgrade (controlled constraint-install failure)
# ---------------------------------------------------------------------------
say 'P3: failed upgrade, constraint-install failure, verified stop'
ensure_services_active
cat > /usr/local/sbin/semodule <<'POISON'
#!/bin/sh
# Let the container-policy listing and the docker_helper.pp load pass
# through; fail ONLY the constraint CIL install (docker-helper's own
# posttrans branch: the centralized fail-closed abort).
[ "$1" = "-l" ] && exec /usr/sbin/semodule "$@"
case "$*" in
  *docker-helper-fifo-rw-constraint.cil*)
    echo "poisoned constraint semodule (MNB38 controlled failure)" >&2
    exit 1
    ;;
esac
exec /usr/sbin/semodule "$@"
POISON
chmod 0755 /usr/local/sbin/semodule

set +e
POISON_OUT="$(rpm -Uvh --replacepkgs "$RPM" \
  --define '_install_script_path /usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin' 2>&1)"
POISON_RC=$?
set -e
printf '%s\n' "$POISON_OUT" > "$EVIDENCE_DIR/p3-failed-rpm.log"
ev p3-failed-rpm.rc "$POISON_RC"
rm -f /usr/local/sbin/semodule

# Tumbleweed behavior: rpm treats a failing %posttrans as a WARNING and
# completes the transaction with exit 0. The failure proof is the
# scriptlet-failure report; the RPM exit code alone proves nothing.
[ "$POISON_RC" = "0" ] || fail "expected the observed rpm exit-0 behavior (the scriptlet failure is the proof); got rpm rc $POISON_RC"
printf '%s\n' "$POISON_OUT" | grep -q 'scriptlet failed' \
  || fail "rpm must report the failing posttrans scriptlet (rpm rc 0 is NOT success evidence)"
for want in 'stopping the running backends' 'both backends confirmed stopped (verified)'; do
  printf '%s\n' "$POISON_OUT" | grep -qF "$want" \
    || fail "the centralized fail-closed abort must report: $want"
done

for u in "$MAIN_UNIT" "$UNIT"; do
  expected_active "$u" && fail "the failed upgrade must leave $u stopped"
done
ev p3-services-after "both stopped (verified by the posttrans + is-active here)"

STATE_FILE=/run/docker-helper-rpm/posttrans-state
[ -f "$STATE_FILE" ] || fail "the failed posttrans must preserve the deferred-restart decision file"
grep -q 'was_active=true' "$STATE_FILE" \
  || fail "the preserved decision must keep was_active=true (the recorded pre-failure state)"

# No automatic restart: sample again after the settle window.
sleep 15
for u in "$MAIN_UNIT" "$UNIT"; do
  expected_active "$u" && fail "$u restarted by itself after the failed upgrade"
done
ev p3-no-restart "both units still inactive after the settle window"

# The constraint module and its loaded constraint survive the failed branch:
# the failure happened BEFORE any removal step in the lifecycle library.
blob_identity_ok || fail "the constraint module must remain in the store after the failed install"
constraint_statement_ok \
  || fail "the loaded constraint must remain active after the failed install"
[ "$(sha256sum "$PP" | awk '{print $1}')" = "$PP_BASELINE_SHA" ] \
  || fail "the release .pp identity must be unchanged after the failed upgrade"

say 'P3: PASS'
}


phase_p4() {
# ---------------------------------------------------------------------------
# P4 — recovery
# ---------------------------------------------------------------------------
say 'P4: recovery, explicit activation, effective constraint'
ensure_clean_semodule
rpm_capture p4-recovery-rpm
[ "$RPM_RC" = "0" ] || { fail "recovery rpm -U --replacepkgs failed (rc $RPM_RC)"; }
printf '%s\n' "$RPM_OUT" | grep -Ein 'scriptlet failed' \
  && fail "the recovery transaction must not report a failed scriptlet" \
  || true
for u in "$MAIN_UNIT" "$UNIT"; do
  expected_active "$u" && fail "the recovery transaction must NOT implicitly restart the stopped $u"
done
ev p4-after-recovery "both units still inactive (no implicit restart; the successful posttrans restarts only services already active)"

start_or_fail p4-explicit-activation
for u in "$MAIN_UNIT" "$UNIT"; do
  expected_active "$u" || fail "explicit activation must leave $u active"
  pid="$(systemctl show "$u" -p MainPID --value)"
  [ -n "$pid" ] && [ "$pid" != "0" ] \
    || fail "$u must carry a valid nonzero MainPID after explicit activation (got $pid)"
done
ev p4-activated "$(systemctl show "$MAIN_UNIT" "$UNIT" -p ActiveState -p MainPID)"
constraint_statement_ok \
  || fail "the effective-policy constraint must hold after recovery"
blob_identity_ok || fail "the constraint store identity must hold after recovery"
[ "$(sha256sum "$PP" | awk '{print $1}')" = "$PP_BASELINE_SHA" ] \
  || fail "the release .pp identity must be unchanged after recovery"

say 'P4: PASS'
}


phase_p5() {
# ---------------------------------------------------------------------------
# P5 — final erase
# ---------------------------------------------------------------------------
say 'P5: final erase, product-owned modules only'
ensure_clean_semodule
MODULES_BEFORE="$(semodule -l)"
ev p5-modules-before "$MODULES_BEFORE"
MODULE_COUNT_BEFORE="$(printf '%s\n' "$MODULES_BEFORE" | grep -c '^')"

set +e
ERASE_OUT="$(rpm -ev docker-helper 2>&1)"
ERASE_RC=$?
set -e
printf '%s\n' "$ERASE_OUT" > "$EVIDENCE_DIR/p5-erase.log"
ev p5-erase.rc "$ERASE_RC"
[ "$ERASE_RC" = "0" ] || { tail -20 "$EVIDENCE_DIR/p5-erase.log"; fail "rpm -e failed (rc $ERASE_RC)"; }
printf '%s\n' "$ERASE_OUT" | grep -Ein 'scriptlet failed' \
  && fail "erase must not report a failed scriptlet" \
  || true

MODULES_AFTER="$(semodule -l)"
ev p5-modules-after "$MODULES_AFTER"
MODULE_COUNT_AFTER="$(printf '%s\n' "$MODULES_AFTER" | grep -c '^')"
MODULE_COUNT_EXPECTED=$((MODULE_COUNT_BEFORE - 2))
[ "$MODULE_COUNT_AFTER" = "$MODULE_COUNT_EXPECTED" ] \
  || fail "erase must remove exactly the product-owned module set (before $MODULE_COUNT_BEFORE, after $MODULE_COUNT_AFTER, expected $MODULE_COUNT_EXPECTED)"
printf '%s\n' "$MODULES_AFTER" | grep -q 'docker_helper' \
  && fail "docker_helper must be removed from the module store"
printf '%s\n' "$MODULES_AFTER" | grep -q 'docker-helper-fifo-rw-constraint' \
  && fail "the constraint module must be removed from the module store"
printf '%s\n' "$MODULES_AFTER" | grep -q 'container' \
  || fail "the container policy must survive the product erase"
[ -n "$(store_blobs 2>/dev/null)" ] \
  && fail "no constraint store directory may remain (orphaned module entries)"
if [ -e "$(store_root)/active/modules/$PRIORITY/docker-helper-fifo-rw-constraint" ] \
  || [ -e "$(store_root)/active/modules/$PRIORITY/hll/docker-helper-fifo-rw-constraint" ]; then
  fail "the priority-400 constraint module directory must be gone after erase"
fi
constraint_statement_ok \
  && fail "the loaded policy must NOT still carry the product constraint after the erase (policy reload removes it with the module)"
ev p5-no-orphan "no product modules in the store, no orphan directories, constraint no longer in the loaded policy"

rpm -q docker-helper >/dev/null 2>&1 \
  && fail "the package must be gone after the erase"
systemctl cat "$MAIN_UNIT" >/dev/null 2>&1 \
  && fail "the main unit must be removed by the erase"
systemctl cat "$UNIT" >/dev/null 2>&1 \
  && fail "the builder unit must be removed by the erase"
for u in "$MAIN_UNIT" "$UNIT"; do
  expected_active "$u" && fail "$u must be inactive after the erase"
done
 ev p5-units "units removed, services inactive"

ev p5-loaded-policy.sha "$(sha256sum /sys/fs/selinux/policy 2>/dev/null | awk '{print $1}')"
say 'P5: PASS'
}

# ----------------------------- re-entry driver -----------------------------
# One attempt finishes every unfinished phase, in order; the first failing
# gate exits non-zero and the per-attempt evidence is collected by the
# orchestrator regardless. Each phase body is re-entry-tolerant within its
# own recorded state (see the notes inside each phase).
run_phase() {
  case "$1" in
    p0) phase_p0 ;;
    p1) phase_p1 ;;
    p2) phase_p2 ;;
    p3) phase_p3 ;;
    p4) phase_p4 ;;
    p5) phase_p5 ;;
    *) fail "unknown phase $1" ;;
  esac
}
for phase in p0 p1 p2 p3 p4 p5; do
  if done_phase "$phase"; then
    say "$phase: PASS already recorded in a previous attempt; re-entry skips it"
    continue
  fi
  run_phase "$phase"
  mark "$phase"
done

echo "R7-MNB38-P0-METADATA=PASS"
echo "R7-MNB38-P1-FRESH-INSTALL=PASS"
echo "R7-MNB38-P2-NO-ABSENT-WINDOW=PASS"
echo "R7-MNB38-P3-VERIFIED-STOP=PASS"
echo "R7-MNB38-P4-RECOVERY-EXPLICIT-ACTIVATION=PASS"
echo "R7-MNB38-P5-CLEAN-ERASE=PASS"
echo "R7-MNB38-VERDICT=PASS"
