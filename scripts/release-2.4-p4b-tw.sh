#!/usr/bin/env bash
#
# Release 2.4 P4 packaging proof — guest-side openSUSE Tumbleweed.
#
# Installs the GENERATED release-candidate RPM and tarball (transferred by the
# host-side orchestrator into /tmp/p4b/) and proves the packaging lifecycle
# through the package managers — never loose files copied from the checkout:
#
#   P1  RPM fresh install via zypper (dependency resolution from the real
#       Tumbleweed repos: shadow rootlesskit slirp4netns apparmor-parser
#       libselinux1 bindfs policycoreutils), rpm-ownership/modes/file-list
#       asserts, provisioning, builder unit enabled, the SELinux
#       docker_helper module loaded by the %post scriptlet, and the
#       standalone builder start boundary asserts;
#   P2  idempotent reinstall (rpm -U --replacepkgs: same subid ranges);
#   P3  failed provisioning is fail-closed (poisoned builder shell -> rpm
#       reports the %post failure) and the interrupted install recovers
#       through a rerun after the account is repaired;
#   P4  tarball: install-system.sh on the SELinux-enforcing host, full
#       assert, then uninstall --purge (identity purged, artifacts gone);
#   P5  upgrade from the pinned released v2.3.0 baseline (no builder
#       identity/unit/payload) to the candidate RPM, with the weak
#       Wants/After coupling and the pinned payload digests re-asserted.
#
# Runs as root inside the guest. Files transferred by the host-side
# orchestrator (scripts/release-2.4-p4b-tw-vm.sh) into /tmp/p4b/.

set -Eeuo pipefail

PREFIX='[release-2.4-p4b-tw]'

GUEST_FILES=/tmp/p4b
EVIDENCE_DIR=/tmp/release-2.4-p4b-tw-evidence
CANDIDATE_DIR="$GUEST_FILES/candidate"
VERSION="${P4B_VERSION:-2.4.0}"
ALLOWED_ROOT=/srv/docker-helper-p4b-uat

RPM_NAME="docker-helper-${VERSION}-1.x86_64.rpm"
TARBALL_NAME="docker-helper-${VERSION}-linux-amd64.tar.gz"
RPM="$CANDIDATE_DIR/$RPM_NAME"
TARBALL="$CANDIDATE_DIR/$TARBALL_NAME"

UNIT=docker-helper-builder.service
MAIN_UNIT=docker-helper.service
BUILDER_USER=docker-helper-builder
PAYLOAD_DIR=/usr/libexec/docker-helper/buildkit
DOC_DIR=/usr/share/doc/docker-helper/buildkit
PROVISIONER_SHIPPED=/usr/share/docker-helper/lib/provision-builder.sh

# Pinned payload identities: read from the single owner (build-buildkit-payload.sh,
# transferred with the other guest files) so the pins exist in exactly one place.
PIN_OWNER="$GUEST_FILES/build-buildkit-payload.sh"

say() { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }
log() { echo "[guest] $*"; }

pin() {
  local value
  value="$(sed -n "s/^$1=\"\([0-9a-f]\{64\}\)\"/\1/p" "$PIN_OWNER")"
  [ -n "$value" ] || fail "cannot read pin $1 from the payload owner $PIN_OWNER"
  printf '%s' "$value"
}

BUILDKITD_SHA256="$(pin BUILDKITD_SHA256)"
BUILDCTL_SHA256="$(pin BUILDCTL_SHA256)"
BUILDKIT_RUNC_SHA256="$(pin BUILDKIT_RUNC_SHA256)"

for f in "$RPM" "$TARBALL" "$GUEST_FILES/uat-upgrade-baseline-fixture.sh" "$PIN_OWNER"; do
  [ -f "$f" ] || fail "missing transferred file: $f"
done

mkdir -p "$EVIDENCE_DIR"
subuid_entry() { awk -F: -v u="$BUILDER_USER" '$1 == u { print $2 " " $3; exit }' /etc/subuid; }
subgid_entry() { awk -F: -v u="$BUILDER_USER" '$1 == u { print $2 " " $3; exit }' /etc/subgid; }

evidence() {
  local name="$1" content="$2"
  printf '%s\n' "$content" > "$EVIDENCE_DIR/$name"
}

# assert_provisioned <expect_identity_present:yes|no>
assert_provisioned() {
  case "$1" in
    no)
      if id "$BUILDER_USER" >/dev/null 2>&1; then
        fail "builder identity $BUILDER_USER must not be provisioned"
      fi
      [ -z "$(subuid_entry)" ] || fail "/etc/subuid must not carry a $BUILDER_USER entry"
      [ -z "$(subgid_entry)" ] || fail "/etc/subgid must not carry a $BUILDER_USER entry"
      return
      ;;
  esac
  id "$BUILDER_USER" >/dev/null 2>&1 || fail "builder identity $BUILDER_USER not provisioned"
  shell="$(awk -F: -v u="$BUILDER_USER" '$1 == u { print $7 }' /etc/passwd)"
  [ "$shell" = "/usr/sbin/nologin" ] || fail "builder shell = $shell, want /usr/sbin/nologin"
  uid_entry="$(subuid_entry)"
  gid_entry="$(subgid_entry)"
  [ -n "$uid_entry" ] || fail "/etc/subuid has no $BUILDER_USER entry"
  [ -n "$gid_entry" ] || fail "/etc/subgid has no $BUILDER_USER entry"
  for entry in "$uid_entry" "$gid_entry"; do
    count="$(printf '%s' "$entry" | awk '{print $2}')"
    if [ -z "$count" ] || [ "$count" -lt 65536 ]; then
      fail "subordinate range too small: '$entry'"
    fi
  done
  evidence "provisioned-subids.txt" "subuid: $uid_entry
subgid: $gid_entry"
}

assert_payload() {
  local member digest perms owner
  for member in buildkitd buildctl buildkit-runc; do
    [ -s "$PAYLOAD_DIR/$member" ] || fail "payload member missing: $PAYLOAD_DIR/$member"
    digest="$(sha256sum "$PAYLOAD_DIR/$member" | awk '{print $1}')"
    case "$member" in
      buildkitd) [ "$digest" = "$BUILDKITD_SHA256" ] || fail "buildkitd digest $digest != pinned $BUILDKITD_SHA256" ;;
      buildctl) [ "$digest" = "$BUILDCTL_SHA256" ] || fail "buildctl digest $digest != pinned $BUILDCTL_SHA256" ;;
      buildkit-runc) [ "$digest" = "$BUILDKIT_RUNC_SHA256" ] || fail "buildkit-runc digest $digest != pinned $BUILDKIT_RUNC_SHA256" ;;
    esac
  done
  [ -s "$DOC_DIR/LICENSE" ] || fail "BuildKit LICENSE missing at $DOC_DIR/LICENSE"
  [ -s "$DOC_DIR/MANIFEST" ] || fail "payload MANIFEST missing at $DOC_DIR/MANIFEST"
  for member in buildkitd buildctl buildkit-runc; do
    perms="$(stat -c '%a' "$PAYLOAD_DIR/$member")"
    [ "$perms" = "755" ] || fail "$PAYLOAD_DIR/$member mode $perms, want 755"
    owner="$(stat -c '%U:%G' "$PAYLOAD_DIR/$member")"
    [ "$owner" = "root:root" ] || fail "$PAYLOAD_DIR/$member owner $owner, want root:root"
  done
  for member in LICENSE MANIFEST; do
    perms="$(stat -c '%a' "$DOC_DIR/$member")"
    [ "$perms" = "644" ] || fail "$DOC_DIR/$member mode $perms, want 644"
  done
}

assert_rpm_files() {
  local list modes
  list="$(rpm -ql docker-helper)"
  for path in /usr/lib/systemd/system/docker-helper.service \
    /usr/lib/systemd/system/docker-helper-builder.service \
    /usr/libexec/docker-helper/buildkit/buildkitd \
    /usr/libexec/docker-helper/buildkit/buildctl \
    /usr/libexec/docker-helper/buildkit/buildkit-runc \
    /usr/share/doc/docker-helper/buildkit/LICENSE \
    /usr/share/doc/docker-helper/buildkit/MANIFEST \
    /usr/share/docker-helper/lib/provision-builder.sh \
    /usr/bin/docker-helper; do
    printf '%s\n' "$list" | grep -qxF "$path" || fail "RPM file list missing $path"
  done
  modes="$(rpm -q docker-helper --qf '[%{FILEMODES:perms} %{FILENAMES}\n]' | grep -E '/(buildkitd|buildctl|buildkit-runc|docker-helper-builder\.service|LICENSE|MANIFEST)$')"
  printf '%s\n' "$modes" | grep -qF -- "-rwxr-xr-x /usr/libexec/docker-helper/buildkit/buildkitd" \
    || fail "RPM buildkitd mode wrong: $modes"
  printf '%s\n' "$modes" | grep -qF -- "-rwxr-xr-x /usr/libexec/docker-helper/buildkit/buildctl" \
    || fail "RPM buildctl mode wrong"
  printf '%s\n' "$modes" | grep -qF -- "-rwxr-xr-x /usr/libexec/docker-helper/buildkit/buildkit-runc" \
    || fail "RPM buildkit-runc mode wrong"
  printf '%s\n' "$modes" | grep -qF -- "-rw-r--r-- /usr/lib/systemd/system/docker-helper-builder.service" \
    || fail "RPM builder unit mode wrong"
  owners="$(rpm -q docker-helper --qf '[%{FILEUSERNAME}:%{FILEGROUPNAME} %{FILENAMES}\n]' | grep -E '/usr/libexec/docker-helper/buildkit/buildkitd$')"
  printf '%s\n' "$owners" | grep -qF "root:root /usr/libexec/docker-helper/buildkit/buildkitd" \
    || fail "RPM buildkitd ownership wrong: $owners"
}

assert_builder_unit_enabled() {
  enabled="$(systemctl is-enabled "$UNIT" 2>/dev/null || true)"
  [ "$enabled" = "enabled" ] || fail "$UNIT is-enabled = '$enabled', want enabled"
  [ -f "$PROVISIONER_SHIPPED" ] || fail "shipped provisioning script missing at $PROVISIONER_SHIPPED"
}

assert_main_unit_coupling() {
  local wants after
  wants="$(systemctl show "$MAIN_UNIT" -p Wants --value)"
  case "$wants" in
    *"docker-helper-builder.service"*) ;;
    *) fail "main unit Wants= must include docker-helper-builder.service (got: $wants)" ;;
  esac
  after="$(systemctl show "$MAIN_UNIT" -p After --value)"
  case "$after" in
    *"docker-helper-builder.service"*) ;;
    *) fail "main unit After= must include docker-helper-builder.service (got: $after)" ;;
  esac
}

assert_builder_manager_process() {
  local mgrpid status sock sock_stat world
  mgrpid="$(systemctl show "$UNIT" -p MainPID --value)"
  if [ -z "$mgrpid" ] || [ "$mgrpid" = "0" ]; then
    fail "$UNIT MainPID missing"
  fi
  status="/proc/$mgrpid/status"
  [ -r "$status" ] || fail "cannot read $status"
  grep -q '^NoNewPrivs:[[:space:]]*0$' "$status" || fail "builder manager must show NoNewPrivs: 0 (the recorded exception)"
  grep -q '^CapEff:[[:space:]]*0000000000000000$' "$status" || fail "builder manager must hold no effective capabilities (CapEff 0)"
  grep -q '^CapBnd:[[:space:]]*00000000802000c2$' "$status" || fail "builder manager CapBnd must be 00000000802000c2 (the frozen five-cap floor)"
  evidence "builder-manager-status.txt" "$(cat "$status")"
  sock="/run/docker-helper-builder/manager.sock"
  [ -S "$sock" ] || fail "manager socket missing: $sock"
  sock_stat="$(stat -c '%U %G %a' "$sock")"
  case "$sock_stat" in
    "docker-helper-builder docker-helper-builder "*) ;;
    *) fail "manager socket owner/group unexpected: $sock_stat" ;;
  esac
  world="$(stat -c '%a' "$sock")"
  [ "$((8#$world & 8#0007))" = "0" ] || fail "manager socket must not be world-accessible: $sock_stat"
}

assert_selinux_module_loaded() {
  semodule -l 2>/dev/null | grep -qw docker_helper \
    || fail "SELinux docker_helper module not loaded after the RPM %post scriptlet"
}

# assert_canonical_third_party_labels <phase> — the third-party binaries the
# deployment lifecycle relabels at install (the rootlesskit launch vehicle,
# the bindfs projection dependency) must carry exactly the label the CURRENT
# fcontext policy resolves as canonical for their paths (matchpathcon). With
# the module loaded the canonical type is the docker_helper exec type; after
# a verified module removal it is whatever the distro policy says for the
# path — the assert is self-consistent and never pinned to a specific type.
assert_canonical_third_party_labels() {
  local phase="$1" bin_path actual canonical
  for bin_path in /usr/bin/rootlesskit /usr/bin/bindfs /usr/bin/slirp4netns /usr/bin/newuidmap; do
    [ -e "$bin_path" ] || fail "$phase: third-party binary missing: $bin_path"
    actual="$(stat -c '%C' "$bin_path" 2>&1)" || fail "$phase: cannot stat $bin_path: $actual"
    canonical="$(matchpathcon "$bin_path" 2>/dev/null | awk '{print $2}')"
    [ -n "$canonical" ] || fail "$phase: matchpathcon resolved no canonical label for $bin_path"
    [ "$actual" = "$canonical" ] \
      || fail "$phase: $bin_path label '$actual' != canonical '$canonical' (uninstall lifecycle must restore third-party binary labels)"
    echo "$phase $bin_path: $actual" >> "$EVIDENCE_DIR/third-party-labels-restore.txt"
  done
}

# --- P1: RPM fresh install ----------------------------------------------------

log "P1: RPM fresh install via zypper (real dependency resolution)"
zypper --non-interactive --gpg-auto-import-keys refresh >/dev/null 2>&1 || true
# The candidate RPM is intentionally unsigned (nfpm does not sign); zypper
# aborts unsigned local packages in non-interactive mode unless explicitly
# allowed (--allow-unsigned-rpm is an install-command option, not a global
# one). Its output is kept in the evidence dir for diagnosis.
zypper --non-interactive install -y --allow-unsigned-rpm "$RPM" \
  >"$EVIDENCE_DIR/zypper-install-candidate.log" 2>&1 \
  || { tail -30 "$EVIDENCE_DIR/zypper-install-candidate.log"; fail "zypper install of the candidate RPM failed"; }
[ "$(rpm -q --qf '%{VERSION}' docker-helper)" = "$VERSION" ] || fail "RPM version mismatch"
assert_rpm_files
assert_provisioned yes
assert_payload
assert_builder_unit_enabled
assert_main_unit_coupling
assert_selinux_module_loaded
# The launch vehicle's helpers are installed by the dependency resolution
# from the real repos (RPM dependencies of the candidate, shipped by the
# distro, never by our payload): confirm the actual paths the policy and the
# proofs rely on, that the distro owns the binaries, and that the UID-map
# helper keeps its setuid bit (its privilege model).
for helper_path in /usr/bin/slirp4netns /usr/bin/newuidmap; do
  [ -x "$helper_path" ] || fail "$helper_path must exist after the RPM dependency resolution"
  rpm -qf "$helper_path" >/dev/null 2>&1 || fail "$helper_path must be owned by a real distro package"
done
[ "$(stat -c '%U:%G' /usr/bin/newuidmap)" = "root:root" ] || fail "newuidmap ownership must be root:root"
test -u /usr/bin/newuidmap || fail "newuidmap must keep its setuid bit"

# P4-B1.2 scriptlet-ordering proof: the docker_helper module load lives in
# %posttrans, which rpm runs after ALL %post scriptlets of the transaction
# and, in transaction install order, after container-selinux's own
# %posttrans. The zypper transaction log shows the %posttrans scriptlet
# sections in execution order; the docker-helper posttrans marker must
# appear after the container-selinux %posttrans section header.
zlog="$EVIDENCE_DIR/zypper-install-candidate.log"
container_pt="$(grep -n 'posttrans(container-selinux' "$zlog" | head -1 | cut -d: -f1)"
helper_pt="$(grep -n 'docker-helper posttrans:' "$zlog" | head -1 | cut -d: -f1)"
[ -n "$container_pt" ] || fail "container-selinux %posttrans not found in the transaction log (scriptlet-ordering proof)"
[ -n "$helper_pt" ] || fail "docker-helper %posttrans output not found in the transaction log (scriptlet-ordering proof)"
[ "$helper_pt" -gt "$container_pt" ] \
  || fail "docker-helper %posttrans must run after container-selinux %posttrans (scriptlet-ordering proof)"

# A fresh install never starts or restarts the main daemon.
[ "$(systemctl is-active "$MAIN_UNIT" 2>/dev/null || true)" = "inactive" ] \
  || fail "the RPM transaction must not start the main daemon on a fresh install"
say "P1 scriptlet-ordering proof OK (container-selinux %posttrans before docker-helper %posttrans)"
say "starting the builder service standalone (P4-A1 boundary asserts under the packaged unit)"
[ "$(stat -c %C /usr/bin/docker-helper 2>/dev/null)" = "system_u:object_r:docker_helper_exec_t:s0" ] \
  || fail "/usr/bin/docker-helper label wrong: '$(stat -c %C /usr/bin/docker-helper 2>/dev/null)', want docker_helper_exec_t"
[ "$(stat -c %C /usr/bin/bindfs 2>/dev/null)" = "system_u:object_r:docker_helper_bindfs_exec_t:s0" ] \
  || fail "/usr/bin/bindfs label wrong: '$(stat -c %C /usr/bin/bindfs 2>/dev/null)', want docker_helper_bindfs_exec_t"
systemctl start "$UNIT" || {
  journalctl -u "$UNIT" -b --no-pager > "$EVIDENCE_DIR/builder-start-failure-journal.txt" 2>&1 || true
  systemctl status "$UNIT" --no-pager > "$EVIDENCE_DIR/builder-start-status.txt" 2>&1 || true
  journalctl -k -b --no-pager | grep -iE "avc" | tail -40 > "$EVIDENCE_DIR/builder-start-avc-kernel.txt" 2>/dev/null || true
  tail -40 /var/log/audit/audit.log > "$EVIDENCE_DIR/builder-start-audit.log" 2>/dev/null || true
  matchpathcon /usr/bin/docker-helper /usr/bin/bindfs > "$EVIDENCE_DIR/builder-start-matchpathcon.txt" 2>&1 || true
  ls -Z /usr/bin/docker-helper /usr/bin/bindfs >> "$EVIDENCE_DIR/builder-start-matchpathcon.txt" 2>&1 || true
  fail "systemctl start $UNIT failed (unit journal, status, AVC and label evidence captured)"
}
[ "$(systemctl is-active "$UNIT" 2>/dev/null || true)" = "active" ] || fail "builder service not active after start"
assert_builder_manager_process
systemctl stop "$UNIT" || fail "systemctl stop $UNIT failed"
say "P1 asserts OK"

# --- P2: idempotent reinstall --------------------------------------------------

log "P2: idempotent reinstall (rpm -U --replacepkgs)"
UID_ENTRY_BEFORE="$(subuid_entry)"
GID_ENTRY_BEFORE="$(subgid_entry)"
rpm -Uvh --replacepkgs "$RPM" >/dev/null || fail "idempotent rpm -U --replacepkgs failed"
[ "$(subuid_entry)" = "$UID_ENTRY_BEFORE" ] || fail "subuid range changed across reinstall: '$UID_ENTRY_BEFORE' -> '$(subuid_entry)'"
[ "$(subgid_entry)" = "$GID_ENTRY_BEFORE" ] || fail "subgid range changed across reinstall"
assert_builder_unit_enabled
say "P2 asserts OK"

# --- P2b: failed SELinux module load must not touch the running daemon --------

# The enforcing-SELinux `docker-helper init` relabels the exact docker CLI
# executable the daemon will exec (applyDeploymentSELinuxRelabel), so the
# docker CLI must be present before init — the same prerequisite a real
# operator satisfies (install-system.sh requires docker too). The engine
# itself is asserted reachable in the P4 tarball phase.
log "installing docker via zypper (docker CLI required by init's SELinux relabel; engine needed by the tarball phase)"
if ! command -v docker >/dev/null 2>&1; then
  zypper --non-interactive install -y docker >"$EVIDENCE_DIR/zypper-install-docker.log" 2>&1 \
    || { tail -20 "$EVIDENCE_DIR/zypper-install-docker.log"; fail "cannot install docker in the guest"; }
fi

log "P2b: semodule failure cannot trigger daemon start/restart (negative proof)"
mkdir -p "$ALLOWED_ROOT" || fail "cannot create the allowed root $ALLOWED_ROOT"
/usr/bin/docker-helper init --allowed-root "$ALLOWED_ROOT" \
  >"$EVIDENCE_DIR/init-negative-phase.log" 2>&1 \
  || { tail -20 "$EVIDENCE_DIR/init-negative-phase.log"; fail "cannot init the docker-helper config for the negative-proof phase (the real init error is above)"; }
systemctl start "$MAIN_UNIT" || fail "cannot start the main daemon for the negative-proof phase"
[ "$(systemctl is-active "$MAIN_UNIT" 2>/dev/null || true)" = "active" ] || fail "main daemon not active after start"
OLD_PID="$(systemctl show "$MAIN_UNIT" -p MainPID --value)"
{ [ -n "$OLD_PID" ] && [ "$OLD_PID" != "0" ]; } || fail "main daemon MainPID missing"

# Poison the module load with a failing semodule shim. rpm scriptlets do
# NOT inherit the invoking root PATH: rpm sets the scriptlet PATH from the
# _install_script_path macro (upstream default
# /sbin:/bin:/usr/sbin:/usr/bin:/usr/X11R6/bin), so /usr/local/sbin is
# unreachable from the %posttrans. The shim is reached through the
# scriptlet-path define on THIS invocation only (the narrow fault injection:
# the shipped scriptlet and the real semodule stay untouched; the recovery
# invocation below uses the default path). The shim passes the -l
# container-policy precondition through to the real semodule and fails
# every install (-i) invocation.
cat > /usr/local/sbin/semodule <<'POISON'
#!/bin/sh
[ "$1" = "-l" ] && exec /usr/sbin/semodule "$@"
echo "poisoned semodule (P4-B1.2 negative proof)" >&2
exit 1
POISON
chmod 0755 /usr/local/sbin/semodule
set +e
POISON_OUT="$(rpm -Uvh --replacepkgs "$RPM" \
  --define '_install_script_path /usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin' 2>&1)"
POISON_RC=$?
set -e
printf '%s\n' "$POISON_OUT" > "$EVIDENCE_DIR/failed-semodule-rpm.txt"
# rpm treats a %posttrans scriptlet failure as a WARNING and completes the
# transaction with exit 0 (observed on Tumbleweed): the refusal proof is the
# failing-scriptlet report plus the shipped %posttrans's own fail-closed
# refusal, never the transaction exit code.
printf '%s\n' "$POISON_OUT" | grep -q "scriptlet failed" \
  || fail "rpm must report the failing scriptlet (actual failure reporting is recorded; never claimed as rollback)"
printf '%s\n' "$POISON_OUT" | grep -q "docker-helper.service was not restarted" \
  || fail "the failed module load must refuse loudly without restarting the daemon (the shipped %posttrans contract)"
[ "$(systemctl is-active "$MAIN_UNIT" 2>/dev/null || true)" = "active" ] \
  || fail "the failed module load must not stop the active daemon"
[ "$(systemctl show "$MAIN_UNIT" -p MainPID --value)" = "$OLD_PID" ] \
  || fail "the failed module load must not restart the active daemon"
[ -f /run/docker-helper-rpm/posttrans-state ] \
  || fail "a failed %posttrans must not consume the deferred-restart decision"
assert_selinux_module_loaded
rm -f /usr/local/sbin/semodule
rpm -Uvh --replacepkgs "$RPM" >/dev/null || fail "recovery rpm -U --replacepkgs after the poisoned-semodule failure"
[ "$(systemctl show "$MAIN_UNIT" -p MainPID --value)" != "$OLD_PID" ] \
  || fail "the recovery posttrans must restart the previously active service"
assert_selinux_module_loaded
say "P2b asserts OK"

# --- P3: failed provisioning + interrupted-install recovery --------------------

log "P3: failed provisioning is fail-closed; interrupted install recovers"
usermod -s /bin/sh "$BUILDER_USER" || fail "cannot poison the builder shell for the failure simulation"
set +e
POISON_OUT="$(rpm -Uvh --replacepkgs "$RPM" 2>&1)"
POISON_RC=$?
set -e
# rpm reports a failed %post scriptlet and still completes the transaction
# (observed on Tumbleweed: the scriptlet failure is a logged report, the
# exit code stays 0). The fail-closed proof is the provisioner's own
# refusal plus the scriptlet-failure report, never the transaction exit
# code.
printf '%s\n' "$POISON_OUT" | grep -q "provision-builder: FAILED" \
  || fail "the provisioning failure must surface (provision-builder: FAILED)"
printf '%s\n' "$POISON_OUT" | grep -q "scriptlet failed" \
  || fail "rpm must report the failing %post scriptlet"
evidence "failed-provisioning-rpm.txt" "$POISON_OUT"
say "provisioner failed closed as required (scriptlet failure reported; rpm exit $POISON_RC)"

usermod -s /usr/sbin/nologin "$BUILDER_USER" || fail "cannot repair the builder shell"
rpm -Uvh --replacepkgs "$RPM" >/dev/null || fail "recovery rpm -U --replacepkgs failed"
[ "$(rpm -q --qf '%{VERSION}' docker-helper)" = "$VERSION" ] || fail "RPM version mismatch after recovery"
say "P3 asserts OK"

# --- P4: tarball install -> assert -> uninstall --purge ------------------------

log "P4: tarball install via the bundled install-system.sh (SELinux host)"
rpm -e docker-helper || fail "rpm -e docker-helper (before the tarball phase) failed"
[ ! -e /usr/lib/systemd/system/docker-helper-builder.service ] || fail "builder unit survived rpm -e"
# rpm removes the owned payload FILES; the parent directories carry no rpm
# dir entries (nfpm lists files only), so an EMPTY leftover dir is rpm
# bookkeeping, not package residue. The residual-state proof is the absence
# of every payload file plus an empty leftover dir; any non-empty leftover
# is real residue and fails with evidence.
[ ! -e "$PAYLOAD_DIR/buildkitd" ] || fail "payload buildkitd survived rpm -e"
[ ! -e "$PAYLOAD_DIR/buildctl" ] || fail "payload buildctl survived rpm -e"
[ ! -e "$PAYLOAD_DIR/buildkit-runc" ] || fail "payload buildkit-runc survived rpm -e"
[ ! -e "$DOC_DIR/LICENSE" ] || fail "payload LICENSE survived rpm -e"
[ ! -e "$DOC_DIR/MANIFEST" ] || fail "payload MANIFEST survived rpm -e"
if [ -d "$PAYLOAD_DIR" ] && [ -n "$(ls -A "$PAYLOAD_DIR" 2>/dev/null)" ]; then
  ls -la "$PAYLOAD_DIR" > "$EVIDENCE_DIR/payload-dir-residue.txt"
  fail "payload dir has unexpected residue after rpm -e (see payload-dir-residue.txt)"
fi
assert_provisioned yes   # the identity is KEPT on package removal (recorded choice)
if semodule -l 2>/dev/null | grep -qw docker_helper; then
  fail "SELinux docker_helper module must be removed by the RPM preremove"
fi
# After the verified module removal the erase lifecycle must have restored
# the third-party binaries' canonical labels (the relabel-then-restore
# contract).
assert_canonical_third_party_labels "rpm-e"

mkdir -p "$ALLOWED_ROOT"
WORK_TAR="$GUEST_FILES/bundle"
rm -rf "$WORK_TAR"
mkdir -p "$WORK_TAR"
tar xzf "$TARBALL" -C "$WORK_TAR"
BUNDLE="$WORK_TAR/docker-helper-${VERSION}-linux-amd64"
[ -x "$BUNDLE/install-system.sh" ] || fail "bundle missing install-system.sh"

systemctl start docker >/dev/null 2>&1 || true
docker info >/dev/null 2>&1 || fail "docker engine not reachable in the guest (required by install-system.sh)"

( cd "$BUNDLE" && ./install-system.sh --yes --allowed-root "$ALLOWED_ROOT" ) \
  || fail "install-system.sh (tarball) failed"

assert_provisioned yes
assert_payload
[ -f /etc/systemd/system/docker-helper-builder.service ] || fail "tarball install did not install the builder unit to /etc/systemd/system"
enabled="$(systemctl is-enabled "$UNIT" 2>/dev/null || true)"
[ "$enabled" = "enabled" ] || fail "tarball install must enable the builder unit (got '$enabled')"
[ "$(systemctl is-active "$UNIT" 2>/dev/null || true)" = "active" ] || fail "builder service not active after tarball install"
[ "$(systemctl is-active "$MAIN_UNIT" 2>/dev/null || true)" = "active" ] || fail "main daemon not active after tarball install"
assert_builder_manager_process
assert_selinux_module_loaded
nnp="$(grep '^NoNewPrivs:' "/proc/$(systemctl show "$MAIN_UNIT" -p MainPID --value)/status" | awk '{print $2}')"
[ "$nnp" = "1" ] || fail "main daemon must keep NoNewPrivs: 1 (got $nnp)"
say "P4 tarball asserts OK"

( cd "$BUNDLE" && ./uninstall-system.sh --yes --purge ) || fail "uninstall-system.sh --purge failed"
[ "$(systemctl is-active "$UNIT" 2>/dev/null || true)" != "active" ] || fail "builder service still active after purge"
[ ! -e /etc/systemd/system/docker-helper-builder.service ] || fail "tarball builder unit still present after purge"
[ ! -d "$PAYLOAD_DIR" ] || fail "payload dir still present after purge"
[ ! -d "$DOC_DIR" ] || fail "payload doc dir still present after purge"
[ ! -d /run/docker-helper-builder ] || fail "builder runtime dir still present after purge"
[ ! -d /var/lib/docker-helper-builder ] || fail "builder state dir still present after purge"
assert_provisioned no
# The tarball uninstaller must restore the third-party binary labels the same
# way the RPM erase does.
assert_canonical_third_party_labels "tarball-purge"
say "P4 purge asserts OK"

# --- P5: upgrade from the pinned released v2.3.0 baseline ----------------------

log "P5: upgrade from pinned v2.3.0 -> candidate RPM"
BASELINE="$GUEST_FILES/baseline-2.3.0.rpm"
# The fixture is a transferred file inside the guest; the analyzer cannot
# follow that path (dynamically-sourced fixture).
# shellcheck disable=SC1091
( source "$GUEST_FILES/uat-upgrade-baseline-fixture.sh" && upgrade230_fetch_rpm "$BASELINE" >/dev/null ) \
  || fail "cannot resolve + verify the pinned v2.3.0 baseline RPM"
evidence "baseline-digest.txt" "$(sha256sum "$BASELINE")"
rpm -Uvh "$BASELINE" >/dev/null || fail "rpm -U of the pinned v2.3.0 baseline failed"
[ "$(rpm -q --qf '%{VERSION}' docker-helper)" = "2.3.0" ] || fail "baseline version mismatch"
assert_provisioned no
[ ! -e /usr/lib/systemd/system/docker-helper-builder.service ] || fail "v2.3.0 must not install the builder unit"
[ ! -d "$PAYLOAD_DIR" ] || fail "v2.3.0 must not install the BuildKit payload"
wants="$(systemctl show "$MAIN_UNIT" -p Wants --value)"
case "$wants" in *"docker-helper-builder.service"*) fail "v2.3.0 main unit must not want the builder service" ;; esac
say "v2.3.0 baseline installed with its recorded shape"

rpm -Uvh "$RPM" >/dev/null || fail "upgrade install (candidate over v2.3.0) failed"
[ "$(rpm -q --qf '%{VERSION}' docker-helper)" = "$VERSION" ] || fail "upgraded version mismatch"
assert_provisioned yes
assert_payload
assert_builder_unit_enabled
assert_main_unit_coupling
assert_selinux_module_loaded
# The upgrade must NOT trigger label cleanup: with the module loaded the
# canonical labels for the third-party binaries are the docker_helper exec
# types, and the %posttrans relabel reapplies them (verified by the same
# self-consistent assert).
assert_canonical_third_party_labels "p5-upgrade"
[ ! -e /etc/systemd/system/docker-helper-builder.service ] || fail "RPM upgrade must not install into /etc/systemd/system"
say "P5 asserts OK"

systemctl start "$UNIT" || fail "systemctl start $UNIT failed (final state)"
assert_builder_manager_process
systemctl stop "$UNIT" || fail "final stop failed"

{
  echo "version=$VERSION"
  echo "rpm=$(sha256sum "$RPM" | awk '{print $1}')"
  echo "tarball=$(sha256sum "$TARBALL" | awk '{print $1}')"
  echo "buildkitd=$BUILDKITD_SHA256"
  echo "buildctl=$BUILDCTL_SHA256"
  echo "buildkit-runc=$BUILDKIT_RUNC_SHA256"
  echo "subids: $(subuid_entry) / $(subgid_entry)"
} > "$EVIDENCE_DIR/digests.txt"

printf '%s P4B-TW-PACKAGES-RESULT=PASS\n' "$PREFIX"
