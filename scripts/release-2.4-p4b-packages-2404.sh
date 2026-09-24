#!/usr/bin/env bash
#
# Release 2.4 P4 packaging proof — Ubuntu 24.04 (hosted runner).
#
# Installs the GENERATED release-candidate artifacts (the canonical producer
# output: tarball + DEB, per candidate.manifest / SHA256SUMS) and proves the
# packaging lifecycle through the package managers — never loose files copied
# from the checkout:
#
#   P1  tarball install via the bundled install-system.sh, full assert, then
#       uninstall --purge (identity removed, all artifacts gone);
#   P2  DEB fresh install (dpkg ownership, modes, file list, provisioning,
#       builder unit enabled, standalone builder start: NoNewPrivs 0,
#       CapEff 0, CapBnd 802000c2, manager socket owner+group-only);
#   P3  idempotent reinstall (same DEB again: same subid ranges, still
#       enabled);
#   P4  failed provisioning is fail-closed (poisoned builder shell -> dpkg
#       reports the postinst failure) and the interrupted install recovers
#       through dpkg --configure -a after the account is repaired;
#   P5  upgrade from the pinned released v2.3.0 baseline (no builder
#       identity/unit/payload) to the candidate: provisioning happens on
#       upgrade, the builder unit + payload land, the main unit carries the
#       weak Wants/After coupling, the restarted daemon pulls the builder
#       service in, and the payload digests stay pinned.
#
# The payload digest assertions use the pinned upstream identities recorded
# in the build-buildkit-payload.sh MANIFEST (tarball digest + per-file
# digests), so every installed format must match the exact proven bytes.
#
# Prereqs (installed by the caller): root; systemd; docker running; dpkg +
# the candidate's package dependencies (passwd uidmap rootlesskit
# slirp4netns apparmor); the repo checkout for the upgrade-baseline fixture.

set -Eeuo pipefail

PREFIX='[release-2.4-p4b-2404]'
EVIDENCE_DIR="${P4B_EVIDENCE_DIR:-/tmp/release-2.4-p4b-evidence}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CANDIDATE_DIR="${P4B_CANDIDATE_DIR:-/tmp/p4b/candidate}"
VERSION="${P4B_VERSION:-2.4.0}"
ALLOWED_ROOT="${P4B_ALLOWED_ROOT:-/srv/docker-helper-p4b-uat}"

DEB_NAME="docker-helper_${VERSION}_amd64.deb"
TARBALL_NAME="docker-helper-${VERSION}-linux-amd64.tar.gz"
DEB="$CANDIDATE_DIR/$DEB_NAME"
TARBALL="$CANDIDATE_DIR/$TARBALL_NAME"

UNIT=docker-helper-builder.service
MAIN_UNIT=docker-helper.service
BUILDER_USER=docker-helper-builder
PAYLOAD_DIR=/usr/libexec/docker-helper/buildkit
DOC_DIR=/usr/share/doc/docker-helper/buildkit
PROVISIONER_SHIPPED=/usr/share/docker-helper/lib/provision-builder.sh

say() { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

evidence() {
	local name="$1" content="$2"
	mkdir -p "$EVIDENCE_DIR"
	printf '%s\n' "$content" > "$EVIDENCE_DIR/$name"
}

# Pinned payload identities: read from the single owner (build-buildkit-payload.sh)
# so the pins exist in exactly one place.
PIN_OWNER="$REPO_DIR/build-buildkit-payload.sh"

pin() {
	local value
	value="$(sed -n "s/^$1=\"\([0-9a-f]\{64\}\)\"/\1/p" "$PIN_OWNER")"
	[ -n "$value" ] || fail "cannot read pin $1 from the payload owner $PIN_OWNER"
	printf '%s' "$value"
}

BUILDKITD_SHA256="$(pin BUILDKITD_SHA256)"
BUILDCTL_SHA256="$(pin BUILDCTL_SHA256)"
BUILDKIT_RUNC_SHA256="$(pin BUILDKIT_RUNC_SHA256)"

subuid_entry() { awk -F: -v u="$BUILDER_USER" '$1 == u { print $2 " " $3; exit }' /etc/subuid; }
subgid_entry() { awk -F: -v u="$BUILDER_USER" '$1 == u { print $2 " " $3; exit }' /etc/subgid; }

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
	local member digest
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

assert_builder_unit_enabled() {
	enabled="$(systemctl is-enabled "$UNIT" 2>/dev/null || true)"
	[ "$enabled" = "enabled" ] || fail "$UNIT is-enabled = '$enabled', want enabled"
	[ -f /usr/lib/systemd/system/docker-helper-builder.service ] || fail "builder unit file missing from the package-owned path"
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

# --- Candidate identity ------------------------------------------------------

id -u | grep -qx 0 || fail "this proof must run as root"
[ -f "$DEB" ] || fail "candidate DEB missing: $DEB (run scripts/release-candidate.sh first)"
[ -f "$TARBALL" ] || fail "candidate tarball missing: $TARBALL"
[ -f "$CANDIDATE_DIR/SHA256SUMS" ] || fail "candidate SHA256SUMS missing"
( cd "$CANDIDATE_DIR" && sha256sum --check SHA256SUMS >/dev/null ) || fail "candidate SHA256SUMS verification failed"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- P1: tarball install -> assert -> uninstall --purge ----------------------

say "=== P1: tarball install via the bundled install-system.sh ==="
tar xzf "$TARBALL" -C "$WORK"
BUNDLE="$WORK/docker-helper-${VERSION}-linux-amd64"
[ -x "$BUNDLE/install-system.sh" ] || fail "bundle missing install-system.sh"
[ -f "$BUNDLE/systemd/system/docker-helper-builder.service" ] || fail "bundle missing the builder unit"
[ -s "$BUNDLE/buildkit/buildkitd" ] || fail "bundle missing the pinned BuildKit payload"
[ -f "$BUNDLE/scripts/provision-builder.sh" ] || fail "bundle missing the provisioning script"

mkdir -p "$ALLOWED_ROOT"
( cd "$BUNDLE" && ./install-system.sh --yes --allowed-root "$ALLOWED_ROOT" ) \
	|| fail "install-system.sh (tarball) failed"

assert_provisioned yes
assert_payload
[ -f /etc/systemd/system/docker-helper-builder.service ] || fail "tarball install did not install the builder unit to /etc/systemd/system"
enabled="$(systemctl is-enabled "$UNIT" 2>/dev/null || true)"
[ "$enabled" = "enabled" ] || fail "tarball install must enable the builder unit (got '$enabled')"
active="$(systemctl is-active "$UNIT" 2>/dev/null || true)"
[ "$active" = "active" ] || fail "tarball install must start the builder unit (main-unit Wants= pull-in; got '$active')"
active="$(systemctl is-active "$MAIN_UNIT" 2>/dev/null || true)"
[ "$active" = "active" ] || fail "main daemon not active after tarball install"
assert_builder_manager_process
nnp="$(grep '^NoNewPrivs:' "/proc/$(systemctl show "$MAIN_UNIT" -p MainPID --value)/status" | awk '{print $2}')"
[ "$nnp" = "1" ] || fail "main daemon must keep NoNewPrivs: 1 (got $nnp)"
say "P1 tarball asserts OK"

say "=== P1 teardown: uninstall-system.sh --purge ==="
( cd "$BUNDLE" && ./uninstall-system.sh --yes --purge ) || fail "uninstall-system.sh --purge failed"
active="$(systemctl is-active "$UNIT" 2>/dev/null || true)"
[ "$active" != "active" ] || fail "builder service still active after purge"
[ ! -e /usr/lib/systemd/system/docker-helper-builder.service ] || fail "builder unit still present after purge"
[ ! -e /etc/systemd/system/docker-helper-builder.service ] || fail "tarball-installed builder unit still present after purge"
[ ! -d "$PAYLOAD_DIR" ] || fail "payload dir still present after purge"
[ ! -d "$DOC_DIR" ] || fail "payload doc dir still present after purge"
[ ! -d /run/docker-helper-builder ] || fail "builder runtime dir still present after purge"
[ ! -d /var/lib/docker-helper-builder ] || fail "builder state dir still present after purge"
assert_provisioned no
say "P1 purge asserts OK"

# --- P2: DEB fresh install ----------------------------------------------------

say "=== P2: DEB fresh install (dpkg -i) ==="
dpkg -i "$DEB" || fail "dpkg -i of the candidate DEB failed"
dpkg-query -W -f '${Status}\n' docker-helper 2>/dev/null | grep -q "install ok installed" \
	|| fail "DEB status not 'install ok installed' after install"
dpkg -S /usr/lib/systemd/system/docker-helper-builder.service >/dev/null || fail "builder unit not dpkg-owned"
dpkg -S "$PAYLOAD_DIR/buildkitd" >/dev/null || fail "buildkitd not dpkg-owned"
dpkg -S /usr/share/docker-helper/lib/provision-builder.sh >/dev/null || fail "shipped provisioning script not dpkg-owned"
for path in /usr/libexec/docker-helper/buildkit/buildctl /usr/libexec/docker-helper/buildkit/buildkit-runc \
	"$DOC_DIR/LICENSE" "$DOC_DIR/MANIFEST" /usr/lib/systemd/system/docker-helper.service; do
	dpkg -L docker-helper | grep -qxF "$path" || fail "DEB file list missing $path"
done
perms="$(stat -c '%a' /usr/lib/systemd/system/docker-helper-builder.service)"
[ "$perms" = "644" ] || fail "builder unit mode $perms, want 644"
assert_provisioned yes
assert_payload
assert_builder_unit_enabled
assert_main_unit_coupling
say "starting the builder service standalone (P4-A1 boundary asserts under the packaged unit)"
systemctl start "$UNIT" || fail "systemctl start $UNIT failed"
active="$(systemctl is-active "$UNIT" 2>/dev/null || true)"
[ "$active" = "active" ] || fail "builder service not active after start"
assert_builder_manager_process
systemctl stop "$UNIT" || fail "systemctl stop $UNIT failed"
say "P2 asserts OK"

# --- P3: idempotent reinstall --------------------------------------------------

say "=== P3: idempotent reinstall (dpkg -i, same version) ==="
UID_ENTRY_BEFORE="$(subuid_entry)"
GID_ENTRY_BEFORE="$(subgid_entry)"
dpkg -i "$DEB" || fail "idempotent dpkg -i failed"
[ "$(subuid_entry)" = "$UID_ENTRY_BEFORE" ] || fail "subuid range changed across reinstall: '$UID_ENTRY_BEFORE' -> '$(subuid_entry)'"
[ "$(subgid_entry)" = "$GID_ENTRY_BEFORE" ] || fail "subgid range changed across reinstall"
assert_builder_unit_enabled
say "P3 asserts OK"

# --- P4: failed provisioning + interrupted-install recovery --------------------

say "=== P4: failed provisioning is fail-closed; interrupted install recovers ==="
usermod -s /bin/sh "$BUILDER_USER" || fail "cannot poison the builder shell for the failure simulation"
set +e
POISON_OUT="$(dpkg -i "$DEB" 2>&1)"
POISON_RC=$?
set -e
[ "$POISON_RC" -ne 0 ] || fail "dpkg -i must fail when provisioning fails (poisoned builder shell)"
printf '%s\n' "$POISON_OUT" | grep -q "provision-builder: FAILED" \
	|| fail "the provisioning failure must surface (provision-builder: FAILED), got: $(printf '%s\n' "$POISON_OUT" | tail -5)"
evidence "failed-provisioning-dpkg.txt" "$POISON_OUT"
say "provisioner failed closed as required (dpkg exit $POISON_RC)"

usermod -s /usr/sbin/nologin "$BUILDER_USER" || fail "cannot repair the builder shell"
dpkg --configure -a || fail "dpkg --configure -a (interrupted-install recovery) failed"
dpkg-query -W -f '${Status}\n' docker-helper 2>/dev/null | grep -q "install ok installed" \
	|| fail "package not configured after the interrupted-install recovery"
say "P4 asserts OK"

# --- P5: upgrade from the pinned released v2.3.0 baseline ----------------------

say "=== P5: upgrade from pinned v2.3.0 -> candidate ==="
# Remove the candidate, then deregister the identity the way the tarball
# --purge does (usermod range removal via shadow-utils, then userdel) so the
# upgrade proves provisioning happens on a TRUE 2.3 host.
dpkg -r docker-helper || fail "dpkg -r docker-helper failed"
[ ! -e /usr/lib/systemd/system/docker-helper-builder.service ] || fail "builder unit survived dpkg -r"
[ ! -d "$PAYLOAD_DIR" ] || fail "payload dir survived dpkg -r"
uid_entry="$(subuid_entry)"
gid_entry="$(subgid_entry)"
if [ -n "$uid_entry" ]; then
	start="$(printf '%s' "$uid_entry" | awk '{print $1}')"; count="$(printf '%s' "$uid_entry" | awk '{print $2}')"
	usermod --del-subuids "$start-$((start + count - 1))" "$BUILDER_USER" || fail "cannot remove subuid range"
fi
if [ -n "$gid_entry" ]; then
	start="$(printf '%s' "$gid_entry" | awk '{print $1}')"; count="$(printf '%s' "$gid_entry" | awk '{print $2}')"
	usermod --del-subgids "$start-$((start + count - 1))" "$BUILDER_USER" || fail "cannot remove subgid range"
fi
userdel "$BUILDER_USER" 2>/dev/null || true
groupdel "$BUILDER_USER" 2>/dev/null || true
assert_provisioned no

BASELINE="$WORK/baseline-2.3.0.deb"
# The fixture is the repo file in CI and a transferred file elsewhere; the
# analyzer cannot follow either path (dynamically-sourced fixture).
# shellcheck disable=SC1091
( source "$REPO_DIR/scripts/uat-upgrade-baseline-fixture.sh" && upgrade230_fetch_deb "$BASELINE" >/dev/null ) \
	|| fail "cannot resolve + verify the pinned v2.3.0 baseline DEB"
evidence "baseline-digest.txt" "$(sha256sum "$BASELINE")"
dpkg -i "$BASELINE" || fail "dpkg -i of the pinned v2.3.0 baseline failed"
dpkg-query -W -f '${Version}\n' docker-helper 2>/dev/null | grep -qx "2.3.0" \
	|| fail "baseline version mismatch"
assert_provisioned no
[ ! -e /usr/lib/systemd/system/docker-helper-builder.service ] || fail "v2.3.0 must not install the builder unit"
[ ! -d "$PAYLOAD_DIR" ] || fail "v2.3.0 must not install the BuildKit payload"
wants="$(systemctl show "$MAIN_UNIT" -p Wants --value)"
case "$wants" in *"docker-helper-builder.service"*) fail "v2.3.0 main unit must not want the builder service" ;; esac
say "v2.3.0 baseline installed with its recorded shape"

docker-helper init --allowed-root "$ALLOWED_ROOT" >/dev/null 2>&1 || fail "docker-helper init (v2.3.0) failed"
systemctl daemon-reload
systemctl enable --now "$MAIN_UNIT" || fail "enabling the v2.3.0 main service failed"
[ "$(systemctl is-active "$MAIN_UNIT" 2>/dev/null || true)" = "active" ] || fail "v2.3.0 main service not active"

dpkg -i "$DEB" || fail "upgrade install (candidate over v2.3.0) failed"
dpkg-query -W -f '${Version}\n' docker-helper 2>/dev/null | grep -qx "$VERSION" \
	|| fail "upgraded version mismatch"
assert_provisioned yes
assert_payload
assert_builder_unit_enabled
assert_main_unit_coupling
active="$(systemctl is-active "$MAIN_UNIT" 2>/dev/null || true)"
[ "$active" = "active" ] || fail "main service not active after the upgrade"
active="$(systemctl is-active "$UNIT" 2>/dev/null || true)"
[ "$active" = "active" ] || fail "builder service not active after the upgrade (main-unit Wants= pull-in expected)"
assert_builder_manager_process
nnp="$(grep '^NoNewPrivs:' "/proc/$(systemctl show "$MAIN_UNIT" -p MainPID --value)/status" | awk '{print $2}')"
[ "$nnp" = "1" ] || fail "main daemon must keep NoNewPrivs: 1 after the upgrade (got $nnp)"
say "P5 asserts OK"

mkdir -p "$EVIDENCE_DIR"
{
	echo "version=$VERSION"
	echo "deb=$(sha256sum "$DEB" | awk '{print $1}')"
	echo "tarball=$(sha256sum "$TARBALL" | awk '{print $1}')"
	echo "buildkitd=$BUILDKITD_SHA256"
	echo "buildctl=$BUILDCTL_SHA256"
	echo "buildkit-runc=$BUILDKIT_RUNC_SHA256"
	echo "subids: $(subuid_entry) / $(subgid_entry)"
} > "$EVIDENCE_DIR/digests.txt"

printf '%s P4B-2404-PACKAGES-RESULT=PASS\n' "$PREFIX"
