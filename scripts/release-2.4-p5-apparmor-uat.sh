#!/usr/bin/env bash
#
# release-2.4-p5-apparmor-uat.sh — Release 2.4 AppArmor backend-parity UAT
# (Ubuntu 24.04 hosted runner, real AppArmor host).
#
# Proves the AppArmor parity line for the R2.4 builder backend on the exact
# candidate tarball through the documented install path
# (./install-system.sh --yes --allowed-root <root>):
#
#   P0  preflight: AppArmor active, SELinux not enforcing, Docker, parser
#   P1  tarball install; installer selects AppArmor; both profiles land
#   P2  confinement: daemon under docker-helper-system (enforce), builder
#       under docker-helper-builder (enforce)
#   P3  session create (principal + credential + session)
#   P4  docker run through the helper (identity + workspace boundary)
#   P5  docker build through per-operation BuildKit; during the build:
#       bundled buildkitd process, per-op runtime/state roots, the OTEL
#       socket redirect, and the buildkit-runc execution window; after the
#       build: no global /run/buildkit path
#   P6  managed-boundaries reload (workspace boundary in the fragment)
#   P7  generated workload profile prepare + cleanup
#   P8  AppArmor DENIED audit over the fresh window
#   P9  uninstall: both profiles unloaded/removed, no helper-owned
#       generated profiles left loaded
#
# Modes:
#   P5AA_HARVEST=1  loads BOTH shipped profiles in complain mode after the
#                   install (the evidence-harvest window: every denial is
#                   logged and permitted, the functional flow still runs,
#                   and the complete denial inventory is printed). The
#                   enforcing run (default) is the parity proof: any DENIED
#                   record for either profile fails the UAT unless it is on
#                   the narrow allowlist of demonstrated benign probes.
#
# The policy is never widened inside this script; denials are evidence for
# profile iterations, per the repo's evidence-first policy rule.
#
# Env:
#   P5AA_CANDIDATE_DIR  staged candidate set (default /tmp/p5aa/candidate)
#   P5AA_VERSION        candidate version (default 2.4.0)
#   P5AA_PRINCIPAL      OS principal (default runner)
#   P5AA_ALLOWED_ROOT   global allowed root (default /home/runner)
#   P5AA_EVIDENCE_DIR   evidence directory (default /tmp/release-2.4-p5aa-evidence)
#   P5AA_HARVEST        1 = complain-mode harvest window
#
# Prereqs: root; systemd; docker running; apparmor_parser + apparmor-utils
# (complain mode); the repo checkout is NOT needed at runtime.

set -Eeuo pipefail

PREFIX='[release-2.4-p5aa]'
EVIDENCE_DIR="${P5AA_EVIDENCE_DIR:-/tmp/release-2.4-p5aa-evidence}"
CANDIDATE_DIR="${P5AA_CANDIDATE_DIR:-/tmp/p5aa/candidate}"
VERSION="${P5AA_VERSION:-2.4.0}"
PRINCIPAL="${P5AA_PRINCIPAL:-runner}"
ALLOWED_ROOT="${P5AA_ALLOWED_ROOT:-/home/runner}"
HARVEST="${P5AA_HARVEST:-0}"
AA_PARSER="${AA_PARSER:-/usr/sbin/apparmor_parser}"
AA_SYSTEM_DEST=/etc/apparmor.d/docker-helper-system
AA_BUILDER_DEST=/etc/apparmor.d/docker-helper-builder
AA_STATE_FILE=/var/lib/docker-helper/apparmor/managed-boundaries
BUILDER_RT_ROOT=/run/docker-helper-builder
BUILDER_ST_ROOT=/var/lib/docker-helper-builder
PAYLOAD_DIR=/usr/libexec/docker-helper/buildkit
TARBALL="$CANDIDATE_DIR/docker-helper-${VERSION}-linux-amd64.tar.gz"

say() { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }
info() { printf '%s       %s\n' "$PREFIX" "$*"; }

evidence() {
	local name="$1" content="$2"
	mkdir -p "$EVIDENCE_DIR"
	printf '%s\n' "$content" > "$EVIDENCE_DIR/$name"
}

# dump_diagnostics prints the failure-path diagnostics: the fresh unit
# journals, the fresh AppArmor denial inventory, and the profile inventory.
# Used on every functional failure so one run yields the complete evidence.
dump_diagnostics() {
	local header="$1"
	printf '\n[P5AA] diagnostics: %s\n' "$header" >&2
	journalctl -u docker-helper.service --since "@${AA_AUDIT_START_EPOCH}" --no-pager 2>/dev/null | tail -60 >&2 || true
	journalctl -u docker-helper-builder.service --since "@${AA_AUDIT_START_EPOCH}" --no-pager 2>/dev/null | tail -60 >&2 || true
	printf '\n[P5AA] fresh AppArmor audit records at failure time:\n' >&2
	audit_records 'apparmor=' | tail -60 >&2 || true
	{
		journalctl -u docker-helper.service --since "@${AA_AUDIT_START_EPOCH}" --no-pager 2>/dev/null || true
		journalctl -u docker-helper-builder.service --since "@${AA_AUDIT_START_EPOCH}" --no-pager 2>/dev/null || true
	} > "$EVIDENCE_DIR/unit-journals.txt" 2>&1 || true
	audit_records 'apparmor=' > "$EVIDENCE_DIR/apparmor-audit-tail.txt" 2>&1 || true
	aa-status > "$EVIDENCE_DIR/aa-status-on-failure.txt" 2>&1 || true
}

AA_AUDIT_START_EPOCH=0
AA_AUDIT_START_ISO=""

audit_ts() {
	sed -n 's/.*audit(\([0-9][0-9]*\)\.[0-9]*:[0-9]*).*/\1/p' | head -1
}

# audit_records merges BOTH kernel-audit sources (the dmesg ring AND the
# journalctl -k window) before the fresh-window filter: a truncated dmesg
# ring or a lagging journal can each silently miss fresh DENIED records
# when used alone; the merge plus sort -u closes that hole.
audit_records() {
	local filter="$1" line ts raw
	raw="$( { dmesg 2>/dev/null || true; journalctl -k --since "@${AA_AUDIT_START_EPOCH}" --no-pager 2>/dev/null || true; } )"
	printf '%s\n' "$raw" \
		| sed -E 's/^.* audit: type=/audit: type=/' \
		| grep -E "$filter" | while IFS= read -r line; do
			ts="$(printf '%s\n' "$line" | audit_ts)"
			if [ -n "$ts" ] && [ "$ts" -ge "$AA_AUDIT_START_EPOCH" ]; then
				printf '%s\n' "$line"
			fi
		done | sort -u
}

collect_denials_profile() {
	audit_records 'apparmor="DENIED"' | grep -F "profile=\"$1\"" || true
}

# allowlist_shape_key normalizes one docker-helper-system DENIED record
# into its shape fields (operation|addr|name|comm|class|family — net bind
# records carry addr instead of a file name). The shape layer pins WHICH
# records the allowlist matchers may ever accept: an allowlisted record
# whose normalized shape is not in the known set means a matcher started
# matching something new, which is re-evidencing work, never silent
# acceptance.
allowlist_shape_key() {
	local line="$1" op name comm cls fam addr
	op="$(printf '%s\n' "$line" | sed -n 's/.* operation="\([^"]*\)".*/\1/p')"
	name="$(printf '%s\n' "$line" | sed -n 's/.* name="\([^"]*\)".*/\1/p')"
	comm="$(printf '%s\n' "$line" | sed -n 's/.* comm="\([^"]*\)".*/\1/p')"
	cls="$(printf '%s\n' "$line" | sed -n 's/.* class="\([^"]*\)".*/\1/p')"
	fam="$(printf '%s\n' "$line" | sed -n 's/.* family="\([^"]*\)".*/\1/p')"
	addr="$(printf '%s\n' "$line" | sed -n 's/.* addr="\([^"]*\)".*/\1/p')"
	case "$addr" in
		"@docker_cli_"*) addr="@docker_cli_*" ;;
	esac
	printf '%s|%s|%s|%s|%s|%s\n' "$op" "$addr" "$name" "$comm" "$cls" "$fam"
}

# allowlist_shape_max prints the pinned maximum count for a known benign
# shape (observed in the canonical enforcing run 38396271388; a small
# tolerance absorbs scheduler jitter), or fails when the shape is unknown.
allowlist_shape_max() {
	case "$1" in
		"open||/sys/fs/cgroup/system.slice/docker-helper.service/cpu.max|docker-helper|file|") echo 3 ;;
		"open||/sys/fs/cgroup/system.slice/docker-helper.service/cpu.max|buildctl|file|") echo 3 ;;
		"open||/etc/ssl/certs/|buildctl|file|") echo 3 ;;
		"open||/etc/ssl/certs/|docker-buildx|file|") echo 3 ;;
		"exec||/usr/libexec/git/git|docker-buildx|file|") echo 3 ;;
		"exec||/usr/bin/git|docker-buildx|file|") echo 3 ;;
		"bind|@docker_cli_*||docker|net|unix") echo 3 ;;
		*) return 1 ;;
	esac
}

# is_allowlisted_deny classifies one docker-helper-system deny record against
# the narrow allowlist of demonstrated benign probes (the same entries the
# standing black-box UAT tolerates; the policy is not widened for them).
is_allowlisted_deny() {
	local line="$1"
	if echo "$line" | grep -q 'name="/sys/fs/cgroup/system.slice/docker-helper.service/cpu.max"'; then
		return 0
	fi
	if echo "$line" | grep -q 'operation="exec"' \
		&& echo "$line" | grep -qE 'name="/(usr/libexec/git|usr/bin)/git"' \
		&& echo "$line" | grep -q 'comm="docker-buildx"'; then
		return 0
	fi
	if echo "$line" | grep -q 'operation="bind"' \
		&& echo "$line" | grep -q 'class="net"' \
		&& echo "$line" | grep -q 'family="unix"' \
		&& echo "$line" | grep -q 'addr="@docker_cli_' \
		&& echo "$line" | grep -q 'comm="docker"'; then
		return 0
	fi
	if echo "$line" | grep -q 'operation="open"' \
		&& echo "$line" | grep -q 'name="/etc/ssl/certs/"' \
		&& echo "$line" | grep -qE 'comm="(docker-buildx|buildctl)"'; then
		return 0
	fi
	return 1
}

process_attr() {
	cat "/proc/$1/attr/current" 2>/dev/null || true
}

profile_loaded() {
	grep -q "^$1 " /sys/kernel/security/apparmor/profiles 2>/dev/null
}

wait_for() {
	local timeout="$1"
	shift
	local deadline=$((SECONDS + timeout))
	until "$@"; do
		[ "$SECONDS" -lt "$deadline" ] || return 1
		sleep 0.5
	done
}

# --- P0: preflight -----------------------------------------------------------

say "=== P0: preflight ==="

[ "$(id -u)" = "0" ] || fail "must run as root"
[ "$(tr -d '[:space:]' < /sys/module/apparmor/parameters/enabled 2>/dev/null)" = "Y" ] \
	|| fail "AppArmor LSM is not enabled"
if [ -e /sys/fs/selinux/enforce ]; then
	[ "$(tr -d '[:space:]' < /sys/fs/selinux/enforce 2>/dev/null)" = "0" ] \
		|| fail "SELinux must not be enforcing on the AppArmor UAT host"
else
	info "no SELinux enforcement filesystem (expected on Ubuntu)"
fi
command -v docker >/dev/null 2>&1 || fail "docker CLI not found"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable"
[ -x "$AA_PARSER" ] || fail "apparmor_parser not found at $AA_PARSER"
command -v systemctl >/dev/null 2>&1 || fail "systemd not available"
[ -f "$TARBALL" ] || fail "candidate tarball missing: $TARBALL"
getent passwd "$PRINCIPAL" >/dev/null 2>&1 || fail "principal '$PRINCIPAL' does not exist"
[ "$PRINCIPAL" = "root" ] && fail "principal must not be root"
[ -d "$ALLOWED_ROOT" ] || fail "allowed root '$ALLOWED_ROOT' does not exist"

AA_AUDIT_START_EPOCH="$(date +%s)"
AA_AUDIT_START_ISO="$(date -Iseconds)"
info "audit window: $AA_AUDIT_START_ISO (epoch $AA_AUDIT_START_EPOCH)"
info "mode: $([ "$HARVEST" = "1" ] && printf 'HARVEST (complain)')$([ "$HARVEST" = "1" ] || printf 'ENFORCING (parity proof)')"

# --- P1: tarball install -----------------------------------------------------

say "=== P1: tarball install via the bundled install-system.sh ==="

WORK=/tmp/p5aa-work
rm -rf "$WORK"
mkdir -p "$WORK"
tar xzf "$TARBALL" -C "$WORK"
BUNDLE="$(find "$WORK" -maxdepth 1 -type d -name 'docker-helper-*' | head -1)"
if [ -z "$BUNDLE" ] || [ ! -x "$BUNDLE/install-system.sh" ]; then
	fail "bundle missing install-system.sh"
fi

INSTALL_OUT="$( cd "$BUNDLE" && ./install-system.sh --yes --allowed-root "$ALLOWED_ROOT" 2>&1 )" \
	|| fail "install-system.sh failed:
$INSTALL_OUT"
evidence "install-output.txt" "$INSTALL_OUT"
printf '%s\n' "$INSTALL_OUT" | grep -q "MAC backend: AppArmor (active)" \
	|| fail "installer did not select the AppArmor backend"
[ -f "$AA_SYSTEM_DEST" ] || fail "system profile not installed to $AA_SYSTEM_DEST"
[ -f "$AA_BUILDER_DEST" ] || fail "builder profile not installed to $AA_BUILDER_DEST"
profile_loaded docker-helper-system || fail "docker-helper-system profile not loaded"
profile_loaded docker-helper-builder || fail "docker-helper-builder profile not loaded"
info "installer selected AppArmor; both profiles installed and loaded"

if [ "$HARVEST" = "1" ]; then
	# The evidence-harvest window: log-and-permit. The shipped profile BYTES
	# stay in place; the profiles are reloaded from those exact bytes with
	# the parser's load-time complain flag (no on-disk change, no
	# apparmor-utils dependency).
	"$AA_PARSER" --replace --skip-read-cache --Complain "$AA_SYSTEM_DEST" \
		|| fail "complain-mode reload (system) failed"
	"$AA_PARSER" --replace --skip-read-cache --Complain "$AA_BUILDER_DEST" \
		|| fail "complain-mode reload (builder) failed"
	info "harvest mode: both profiles reloaded in complain mode from the shipped bytes"
fi

# --- P2: confinement ---------------------------------------------------------

say "=== P2: daemon and builder confinement ==="

DAEMON_PID="$(systemctl show -p MainPID --value docker-helper.service)"
if [ -z "$DAEMON_PID" ] || [ "$DAEMON_PID" = "0" ]; then
	fail "daemon MainPID is empty"
fi
if [ "$HARVEST" = "1" ]; then
	case "$(process_attr "$DAEMON_PID")" in
		"docker-helper-system (enforce)"|"docker-helper-system (complain)") ;;
		*) fail "daemon attr/current = '$(process_attr "$DAEMON_PID")', want docker-helper-system" ;;
	esac
else
	[ "$(process_attr "$DAEMON_PID")" = "docker-helper-system (enforce)" ] \
		|| fail "daemon is not confined in docker-helper-system (enforce): got '$(process_attr "$DAEMON_PID")'"
fi
BUILDER_PID="$(systemctl show -p MainPID --value docker-helper-builder.service)"
if [ -z "$BUILDER_PID" ] || [ "$BUILDER_PID" = "0" ]; then
	fail "builder MainPID is empty"
fi
if [ "$HARVEST" = "1" ]; then
	case "$(process_attr "$BUILDER_PID")" in
		"docker-helper-builder (enforce)"|"docker-helper-builder (complain)") ;;
		*) fail "builder attr/current = '$(process_attr "$BUILDER_PID")', want docker-helper-builder" ;;
	esac
else
	[ "$(process_attr "$BUILDER_PID")" = "docker-helper-builder (enforce)" ] \
		|| fail "builder is not confined in docker-helper-builder (enforce): got '$(process_attr "$BUILDER_PID")'"
fi
aa-status > "$EVIDENCE_DIR/aa-status.txt" 2>&1 || true
info "daemon pid=$DAEMON_PID profile=$(process_attr "$DAEMON_PID")"
info "builder pid=$BUILDER_PID profile=$(process_attr "$BUILDER_PID")"

# --- P3: session create ------------------------------------------------------

say "=== P3: principal + credential + session create ==="

# The installer returns before the daemon has bound its API socket (the
# start is asynchronous), so the first API call can race the socket bind.
# Wait (bounded, short interval) for the actual readiness condition — the
# API socket serving GET /health — and fail fast if the service exits.
DH_SOCK=/run/docker-helper/docker-helper.sock
DH_READY=0
for _ in $(seq 1 100); do
	if [ -S "$DH_SOCK" ] && curl --silent --fail --max-time 1 \
		--unix-socket "$DH_SOCK" http://localhost/health >/dev/null 2>&1; then
		DH_READY=1
		break
	fi
	if ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
		fail "docker-helper.service exited/failed while waiting for the API socket"
	fi
	sleep 0.2
done
[ "$DH_READY" = "1" ] || fail "API socket did not become ready"
info "API socket ready"

WS="$ALLOWED_ROOT/p5aa-workspace"
rm -rf "$WS"
mkdir -p "$WS/rw" "$WS/ro" "$WS/buildctx"
printf 'ro-content\n' > "$WS/ro/readme.txt"
printf 'FROM alpine:3.24\nRUN apk add --no-cache curl ca-certificates && sleep 6\nUSER 65534:65534\n' > "$WS/buildctx/Dockerfile"
chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
chmod 0755 "$WS" "$WS/rw" "$WS/ro" "$WS/buildctx"

docker-helper principal create --no-credential "$PRINCIPAL" >/dev/null \
	|| fail "principal create failed"
docker-helper principal allowed-root add "$PRINCIPAL" "$ALLOWED_ROOT" \
	|| fail "principal allowed-root add failed"

CRED_FILE=/tmp/p5aa-cred
CRED_OUT="$(docker-helper credential create --name p5aa-default "$PRINCIPAL")" \
	|| fail "credential create failed"
CRED_TOKEN="$(printf '%s\n' "$CRED_OUT" | sed -n 's/^  Token: //p')"
[ -n "$CRED_TOKEN" ] || fail "could not parse credential token"
printf '%s\n' "$CRED_TOKEN" > "$CRED_FILE"
chmod 600 "$CRED_FILE"

SESSION_JSON="$(docker-helper session create --token-file "$CRED_FILE" "$WS" --json)" \
	|| fail "session create failed"
SESSION_ID="$(printf '%s\n' "$SESSION_JSON" | grep -oP '"id": "\K[^"]+' | head -1)"
SESSION_TOKEN="$(printf '%s\n' "$SESSION_JSON" | grep -oP '"token": "\K[^"]+' | head -1)"
if [ -z "$SESSION_ID" ] || [ -z "$SESSION_TOKEN" ]; then
	fail "session create returned no id/token"
fi
export DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN"
info "session created: $SESSION_ID"

# --- P4: docker run through the helper ---------------------------------------

say "=== P4: docker run through the helper ==="

PUID="$(id -u "$PRINCIPAL")"
docker-helper pull alpine:3.24 || fail "docker-helper pull failed"
RUN_OUT="$(docker-helper run --workdir /tmp alpine:3.24 -- sh -ec "test \"\$(id -u)\" = \"$PUID\" && echo P5AA-RUN-OK")" \
	|| { dump_diagnostics "docker-helper run failed: $RUN_OUT"; fail "docker-helper run failed: $RUN_OUT"; }
printf '%s\n' "$RUN_OUT" | grep -q 'P5AA-RUN-OK' || fail "run identity check failed: $RUN_OUT"
MOUNT_OUT="$(docker-helper run --mount rw:/mnt/rw alpine:3.24 -- sh -ec 'echo mounted > /mnt/rw/p5aa.txt && echo P5AA-MOUNT-OK')" \
	|| fail "mount run failed: $MOUNT_OUT"
printf '%s\n' "$MOUNT_OUT" | grep -q 'P5AA-MOUNT-OK' || fail "mount check failed: $MOUNT_OUT"
[ -f "$WS/rw/p5aa.txt" ] || fail "RW mount did not persist to the host workspace"
info "run + workspace mount ok (managed boundary and workload profile exercised below)"

# --- P5: docker build through per-operation BuildKit -------------------------

say "=== P5: docker build through per-operation BuildKit ==="

BUILD_LOG="$EVIDENCE_DIR/build-output.txt"
( cd "$ALLOWED_ROOT" && docker-helper build buildctx --dockerfile Dockerfile --image p5aa-curl:alpine3.24 ) > "$BUILD_LOG" 2>&1 &
BUILD_PID=$!

# While the build runs: the per-operation roots (SAME-OP PAIRED: the op id
# comes from the runtime dir basename and the state dir MUST carry the same
# id — independent first-dir discovery could pair runtime from one
# operation with state from another under stale or concurrent residue),
# the bundled buildkitd process, and the OTEL socket redirect.
OPS_RT=""
OPS_ST=""
OP_ID=""
BUILDKITD_PID=""
OTEL_SOCK=""
OPS_SEEN=0
for _ in $(seq 1 240); do
	kill -0 "$BUILD_PID" 2>/dev/null || break
	for d in "$BUILDER_RT_ROOT"/ops/*/; do
		[ -d "$d" ] || continue
		OP_ID="$(basename "${d%/}")"
		OPS_RT="${d%/}"
		OPS_ST="$BUILDER_ST_ROOT/ops/$OP_ID"
		if [ -d "$OPS_ST" ]; then
			OPS_SEEN=1
			break
		fi
		OPS_RT=""
		OPS_ST=""
		OP_ID=""
	done
	[ -n "$OPS_RT" ] && [ -n "$OPS_ST" ] && break
	sleep 0.25
done
if [ -n "$OPS_RT" ] && [ -n "$OPS_ST" ]; then
	: # in-build assertions below
else
	# The per-op trees are created and removed inside the START round-trip
	# when a launch fails (the failed-start convergence owns the removal),
	# so a failed START leaves no stable residue. The journals and the
	# denial inventory are the evidence.
	dump_diagnostics "no stable per-operation dirs appeared (ops_seen=$OPS_SEEN); build log follows"
	printf '%s\n' "$(cat "$BUILD_LOG" 2>/dev/null || true)" >&2
	fail "no per-operation runtime/state dirs observed under the builder roots during the build"
fi
info "per-op runtime dir: $OPS_RT"
info "per-op state dir: $OPS_ST"
# Same-op identity: the paired dirs must be one operation's runtime/state
# pair under the canonical op_<32hex> grammar.
[[ "$OP_ID" =~ ^op_[0-9a-f]{32}$ ]] \
	|| fail "operation id '$OP_ID' is not the canonical op_<32hex> form"
if [ "$(basename "$OPS_RT")" != "$OP_ID" ] || [ "$(basename "$OPS_ST")" != "$OP_ID" ]; then
	fail "runtime/state pairing broken: runtime=$(basename "$OPS_RT") state=$(basename "$OPS_ST") op=$OP_ID"
fi
info "same-op pairing: $OP_ID (runtime + state)"

BUILDKITD_PID="$(pgrep -f "exec $PAYLOAD_DIR/buildkitd" | head -1 || true)"
[ -n "$BUILDKITD_PID" ] || BUILDKITD_PID="$(pgrep -f "$PAYLOAD_DIR/buildkitd" | head -1 || true)"
[ -n "$BUILDKITD_PID" ] || fail "no bundled buildkitd process ran during the build (expected $PAYLOAD_DIR/buildkitd)"
# Exact per-operation endpoint proof: the cmdline must be THIS operation's
# buildkitd — root/addr/otel-socket all name the same op's paths — and must
# never reference the global buildkit state paths the isolation model
# forbids.
BK_CMDLINE="$(tr '\0' '\n' < "/proc/$BUILDKITD_PID/cmdline" 2>/dev/null || true)"
for want in \
	"$PAYLOAD_DIR/buildkitd" \
	"--rootless" \
	"--root=$OPS_ST/root" \
	"--addr=unix://$OPS_RT/buildkitd.sock" \
	"--otel-socket-path=$OPS_RT/buildkit/otel-grpc.sock"; do
	printf '%s\n' "$BK_CMDLINE" | grep -qxF -- "$want" \
		|| fail "bundled buildkitd cmdline (op $OP_ID) missing $want"
done
for banned in /run/buildkit /var/lib/buildkit; do
	if printf '%s\n' "$BK_CMDLINE" | grep -qF -- "$banned"; then
		fail "bundled buildkitd cmdline (op $OP_ID) references the global $banned path"
	fi
done
evidence "buildkitd-cmdline.txt" "$BK_CMDLINE"
info "bundled buildkitd ran: pid=$BUILDKITD_PID (cmdline matches op $OP_ID)"

# The CONFINED model's transition proof: the launch vehicle must run
# under the DISTRO rootlesskit profile (the single owner of the userns
# permission). `px` has an unconfined fallback on hosts without the
# distro profile, so a functional build alone cannot prove the
# transition — the process label is the proof. On the AppArmor parity
# target (Ubuntu: the distro apparmor package ships
# /etc/apparmor.d/rootlesskit) the leader label is
# "rootlesskit (unconfined)": the distro profile is declared
# flags=(unconfined), i.e. a NAMED attachment point that owns the
# userns permission and applies no file mediation, so AppArmor reports
# its mode as (unconfined). The transition proof is the profile name:
# without the distro profile the px fallback keeps the caller's label
# (docker-helper-builder), never a rootlesskit label. The distro
# profile is not touched by the harvest window (only the two helper
# profiles are reloaded in complain mode), so the assertion holds in
# both passes.
RK_PID=""
for rpid in $(pgrep -x rootlesskit); do
	if tr '\0' ' ' < "/proc/$rpid/cmdline" 2>/dev/null \
		| grep -qF -- "--state-dir=$OPS_ST/rootlesskit-state"; then
		RK_PID="$rpid"
		break
	fi
done
[ -n "$RK_PID" ] || { dump_diagnostics "no rootlesskit leader found for the operation"; fail "no rootlesskit leader found for the operation (state-dir $OPS_ST/rootlesskit-state)"; }
RK_LABEL="$(cat "/proc/$RK_PID/attr/current" 2>/dev/null || true)"
[ "$RK_LABEL" = "rootlesskit (unconfined)" ] \
	|| fail "rootlesskit leader profile = '$RK_LABEL', want 'rootlesskit (unconfined)' (the distro rootlesskit profile must own the launch vehicle for AppArmor parity)"
# The buildkitd child's label is RECORDED, never asserted as confinement:
# the child inherits the same distro rootlesskit profile (observed
# "rootlesskit (unconfined)" — the profile is deliberately unmediated), and
# the AppArmor backend makes no deeper child-confinement claim. The
# transition proof above is the leader's profile name.
RK_CHILD_LABEL="$(cat "/proc/$BUILDKITD_PID/attr/current" 2>/dev/null || true)"
info "rootlesskit leader: pid=$RK_PID profile=$RK_LABEL"
info "buildkitd child profile (recorded): $RK_CHILD_LABEL"
evidence "flow-profile-labels.txt" "rootlesskit leader pid=$RK_PID attr/current=$RK_LABEL
buildkitd child pid=$BUILDKITD_PID attr/current=$RK_CHILD_LABEL"

wait_for 10 test -S "$OPS_RT/buildkit/otel-grpc.sock" \
	|| fail "OTEL socket redirect missing: $OPS_RT/buildkit/otel-grpc.sock"
OTEL_SOCK="$OPS_RT/buildkit/otel-grpc.sock"
info "OTEL socket redirect present: $OTEL_SOCK"

# The OCI worker path proof tiers:
#   1. the successful RUN step proves the OCI worker path (a RUN step
#      cannot execute without the worker's runc);
#   2. the EXACT bundled buildkit-runc exec observation is best-effort:
#      the exec window is short and the pgrep poll can miss it
#      (observed=1 caught, observed=0 missed). No audit record exists
#      for a successful exec, and the candidate bytes are never wrapped,
#      so tier 2 is evidence-strengthening only, never the claim.
RUNC_SEEN=0
for _ in $(seq 1 40); do
	kill -0 "$BUILD_PID" 2>/dev/null || break
	if pgrep -f "$PAYLOAD_DIR/buildkit-runc" >/dev/null 2>&1; then
		RUNC_SEEN=1
		break
	fi
	sleep 0.25
done
info "OCI worker path: exercised by the successful RUN step"
info "exact bundled buildkit-runc exec observation: best-effort (observed=$RUNC_SEEN; 1 = exec window caught, 0 = window missed)"
evidence "buildkit-runc-observed.txt" "$RUNC_SEEN"

if ! wait "$BUILD_PID"; then
	dump_diagnostics "docker-helper build failed; build log follows"
	printf '%s\n' "$(cat "$BUILD_LOG" 2>/dev/null || true)" >&2
	fail "docker-helper build failed (log: $BUILD_LOG)"
fi
evidence "build-output.txt" "$(cat "$BUILD_LOG")"

RUN2_OUT="$(docker-helper run p5aa-curl:alpine3.24 -- sh -ec 'test -x /usr/bin/curl && echo P5AA-BUILD-IMAGE-OK')" \
	|| fail "built image not usable: $RUN2_OUT"
printf '%s\n' "$RUN2_OUT" | grep -q 'P5AA-BUILD-IMAGE-OK' \
	|| fail "built image check failed: $RUN2_OUT"

[ ! -e /run/buildkit ] || fail "global /run/buildkit path exists (the OTEL redirect and per-op roots own all buildkit state)"
[ ! -e /var/lib/buildkit ] || fail "global /var/lib/buildkit path exists"
info "build through per-operation BuildKit ok; no global daemon/cache path"

# --- P6: managed boundaries reload -------------------------------------------

say "=== P6: managed-boundaries fragment ==="

[ -f "$AA_STATE_FILE" ] || fail "managed-boundaries state missing at $AA_STATE_FILE"
FRAGMENT="$(cat "$AA_STATE_FILE")"
evidence "managed-boundaries.txt" "$FRAGMENT"
printf '%s\n' "$FRAGMENT" | grep -F "$WS" >/dev/null \
	|| fail "managed-boundaries fragment does not carry the session workspace $WS"
# Root-json boundary form for the ACTUAL allowed root: the UAT fixes the
# workspace under $ALLOWED_ROOT by construction, so the form check follows
# the variable instead of a hard-coded /home prefix.
printf '%s\n' "$FRAGMENT" | grep -F "\"$ALLOWED_ROOT" >/dev/null \
	|| fail "managed-boundaries fragment does not carry the root-json boundary form for $ALLOWED_ROOT"
info "managed-boundaries fragment carries the issued workspace boundary (root-json form for $ALLOWED_ROOT)"

# --- P7: generated workload profile ------------------------------------------

say "=== P7: generated workload profile prepare + cleanup ==="

# The generated workload profile is a per-operation transient: the daemon
# loads it for the operation's containers and unloads it at the operation's
# terminal cleanup (2.2 workload-MAC lifecycle). Prove both halves against
# one long-running operation: the profile appears while the container runs
# and is gone after the operation finishes.
( docker-helper run alpine:3.24 -- sleep 8 ) > "$EVIDENCE_DIR/p7-run-output.txt" 2>&1 &
P7_PID=$!
WL_PROFILE=""
for _ in $(seq 1 120); do
	kill -0 "$P7_PID" 2>/dev/null || break
	WL_PROFILE="$(grep -o 'docker-helper-workload-[A-Za-z0-9_-]*' /sys/kernel/security/apparmor/profiles 2>/dev/null | sort -u | head -1 || true)"
	[ -n "$WL_PROFILE" ] && break
	sleep 0.25
done
[ -n "$WL_PROFILE" ] || { dump_diagnostics "no generated workload profile appeared while the run was in flight"; fail "no generated workload profile found in the AppArmor profile inventory while a run was in flight"; }
info "generated workload profile loaded during the run: $WL_PROFILE"
evidence "workload-profile.txt" "$WL_PROFILE"

wait "$P7_PID" || fail "the P7 run failed (see p7-run-output.txt)"
wait_for 30 bash -c "! grep -q 'docker-helper-workload-' /sys/kernel/security/apparmor/profiles 2>/dev/null" \
	|| fail "generated workload profile $WL_PROFILE still loaded after the run finished (cleanup broken)"
info "generated workload profile unloaded after the run finished"

docker-helper session delete "$SESSION_ID" >/dev/null 2>&1 \
	|| fail "session delete failed"

# --- P8: AppArmor denial audit -----------------------------------------------

say "=== P8: AppArmor denial audit (fresh window) ==="

SYSTEM_DENIALS="$(collect_denials_profile docker-helper-system)"
BUILDER_DENIALS="$(collect_denials_profile docker-helper-builder)"
FLOW_DENIALS="$(audit_records 'apparmor="DENIED"' | grep -F 'profile="rootlesskit"' || true)"
evidence "denials-system.txt" "$SYSTEM_DENIALS"
evidence "denials-builder.txt" "$BUILDER_DENIALS"
evidence "denials-flow.txt" "$FLOW_DENIALS"

if [ "$HARVEST" = "1" ]; then
	say "HARVEST inventory (log-and-permit; evidence for profile iterations):"
	say "-- docker-helper-system DENIED records: $(printf '%s' "$SYSTEM_DENIALS" | grep -c . || true)"
	printf '%s\n' "$SYSTEM_DENIALS" || true
	say "-- docker-helper-builder DENIED records: $(printf '%s' "$BUILDER_DENIALS" | grep -c . || true)"
	printf '%s\n' "$BUILDER_DENIALS" || true
	say "-- rootlesskit (flow) DENIED records: $(printf '%s' "$FLOW_DENIALS" | grep -c . || true)"
	printf '%s\n' "$FLOW_DENIALS" || true
else
	UNEXPECTED_SYSTEM=""
	ALLOWLISTED=0
	declare -A SHAPE_COUNT
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		if is_allowlisted_deny "$line"; then
			ALLOWLISTED=$((ALLOWLISTED + 1))
			shape_key="$(allowlist_shape_key "$line")"
			SHAPE_COUNT["$shape_key"]=$(( ${SHAPE_COUNT["$shape_key"]:-0} + 1 ))
			info "allowlisted benign deny: $line"
		else
			UNEXPECTED_SYSTEM+="$line"$'\n'
		fi
	done <<< "$SYSTEM_DENIALS"
	# Shape drift control: every allowlisted record must normalize to a
	# known benign probe shape and no shape may exceed its pinned maximum.
	SHAPE_DRIFT=""
	for shape_key in "${!SHAPE_COUNT[@]}"; do
		shape_max="$(allowlist_shape_max "$shape_key" || true)"
		if [ -z "$shape_max" ]; then
			SHAPE_DRIFT+="unknown allowlisted shape: $shape_key"$'\n'
		elif [ "${SHAPE_COUNT[$shape_key]}" -gt "$shape_max" ]; then
			SHAPE_DRIFT+="allowlisted shape above its pinned maximum ($shape_key: ${SHAPE_COUNT[$shape_key]} > $shape_max)"$'\n'
		fi
	done
	if [ -n "$SHAPE_DRIFT" ]; then
		printf '\n[P5AA] allowlist shape drift:\n%s\n' "$SHAPE_DRIFT" >&2
		fail "allowlisted AppArmor denial shapes drifted from the known benign set"
	fi
	if [ -n "$UNEXPECTED_SYSTEM" ]; then
		printf '\n[P5AA] UNEXPECTED docker-helper-system DENIED records:\n%s\n' "$UNEXPECTED_SYSTEM" >&2
		fail "unexpected AppArmor denials under docker-helper-system"
	fi
	if [ -n "$BUILDER_DENIALS" ]; then
		printf '\n[P5AA] docker-helper-builder DENIED records (the builder profile must run clean in enforce mode):\n%s\n' "$BUILDER_DENIALS" >&2
		fail "unexpected AppArmor denials under docker-helper-builder"
	fi
	if [ -n "$FLOW_DENIALS" ]; then
		printf '\n[P5AA] rootlesskit-profile DENIED records:\n%s\n' "$FLOW_DENIALS" >&2
		fail "unexpected AppArmor denials under the flow profile"
	fi
	info "audit check passed (system allowlisted=$ALLOWLISTED, builder=0, flow=0)"
fi

# --- P9: uninstall -----------------------------------------------------------

say "=== P9: uninstall removes/unloads helper-owned profiles ==="

UNINSTALL_BUNDLE="$(basename "$BUNDLE")"
UNINSTALL_OUT="$(/tmp/p5aa-work/"$UNINSTALL_BUNDLE"/uninstall-system.sh --yes --purge 2>&1)" \
	|| fail "uninstall-system.sh failed:
$UNINSTALL_OUT"
evidence "uninstall-output.txt" "$UNINSTALL_OUT"
[ ! -e "$AA_SYSTEM_DEST" ] || fail "system profile file still present after uninstall"
[ ! -e "$AA_BUILDER_DEST" ] || fail "builder profile file still present after uninstall"
! profile_loaded docker-helper-system || fail "docker-helper-system still loaded after uninstall"
! profile_loaded docker-helper-builder || fail "docker-helper-builder still loaded after uninstall"
RESIDUAL_WORKLOAD="$(grep -c 'docker-helper-workload-' /sys/kernel/security/apparmor/profiles 2>/dev/null || true)"
[ "$RESIDUAL_WORKLOAD" = "0" ] || fail "$RESIDUAL_WORKLOAD helper-owned generated workload profiles still loaded after uninstall"
info "uninstall removed/unloaded both shipped profiles; no helper-owned generated profiles remain"

say "P5 AppArmor parity UAT PASSED (mode: $([ "$HARVEST" = "1" ] && printf harvest || printf enforcing))"
