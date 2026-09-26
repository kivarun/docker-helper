#!/usr/bin/env bash
# install-system.sh — system (root) installation of docker-helper.
#
# Installs the binary to /usr/bin/docker-helper, the systemd system unit, and
# initializes the daemon. The installer is MAC-backend neutral: it selects the
# single supported active backend from kernel state and configures either
# AppArmor (profile install/load + managed-boundary state) or enforcing SELinux
# (docker_helper module load + narrow restorecon). A host with neither active
# backend, or with both active, is rejected before any mutation.
#
# Usage:
#   sudo ./install-system.sh
#   sudo ./install-system.sh --yes --allowed-root /path
#
# Flags:
#   --yes            Non-interactive: accept all defaults, init, enable+start.
#                    On a reinstall this restores exactly the services that
#                    were active before the install (both services are
#                    stopped first — they exec the same binary — and a
#                    previously-inactive main service is left stopped).
#   --allowed-root P Required with --yes when /etc/docker-helper/config.json
#                    is absent. Sets the initial allowed_root for init.
#
# Requires: bash 4+, root (effective UID 0), Docker, and the runtime tooling
# for the single active MAC backend (AppArmor parser, or semodule+restorecon
# and bindfs — the SELinux read-only workload projection dependency).

set -euo pipefail

# --- Constants (overridable for testing) ---
BINARY_NAME="${BINARY_NAME:-docker-helper}"
BINARY_DEST="${BINARY_DEST:-/usr/bin/docker-helper}"
UNIT_SRC="${UNIT_SRC:-systemd/system/docker-helper.service}"
UNIT_DEST="${UNIT_DEST:-/etc/systemd/system/docker-helper.service}"
UNIT_NAME="${UNIT_NAME:-docker-helper.service}"
BUILDER_UNIT_SRC="${BUILDER_UNIT_SRC:-systemd/system/docker-helper-builder.service}"
BUILDER_UNIT_DEST="${BUILDER_UNIT_DEST:-/etc/systemd/system/docker-helper-builder.service}"
BUILDER_UNIT_NAME="${BUILDER_UNIT_NAME:-docker-helper-builder.service}"
# ONE builder provisioning owner (packaging/scripts/lib/provision-builder.sh,
# shipped in the bundle as scripts/provision-builder.sh): executed, never
# re-implemented.
PROVISION_BUILDER_SRC="${PROVISION_BUILDER_SRC:-scripts/provision-builder.sh}"
BUILDKIT_BIN_SRC="${BUILDKIT_BIN_SRC:-buildkit}"
BUILDKIT_BIN_DEST="${BUILDKIT_BIN_DEST:-/usr/libexec/docker-helper/buildkit}"
BUILDKIT_DOC_DEST="${BUILDKIT_DOC_DEST:-/usr/share/doc/docker-helper/buildkit}"
AA_PROFILE_SRC="${AA_PROFILE_SRC:-apparmor/docker-helper-system}"
AA_PROFILE_DEST="${AA_PROFILE_DEST:-/etc/apparmor.d/docker-helper-system}"
AA_STATE_FILE="${AA_STATE_FILE:-/var/lib/docker-helper/apparmor/managed-boundaries}"
AA_LEGACY_FRAGMENT="${AA_LEGACY_FRAGMENT:-/etc/apparmor.d/docker-helper.d/managed-roots}"
AA_PARSER="${AA_PARSER:-/usr/sbin/apparmor_parser}"
SELINUX_PP_SRC="${SELINUX_PP_SRC:-selinux/docker_helper.pp}"
SELINUX_PP_DEST="${SELINUX_PP_DEST:-/usr/share/selinux/docker_helper.pp}"
SEMODULE="${SEMODULE:-semodule}"
RESTORECON="${RESTORECON:-restorecon}"
BINDFS="${BINDFS:-bindfs}"
# Descriptor-safe recursive relabel floor. The libselinux 3.11
# selinux_restorecon rewrite labels inodes through /proc/self/fd paths so a
# pathname replacement racing the tree walk cannot redirect a relabel to a
# foreign inode; older implementations relabel by pathname and stay racy.
# The supported openSUSE SELinux path proves the installed implementation
# through the rpm package database (libselinux1); no other provider grammar
# is invented, and anything older, non-libselinux, or unparseable fails
# closed before any SELinux installation mutation.
LIBSELINUX_MIN="3.11"
# Kernel truth for MAC backend selection (the same sources the RPM postinstall
# and the MAC UAT adapters use).
AA_ENABLED_PATH="${AA_ENABLED_PATH:-/sys/module/apparmor/parameters/enabled}"
SELINUX_ENFORCE_PATH="${SELINUX_ENFORCE_PATH:-/sys/fs/selinux/enforce}"
CONFIG_PATH="${CONFIG_PATH:-/etc/docker-helper/config.json}"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
DOCKER="${DOCKER:-docker}"

# --- State ---
interactive=true
allowed_root=""
script_dir=""
service_was_active=false
builder_service_was_active=false
was_installed=false

# --- Helpers ---

info() {
	printf '%s\n' "$*"
}

warn() {
	printf 'warning: %s\n' "$*" >&2
}

error() {
	printf 'error: %s\n' "$*" >&2
}

ask() {
	local prompt="$1"
	local answer

	if $interactive; then
		printf '%s [Y/n]: ' "$prompt"
		read -r answer
		if [[ -z "$answer" ]]; then
			answer="y"
		fi
		[[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]
	else
		true
	fi
}

# --- Argument parsing ---

parse_args() {
	script_dir="$(cd "$(dirname "$0")" && pwd)"

	while (($#)); do
		case "$1" in
			--yes)
				interactive=false
				shift
				;;
			--allowed-root)
				if [[ $# -lt 2 ]] || [[ "$2" == --* ]]; then
					error "--allowed-root requires a path argument"
					exit 1
				fi
				allowed_root="$2"
				shift 2
				;;
			*)
				error "unknown option: $1"
				exit 1
				;;
		esac
	done
}

# --- Preflight checks ---

check_root() {
	if [[ "$(id -u)" -ne 0 ]]; then
		error "this script must be run as root (effective UID 0)"
		exit 1
	fi
}

check_bundled_assets() {
	local binary_path="$script_dir/$BINARY_NAME"
	if [[ ! -f "$binary_path" ]]; then
		error "$BINARY_NAME binary not found in $script_dir"
		exit 1
	fi

	local unit_path="$script_dir/$UNIT_SRC"
	if [[ ! -f "$unit_path" ]]; then
		error "systemd unit not found at $unit_path"
		exit 1
	fi

	# Release 2.4 builder backend bundle members: the builder unit, the
	# pinned BuildKit payload, and the provisioning script. A tarball that
	# lost any of them fails the preflight BEFORE any system mutation.
	local builder_unit_path="$script_dir/$BUILDER_UNIT_SRC"
	if [[ ! -f "$builder_unit_path" ]]; then
		error "builder systemd unit not found at $builder_unit_path"
		exit 1
	fi
	local provisioner_path="$script_dir/$PROVISION_BUILDER_SRC"
	if [[ ! -f "$provisioner_path" ]]; then
		error "builder provisioning script not found at $provisioner_path"
		exit 1
	fi
	local payload_member
	for payload_member in buildkitd buildctl buildkit-runc LICENSE MANIFEST; do
		if [[ ! -s "$script_dir/$BUILDKIT_BIN_SRC/$payload_member" ]]; then
			error "pinned BuildKit payload member missing or empty: $BUILDKIT_BIN_SRC/$payload_member"
			exit 1
		fi
	done
}

check_systemctl() {
	if ! command -v "$SYSTEMCTL" >/dev/null 2>&1; then
		error "systemctl not found in PATH"
		exit 1
	fi
}

check_apparmor_parser() {
	if [[ ! -x "$AA_PARSER" ]]; then
		error "AppArmor parser not found or not executable at $AA_PARSER"
		error "AppArmor parser is required for system mode installation on an AppArmor host."
		exit 1
	fi
}

# select_mac_backend is the single owner of MAC backend selection for system
# mode. It reads the same kernel truth used by the RPM postinstall and the MAC
# UAT adapters:
#   AppArmor active:  /sys/module/apparmor/parameters/enabled == Y
#   SELinux enforcing: /sys/fs/selinux/enforce == 1
# Exactly one supported backend must be active: AppArmor-only, or
# SELinux-enforcing-only. A host with neither active, or with both active, is
# rejected BEFORE any installation mutation (system mode must not install
# unconfined, and the dual-active configuration is unsupported). On success it
# sets the global selected_mac to "apparmor" or "selinux".
select_mac_backend() {
	local aa selinux
	aa="$(cat "$AA_ENABLED_PATH" 2>/dev/null || true)"
	aa="$(echo "$aa" | tr -d '[:space:]')"
	selinux="$(cat "$SELINUX_ENFORCE_PATH" 2>/dev/null || true)"
	selinux="$(echo "$selinux" | tr -d '[:space:]')"

	local aa_active=false
	local selinux_active=false
	[[ "$aa" == "Y" ]] && aa_active=true
	[[ "$selinux" == "1" ]] && selinux_active=true

	if $aa_active && $selinux_active; then
		error "both AppArmor and enforcing SELinux are active on this host"
		error "docker-helper system mode supports exactly one active MAC backend; dual-active is unsupported."
		exit 1
	fi
	if ! $aa_active && ! $selinux_active; then
		error "no supported MAC backend is active (AppArmor not active and SELinux not enforcing)"
		error "docker-helper system mode must not install unconfined."
		exit 1
	fi

	if $aa_active; then
		selected_mac="apparmor"
		info "MAC backend: AppArmor (active)"
	else
		selected_mac="selinux"
		info "MAC backend: SELinux (enforcing)"
	fi
}

# version_at_least A B compares two dot-separated numeric version strings
# (three components). Returns 0 when A >= B, 1 when A < B, and 2 when either
# string carries a non-numeric component (the caller refuses unparseable
# versions; it never guesses).
version_at_least() {
	local a="$1" b="$2" i ai bi
	local -a A B
	IFS=. read -r -a A <<<"$a"
	IFS=. read -r -a B <<<"$b"
	for i in 0 1 2; do
		ai="${A[i]:-0}"
		bi="${B[i]:-0}"
		case "$ai" in ''|*[!0-9]*) return 2 ;; esac
		case "$bi" in ''|*[!0-9]*) return 2 ;; esac
		if ((10#$ai > 10#$bi)); then return 0; fi
		if ((10#$ai < 10#$bi)); then return 1; fi
	done
	return 0
}

# check_libselinux_floor establishes that the installed libselinux restorecon
# implementation is the descriptor-safe floor (libselinux1 >= $LIBSELINUX_MIN)
# BEFORE any SELinux installation mutation. The supported openSUSE SELinux
# path proves it through the rpm package database: the restorecon frontend
# must link libselinux.so.1, the resolved library file must be owned by the
# libselinux1 package, and that package's version must satisfy the floor.
# A missing rpm database, a missing linkage, a foreign owning package, an
# older version, or an unparseable version all fail closed with an
# actionable diagnostic. Nothing here is a generic-distro version heuristic.
check_libselinux_floor() {
	if ! command -v ldd >/dev/null 2>&1; then
		error "ldd not found in PATH"
		error "cannot establish the installed libselinux implementation; docker-helper SELinux system mode requires libselinux1 >= $LIBSELINUX_MIN."
		exit 1
	fi
	if ! command -v rpm >/dev/null 2>&1; then
		error "rpm not found in PATH"
		error "cannot establish the installed libselinux implementation from the package database; docker-helper SELinux system mode requires libselinux1 >= $LIBSELINUX_MIN (install it, or use the docker-helper RPM, which requires the floor directly)."
		exit 1
	fi
	local restorecon_bin lib owner name version
	restorecon_bin="$(command -v "$RESTORECON")" || {
		error "cannot resolve the restorecon frontend in PATH"
		exit 1
	}
	lib="$(ldd "$restorecon_bin" 2>/dev/null | awk '$1 == "libselinux.so.1" {print $3; exit}' || true)"
	if [[ -z "$lib" ]]; then
		error "$restorecon_bin does not link libselinux.so.1"
		error "cannot establish the installed libselinux implementation; docker-helper SELinux system mode requires libselinux1 >= $LIBSELINUX_MIN."
		exit 1
	fi
	if ! lib="$(readlink -f "$lib" 2>/dev/null)" || [[ -z "$lib" ]]; then
		error "cannot resolve the libselinux library path reported by ldd"
		error "cannot establish the installed libselinux implementation; docker-helper SELinux system mode requires libselinux1 >= $LIBSELINUX_MIN."
		exit 1
	fi
	owner="$(rpm -qf --qf '%{NAME} %{VERSION}\n' "$lib" 2>/dev/null)" || {
		error "$lib is not owned by any installed rpm package"
		error "cannot establish the installed libselinux implementation; docker-helper SELinux system mode requires libselinux1 >= $LIBSELINUX_MIN (install it, or use the docker-helper RPM, which requires the floor directly)."
		exit 1
	}
	name="${owner%% *}"
	version="${owner#* }"
	if [[ "$name" != "libselinux1" ]]; then
		error "$lib is owned by package '$name', not libselinux1"
		error "cannot establish the descriptor-safe libselinux implementation; docker-helper SELinux system mode requires libselinux1 >= $LIBSELINUX_MIN."
		exit 1
	fi
	cmp_rc=0
	version_at_least "$version" "$LIBSELINUX_MIN" || cmp_rc=$?
	case "$cmp_rc" in
		0)
			info "libselinux implementation: libselinux1-$version (descriptor-safe floor $LIBSELINUX_MIN satisfied)"
			;;
		1)
			error "installed libselinux1-$version is older than the descriptor-safe floor $LIBSELINUX_MIN (the pathname-replacement relabel race is closed only in libselinux >= 3.11)"
			error "install libselinux1 >= $LIBSELINUX_MIN first, or use the docker-helper RPM, which requires the floor directly."
			exit 1
			;;
		*)
			error "cannot parse installed libselinux1 version '$version'"
			error "refusing to proceed on a SELinux host without a provable descriptor-safe libselinux implementation (requires libselinux1 >= $LIBSELINUX_MIN)."
			exit 1
			;;
	esac
}

# check_selected_mac_tools validates the runtime tooling and the bundled MAC
# artifact for the selected backend. It runs BEFORE any installation mutation,
# so a missing required tool or a missing bundled artifact never leaves a
# partially-installed system. Tooling of the inactive backend is never required.
check_selected_mac_tools() {
	if [[ "$selected_mac" == "apparmor" ]]; then
		check_apparmor_parser
		if [[ ! -f "$script_dir/$AA_PROFILE_SRC" ]]; then
			error "AppArmor profile not found at $script_dir/$AA_PROFILE_SRC"
			exit 1
		fi
	else
		if ! command -v "$SEMODULE" >/dev/null 2>&1; then
			error "semodule not found in PATH"
			error "SELinux runtime tooling (semodule) is required for system mode on a SELinux host."
			exit 1
		fi
		if ! command -v "$RESTORECON" >/dev/null 2>&1; then
			error "restorecon not found in PATH"
			error "SELinux runtime tooling (restorecon) is required for system mode on a SELinux host."
			exit 1
		fi
		# Prove the installed libselinux implementation is the
		# descriptor-safe floor before any SELinux installation mutation.
		check_libselinux_floor
		if ! command -v "$BINDFS" >/dev/null 2>&1; then
			error "bindfs not found in PATH"
			error "bindfs is required for SELinux read-only workload projection; install the bindfs package first."
			exit 1
		fi
		if [[ ! -f "$script_dir/$SELINUX_PP_SRC" ]]; then
			error "bundled SELinux policy module not found at $script_dir/$SELINUX_PP_SRC"
			error "the release tarball must carry selinux/docker_helper.pp."
			exit 1
		fi
	fi
}

check_docker() {
	info ""
	info "WARNING: docker-helper requires access to the Docker daemon."
	info "Access via a rootful Docker daemon effectively grants root-equivalent"
	info "privileges on the host. Ensure you trust this access."
	info ""

	if ! "$DOCKER" info >/dev/null 2>&1; then
		error "cannot access Docker daemon (docker info failed)"
		exit 1
	fi
}

check_allowed_root() {
	# If --yes and config doesn't exist, --allowed-root is mandatory.
	if ! $interactive && [[ ! -f "$CONFIG_PATH" ]]; then
		if [[ -z "$allowed_root" ]]; then
			error "--yes with fresh install requires --allowed-root PATH"
			exit 1
		fi
	fi
}

# --- Service check ---

# detect_existing_install records whether a previous installation exists
# (the binary or the main unit file is present). It only gates the
# post-install start behavior: a reinstall restores the previously-active
# services and never starts a previously-inactive main service, while a
# fresh install keeps the existing enable+start setup contract.
detect_existing_install() {
	if [[ -e "$BINARY_DEST" || -e "$UNIT_DEST" ]]; then
		was_installed=true
	fi
}

# check_active_service is the preflight owner of the service-activity
# contract. It records the initial activity of BOTH services (the main
# daemon and the builder backend) before anything is stopped, keeps the
# single interactive confirmation, then stops the active services and
# CONFIRMS both are down BEFORE any file mutation: both services exec the
# same /usr/bin/docker-helper binary, so a still-running service would make
# the binary replacement fail with "Text file busy". A failed stop aborts
# the installation before provisioning or any destination file is touched.
check_active_service() {
	if "$SYSTEMCTL" is-active --quiet "$UNIT_NAME" 2>/dev/null; then
		service_was_active=true
	fi
	if "$SYSTEMCTL" is-active --quiet "$BUILDER_UNIT_NAME" 2>/dev/null; then
		builder_service_was_active=true
	fi

	if ! $service_was_active && ! $builder_service_was_active; then
		return
	fi

	local current_version=""
	local new_version=""

	if [[ -x "$BINARY_DEST" ]]; then
		current_version="$("$BINARY_DEST" version 2>/dev/null || true)"
	fi
	new_version="$("$script_dir/$BINARY_NAME" version 2>/dev/null || true)"

	info ""
	info "The docker-helper services are currently active:"
	if $service_was_active; then
		info "  $UNIT_NAME"
	fi
	if $builder_service_was_active; then
		info "  $BUILDER_UNIT_NAME"
	fi
	info ""

	if [[ -n "$current_version" && -n "$new_version" ]]; then
		if [[ "$current_version" == "$new_version" ]]; then
			info "This will reinstall the same version: $current_version"
		else
			info "Current version: $current_version"
			info "New version:     $new_version"
		fi
	else
		info "Unable to determine version(s). This may be an upgrade or reinstall."
	fi
	info ""

	if ! ask "Stop the services and continue installation"; then
		info "Aborting without changes."
		info ""
		info "To reinstall later, stop the services first:"
		info "  systemctl stop $UNIT_NAME $BUILDER_UNIT_NAME"
		info ""
		exit 0
	fi

	if $service_was_active; then
		info "Stopping $UNIT_NAME"
		if ! "$SYSTEMCTL" stop "$UNIT_NAME" 2>/dev/null; then
			error "Failed to stop $UNIT_NAME"
			error "Aborting without changes. Stop the service manually and retry."
			exit 1
		fi
		if "$SYSTEMCTL" is-active --quiet "$UNIT_NAME" 2>/dev/null; then
			error "$UNIT_NAME is still active after the stop attempt"
			error "Aborting without changes. Stop the service manually and retry."
			exit 1
		fi
	fi
	if $builder_service_was_active; then
		info "Stopping $BUILDER_UNIT_NAME"
		if ! "$SYSTEMCTL" stop "$BUILDER_UNIT_NAME" 2>/dev/null; then
			error "Failed to stop $BUILDER_UNIT_NAME"
			error "Aborting without changes. Stop the service manually and retry."
			exit 1
		fi
		if "$SYSTEMCTL" is-active --quiet "$BUILDER_UNIT_NAME" 2>/dev/null; then
			error "$BUILDER_UNIT_NAME is still active after the stop attempt"
			error "Aborting without changes. Stop the service manually and retry."
			exit 1
		fi
	fi
}

# --- Installation steps ---

install_binary() {
	info "Installing $BINARY_NAME to $BINARY_DEST"
	cp "$script_dir/$BINARY_NAME" "$BINARY_DEST"
	chmod 0755 "$BINARY_DEST"
}

# provision_builder runs the ONE canonical provisioning owner (identity +
# subordinate-ID ranges, verify-first idempotent, fail-closed). It mutates
# the account state, so it runs as the first installation mutation, before
# any package-shaped file is placed; a provisioning failure aborts the
# installer before the service can be touched.
provision_builder() {
	info "Provisioning the builder identity (scripts/provision-builder.sh)"
	if ! sh "$script_dir/$PROVISION_BUILDER_SRC"; then
		error "builder identity provisioning failed; installation aborted"
		exit 1
	fi
}

install_builder_unit() {
	info "Installing builder systemd unit to $BUILDER_UNIT_DEST"
	cp "$script_dir/$BUILDER_UNIT_SRC" "$BUILDER_UNIT_DEST"
	chmod 0644 "$BUILDER_UNIT_DEST"
}

install_buildkit_payload() {
	local member
	for member in buildkitd buildctl buildkit-runc; do
		info "Installing pinned BuildKit payload member to $BUILDKIT_BIN_DEST/$member"
		install -d -m 0755 "$BUILDKIT_BIN_DEST"
		install -m 0755 "$script_dir/$BUILDKIT_BIN_SRC/$member" "$BUILDKIT_BIN_DEST/$member"
	done
	for member in LICENSE MANIFEST; do
		info "Installing BuildKit license/manifest to $BUILDKIT_DOC_DEST/$member"
		install -d -m 0755 "$BUILDKIT_DOC_DEST"
		install -m 0644 "$script_dir/$BUILDKIT_BIN_SRC/$member" "$BUILDKIT_DOC_DEST/$member"
	done
}

install_unit() {
	info "Installing systemd system unit to $UNIT_DEST"
	cp "$script_dir/$UNIT_SRC" "$UNIT_DEST"
	chmod 0644 "$UNIT_DEST"
}

install_apparmor_profile() {
	info "Installing AppArmor profile to $AA_PROFILE_DEST"
	cp "$script_dir/$AA_PROFILE_SRC" "$AA_PROFILE_DEST"
	chmod 0644 "$AA_PROFILE_DEST"
}

prepare_apparmor_state() {
	info "Preparing AppArmor managed boundaries state"
	local state_dir top_state_dir
	state_dir="$(dirname "$AA_STATE_FILE")"
	top_state_dir="$(dirname "$state_dir")"

	# Ensure the top-level state directory exists with the systemd
	# StateDirectory security contract (0700).
	mkdir -p "$top_state_dir"
	chmod 0700 "$top_state_dir"

	# Ensure the AppArmor state subdirectory exists.
	mkdir -p "$state_dir"
	chmod 0755 "$state_dir"

	# Migrate the legacy managed-roots fragment only when the new state does
	# not already exist, so an existing new state file is never overwritten.
	if [[ -f "$AA_LEGACY_FRAGMENT" ]] && [[ ! -f "$AA_STATE_FILE" ]]; then
		info "Migrating legacy AppArmor managed-roots fragment to $AA_STATE_FILE"
		local tmp_file
		tmp_file="$(mktemp "$state_dir/managed-boundaries-XXXXXX.tmp")"
		if ! cp "$AA_LEGACY_FRAGMENT" "$tmp_file" || ! chmod 0644 "$tmp_file" || ! mv -f "$tmp_file" "$AA_STATE_FILE"; then
			rm -f "$tmp_file"
			error "Failed to migrate legacy AppArmor managed-roots fragment"
			exit 1
		fi
	fi
}

cleanup_legacy_apparmor_state() {
	# Called only after the new profile has been loaded successfully, so the
	# migrated copy is the authoritative one before the legacy file is removed.
	if [[ -f "$AA_LEGACY_FRAGMENT" ]] && [[ -f "$AA_STATE_FILE" ]]; then
		rm -f "$AA_LEGACY_FRAGMENT"
		local legacy_dir
		legacy_dir="$(dirname "$AA_LEGACY_FRAGMENT")"
		if [[ -d "$legacy_dir" ]] && [[ -z "$(ls -A "$legacy_dir" 2>/dev/null)" ]]; then
			rmdir "$legacy_dir" 2>/dev/null || true
		fi
	fi
}

install_completion() {
	local completion_src="$script_dir/completions/docker-helper"
	local completion_dest="/usr/share/bash-completion/completions/docker-helper"
	if [[ ! -f "$completion_src" ]]; then
		return
	fi
	info "Installing Bash completion to $completion_dest"
	mkdir -p "$(dirname "$completion_dest")"
	cp "$completion_src" "$completion_dest"
	chmod 0644 "$completion_dest"
}

load_apparmor_profile() {
	info "Loading AppArmor profile $AA_PROFILE_DEST"
	if ! "$AA_PARSER" --replace --skip-read-cache "$AA_PROFILE_DEST"; then
		error "Failed to load AppArmor profile"
		error "Installation aborted. Service will not be started."
		exit 1
	fi
}

install_selinux_policy() {
	info "Loading SELinux policy module from $SELINUX_PP_SRC"
	if ! "$SEMODULE" -i "$script_dir/$SELINUX_PP_SRC"; then
		error "Failed to load SELinux policy module (semodule -i)"
		error "Installation aborted. Service will not be started."
		exit 1
	fi

	# Install the policy artifact to the stable path used by the RPM layout
	# so the uninstaller and the verification contract can find it.
	info "Installing SELinux policy artifact to $SELINUX_PP_DEST"
	mkdir -p "$(dirname "$SELINUX_PP_DEST")"
	if ! cp "$script_dir/$SELINUX_PP_SRC" "$SELINUX_PP_DEST" || ! chmod 0644 "$SELINUX_PP_DEST"; then
		error "Failed to install SELinux policy artifact to $SELINUX_PP_DEST"
		exit 1
	fi
}

apply_selinux_restorecon() {
	# Exact narrow restorecon behavior already proven by the RPM postinstall:
	# the binary, config and state trees, and ONLY the /run/docker-helper dir
	# itself (never recursively — recursive relabeling would walk the
	# bind-mount aliases in /run/docker-helper/mounts and relabel the real
	# workspace files to docker_helper_runtime_t). Best-effort, like the RPM
	# path: the loaded module + unit SELinuxContext provide confinement even if
	# a label cannot be applied. Docker daemon/socket labels are never touched.
	info "Applying SELinux file contexts"
	if ! "$RESTORECON" /usr/bin/docker-helper; then
		warn "restorecon /usr/bin/docker-helper failed (continuing; module + unit confinement apply)"
	fi
	# bindfs executable label for the workload read-only projection;
	# best-effort like the rest of the tree.
	"$RESTORECON" /usr/bin/bindfs 2>/dev/null || true
	# P5-S1 builder-owned trees (dedicated builder runtime/state types).
	# Recursive here is safe: these trees contain only builder-owned
	# objects (manager/op sockets, pid files, per-op BuildKit state) — no
	# workspace bind-mount aliases live under these stems. Fresh installs
	# have no builder dirs yet (restorecon no-ops); re-runs migrate dirs
	# labeled under an older module to the dedicated types.
	"$RESTORECON" /usr/bin/rootlesskit 2>/dev/null || true
	# slirp4netns: the launch vehicle's user-network helper; the dedicated
	# exec type is executable only from the rootlesskit child domain.
	"$RESTORECON" /usr/bin/slirp4netns 2>/dev/null || true
	# newuidmap: the launch vehicle's setuid-root UID-map helper; the
	# dedicated exec type is executable only from the rootlesskit child
	# domain.
	"$RESTORECON" /usr/bin/newuidmap 2>/dev/null || true
	# newgidmap: the launch vehicle's root-owned GID-map helper (the distro
	# chkstat-applied cap_setgid file capability is its privilege
	# mechanism); the dedicated exec type is executable only from the
	# rootlesskit child domain. Label-only: restorecon never alters owner,
	# mode, or xattrs.
	"$RESTORECON" /usr/bin/newgidmap 2>/dev/null || true
	"$RESTORECON" -R /run/docker-helper-builder 2>/dev/null || true
	"$RESTORECON" -R /var/lib/docker-helper-builder 2>/dev/null || true
	"$RESTORECON" -R /etc/docker-helper 2>/dev/null || true
	"$RESTORECON" -R /var/lib/docker-helper 2>/dev/null || true
	"$RESTORECON" /run/docker-helper 2>/dev/null || true
}

run_init() {
	if [[ -f "$CONFIG_PATH" ]]; then
		info "Existing configuration found at $CONFIG_PATH, skipping init"
		return
	fi

	info "Running initial system init"
	if [[ -n "$allowed_root" ]]; then
		if ! "$BINARY_DEST" init --allowed-root "$allowed_root"; then
			error "init failed"
			exit 1
		fi
	else
		if ! "$BINARY_DEST" init; then
			error "init failed"
			exit 1
		fi
	fi
}

reload_systemd() {
	info "Reloading systemd daemon"
	if ! "$SYSTEMCTL" daemon-reload; then
		error "daemon-reload failed"
		exit 1
	fi
}

enable_and_start_service() {
	info "Enabling $BUILDER_UNIT_NAME"
	if ! "$SYSTEMCTL" enable "$BUILDER_UNIT_NAME"; then
		error "Failed to enable $BUILDER_UNIT_NAME"
		exit 1
	fi

	info "Enabling $UNIT_NAME"
	if ! "$SYSTEMCTL" enable "$UNIT_NAME"; then
		error "Failed to enable $UNIT_NAME"
		exit 1
	fi

	info "Starting $UNIT_NAME"
	if ! "$SYSTEMCTL" start "$UNIT_NAME"; then
		error "Failed to start $UNIT_NAME"
		info ""
		info "Check status with:"
		info "  systemctl status $UNIT_NAME"
		info "  journalctl -u $UNIT_NAME"
		exit 1
	fi
}

start_service() {
	info "Starting $UNIT_NAME"
	if ! "$SYSTEMCTL" start "$UNIT_NAME"; then
		error "Failed to start $UNIT_NAME"
		info ""
		info "Check status with:"
		info "  systemctl status $UNIT_NAME"
		info "  journalctl -u $UNIT_NAME"
		exit 1
	fi
}

# start_builder_service restores the builder backend when it was active
# before the install. The main unit's Wants= coupling already pulls it in
# when the main daemon is started, so this is a no-op then; it is the
# restoration for the only-builder-active case, where no main start can be
# relied on (and a previously-inactive main service must stay down).
start_builder_service() {
	info "Starting $BUILDER_UNIT_NAME"
	if ! "$SYSTEMCTL" start "$BUILDER_UNIT_NAME"; then
		error "Failed to start $BUILDER_UNIT_NAME"
		info ""
		info "Check status with:"
		info "  systemctl status $BUILDER_UNIT_NAME"
		info "  journalctl -u $BUILDER_UNIT_NAME"
		exit 1
	fi
}

# --- Main ---

main() {
	parse_args "$@"

	check_root
	check_bundled_assets
	check_systemctl
	# MAC backend selection and its tooling/artifact preflight happen before
	# any installation mutation: neither/both active backends, a missing
	# required backend tool, or a missing bundled MAC artifact aborts here.
	select_mac_backend
	check_selected_mac_tools
	check_docker
	check_allowed_root
	detect_existing_install
	check_active_service

	provision_builder
	install_binary
	install_unit
	install_builder_unit
	install_buildkit_payload
	install_completion

	if [[ "$selected_mac" == "apparmor" ]]; then
		install_apparmor_profile
		prepare_apparmor_state
		load_apparmor_profile
		cleanup_legacy_apparmor_state
	else
		install_selinux_policy
		apply_selinux_restorecon
	fi

	run_init
	reload_systemd

	# Restoration contract: restore exactly the services that were active
	# before the installation. A previously-inactive main service is not
	# started on a reinstall (the operator may have stopped it
	# deliberately); starting the main daemon pulls the builder in through
	# the unit's existing Wants= coupling, and the explicit builder start
	# below is the restoration for the only-builder-active case. A fresh
	# install keeps the existing enable+start setup contract.
	if $service_was_active; then
		start_service
	fi
	if $builder_service_was_active; then
		start_builder_service
	fi
	if ! $service_was_active && ! $builder_service_was_active; then
		if $was_installed; then
			info ""
			info "Reinstall complete. The services were inactive before the install"
			info "and were left stopped:"
			info "  systemctl start $UNIT_NAME"
		else
			if $interactive; then
				if ask "Enable and start $UNIT_NAME"; then
					enable_and_start_service
				else
					info "Service not started. Enable and start with:"
					info "  systemctl enable --now $UNIT_NAME"
				fi
			else
				enable_and_start_service
			fi
		fi
	fi

	info ""
	info "docker-helper system installation complete (MAC backend: $selected_mac)."
	info ""
	info "Manage the service with:"
	info "  systemctl status $UNIT_NAME"
	info "  systemctl restart $UNIT_NAME"
	info ""
	if [[ "$selected_mac" == "apparmor" ]]; then
		info "AppArmor MAC coverage is prepared by docker-helper sessions"
		info "(managed AppArmor MAC boundaries for the issued filesystem trees)."
		info "Diagnose the installed policy with:"
		info "  docker-helper apparmor root list"
		info "  docker-helper apparmor check"
	else
		info "SELinux workspace MAC coverage is managed by docker-helper sessions"
		info "(semanage fcontext + restorecon for non-home workspaces)."
		info "Diagnose the installed SELinux policy with:"
		info "  docker-helper selinux check"
	fi
}

# Only run main when executed directly (not when sourced for testing)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
