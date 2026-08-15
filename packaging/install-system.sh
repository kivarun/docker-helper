#!/usr/bin/env bash
# install-system.sh — system (root) installation of docker-helper.
#
# Installs the binary to /usr/bin/docker-helper, the systemd system
# unit, the AppArmor system profile, and initializes the daemon.
#
# Usage:
#   sudo ./install-system.sh
#   sudo ./install-system.sh --yes --allowed-root /path
#
# Flags:
#   --yes            Non-interactive: accept all defaults, init, enable+start.
#   --allowed-root P Required with --yes when /etc/docker-helper/config.json
#                    is absent. Sets the initial allowed_root for init.
#
# Requires: bash 4+, root (effective UID 0), Docker, AppArmor parser.

set -euo pipefail

# --- Constants (overridable for testing) ---
BINARY_NAME="${BINARY_NAME:-docker-helper}"
BINARY_DEST="${BINARY_DEST:-/usr/bin/docker-helper}"
UNIT_SRC="${UNIT_SRC:-systemd/system/docker-helper.service}"
UNIT_DEST="${UNIT_DEST:-/etc/systemd/system/docker-helper.service}"
UNIT_NAME="${UNIT_NAME:-docker-helper.service}"
AA_PROFILE_SRC="${AA_PROFILE_SRC:-apparmor/docker-helper-system}"
AA_PROFILE_DEST="${AA_PROFILE_DEST:-/etc/apparmor.d/docker-helper-system}"
AA_FRAGMENT_SRC="${AA_FRAGMENT_SRC:-apparmor/docker-helper.d/managed-roots}"
AA_FRAGMENT_DEST="${AA_FRAGMENT_DEST:-/etc/apparmor.d/docker-helper.d/managed-roots}"
AA_PARSER="${AA_PARSER:-/usr/sbin/apparmor_parser}"
CONFIG_PATH="${CONFIG_PATH:-/etc/docker-helper/config.json}"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
DOCKER="${DOCKER:-docker}"

# --- State ---
interactive=true
allowed_root=""
script_dir=""
service_was_active=false

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

	local profile_path="$script_dir/$AA_PROFILE_SRC"
	if [[ ! -f "$profile_path" ]]; then
		error "AppArmor profile not found at $profile_path"
		exit 1
	fi

	local fragment_path="$script_dir/$AA_FRAGMENT_SRC"
	if [[ ! -f "$fragment_path" ]]; then
		error "AppArmor managed-roots fragment not found at $fragment_path"
		exit 1
	fi
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
		error "AppArmor is mandatory for system mode installation."
		exit 1
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

check_active_service() {
	if ! "$SYSTEMCTL" is-active --quiet "$UNIT_NAME" 2>/dev/null; then
		return
	fi

	local current_version=""
	local new_version=""

	if [[ -x "$BINARY_DEST" ]]; then
		current_version="$("$BINARY_DEST" version 2>/dev/null || true)"
	fi
	new_version="$("$script_dir/$BINARY_NAME" version 2>/dev/null || true)"

	info ""
	info "$UNIT_NAME is currently active."
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

	if ! ask "Stop the service and continue installation"; then
		info "Aborting without changes."
		info ""
		info "To reinstall later, stop the service first:"
		info "  systemctl stop $UNIT_NAME"
		info ""
		exit 0
	fi

	info "Stopping $UNIT_NAME"
	if ! "$SYSTEMCTL" stop "$UNIT_NAME" 2>/dev/null; then
		error "Failed to stop $UNIT_NAME"
		error "Aborting without changes. Stop the service manually and retry."
		exit 1
	fi

	service_was_active=true
}

# --- Installation steps ---

install_binary() {
	info "Installing $BINARY_NAME to $BINARY_DEST"
	cp "$script_dir/$BINARY_NAME" "$BINARY_DEST"
	chmod 0755 "$BINARY_DEST"
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

install_apparmor_fragment() {
	info "Installing AppArmor managed-roots fragment"
	local dest_dir="$(dirname "$AA_FRAGMENT_DEST")"
	mkdir -p "$dest_dir"

	if [[ -f "$AA_FRAGMENT_DEST" ]]; then
		info "Existing managed-roots fragment preserved (not overwritten)"
		return
	fi

	cp "$script_dir/$AA_FRAGMENT_SRC" "$AA_FRAGMENT_DEST"
	chmod 0644 "$AA_FRAGMENT_DEST"
}

load_apparmor_profile() {
	info "Loading AppArmor profile $AA_PROFILE_DEST"
	if ! "$AA_PARSER" --replace --skip-read-cache "$AA_PROFILE_DEST"; then
		error "Failed to load AppArmor profile"
		error "Installation aborted. Service will not be started."
		exit 1
	fi
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

# --- Main ---

main() {
	parse_args "$@"

	check_root
	check_bundled_assets
	check_systemctl
	check_apparmor_parser
	check_docker
	check_allowed_root
	check_active_service

	install_binary
	install_unit
	install_apparmor_profile
	install_apparmor_fragment
	load_apparmor_profile
	run_init
	reload_systemd

	if $service_was_active; then
		start_service
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

	info ""
	info "docker-helper system installation complete."
	info ""
	info "Manage the service with:"
	info "  systemctl status $UNIT_NAME"
	info "  systemctl restart $UNIT_NAME"
	info ""
	info "Manage AppArmor workspace roots with:"
	info "  docker-helper apparmor root add PATH"
	info "  docker-helper apparmor root remove PATH"
}

# Only run main when executed directly (not when sourced for testing)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
