#!/usr/bin/env bash
# install.sh — user-only installation of docker-helper.
#
# Installs the binary to ~/.local/bin/docker-helper and the systemd user
# unit to ~/.config/systemd/user/docker-helper.service.
#
# Usage:
#   ./install.sh [--yes]
#
# Flags:
#   --yes   Non-interactive: accept all defaults, run init, enable+start service.
#
# Requires: bash 4+, Docker access for the current user.
# Does NOT require: sudo (except optional AppArmor step).

set -euo pipefail

# --- Constants ---
readonly BINARY_NAME="docker-helper"
readonly INSTALL_DIR="$HOME/.local/bin"
readonly UNIT_DIR="$HOME/.config/systemd/user"
readonly UNIT_NAME="docker-helper.service"
readonly APPARMOR_PROFILE_NAME="docker-helper"

# --- State ---
interactive=true
script_dir=""

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

	for arg in "$@"; do
		case "$arg" in
			--yes)
				interactive=false
				;;
			*)
				error "unknown option: $arg"
				exit 1
				;;
		esac
	done
}

# --- Pre-flight checks ---

check_docker() {
	if ! docker info >/dev/null 2>&1; then
		error "cannot access Docker daemon."
		error "Ensure the current user has Docker access (e.g., is in the 'docker' group or uses rootless Docker)."
		error "docker-helper will not work without Docker access."
		exit 1
	fi
}

check_binary() {
	local binary_path="$script_dir/$BINARY_NAME"
	if [[ ! -f "$binary_path" ]]; then
		error "$BINARY_NAME binary not found in $script_dir"
		error "Run this script from the release tarball directory or place the binary alongside it."
		exit 1
	fi
}

# --- Installation steps ---

install_binary() {
	info "Installing $BINARY_NAME to $INSTALL_DIR"
	mkdir -p "$INSTALL_DIR"
	cp "$script_dir/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
	chmod 755 "$INSTALL_DIR/$BINARY_NAME"
}

install_unit() {
	info "Installing systemd user unit to $UNIT_DIR/$UNIT_NAME"
	local unit_path="$script_dir/systemd/user/$UNIT_NAME"
	if [[ ! -f "$unit_path" ]]; then
		warn "systemd unit not found at $unit_path, skipping"
		return
	fi
	mkdir -p "$UNIT_DIR"
	cp "$unit_path" "$UNIT_DIR/$UNIT_NAME"
	chmod 644 "$UNIT_DIR/$UNIT_NAME"
}

install_apparmor() {
	local profile_path="$script_dir/apparmor/$APPARMOR_PROFILE_NAME"
	if [[ ! -f "$profile_path" ]]; then
		return
	fi

	# Check if AppArmor is available
	if ! command -v apparmor_parser >/dev/null 2>&1; then
		return
	fi

	if ! ask "Install $APPARMOR_PROFILE_NAME AppArmor profile (requires sudo)"; then
		info "Skipping AppArmor profile installation"
		return
	fi

	# Absolute binary path for executable attachment.
	local binary_path="$INSTALL_DIR/$BINARY_NAME"

	# Read allowed_root from existing config to grant workspace access.
	local workspace_rule="# (no workspace configured yet; add allowed_root rule manually if needed)"
	local config_file="${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/config.json"
	if [[ -f "$config_file" ]]; then
		local allowed_root
		allowed_root=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['allowed_root'])" "$config_file" 2>/dev/null || true)
		if [[ -n "$allowed_root" ]]; then
			workspace_rule="${allowed_root}/ r,
	owner ${allowed_root}/** rw,"
		fi
	fi

	# Generate the final profile with paths substituted.
	local target_dir="/etc/apparmor.d"
	local final_profile
	final_profile=$(sed -e "s|@@BINARY_PATH@@|${binary_path}|g" \
		-e "s|@@WORKSPACE_RULE@@|${workspace_rule}|" "$profile_path")

	if ! echo "$final_profile" | sudo tee "$target_dir/$APPARMOR_PROFILE_NAME" >/dev/null 2>&1; then
		warn "Failed to install AppArmor profile"
		return
	fi

	if ! sudo apparmor_parser -a "$target_dir/$APPARMOR_PROFILE_NAME" >/dev/null 2>&1; then
		warn "Failed to load AppArmor profile"
		return
	fi

	info "AppArmor profile installed"
}

check_path() {
	if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
		info ""
		info "$INSTALL_DIR is not in your current PATH."
		info "To use $BINARY_NAME from the command line, either:"
		info "  - Start a new login session, or"
		info "  - Run:  export PATH=\"\$PATH:$INSTALL_DIR\""
		info "  - Or:   source ~/.profile   (if your shell config adds ~/.local/bin)"
		info ""
	fi
}

run_init() {
	if [[ -f "${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/config.json" ]]; then
		info "Config already exists, skipping init"
		return
	fi

	if ! ask "Run initial setup (docker-helper init)?"; then
		return
	fi

	info ""
	info "$INSTALL_DIR/$BINARY_NAME init"
	if "$INSTALL_DIR/$BINARY_NAME" init; then
		info ""
		info "Setup complete."
	fi
}

enable_service() {
	if ! ask "Enable and start the systemd user service?"; then
		return
	fi

	if ! systemctl --user daemon-reload 2>/dev/null; then
		warn "systemctl --user daemon-reload failed"
		return
	fi

	if ! systemctl --user enable "$UNIT_NAME" 2>/dev/null; then
		warn "Failed to enable $UNIT_NAME"
		return
	fi

	if ! systemctl --user start "$UNIT_NAME" 2>/dev/null; then
		warn "Failed to start $UNIT_NAME"
		return
	fi

	info ""
	info "Service enabled and started."
	info "Check status with:  systemctl --user status $UNIT_NAME"
	info "View logs with:     journalctl --user -u $UNIT_NAME"
}

# --- Main ---

main() {
	parse_args "$@"

	check_docker
	check_binary

	install_binary
	install_unit
	install_apparmor
	check_path

	info ""
	info "$BINARY_NAME installed to $INSTALL_DIR/$BINARY_NAME"
	info ""

	run_init
	enable_service

	info ""
	info "Installation complete."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
