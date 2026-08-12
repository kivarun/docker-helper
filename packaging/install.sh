#!/usr/bin/env bash
# install.sh — user-only installation of docker-helper.
#
# Installs the binary to ~/.local/bin/docker-helper, the systemd user
# unit to ~/.config/systemd/user/docker-helper.service, and optionally
# the agent skill to ~/.claude/skills/docker-helper.
#
# Usage:
#   ./install.sh [--yes]
#
# Flags:
#   --yes   Non-interactive: accept all defaults, run init, enable+start service.
#
# Requires: bash 4+, Docker access for the current user.
# Does NOT require: sudo.

set -euo pipefail

# --- Constants ---
readonly BINARY_NAME="docker-helper"
readonly INSTALL_DIR="$HOME/.local/bin"
readonly UNIT_DIR="$HOME/.config/systemd/user"
readonly UNIT_NAME="docker-helper.service"
readonly SKILL_INSTALL_DIR="$HOME/.claude/skills/docker-helper"

# --- State ---
interactive=true
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
	info ""
	info "WARNING: docker-helper requires access to the Docker daemon."
	info "Access via a rootful Docker daemon (e.g., membership in the 'docker'"
	info "group) effectively grants root-equivalent privileges on the host."
	info "Rootless Docker does not carry the same risk."
	info "Ensure you trust this access before proceeding."
	info ""

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

# --- Service check ---

check_active_service() {
	if ! systemctl --user is-active --quiet "$UNIT_NAME" 2>/dev/null; then
		return
	fi

	local current_version=""
	local new_version=""

	if [[ -x "$INSTALL_DIR/$BINARY_NAME" ]]; then
		current_version="$("$INSTALL_DIR/$BINARY_NAME" version 2>/dev/null || true)"
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
		info "  systemctl --user stop $UNIT_NAME"
		info ""
		exit 0
	fi

	info "Stopping $UNIT_NAME"
	if ! systemctl --user stop "$UNIT_NAME" 2>/dev/null; then
		error "Failed to stop $UNIT_NAME"
		error "Aborting without changes. Stop the service manually and retry."
		exit 1
	fi

	service_was_active=true
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

install_skill() {
	local skill_src="$script_dir/skills/docker-helper/SKILL.md"
	if [[ ! -f "$skill_src" ]]; then
		return
	fi

	if ! ask "Install docker-helper agent skill to ~/.claude/skills/docker-helper"; then
		info "Skipping skill installation"
		return
	fi

	info "Installing docker-helper skill to $SKILL_INSTALL_DIR"
	mkdir -p "$SKILL_INSTALL_DIR"
	cp "$skill_src" "$SKILL_INSTALL_DIR/SKILL.md"
	info "Skill installed"
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
	check_active_service

	install_binary
	install_unit
	install_skill
	check_path

	info ""
	info "$BINARY_NAME installed to $INSTALL_DIR/$BINARY_NAME"
	info ""

	run_init

	if $service_was_active; then
		if ! systemctl --user daemon-reload 2>/dev/null; then
			warn "systemctl --user daemon-reload failed"
		else
			if ! systemctl --user start "$UNIT_NAME" 2>/dev/null; then
				warn "Failed to start $UNIT_NAME"
			else
				info ""
				info "Service restarted."
				info "Check status with:  systemctl --user status $UNIT_NAME"
				info "View logs with:     journalctl --user -u $UNIT_NAME"
			fi
		fi
	else
		enable_service
	fi

	info ""
	info "Installation complete."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
