#!/usr/bin/env bash
# uninstall.sh — remove docker-helper user installation.
#
# Removes the binary, systemd user unit, and optionally the AppArmor profile.
# Config, admin token, and state are preserved by default.
#
# Usage:
#   ./uninstall.sh [--yes] [--purge]
#
# Flags:
#   --yes   Non-interactive: accept all defaults.
#   --purge Also remove config (~/.config/docker-helper) and
#           state (~/.local/state/docker-helper). Default: No.

set -euo pipefail

# --- Constants ---
readonly BINARY_NAME="docker-helper"
readonly INSTALL_DIR="$HOME/.local/bin"
readonly UNIT_DIR="$HOME/.config/systemd/user"
readonly UNIT_NAME="docker-helper.service"
readonly APPARMOR_PROFILE_NAME="docker-helper"
readonly CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper"
readonly STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/docker-helper"

# --- State ---
interactive=true
purge=false

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
	local default="${2:-y}"
	local answer

	if $interactive; then
		printf '%s [%s/n]: ' "$prompt" "$default"
		read -r answer
		if [[ -z "$answer" ]]; then
			answer="$default"
		fi
		[[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]
	else
		true
	fi
}

# --- Argument parsing ---

parse_args() {
	for arg in "$@"; do
		case "$arg" in
			--yes)
				interactive=false
				;;
			--purge)
				purge=true
				;;
			*)
				error "unknown option: $arg"
				exit 1
				;;
		esac
	done
}

# --- Uninstall steps ---

stop_disable_service() {
	if systemctl --user is-active --quiet "$UNIT_NAME" 2>/dev/null; then
		info "Stopping $UNIT_NAME"
		systemctl --user stop "$UNIT_NAME" 2>/dev/null || true
	fi

	if systemctl --user is-enabled --quiet "$UNIT_NAME" 2>/dev/null; then
		info "Disabling $UNIT_NAME"
		systemctl --user disable "$UNIT_NAME" 2>/dev/null || true
	fi

	systemctl --user daemon-reload 2>/dev/null || true
}

remove_binary() {
	if [[ -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
		info "Removing $INSTALL_DIR/$BINARY_NAME"
		rm -f "$INSTALL_DIR/$BINARY_NAME"
	fi
}

remove_unit() {
	if [[ -f "$UNIT_DIR/$UNIT_NAME" ]]; then
		info "Removing $UNIT_DIR/$UNIT_NAME"
		rm -f "$UNIT_DIR/$UNIT_NAME"
	fi
}

remove_apparmor() {
	if [[ -f "/etc/apparmor.d/$APPARMOR_PROFILE_NAME" ]]; then
		if $interactive; then
			printf 'Remove %s AppArmor profile (requires sudo)? [y/N]: ' "$APPARMOR_PROFILE_NAME"
			read -r answer
			if [[ "${answer,,}" != "y" && "${answer,,}" != "yes" ]]; then
				info "Skipping AppArmor profile removal"
				return
			fi
		else
			# --yes: remove AppArmor profile like other artifacts.
			:
		fi

		# Unload the profile first while the file still exists.
		sudo apparmor_parser -R "/etc/apparmor.d/$APPARMOR_PROFILE_NAME" 2>/dev/null || true

		if ! sudo rm -f "/etc/apparmor.d/$APPARMOR_PROFILE_NAME"; then
			warn "Failed to remove AppArmor profile"
			return
		fi

		info "AppArmor profile removed"
	fi
}

purge_config_and_state() {
	if [[ -d "$CONFIG_DIR" ]]; then
		info "Removing config directory: $CONFIG_DIR"
		rm -rf "$CONFIG_DIR"
	fi

	if [[ -d "$STATE_DIR" ]]; then
		info "Removing state directory: $STATE_DIR"
		rm -rf "$STATE_DIR"
	fi
}

# --- Main ---

main() {
	parse_args "$@"

	info "Uninstalling $BINARY_NAME"
	info ""

	stop_disable_service
	remove_binary
	remove_unit
	remove_apparmor

	info ""

	if $purge; then
		if $interactive; then
			if ! ask "Permanently delete config and state (admin token, sessions, database)?" n; then
				info "Keeping config and state"
				info ""
				info "Config: $CONFIG_DIR"
				info "State:  $STATE_DIR"
				info ""
				info "Uninstall complete."
				return
			fi
		fi
		purge_config_and_state
	else
		info "Config and state preserved:"
		info "  Config: $CONFIG_DIR"
		info "  State:  $STATE_DIR"
		info ""
		info "To remove them later, run:  $0 --purge"
	fi

	info ""
	info "Uninstall complete."
}

main "$@"