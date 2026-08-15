#!/usr/bin/env bash
# uninstall-system.sh — system (root) uninstallation of docker-helper.
#
# Stops and removes the system service, unloads the AppArmor profile,
# and removes the binary. Config, state, and managed-roots are preserved
# by default. Use --purge to remove them.
#
# Usage:
#   sudo ./uninstall-system.sh
#   sudo ./uninstall-system.sh --yes
#   sudo ./uninstall-system.sh --purge
#   sudo ./uninstall-system.sh --yes --purge
#
# Flags:
#   --yes   Non-interactive: confirm all actions.
#   --purge Also remove /etc/docker-helper, /var/lib/docker-helper,
#           /run/docker-helper, and managed-roots fragment.
#
# Requires: bash 4+, root (effective UID 0).

set -euo pipefail

# --- Constants ---
readonly BINARY_NAME="docker-helper"
readonly BINARY_DEST="/usr/bin/docker-helper"
readonly UNIT_DEST="/etc/systemd/system/docker-helper.service"
readonly UNIT_NAME="docker-helper.service"
readonly AA_PROFILE_DEST="/etc/apparmor.d/docker-helper-system"
readonly AA_FRAGMENT_DEST="/etc/apparmor.d/docker-helper.d/managed-roots"
readonly AA_FRAGMENT_DIR="/etc/apparmor.d/docker-helper.d"
readonly AA_PARSER="/usr/sbin/apparmor_parser"
readonly CONFIG_DIR="/etc/docker-helper"
readonly STATE_DIR="/var/lib/docker-helper"
readonly RUNTIME_DIR="/run/docker-helper"

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

# --- Preflight ---

check_root() {
	if [[ "$(id -u)" -ne 0 ]]; then
		error "this script must be run as root (effective UID 0)"
		exit 1
	fi
}

# --- Service management ---

stop_service() {
	if ! systemctl is-active --quiet "$UNIT_NAME" 2>/dev/null; then
		return
	fi

	info "Stopping $UNIT_NAME"
	if ! systemctl stop "$UNIT_NAME" 2>/dev/null; then
		error "Failed to stop $UNIT_NAME"
		error "Aborting. Stop the service manually and retry."
		exit 1
	fi
}

disable_service() {
	systemctl disable "$UNIT_NAME" 2>/dev/null || true
}

remove_unit() {
	info "Removing systemd unit $UNIT_DEST"
	rm -f "$UNIT_DEST"
}

reload_systemd() {
	info "Reloading systemd daemon"
	systemctl daemon-reload || true
}

# --- AppArmor ---

unload_apparmor_profile() {
	if [[ ! -x "$AA_PARSER" ]]; then
		info "AppArmor parser not available, skipping profile unload"
		return
	fi

	info "Unloading AppArmor profile docker-helper-system"
	if ! "$AA_PARSER" -R "$AA_PROFILE_DEST" 2>/dev/null; then
		warn "Failed to unload AppArmor profile (may not be loaded or already removed)"
	fi
}

remove_apparmor_profile() {
	info "Removing AppArmor profile $AA_PROFILE_DEST"
	rm -f "$AA_PROFILE_DEST"
}

# --- Binary ---

remove_binary() {
	info "Removing $BINARY_DEST"
	rm -f "$BINARY_DEST"
}

# --- Purge ---

purge_persistent_data() {
	info "Purging persistent data"
	rm -rf "$CONFIG_DIR"
	rm -rf "$STATE_DIR"
	rm -rf "$RUNTIME_DIR"

	if [[ -f "$AA_FRAGMENT_DEST" ]]; then
		info "Removing managed-roots fragment $AA_FRAGMENT_DEST"
		rm -f "$AA_FRAGMENT_DEST"
		# Remove docker-helper.d directory if empty
		if [[ -d "$AA_FRAGMENT_DIR" ]] && [[ -z "$(ls -A "$AA_FRAGMENT_DIR" 2>/dev/null)" ]]; then
			rmdir "$AA_FRAGMENT_DIR" 2>/dev/null || true
		fi
	fi
}

# --- Main ---

main() {
	parse_args "$@"

	check_root

	if $purge; then
		if $interactive; then
			info ""
			info "WARNING: --purge will permanently remove:"
			info "  $CONFIG_DIR"
			info "  $STATE_DIR"
			info "  $RUNTIME_DIR"
			info "  $AA_FRAGMENT_DEST"
			info ""
			if ! ask "Permanently delete all persistent data and continue"; then
				info "Aborting without changes."
				exit 0
			fi
		fi
	fi

	stop_service
	disable_service
	remove_unit
	reload_systemd
	unload_apparmor_profile
	remove_apparmor_profile
	remove_binary

	if $purge; then
		purge_persistent_data
	fi

	info ""
	info "docker-helper system uninstallation complete."
	info ""
	if ! $purge; then
		info "Preserved (can be reused for reinstall):"
		info "  $CONFIG_DIR"
		info "  $STATE_DIR"
		info "  $AA_FRAGMENT_DEST"
		info ""
		info "To remove them manually:"
		info "  rm -rf $CONFIG_DIR $STATE_DIR"
		info "  rm -f $AA_FRAGMENT_DEST"
	fi
}

main "$@"
