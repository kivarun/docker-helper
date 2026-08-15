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

# --- Constants (overridable for testing) ---
BINARY_NAME="${BINARY_NAME:-docker-helper}"
BINARY_DEST="${BINARY_DEST:-/usr/bin/docker-helper}"
UNIT_DEST="${UNIT_DEST:-/etc/systemd/system/docker-helper.service}"
UNIT_NAME="${UNIT_NAME:-docker-helper.service}"
AA_PROFILE_DEST="${AA_PROFILE_DEST:-/etc/apparmor.d/docker-helper-system}"
AA_FRAGMENT_DEST="${AA_FRAGMENT_DEST:-/etc/apparmor.d/docker-helper.d/managed-roots}"
AA_FRAGMENT_DIR="${AA_FRAGMENT_DIR:-/etc/apparmor.d/docker-helper.d}"
AA_PARSER="${AA_PARSER:-/usr/sbin/apparmor_parser}"
CONFIG_DIR="${CONFIG_DIR:-/etc/docker-helper}"
STATE_DIR="${STATE_DIR:-/var/lib/docker-helper}"
RUNTIME_DIR="${RUNTIME_DIR:-/run/docker-helper}"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"

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

ask_no_default() {
	# Ask with default No (Enter = no)
	local prompt="$1"
	local answer

	if $interactive; then
		printf '%s [y/N]: ' "$prompt"
		read -r answer
		[[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]
	else
		true
	fi
}

# --- Argument parsing ---

parse_args() {
	while (($#)); do
		case "$1" in
			--yes)
				interactive=false
				shift
				;;
			--purge)
				purge=true
				shift
				;;
			*)
				error "unknown option: $1"
				exit 1
				;;
		esac
	done
}

# --- Preflight ---

check_root() {
	if [[ "${CHECK_ROOT:-true}" == "true" ]] && [[ "$(id -u)" -ne 0 ]]; then
		error "this script must be run as root (effective UID 0)"
		exit 1
	fi
}

# --- Service management ---

stop_service() {
	if ! "$SYSTEMCTL" is-active --quiet "$UNIT_NAME" 2>/dev/null; then
		return
	fi

	info "Stopping $UNIT_NAME"
	if ! "$SYSTEMCTL" stop "$UNIT_NAME" 2>/dev/null; then
		error "Failed to stop $UNIT_NAME"
		error "Aborting. Stop the service manually and retry."
		exit 1
	fi
}

disable_service() {
	"$SYSTEMCTL" disable "$UNIT_NAME" 2>/dev/null || true
}

remove_unit() {
	info "Removing systemd unit $UNIT_DEST"
	rm -f "$UNIT_DEST"
}

reload_systemd() {
	info "Reloading systemd daemon"
	"$SYSTEMCTL" daemon-reload || true
}

# --- AppArmor ---

unload_apparmor_profile() {
	if [[ ! -x "$AA_PARSER" ]]; then
		info "AppArmor parser not available, skipping profile unload"
		return
	fi

	info "Unloading AppArmor profile docker-helper-system"
	if ! "$AA_PARSER" -R "$AA_PROFILE_DEST"; then
		local parser_err="$?"
		warn "Failed to unload AppArmor profile (exit $parser_err, may not be loaded or already removed)"
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
			if ! ask_no_default "Permanently delete all persistent data and continue"; then
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

# Only run main when executed directly (not when sourced for testing)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
