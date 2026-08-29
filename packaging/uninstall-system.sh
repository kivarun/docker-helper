#!/usr/bin/env bash
# uninstall-system.sh — system (root) uninstallation of docker-helper.
#
# Stops and removes the system service, unloads/removes the installed MAC
# backend policy (AppArmor profile and/or SELinux docker_helper module +
# artifact) and removes the binary. Config, state, and managed-roots are
# preserved by default. Use --purge to remove them.
#
# The uninstaller is MAC-neutral: it cleans up whichever backend was installed
# (AppArmor profile, and/or the SELinux docker_helper module + policy artifact)
# without requiring the currently active LSM to match the installed backend, so
# an administrator can still uninstall after host configuration changes. It
# never damages unrelated AppArmor/SELinux state.
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
AA_STATE_FILE="${AA_STATE_FILE:-/var/lib/docker-helper/apparmor/managed-boundaries}"
AA_LEGACY_FRAGMENT="${AA_LEGACY_FRAGMENT:-/etc/apparmor.d/docker-helper.d/managed-roots}"
AA_PARSER="${AA_PARSER:-/usr/sbin/apparmor_parser}"
SELINUX_PP_DEST="${SELINUX_PP_DEST:-/usr/share/selinux/docker_helper.pp}"
SEMODULE="${SEMODULE:-semodule}"
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
	if [[ "$(id -u)" -ne 0 ]]; then
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
	local parser_err=0
	"$AA_PARSER" -R "$AA_PROFILE_DEST" || parser_err=$?
	if [[ $parser_err -ne 0 ]]; then
		warn "Failed to unload AppArmor profile (exit $parser_err, may not be loaded or already removed)"
	fi
}

remove_apparmor_profile() {
	info "Removing AppArmor profile $AA_PROFILE_DEST"
	rm -f "$AA_PROFILE_DEST"
}

# --- SELinux ---

remove_selinux_policy() {
	# Best-effort module removal mirroring the RPM final-erase semantics
	# (packaging/scripts/rpm/preremove.sh): the docker_helper module is removed
	# when loaded, but removal is best-effort and a failure only warns. This is
	# independent of the currently active LSM so an administrator can uninstall
	# after host configuration changes; it only ever touches docker_helper.
	if ! command -v "$SEMODULE" >/dev/null 2>&1; then
		warn "semodule not available; skipping SELinux policy module removal"
		return
	fi
	info "Removing SELinux policy module docker_helper (best-effort)"
	if ! "$SEMODULE" -r docker_helper 2>/dev/null; then
		warn "Failed to remove SELinux policy module docker_helper (may not be loaded)"
	fi
}

remove_selinux_artifact() {
	if [[ -f "$SELINUX_PP_DEST" ]]; then
		info "Removing SELinux policy artifact $SELINUX_PP_DEST"
		rm -f "$SELINUX_PP_DEST"
	fi
}

# --- Binary ---

remove_binary() {
	info "Removing $BINARY_DEST"
	rm -f "$BINARY_DEST"
}

remove_completion() {
	local completion_dest="/usr/share/bash-completion/completions/docker-helper"
	if [[ -f "$completion_dest" ]]; then
		info "Removing $completion_dest"
		rm -f "$completion_dest"
	fi
}

# --- Purge ---

purge_persistent_data() {
	info "Purging persistent data"
	rm -rf "$CONFIG_DIR"
	rm -rf "$STATE_DIR"
	rm -rf "$RUNTIME_DIR"

	# Clean up the legacy managed-roots fragment on purge.
	if [[ -f "$AA_LEGACY_FRAGMENT" ]]; then
		info "Removing legacy managed-roots fragment $AA_LEGACY_FRAGMENT"
		rm -f "$AA_LEGACY_FRAGMENT"
		local legacy_dir="$(dirname "$AA_LEGACY_FRAGMENT")"
		if [[ -d "$legacy_dir" ]] && [[ -z "$(ls -A "$legacy_dir" 2>/dev/null)" ]]; then
			rmdir "$legacy_dir" 2>/dev/null || true
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
			info "  $AA_LEGACY_FRAGMENT"
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
	remove_selinux_policy
	remove_selinux_artifact
	remove_binary
	remove_completion

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
		info ""
		info "To remove them manually:"
		info "  rm -rf $CONFIG_DIR $STATE_DIR"
	fi
}

# Only run main when executed directly (not when sourced for testing)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
