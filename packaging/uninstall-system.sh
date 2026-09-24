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
BUILDER_UNIT_DEST="${BUILDER_UNIT_DEST:-/etc/systemd/system/docker-helper-builder.service}"
BUILDER_UNIT_NAME="${BUILDER_UNIT_NAME:-docker-helper-builder.service}"
BUILDER_IDENTITY="${BUILDER_IDENTITY:-docker-helper-builder}"
BUILDKIT_BIN_DIR="${BUILDKIT_BIN_DIR:-/usr/libexec/docker-helper/buildkit}"
BUILDKIT_DOC_DIR="${BUILDKIT_DOC_DIR:-/usr/share/doc/docker-helper/buildkit}"
BUILDER_STATE_DIR="${BUILDER_STATE_DIR:-/var/lib/docker-helper-builder}"
BUILDER_RUNTIME_DIR="${BUILDER_RUNTIME_DIR:-/run/docker-helper-builder}"
SUBUID_DB="${SUBUID_DB:-/etc/subuid}"
SUBGID_DB="${SUBGID_DB:-/etc/subgid}"
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

# The builder service runs independently of the daemon (the main unit's
# Wants= only pulls it in on start); stop it explicitly, tolerating hosts
# where it was never installed. Its children (RootlessKit/buildkitd) die
# in its control group.
stop_builder_service() {
	if ! "$SYSTEMCTL" is-active --quiet "$BUILDER_UNIT_NAME" 2>/dev/null; then
		return
	fi

	info "Stopping $BUILDER_UNIT_NAME"
	if ! "$SYSTEMCTL" stop "$BUILDER_UNIT_NAME" 2>/dev/null; then
		error "Failed to stop $BUILDER_UNIT_NAME"
		error "Aborting. Stop the service manually and retry."
		exit 1
	fi
}

disable_service() {
	"$SYSTEMCTL" disable "$UNIT_NAME" 2>/dev/null || true
	"$SYSTEMCTL" disable "$BUILDER_UNIT_NAME" 2>/dev/null || true
}

remove_unit() {
	info "Removing systemd unit $UNIT_DEST"
	rm -f "$UNIT_DEST"
	info "Removing systemd unit $BUILDER_UNIT_DEST"
	rm -f "$BUILDER_UNIT_DEST"
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

# --- Builder backend ---

# remove_buildkit_payload removes the shipped pinned BuildKit payload and its
# license/manifest material (installed by install-system.sh and owned by the
# tarball deployment).
remove_buildkit_payload() {
	if [[ -d "$BUILDKIT_BIN_DIR" ]]; then
		info "Removing pinned BuildKit payload $BUILDKIT_BIN_DIR"
		rm -rf "$BUILDKIT_BIN_DIR"
	fi
	if [[ -d "$BUILDKIT_DOC_DIR" ]]; then
		info "Removing BuildKit license/manifest material $BUILDKIT_DOC_DIR"
		rm -rf "$BUILDKIT_DOC_DIR"
	fi
}

# The provisioned builder identity is deliberately KEPT on ordinary
# uninstall (subordinate-ID reallocation on reinstall is idempotent); only
# --purge removes it. The subid range removal is delegated to upstream
# shadow-utils (`usermod --del-subuids/--del-subgids`, reading the ranges
# the provisioning owner wrote) — docker-helper never writes the subid
# databases directly. A usermod without subid support fails the purge with
# an actionable message instead of falling back to a hand-rolled writer.
purge_builder_identity() {
	if ! id "$BUILDER_IDENTITY" >/dev/null 2>&1; then
		info "Builder identity $BUILDER_IDENTITY not present; nothing to purge"
		return
	fi
	if ! command -v usermod >/dev/null 2>&1 || ! command -v userdel >/dev/null 2>&1; then
		error "usermod/userdel (shadow-utils) not available; cannot purge the builder identity"
		error "purge the account manually, or re-run --purge after installing shadow-utils"
		exit 1
	fi
	info "Purging builder identity $BUILDER_IDENTITY (subordinate ranges via usermod, then userdel)"
	local db start count
	# Collect the provisioned ranges BEFORE mutating anything: usermod
	# rewrites the databases, and reading during that mutation would race
	# the rewrite. Unknown-format lines are skipped; only this identity's
	# numeric entries are touched. /etc/subuid carries [start, count);
	# usermod's --del-subuids/--del-subgids grammar is FIRST-LAST, so the
	# stored interval is converted once, here, before the delegation.
	local -a uid_ranges=() gid_ranges=()
	# SC2094: the loop below only READS the databases; the usermod mutations
	# run strictly after the collection loop finished.
	# shellcheck disable=SC2094
	for db in "$SUBUID_DB" "$SUBGID_DB"; do
		[[ -f "$db" ]] || continue
		while IFS=: read -r user start count; do
			[[ "$user" == "$BUILDER_IDENTITY" ]] || continue
			case "$start" in ''|*[!0-9]*)
				error "$db holds a nonnumeric $BUILDER_IDENTITY start ($start:$count); resolve it manually and re-run --purge"
				exit 1 ;;
			esac
			case "$count" in ''|*[!0-9]*)
				error "$db holds a nonnumeric $BUILDER_IDENTITY count ($start:$count); resolve it manually and re-run --purge"
				exit 1 ;;
			esac
			local last=$((start + count - 1))
			if [[ "$db" == "$SUBUID_DB" ]]; then
				uid_ranges+=("$start-$last")
			else
				gid_ranges+=("$start-$last")
			fi
		done < "$db"
	done
	for start in "${uid_ranges[@]}"; do
		if ! usermod --del-subuids "$start" "$BUILDER_IDENTITY"; then
			error "usermod --del-subuids failed for $BUILDER_IDENTITY range $start"
			exit 1
		fi
	done
	for start in "${gid_ranges[@]}"; do
		if ! usermod --del-subgids "$start" "$BUILDER_IDENTITY"; then
			error "usermod --del-subgids failed for $BUILDER_IDENTITY range $start"
			exit 1
		fi
	done
	if ! userdel "$BUILDER_IDENTITY"; then
		error "userdel $BUILDER_IDENTITY failed"
		exit 1
	fi
	groupdel "$BUILDER_IDENTITY" 2>/dev/null || true
	info "Builder identity purged"
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
		local legacy_dir
		legacy_dir="$(dirname "$AA_LEGACY_FRAGMENT")"
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
			info "  $BUILDER_STATE_DIR"
			info "  $BUILDER_RUNTIME_DIR"
			info "  and the builder identity $BUILDER_IDENTITY (including its"
			info "  subordinate-ID ranges, via usermod)"
			info ""
			if ! ask_no_default "Permanently delete all persistent data and continue"; then
				info "Aborting without changes."
				exit 0
			fi
		fi
	fi

	stop_service
	stop_builder_service
	disable_service
	remove_unit
	reload_systemd
	unload_apparmor_profile
	remove_apparmor_profile
	remove_selinux_policy
	remove_selinux_artifact
	remove_buildkit_payload
	remove_binary
	remove_completion

	if $purge; then
		purge_persistent_data
		if [[ -d "$BUILDER_STATE_DIR" ]]; then
			info "Removing builder state $BUILDER_STATE_DIR"
			rm -rf "$BUILDER_STATE_DIR"
		fi
		if [[ -d "$BUILDER_RUNTIME_DIR" ]]; then
			info "Removing builder runtime directory $BUILDER_RUNTIME_DIR"
			rm -rf "$BUILDER_RUNTIME_DIR"
		fi
		purge_builder_identity
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
