#!/usr/bin/env bash
# uninstall.sh — remove docker-helper user installation.
#
# Removes the binary, systemd user unit, and optionally the skill.
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
readonly CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper"
readonly STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/docker-helper"
readonly SKILL_INSTALL_DIR="$HOME/.claude/skills/docker-helper"

# --- State ---
interactive=true
purge=false

# --- Helpers ---

usage() {
	cat <<'EOF'
Usage: ./uninstall.sh [--yes] [--purge]

Remove docker-helper user installation.

Flags:
  -h, --help   Show this help message
  --yes        Non-interactive: accept all defaults
  --purge      Also remove config and state (default: preserve)
EOF
}

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
		printf '%s [y/N]: ' "$prompt"
		read -r answer
		if [[ -z "$answer" ]]; then
			answer="n"
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
			-h|--help)
				usage
				exit 0
				;;
			--yes)
				interactive=false
				;;
			--purge)
				purge=true
				;;
			*)
				error "unknown option: $arg"
				echo "" >&2
				echo "Try './uninstall.sh --help' for usage information." >&2
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

remove_skill() {
	if [[ ! -f "$SKILL_INSTALL_DIR/SKILL.md" ]]; then
		return
	fi

	if ! ask "Remove docker-helper skill from ~/.claude/skills/docker-helper"; then
		info "Keeping skill at $SKILL_INSTALL_DIR"
		return
	fi

	info "Removing $SKILL_INSTALL_DIR/SKILL.md"
	rm -f "$SKILL_INSTALL_DIR/SKILL.md"

	# Remove the docker-helper directory if it's now empty.
	if [[ -d "$SKILL_INSTALL_DIR" ]] && [[ -z "$(ls -A "$SKILL_INSTALL_DIR" 2>/dev/null)" ]]; then
		rmdir "$SKILL_INSTALL_DIR" 2>/dev/null || true
	fi

	info "Skill removed"
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
	remove_skill

	info ""

	if $purge; then
		if $interactive; then
			if ! ask "Permanently delete config and state (admin token, sessions, database)?"; then
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

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
