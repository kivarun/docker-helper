#!/usr/bin/env bash
#
# uat-regression-system-only-daemon.sh — Release-2.3 targeted regression
# group: system-only daemon deployment contract (Ubuntu / DEB / AppArmor).
#
# Black-box acceptance for the Release-2.3 cutover: the user-mode daemon no
# longer exists as a production concept. The ONLY daemon deployment is the
# root-owned system service; non-root clients remain first-class through
# installed credentials (owned by the endpoint-resolution group). Proven
# here:
#
#   A. non-root `init` refuses: the user-mode daemon bootstrap no longer
#      exists. The refusal states the root/system-service requirement and
#      creates no per-user daemon state: no XDG config.json, no per-user
#      admin.token, no per-user state tree. (RED on the 2.2 baseline, where
#      non-root init bootstraps a real user-mode daemon configuration.)
#   B. non-root `serve` refuses: no user daemon can start. No socket appears
#      under the user's XDG runtime directory and no daemon process survives
#      the refusal. (RED on the 2.2 baseline, where a real user-mode daemon
#      starts and serves until the bounded timeout.)
#   C. the user systemd service/unit is gone: the package does not ship
#      /usr/lib/systemd/user/docker-helper.service, the file is absent after
#      install, and `init --help` no longer carries the user-unit/user-mode
#      bootstrap language.
#   D. the root system deployment remains the positive path: the system
#      service is active, its config and admin-token paths are the canonical
#      /etc/docker-helper locations, and the `mode` config projection no
#      longer exists (there is no mode to project).
#   E. the mode-selection grammar is gone: `--system` is no longer an
#      operator flag and command help no longer carries it.
#
# Docker is NOT required. Requires: root, the installed candidate system
# service (active), and an OS user account for the non-root probes.
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "11. System-only daemon deployment"

reg_require_root
reg_require_service
reg_require_cmd curl "health probing of the system service"

USER_NAME="uat23only"
USER_HOME="/home/$USER_NAME"

if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd -m -d "$USER_HOME" -s /bin/bash "$USER_NAME" \
    || reg_blocked "cannot create the non-root probe account $USER_NAME"
fi

REFUSAL="must be run as root"

# run_as_probe_user CMD... — run a command as the probe account with its own
# HOME/XDG environment. Prints nothing; the caller inspects rc/output.
run_as_probe_user() { # cmd...
  sudo -u "$USER_NAME" \
    env -u XDG_CONFIG_HOME -u XDG_RUNTIME_DIR -u XDG_STATE_HOME \
    HOME="$USER_HOME" XDG_RUNTIME_DIR="$USER_HOME/xdg-run" \
    "$@"
}

# ---------------------------------------------------------------------------
# A. non-root `init` refuses and creates no per-user daemon state.
# ---------------------------------------------------------------------------
INIT_OUT="$(run_as_probe_user docker-helper init --allowed-root /home 2>&1)"
INIT_RC=$?
if [ "$INIT_RC" -ne 0 ] && printf '%s\n' "$INIT_OUT" | grep -q "$REFUSAL"; then
  reg_ok "non-root init refused ($REFUSAL)"
else
  reg_fail "non-root init must refuse with '$REFUSAL' (rc=$INIT_RC, output below)
$(printf '%s\n' "$INIT_OUT" | redact | head -5)"
fi

for state_path in \
  "$USER_HOME/.config/docker-helper/config.json" \
  "$USER_HOME/.config/docker-helper/admin.token" \
  "$USER_HOME/.local/state/docker-helper" \
  "$USER_HOME/.local/share/docker-helper"; do
  if [ ! -e "$state_path" ]; then
    reg_ok "non-root init left no daemon state at $state_path"
  else
    reg_fail "non-root init created per-user daemon state at $state_path"
  fi
done

# ---------------------------------------------------------------------------
# B. non-root `serve` refuses: no user daemon, no user socket, no process.
# ---------------------------------------------------------------------------
SERVE_OUT="$(run_as_probe_user timeout 20 docker-helper serve 2>&1)"
SERVE_RC=$?
if [ "$SERVE_RC" -eq 124 ]; then
  reg_fail "non-root serve did not refuse: a user-mode daemon started and served until the bounded timeout"
elif [ "$SERVE_RC" -ne 0 ] && printf '%s\n' "$SERVE_OUT" | grep -q "$REFUSAL"; then
  reg_ok "non-root serve refused ($REFUSAL, rc=$SERVE_RC)"
else
  reg_fail "non-root serve must refuse with '$REFUSAL' (rc=$SERVE_RC, output below)
$(printf '%s\n' "$SERVE_OUT" | redact | head -5)"
fi

if [ ! -e "$USER_HOME/xdg-run/docker-helper/docker-helper.sock" ]; then
  reg_ok "non-root serve created no socket under the XDG runtime directory"
else
  reg_fail "non-root serve left a socket at $USER_HOME/xdg-run/docker-helper/docker-helper.sock"
fi

# ---------------------------------------------------------------------------
# C. the user systemd unit is gone from the package payload and the host.
# ---------------------------------------------------------------------------
if [ ! -e "/usr/lib/systemd/user/docker-helper.service" ]; then
  reg_ok "no shipped user systemd unit at /usr/lib/systemd/user/docker-helper.service"
else
  reg_fail "/usr/lib/systemd/user/docker-helper.service still exists after install"
fi

if dpkg -S /usr/lib/systemd/user/docker-helper.service >/dev/null 2>&1; then
  reg_fail "the user systemd unit is still owned by the installed package"
else
  reg_ok "the user systemd unit is not owned by the installed package"
fi

INIT_HELP="$(docker-helper init --help 2>&1)"
if printf '%s\n' "$INIT_HELP" | grep -Eq "User mode|user mode|systemctl --user|user unit"; then
  reg_fail "init help still carries user-mode/user-unit bootstrap language"
else
  reg_ok "init help carries no user-mode/user-unit bootstrap language"
fi

# ---------------------------------------------------------------------------
# D. the root system deployment is the positive path; no mode projection.
# ---------------------------------------------------------------------------
CONFIG_PATH_OUT="$(docker-helper config show config_path 2>/dev/null)"
if [ "$CONFIG_PATH_OUT" = "/etc/docker-helper/config.json" ]; then
  reg_ok "system config path is the canonical /etc/docker-helper/config.json"
else
  reg_fail "system config path is '$CONFIG_PATH_OUT' (expected /etc/docker-helper/config.json)"
fi

ADMIN_PATH_OUT="$(docker-helper config show admin_token_path 2>/dev/null)"
if [ "$ADMIN_PATH_OUT" = "/etc/docker-helper/admin.token" ]; then
  reg_ok "admin token path is the canonical /etc/docker-helper/admin.token"
else
  reg_fail "admin token path is '$ADMIN_PATH_OUT' (expected /etc/docker-helper/admin.token)"
fi

MODE_OUT="$(docker-helper config show mode 2>&1)"
MODE_RC=$?
if [ "$MODE_RC" -ne 0 ]; then
  reg_ok "config show mode no longer exists (there is no deployment mode to project)"
else
  reg_fail "config show mode still resolves (rc=$MODE_RC, output: $MODE_OUT)"
fi

# ---------------------------------------------------------------------------
# E. the mode-selection grammar is gone.
# ---------------------------------------------------------------------------
SYS_OUT="$(docker-helper session list --system 2>&1)"
SYS_RC=$?
if [ "$SYS_RC" -eq 2 ] && printf '%s\n' "$SYS_OUT" | grep -q "flag provided but not defined: -system"; then
  reg_ok "--system is no longer an operator flag"
else
  reg_fail "--system must be an undefined flag (rc=$SYS_RC, output below)
$(printf '%s\n' "$SYS_OUT" | redact | head -5)"
fi

for cmd_help in "reload --help" "session list --help"; do
  HELP_OUT="$(docker-helper $cmd_help 2>&1)"
  if printf '%s\n' "$HELP_OUT" | grep -q -- "--system"; then
    reg_fail "$cmd_help still carries the --system mode-selection flag"
  else
    reg_ok "$cmd_help carries no --system mode-selection flag"
  fi
done

reg_result
