#!/usr/bin/env bash
#
# diagnose-launch.sh — the standalone bounded diagnostic for the lab VM
# container launch path. Runs as root INSIDE the lab VM; the ladder itself
# runs as the agent account (the trusted launcher context) so the replayed
# configuration matches the production launch contract.
#
# What it is: the D0-D4 diagnostic ladder (see lab-diag-lib.sh) plus safe
# evidence collection. It never runs the integration UAT, never starts the
# model's real workload and never touches an LLM. The compact report and
# the private evidence directory are its whole output; when the cause is
# not proven by the ladder's own evidence it is reported UNRESOLVED, never
# guessed.
#
# Secrets: no Session bearer, principal credential, LLM key, SSH private
# key or full environment is ever printed; no shell tracing is enabled; the
# public output is a strict allowlist (the compact ladder report plus the
# predefined safe evidence fields — no raw docker top argv, no Docker error
# strings, no environment or shell payload); all raw artifacts live in a
# private mktemp directory and the unique workspace, both removed by the
# EXIT/INT/TERM traps.
#
# Cleanup contract: only resources this diagnostic created (its evidence
# directory, its named containers, its Session delta, its workspace and the
# per-step ssh agents started by the canonical launches) are cleaned; no
# other process is touched.
#
# Env: AGENT_USER (default agent).

set -u
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab-vm-guard.sh
. "$SCRIPT_DIR/lab-vm-guard.sh"
require_lab_vm

AGENT_USER="${AGENT_USER:-agent}"
AGENT_HOME="/home/$AGENT_USER"
[ "$(id -u)" = 0 ] || { echo "must run as root in the guest" >&2; exit 1; }
getent passwd "$AGENT_USER" >/dev/null || { echo "no $AGENT_USER account (run setup-agent-user.sh first)" >&2; exit 1; }
[ -S /run/docker.sock ] || { echo "docker socket missing" >&2; exit 1; }

# UAT-8e: the root driver prints sanitized evidence, so the SINGLE
# sanitization owner must be available HERE, not only in the child. The lib
# is installed at the same path the provisioning step ships; a missing owner
# is a hard failure — sanitization errors must never degrade into a PASS.
if [ -r /opt/lab/lab-diag-lib.sh ]; then
  # shellcheck source=/dev/null
  source /opt/lab/lab-diag-lib.sh
else
  echo "the sanitization owner is unavailable (/opt/lab/lab-diag-lib.sh missing); refusing to run" >&2
  exit 1
fi

DIAG_ROOT="$(mktemp -d)" || { echo "mktemp failed" >&2; exit 1; }
chmod 0711 "$DIAG_ROOT"
EVID="$DIAG_ROOT/evidence"
install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$EVID"

# The single cleanup owner (EXIT/INT/TERM): the unique diagnostic workspace
# and the private evidence root. A surviving path is a hard failure — the
# driver never reports success after failing to remove its own resources.
DIAG_WS=""
cleanup() {
  if ! diag_driver_cleanup "$DIAG_ROOT" "$DIAG_WS"; then
    printf 'CRITICAL: the diagnostic could not remove its own workspace or evidence; failing closed\n' >&2
    exit 1
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The unique diagnostic workspace: allocated ATOMICALLY under the agent's
# allowed root with an unpredictable name (mktemp -d, 0700, agent-owned,
# canonical-path verified). A pre-existing directory is never reused — a
# stale PID-named workspace holding other data is never touched and never
# removed. Uniqueness also keeps the Session ownership attribution exact:
# the diagnostic deletes only Sessions whose workspace equals THIS run's
# workspace.
DIAG_WS="$(diag_alloc_workspace "$AGENT_HOME" "$AGENT_USER")" || {
  echo "cannot allocate a unique diagnostic workspace under $AGENT_HOME/work" >&2
  exit 1
}
ws="$DIAG_WS"

RUNNER="$DIAG_ROOT/runner.sh"
cat > "$RUNNER" <<'SH'
#!/usr/bin/env bash
set -u
umask 077
EVID="$1"
cd "$2" || exit 1
# shellcheck source=/dev/null
source "$HOME/.bash_aliases"
# shellcheck source=/dev/null
source /opt/lab/lab-diag-lib.sh
DIAG_DIR="$EVID"
DIAG_RUNID="diag-$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | cut -c1-8)-$$"
export DIAG_DIR DIAG_RUNID
diag_run_ladder "$_OC_BASE" "$PWD" "$DIAG_RUNID"
SH
chmod 0755 "$RUNNER"

# The runner executes under script(1) so the canonical launches see the same
# pty context the production launcher sees in the operator's workflow.
# The pty transcript (the compact report and the launcher's stderr) flows to
# this script's stdout, so the operator sees the report directly; the
# separated evidence files stay in the private evidence directory.
sudo -u "$AGENT_USER" -H env EVID="$EVID" \
  script -qec "bash $RUNNER $EVID $ws" /dev/null
diag_rc=$?

# The compact report (the ladder's stdout) plus the safe allowlisted
# evidence summary — one owner (the lib), sanitized at print time.
diag_print_evidence_summary "$EVID" || {
  echo "the evidence summary could not be sanitized safely; failing closed" >&2
  exit 1
}
exit "$diag_rc"
