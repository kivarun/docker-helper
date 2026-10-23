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
# key or full environment is ever printed; no shell tracing is enabled; no
# raw docker inspect (an allowlist of state fields only); all artifacts
# live in a private mktemp directory removed by the EXIT/INT/TERM traps.
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

cleanup() {
  rm -rf -- "$DIAG_ROOT"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# the diagnostic workspace must live under the agent's allowed root so the
# canonical mount composition accepts it
ws="$AGENT_HOME/work/diag-$$"
install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$ws"

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
  rm -rf -- "$ws"
  exit 1
}
rm -rf -- "$ws"
exit "$diag_rc"
