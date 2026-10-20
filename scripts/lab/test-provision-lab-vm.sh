#!/usr/bin/env bash
#
# test-provision-lab-vm.sh — focused tests for the stage orchestration of
# scripts/lab/provision-lab-vm.sh (the guest-side scripts are recorded, not
# executed; each of them has its own suite).
#
# What this protects (one invariant per test):
#   1. `all` runs the stages in order: snapshot -> online (network OPEN) ->
#      isolate (network ISOLATED) -> verify;
#   2. the online stage runs the guest scripts in the dependency order
#      (docker -> agent phase 1 -> helper -> agent phase 2 -> operator files)
#      and pre-pulls both pinned images;
#   3. the VM stops before each posture change and after the online stage;
#   4. the snapshot is idempotent (an existing pre-provisioning snapshot is
#      kept, never recreated);
#   5. a missing VM disk fails the driver;
#   6. `verify` refuses to run when the VM is not running;
#   7. an unknown stage fails.
#
# Usage: scripts/lab/test-provision-lab-vm.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2' got '$3')"; fi; }
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2')" ;; esac; }

# --- fake repo tree ----------------------------------------------------------
REPO="$WORK/repo/scripts"
mkdir -p "$REPO/lab" "$WORK/vmstate"
cp "$SRC_DIR/lab/provision-lab-vm.sh" "$REPO/lab/"
# The whole lab directory is copied (like copy_lab_scripts does); the guest
# scripts are only RECORDED by the stub driver, never executed here.
for f in "$SRC_DIR"/lab/*.sh; do cp "$f" "$REPO/lab/"; done
for stub in probe-vm-isolation integration-agent-vm provision-operator-files; do
  printf '#!/usr/bin/env bash\necho "STUB %s ran"\n' "$stub" > "$REPO/lab/$stub.sh"
done
STATE="$WORK/state"; echo stopped > "$STATE"
DISK="$WORK/vmstate/disk.qcow2"; : > "$DISK"
SNAPMARK="$WORK/snap.pre-provisioning"
REC="$WORK/rec"; : > "$REC"

cat > "$REPO/dev-vm-local.sh" <<SH
#!/usr/bin/env bash
case "\${1:-}" in
  status)
    printf 'state:    %s\n' "\$(cat "$STATE")"
    printf 'workdir:  %s\n' "$WORK/vmstate"
    printf 'ssh:      127.0.0.1:2222 (user opc)\n' ;;
  stop)
    echo stop >> "$REC"; echo stopped > "$STATE" ;;
  start)
    echo "start isolated=\${DEV_VM_NET_ISOLATED:-unset}" >> "$REC"; echo running > "$STATE" ;;
  ssh)
    shift; echo "ssh \$1" >> "$REC"
    if [ "\$1" = "sudo tee /opt/lab/extra" ]; then cat > /dev/null; else cat > /dev/null 2>/dev/null || true; fi
    exit 0 ;;
  *) echo "stub: unknown op \$1" >&2; exit 2 ;;
esac
SH
chmod +x "$REPO/dev-vm-local.sh"

# qemu-img stub: keeps the snapshot marker in a file, records calls.
cat > "$WORK/qemu-img" <<SH
#!/usr/bin/env bash
case "\$1 \$2" in
  "snapshot -l") [ -f "$SNAPMARK" ] && printf '  1  pre-provisioning   0 B\n'; exit 0 ;;
  "snapshot -c") echo "\$3" >> "$REC"; touch "$SNAPMARK"; exit 0 ;;
esac
echo "qemu-img stub: unsupported call \$*" >&2
exit 2
SH
chmod +x "$WORK/qemu-img"

run_driver() { # stage...
  PATH="$WORK:$PATH" bash "$REPO/lab/provision-lab-vm.sh" "$@" >"$WORK/out" 2>&1
  RC=$?
  OUT="$(cat "$WORK/out")"
  return "$RC"
}

# --- 1/2/3. the full sequence -------------------------------------------------
: > "$REC"
echo stopped > "$STATE"
if run_driver all; then ok "all stages succeed"; else bad "all failed (rc $RC): $OUT"; fi
seq="$(cat "$REC")"
snapshot_line="$(printf '%s' "$seq" | grep -n '^pre-provisioning$' | head -1 | cut -d: -f1)"
online_start="$(printf '%s' "$seq" | grep -n '^start isolated=0$' | head -1 | cut -d: -f1)"
isolate_start="$(printf '%s' "$seq" | grep -n '^start isolated=1$' | head -1 | cut -d: -f1)"
if [ -n "$snapshot_line" ] && [ -n "$online_start" ] && [ -n "$isolate_start" ] \
   && [ "$snapshot_line" -lt "$online_start" ] && [ "$online_start" -lt "$isolate_start" ]; then
  ok "snapshot -> online(open) -> isolate(isolated) ordering holds"
else
  bad "stage ordering broken (snap=$snapshot_line online=$online_start isolate=$isolate_start)"
fi
contains "the VM stops before the isolated boot" "stop" "$seq"
first_docker="$(printf '%s' "$seq" | grep -n 'bash /opt/lab/install-docker-vm.sh' | head -1 | cut -d: -f1)"
agent1="$(printf '%s' "$seq" | grep -n 'bash /opt/lab/setup-agent-user.sh' | head -1 | cut -d: -f1)"
helper="$(printf '%s' "$seq" | grep -n 'bash /opt/lab/install-docker-helper-v230.sh' | head -1 | cut -d: -f1)"
agent2="$(printf '%s' "$seq" | grep -n 'bash /opt/lab/setup-agent-user.sh' | tail -1 | cut -d: -f1)"
if [ -n "$first_docker" ] && [ -n "$agent1" ] && [ -n "$helper" ] && [ -n "$agent2" ] \
   && [ "$first_docker" -lt "$agent1" ] && [ "$agent1" -lt "$helper" ] && [ "$helper" -lt "$agent2" ]; then
  ok "guest scripts run in the dependency order (docker, agent1, helper, agent2)"
else
  bad "guest script ordering broken ($first_docker/$agent1/$helper/$agent2)"
fi
check "both pinned images are pre-pulled" "2" "$(printf '%s' "$seq" | grep -c 'docker pull')"
contains "the lab scripts are copied into /opt/lab" "sudo tee /opt/lab/install-docker-vm.sh" "$seq"
contains "the integration runs last" "integration-agent-vm.sh" "$seq"
contains "the isolation probe runs in the isolate stage" "STUB probe-vm-isolation ran" "$OUT"
contains "operator file provisioning runs in the online stage" "STUB provision-operator-files ran" "$OUT"

# --- 4. snapshot idempotency ---------------------------------------------------
: > "$REC"
if run_driver snapshot; then ok "snapshot stage re-run succeeds"; else bad "snapshot re-run failed: $OUT"; fi
contains "existing snapshot is kept" "already exists" "$OUT"
check "no second snapshot was taken" "0" "$(grep -c '^pre-provisioning$' "$REC")"

# --- 5. missing disk fails -----------------------------------------------------
mv "$DISK" "$WORK/disk.bak"
if run_driver snapshot; then bad "missing disk accepted"; else ok "missing disk fails the driver"; fi
mv "$WORK/disk.bak" "$DISK"
rm -f "$SNAPMARK"

# --- 6. verify requires a running VM -------------------------------------------
echo stopped > "$STATE"
if run_driver verify; then bad "verify ran without a running VM"; else ok "verify refuses without a running VM"; fi
contains "verify names the prerequisite" "isolate stage first" "$OUT"

# --- 7. unknown stage -----------------------------------------------------------
if run_driver bogus; then bad "unknown stage accepted"; else ok "unknown stage fails"; fi

echo
printf 'provision-lab-vm tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
