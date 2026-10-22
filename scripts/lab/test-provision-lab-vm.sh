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
  cat > "$REPO/lab/$stub.sh" <<SH
#!/usr/bin/env bash
[ "\${FAIL_ON:-}" = "$stub" ] && { echo "stub $stub injected failure" >&2; exit 1; }
echo "STUB $stub ran"
SH
done
STATE="$WORK/state"; echo stopped > "$STATE"
DISK="$WORK/vmstate/disk.qcow2"; : > "$DISK"
SNAPMARK="$WORK/snap.pre-provisioning"
REC="$WORK/rec"; : > "$REC"

cat > "$REPO/dev-vm-local.sh" <<SH
#!/usr/bin/env bash
case "\${1:-}" in
  set-ipv6-disable)
    echo "set-ipv6-disable" >> "$REC"
    [ "\${FAIL_ON:-}" = ipv6 ] && { echo "stub: ipv6.disable bootstrap failed" >&2; exit 1; }
    exit 0 ;;
  status)
    printf 'state:    %s\n' "\$(cat "$STATE")"
    printf 'workdir:  %s\n' "$WORK/vmstate"
    printf 'ssh:      127.0.0.1:2222 (user opc)\n' ;;
  stop)
    echo stop >> "$REC"
    case "\${STOP_FAIL:-}" in
      stop) echo "stub: stop failed" >&2; exit 1 ;;
      stop-lying) echo "stub: stop claimed success" >&2; exit 0 ;;
      stop-unknown) echo unknown > "$STATE"; echo "stub: stop claimed success" >&2; exit 0 ;;
    esac
    [ "\${FAIL_ON:-}" = stop ] && { echo "stub: stop failed" >&2; exit 1; }
    echo stopped > "$STATE" ;;
  start)
    echo "start isolated=\${DEV_VM_NET_ISOLATED:-unset}" >> "$REC"
    case "\${FAIL_ON:-}" in
      start-open)
        echo running > "$STATE"
        echo started > "$WORK/start.marker"
        [ -p "$WORK/ctrl.fifo" ] && { read -t 15 _ < "$WORK/ctrl.fifo" || true; }
        echo "stub: start failed after boot (readiness)" >&2; exit 1 ;;
      start-stopped)
        echo stopped > "$STATE"
        echo "stub: start failed (VM never came up)" >&2; exit 1 ;;
    esac
    echo running > "$STATE" ;;
  ssh)
    [ "\${FAIL_ON:-}" = ssh-down ] && { echo "stub: ssh connection failed" >&2; exit 255; }
    shift; echo "ssh \$1" >> "$REC"
    cat > /dev/null 2>/dev/null || true
    case "\$1" in
      *INTEGRATION_NETWORKED=1*integration-agent-vm*)
        [ "\${FAIL_ON:-}" = integration ] && { echo "stub: networked integration failed" >&2; exit 1; } ;;
      *bash\ /opt/lab/diagnose-launch.sh*)
        [ "\${FAIL_ON:-}" = diagnose ] && { echo "stub: launch diagnostics reported failures" >&2; exit 3; }
        echo "D0 PASS rc=0 elapsed=1"
        echo "D4 PASS rc=0 elapsed=2" ;;
      *setup-agent-user.sh*)
        n=\$(( \$(cat "$WORK/setupcount" 2>/dev/null || echo 0) + 1 ))
        echo "\$n" > "$WORK/setupcount"
        if [ "\${FAIL_ON:-}" = "setup\$n" ]; then echo "stub: setup phase \$n failed" >&2; exit 1; fi ;;
      *install-docker-vm*) [ "\${FAIL_ON:-}" = docker ] && { echo "stub: docker install failed" >&2; exit 1; } ;;
      *install-docker-helper*) [ "\${FAIL_ON:-}" = helper ] && { echo "stub: helper install failed" >&2; exit 1; } ;;
      *curl\ --cacert*) [ "\${FAIL_ON:-}" = tls ] && { echo "stub: positive TLS failed" >&2; exit 1; }
        echo CA_TLS_OK ;;
      *CONTAINER_CA_CERT_READABLE*) echo CONTAINER_CA_CERT_READABLE ;;
      *CONTAINER_CA_NODE_OK*)
        if [ -f "$WORK/node-present" ]; then echo CONTAINER_CA_NODE_OK; else echo "stub: node absent in image" >&2; exit 1; fi ;;
      *CONTAINER_CA_OK*) echo CONTAINER_CA_OK ;;
      *CONTAINER_PUBLIC_OK*)
        case "\${FAIL_ON:-}" in
          public-fail) echo "stub: docker run failed" >&2; exit 1 ;;
          public-silent) exit 0 ;;
          public-marker-fail) echo CONTAINER_PUBLIC_OK; echo "stub: docker died after the marker" >&2; exit 1 ;;
        esac
        if [ "\${UAT7_EARLY_TAIL:-}" = 1 ]; then
          echo CONTAINER_PUBLIC_OK
          echo "diag echo: admin token LABUAT7SECRETVALUE" >&2
          head -c 200000 /dev/zero | tr '\0' 'x'
        fi
        echo CONTAINER_PUBLIC_OK ;;
      *oc_lab_mount_source_ok*)
        # UAT-3/F1: the guest mount gate runs INSIDE the agent's context. The
        # real guest semantics: the agent home is 0700 agent:agent, so a gate
        # run as opc (or as agent from an inaccessible cwd) cannot traverse
        # the source and must fail. The stub models that: only the
        # sudo-as-agent + cd-home invocation succeeds.
        case "\$1" in
          *'sudo -u agent -H bash -c'*'cd /home/agent'*'source /opt/lab/lab-mount-gate.sh'*)
            [ "\${FAIL_ON:-}" = gate ] && { echo "stub: mount gate refused" >&2; exit 1; }
            exit 0 ;;
          *)
            echo "stub: gate run without the agent context (opc cannot traverse /home/agent)" >&2
            exit 1 ;;
        esac ;;
      *combined-ca-bundle.crt*)
        if [ -f "$WORK/combined-present" ]; then exit 0; else exit 1; fi ;;
      *docker\ pull*) [ "\${FAIL_ON:-}" = pull ] && { echo "stub: pull failed" >&2; exit 1; } ;;
    esac
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

# qemu argv evidence source (the pgrep stub reads this file); the isolated
# argv is the default so the happy-path flows find a provably isolated VM.
QEMU_ARGV="$WORK/qemu.argv"
cat > "$WORK/pgrep" <<SH
#!/usr/bin/env bash
case "\$*" in
  *qemu-system*) cat "$QEMU_ARGV" 2>/dev/null ;;
  *) exit 1 ;;
esac
SH
chmod +x "$WORK/pgrep"
ISOLATED_ARGV="qemu-system-x86_64 -machine q35 -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22,restrict=on -device virtio-net-pci,netdev=net0 -drive file=$WORK/vmstate/disk.qcow2,if=virtio,format=qcow2"
ONLINE_ARGV="qemu-system-x86_64 -machine q35 -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=net0 -drive file=$WORK/vmstate/disk.qcow2,if=virtio,format=qcow2"
printf '1234 %s\n' "$ISOLATED_ARGV" > "$QEMU_ARGV"

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

# --- F2. the online window closes on ANY failure --------------------------------
# Injection on every post-start transition: the VM must be stopped, the
# failure must not look like success, and a failing stop must produce an
# explicit CRITICAL with the recovery command.
run_f2() { # FAIL_ON_VALUE
  echo stopped > "$STATE"; : > "$REC"; rm -f "$SNAPMARK"; rm -f "$WORK/setupcount"
  FAIL_ON="$1" run_driver online
}

f2_case() { # NAME
  local name="$1"
  if [ "$RC" = 0 ]; then bad "F2/$name: the online stage reported success"; else ok "F2/$name: the failure is not a success"; fi
  if printf '%s' "$OUT" | grep -q "online stage done"; then bad "F2/$name: false success message"; else ok "F2/$name: no success message"; fi
  local seq2 open_line stop_line
  seq2="$(cat "$REC")"
  open_line="$(printf '%s' "$seq2" | grep -n '^start isolated=0$' | head -1 | cut -d: -f1)"
  stop_line="$(printf '%s' "$seq2" | grep -n '^stop$' | head -1 | cut -d: -f1)"
  if [ -n "$open_line" ] && [ -n "$stop_line" ] && [ "$stop_line" -gt "$open_line" ]; then
    ok "F2/$name: the VM was stopped after the failure"
  else
    bad "F2/$name: the VM was left with the network open"
  fi
  check "F2/$name: final VM state is stopped" "stopped" "$(cat "$STATE")"
}

for injected in docker setup1 helper setup2 provision-operator-files pull; do
  run_f2 "$injected"
  f2_case "$injected"
done

export LAB_CA_SOURCE="$WORK/ca-src"; export LAB_CA_TEST_URL="https://ca-test.example/"
run_f2 tls
unset LAB_CA_SOURCE LAB_CA_TEST_URL
f2_case tls

STOP_FAIL=stop run_f2 stop
if [ "$RC" != 0 ]; then ok "F2/stop: the stop failure propagates"; else bad "F2/stop: tolerated"; fi
contains "F2/stop: CRITICAL is reported" "CRITICAL" "$OUT"
contains "F2/stop: the recovery command is given" "dev-vm-local.sh stop" "$OUT"
not_contains "F2/stop: no false success" "online stage done" "$OUT"
check "F2/stop: the VM state is honestly still running" "running" "$(cat "$STATE")"

# the preflight closes a leftover open VM from a killed previous run
echo running > "$STATE"; : > "$REC"; rm -f "$SNAPMARK"
run_driver online
preflight_stop="$(printf '%s' "$(cat "$REC")" | grep -n '^stop$' | head -1 | cut -d: -f1)"
preflight_open="$(printf '%s' "$(cat "$REC")" | grep -n '^start isolated=0$' | head -1 | cut -d: -f1)"
if [ -n "$preflight_stop" ] && [ -n "$preflight_open" ] && [ "$preflight_stop" -lt "$preflight_open" ]; then
  ok "F2/preflight: a leftover open VM is stopped before the window opens"
else
  bad "F2/preflight: the leftover open VM was not closed first"
fi

# --- F3. verify refuses anything it cannot prove isolated --------------------
run_verify() { # the VM state must be set by the caller
  : > "$REC"
  PATH="$WORK:$PATH" bash "$REPO/lab/provision-lab-vm.sh" verify >"$WORK/out" 2>&1
  RC=$?
  OUT="$(cat "$WORK/out")"
  return "$RC"
}

echo stopped > "$STATE"
if run_verify; then bad "F3: verify ran with the VM stopped"; else ok "F3: verify refuses a stopped VM"; fi
echo running > "$STATE"

echo running > "$STATE"; printf '1234 %s\n' "$ONLINE_ARGV" > "$QEMU_ARGV"
if run_verify; then bad "F3: verify accepted an ONLINE VM"; else ok "F3: verify refuses a VM booted with the network open"; fi
contains "F3: the refusal names the missing isolation" "restrict=on" "$OUT"

printf '1234 %s\n1235 %s\n' "$ISOLATED_ARGV" "$ISOLATED_ARGV" > "$QEMU_ARGV"
if run_verify; then bad "F3: verify accepted an ambiguous QEMU state"; else ok "F3: verify refuses an ambiguous QEMU PID set"; fi

: > "$QEMU_ARGV"
if run_verify; then bad "F3: verify accepted a missing QEMU process"; else ok "F3: verify refuses when no QEMU process matches the VM disk"; fi

printf '1234 %s\n' "$ISOLATED_ARGV" > "$QEMU_ARGV"
if FAIL_ON=probe-vm-isolation run_verify; then bad "F3: verify ran without a passing probe"; else ok "F3: verify refuses when the network probe cannot run"; fi

# a lying state file must not produce a PASS: the argv evidence decides
echo isolated-not-running-marker > "$STATE"; : > "$QEMU_ARGV"
if run_verify; then bad "F3: a substituted state produced a PASS"; else ok "F3: verify does not trust bookkeeping state alone"; fi

echo running > "$STATE"; printf '1234 %s\n' "$ISOLATED_ARGV" > "$QEMU_ARGV"
if run_verify; then
  ok "F3: a provably isolated VM allows the integration"
  contains "F3: the probe ran before the integration" "STUB probe-vm-isolation ran" "$OUT"
  contains "F3: the integration ran after the probe" "sudo bash /opt/lab/integration-agent-vm.sh" "$(cat "$REC")"
else
  bad "F3: the isolated case failed: $OUT"
fi

# --- R5. online diagnostics pass the SAME mount-source gate ------------------
# The one-off diagnostic container must consult the shared mount gate (the
# same library the launcher uses) BEFORE any docker run, and must refuse an
# unsafe source without running docker at all. UAT-3/F1: the gate refusal is
# exercised at the REAL gate invocation (a CA is configured so the driver
# actually consults the gate inside the agent's context).
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" FAIL_ON=gate run_driver online
if [ "$RC" != 0 ]; then ok "R5: diagnostics refuse when the mount gate fails"; else bad "R5: diagnostics ran despite a gate failure"; fi
if printf '%s' "$(cat "$REC")" | grep -q 'docker run'; then
  bad "R5: a diagnostic docker run happened after the gate refused"
else
  ok "R5: no diagnostic docker run after the gate refusal"
fi

: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
run_driver online
rec="$(cat "$REC")"
gate_line="$(printf '%s' "$rec" | grep -n 'lab-mount-gate' | head -1 | cut -d: -f1)"
docker_line="$(printf '%s' "$rec" | grep -n 'docker run' | head -1 | cut -d: -f1)"
if [ -n "$gate_line" ] && [ -n "$docker_line" ] && [ "$gate_line" -lt "$docker_line" ]; then
  ok "R5: the gate is consulted before the diagnostic docker run"
else
  bad "R5: the diagnostic docker run is not gated (gate=$gate_line docker=$docker_line)"
fi

# --- UAT-7. the marker diagnostics consume the whole driver output -----------
# The old `ssh ... | grep -q MARKER` diagnostics closed the read pipe as
# soon as grep matched; the SSH driver's remaining output then died with
# SIGPIPE (rc 141) and, under set -o pipefail, turned a real PASS into a
# false FAIL (the real UAT reproduction). A marker is now searched only
# AFTER the driver output is fully consumed and its exit status is checked
# separately: an SSH/Docker/TLS failure must never pass because the marker
# text appeared somewhere in its output, a zero exit without the marker is
# not evidence, and the captured payload is never printed.
uat7_run() { # [EXTRA-ENV...] — run the online diagnostics with a fresh state
  : > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
  # the combined-bundle fixture puts the corporate container evidence on the
  # deterministic curl path (no dependence on the Node fixture)
  : > "$WORK/combined-present"; : > "$WORK/node-present"
  run_driver online
}

# U7.1 RED: the marker appears early, a large driver tail follows it —
# the diagnostics must still pass (and print nothing of the payload)
if LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" UAT7_EARLY_TAIL=1 uat7_run online; then
  ok "UAT-7: an early marker with a large trailing output still passes"
else
  bad "UAT-7 RED: the SIGPIPE race turned a real PASS into a failure (rc $RC): $(printf '%s' "$OUT" | grep -E 'ERROR|CRITICAL|exited|marker' | head -3)"
fi
contains "UAT-7: the public evidence is recorded" "positive TLS evidence recorded (container, public)" "$OUT"
case "$OUT" in
  *LABUAT7SECRETVALUE*) bad "UAT-7: the diagnostic payload leaked into the output" ;;
  *) ok "UAT-7: the diagnostic payload is not printed" ;;
esac
case "$OUT" in
  *xxxxxxxxxxxxxxxxxxxx*) bad "UAT-7: the driver tail leaked into the output" ;;
  *) ok "UAT-7: the driver tail is not printed" ;;
esac

# U7.2 a failed diagnostic cannot pass on the marker alone
if LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" FAIL_ON=public-marker-fail uat7_run online; then
  bad "UAT-7 RED: a failed diagnostic passed because its output contained the marker"
else
  ok "UAT-7: a failed diagnostic cannot pass on the marker alone"
fi

# U7.3 an SSH-level connection failure fails the diagnostic
if LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" FAIL_ON=ssh-down uat7_run online; then
  bad "UAT-7: an SSH connection failure passed the diagnostic"
else
  ok "UAT-7: an SSH connection failure fails the diagnostic"
fi

# U7.4 a zero exit without the marker is not evidence
if LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" FAIL_ON=public-silent uat7_run online; then
  bad "UAT-7: a marker-less exit 0 passed the diagnostic"
else
  ok "UAT-7: a zero exit without the marker fails the diagnostic"
fi

# U7.5 a Docker failure (an error, no marker) fails the diagnostic
if LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" FAIL_ON=public-fail uat7_run online; then
  bad "UAT-7: a docker failure passed the diagnostic"
else
  ok "UAT-7: a docker failure fails the diagnostic"
fi

# U7.6 the guest TLS failure keeps failing
if LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" FAIL_ON=tls uat7_run online; then
  bad "UAT-7: the guest TLS failure passed the diagnostic"
else
  ok "UAT-7: the guest TLS failure fails the diagnostic"
fi

# --- R2. the lifecycle owns the online start ATTEMPT itself ------------------
# The window opens with the start attempt: a failed start with a booted QEMU
# must still close the window; a failed stop or an unverifiable state must
# produce CRITICAL, never success.
r2_run() { # extra env via caller exports; runs the online stage
  echo stopped > "$STATE"; : > "$REC"; rm -f "$SNAPMARK"; rm -f "$WORK/setupcount"
  run_driver online
}

# R2.1 start fails, QEMU is up (state running) -> the cleanup stops the VM
FAIL_ON=start-open r2_run
if [ "$RC" != 0 ]; then ok "R2: a failed online start is a failure"; else bad "R2: a failed start looked successful"; fi
stop_line="$(printf '%s' "$(cat "$REC")" | grep -n '^stop$' | head -1 | cut -d: -f1)"
start_line="$(printf '%s' "$(cat "$REC")" | grep -n '^start isolated=0$' | head -1 | cut -d: -f1)"
if [ -n "$stop_line" ] && [ -n "$start_line" ] && [ "$stop_line" -gt "$start_line" ]; then
  ok "R2: the failed start still stopped the VM"
else
  bad "R2: the VM stayed network-open after a failed start"
fi
check "R2: final state after a failed start" "stopped" "$(cat "$STATE")"

# R2.2 start fails, the VM never came up -> clean error, no stop attempt
: > "$REC"
FAIL_ON=start-stopped r2_run
if [ "$RC" != 0 ]; then ok "R2: a failed start without a VM is an error"; else bad "R2: tolerated a dead start"; fi
if printf '%s' "$(cat "$REC")" | grep -q '^stop$'; then bad "R2: a needless stop was attempted"; else ok "R2: no stop attempt when the VM never started"; fi
if printf '%s' "$OUT" | grep -q CRITICAL; then bad "R2: CRITICAL noise on a clean failure"; else ok "R2: no CRITICAL when the VM was never up"; fi

# R2.3 stop returns 0 but the VM is still running -> CRITICAL
STOP_FAIL=stop-lying FAIL_ON=docker r2_run
if [ "$RC" != 0 ]; then ok "R2: a lying stop is a failure"; else bad "R2: a lying stop looked successful"; fi
contains "R2: a lying stop produces CRITICAL" "CRITICAL" "$OUT"
contains "R2: the CRITICAL names the actual state" "running" "$OUT"

# R2.4 stop returns 0 but the status is unknown -> CRITICAL
STOP_FAIL=stop-unknown FAIL_ON=docker r2_run
if [ "$RC" != 0 ]; then ok "R2: an unknown post-stop state is a failure"; else bad "R2: an unknown state looked successful"; fi
contains "R2: an unknown state produces CRITICAL" "CRITICAL" "$OUT"

# R2.6 SIGINT during the online start -> the window is closed
mkfifo "$WORK/ctrl.fifo" 2>/dev/null || true
echo stopped > "$STATE"; : > "$REC"; rm -f "$SNAPMARK"
( FAIL_ON=start-open PATH="$WORK:$PATH" bash "$REPO/lab/provision-lab-vm.sh" online ) >"$WORK/out" 2>&1 &
r2_sig_pid=$!
for _ in $(seq 1 50); do [ -e "$WORK/start.marker" ] && break; sleep 0.1; done
kill -INT "$r2_sig_pid" 2>/dev/null || true
printf '\n' > "$WORK/ctrl.fifo"
wait "$r2_sig_pid" 2>/dev/null
r2_sig_rc=$?
rm -f "$WORK/ctrl.fifo" "$WORK/start.marker"
if [ "$r2_sig_rc" != 0 ]; then ok "R2: an interrupted start is a failure"; else bad "R2: an interrupted start looked successful"; fi
stop_line="$(printf '%s' "$(cat "$REC")" | grep -n '^stop$' | head -1 | cut -d: -f1)"
if [ -n "$stop_line" ]; then ok "R2: the interrupted start closed the window"; else bad "R2: the interrupted start left the window open"; fi

# R2.7 all does not reach isolate when the online window cannot be closed
echo stopped > "$STATE"; : > "$REC"; rm -f "$SNAPMARK"
STOP_FAIL=stop-lying FAIL_ON=docker run_driver all
if [ "$RC" != 0 ]; then ok "R2: a failed close fails the whole run"; else bad "R2: the run continued past a failed close"; fi
if printf '%s' "$(cat "$REC")" | grep -q '^start isolated=1$'; then
  bad "R2: all proceeded to isolate after a failed close"
else
  ok "R2: all never reaches isolate after a failed close"
fi

# --- R6. driver-supplied URLs are validated before any guest command ---------
r6_url_case() { # LABEL VALUE EXPECT(accept|reject)
  : > "$WORK/combined-present"; : > "$WORK/node-present"
  : > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"; rm -f "$WORK/setupcount"
  LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="$2" run_driver online
  if [ "$3" = reject ]; then
    if [ "$RC" != 0 ]; then ok "R6/driver-url/$1: rejected"; else bad "R6/driver-url/$1: accepted"; fi
  else
    if [ "$RC" = 0 ]; then ok "R6/driver-url/$1: accepted"; else bad "R6/driver-url/$1: rejected: $(tail -3 "$WORK/out" | tr '\n' '|')"; fi
  fi
  if printf '%s' "$(cat "$REC")" | grep -qF 'touch BAD'; then
    bad "R6/driver-url/$1: the payload reached a guest command"
  else
    ok "R6/driver-url/$1: the payload never reached the guest"
  fi
}
for evil in 'https://h/;touch BAD' 'https://h/$(touch BAD)' 'https://h/`touch BAD`' 'https://h/ R' 'http://h/ok'; do
  r6_url_case "evil-$evil" "$evil" reject
done
r6_url_case "valid-path" "https://corporate.example/health" accept
r6_url_case "valid-port" "https://ca.corp.example:8443/pkix" accept

# --- F1. diagnostic containers run as the authorized docker user -------------
# Rootful Docker access belongs to the agent account only; opc must not gain
# it. Every diagnostic docker run must therefore be executed as agent inside
# the guest.
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
run_driver online
rec="$(cat "$REC")"
if printf '%s' "$rec" | grep -q 'sudo -u agent -H docker run'; then
  ok "F1: the diagnostics run docker as the agent account"
else
  bad "F1: a diagnostic docker run is not executed as agent"
fi
if printf '%s' "$rec" | grep 'docker run' | grep -vq 'sudo -u agent -H docker run'; then
  bad "F1: an unprivileged docker run path exists"
else
  ok "F1: no diagnostic docker run bypasses the agent authorization"
fi

# --- F2. the TLS diagnostics follow the launcher's trust contract ------------
f2_tls_run() { # -> the recorded docker run lines of the online stage
  : > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"; rm -f "$WORK/setupcount"
  run_driver online >/dev/null 2>&1
  RC=$?
  printf '%s' "$(cat "$REC")" | grep 'docker run'
}

# F2/a: no CA at all -> no trust-replacing variables anywhere
rm -f "$WORK/combined-present"
envs="$(f2_tls_run | grep -o '\-e [A-Z_]*' | sort -u | tr '\n' ' ')"
if printf '%s' "$envs" | grep -qE 'SSL_CERT_FILE|CURL_CA_BUNDLE|GIT_SSL_CAINFO|NODE_EXTRA_CA_CERTS'; then
  bad "F2/a: trust variables set without any provisioned CA"
else
  ok "F2/a: no CA -> no trust variables at all"
fi

# F2/b: CA + combined bundle -> the full launcher contract
: > "$WORK/combined-present"
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" run_driver online >/dev/null 2>&1
envs="$(printf '%s' "$(cat "$REC")" | grep 'docker run' | grep -oE '\-e [A-Z_]+=[^ ]*' | sort -u | tr '\n' ' ')"
for want in NODE_EXTRA_CA_CERTS SSL_CERT_FILE CURL_CA_BUNDLE GIT_SSL_CAINFO; do
  if printf '%s' "$envs" | grep -q "$want"; then ok "F2/b: $want is set with the combined bundle"; else bad "F2/b: $want missing with the combined bundle (envs=$envs)"; fi
done

# F2/c: CA WITHOUT the combined bundle -> NODE only, no replacing variables,
# and no container corporate check that could produce a false PASS
rm -f "$WORK/combined-present"
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" run_driver online >/dev/null 2>&1
rec="$(cat "$REC")"
if printf '%s' "$rec" | grep 'docker run' | grep -q 'NODE_EXTRA_CA_CERTS'; then
  ok "F2/c: NODE_EXTRA_CA_CERTS is set with the corporate CA"
else
  bad "F2/c: NODE_EXTRA_CA_CERTS missing"
fi
if printf '%s' "$rec" | grep 'docker run' | grep -qE 'SSL_CERT_FILE|CURL_CA_BUNDLE|GIT_SSL_CAINFO'; then
  bad "F2/c: replacing trust variables point at a nonexistent combined bundle: $(printf '%s' "$rec" | grep 'docker run' | grep -oE '\-e (SSL_CERT_FILE|CURL_CA_BUNDLE|GIT_SSL_CAINFO)=[^ ]*' | head -2)"
else
  ok "F2/c: no replacing trust variables without the combined bundle"
fi
if printf '%s' "$rec" | grep 'docker run' | grep -q 'CONTAINER_CA_OK'; then
  bad "F2/c: a curl-based corporate check ran without the combined bundle"
else
  ok "F2/c: no curl-based corporate check without the combined bundle"
fi
if printf '%s' "$rec" | grep 'docker run' | grep -q 'CONTAINER_CA_NODE_OK'; then
  ok "F2/c: the Node-only corporate check covers the CA-without-combined case"
else
  bad "F2/c: no Node-only corporate evidence for CA without the combined bundle"
fi

# --- F6. the certificate path and its in-container evidence ------------------
# F6/a: the NODE_EXTRA_CA_CERTS path carries the .crt suffix that matches the
# provisioner's and launcher's naming contract.
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
LAB_CA_SOURCE="$WORK/ca-src" run_driver online >/dev/null 2>&1
if printf '%s' "$(cat "$REC")" | grep 'docker run' | grep -q 'NODE_EXTRA_CA_CERTS=/etc/opencode-ca/ca-src.crt'; then
  ok "F6/a: NODE_EXTRA_CA_CERTS uses the .crt naming contract"
else
  bad "F6/a: NODE_EXTRA_CA_CERTS path diverges from the provisioner naming"
fi

# F6/b: the corporate container check proves the certificate is readable
# inside the container before claiming success.
: > "$WORK/combined-present"
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" run_driver online >/dev/null 2>&1
if printf '%s' "$(cat "$REC")" | grep 'docker run' | grep -q 'CONTAINER_CA_CERT_READABLE'; then
  ok "F6/b: the corporate container check verifies certificate readability"
else
  bad "F6/b: no in-container certificate readability evidence: $(printf '%s' "$(cat "$REC")" | grep -c 'docker run') docker runs recorded"
fi

# F6/c: without the combined bundle, the corporate chain is validated through
# Node when the image provides it.
rm -f "$WORK/combined-present"; : > "$WORK/node-present"
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" run_driver online >/dev/null 2>&1
if printf '%s' "$(cat "$REC")" | grep 'docker run' | grep -q 'CONTAINER_CA_NODE_OK'; then
  ok "F6/c: the corporate chain is validated through Node without the combined bundle"
else
  bad "F6/c: no Node-based corporate TLS evidence"
fi

# F6/d: when Node is absent in the image, the missing evidence fails the
# online stage and closes the window (no false PASS).
rm -f "$WORK/node-present"
echo stopped > "$STATE"; rm -f "$SNAPMARK"
LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" run_driver online >/dev/null 2>&1; rc=$?
if [ "$rc" != 0 ]; then
  ok "F6/d: missing Node evidence fails the online stage"
else
  bad "F6/d: a missing Node TLS evidence produced a PASS"
fi
if [ "$(cat "$STATE")" = stopped ]; then
  ok "F6/d: the online window is closed on the failed diagnostic"
else
  bad "F6/d: the online window stayed open after the failed diagnostic"
fi

# --- UAT-3/F1. the guest mount gate runs inside the agent's context ----------
# Real UAT: 'ERROR: the diagnostic CA mount source failed the shared mount
# gate' although the source was fine — the gate ran as opc, and the agent
# home (0700 agent:agent) cannot be traversed by opc; find also cannot
# restore an unreachable working directory. The gate invocation must run as
# agent (sudo -u agent -H), from /home/agent, loading the trusted
# /opt/lab/lab-mount-gate.sh. The stub models the real guest semantics: only
# that invocation shape succeeds.
: > "$WORK/combined-present"; : > "$WORK/node-present"
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
LAB_CA_SOURCE="$WORK/ca-src" LAB_CA_TEST_URL="https://corp.example.test/" run_driver online
gate_line="$(printf '%s' "$(cat "$REC")" | grep 'oc_lab_mount_source_ok' | head -1)"
if printf '%s' "$gate_line" | grep -q 'sudo -u agent -H'; then
  ok "UAT-3/F1: the gate is executed as the agent (sudo -u agent -H)"
else
  bad "UAT-3/F1: the gate is not executed as the agent: $gate_line"
fi
if printf '%s' "$gate_line" | grep -q 'cd /home/agent'; then
  ok "UAT-3/F1: the gate runs from the agent's home (an inaccessible cwd cannot break find)"
else
  bad "UAT-3/F1: the gate does not start from the agent home"
fi
if printf '%s' "$gate_line" | grep -q '/opt/lab/lab-mount-gate.sh'; then
  ok "UAT-3/F1: the gate library is loaded from the trusted /opt/lab copy"
else
  bad "UAT-3/F1: the gate library is not loaded from /opt/lab"
fi
if [ "$RC" = 0 ]; then
  ok "UAT-3/F1: the diagnostics complete when the gate runs in the agent's context"
else
  bad "UAT-3/F1: the diagnostics failed although the gate ran as agent"
fi

# --- UAT-4/F2. the guest boot config is set while the VM is up, fail-closed --
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
run_driver online >/dev/null 2>&1
ipv6_ln="$(printf '%s' "$(cat "$REC")" | grep -n '^set-ipv6-disable' | head -1 | cut -d: -f1)"
stop_ln="$(printf '%s' "$(cat "$REC")" | grep -n '^stop' | head -1 | cut -d: -f1)"
if [ -n "$ipv6_ln" ] && [ -n "$stop_ln" ] && [ "$ipv6_ln" -lt "$stop_ln" ]; then
  ok "UAT-4/F2: the ipv6.disable bootstrap runs while the VM is up (before the window closes)"
else
  bad "UAT-4/F2: the ipv6.disable bootstrap ordering is wrong (ipv6=$ipv6_ln stop=$stop_ln)"
fi
echo stopped > "$STATE"; rm -f "$SNAPMARK"
FAIL_ON=ipv6 run_driver online >/dev/null 2>&1
if [ "$RC" != 0 ]; then
  ok "UAT-4/F2: a failed ipv6.disable bootstrap fails the online stage"
else
  bad "UAT-4/F2: a failed ipv6.disable bootstrap was tolerated"
fi
if printf '%s' "$OUT" | grep -q "setting ipv6.disable=1 in the guest boot config failed"; then
  ok "UAT-4/F2: the failure names the ipv6.disable step"
else
  bad "UAT-4/F2: the ipv6.disable failure reason is missing"
fi

# --- UAT-3b. the gate command is a SINGLE bash process (really executed) -----
# The reviewer's blocker: `sudo -u agent -H sh -c "cd ... && bash lib && func"`
# defines the function in a CHILD bash that exits; the parent sh then calls a
# function it never had. This test extracts the ACTUAL remote command from the
# production driver, executes its shell semantics for real (the VM's
# `sudo -u agent -H` user switch is the only part replaced) against the REAL
# gate library and a private temp tree, and proves positive and negative
# outcomes.
uat3b_home="$(mktemp -d "$WORK/uat3b-home.XXXXXX")"
chmod 0700 "$uat3b_home"
mkdir -p "$uat3b_home/.opencode-docker/ca"
printf 'SAFE-CA\n' > "$uat3b_home/.opencode-docker/ca/anchor.crt"
uat3b_lib="$uat3b_home/lib/lab-mount-gate.sh"
mkdir -p "$uat3b_home/lib"
cp "$SRC_DIR/lab/lab-mount-gate.sh" "$uat3b_lib"

uat3b_raw="$(grep -F 'oc_lab_mount_source_ok dir /home/agent' "$SRC_DIR/lab/provision-lab-vm.sh" | head -1)"
uat3b_cmd="$(printf '%s' "$uat3b_raw" | sed -n "s/^.*ssh '\(.*\)'.*$/\1/p")"
if [ -n "$uat3b_cmd" ]; then
  ok "UAT-3b: the remote gate command is extracted from the production driver"
else
  bad "UAT-3b: the remote gate command could not be extracted: $uat3b_raw"
fi
case "$uat3b_cmd" in
  'sudo -u agent -H bash -c '*)
    ok "UAT-3b: the gate runs as agent inside ONE bash -c process"
    ;;
  *)
    bad "UAT-3b: the gate command lost the sudo-as-agent single-bash structure: $uat3b_cmd"
    ;;
esac
uat3b_exec="${uat3b_cmd#sudo -u agent -H }"
uat3b_exec="${uat3b_exec//\/home\/agent/$uat3b_home}"
uat3b_exec="${uat3b_exec//\/opt\/lab\/lab-mount-gate.sh/$uat3b_lib}"

# positive: a safe agent-owned tree passes through the real gate invocation
if bash -c "$uat3b_exec" >/dev/null 2>&1; then
  ok "UAT-3b: the real command execution passes a safe source (cd + source + call in one bash)"
else
  bad "UAT-3b: the real command execution failed on a safe source: $(bash -c "$uat3b_exec" 2>&1 | tail -1)"
fi

# negative: a missing gate library fails closed
uat3b_missing="${uat3b_exec//$uat3b_lib/$uat3b_home/lib/missing.sh}"
if bash -c "$uat3b_missing" >/dev/null 2>&1; then
  bad "UAT-3b: a missing gate library was tolerated"
else
  ok "UAT-3b: a missing gate library fails closed"
fi

# negative: an unsafe source (a symlinked entry) is refused by the real gate
ln -s /etc/passwd "$uat3b_home/.opencode-docker/ca/evil.crt"
if bash -c "$uat3b_exec" >/dev/null 2>&1; then
  bad "UAT-3b: a symlinked source entry was accepted by the real gate invocation"
else
  ok "UAT-3b: an unsafe source is refused by the real gate invocation"
fi
rm -f "$uat3b_home/.opencode-docker/ca/evil.crt"

# negative: an unreadable nested directory makes the gate refuse (fail closed)
mkdir -p "$uat3b_home/.opencode-docker/ca/locked"
printf 'X\n' > "$uat3b_home/.opencode-docker/ca/locked/f.crt"
chmod 000 "$uat3b_home/.opencode-docker/ca/locked"
if bash -c "$uat3b_exec" >/dev/null 2>&1; then
  bad "UAT-3b: an unreadable nested directory was accepted"
else
  ok "UAT-3b: a refusing check fails the invocation closed"
fi
chmod 0755 "$uat3b_home/.opencode-docker/ca/locked"

# --- UAT-8. the explicit networked integration UAT stage ---------------------
# A networked UAT window is an EXPLICIT stage: it boots with the network
# open, runs the integration suite with INTEGRATION_NETWORKED=1, then closes
# the window and confirms the VM is stopped. It never runs the isolation
# probe and never claims isolation; the isolation evidence stays with the
# isolate/verify stages.
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
if run_driver uat-networked; then
  ok "UAT-8: the networked UAT stage succeeds"
else
  bad "UAT-8: the networked UAT stage failed (rc $RC): $OUT"
fi
seq="$(cat "$REC")"
contains "UAT-8: the networked window boots with the network open" "start isolated=0" "$seq"
contains "UAT-8: the integration runs in the networked mode" \
  "sudo env INTEGRATION_NETWORKED=1 bash /opt/lab/integration-agent-vm.sh" "$seq"
if case "$OUT" in *"proving the isolated network posture"*) true ;; *) false ;; esac; then
  bad "UAT-8: the networked stage ran the isolation posture proof"
else
  ok "UAT-8: the networked stage makes no isolation claim"
fi
state_line="$(cat "$STATE" 2>/dev/null)"
check "UAT-8: the window closes with a confirmed stopped VM" "stopped" "$state_line"
contains "UAT-8: the stage confirms the closed window" \
  "networked UAT stage done (the network window is closed and the VM is confirmed stopped)" "$OUT"

# a failed networked integration must close the window and fail the stage
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
if FAIL_ON=integration run_driver uat-networked; then
  bad "UAT-8: a failed networked integration was accepted"
else
  ok "UAT-8: a failed networked integration fails the stage"
fi
state_line="$(cat "$STATE" 2>/dev/null)"
check "UAT-8: the window is still closed after the failed integration" "stopped" "$state_line"
contains "UAT-8: the stop happens despite the failure" "stop" "$(cat "$REC")"

# the isolated path is untouched: verify still requires the isolation evidence
if FAIL_ON=probe-vm-isolation run_verify; then bad "UAT-8: verify regressed"; else ok "UAT-8: verify still refuses without a passing isolation probe"; fi

# --- UAT-8c. the explicit launch-diagnostic stage ----------------------------
# The diagnostic window is its own stage: it boots with the network open,
# runs the bounded D0-D4 ladder, and ALWAYS closes the window and confirms
# the VM is stopped — on a passing ladder and on a failing one. It never
# runs the integration UAT and never touches an LLM.
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
if run_driver uat-diagnose; then
  ok "UAT-8c: the diagnostic stage succeeds on a passing ladder"
else
  bad "UAT-8c: the diagnostic stage failed on a passing ladder (rc $RC): $OUT"
fi
seq="$(cat "$REC")"
contains "UAT-8c: the diagnostic window boots with the network open" "start isolated=0" "$seq"
contains "UAT-8c: the diagnostics run inside the VM" "sudo bash /opt/lab/diagnose-launch.sh" "$seq"
if printf '%s' "$seq" | grep -q 'sudo bash /opt/lab/integration-agent-vm.sh'; then
  bad "UAT-8c: the diagnostic stage ran the integration UAT"
else
  ok "UAT-8c: the diagnostic stage is independent of the integration UAT (the script copy is provisioning, not a run)"
fi
contains "UAT-8c: the ladder evidence reaches the driver output" "D0 PASS rc=0" "$OUT"
state_line="$(cat "$STATE" 2>/dev/null)"
check "UAT-8c: the window closes with a confirmed stopped VM" "stopped" "$state_line"

# a failing ladder still closes the window and fails the stage
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
if FAIL_ON=diagnose run_driver uat-diagnose; then
  true
  bad "UAT-8c: a failing ladder was accepted"
else
  ok "UAT-8c: a failing ladder fails the stage"
fi
state_line="$(cat "$STATE" 2>/dev/null)"
check "UAT-8c: the window is closed after a failing ladder" "stopped" "$state_line"
contains "UAT-8c: the failure is reported after the confirmed stop" \
  "the launch diagnostics reported failures (rc 3) — the network window is closed" "$OUT"


echo
printf 'provision-lab-vm tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
