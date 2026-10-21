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
    shift; echo "ssh \$1" >> "$REC"
    cat > /dev/null 2>/dev/null || true
    case "\$1" in
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
      *CONTAINER_PUBLIC_OK*) echo CONTAINER_PUBLIC_OK ;;
      *lab-mount-gate*) [ "\${FAIL_ON:-}" = gate ] && { echo "stub: mount gate refused" >&2; exit 1; }
        exit 0 ;;
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
# unsafe source without running docker at all.
: > "$REC"; echo stopped > "$STATE"; rm -f "$SNAPMARK"
FAIL_ON=gate run_driver online
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

echo
printf 'provision-lab-vm tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
