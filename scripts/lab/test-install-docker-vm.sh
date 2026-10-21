#!/usr/bin/env bash
#
# test-install-docker-vm.sh — behavioral tests for scripts/lab/install-docker-vm.sh
# with stubbed guest tooling (no root, no VM, no real zypper).
#
# The stubs are STATEFUL: the stat shim reports the CURRENT label, which
# changes only when the restorecon shim actually runs, and the daemon domain
# changes only after a simulated systemctl restart that follows the binary
# relabel. A test cannot pass because stat "always" reports the right label —
# the installer really has to drive the state transitions.
#
# What this protects (one invariant per test):
#   1. the script refuses to run outside the lab VM and performs no side
#      effects; SELinux must be Enforcing before any mutation;
#   2. the happy path installs Docker through zypper WITH package signature
#      verification (the --no-gpg-checks regression is banned);
#   3. the verified event order: install → restore the dockerd label →
#      restart → restore the socket label → verify labels → verify Engine;
#   4. idempotent re-run on a correct system: no reinstall, no restart;
#   5. recovery: Docker installed with wrong labels → restorecon + restart;
#   6. a restorecon failure fails the install closed (no false PASS);
#   7. a label that stays wrong after restorecon fails the install;
#   8. a process that stays outside container_runtime_t fails the install;
#   9. a missing socket or an unaccepted socket type fails the install;
#  10. a daemon that fails to start after the binary relabel fails the install;
#  11. a zypper failure fails the install closed.
#
# Usage: scripts/lab/test-install-docker-vm.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LAB_DIR="$SRC_DIR/lab"
[ -f "$LAB_DIR/install-docker-vm.sh" ] || { echo "missing install-docker-vm.sh" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2')" ;; esac; }
lacks() { case "$3" in *"$2"*) bad "$1 (unexpected '$2')" ;; *) ok "$1" ;; esac; }

# A COPY of the lab directory with a stub guard (the real guard cases live in
# test-lab-vm-guard.sh): the copied script's guard passes when the test
# marker exists.
LAB_COPY="$WORK/lab"
mkdir -p "$LAB_COPY"
cp "$LAB_DIR"/*.sh "$LAB_COPY"/
cat > "$LAB_COPY/lab-vm-guard.sh" <<'SH'
require_lab_vm() {
  [ -r "${LAB_VM_TEST_MARKER:?}" ] || { printf 'guard stub: no marker\n' >&2; exit 1; }
}
SH
SCRIPT="$LAB_COPY/install-docker-vm.sh"

SHIM="$WORK/shim"; mkdir -p "$SHIM"
REC="$WORK/rec"; : > "$REC"
MARKER="$WORK/marker"; printf 'docker-helper-lab-vm 1 x\n' > "$MARKER"
STATE="$WORK/state"; mkdir -p "$STATE"
export LAB_VM_TEST_MARKER="$MARKER" REC STATE

# cat shim: only the SELinux enforce probe is faked; everything else is real.
cat > "$SHIM/cat" <<'SH'
#!/bin/sh
[ "${1:-}" = /sys/fs/selinux/enforce ] && { echo "${ENFORCE:-1}"; exit 0; }
exec /bin/cat "$@"
SH
cat > "$SHIM/id" <<'SH'
#!/bin/sh
echo 0
SH
# stat shim: the label reflects the CURRENT state, not a constant.
#   dockerd:  bin_t until restorecon touched it, then container_runtime_exec_t
#   socket:   var_run_t until restorecon touched it, then container_var_run_t
#   *_FORCE overrides model a relabel that did not take effect.
cat > "$SHIM/stat" <<SH
#!/bin/sh
case "\$*" in
  *dockerd*)
    [ -n "\${STAT_FORCE_DOCKERD:-}" ] && { echo "\$STAT_FORCE_DOCKERD"; exit 0; }
    if [ -f "$STATE/dockerd-relabeled" ]; then
      echo "system_u:object_r:container_runtime_exec_t:s0"
    else
      echo "system_u:object_r:bin_t:s0"
    fi ;;
  *docker.sock*)
    [ -n "\${STAT_FORCE_SOCK:-}" ] && { echo "\$STAT_FORCE_SOCK"; exit 0; }
    if [ -f "$STATE/sock-relabeled" ]; then
      echo "system_u:object_r:container_var_run_t:s0"
    else
      echo "system_u:object_r:var_run_t:s0"
    fi ;;
  *) echo "system_u:object_r:unlabeled_t:s0" ;;
esac
SH
# restorecon shim: applies the state transition and can be made to fail.
cat > "$SHIM/restorecon" <<SH
#!/bin/sh
echo "restorecon \$*" >> "\$REC"
[ -n "\${RESTORECON_FAIL:-}" ] && exit 1
case "\$*" in
  *dockerd*) : > "$STATE/dockerd-relabeled" ;;
  *docker.sock*) : > "$STATE/sock-relabeled" ;;
esac
exit 0
SH
# systemctl shim: the MainPID appears only after a successful restart.
cat > "$SHIM/systemctl" <<SH
#!/bin/sh
echo "systemctl \$*" >> "\$REC"
case "\$1 \$2" in
  "restart docker")
    [ -n "\${SYSTEMCTL_FAIL:-}" ] && exit 1
    : > "$STATE/restarted" ;;
  "show -p") [ -f "$STATE/restarted" ] && { echo 4242; exit 0; }; echo 0 ;;
  "is-active") [ -f "$STATE/restarted" ] || exit 1 ;;
  *) exit 0 ;;
esac
exit 0
SH
# ps shim: the daemon domain is correct only after a relabel + restart.
cat > "$SHIM/ps" <<SH
#!/bin/sh
case "\${PS_FORCE:-}" in
  ?*) echo "\$PS_FORCE"; exit 0 ;;
esac
if [ -f "$STATE/dockerd-relabeled" ] && [ -f "$STATE/restarted" ]; then
  echo "system_u:system_r:container_runtime_t:s0"
else
  echo "system_u:system_r:unconfined_service_t:s0"
fi
SH
cat > "$SHIM/docker" <<'SH'
#!/bin/sh
echo "docker $*" >> "$REC"
case "$1 $2" in
  "version --format") echo "27.5.1" ;;
  --version*) echo "Docker version 27.5.1, build test" ;;
  version) echo "Docker version 27.5.1" ;;
  info) exit 0 ;;
esac
exit 0
SH
# The docker shim starts OUTSIDE PATH resolution (named .docker-src): the
# zypper shim "installs" it into PATH exactly like the package install would.
mv "$SHIM/docker" "$SHIM/.docker-src"
chmod 0755 "$SHIM/.docker-src"
cat > "$SHIM/zypper" <<'SH'
#!/bin/sh
echo "zypper $*" >> "$REC"
[ -n "${ZYPPER_FAIL:-}" ] && exit 1
case "$*" in
  *install\ docker*) cp "$(dirname "$0")/.docker-src" "$(dirname "$0")/docker" ;;
esac
exit 0
SH
# The standard socket must exist for the verification: create it as a real
# socket in the test workdir and point the script at it.
python3 -c 'import socket, sys; s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])' "$WORK/docker.sock" 2>/dev/null || true
export DOCKER_SOCK="$WORK/docker.sock"
cat > "$SHIM/getent" <<'SH'
#!/bin/sh
exit 0
SH
# command -v dockerd/docker must resolve into the shim: provide dockerd too.
printf '#!/bin/sh\nexit 0\n' > "$SHIM/dockerd"
chmod +x "$SHIM"/*

reset_state() { rm -rf "$STATE"; mkdir -p "$STATE"; }
install_docker_in_path() { cp "$SHIM/.docker-src" "$SHIM/docker"; }
run_install() { # -> OUT, RC (the function itself returns the script's rc)
  PATH="$SHIM:$PATH" bash "$SCRIPT" >"$WORK/out" 2>&1
  RC=$?
  OUT="$(cat "$WORK/out")"
  return "$RC"
}

# --- 1. refusal outside the lab VM, and non-enforcing SELinux ----------------
rm -f "$MARKER"
: > "$REC"
if run_install; then bad "installer ran outside the lab VM"; else ok "installer refuses outside the lab VM"; fi
if [ -s "$REC" ]; then bad "refused installer had side effects"; else ok "refused installer had no side effects"; fi
printf 'docker-helper-lab-vm 1 x\n' > "$MARKER"
export ENFORCE=0
: > "$REC"
if run_install; then bad "installer ran without SELinux enforcing"; else ok "installer refuses when SELinux is not enforcing"; fi
if [ -s "$REC" ]; then bad "non-enforcing run had side effects"; else ok "non-enforcing run had no side effects"; fi
unset ENFORCE

# --- 2/3. fresh install: the installer repairs all three contexts ------------
reset_state
: > "$REC"
run_install
if [ "$RC" = 0 ]; then ok "fresh install succeeds and repairs the labels"; else bad "fresh install failed (rc $RC): $OUT"; fi
zypper_line="$(grep '^zypper ' "$REC" || true)"
contains "docker is installed via zypper" "zypper --non-interactive install docker" "$zypper_line"
if printf '%s' "$zypper_line" | grep -q -- '--no-gpg-checks'; then
  bad "package signature verification was disabled (--no-gpg-checks)"
else
  ok "zypper runs WITH signature verification (no --no-gpg-checks)"
fi
contains "dockerd executable label was restored" "restorecon" "$(grep dockerd "$REC" || true)"
contains "socket label was restored" "restorecon" "$(grep docker.sock "$REC" || true)"
contains "docker.service is restarted" "systemctl restart docker" "$(cat "$REC")"
contains "dockerd SELinux context recorded" "dockerd SELinux context" "$OUT"
contains "socket SELinux context recorded" "docker socket SELinux context" "$OUT"
contains "process domain verified" "dockerd process domain" "$OUT"
lacks "plain var_run_t is never accepted" "socket label already correct: system_u:object_r:var_run_t" "$OUT"
# event order: install → restore dockerd label → restart → restore socket →
# verify Engine
order_rc=0
zypper_ln="$(grep -n '^zypper ' "$REC" | head -1 | cut -d: -f1)"
bin_ln="$(grep -n '^restorecon .*dockerd' "$REC" | head -1 | cut -d: -f1)"
restart_ln="$(grep -n '^systemctl restart docker' "$REC" | head -1 | cut -d: -f1)"
sock_ln="$(grep -n '^restorecon .*docker.sock' "$REC" | head -1 | cut -d: -f1)"
engine_ln="$(grep -n '^docker version' "$REC" | head -1 | cut -d: -f1)"
for pair in "$zypper_ln:$bin_ln" "$bin_ln:$restart_ln" "$restart_ln:$sock_ln" "$sock_ln:$engine_ln"; do
  a="${pair%%:*}"; b="${pair##*:}"
  [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ] || { order_rc=1; break; }
done
if [ "$order_rc" = 0 ]; then
  ok "event order: install → dockerd label → restart → socket label → Engine"
else
  bad "event order violated (zypper=$zypper_ln bin=$bin_ln restart=$restart_ln sock=$sock_ln engine=$engine_ln)"
fi

# --- 4. idempotent re-run on a correct system --------------------------------
: > "$REC"
run_install
if [ "$RC" = 0 ]; then ok "idempotent re-run succeeds"; else bad "idempotent re-run failed (rc $RC): $OUT"; fi
lacks "no package reinstall on a correct system" "zypper install" "$(cat "$REC")"
lacks "no service restart on a correct system" "systemctl restart docker" "$(cat "$REC")"
contains "the correct-system re-run still verifies the labels" "dockerd SELinux context" "$OUT"

# --- 5. recovery: installed Docker, wrong labels ------------------------------
rm -f "$SHIM/docker"   # simulate: packages installed but the shim's PATH copy... keep docker present
install_docker_in_path
reset_state
: > "$REC"
run_install
if [ "$RC" = 0 ]; then ok "recovery run repairs wrong labels"; else bad "recovery run failed (rc $RC): $OUT"; fi
lacks "no package reinstall during recovery" "zypper install" "$(cat "$REC")"
contains "recovery restores the binary label" "restorecon" "$(grep dockerd "$REC" || true)"
contains "recovery restarts the daemon into the correct domain" "systemctl restart docker" "$(cat "$REC")"

# --- 6. restorecon failure fails closed ---------------------------------------
reset_state
export RESTORECON_FAIL=1
: > "$REC"
if run_install; then bad "a restorecon failure was tolerated"; else ok "a restorecon failure fails the install closed"; fi
unset RESTORECON_FAIL
lacks "no restart after a failed binary relabel" "systemctl restart docker" "$(cat "$REC")"

# --- 7. the label stays wrong after restorecon --------------------------------
reset_state
export STAT_FORCE_DOCKERD="system_u:object_r:bin_t:s0"
if run_install; then bad "a relabel that did not take effect was tolerated"; else ok "a stubborn binary label fails the install"; fi
unset STAT_FORCE_DOCKERD

# --- 8. the process stays outside container_runtime_t -------------------------
reset_state
export PS_FORCE="system_u:system_r:unconfined_service_t:s0"
if run_install; then bad "an unconfined daemon was accepted"; else ok "a daemon outside container_runtime_t fails the install"; fi
unset PS_FORCE

# --- 9. socket problems --------------------------------------------------------
DOCKER_SOCK="$WORK/no-such.sock"
if run_install; then bad "a missing docker socket was tolerated"; else ok "a missing docker socket fails the install"; fi
DOCKER_SOCK="$WORK/docker.sock"
reset_state
export STAT_FORCE_SOCK="system_u:object_r:var_run_t:s0"
if run_install; then bad "an unlabeled socket was tolerated"; else ok "a socket label that stays wrong fails the install"; fi
unset STAT_FORCE_SOCK
reset_state

# --- 10. the daemon fails to start after the relabel --------------------------
reset_state
export SYSTEMCTL_FAIL=restart
if run_install; then bad "a failed daemon start was tolerated"; else ok "a failed daemon start fails the install closed"; fi
unset SYSTEMCTL_FAIL

# --- 11. zypper failure fails closed ------------------------------------------
rm -f "$SHIM/docker"
reset_state
export ZYPPER_FAIL=1
: > "$REC"
if run_install; then bad "a zypper failure was tolerated"; else ok "zypper failure fails the install closed"; fi
unset ZYPPER_FAIL

echo
printf 'install-docker-vm tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
