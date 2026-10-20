#!/usr/bin/env bash
#
# test-install-docker-vm.sh — focused tests for scripts/lab/install-docker-vm.sh
# with stubbed guest tooling (no root, no VM, no real zypper).
#
# What this protects (one invariant per test):
#   1. the script refuses to run outside the lab VM and performs no side
#      effects;
#   2. the happy path installs Docker through zypper WITH package signature
#      verification (the --no-gpg-checks regression is banned);
#   3. the service is enabled and (re)started;
#   4. verification covers version, info, socket, SELinux contexts and the
#      docker group;
#   5. an unexpected dockerd or socket SELinux context fails the install;
#   6. a zypper failure fails the install closed.
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
export LAB_VM_TEST_MARKER="$MARKER" REC

# cat shim: only the SELinux enforce probe is faked; everything else is real.
cat > "$SHIM/cat" <<'SH'
#!/bin/sh
[ "${1:-}" = /sys/fs/selinux/enforce ] && { echo 1; exit 0; }
exec /bin/cat "$@"
SH
cat > "$SHIM/id" <<'SH'
#!/bin/sh
echo 0
SH
# stat shim: dockerd binary and docker socket contexts, as openSUSE labels them.
cat > "$SHIM/stat" <<'SH'
#!/bin/sh
case "$*" in
  *docker.sock*) echo "system_u:object_r:container_var_run_t:s0" ;;
  *) echo "system_u:object_r:container_runtime_exec_t:s0" ;;
esac
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
# zypper shim "installs" it into PATH exactly like the package install would,
# so both the fresh-install path and the idempotent re-run are exercised.
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
cat > "$SHIM/systemctl" <<'SH'
#!/bin/sh
echo "systemctl $*" >> "$REC"
exit 0
SH
cat > "$SHIM/getent" <<'SH'
#!/bin/sh
exit 0
SH
# command -v dockerd/docker must resolve into the shim: provide dockerd too.
printf '#!/bin/sh\nexit 0\n' > "$SHIM/dockerd"
chmod +x "$SHIM"/*

run_install() { # -> OUT, RC (the function itself returns the script's rc)
  PATH="$SHIM:$PATH" bash "$SCRIPT" >"$WORK/out" 2>&1
  RC=$?
  OUT="$(cat "$WORK/out")"
  return "$RC"
}

# --- 1. refusal outside the lab VM ------------------------------------------
rm -f "$MARKER"
: > "$REC"
if run_install; then bad "installer ran outside the lab VM"; else ok "installer refuses outside the lab VM"; fi
if [ -s "$REC" ]; then bad "refused installer had side effects"; else ok "refused installer had no side effects"; fi
printf 'docker-helper-lab-vm 1 x\n' > "$MARKER"

# --- 2/3/4. happy path -------------------------------------------------------
: > "$REC"
run_install
if [ "$RC" = 0 ]; then ok "happy path succeeds"; else bad "happy path failed (rc $RC): $OUT"; fi
zypper_line="$(grep '^zypper ' "$REC" || true)"
contains "docker is installed via zypper" "zypper --non-interactive install docker" "$zypper_line"
if printf '%s' "$zypper_line" | grep -q -- '--no-gpg-checks'; then
  bad "package signature verification was disabled (--no-gpg-checks)"
else
  ok "zypper runs WITH signature verification (no --no-gpg-checks)"
fi
contains "docker.service is enabled" "systemctl enable docker" "$(cat "$REC")"
contains "docker.service is restarted" "systemctl restart docker" "$(cat "$REC")"
contains "docker version verified" "docker server version: 27.5.1" "$OUT"
contains "dockerd SELinux context recorded" "dockerd SELinux context" "$OUT"
contains "socket SELinux context recorded" "docker socket SELinux context" "$OUT"

# --- 5. unexpected SELinux context fails the install -------------------------
cat > "$SHIM/stat" <<'SH'
#!/bin/sh
echo "system_u:object_r:bin_t:s0"
SH
run_install
if [ "$RC" != 0 ]; then ok "unexpected SELinux context fails the install"; else bad "unexpected SELinux context accepted"; fi
# restore the good shim
cat > "$SHIM/stat" <<'SH'
#!/bin/sh
case "$*" in
  *docker.sock*) echo "system_u:object_r:container_var_run_t:s0" ;;
  *) echo "system_u:object_r:container_runtime_exec_t:s0" ;;
esac
SH

# --- 6. zypper failure fails closed ------------------------------------------
# Force the fresh-install branch again so the failing zypper call is reached.
rm -f "$SHIM/docker"
export ZYPPER_FAIL=1
: > "$REC"
run_install
unset ZYPPER_FAIL
if [ "$RC" != 0 ]; then ok "zypper failure fails the install closed"; else bad "zypper failure was tolerated"; fi

echo
printf 'install-docker-vm tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
