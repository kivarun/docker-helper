#!/usr/bin/env bash
#
# test-install-docker-helper.sh — behavioral tests for
# scripts/lab/install-docker-helper-v230.sh with a stubbed guest environment
# (no root, no VM, no real download).
#
# The canonical installer from the release tarball is represented by a FAKE
# installer that the test itself packs into the tarball the curl shim
# "downloads". The fake installer models the v2.3.0 init output contract:
# on first initialization it prints the success block INCLUDING an
# 'Admin token:' section with a fake opaque token; on an existing
# configuration it prints no token at all. The pinned artifact sha256 is
# computed from the fake tarball, so the wrapper's sha256 verification is
# genuinely exercised.
#
# What this protects (one invariant per test):
#   1. the wrapper installs through the canonical installer and keeps the
#      sha256 pinning enforced (a tampered artifact fails closed);
#   2. the admin token printed by the canonical installer NEVER reaches the
#      wrapper's stdout/stderr — the 'Admin token:' value is redacted by
#      structure while the surrounding diagnostics pass through;
#   3. a failed canonical install keeps its original exit status, keeps the
#      failure diagnosis visible, and still does not leak the token;
#   4. a re-run against an existing configuration does not re-initialize
#      (no second token), keeps the pinned version/sha, and still verifies
#      the SELinux evidence;
#   5. the wrapper's own output never contains the fake token even on
#      failure paths.
#
# Usage: scripts/lab/test-install-docker-helper.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LAB_DIR="$SRC_DIR/lab"
[ -f "$LAB_DIR/install-docker-helper-v230.sh" ] || { echo "missing install-docker-helper-v230.sh" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2')" ;; esac; }
lacks() { case "$3" in *"$2"*) bad "$1 (unexpected '$2')" ;; *) ok "$1" ;; esac; }

LAB_COPY="$WORK/lab"
mkdir -p "$LAB_COPY"
cp "$LAB_DIR"/*.sh "$LAB_COPY"/
cat > "$LAB_COPY/lab-vm-guard.sh" <<'SH'
require_lab_vm() { :; }
SH
SCRIPT="$LAB_COPY/install-docker-helper-v230.sh"

GUESTROOT="$WORK/guestroot"
mkdir -p "$GUESTROOT/usr/bin" "$GUESTROOT/usr/local/bin" "$GUESTROOT/var/lib"
STATE="$WORK/state"; mkdir -p "$STATE"
SHIM="$WORK/shim"; mkdir -p "$SHIM"
REC="$WORK/rec"; : > "$REC"
export REC STATE GUESTROOT

# The fake admin token: a valid-shaped opaque value (dht_ + 64 hex chars)
# with a unique test marker. Its presence in ANY wrapper output is a leak.
FAKE_TOKEN="dht_aaaa0000bbbb1111cccc2222dddd3333eeee4444ffff55556666777788889999ab"

# --- the fake canonical installer + the fake artifact -------------------------
build_artifact() { # -> sets FAKE_TGZ and FAKE_SHA
  local stage="$WORK/artifact/docker-helper-2.3.0-linux-amd64"
  rm -rf "$WORK/artifact"; mkdir -p "$stage"
  cat > "$stage/install-system.sh" <<SH
#!/usr/bin/env bash
mkdir -p "$GUESTROOT/usr/bin" "$GUESTROOT/usr/local"
cat > "$GUESTROOT/usr/bin/docker-helper" <<'BIN'
#!/bin/sh
case "\$1" in version) echo "2.3.0" ;; esac
exit 0
BIN
chmod 0755 "$GUESTROOT/usr/bin/docker-helper"
if [ -n "\${FAKE_INSTALL_FAIL:-}" ]; then
  echo "stage: preflight ok"
  echo "Admin token:"
  echo "$FAKE_TOKEN"
  echo "FATAL: modeled canonical installer failure"
  exit 3
fi
if [ -f "$STATE/init-ran" ]; then
  echo "stage: existing configuration detected"
  echo "already initialized; nothing to do"
  : > "$STATE/reinit-ran"
  exit 0
fi
echo "Docker Helper initialized successfully."
echo
echo "Admin token:"
echo "$FAKE_TOKEN"
echo
echo "Stored at:"
echo "$GUESTROOT/var/lib/docker-helper/admin.token"
echo
echo "Configuration:"
echo "$GUESTROOT/etc/docker-helper/config.json"
: > "$STATE/init-ran"
exit 0
SH
  chmod +x "$stage/install-system.sh"
  FAKE_TGZ="$WORK/artifact/bundle.tgz"
  tar -czf "$FAKE_TGZ" -C "$WORK/artifact" "docker-helper-2.3.0-linux-amd64"
  FAKE_SHA="$(sha256sum "$FAKE_TGZ" | awk '{print $1}')"
}
build_artifact

# --- shims ---------------------------------------------------------------------
cat > "$SHIM/id" <<'SH'
#!/bin/sh
echo 0
SH
cat > "$SHIM/cat" <<'SH'
#!/bin/sh
[ "${1:-}" = /sys/fs/selinux/enforce ] && { echo 1; exit 0; }
exec /bin/cat "$@"
SH
cat > "$SHIM/curl" <<SH
#!/bin/sh
echo "curl \$*" >> "\$REC"
out=""
prev=""
for a in "\$@"; do
  [ "\$prev" = "-o" ] && out="\$a"
  prev="\$a"
done
[ -n "\$out" ] || exit 1
if [ -n "\${TAMPER:-}" ]; then
  cp "$FAKE_TGZ" "\$out"
  printf 'tampered' >> "\$out"
else
  cp "$FAKE_TGZ" "\$out"
fi
exit 0
SH
cat > "$SHIM/systemctl" <<SH
#!/bin/sh
echo "systemctl \$*" >> "\$REC"
exit 0
SH
cat > "$SHIM/zypper" <<SH
#!/bin/sh
echo "zypper \$*" >> "\$REC"
case "\$*" in
  *install\ bindfs*)
    printf '#!/bin/sh\nexit 0\n' > "$SHIM/bindfs"
    chmod +x "$SHIM/bindfs" ;;
esac
exit 0
SH
cat > "$SHIM/pkill" <<SH
#!/bin/sh
echo "pkill \$*" >> "\$REC"
exit 1
SH
cat > "$SHIM/install" <<SH
#!/bin/sh
echo "install \$*" >> "\$REC"
mode=""
dir=""
prev=""
for a in "\$@"; do
  case "\$prev" in -m) mode="\$a" ;; esac
  case "\$a" in -*) ;; *) [ -z "\$dir" ] && dir="\$a" ;; esac
  prev="\$a"
done
mkdir -p \${mode:+-m "\$mode"} -- "\$dir"
SH
cat > "$SHIM/semodule" <<'SH'
#!/bin/sh
echo "docker_helper 2.3.0"
SH
cat > "$SHIM/ps" <<'SH'
#!/bin/sh
echo "system_u:system_r:docker_helper_t:s0"
SH
printf '#!/bin/sh\nexit 0\n' > "$SHIM/sleep"
chmod +x "$SHIM"/*

export LAB_GUEST_ROOT="$GUESTROOT" LAB_HELPER_ALLOWED_ROOT="$GUESTROOT/home/agent"
mkdir -p "$LAB_HELPER_ALLOWED_ROOT"
export DH_V230_URL="https://artifact.test/fake.tar.gz" DH_V230_SHA256="$FAKE_SHA"

run_wrapper() { # -> OUT, RC
  PATH="$SHIM:$PATH" bash "$SCRIPT" >"$WORK/out" 2>&1
  RC=$?
  OUT="$(cat "$WORK/out")"
  return "$RC"
}
reset_state() {
  : > "$REC"
  rm -rf "$STATE"; mkdir -p "$STATE"
  rm -rf "$GUESTROOT"; mkdir -p "$GUESTROOT/usr/bin" "$GUESTROOT/usr/local/bin" "$GUESTROOT/var/lib" "$LAB_HELPER_ALLOWED_ROOT"
}

# --- T1/T2: fresh install; the token never leaks; diagnostics pass through ----
reset_state
if run_wrapper; then ok "fresh install succeeds"; else bad "fresh install failed (rc $RC): $OUT"; fi
lacks "the fake admin token never reaches the wrapper output" "$FAKE_TOKEN" "$OUT"
contains "the success diagnostics pass through" "Docker Helper initialized successfully." "$OUT"
contains "the storage path diagnostics pass through" "Stored at:" "$OUT"
contains "the token section is redacted by structure" "[redacted by the lab installer wrapper: admin token]" "$OUT"
contains "the pinned version is installed" "installed version: 2.3.0" "$OUT"
contains "the artifact sha256 is verified and logged" "artifact sha256 verified" "$OUT"
contains "the SELinux module evidence is recorded" "installed SELinux module:" "$OUT"
contains "the daemon domain evidence is recorded" "daemon SELinux context:" "$OUT"
contains "the binary type evidence is recorded" "binary SELinux type:" "$OUT"
contains "the service is restarted" "systemctl restart docker-helper" "$(cat "$REC")"

# --- T3: a failed canonical install keeps its status and its diagnosis ---------
reset_state
export FAKE_INSTALL_FAIL=1
run_wrapper; rc=$?
unset FAKE_INSTALL_FAIL
if [ "$rc" = 3 ]; then ok "the original canonical installer exit status is preserved (3)"; else bad "the original exit status was not preserved (rc $rc)"; fi
lacks "no token leak on the failure path" "$FAKE_TOKEN" "$OUT"
contains "the failure diagnosis stays visible" "FATAL: modeled canonical installer failure" "$OUT"
contains "the wrapper reports the installer failure" "the canonical installer failed with exit status 3" "$OUT"
contains "the token section is redacted on the failure path too" "[redacted by the lab installer wrapper: admin token]" "$OUT"

# --- T4: re-run on an existing configuration ------------------------------------
reset_state
run_wrapper >/dev/null 2>&1
: > "$REC"
if run_wrapper; then ok "the re-run on an existing configuration succeeds"; else bad "the re-run failed (rc $RC): $OUT"; fi
lacks "no token on the re-run" "$FAKE_TOKEN" "$OUT"
contains "the existing configuration is detected" "already initialized" "$OUT"
lacks "no re-initialization on the re-run" "Docker Helper initialized successfully." "$OUT"
lacks "no package reinstall shadow check failure" "still shadows /usr/bin" "$OUT"
if [ -f "$STATE/reinit-ran" ]; then
  ok "the second run took the existing-configuration path (no re-initialization)"
else
  bad "the second run re-initialized the configuration"
fi
contains "the pinned version stays after the re-run" "installed version: 2.3.0" "$OUT"
contains "the sha256 pinning stays enforced after the re-run" "artifact sha256 verified" "$OUT"

# --- T5: a tampered artifact fails the sha256 pinning ---------------------------
reset_state
export TAMPER=1
if run_wrapper; then bad "a tampered artifact was accepted"; else ok "a tampered artifact fails the sha256 pinning"; fi
unset TAMPER
contains "the tamper failure names the sha256 mismatch" "release artifact sha256 mismatch" "$OUT"
lacks "no token on the tamper path" "$FAKE_TOKEN" "$OUT"

echo
printf 'install-docker-helper tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
