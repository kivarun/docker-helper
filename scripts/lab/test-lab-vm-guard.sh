#!/usr/bin/env bash
#
# test-lab-vm-guard.sh — tests for scripts/lab/lab-vm-guard.sh and for the
# guard wiring of the destructive lab scripts.
#
# What this protects (one invariant per test):
#   1. the guard library fails closed on: missing marker, malformed marker,
#      wrong tag, unsupported version, wrong machine-id;
#   2. the guard library passes for a correct marker (right tag, right
#      version, this system's machine-id);
#   3. setup-agent-user.sh (unmodified) refuses to run on this (non-VM) host
#      and performs NO side effects;
#   4. install-docker-helper-v230.sh (unmodified) refuses to run on this
#      (non-VM) host and performs NO state change (no download, no dependency
#      install, no service stop, no binary removal) — the guard runs before
#      ANY mutation;
#   5. the destructive scripts actually CALL require_lab_vm (wiring cannot
#      silently disappear).
#
# Usage: scripts/lab/test-lab-vm-guard.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LAB_DIR="$SRC_DIR/lab"
GUARD="$LAB_DIR/lab-vm-guard.sh"
SETUP="$LAB_DIR/setup-agent-user.sh"
INSTALL="$LAB_DIR/install-docker-helper-v230.sh"
for f in "$GUARD" "$SETUP" "$INSTALL"; do
  [ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }

# --- 1/2. guard library, direct cases (explicit path = the test seam) -------
MID="$(cat /etc/machine-id)"
MARKER="$WORK/marker"

guard_case() { # <desc> <expected-rc> <marker-content|ABSENT>
  local desc="$1" want="$2" content="$3"
  local rc
  if [ "$content" = ABSENT ]; then
    rm -f "$MARKER"
  else
    printf '%s\n' "$content" > "$MARKER"
  fi
  # shellcheck disable=SC1090
  ( . "$GUARD"; require_lab_vm "$MARKER" ) >/dev/null 2>&1
  rc=$?
  if [ "$rc" = "$want" ]; then ok "$desc"; else bad "$desc (want rc $want, got $rc)"; fi
}

guard_case "guard: missing marker refused" 1 ABSENT
guard_case "guard: empty marker refused" 1 ""
guard_case "guard: wrong tag refused" 1 "wrongtag 1 $MID"
guard_case "guard: unsupported version refused" 1 "docker-helper-lab-vm 2 $MID"
guard_case "guard: wrong machine-id refused" 1 "docker-helper-lab-vm 1 deadbeef"
guard_case "guard: correct marker passes" 0 "docker-helper-lab-vm 1 $MID"
# The argument seam is the ONLY way to redirect the marker: the fixed path is
# used when no argument is passed.
if [ -e /etc/docker-helper-lab-vm ]; then
  bad "this host HAS /etc/docker-helper-lab-vm; the fixed-path refusal case would be meaningless"
else
  # shellcheck disable=SC1090
  ( . "$GUARD"; require_lab_vm ) >/dev/null 2>&1
  if [ "$?" != 0 ]; then ok "guard: fixed marker path refused on this host (no argument seam)"; else bad "guard: fixed marker path unexpectedly passed"; fi
fi

# --- 3. setup-agent-user.sh refuses with no side effects --------------------
# Stubs make the script reach the guard (uid 0) on this non-VM host; every
# mutating tool is a recorder that must stay EMPTY.
SHIM="$WORK/shim"; mkdir -p "$SHIM"
REC="$WORK/rec"; : > "$REC"
cat > "$SHIM/id" <<'SH'
#!/bin/sh
[ "${1:-}" = -u ] && { echo 0; exit 0; }
echo 0
SH
for tool in useradd usermod chown sed install su jq systemctl pkill curl zypper tar python3; do
  cat > "$SHIM/$tool" <<SH
#!/bin/sh
printf '%s\n' "$tool \$*" >> "$REC"
exit 0
SH
  chmod +x "$SHIM/$tool"
done
chmod +x "$SHIM"/*
if PATH="$SHIM:$PATH" bash "$SETUP" >/dev/null 2>&1; then
  bad "setup ran outside the lab VM"
else
  ok "setup-agent-user.sh refuses to run outside the lab VM"
fi
check_rec_empty() {
  if [ -s "$REC" ]; then bad "$1 (side effects recorded: $(cat "$REC"))"; else ok "$1"; fi
}
check_rec_empty "refused setup performed no side effects"

# --- 4. install-docker-helper-v230.sh refuses with no state change ----------
: > "$REC"
if PATH="$SHIM:$PATH" bash "$INSTALL" >/dev/null 2>&1; then
  bad "installer ran outside the lab VM"
else
  ok "install-docker-helper-v230.sh refuses to run outside the lab VM"
fi
check_rec_empty "refused installer performed no state change"

# --- 5. the destructive scripts wire the guard ------------------------------
grep -q 'require_lab_vm' "$SETUP" && ok "setup wires require_lab_vm" || bad "setup lost require_lab_vm"
grep -q 'require_lab_vm' "$INSTALL" && ok "installer wires require_lab_vm" || bad "installer lost require_lab_vm"
# Provisioning must never touch the helper database or the user database.
# The ban applies to CODE: leading comment lines document the policy itself.
setup_code="$(grep -v '^[[:space:]]*#' "$SETUP" || true)"
for banned in 'sqlite3' 'UPDATE ' 'DELETE FROM' 'INSERT INTO' '/etc/passwd' '/etc/shadow' '/etc/group' 'useradd -o'; do
  if printf '%s\n' "$setup_code" | grep -qF -- "$banned"; then bad "setup contains banned pattern '$banned'"; else ok "setup free of '$banned'"; fi
done

echo
printf 'lab-vm-guard tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
