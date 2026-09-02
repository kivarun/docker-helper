#!/usr/bin/env bash
#
# uat-selinux-check-regression.sh — black-box proof that `docker-helper
# selinux check` succeeds on the installed candidate in the normal supported
# SELinux state, and that the check is read-only (does not alter SELinux state).
#
# Runs as root inside the Tumbleweed SELinux VM (invoked via run_guest_capture
# with sudo). Requires the docker-helper package to be installed and the
# docker_helper policy module loaded.
set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

fail() { echo "[selinux-check] FAILED: $*" >&2; exit 1; }

for cmd in docker-helper semodule stat; do
  command -v "$cmd" >/dev/null 2>&1 || fail "$cmd not found"
done

echo "== snapshot SELinux state before the check =="
MOD_BEFORE="$(semodule -l 2>/dev/null | grep '^docker_helper' || true)"
LABEL_BEFORE="$(stat -c %C /usr/bin/docker-helper 2>/dev/null || true)"
echo "module: $MOD_BEFORE"
echo "label:  $LABEL_BEFORE"

echo "== run docker-helper selinux check =="
OUT="$(docker-helper selinux check 2>/tmp/selinux-check.stderr)" \
  || fail "selinux check exited nonzero (stderr: $(cat /tmp/selinux-check.stderr 2>/dev/null || true))"
if [ "$OUT" != "SELinux policy valid" ]; then
  fail "unexpected stdout: $OUT"
fi
if [ -s /tmp/selinux-check.stderr ]; then
  fail "stderr not empty: $(cat /tmp/selinux-check.stderr)"
fi
rm -f /tmp/selinux-check.stderr
echo "selinux check reported: $OUT"

echo "== snapshot SELinux state after the check =="
MOD_AFTER="$(semodule -l 2>/dev/null | grep '^docker_helper' || true)"
LABEL_AFTER="$(stat -c %C /usr/bin/docker-helper 2>/dev/null || true)"
if [ "$MOD_BEFORE" != "$MOD_AFTER" ]; then
  fail "docker_helper module state changed by the check"
fi
if [ "$LABEL_BEFORE" != "$LABEL_AFTER" ]; then
  fail "/usr/bin/docker-helper label changed by the check"
fi

echo "selinux check regression PASSED (read-only, valid policy)"
