#!/usr/bin/env bash
#
# uat-projection-microproof.sh — Phase A3 bounded diagnostic for the read-only
# projection mount failure on the Tumbleweed / RPM / SELinux profile:
#   bindfs projection worker exited with error: exit status 4
#   (stderr: fuse: mount failed: Permission denied)
# Runs INSIDE the guest as root, against the installed exact candidate.
#
# The failing operation is the workload-MAC read-only projection: one
# docker-helper run with a read-only exposure makes the daemon prepare one
# bindfs projection under the helper runtime tree and FUSE-mount it with the
# fixed projection mount context, before any container exists. This ONE
# bounded experiment:
#   1. disables dontaudit (semodule -DB) so denied operations log AVCs;
#   2. creates one read-only global root, one read-only Session workspace,
#      and issues exactly one docker-helper run with that read-only exposure;
#   3. dumps the daemon operational log, the fresh AVC/USER_AVC records, and
#      the SELinux labels of the runtime tree the mountpoint lives in, plus
#      the FUSE device/helper state;
#   4. ALWAYS restores dontaudit behavior (semodule -B), even on failure.
#
# It ALWAYS restores dontaudit behavior (semodule -B) even if the run fails.
#
# Exit 0 even when the projection mount fails (this is evidence collection,
# not a pass/fail gate); nonzero only on harness failure.

set -uo pipefail

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
for t in semodule ausearch docker-helper; do
  command -v "$t" >/dev/null 2>&1 || { echo "error: $t not found" >&2; exit 1; }
done

restore_dontaudit() {
  echo "MICROPROOF restoring dontaudit: semodule -B"
  semodule -B 2>&1 || echo "warning: semodule -B failed (dontaudit may remain disabled)"
}
redact() {
  sed -E \
    -e 's/dht_[A-Za-z0-9_-]+/<redacted-token>/g' \
    -e 's/dhc_[A-Za-z0-9_-]+/<redacted-token>/g'
}
A3_DIR="$(mktemp -d /tmp/uat-a3-microproof.XXXXXX)"
# One EXIT trap only: a second trap assignment would replace the dontaudit
# restore, and this diagnostic must always leave dontaudit enabled state as
# it found it.
# An EXIT trap that completes normally preserves the original exit status,
# so the cleanup needs no explicit rc capture.
trap 'rm -rf "$A3_DIR" 2>/dev/null; restore_dontaudit' EXIT

echo "===== READ-ONLY PROJECTION MICRO-PROOF ====="

# --- 1. service + FUSE device/helper state ------------------------------------
systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
for _ in $(seq 1 60); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
systemctl is-active --quiet docker-helper.service || { echo "error: service not active" >&2; exit 1; }

echo "--- FUSE device/helper ---"
ls -lZ /dev/fuse 2>&1 || true
ls -lZ /usr/bin/fusermount3 /usr/bin/fusermount 2>&1 || true
command -v fusermount3 || echo "(fusermount3 absent)"
grep -c fuse /proc/filesystems 2>/dev/null || true

# --- 2. disable dontaudit so the diagnostic run logs AVCs ----------------------
echo "MICROPROOF disable dontaudit: semodule -DB"
semodule -DB 2>&1 || { echo "error: semodule -DB failed" >&2; exit 1; }

# --- 3. one read-only root + one Session over it -------------------------------
echo "MICROPROOF ensure read-only region + session"
rm -rf /opt/uat-a3-ro
mkdir -p /opt/uat-a3-ro/ws
echo 'a3-probe' > /opt/uat-a3-ro/ws/probe.txt
if ! docker-helper config allowed-root add --access read_only /opt/uat-a3-ro >/dev/null 2>&1; then
  echo "error: cannot add read-only global root /opt/uat-a3-ro" >&2
  exit 1
fi
# Global flags precede positionals; trailing flags are rejected by the CLI and
# a silently skipped principal root would make the session create fail with
# invalid_workspace and hide the projection mount evidence this proof exists
# to collect.
docker-helper principal allowed-root add --system --access read_only opc /opt/uat-a3-ro \
  >"$A3_DIR/principal-add.out" 2>&1
if docker-helper principal allowed-root list --system opc 2>/dev/null | grep -F '/opt/uat-a3-ro'; then
  echo "MICROPROOF_PRINCIPAL_ROOT=yes"
else
  echo "MICROPROOF_PRINCIPAL_ROOT=no (principal add: $(redact <"$A3_DIR/principal-add.out" | tail -2))"
fi

ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
SESSION_JSON=""
if [ -n "$ADMIN_TOKEN" ]; then
  SESSION_JSON="$(curl --silent --max-time 5 \
    --unix-socket /run/docker-helper/docker-helper.sock \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d '{"workspace":"/opt/uat-a3-ro/ws","principal":"opc"}' \
    http://localhost/sessions 2>/dev/null || true)"
fi
if [ -z "$SESSION_JSON" ]; then
  SESSION_JSON="$(docker-helper session create --system --workspace /opt/uat-a3-ro/ws --json 2>&1 || true)"
fi
# Tolerant of both pretty and compact JSON token forms (run 5/6 proved the
# daemon answers compact JSON; the spaced form alone misses it).
TOKEN="$(printf '%s\n' "$SESSION_JSON" | grep -oP '"token": ?"\K[^"]+' | head -1)"
if [ -z "$TOKEN" ]; then
  echo "MICROPROOF_SESSION_CREATED=no"
  printf '%s\n' "$SESSION_JSON" | sed -E 's/dht_[A-Za-z0-9_-]+/<redacted>/g'
  exit 0
fi
echo "MICROPROOF_SESSION_CREATED=yes"

# --- 4. one diagnostic read-only run (dontaudit disabled) ----------------------
# The read-only exposure goes through the bindfs projection path before any
# container exists: a projection mount failure surfaces here even if Docker
# would later fail for an unrelated reason.
RUN_RC=0
RUN_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$TOKEN" \
  docker-helper run --image alpine:3.24 --mount .:/mnt/ws:ro -- \
  sh -ec 'cat /mnt/ws/probe.txt' 2>&1)" || RUN_RC=$?
printf '%s\n' "$RUN_OUT" | sed -E 's/dht_[A-Za-z0-9_-]+/<redacted>/g' | tail -20
echo "MICROPROOF_RUN_RC=$RUN_RC"

# --- 4b. direct bindfs probes (discriminate the mount failure) ---------------
# The daemon run fails with EACCES and, with dontaudit disabled, produces no
# AVC at all, so the failure is not a policy denial from the confined daemon
# domain. These probes isolate which variable carries the EACCES:
#   probe 1: plain allow_other, unconfined SSH session;
#   probe 2: production options (allow_other + fixed projection context),
#            unconfined SSH session;
#   probe 3: production options inside the daemon's systemd sandbox
#            (NoNewPrivileges, RestrictNamespaces, MemoryDenyWriteExecute,
#            docker_helper_t) via a bounded transient unit.
probe_bindfs() { # label use_context use_sandbox
  local label="$1" use_ctx="$2" use_sb="$3"
  local src mp ctx out rc pid
  src=/opt/uat-a3-probe-src; mp=/run/docker-helper/a3probe-mp
  ctx=system_u:object_r:docker_helper_ro_projection_t:s0
  rm -rf "$src" "$mp" /tmp/uat-a3-bindfs-probe.out
  mkdir -p "$src" "$mp"
  echo probe > "$src/f"
  local args=(-f -o allow_other)
  [ "$use_ctx" = yes ] && args+=(-o "context=$ctx")
  out=/tmp/uat-a3-bindfs-probe.out
  echo "PROBE $label: bindfs ${args[*]} $src $mp"
  if [ "$use_sb" = yes ]; then
    systemd-run --collect --unit=uat-a3bindfsprobe \
      --property=NoNewPrivileges=true --property=RestrictNamespaces=true \
      --property=MemoryDenyWriteExecute=true \
      --property=SELinuxContext=system_u:system_r:docker_helper_t:s0 \
      bindfs "${args[@]}" "$src" "$mp" >"$out" 2>&1
    rc=$?
    echo "PROBE $label: systemd-run rc=$rc"
    sleep 2
    if mount | grep -F "$mp" >/dev/null 2>&1; then
      echo "PROBE $label: MOUNTED=yes"
    else
      echo "PROBE $label: MOUNTED=no"
      tail -5 "$out" 2>/dev/null | sed -E 's/dht_[A-Za-z0-9_-]+/<redacted>/g'
      systemctl status uat-a3bindfsprobe.service --no-pager 2>&1 | head -12 || true
    fi
    systemctl stop uat-a3bindfsprobe.service >/dev/null 2>&1 || true
    fusermount3 -u "$mp" >/dev/null 2>&1 || true
  else
    bindfs "${args[@]}" "$src" "$mp" >"$out" 2>&1 &
    pid=$!
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
      echo "PROBE $label: MOUNTED=yes"
      kill "$pid" 2>/dev/null; sleep 1
      kill -9 "$pid" 2>/dev/null || true
    else
      echo "PROBE $label: MOUNTED=no"
      wait "$pid" 2>/dev/null
      echo "PROBE $label: bindfs rc=$?"
      tail -5 "$out" 2>/dev/null | sed -E 's/dht_[A-Za-z0-9_-]+/<redacted>/g'
    fi
    fusermount3 -u "$mp" >/dev/null 2>&1 || true
  fi
  rm -rf "$src" "$mp"
}
grep -n 'user_allow_other' /etc/fuse.conf 2>/dev/null || echo "(no user_allow_other line in /etc/fuse.conf)"
fusermount3 --version 2>&1 || true
probe_bindfs "1-plain-unconfined" no no
probe_bindfs "2-context-unconfined" yes no
probe_bindfs "3-context-daemon-sandbox" yes yes
echo "PROBES_DONE"

# --- 5. capture the complete evidence ------------------------------------------
echo "MICROPROOF AVC capture (ausearch --start recent, complete bounded):"
ausearch -m AVC -m USER_AVC --start recent 2>/dev/null | tail -60 || true
echo "--- dmesg AVC fallback view ---"
dmesg 2>/dev/null | grep -i 'avc' | tail -20 || true
echo "--- daemon operational log (projection context) ---"
journalctl -u docker-helper.service -n 200 --no-pager -o cat 2>/dev/null \
  | grep -iE 'projection|bindfs|workload' | tail -20 || true
echo "--- SELinux labels of the runtime mount tree ---"
ls -Zd /run/docker-helper /run/docker-helper/workload-mac 2>&1 || true
ls -Zd /run/docker-helper/workload-mac/mount-* /run/docker-helper/workload-mac/mount-*/mount 2>&1 || true
matchpathcon /run/docker-helper/workload-mac/mount-0/mount 2>&1 || true
echo "--- local fcontext rules (tail) ---"
semanage fcontext -l -C -n 2>&1 | tail -15 || true
echo "MICROPROOF_DONE"

# trap restores dontaudit
exit 0
