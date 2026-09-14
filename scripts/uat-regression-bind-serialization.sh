#!/usr/bin/env bash
#
# uat-regression-bind-serialization.sh — Release-2 targeted regression
# group 22: M13 Docker bind-mount serialization (Ubuntu / DEB / AppArmor).
#
# Real-Docker proof of the canonical bind-mount serializer (one production
# owner for every Docker bind form). The Docker CLI parses one --mount value
# as ONE CSV record; the serializer encodes caller-visible fields with the
# Docker-sanctioned CSV quoting and refuses the one unrepresentable case:
#
#   1. a hostile target carrying a newline mounts READ-ONLY at the exact
#      intended target, the marker file is readable there, and the write
#      attempt inside the container fails — the historical M13 desync (an
#      unquoted control character truncating the CSV record so the trailing
#      readonly flag is dropped) cannot happen;
#   2. a hostile option-injection spelling stays writable at the exact
#      intended target (the container path literally is
#      "/mnt/dta,readonly") — the crafted data injects no option;
#   3. a CRLF target, which the Docker mount grammar cannot represent
#      faithfully, is refused invalid_mount before any Docker state exists;
#   4. every proof reads the real container state via docker inspect (taken
#      while the container is running — run containers are removed on exit)
#      and the real container filesystem, not helper responses alone.
#
# Requires: installed docker-helper system service (active, system mode),
# Docker reachable, root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "22. M13 Docker bind-mount serialization"

reg_require_root
reg_require_service
reg_require_docker

IMAGE="alpine:3.24"
USER="uatreg22"

home="$(reg_setup_principal "$USER")" || { reg_fail "setup principal failed"; reg_result; }
ws="$home/ws"; src="$ws/src"; ctl="$ws/ctl"
mkdir -p "$src" "$ctl"
printf 'CONTENT\n' > "$src/marker"
chown -R "$USER:$USER" "$ws"

cred="/tmp/uat-reg22.token"
reg_principal_credential "$USER" "$cred" || { reg_fail "credential create failed"; reg_result; }

# inspect_mounts prints, for the running container of one session, the
# tab-separated bind-mount facts (Destination verbatim, RW, Source,
# Propagation) read from the real docker inspect state.
inspect_mounts() {
  local sid="$1" cid json
  cid="$(docker ps -q --filter "label=com.dockerhelper.session.id=$sid" 2>/dev/null | head -1)"
  [ -n "$cid" ] || { echo "NO-CONTAINER"; return; }
  json="$(docker inspect "$cid" 2>/dev/null)" || { echo "INSPECT-FAILED"; return; }
  python3 -c '
import json, sys
spec = json.loads(sys.argv[1])
mounts = [m for m in spec[0].get("Mounts", []) if m.get("Type") == "bind"]
for m in mounts:
    print("%s\t%s\t%s\t%s" % (m.get("Destination"), str(m.get("RW")).lower(), m.get("Source"), m.get("Propagation", "")))
' "$json"
}

# mount_line_exists reports whether the running container of one session has
# a bind mount whose verbatim Destination/RW/Source/Propagation line equals
# the expected one (exact whole-line comparison: the expected value may
# contain newlines, which a grep pattern cannot carry). 0 = found, 1 = not
# found, 2 = no container or inspect failure.
mount_line_exists() {
  local sid="$1" expected="$2" cid
  cid="$(docker ps -q --filter "label=com.dockerhelper.session.id=$sid" 2>/dev/null | head -1)"
  [ -n "$cid" ] || return 2
  docker inspect "$cid" 2>/dev/null | python3 -c '
import json, sys
expected = sys.argv[2]
spec = json.loads(sys.stdin.read())
mounts = [m for m in spec[0].get("Mounts", []) if m.get("Type") == "bind"]
for m in mounts:
    line = "%s\t%s\t%s\t%s" % (m.get("Destination"), str(m.get("RW")).lower(), m.get("Source"), m.get("Propagation", ""))
    if line == expected:
        sys.exit(0)
sys.exit(1)
' - "$expected"
}

session_container_count() {
  docker ps -aq --filter "label=com.dockerhelper.session.id=$1" 2>/dev/null | wc -l
}

wait_for_file() {
  local path="$1"
  for _ in $(seq 1 60); do
    [ -f "$path" ] && return 0
    sleep 1
  done
  return 1
}

NL=$'\n'
TAB=$'\t'

# ---------------------------------------------------------------------------
# 1. Hostile newline target + :ro — the historical M13 desync class
# ---------------------------------------------------------------------------
reg_session "$cred" "$ws" || { reg_fail "session create failed"; reg_result; }
SID_RO="$REG_SESSION_ID"; TOK_RO="$REG_SESSION_TOKEN"

HOSTILE_RO_TARGET="/mnt/probe${NL}readonly-evil"
EXPECTED_RO="${HOSTILE_RO_TARGET}${TAB}false"
RUN_LOG="/tmp/uat-reg22-ro.log"
# The container reads the marker through the hostile newline target, proves
# the write attempt fails, reports both through the writable control mount,
# and stays alive until the host inspected the real Docker state.
DOCKER_HELPER_SESSION_TOKEN="$TOK_RO" \
  dh run --image "$IMAGE" \
    --mount "$src:$HOSTILE_RO_TARGET:ro" \
    --mount "$ctl:/mnt/ctl" \
    -- sh -c 'p=$(printf "/mnt/probe\nreadonly-evil"); cat "$p/marker" > /mnt/ctl/ro-read 2>/mnt/ctl/ro-read-err; if touch "$p/w-probe" 2>/dev/null; then echo WRITE-SUCCEEDED > /mnt/ctl/ro-write; else echo WRITE-DENIED > /mnt/ctl/ro-write; fi; while [ ! -f /mnt/ctl/release-ro ]; do sleep 1; done' \
  >"$RUN_LOG" 2>&1 &
RUN_PID=$!

wait_for_file "$ctl/ro-write" || { reg_fail "hostile newline RO container did not report in 60s (log: $(tail -3 "$RUN_LOG" | redact))"; kill "$RUN_PID" 2>/dev/null; reg_result; }
MOUNTS_RO="$(inspect_mounts "$SID_RO")"
mount_line_exists "$SID_RO" "$EXPECTED_RO"; RO_LINE_RC=$?
mount_line_exists "$SID_RO" "${HOSTILE_RO_TARGET}${TAB}true"; RO_WRITABLE_RC=$?
touch "$ctl/release-ro"
wait "$RUN_PID" 2>/dev/null; RC_RO=$?

if [ "$(cat "$ctl/ro-read" 2>/dev/null)" = "CONTENT" ]; then
  reg_ok "hostile newline RO container read the marker at the exact intended target"
else
  reg_fail "marker not readable at the exact newline target (read: $(cat "$ctl/ro-read-err" 2>/dev/null | redact))"
fi
if [ "$(cat "$ctl/ro-write" 2>/dev/null)" = "WRITE-DENIED" ]; then
  reg_ok "the write attempt inside the read-only mount failed"
else
  reg_fail "the write attempt inside the read-only mount succeeded: $(cat "$ctl/ro-write" 2>/dev/null | redact)"
fi
if [ "$RC_RO" -eq 0 ] || [ "$RC_RO" -eq 137 ]; then
  reg_ok "hostile newline RO run terminated normally"
else
  reg_fail "hostile newline RO run exited unexpectedly (rc=$RC_RO, log: $(tail -3 "$RUN_LOG" | redact))"
fi
if [ "$RO_LINE_RC" -eq 0 ]; then
  reg_ok "docker inspect shows the exact intended newline target mounted read-only"
else
  reg_fail "docker inspect does not show the exact newline target read-only: $MOUNTS_RO"
fi
if [ "$RO_WRITABLE_RC" -eq 1 ]; then
  reg_ok "no writable mount of the hostile spelling exists"
else
  reg_fail "a writable mount of the hostile spelling exists: $MOUNTS_RO"
fi

# ---------------------------------------------------------------------------
# 2. Hostile option-injection spelling stays writable at the exact target
# ---------------------------------------------------------------------------
reg_session "$cred" "$ws" || { reg_fail "second session create failed"; reg_result; }
SID_RW="$REG_SESSION_ID"; TOK_RW="$REG_SESSION_TOKEN"

INJECT_TARGET="/mnt/dta,readonly"
EXPECTED_RW="${INJECT_TARGET}${TAB}true"
RUN2_LOG="/tmp/uat-reg22-rw.log"
# The container path literally is "/mnt/dta,readonly": the marker is readable
# at exactly that path, proving no "/mnt/data,readonly" option split happened.
DOCKER_HELPER_SESSION_TOKEN="$TOK_RW" \
  dh run --image "$IMAGE" \
    --mount "$src:$INJECT_TARGET" \
    --mount "$ctl:/mnt/ctl" \
    -- sh -c 'cat "/mnt/dta,readonly/marker" > /mnt/ctl/rw-read 2>/mnt/ctl/rw-read-err; echo RW-RAN > /mnt/ctl/rw-report; while [ ! -f /mnt/ctl/release-rw ]; do sleep 1; done' \
  >"$RUN2_LOG" 2>&1 &
RUN2_PID=$!

wait_for_file "$ctl/rw-report" || { reg_fail "option-injection container did not report in 60s (log: $(tail -3 "$RUN2_LOG" | redact))"; kill "$RUN2_PID" 2>/dev/null; reg_result; }
MOUNTS_RW="$(inspect_mounts "$SID_RW")"
mount_line_exists "$SID_RW" "$EXPECTED_RW"; RW_LINE_RC=$?
touch "$ctl/release-rw"
wait "$RUN2_PID" 2>/dev/null; RC_RW=$?

if [ "$(cat "$ctl/rw-read" 2>/dev/null)" = "CONTENT" ]; then
  reg_ok "option-injection spelling container read the marker at the exact comma path (no option split)"
else
  reg_fail "marker not readable at the exact comma target (read: $(cat "$ctl/rw-read-err" 2>/dev/null | redact))"
fi
if [ "$RC_RW" -eq 0 ] || [ "$RC_RW" -eq 137 ]; then
  reg_ok "option-injection spelling run terminated normally"
else
  reg_fail "option-injection spelling run exited unexpectedly (rc=$RC_RW, log: $(tail -3 "$RUN2_LOG" | redact))"
fi
if [ "$RW_LINE_RC" -eq 0 ]; then
  reg_ok "docker inspect shows the exact comma target writable — no option injected"
else
  reg_fail "docker inspect does not show the exact comma target writable: $MOUNTS_RW"
fi

# ---------------------------------------------------------------------------
# 3. CRLF target — unrepresentable, refused before any Docker state
# ---------------------------------------------------------------------------
reg_session "$cred" "$ws" || { reg_fail "third session create failed"; reg_result; }
SID_CRLF="$REG_SESSION_ID"; TOK_CRLF="$REG_SESSION_TOKEN"

CRLF_TARGET="$(printf '/mnt/probe\r\ncrlf-evil')"
RUN3_LOG="/tmp/uat-reg22-crlf.log"
DOCKER_HELPER_SESSION_TOKEN="$TOK_CRLF" \
  dh run --image "$IMAGE" \
    --mount "$src:$CRLF_TARGET:ro" \
    -- sh -c 'echo SHOULD-NOT-RUN' \
  >"$RUN3_LOG" 2>&1
RC_CRLF=$?

if [ "$RC_CRLF" -ne 0 ] && grep -q 'invalid_mount' "$RUN3_LOG"; then
  reg_ok "CRLF target refused invalid_mount before Docker"
else
  reg_fail "CRLF target was not refused invalid_mount (rc=$RC_CRLF, log: $(cat "$RUN3_LOG" | redact | tail -3))"
fi
if [ "$(session_container_count "$SID_CRLF")" = "0" ]; then
  reg_ok "no container/state residue exists after the unrepresentable-mount refusal"
else
  reg_fail "Docker state was created for an unrepresentable mount request"
fi

# Cleanup: remove the proof containers of this group.
for sid in "$SID_RO" "$SID_RW"; do
  for cid in $(docker ps -aq --filter "label=com.dockerhelper.session.id=$sid" 2>/dev/null); do
    docker rm -f "$cid" >/dev/null 2>&1 || true
  done
done

reg_result
