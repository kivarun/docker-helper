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
#      intended target — the crafted data injects no option;
#   3. a CRLF target, which the Docker mount grammar cannot represent
#      faithfully, is refused invalid_mount before any Docker state exists;
#   4. every proof reads the real container state via docker inspect and the
#      real container filesystem, not helper responses alone.
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
ws="$home/ws"; src="$ws/src"
mkdir -p "$src"
printf 'CONTENT\n' > "$src/marker"
chown -R "$USER:$USER" "$ws"

cred="/tmp/uat-reg22.token"
reg_principal_credential "$USER" "$cred" || { reg_fail "credential create failed"; reg_result; }

# inspect_mounts prints, for the newest container of one session, the
# tab-separated bind-mount facts (Destination verbatim, RW, Source, Propagation)
# read from the real docker inspect state.
inspect_mounts() {
  local sid="$1" cid json
  cid="$(docker ps -a -q --filter "label=com.dockerhelper.session.id=$sid" --latest 2>/dev/null | head -1)"
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

session_container_count() {
  docker ps -aq --filter "label=com.dockerhelper.session.id=$1" 2>/dev/null | wc -l
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
DOCKER_HELPER_SESSION_TOKEN="$TOK_RO" \
  dh run --image "$IMAGE" \
    --mount "$src:$HOSTILE_RO_TARGET:ro" \
    -- sh -c 'p=$(printf "/mnt/probe\nreadonly-evil"); cat "$p/marker" || exit 4; if touch "$p/w-probe" 2>/dev/null; then echo WRITE-SUCCEEDED; exit 3; else echo WRITE-DENIED; fi' \
  >"$RUN_LOG" 2>&1
RC_RO=$?

if [ "$RC_RO" -eq 0 ] && grep -q 'CONTENT' "$RUN_LOG" && grep -q 'WRITE-DENIED' "$RUN_LOG"; then
  reg_ok "hostile newline RO container read the marker at the exact target and the write attempt failed"
else
  reg_fail "hostile newline RO run did not prove the RO semantics (rc=$RC_RO, log: $(cat "$RUN_LOG" | redact | tail -3))"
  reg_result
fi

MOUNTS_RO="$(inspect_mounts "$SID_RO")"
if printf '%s' "$MOUNTS_RO" | grep -F -- "$EXPECTED_RO" >/dev/null 2>&1; then
  reg_ok "docker inspect shows the exact intended newline target mounted read-only"
else
  reg_fail "docker inspect does not show the exact newline target read-only: $MOUNTS_RO"
fi
if printf '%s' "$MOUNTS_RO" | grep -F -- "${HOSTILE_RO_TARGET}${TAB}true" >/dev/null 2>&1; then
  reg_fail "a writable mount of the hostile spelling exists: $MOUNTS_RO"
else
  reg_ok "no writable mount of the hostile spelling exists"
fi

# ---------------------------------------------------------------------------
# 2. Hostile option-injection spelling stays writable at the exact target
# ---------------------------------------------------------------------------
reg_session "$cred" "$ws" || { reg_fail "second session create failed"; reg_result; }
SID_RW="$REG_SESSION_ID"; TOK_RW="$REG_SESSION_TOKEN"

INJECT_TARGET="/mnt/dta,readonly"
EXPECTED_RW="${INJECT_TARGET}${TAB}true"
RUN2_LOG="/tmp/uat-reg22-rw.log"
DOCKER_HELPER_SESSION_TOKEN="$TOK_RW" \
  dh run --image "$IMAGE" \
    --mount "$src:$INJECT_TARGET" \
    -- sh -c 'cat /mnt/dta/marker; echo RW-RAN' \
  >"$RUN2_LOG" 2>&1
RC_RW=$?

if [ "$RC_RW" -eq 0 ] && grep -q 'CONTENT' "$RUN2_LOG" && grep -q 'RW-RAN' "$RUN2_LOG"; then
  reg_ok "option-injection spelling run completed writable at the crafted target"
else
  reg_fail "option-injection spelling run failed (rc=$RC_RW, log: $(cat "$RUN2_LOG" | redact | tail -3))"
  reg_result
fi

MOUNTS_RW="$(inspect_mounts "$SID_RW")"
if printf '%s' "$MOUNTS_RW" | grep -F -- "$EXPECTED_RW" >/dev/null 2>&1; then
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
