#!/usr/bin/env bash
#
# uat-regression-selinux-helper-socket.sh — 2.1.1 targeted regression
# group 6: helper_socket live enforcing SELinux UAT (Tumbleweed / RPM / SELinux).
#
# Proves, black-box on a real enforcing guest with the exact candidate RPM,
# that the 2.1.1 helper_socket capability works under the confined
# docker_helper_container_t domain and grants nothing beyond transport:
#
#   1. ordinary run without --helper-socket: no helper runtime inside the
#      workload and the container process runs as docker_helper_container_t;
#   2. run with --helper-socket: the injected socket is reachable;
#   3. a real authorized request through the injected socket with an
#      explicit Launcher bearer credential succeeds (connectto/sock_file
#      grants actually enforced);
#   4. helper-private runtime state stays unreadable;
#   5. bounded AVC evidence: zero unexpected denials from
#      docker_helper_container_t during the scenario (the capability works
#      through the shipped grants, not permissive/unconfined fallback).
#
# Requires: installed docker-helper system service (active), enforcing SELinux,
# root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "6. SELinux helper_socket enforcing UAT"

reg_require_root
reg_require_service
reg_require_cmd docker "the workload runs through Docker"
reg_require_cmd ausearch "bounded AVC evidence"

if [ "$(getenforce 2>/dev/null || true)" != "Enforcing" ]; then
  reg_blocked "SELinux is not enforcing"
fi

IMAGE="alpine:3.24"
AVC_TS="$(date '+%m/%d/%Y %H:%M:%S')"

# Workspace inside an authorized global root (/opt; /home/* is not authorized
# on the enforcing guest — its home root is the operator's own /home/opc).
WS="/opt/uat-reg6-$RANDOM/ws"
mkdir -p "$WS"
dh config allowed-root add /opt >/dev/null 2>&1 || true
dh config reload --system >/dev/null 2>&1 || true

# --- session owner (principal + default Launcher + credential) ----------------
SEL_P="selsock"; SEL_CRED="/tmp/selsock.tok"
reg_setup_principal "$SEL_P" >/dev/null || { reg_fail "principal setup failed"; reg_result; }
dh principal allowed-root add --system "$SEL_P" /opt >/dev/null 2>&1 \
  || { reg_fail "principal allowed-root add failed"; reg_result; }
reg_principal_credential "$SEL_P" "$SEL_CRED" || { reg_fail "credential create failed"; reg_result; }

# Launcher credential for the explicit in-workload bearer (value kept out of argv).
LC_JSON="$(dh launcher credential create --system --principal "$SEL_P" 2>/dev/null)" \
  || { reg_fail "launcher credential create failed"; reg_result; }
LC_TOKEN="$(printf '%s\n' "$LC_JSON" | json_field token)"
[ -n "$LC_TOKEN" ] || { reg_fail "launcher credential token missing"; reg_result; }

reg_session "$SEL_CRED" "$WS" || { reg_fail "session create failed"; reg_result; }
SID="$REG_SESSION_ID"; STOK="$REG_SESSION_TOKEN"

# docker-helper binary travels through the workspace bind for the in-workload op.
cp /usr/bin/docker-helper "$WS/docker-helper"
chmod 755 "$WS/docker-helper"
rm -f "$WS/reg6-child-id" 2>/dev/null || true

# --- 1. ordinary run: no projection, confined container domain ----------------
# Without --helper-socket no helper SOCKET may appear inside the workload.
# (The /run/docker-helper DIRECTORY may exist by design: the trusted-CA
# projection mounts into /run/docker-helper/trusted-ca.)
if DOCKER_HELPER_SESSION_TOKEN="$STOK" \
   dh run --image "$IMAGE" --mount .:/workspace \
   -- sh -ec '
     test ! -S /run/docker-helper/docker-helper.sock
     label="$(cat /proc/self/attr/current 2>/dev/null || true)"
     case "$label" in *docker_helper_container_t*) true;; *) echo "unexpected domain: $label" >&2; exit 1;; esac
     echo DOM-OK' 2>&1 | grep -q 'DOM-OK'; then
  reg_ok "ordinary run: no helper socket inside the workload; process domain docker_helper_container_t"
else
  reg_fail "ordinary run: projection/domain invariant violated"
fi

# --- 2. run with --helper-socket: the injected socket is reachable -------------
if DOCKER_HELPER_SESSION_TOKEN="$STOK" \
   dh run --image "$IMAGE" --helper-socket \
   -- sh -ec '
     test -S /run/docker-helper/docker-helper.sock
     label="$(cat /proc/self/attr/current 2>/dev/null || true)"
     case "$label" in *docker_helper_container_t*) true;; *) echo "unexpected domain: $label" >&2; exit 1;; esac
     echo SOCK-OK' 2>&1 | grep -q 'SOCK-OK'; then
  reg_ok "run with --helper-socket: injected socket reachable under docker_helper_container_t"
else
  reg_fail "run with --helper-socket did not expose the socket under the confined domain"
fi

# --- 3. real authorized request through the injected socket --------------------
if DOCKER_HELPER_SESSION_TOKEN="$STOK" UAT_LAUNCHER_CRED_SOURCE="$LC_TOKEN" \
   dh run --image "$IMAGE" --helper-socket --mount .:/workspace \
   --env-from "UAT_LC=UAT_LAUNCHER_CRED_SOURCE" \
   -- sh -ec '
     printf "%s\n" "$UAT_LC" > /tmp/launcher-cred
     chmod 600 /tmp/launcher-cred
     LIST=$(/workspace/docker-helper session list \
       --endpoint /run/docker-helper/docker-helper.sock \
       --token-file /tmp/launcher-cred --json)
     printf "%s\n" "$LIST" | grep -qF "$1"
     rm -f /tmp/launcher-cred
     echo AUTHZ-OK' _ "$SID" 2>&1 | grep -q 'AUTHZ-OK'; then
  reg_ok "authorized Launcher operation through the injected socket succeeded (enforcing)"
else
  reg_fail "authorized operation through the injected socket failed under enforcing SELinux"
fi

# --- 4. helper-private runtime state stays unreadable ---------------------------
if DOCKER_HELPER_SESSION_TOKEN="$STOK" \
   dh run --image "$IMAGE" --helper-socket -- sh -ec '
     ls /run/docker-helper/builds >/dev/null 2>&1 && exit 1
     ls /run/docker-helper/mounts >/dev/null 2>&1 && exit 1
     ls /run/docker-helper/sessions >/dev/null 2>&1 && exit 1
     cat /run/docker-helper/docker-helper.sock.lock >/dev/null 2>&1 && exit 1
     echo PRIVATE-OK' 2>&1 | grep -q 'PRIVATE-OK'; then
  reg_ok "helper-private runtime state unreadable for the workload"
else
  reg_fail "helper-private runtime state was readable"
fi

# --- 5. bounded AVC evidence: zero unexpected denials from the container domain -
AVC_OUT="$(ausearch -m AVC,USER_AVC -ts "$AVC_TS" 2>/dev/null | grep 'docker_helper_container_t' || true)"
if [ -z "$AVC_OUT" ]; then
  reg_ok "no unexpected AVC from docker_helper_container_t during the helper_socket scenario"
else
  reg_fail "unexpected AVC from docker_helper_container_t during the helper_socket scenario: $(printf '%s' "$AVC_OUT" | tail -5 | tr '\n' ' ')"
fi

# --- cleanup --------------------------------------------------------------------
dh session delete --system --id "$SID" >/dev/null 2>&1 || reg_fail "session delete failed"
rm -f "$SEL_CRED"
rm -rf "$(dirname "$WS")"

reg_result
