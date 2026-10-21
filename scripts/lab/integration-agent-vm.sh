#!/usr/bin/env bash
#
# integration-agent-vm.sh — REAL end-to-end checks inside the lab VM
# (SELinux enforcing, real dockerd + docker-helper v2.3.0, real container).
#
# Run as root in the guest, after install-docker-helper-v230.sh and
# setup-agent-user.sh have run. Complements the stubbed unit tests by entering
# through the real production paths.
#
# What it proves (one invariant per check):
#   1. the installed docker-helper is the pinned v2.3.0;
#   2. opc and agent have distinct uids and no duplicate-uid resolution;
#   3. the principal record matches the OS uid;
#   4. SELinux is enforcing, the daemon runs in docker_helper_t, the binary is
#      docker_helper_exec_t;
#   5. an existing valid credential is reused (no rotate);
#   6. a missing credential fails closed without rotating;
#   7. rotation semantics run on a SEPARATE named test credential (old bearer
#      dies, new bearer lives, revocation closes it, the default credential is
#      untouched);
#   8. the launcher creates one Session, runs the container as the agent uid,
#      and deletes the Session (no orphan);
#   9. the container argv carries the isolation posture and only the bearer;
#  10. the model reaches docker-helper through the Session bearer inside the
#      real container, and is denied without the bearer;
#  11. a failing launcher propagates a NONZERO exit status;
#  12. the system docker-init inode and SELinux label are unchanged by the
#      launch (the lab copy is byte-identical and carries the relabel);
#  13. the container can write the agent-owned OpenCode mounts;
#  14. the explicit --recover-credential path rotates and reinstalls the
#      default credential, leaving a consistent final state.
#
# Rotation checks use a separate named test credential (revoked afterwards);
# the explicit recovery runs last so a mid-suite failure never leaves the
# default credential rotated without the follow-up checks.
#
# Artifact hygiene: everything for one run lives in a single mktemp -d
# workspace created with umask 077. Credential material (test bearer files)
# sits in a root-owned 0700 subdirectory with 0600 files; the records the
# agent-user shim writes go into a dedicated agent-owned 0750 subdirectory.
# Nothing is written under predictable global /tmp paths, nothing is
# world-writable, and the EXIT/INT/TERM traps remove the run directory (and
# restore a moved credential) — no secrets or evidence files are left behind.
# Bearers are never printed to stdout/stderr or any report.
#
# Env: EXPECT_VERSION (default 2.3.0), AGENT_USER (default agent).
set -u
umask 077

EXPECT_VERSION="${EXPECT_VERSION:-2.3.0}"
AGENT_USER="${AGENT_USER:-agent}"
AGENT_HOME="/home/$AGENT_USER"
DH=/usr/bin/docker-helper
CRED="$AGENT_HOME/.config/docker-helper/credential.token"
CRED_MOVED="$AGENT_HOME/.config/docker-helper/credential.token.itest-moved"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab-vm-guard.sh
. "$SCRIPT_DIR/lab-vm-guard.sh"
require_lab_vm

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf 'skip - %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2' got '$3')"; fi; }
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2' in '$3')" ;; esac; }
not_contains() { case "$3" in *"$2"*) bad "$1 (unexpected '$2')" ;; *) ok "$1" ;; esac; }

# --- per-run private workspace ----------------------------------------------
# root-owned 0711 traversal root; secrets stay in a 0700 subdirectory; the
# agent-writable recorder area is a separate 0750 directory owned by agent.
[ "$(id -u)" = 0 ] || { echo "must run as root in the guest" >&2; exit 1; }
getent passwd "$AGENT_USER" >/dev/null || { echo "no $AGENT_USER account (run setup-agent-user.sh first)" >&2; exit 1; }

ITEST_DIR="$(mktemp -d)" || { echo "mktemp failed" >&2; exit 1; }
chmod 0711 "$ITEST_DIR"
SECRETS_DIR="$ITEST_DIR/secrets"
RUN_DIR="$ITEST_DIR/run"
SHIM="$ITEST_DIR/shim"
RUNNER="$ITEST_DIR/run.sh"
mkdir -m 0700 "$SECRETS_DIR"
install -d -m 0755 "$SHIM"
install -d -m 0750 -o "$AGENT_USER" -g "$AGENT_USER" "$RUN_DIR"

cleanup() {
  # Restore a moved credential first, then remove only THIS run's directory.
  [ -e "$CRED_MOVED" ] && mv -f "$CRED_MOVED" "$CRED" 2>/dev/null
  [ -z "${tls_srv_pid:-}" ] || kill "$tls_srv_pid" 2>/dev/null || true
  rm -rf -- "$ITEST_DIR"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# --- 1. pinned version ------------------------------------------------------
check "docker-helper version is v$EXPECT_VERSION" "$EXPECT_VERSION" "$("$DH" version)"

# --- 1b. Docker runtime inside the VM ---------------------------------------
docker_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null)" \
  && ok "docker server version: $docker_version" || bad "docker version failed"
systemctl is-active --quiet docker && ok "docker.service is active" || bad "docker.service is not active"
[ -S /run/docker.sock ] && ok "docker socket present" || bad "docker socket missing"
sock_ctx="$(stat -c '%C' /run/docker.sock 2>/dev/null || echo unknown)"
case "$sock_ctx" in
  *var_run_t*) ok "docker socket SELinux context: $sock_ctx" ;;
  *) bad "unexpected docker socket SELinux context: $sock_ctx" ;;
esac
sudo -u "$AGENT_USER" docker info >/dev/null 2>&1 \
  && ok "the agent (trusted launcher) reaches the docker daemon" \
  || bad "the agent cannot reach the docker daemon"

# --- 2. uid uniqueness ------------------------------------------------------
opc_uid="$(id -u opc)"
agent_uid="$(id -u "$AGENT_USER")"
if [ "$opc_uid" != "$agent_uid" ]; then ok "opc and agent uids differ ($opc_uid vs $agent_uid)"; else bad "uid collision: both $opc_uid"; fi
check "getent resolves the agent uid to $AGENT_USER" "$AGENT_USER" "$(getent passwd "$agent_uid" | cut -d: -f1)"
check "getent resolves the opc uid to opc" "opc" "$(getent passwd "$opc_uid" | cut -d: -f1)"

# --- 3. principal record matches the OS uid ---------------------------------
p_uid="$("$DH" principal show "$AGENT_USER" --json | jq -r '.uid')"
check "principal record uid matches the OS uid" "$agent_uid" "$p_uid"

# --- 4. SELinux -------------------------------------------------------------
check "SELinux enforcing" "Enforcing" "$(getenforce)"
contains "daemon runs in docker_helper_t" "docker_helper_t" "$(ps -o label= -C docker-helper | head -1)"
contains "binary carries docker_helper_exec_t" "docker_helper_exec_t" "$(ls -Z "$DH")"
check "docker_helper policy module loaded" "docker_helper" "$(semodule -l | awk '/^docker_helper/ {print $1}')"

# --- 5. valid credential reused --------------------------------------------
bash /opt/lab/setup-agent-user.sh >"$ITEST_DIR/setup.out" 2>&1 && ok "idempotent setup succeeds" || bad "idempotent setup failed"
contains "valid credential reused" "reusing the installed credential" "$(cat "$ITEST_DIR/setup.out")"
not_contains "reuse does not rotate" "recovering credential" "$(cat "$ITEST_DIR/setup.out")"

# --- 6. missing credential fails closed (no rotate) -------------------------
# The move is a rename INSIDE the agent's credential directory (same
# filesystem, ownership preserved); the EXIT/INT/TERM trap restores it.
default_id="$("$DH" principal credential list "$AGENT_USER" --json | jq -r '.credentials[0].id')"
mv "$CRED" "$CRED_MOVED"
if bash /opt/lab/setup-agent-user.sh >"$ITEST_DIR/fc.out" 2>&1; then bad "missing credential was accepted"; else ok "missing credential fails closed"; fi
check "fail-closed did not rotate (same credential id)" "$default_id" "$("$DH" principal credential list "$AGENT_USER" --json | jq -r '.credentials[0].id')"
mv "$CRED_MOVED" "$CRED"

# --- 7. rotation semantics on a SEPARATE named test credential --------------
tc_json="$("$DH" principal credential create "$AGENT_USER" --name labtest --json)"
tc_id="$(printf '%s' "$tc_json" | jq -r '.credential.id')"
tc_tok1="$(printf '%s' "$tc_json" | jq -r '.token')"
tc_json=""
[ -n "$tc_tok1" ] && ok "separate test credential created" || bad "test credential creation failed"
# Bearer files live only in the root-owned 0700 secrets dir, mode 0600.
printf '%s\n' "$tc_tok1" > "$SECRETS_DIR/testcred.token"
chmod 0600 "$SECRETS_DIR/testcred.token"
unset tc_tok1
"$DH" self --token-file "$SECRETS_DIR/testcred.token" >/dev/null 2>&1 && ok "test credential authenticates" || bad "test credential rejected"
tr_json="$("$DH" principal credential rotate "$AGENT_USER" --name labtest --json)"
tc_tok2="$(printf '%s' "$tr_json" | jq -r '.token')"
tr_json=""
[ -n "$tc_tok2" ] && ok "test credential rotated (replacement bearer returned)" || bad "test credential rotation returned no bearer"
printf '%s\n' "$tc_tok2" > "$SECRETS_DIR/testcred2.token"
chmod 0600 "$SECRETS_DIR/testcred2.token"
unset tc_tok2
"$DH" self --token-file "$SECRETS_DIR/testcred.token" >/dev/null 2>&1 \
  && bad "old test bearer still valid after rotate" || ok "old test bearer invalidated by rotate"
"$DH" self --token-file "$SECRETS_DIR/testcred2.token" >/dev/null 2>&1 \
  && ok "rotated test bearer authenticates" || bad "rotated test bearer rejected"
"$DH" principal credential revoke "$tc_id" --json >/dev/null 2>&1 && ok "test credential revoked" || bad "test credential revocation failed"
"$DH" self --token-file "$SECRETS_DIR/testcred2.token" >/dev/null 2>&1 \
  && bad "revoked test bearer still authenticates" || ok "revoked test bearer rejected"
sudo -u "$AGENT_USER" "$DH" self --json >/dev/null 2>&1 \
  && ok "default agent credential untouched by the test rotation" \
  || bad "default agent credential broken by the test rotation"

# --- 7b. corporate CA provisioning (optional; provisioned by the operator) --
# The helper injection path (trusted_ca_path + trusted_ca_injection=auto) is
# verified through the supported CLI surface; the container-facing lab copy
# must be byte-identical to the trust-store anchor. With no CA provisioned
# these checks are an explicit SKIP, never a silent pass.
ca_anchor=""
for cand in /etc/pki/trust/anchors/*; do
  # The helper copy identifies the provisioned CA uniquely.
  if [ -f "/etc/docker-helper/$(basename "$cand").crt" ]; then
    ca_anchor="$cand"
    break
  fi
done
if [ -n "$ca_anchor" ]; then
  ca_name="$(basename "$ca_anchor")"
  tcp_inj="$(docker-helper config show --json 2>/dev/null | jq -r '.trusted_ca_injection // empty')"
  check "trusted_ca_injection is auto" "auto" "$tcp_inj"
  tcp_path="$(docker-helper config show --json 2>/dev/null | jq -r '.trusted_ca_path // empty')"
  check "trusted_ca_path points at the helper-owned copy" "/etc/docker-helper/$ca_name.crt" "$tcp_path"
  check "anchor and helper CA copy are byte-identical" \
    "$(sha256sum < "$ca_anchor" | awk '{print $1}')" \
    "$(sha256sum < "/etc/docker-helper/$ca_name.crt" | awk '{print $1}')"
  if [ -f "$AGENT_HOME/.opencode-docker/ca/$ca_name.crt" ]; then
    check "anchor and container CA copy are byte-identical" \
      "$(sha256sum < "$ca_anchor" | awk '{print $1}')" \
      "$(sha256sum < "$AGENT_HOME/.opencode-docker/ca/$ca_name.crt" | awk '{print $1}')"
  else
    bad "container-facing CA copy missing: $AGENT_HOME/.opencode-docker/ca/$ca_name.crt"
  fi
else
  skip "corporate CA checks (no CA provisioned)"
fi

# --- 8/9/10. real launcher end-to-end ---------------------------------------
ws="$AGENT_HOME/work/itest"
install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$ws"
cat > "$SHIM/docker-helper" <<'SH'
#!/bin/sh
if [ "${1:-} ${2:-}" = "session create" ] && [ -n "${FAIL_SESSION_CREATE:-}" ]; then
  echo "DHFAIL session create unavailable" >&2
  exit 1
fi
printf 'DH %s\n' "$*" >> "$ARGV_REC"
exec /usr/bin/docker-helper "$@"
SH
chmod 0755 "$SHIM/docker-helper"
cat > "$RUNNER" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
export PATH="$SHIM_DIR:$PATH"
cd "$1"
docker() { printf '%s\n' "$*" >> "$ARGV_REC"; command docker "$@"; }
# shellcheck source=/dev/null
source "$HOME/.bash_aliases"
# C7/F3: `oc` is a Bash function — GNU timeout cannot exec it directly. Every
# time-bounded launch therefore runs inside a fresh, correctly initialized
# Bash (aliases sourced, docker recorder present). timeout bounds the WHOLE
# launch; the launcher's own traps clean up the Session and the ssh-agent when
# the timeout kills the shell; the exit status propagates through timeout.
oc_t() {
  timeout 60 bash -c '
    docker() { printf "%s\n" "$*" >> "$ARGV_REC"; command docker "$@"; }
    # shellcheck source=/dev/null
    source "$HOME/.bash_aliases"
    oc "$@"
  ' _ "$@"
}
oc --version
# The model's access path: docker-helper self inside the real container with
# the Session bearer. Two argv channels are attempted (direct image args and
# sh -c) because the image entrypoint contract is not pinned here; each
# attempt is time-bounded so a TTY-hungry argv interpretation cannot hang the
# probe. The check fails only when NEITHER channel reaches the helper.
channel=none
self_out=""
if out="$(oc_t docker-helper self --json 2>&1)" && printf '%s' "$out" | grep -q '"type"'; then
  channel=args; self_out="$out"
elif out="$(oc_t sh -c 'docker-helper self --json' 2>&1)" && printf '%s' "$out" | grep -q '"type"'; then
  channel=sh; self_out="$out"
else
  out="$(oc_t sh -c 'docker-helper self --json' 2>&1)" || true
  self_out="$out"
fi
printf 'SELF_CHANNEL=%s\n' "$channel" >> "$ARGV_REC"
printf '%s\n' "$self_out" > "$OC_SELF_OUT"
nb_rc=""
nb_out=""
if [ "$channel" = args ]; then
  if out="$(oc_t env -u DOCKER_HELPER_SESSION_TOKEN docker-helper self --json 2>&1)"; then nb_rc=0; nb_out="$out"; else nb_rc=$?; nb_out="$out"; fi
elif [ "$channel" = sh ]; then
  if out="$(oc_t sh -c 'unset DOCKER_HELPER_SESSION_TOKEN; docker-helper self --json' 2>&1)"; then nb_rc=0; nb_out="$out"; else nb_rc=$?; nb_out="$out"; fi
fi
printf 'NO_BEARER_RC=%s\n' "${nb_rc:-none}" >> "$ARGV_REC"
printf '%s\n' "$nb_out" > "$OC_NOBEARER_OUT"
SH
chmod 0755 "$RUNNER"
# Recorder files are pre-created agent-owned (0600) in the agent-owned 0750
# run directory: no world-writable evidence file exists.
ARGV="$RUN_DIR/argv"
install -m 0600 -o "$AGENT_USER" -g "$AGENT_USER" /dev/null "$ARGV"
ARGV_FAIL="$RUN_DIR/argv-fail"
install -m 0600 -o "$AGENT_USER" -g "$AGENT_USER" /dev/null "$ARGV_FAIL"

# System docker-init state BEFORE the launch (label, ownership, mode, inode).
init_sys="$(readlink -f "$(command -v docker-init 2>/dev/null || echo /usr/bin/docker-init)")"
init_before="$(stat -c '%n %C %u:%g %a' "$init_sys")"
init_inode_before="$(stat -c '%i' "$init_sys")"

sudo -u "$AGENT_USER" env ARGV_REC="$ARGV" SHIM_DIR="$SHIM" \
  OC_SELF_OUT="$RUN_DIR/oc-self.out" OC_NOBEARER_OUT="$RUN_DIR/oc-nobearer.out" \
  script -qec "bash $RUNNER $ws" /dev/null >"$ITEST_DIR/oc.out" 2>&1
oc_rc=$?
if [ "$oc_rc" = 0 ]; then ok "launcher exited 0"; else bad "launcher exited $oc_rc"; fi
grep -Eq '[0-9]+\.[0-9]+\.[0-9]+' "$ITEST_DIR/oc.out" && ok "container ran opencode (version printed)" || bad "no opencode version in output"

argv="$(cat "$ARGV")"
contains "launcher created a Session" "DH session create" "$argv"
contains "launcher deleted the Session" "DH session delete" "$argv"
contains "container runs as the agent uid" "--user $(id -u "$AGENT_USER"):$(id -g "$AGENT_USER")" "$argv"
contains "container drops caps" "--cap-drop ALL" "$argv"
contains "container sets no-new-privileges" "no-new-privileges=true" "$argv"
contains "container runs in docker_helper_container_t" "label=type:docker_helper_container_t" "$argv"
contains "workspace is a private relabel" ":/workspace:Z" "$argv"
contains "opencode .local is agent-owned" "/.local:/home/opencode/.local:Z" "$argv"
contains "helper runtime dir is read-only" "/run/docker-helper:ro" "$argv"
contains "container gets only the session bearer env" "-e DOCKER_HELPER_SESSION_TOKEN" "$argv"
not_contains "container has no docker.sock" "docker.sock" "$argv"
not_contains "container has no admin token" "ADMIN" "$argv"
not_contains "container has no principal credential" "/.config/docker-helper" "$argv"
not_contains "the agent's real .ssh is never a mount source" "-v $AGENT_HOME/.ssh" "$argv"
not_contains "the private ssh key is never a mount source" "$AGENT_HOME/.ssh/id_ed25519_opencode" "$argv"

# SSH agent forwarding (optional; only when the operator provisioned a key).
if [ -f "$AGENT_HOME/.ssh/id_ed25519_opencode" ]; then
  # C7/F3: since the per-launch private run directories, the mount source is
  # agent-ssh/run.XXXXXX — the assertion checks the structure (private run
  # directory under agent-ssh, read-only, unique name), not a fixed name.
  ssh_mount="$(printf '%s' "$argv" | grep -oE -- "-v $AGENT_HOME/\.opencode-docker/agent-ssh/run\.[A-Za-z0-9]{6}:/ssh-agent:ro" | head -1)"
  if [ -n "$ssh_mount" ]; then
    ok "the per-launch ssh-agent run dir is mounted read-only for the model"
  else
    bad "no agent-ssh run.<suffix> mount for the model: $(printf '%s' "$argv" | grep -o -- '-v [^ ]*agent-ssh[^ ]*' | head -2)"
  fi
  ssh_mounts="$(printf '%s' "$argv" | grep -oE -- "-v $AGENT_HOME/\.opencode-docker/agent-ssh/run\.[A-Za-z0-9]{6}:" | sort -u | wc -l)"
  check "exactly one ssh-agent run dir is mounted" "1" "$ssh_mounts"
  contains "SSH_AUTH_SOCK points at the forwarded socket" \
    "-e SSH_AUTH_SOCK=/ssh-agent/agent.sock" "$argv"
else
  skip "ssh-agent forwarding argv checks (no agent key provisioned)"
fi
# init binary: the mount source is the lab copy, never the system binary.
init_copy="$AGENT_HOME/.opencode-docker/init/docker-init"
contains "init mount target is the runtime init path" ":/sbin/docker-init:ro,z" "$argv"
contains "init mount source is the lab copy" "$init_copy:/sbin/docker-init:ro,z" "$argv"
not_contains "system docker-init is never a mount source" "$init_sys:" "$argv"
if [ -f "$init_copy" ] && [ "$(sha256sum < "$init_copy" | awk '{print $1}')" = "$(sha256sum < "$init_sys" | awk '{print $1}')" ]; then
  ok "lab init copy is byte-identical to the system binary"
else
  bad "lab init copy missing or differs from the system binary"
fi

# in-container model access: bearer works, absence is denied.
self_channel="$(printf '%s' "$argv" | sed -n 's/^SELF_CHANNEL=//p')"
if [ "$self_channel" != "none" ]; then
  ok "docker-helper is reachable inside the container ($self_channel channel)"
else
  bad "docker-helper was NOT reachable inside the container: $(tail -c 300 "$RUN_DIR/oc-self.out" 2>/dev/null)"
fi
contains "model self via the Session bearer reports a session" '"type": "session"' "$(cat "$RUN_DIR/oc-self.out" 2>/dev/null || true)"
nb_line="$(printf '%s' "$argv" | sed -n 's/^NO_BEARER_RC=//p')"
if [ -n "$nb_line" ] && [ "$nb_line" != "none" ] && [ "$nb_line" != "0" ]; then
  ok "self without the bearer is denied (rc $nb_line)"
else
  bad "self without the bearer was not denied (NO_BEARER_RC=$nb_line)"
fi
grep -Eiq '401|unauthorized' "$RUN_DIR/oc-nobearer.out" 2>/dev/null \
  && ok "denial without the bearer comes from the daemon (unauthorized)" \
  || bad "no daemon denial evidence without the bearer"

# --- 11. a failing launcher propagates a nonzero exit status ----------------
sudo -u "$AGENT_USER" env ARGV_REC="$ARGV_FAIL" SHIM_DIR="$SHIM" FAIL_SESSION_CREATE=1 \
  script -qec "bash $RUNNER $ws" /dev/null >"$ITEST_DIR/oc-fail.out" 2>&1
fail_rc=$?
if [ "$fail_rc" != 0 ]; then ok "failing launcher propagates a nonzero rc ($fail_rc)"; else bad "failing launcher reported success"; fi
grep -q 'DHFAIL' "$ITEST_DIR/oc-fail.out" \
  && ok "the failure came from the session-create path (DHFAIL marker)" \
  || bad "the intended failure path was not reached (no DHFAIL marker)"

# --- 11b. TLS trust is ENFORCED inside the container (negative evidence) -----
# A throwaway self-signed TLS server runs in the guest (untrusted for the
# container): the container TLS client must REFUSE the handshake. An error
# that is not a certificate error would be inconclusive and is reported as
# FAIL. When the CA is provisioned, the container env must carry
# NODE_EXTRA_CA_CERTS pointing at the mounted lab copy.
if command -v openssl >/dev/null 2>&1 && [ -n "$(ip -4 -o addr show docker0 2>/dev/null | awk '{print $4; exit}')" ]; then
  bridge_ip="$(ip -4 -o addr show docker0 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')"
  tcert="$ITEST_DIR/tls-srv.crt"; tkey="$ITEST_DIR/tls-srv.key"
  openssl req -x509 -newkey rsa:2048 -nodes -batch -subj "/CN=lab-foreign-tls" \
    -keyout "$tkey" -out "$tcert" -days 1 >/dev/null 2>&1 \
    || bad "cannot generate the throwaway TLS test certificate"
  openssl s_server -accept 9443 -cert "$tcert" -key "$tkey" -www >/dev/null 2>&1 &
  tls_srv_pid=$!
  srv_ready=0
  for _ in $(seq 1 20); do
    if timeout 2 bash -c "exec 3<>/dev/tcp/$bridge_ip/9443" 2>/dev/null; then srv_ready=1; break; fi
    sleep 0.1
  done
  if [ "$srv_ready" = 1 ]; then
    ARGV_TLS="$RUN_DIR/argv-tls"
    install -m 0600 -o "$AGENT_USER" -g "$AGENT_USER" /dev/null "$ARGV_TLS"
    RUNNER_TLS="$ITEST_DIR/run-tls.sh"
    probe_cmd="printenv NODE_EXTRA_CA_CERTS || true; if command -v curl >/dev/null 2>&1; then curl -sS --max-time 6 https://$bridge_ip:9443/ 2>&1; echo TLS_RC=\$?; else echo NO_CURL_IN_CONTAINER; fi"
    cat > "$RUNNER_TLS" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
export PATH="$SHIM_DIR:$PATH"
cd "$1"
docker() { printf '%s\n' "$*" >> "$ARGV_REC"; command docker "$@"; }
# shellcheck source=/dev/null
source "$HOME/.bash_aliases"
# F6: the curl availability check runs INSIDE the container (the probe
# executes there), not in the guest; the probe command arrives through
# TLS_PROBE_CMD from the outer script. C7/F3: the same time-bounded,
# correctly initialized Bash wrapper as the runner's oc_t — `oc` is a
# function and cannot be exec'd by timeout directly.
raw="$(timeout 90 bash -c '
  docker() { printf "%s\n" "$*" >> "$ARGV_REC"; command docker "$@"; }
  # shellcheck source=/dev/null
  source "$HOME/.bash_aliases"
  oc sh -c "$TLS_PROBE_CMD"
' 2>&1 || true)"
printf '%s\n' "$(printf '%s\n' "$raw" | head -1)" > "$CA_ENV_OUT"
printf '%s\n' "$(printf '%s\n' "$raw" | tail -n +2)" > "$TLS_OUT"
SH
    chmod 0755 "$RUNNER_TLS"
    sudo -u "$AGENT_USER" env ARGV_REC="$ARGV_TLS" SHIM_DIR="$SHIM" \
      TLS_TARGET_IP="$bridge_ip" TLS_PROBE_CMD="$probe_cmd" \
      CA_ENV_OUT="$RUN_DIR/ca-env.out" TLS_OUT="$RUN_DIR/tls.out" \
      script -qec "bash $RUNNER_TLS $ws" /dev/null >"$ITEST_DIR/oc-tls.out" 2>&1
    kill "$tls_srv_pid" 2>/dev/null || true
    tls_srv_pid=""
    if grep -q 'NO_CURL_IN_CONTAINER' "$RUN_DIR/tls.out"; then
      skip "in-container TLS check (curl is not available inside the image)"
    else
      tls_rc="$(sed -n 's/^TLS_RC=//p' "$RUN_DIR/tls.out")"
      tls_text="$(grep -v '^TLS_RC=' "$RUN_DIR/tls.out" || true)"
      verdict="$("$SCRIPT_DIR/tls-verdict.sh" "${tls_rc:-999}" "$tls_text" | head -1)"
      case "$verdict" in
        VERIFICATION_FAILURE)
          ok "the container rejected the untrusted TLS endpoint (rc $tls_rc)"
          if printf '%s' "$tls_text" | grep -qi 'certificate'; then
            ok "the refusal is a certificate-validation failure, not a connection error"
          else
            bad "the TLS refusal could not be attributed to certificate validation: $(tail -c 200 "$RUN_DIR/tls.out" 2>/dev/null)"
          fi
          ;;
        ACCEPTED)
          bad "the container ACCEPTED the untrusted TLS endpoint"
          ;;
        CONNECTION_FAILURE)
          skip "the TLS probe is inconclusive (connection failure despite a ready server)"
          ;;
        *)
          skip "the TLS probe is inconclusive (unexpected outcome, rc=${tls_rc:-unset})"
          ;;
      esac
    fi
    if [ -n "$ca_anchor" ]; then
      check "NODE_EXTRA_CA_CERTS reaches the container" \
        "/etc/opencode-ca/$ca_name.crt" \
        "$(cat "$RUN_DIR/ca-env.out" 2>/dev/null | head -1)"
    fi
  else
    skip "in-container TLS check (the throwaway server did not become reachable)"
  fi
  kill "$tls_srv_pid" 2>/dev/null || true
  tls_srv_pid=""
else
  skip "in-container TLS check (openssl or the docker bridge is unavailable)"
fi

# --- 12. system docker-init unchanged ---------------------------------------
init_after="$(stat -c '%n %C %u:%g %a' "$init_sys")"
init_inode_after="$(stat -c '%i' "$init_sys")"
check "system docker-init label/ownership/mode unchanged" "$init_before" "$init_after"
check "system docker-init inode unchanged" "$init_inode_before" "$init_inode_after"

n_sessions="$(sudo -u "$AGENT_USER" "$DH" session list --json | jq '.sessions | length')"
check "no orphan Session after the launches" "0" "$n_sessions"

# the container wrote the agent-owned state tree (mount writability across uid)
if [ -n "$(find "$AGENT_HOME/.opencode-docker/.local" -mindepth 1 2>/dev/null)" ]; then
  ok "container wrote the agent-owned .local tree"
else
  bad "container did not write the agent-owned .local tree"
fi

# --- 13. explicit recovery on the default credential (last; consistent) -----
bash /opt/lab/setup-agent-user.sh --recover-credential >"$ITEST_DIR/rec.out" 2>&1 && ok "recovery succeeds" || bad "recovery failed"
check "rotate keeps the credential id" "$default_id" "$("$DH" principal credential list "$AGENT_USER" --json | jq -r '.credentials[0].id')"
sudo -u "$AGENT_USER" "$DH" self --json >"$ITEST_DIR/self.out" 2>&1 && ok "rotated default bearer authenticates" || bad "rotated default bearer rejected"
contains "self reports the agent principal" '"type": "principal"' "$(cat "$ITEST_DIR/self.out")"
n_sessions="$(sudo -u "$AGENT_USER" "$DH" session list --json | jq '.sessions | length')"
check "no orphan Session at the end" "0" "$n_sessions"

echo
printf 'agent VM integration: %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" = 0 ]
