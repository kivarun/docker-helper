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

# --- UAT-8: explicit integration mode ---------------------------------------
# ISOLATED (default): the run happens against a VM booted with restrict=on;
#   the isolation EVIDENCE itself belongs to the isolate/verify stages and
#   the standalone network probe — never to this script.
# NETWORKED (INTEGRATION_NETWORKED=1, selected explicitly by the
#   uat-networked driver stage): the guest network is ON for real
#   integration work. This run makes NO isolation claims, and a networked
#   VM can never pass the isolation verification (the QEMU argv evidence
#   gate refuses anything without restrict=on).
INTEGRATION_NETWORKED="${INTEGRATION_NETWORKED:-0}"
case "$INTEGRATION_NETWORKED" in
  0) printf 'integration mode: ISOLATED\n' ;;
  1) printf 'integration mode: NETWORKED (guest network ON) — this run makes no VM isolation claims\n' ;;
  *) echo "INTEGRATION_NETWORKED must be 0 or 1" >&2; exit 2 ;;
esac

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
# R3: even the version probe is time-bounded through the same wrapper — a
# TTY-hungry entrypoint interpretation cannot hang the suite here either.
if oc_t --version; then version_rc=0; else version_rc=$?; fi
# UAT-8: the image ENTRYPOINT is `opencode`, so `oc docker-helper self ...`
# and `oc sh -c ...` hand their words to the OpenCode CLI as ITS arguments —
# neither docker-helper nor sh ever ran (the real-VM finding). The model's
# access path is exercised through oc-probe: the SAME canonical launch
# composition with the payload exec'd through `--entrypoint /bin/sh -c`.
# Every probe is time-bounded; its stdout is framed with PROBE_BEGIN /
# PROBE_END markers so the launcher's own service output can never be
# mistaken for the container's result, and the marker scan never relies on
# the first output line.
probe_run() { # NAME BODY [TIMEOUT] -> one bounded probe, framed, recorded
  local name="$1" body="$2" bound="${3:-60}" raw lrc
  if raw="$(OC_PROBE_PAYLOAD="printf 'PROBE_BEGIN\n'; { $body; } 2>&1; printf 'PROBE_RC=%s\n' \"\$?\"; printf '%s\n' PROBE_END" \
      timeout "$bound" bash -c '
        docker() { printf "%s\n" "$*" >> "$ARGV_PROBE_REC"; command docker "$@"; }
        # shellcheck source=/dev/null
        source "$HOME/.bash_aliases"
        oc-probe "$OC_PROBE_PAYLOAD"
      ' 2>/dev/null)"; then lrc=0; else lrc=$?; fi
  # Docker -it under script(1) emits CRLF; normalize before line-anchored
  # PROBE_BEGIN / PROBE_END and numeric PROBE_RC parsing.
  raw="${raw//$'\r'/}"
  printf '%s\n' "$lrc" > "$PROBE_DIR/$name.launchrc"
  printf '%s\n' "$raw" > "$PROBE_DIR/$name.raw"
}
probe_parse() { # NAME -> P_RC (in-container rc) and P_OUT (the framed body)
  P_RC="$(sed -n 's/^PROBE_RC=//p' "$PROBE_DIR/$1.raw" 2>/dev/null | head -1)"
  P_OUT="$(sed -n '/^PROBE_BEGIN$/,/^PROBE_END$/p' "$PROBE_DIR/$1.raw" 2>/dev/null | sed '1d;$d' | grep -v '^PROBE_RC=' || true)"
}
# UAT-8 timeout diagnostics: when the model launch failed (e.g. rc 124), do
# NOT just report a timeout — run a bounded ladder that separates the factors
# of the canonical launch contract and records which one is implicated:
#   L1  the exec-path container itself (echo through oc-probe)
#   L2  opencode --version under the mounted HOME (the canonical env)
#   L3  opencode --version with HOME=/tmp (the operator's real experiment)
# Each step is bounded; every step's rc and output are recorded as evidence.
if [ "$version_rc" != 0 ]; then
  {
    printf 'DIAG_BEGIN (the model launch failed with rc %s)\n' "$version_rc"
    probe_run diag_l1 'echo DIAG_L1_CONTAINER_OK'
    probe_parse diag_l1
    printf 'DIAG_L1_RC=%s\n' "${P_RC:-launch-failed}"
    probe_run diag_l2 'opencode --version'
    probe_parse diag_l2
    printf 'DIAG_L2_RC=%s\n' "${P_RC:-launch-failed}"
    probe_run diag_l3 'HOME=/tmp opencode --version'
    probe_parse diag_l3
    printf 'DIAG_L3_RC=%s\n' "${P_RC:-launch-failed}"
    printf 'DIAG_END\n'
  } >> "$ARGV_REC"
fi
# The mandatory access-path evidence: a valid Session bearer reports a
# session; the bearer's absence is refused BY DOCKER HELPER itself; a wrong
# bearer is refused by the daemon; the principal credential never
# substitutes the Session bearer; docker.sock and any ADMIN* env are absent
# inside the container (counted, never printed).
# Keep authentication rc authoritative: later boundary printfs must not
# overwrite the result of docker-helper self.
probe_run self 'docker-helper self --json'
probe_run boundary 'printf "PROBE_SOCK=%s\n" "$(test -S /var/run/docker.sock && echo present || echo absent)"; printf "PROBE_ADMIN_ENV=%s\n" "$(printenv | grep -c "^ADMIN" || true)"'
probe_run nobearer 'env -u DOCKER_HELPER_SESSION_TOKEN docker-helper self --json'
probe_run wrongbearer 'DOCKER_HELPER_SESSION_TOKEN=dht_invalid_probe_value docker-helper self --json'
# Preserve the denial rc even after emitting the credential-absence marker.
probe_run princred 'rc=0; env -u DOCKER_HELPER_SESSION_TOKEN docker-helper self --json || rc=$?; if [ ! -e "$HOME/.config/docker-helper/credential.token" ]; then echo PRINCIPAL_CRED_ABSENT; fi; (exit "$rc")'
# UAT-8 networked mode: the provider gate runs INSIDE the container (its env
# is the launch's env); the decision evidence is recorded for the outer
# script, which owns the pass/fail/skip verdicts. A missing provider is
# never a masked pass.
if [ "$INTEGRATION_NETWORKED" = 1 ]; then
  probe_run llmping 'if [ -n "${LLM_SERVER:-}" ] && [ -n "${LLM_KEY:-}" ]; then echo PROVIDER_CONFIGURED; else echo NO_PROVIDER; fi'
  probe_parse llmping
  # a configured provider gets one bounded real-model interaction, recorded
  # for the outer script's verdicts; a missing provider records no llmrun at
  # all (absence of llmrun evidence is itself the decision)
  case "$P_OUT" in
    *PROVIDER_CONFIGURED*) probe_run llmrun 'opencode run "Reply with the single word OK"' 120 ;;
  esac
else
  printf 'ISOLATED_MODE\n' > "$PROBE_DIR/llmping.decision"
fi
# Preserve the model launch result across subsequent probe launches. The
# final probe's success must never turn an OpenCode failure into runner rc=0.
printf 'VERSION_RC=%s\n' "$version_rc" >> "$ARGV_REC"
exit "$version_rc"
SH
chmod 0755 "$RUNNER"
# Recorder files are pre-created agent-owned (0600) in the agent-owned 0750
# run directory: no world-writable evidence file exists.
ARGV="$RUN_DIR/argv"
install -m 0600 -o "$AGENT_USER" -g "$AGENT_USER" /dev/null "$ARGV"
ARGV_FAIL="$RUN_DIR/argv-fail"
install -m 0600 -o "$AGENT_USER" -g "$AGENT_USER" /dev/null "$ARGV_FAIL"
ARGV_PROBE="$RUN_DIR/argv-probe"
install -m 0600 -o "$AGENT_USER" -g "$AGENT_USER" /dev/null "$ARGV_PROBE"
PROBE_DIR="$RUN_DIR/probes"
install -d -m 0750 -o "$AGENT_USER" -g "$AGENT_USER" "$PROBE_DIR"

# System docker-init state BEFORE the launch (label, ownership, mode, inode).
init_sys="$(readlink -f "$(command -v docker-init 2>/dev/null || echo /usr/bin/docker-init)")"
init_before="$(stat -c '%n %C %u:%g %a' "$init_sys")"
init_inode_before="$(stat -c '%i' "$init_sys")"

sudo -u "$AGENT_USER" env ARGV_REC="$ARGV" ARGV_PROBE_REC="$ARGV_PROBE" SHIM_DIR="$SHIM" \
  PROBE_DIR="$PROBE_DIR" INTEGRATION_NETWORKED="$INTEGRATION_NETWORKED" \
  script -qec "bash $RUNNER $ws" /dev/null >"$ITEST_DIR/oc.out" 2>&1
oc_rc=$?
if [ "$oc_rc" = 0 ]; then ok "launcher exited 0"; else bad "launcher exited $oc_rc"; fi
grep -Eq '[0-9]+\.[0-9]+\.[0-9]+' "$ITEST_DIR/oc.out" && ok "container ran opencode (version printed)" || bad "no opencode version in output"
# UAT-8 timeout diagnostics: a failed launch must produce factor-separated
# evidence (the bounded ladder inside the runner), never a bare timeout.
if [ "$oc_rc" != 0 ]; then
  if grep -q 'DIAG_BEGIN' "$ARGV" && grep -q 'DIAG_L1_RC=' "$ARGV"; then
    ok "the failed launch produced bounded factor diagnostics"
    contains "the diagnostics separate the container-exec factor" "DIAG_L1_RC=" "$(grep -o 'DIAG_L1_RC=[a-z0-9-]*' "$ARGV" | head -1)"
  else
    bad "the launch failed but the diagnostics produced no factor evidence"
  fi
fi

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

# in-container model access — every outcome is explicitly confirmed from one
# bounded probe run; an empty or missing result is a failure, never a pass
# (the old `!= "none"` check accepted an empty channel string as success).
probe_rc() { cat "$PROBE_DIR/$1.launchrc" 2>/dev/null || echo missing; }
probe_raw() { cat "$PROBE_DIR/$1.raw" 2>/dev/null || true; }
probe_parse() { # NAME -> P_RC (in-container rc) and P_OUT (the framed body)
  P_RC="$(sed -n 's/^PROBE_RC=//p' "$PROBE_DIR/$1.raw" 2>/dev/null | head -1)"
  P_OUT="$(sed -n '/^PROBE_BEGIN$/,/^PROBE_END$/p' "$PROBE_DIR/$1.raw" 2>/dev/null | sed '1d;$d' | grep -v '^PROBE_RC=' || true)"
}
launch_rc="$(probe_rc self)"
case "$launch_rc" in
  0) ok "the access-path probe launcher exited 0" ;;
  *) bad "the access-path probe launcher failed (launch rc $launch_rc)" ;;
esac
P_RC=""; P_OUT=""
probe_parse self
case "$P_RC" in
  0) ok "docker-helper self executed inside the container (rc 0)" ;;
  *) bad "docker-helper self did not execute cleanly inside the container (rc ${P_RC:-absent})" ;;
esac
contains "model self via the Session bearer reports a session" '"type": "session"' "$P_OUT"
# The boundary probe is a distinct, bounded container launch with its own
# exit-status evidence (rather than masking self's exit with printf).
boundary_launch="$(probe_rc boundary)"
probe_parse boundary
if [ "$boundary_launch" = 0 ] && [ "$P_RC" = 0 ]; then
  ok "the boundary probe executed inside the container"
else
  bad "the boundary probe failed (launch rc $boundary_launch, in-container rc ${P_RC:-absent})"
fi
contains "docker.sock is absent inside the container" "PROBE_SOCK=absent" "$P_OUT"
contains "no ADMIN* environment reaches the container" "PROBE_ADMIN_ENV=0" "$P_OUT"
probe_parse nobearer
nb_launch="$(probe_rc nobearer)"
if [ "$nb_launch" = 0 ] && [ -n "$P_RC" ] && [ "$P_RC" != 0 ]; then
  ok "self without the bearer is denied (in-container rc $P_RC)"
else
  bad "self without the bearer was not denied (launch rc $nb_launch, rc ${P_RC:-absent})"
fi
case "$P_OUT" in
  *"DOCKER_HELPER_SESSION_TOKEN is not set"*) ok "the refusal without the bearer comes from Docker Helper itself" ;;
  *) bad "the denial without the bearer is not the Docker Helper refusal: $(printf '%s' "$P_OUT" | tail -c 200)" ;;
esac
probe_parse wrongbearer
wb_launch="$(probe_rc wrongbearer)"
if [ "$wb_launch" = 0 ] && [ -n "$P_RC" ] && [ "$P_RC" != 0 ]; then
  ok "self with a wrong bearer is denied (in-container rc $P_RC)"
else
  bad "self with a wrong bearer was not denied (launch rc $wb_launch, rc ${P_RC:-absent})"
fi
grep -Eiq '401|unauthorized' "$PROBE_DIR/wrongbearer.raw" 2>/dev/null \
  && ok "the wrong-bearer denial comes from the daemon (unauthorized)" \
  || bad "no daemon denial evidence for a wrong bearer"
probe_parse princred
pi_launch="$(probe_rc princred)"
if [ "$pi_launch" = 0 ] && [ -n "$P_RC" ] && [ "$P_RC" != 0 ] \
   && printf '%s' "$P_OUT" | grep -q 'DOCKER_HELPER_SESSION_TOKEN is not set' \
   && printf '%s' "$P_OUT" | grep -q 'PRINCIPAL_CRED_ABSENT'; then
  ok "the principal credential cannot substitute the Session bearer (refused, credential absent)"
else
  bad "the principal-credential substitution was not refused (launch rc $pi_launch, rc ${P_RC:-absent})"
fi
# the probe launches reuse the canonical posture: the same isolation flags
# and the same boundary, recorded from the probe launches themselves
pargv="$(cat "$ARGV_PROBE")"
# Recorder lines include the probe's /bin/sh -c PAYLOAD after the image.
# The code being tested intentionally mentions docker.sock, ADMIN and the
# principal credential; these strings are not Docker mount/env OPTIONS.
# Check options only, stopping at the payload delimiter on EACH launch.
pargv_opts="$(printf '%s\n' "$pargv" | sed 's/ -c .*//')"
contains "the probe container runs as the agent uid" "--user $(id -u "$AGENT_USER"):$(id -g "$AGENT_USER")" "$pargv"
contains "the probe container drops caps" "--cap-drop ALL" "$pargv"
contains "the probe container sets no-new-privileges" "no-new-privileges=true" "$pargv"
contains "the probe container runs in docker_helper_container_t" "label=type:docker_helper_container_t" "$pargv"
contains "the probe workspace is a private relabel" ":/workspace:Z" "$pargv"
contains "the probe helper runtime dir is read-only" "/run/docker-helper:ro" "$pargv"
contains "the probe container gets the session bearer env" "-e DOCKER_HELPER_SESSION_TOKEN" "$pargv"
not_contains "the probe container has no docker.sock" "docker.sock" "$pargv_opts"
not_contains "the probe container has no admin token" "ADMIN" "$pargv_opts"
not_contains "the probe container has no principal credential" "/.config/docker-helper" "$pargv_opts"

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
    # UAT-8: the probe payload is framed (TLS_BEGIN / CA_ENV_BEGIN..END /
    # TLS_RC / TLS_END) so the launcher's service output can never be
    # mistaken for the container's result, and the NODE_EXTRA_CA_CERTS value
    # is parsed from its own markers, never from the first stdout line. The
    # probe runs through oc-probe (the exec path — `oc sh -c ...` would hand
    # the payload to the OpenCode CLI, not to sh).
    probe_cmd="printf '%s\n' TLS_BEGIN; printf '%s\n' CA_ENV_BEGIN; if [ -n \"\${NODE_EXTRA_CA_CERTS:-}\" ]; then printf 'NODE_EXTRA_CA_CERTS=%s\n' \"\$NODE_EXTRA_CA_CERTS\"; fi; printf '%s\n' CA_ENV_END; if command -v curl >/dev/null 2>&1; then curl -sS --max-time 6 https://$bridge_ip:9443/ 2>&1; echo TLS_RC=\$?; else echo NO_CURL_IN_CONTAINER; fi; printf '%s\n' TLS_END"
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
# correctly initialized Bash wrapper — `oc-probe` is a function and cannot
# be exec'd by timeout directly. UAT-8: the launcher's exit status is
# recorded separately (never masked with || true) — a failed or timed-out
# launcher is missing mandatory evidence, not an inconclusive probe.
if raw="$(timeout 90 bash -c '
  docker() { printf "%s\n" "$*" >> "$ARGV_REC"; command docker "$@"; }
  # shellcheck source=/dev/null
  source "$HOME/.bash_aliases"
  oc-probe "$TLS_PROBE_CMD"
')"; then tlrc=0; else tlrc=$?; fi
# TLS marker lines also arrive through Docker's PTY as CRLF.
raw="${raw//$'\r'/}"
printf '%s\n' "$tlrc" > "$TLS_LAUNCH_RC"
printf '%s\n' "$raw" > "$TLS_OUT"
SH
    chmod 0755 "$RUNNER_TLS"
    sudo -u "$AGENT_USER" env ARGV_REC="$ARGV_TLS" SHIM_DIR="$SHIM" \
      TLS_PROBE_CMD="$probe_cmd" \
      TLS_LAUNCH_RC="$RUN_DIR/tls-launch.rc" TLS_OUT="$RUN_DIR/tls.out" \
      script -qec "bash $RUNNER_TLS $ws" /dev/null >"$ITEST_DIR/oc-tls.out" 2>&1
    kill "$tls_srv_pid" 2>/dev/null || true
    tls_srv_pid=""
    tls_launch="$(cat "$RUN_DIR/tls-launch.rc" 2>/dev/null || echo missing)"
    tls_out="$(cat "$RUN_DIR/tls.out" 2>/dev/null || true)"
    if [ "$tls_launch" != 0 ]; then
      bad "the TLS probe launcher failed (rc $tls_launch) — mandatory evidence is missing"
    elif ! printf '%s' "$tls_out" | grep -q '^TLS_BEGIN$' \
         || ! printf '%s' "$tls_out" | grep -q '^TLS_END$'; then
      bad "the TLS probe output is not framed (no TLS_BEGIN/TLS_END) — no verdict without the marker evidence"
    elif grep -q 'NO_CURL_IN_CONTAINER' "$RUN_DIR/tls.out"; then
      bad "in-container TLS check unavailable: curl is missing (mandatory evidence)"
    else
      tls_rc="$(sed -n 's/^TLS_RC=//p' "$RUN_DIR/tls.out" | head -1)"
      tls_text="$(sed -n '/^TLS_BEGIN$/,/^TLS_END$/p' "$RUN_DIR/tls.out" | sed '1d;$d' | grep -v '^TLS_RC=')"
      # UAT-8: the verdict helper is a 0644 library file in /opt/lab — it is
      # invoked through bash, and ITS OWN failure is a failed check, never a
      # skip.
      verdict="$(bash "$SCRIPT_DIR/tls-verdict.sh" "${tls_rc:-999}" "$tls_text")"
      verdict_rc=$?
      if [ "$verdict_rc" != 0 ] || [ -z "$verdict" ]; then
        bad "the TLS verdict helper failed (rc $verdict_rc) — refusing to treat the refusal as a skip"
      else
        case "$verdict" in
          VERIFICATION_FAILURE*)
            ok "the container rejected the untrusted TLS endpoint (rc $tls_rc)"
            if printf '%s' "$tls_text" | grep -qi 'certificate'; then
              ok "the refusal is a certificate-validation failure, not a connection error"
            else
              bad "the TLS refusal could not be attributed to certificate validation: $(tail -c 200 "$RUN_DIR/tls.out" 2>/dev/null)"
            fi
            ;;
          ACCEPTED*)
            bad "the container ACCEPTED the untrusted TLS endpoint"
            ;;
          # UAT-8: a connection failure, a timeout or any other unexpected
          # outcome is NOT a pass — the negative TLS evidence is mandatory.
          CONNECTION_FAILURE*)
            bad "the TLS probe ended in a connection failure despite a ready server (no verification evidence)"
            ;;
          *)
            bad "the TLS probe ended in an unexpected outcome (rc ${tls_rc:-unset}) — no verification evidence"
            ;;
        esac
      fi
    fi
    if [ -n "$ca_anchor" ]; then
      ca_env="$(sed -n '/^CA_ENV_BEGIN$/,/^CA_ENV_END$/p' "$RUN_DIR/tls.out" 2>/dev/null | sed '1d;$d')"
      check "NODE_EXTRA_CA_CERTS reaches the container" \
        "/etc/opencode-ca/$ca_name.crt" \
        "$(printf '%s' "$ca_env" | sed -n 's/^NODE_EXTRA_CA_CERTS=//p')"
    fi
  else
    skip "in-container TLS check (the throwaway server did not become reachable)"
  fi
  kill "$tls_srv_pid" 2>/dev/null || true
  tls_srv_pid=""
else
  skip "in-container TLS check (openssl or the docker bridge is unavailable)"
fi

# --- 11c. the real model interaction (networked mode, provider-gated) --------
# The gate decision comes from the container env (recorded by the runner); a
# missing provider is an explicit SKIP, never a masked pass; a configured
# provider that does not answer within the bound is a FAIL.
if [ "$INTEGRATION_NETWORKED" = 1 ]; then
  llmping_launch="$(probe_rc llmping)"
  if [ "$llmping_launch" != 0 ]; then
    bad "the provider-gate probe launcher failed (rc $llmping_launch)"
  else
    P_RC=""; P_OUT=""
    probe_parse llmping
    case "$P_OUT" in
      *NO_PROVIDER*)
        skip "the real LLM interaction check (no provider configured in the launch env)"
        ;;
      *PROVIDER_CONFIGURED*)
        llm_launch="$(probe_rc llmrun)"
        P_RC=""; P_OUT=""
        probe_parse llmrun
        if [ "$llm_launch" = 0 ] && [ "$P_RC" = 0 ] \
           && [ -n "$(printf '%s' "$P_OUT" | tr -d '[:space:]')" ]; then
          ok "the configured provider answered the bounded real-model interaction"
        else
          bad "the configured provider did not answer (launch rc $llm_launch, in-container rc ${P_RC:-absent})"
        fi
        ;;
      *)
        bad "the provider gate produced no decision (unframed probe output)"
        ;;
    esac
  fi
else
  skip "the real LLM interaction check (isolated mode: no provider network path)"
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
