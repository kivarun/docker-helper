#!/usr/bin/env bash
#
# release-2.4-r7-diag-guest.sh — R7 full-gate corrective guest diagnostic
# (runs INSIDE the disposable environment: openSUSE Tumbleweed VM with the
# selected MAC backend, or the hosted Ubuntu runner).
#
# Purpose (R7): reproduce the full artifact-gate UAT failures on the EXACT
# candidate bytes and collect the evidence the gate's UAT diagnostics did not
# capture:
#
#   R7-A  the SELinux buildctl execution denial: packaged labels
#         (ls -lZ / matchpathcon -V / semanage fcontext), the live AVC
#         records for the build window, and a differential exec control.
#   R7-B  the runtime dependency presence per platform (rootlesskit,
#         slirp4netns, uidmap/newuidmap, getsubids) against the packaged
#         dependency contract.
#   R7-C  the builder START refusal chain: docker-helper-builder.service
#         status + FULL journal (the manager's diag lines land there,
#         StandardError=journal), the builder identity, the launch-vehicle
#         prerequisites (distro rootlesskit AppArmor profile for px,
#         userns restriction state), and kernel audit records.
#   R7-D  the manager's child-lifecycle surface during STOP/liveness:
#         the exact categorized child contexts (ps) and the signal/signull
#         AVC records.
#   R7-A  the lchown(0,42) ownership forensics: while the mount callback
#         runs, the /etc/shadow inode's st_dev/st_ino/uid/gid sampled
#         from BOTH sides of the build namespace boundary (in-namespace
#         via nsenter -U -m with the stat itself inside the namespaces,
#         host via the bind source and /proc/<pid>/root) with an
#         explicit inode-match verdict per pair, plus the exact syscall
#         trace of lchown/fchownat(0,42) via kernel audit rules
#         (strace fallback): the calling TID, its per-thread
#         namespace/capability context (uid_map/gid_map, CapEff — not
#         the main PID's), the mount namespace and mount ID of the
#         operation, the target inode, and the VM's idmapped-mount
#         kernel support — the inputs for naming the first failing
#         kernel predicate, on the SELinux and the AppArmor VM alike.
#
# The script is evidence-first: every collection step survives build failure,
# and the terminal verdict line states only what was observed:
#
#   R7-DIAG-BUILD-RC=<n>     exit status of the reproduced docker-helper build
#   R7-DIAG-RESULT=REPRODUCED|BUILD-OK|UNEXPECTED
#     REPRODUCED — R7_EXPECT=fail and the build failed (red reproduction)
#     BUILD-OK   — R7_EXPECT=ok and the build succeeded (green proof)
#     UNEXPECTED — observation did not match the expectation
#
# Env inputs:
#   R7_BACKEND        selinux | apparmor (evidence selection)
#   R7_INSTALL        rpm | tarball
#   R7_ARTIFACT       path to the exact candidate artifact
#   R7_ARTIFACT_SHA256 expected SHA-256 of that artifact
#   R7_EXPECT         fail | ok
#   R7_RUNTIME_DEPS   install | skip (skip reproduces the gate's unprovisioned
#                     Ubuntu runner; install applies the R7-B contract)
#
# The candidate version and the daemon state are only observed, never mutated
# beyond the install itself; the script never touches the release tag.

set -uo pipefail

BACKEND="${R7_BACKEND:?R7_BACKEND required}"
INSTALL_FMT="${R7_INSTALL:?R7_INSTALL required}"
ARTIFACT="${R7_ARTIFACT:?R7_ARTIFACT required}"
ARTIFACT_SHA="${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"
EXPECT="${R7_EXPECT:-fail}"
RUNTIME_DEPS="${R7_RUNTIME_DEPS:-install}"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log()  { printf '[r7-diag] %s\n' "$*"; }
fail() { printf '[r7-diag] FAILED: %s\n' "$*" >&2; exit 1; }

EVIDENCE_DIR="${R7_EVIDENCE_DIR:-/tmp/r7-diag-evidence}"
mkdir -p "$EVIDENCE_DIR"

# cap: run a command, capture combined output to a file, echo it bounded.
cap() { # <name> <max-lines> <cmd...>
  # Evidence collection must never abort the diagnostic: every capture is
  # best-effort by definition. The caller's exit status is recorded into
  # the capture so a failed probe is still visible evidence.
  local name="$1" maxn="$2" rc; shift 2
  "$@" >"$EVIDENCE_DIR/$name.log" 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || printf 'capture rc=%d\n' "$rc" >>"$EVIDENCE_DIR/$name.log"
  log "--- $name (evidence: $EVIDENCE_DIR/$name.log, first $maxn lines) ---"
  head -n "$maxn" "$EVIDENCE_DIR/$name.log"
  return 0
}

[ "$(id -u)" = "0" ] || fail "must run as root"
[ -f "$ARTIFACT" ] || fail "artifact missing: $ARTIFACT"
now_sha="$(sha256sum "$ARTIFACT" | awk '{print $1}')"
[ "$now_sha" = "$ARTIFACT_SHA" ] || fail "artifact SHA mismatch (expected $ARTIFACT_SHA, got $now_sha)"

PRINCIPAL="${SUDO_USER:-}"
[ -n "$PRINCIPAL" ] && [ "$PRINCIPAL" != "root" ] || fail "cannot derive non-root principal (SUDO_USER='$SUDO_USER')"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
[ -n "$PRINCIPAL_HOME" ] && [ -d "$PRINCIPAL_HOME" ] || fail "principal home not found: $PRINCIPAL"
ALLOWED_ROOT="$PRINCIPAL_HOME"

# ============================================================================
# Section 1: environment + dependency-contract evidence (R7-B)
# ============================================================================
# The diag VM reboots mid-diagnosis (observed ~55s after boot, runs
# 39006788899+). Every phase writes a state marker; a re-entry (the
# runner re-invokes this script over a fresh SSH session after the
# reboot) skips completed phases and finishes the remaining ones. The
# runner loops the invocation until the verdict appears.
STATE_DIR=/tmp/r7-diag-state
mkdir -p "$STATE_DIR"
log "=== section 1: platform + dependency evidence (R7-B) ==="
if [ -f "$STATE_DIR/sec1" ]; then log "phase marker: section 1 done; skipping"; else
cat /etc/os-release
cap r7-packages-runtime 20 bash -c 'rpm -qa 2>/dev/null | grep -Ei "rootlesskit|slirp4netns|uidmap|^shadow|apparmor|libselinux|policycoreutils" | sort || dpkg -l 2>/dev/null | grep -Ei "rootlesskit|slirp4netns|uidmap" || true'
for b in rootlesskit slirp4netns newuidmap newgidmap getsubids; do
  p="$(command -v "$b" 2>/dev/null || true)"
  if [ -n "$p" ]; then
    log "dep $b -> $p ($("$p" --version 2>&1 | head -1 || true))"
  else
    log "dep $b -> MISSING"
  fi
done

if [ "$RUNTIME_DEPS" = "install" ]; then
  log "installing the packaged runtime dependency contract (rootlesskit slirp4netns uidmap-equivalents)"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y rootlesskit slirp4netns uidmap \
      || fail "runtime dependency install failed (apt)"
  elif command -v zypper >/dev/null 2>&1; then
    # shadow (newuidmap/newgidmap) and kmod are Tumbleweed-base per the RPM
    # contract; install the explicit runtime trio the RPM Requires.
    zypper --non-interactive install -y rootlesskit slirp4netns \
      || fail "runtime dependency install failed (zypper)"
  else
    fail "no known package manager for the runtime dependency install"
  fi
else
  log "R7_RUNTIME_DEPS=skip: reproducing the gate's unprovisioned environment"
fi

touch "$STATE_DIR/sec1"
fi
# ============================================================================
# Section 2: exact candidate install (never rebuilds)
# ============================================================================
if [ -f "$STATE_DIR/sec2" ]; then log "phase marker: section 2 done; skipping"; else
log "=== section 2: candidate install ($INSTALL_FMT) ==="
if [ "$INSTALL_FMT" = "rpm" ]; then
  rpm -q docker-helper >/dev/null 2>&1 && rpm -e docker-helper >/dev/null 2>&1 || true
  rpm -i "$ARTIFACT" || fail "rpm -i failed"
  log "RPM installed: $(rpm -q docker-helper)"
  # The RPM install adapter runs `docker-helper init --allowed-root` after
  # `rpm -i` (the init provisions the config and starts the daemon; the RPM
  # scriptlets do not). Without it the API socket never appears.
  docker-helper init --allowed-root "$ALLOWED_ROOT" || fail "docker-helper init failed"
elif [ "$INSTALL_FMT" = "tarball" ]; then
  EXTRACT="$(mktemp -d /tmp/r7-bundle.XXXXXX)"
  chmod 755 "$EXTRACT"
  tar xzf "$ARTIFACT" -C "$EXTRACT" || fail "tar extraction failed"
  BUNDLE="$(find "$EXTRACT" -maxdepth 1 -type d -name 'docker-helper-*' | head -1)"
  [ -n "$BUNDLE" ] && [ -x "$BUNDLE/install-system.sh" ] || fail "bundle/install-system.sh not found"
  (cd "$BUNDLE" && ./install-system.sh --yes --allowed-root "$ALLOWED_ROOT") \
    || fail "install-system.sh failed"
  log "tarball install complete"
  printf '%s\n' "$BUNDLE" > "$EVIDENCE_DIR/r7-bundle-path"
else
  fail "unknown R7_INSTALL '$INSTALL_FMT'"
fi

systemctl daemon-reload
systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
if [ "$BACKEND" = "selinux" ] || [ "$BACKEND" = "apparmor" ]; then
  systemctl enable --now docker-helper-builder.service >/dev/null 2>&1 || true
fi

DH_SOCK=/run/docker-helper/docker-helper.sock
READY=0
for _ in $(seq 1 50); do
  if [ -S "$DH_SOCK" ] && curl --silent --fail --max-time 1 \
      --unix-socket "$DH_SOCK" http://localhost/health >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 0.2
done
[ "$READY" = 1 ] || fail "daemon API socket not ready"
log "daemon ready on $DH_SOCK"

touch "$STATE_DIR/sec2"
fi

# ============================================================================
# Section 3: pre-build MAC/policy evidence (R7-A labels, R7-C prerequisites)
# ============================================================================
log "=== section 3: pre-build policy evidence ==="
if [ "$BACKEND" = "selinux" ]; then
  cap r7-buildkit-labels 20 bash -c 'ls -lZ /usr/libexec/docker-helper/buildkit/ 2>&1; for f in buildctl buildkitd buildkit-runc; do echo "matchpathcon -V $f:"; matchpathcon -V "/usr/libexec/docker-helper/buildkit/$f" 2>&1; done'
  cap r7-fcontext-rules 40 bash -c 'semanage fcontext -l 2>/dev/null | grep -E "docker-helper|buildkit" || echo "(no matching fcontext rules)"'
  cap r7-loaded-modules 10 bash -c 'semodule -l 2>/dev/null | grep -w docker_helper || echo "(no docker_helper module)"'
  command -v sesearch >/dev/null 2>&1 || { zypper --non-interactive install -y setools-console >/dev/null 2>&1 || true; }
  cap r7-sesearch-daemon-bint 30 sesearch -A -s docker_helper_t -t bin_t -c file
  cap r7-sesearch-daemon-buildctl 20 bash -c 'sesearch -A -s docker_helper_t -c file 2>/dev/null | grep -E "buildkit|buildctl" || echo "(no docker_helper_t exec allows touching the buildkit payload types)"'
elif [ "$BACKEND" = "apparmor" ]; then
  cap r7-aa-status 40 aa-status
  cap r7-aa-distro-rootlesskit-profile 10 bash -c 'if [ -f /etc/apparmor.d/rootlesskit ]; then echo "DISTRO-ROOTLESSKIT-PROFILE=present"; head -40 /etc/apparmor.d/rootlesskit; else echo "DISTRO-ROOTLESSKIT-PROFILE=absent"; fi'
  cap r7-aa-userns-restriction 5 bash -c 'for f in /proc/sys/kernel/apparmor_restrict_unprivileged_userns /proc/sys/kernel/unprivileged_userns_clone; do [ -e "$f" ] && echo "$f=$(cat "$f")"; done; true'
  cap r7-aa-loaded-profiles 30 bash -c 'aa-status 2>/dev/null | sed -n "/profiles are in enforce mode/,/processes are in enforce mode/p" || true'
fi
cap r7-builder-service-status 30 systemctl status docker-helper-builder.service --no-pager
cap r7-builder-identity 10 bash -c 'id docker-helper-builder 2>&1; getent subuid docker-helper-builder 2>&1 || true; getent subgid docker-helper-builder 2>&1 || true'
cap r7-daemon-confinement 6 bash -c 'DHPID="$(systemctl show -p MainPID --value docker-helper.service)"; echo "daemon pid=$DHPID"; cat "/proc/$DHPID/attr/current" 2>/dev/null || true; echo'
cap r7-builder-confinement 6 bash -c 'BPID="$(systemctl show -p MainPID --value docker-helper-builder.service)"; echo "builder pid=$BPID"; cat "/proc/$BPID/attr/current" 2>/dev/null || true; echo'

# R7-A install stabilization: the diag VM reboots mid-diagnosis (~55s
# after boot, run 39006788899+), and a reboot landing inside the RPM
# transaction leaves the just-installed environment half-configured.
# Observed shapes:
#   * run 39048909303 SELinux: buildkitd/buildkit-runc relabeled by the
#     posttrans, buildctl left at the distro bin_t (the transaction died
#     between adjacent restorecon lines) — the build then died at
#     "fork/exec buildctl: permission denied" before ever reaching the
#     lchown window;
#   * the same run, AppArmor: the post-reboot build raced the boot-time
#     AppArmor profile load and died with apparmor="DENIED" ...
#     "profile transition not found" on /usr/bin/rootlesskit before any
#     build step.
# This step verifies and, where needed, repairs the install the diag
# itself just performed — diagnostic-environment stabilization only; it
# never touches product bytes, policy sources, or MAC mode — and records
# the before/after state so the flakiness stays documented.
STAB_LOG="$EVIDENCE_DIR/r7-install-stabilization.log"
stab_list() {
  for f in /usr/bin/docker-helper /usr/bin/rootlesskit /usr/bin/newuidmap \
           /usr/bin/newgidmap /usr/bin/nsenter \
           /usr/libexec/docker-helper/buildkit/buildctl \
           /usr/libexec/docker-helper/buildkit/buildkitd \
           /usr/libexec/docker-helper/buildkit/buildkit-runc; do
    if [ ! -e "$f" ]; then printf '%s MISSING\n' "$f"; continue; fi
    printf '%s actual=%s computed_type=%s\n' "$f" \
      "$(ls -lZd "$f" 2>&1 | awk '{print $1, $3, $4}')" \
      "$(matchpathcon "$f" 2>/dev/null | awk '{print $2}' | awk -F: '{print $3}')"
  done
}
if [ "$BACKEND" = "selinux" ] && command -v restorecon >/dev/null 2>&1 && command -v semodule >/dev/null 2>&1; then
  {
    echo "=== pre-repair state ($(date +%H:%M:%S)):"
    stab_list
    repaired=0
    for f in /usr/libexec/docker-helper/buildkit/buildctl \
             /usr/libexec/docker-helper/buildkit/buildkitd \
             /usr/libexec/docker-helper/buildkit/buildkit-runc \
             /usr/bin/rootlesskit /usr/bin/newuidmap /usr/bin/newgidmap \
             /usr/bin/nsenter /usr/bin/docker-helper; do
      [ -e "$f" ] || continue
      t="$(matchpathcon "$f" 2>/dev/null | awk '{print $2}' | awk -F: '{print $3}')"
      case "$t" in
        docker_helper_*) ;;
        *)
          echo "--- relabeling $f (computed type '$t' is not a docker_helper type)"
          restorecon "$f" 2>&1 || true
          repaired=$((repaired + 1));;
      esac
    done
    t="$(matchpathcon /usr/libexec/docker-helper/buildkit/buildctl 2>/dev/null | awk '{print $2}' | awk -F: '{print $3}')"
    if [ "$t" != docker_helper_buildctl_exec_t ]; then
      echo "--- buildctl rule absent: reloading the shipped policy module"
      PP="$(rpm -ql docker-helper 2>/dev/null | grep 'docker_helper\.pp$' | head -1)"
      echo "--- module path: ${PP:-NOT-FOUND}"
      if [ -n "$PP" ]; then
        semodule -i "$PP" 2>&1 || true
        restorecon /usr/libexec/docker-helper/buildkit/buildctl 2>&1 || true
        repaired=$((repaired + 1))
      fi
    fi
    echo "=== post-repair state (repaired=$repaired):"
    stab_list
  } >"$STAB_LOG" 2>&1
  log "install stabilization (selinux): repaired=$repaired (evidence: $STAB_LOG)"
elif [ "$BACKEND" = "apparmor" ]; then
  {
    echo "=== pre-repair state ($(date +%H:%M:%S)):"
    aa-status 2>&1 | grep -E "docker-helper|rootlesskit" | head -10 || true
    loaded=0
    for _ in $(seq 1 30); do
      if aa-status 2>/dev/null | grep -q "docker-helper-builder" \
         && aa-status 2>/dev/null | grep -q "rootlesskit"; then
        loaded=1; break
      fi
      sleep 0.5
    done
    echo "--- profiles settled wait: loaded=$loaded"
    if [ "$loaded" != 1 ]; then
      echo "--- force-loading the shipped profiles:"
      apparmor_parser --replace --skip-read-cache /etc/apparmor.d/docker-helper-system 2>&1 || true
      apparmor_parser --replace --skip-read-cache /etc/apparmor.d/docker-helper-builder 2>&1 || true
      if [ -e /etc/apparmor.d/rootlesskit ]; then
        apparmor_parser --replace --skip-read-cache /etc/apparmor.d/rootlesskit 2>&1 || true
      fi
      repaired=1
    else
      repaired=0
    fi
    echo "=== post-repair state (repaired=$repaired):"
    aa-status 2>&1 | grep -E "docker-helper|rootlesskit" | head -10 || true
  } >"$STAB_LOG" 2>&1
  log "install stabilization (apparmor): repaired=$repaired (evidence: $STAB_LOG)"
fi

# ============================================================================
# Section 4: minimal build reproduction through the REAL daemon
# ============================================================================
log "=== section 4: build reproduction ==="
if [ -f "$STATE_DIR/build-rc" ]; then
  log "phase marker: build already reproduced (rc=$(cat "$STATE_DIR/build-rc")); skipping to forensics"
  BUILD_RC="$(cat "$STATE_DIR/build-rc")"
else
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
[ -n "$ADMIN_TOKEN" ] || fail "admin token unreadable"

WS="$ALLOWED_ROOT/r7-ws"
rm -rf "$WS"; mkdir -p "$WS/buildctx"
cat > "$WS/buildctx/Dockerfile" <<'EOF'
FROM alpine:3.24
RUN apk add --no-cache curl ca-certificates
USER 65534:65534
EOF
chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"

# The principal must exist before the admin principal-selector session create
# (the eager 'default' Launcher is provisioned at principal create — the same
# sequence the UAT scenario runs). The create tolerates a principal left by a
# prior diagnostic phase on the same environment.
if ! docker-helper principal create --no-credential "$PRINCIPAL" 2>/dev/null; then
  docker-helper principal show "$PRINCIPAL" >/dev/null \
    || fail "principal create failed and principal '$PRINCIPAL' is absent"
fi
docker-helper principal allowed-root add "$PRINCIPAL" "$ALLOWED_ROOT" 2>/dev/null \
  || docker-helper principal show "$PRINCIPAL" >/dev/null \
  || fail "principal allowed-root add failed"

SESS_JSON="$(curl --silent --max-time 5 \
  --unix-socket "$DH_SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"workspace\":\"$WS\",\"principal\":\"$PRINCIPAL\"}" \
  -o "$EVIDENCE_DIR/r7-session-response.json" -w '%{http_code}' http://localhost/sessions)" \
  || { cat "$EVIDENCE_DIR/r7-session-response.json"; fail "session create request failed"; }
log "session create HTTP $SESS_JSON"
SESS_TOKEN="$(grep -oE '"token": *"[^"]+"' "$EVIDENCE_DIR/r7-session-response.json" | head -1 | sed 's/.*"token": *"//;s/"$//')"
[ -n "$SESS_TOKEN" ] || fail "session token missing (response: $(head -c 400 "$EVIDENCE_DIR/r7-session-response.json"))"
log "session created"

export DOCKER_HELPER_SESSION_TOKEN="$SESS_TOKEN"
docker-helper pull alpine:3.24 || log "pull failed (continuing; build may still fail on its own stage)"

# R7-A lchown trace setup: capture the EXACT failing syscall — its TID,
# arguments, result and target inode — plus the calling thread's
# namespace and capability context. Kernel syscall auditing (auditctl)
# is the primary mechanism: rules are filtered to the exact failing
# argument pattern (uid=0 gid=42), audit runs in the kernel, changes no
# process behavior and no SELinux decision. strace (ptrace) is the
# fallback. The event stream is consumed continuously during the build;
# the ownership poller below snapshots /proc/<tid> the moment an event
# appears, so the thread's own CapEff — not the main PID's — is the
# capability evidence.
LCHOWN_TRACE=none
EV_STREAM="$EVIDENCE_DIR/r7-lchown-events.raw"
EV_SEEN="$EVIDENCE_DIR/r7-lchown-events-seen.log"
LCHOWN_FORENSICS="$EVIDENCE_DIR/r7-lchown-forensics.log"
STRACE_LOG="$EVIDENCE_DIR/r7-lchown-strace.log"
: >"$EV_STREAM"
: >"$EV_SEEN"
: >"$LCHOWN_FORENSICS"
{
  echo "trace-tool probe ($(date +%H:%M:%S)):"
  echo "auditctl=$(command -v auditctl || echo MISSING) strace=$(command -v strace || echo MISSING) ausearch=$(command -v ausearch || echo MISSING)"
} >"$LCHOWN_FORENSICS"
if ! command -v auditctl >/dev/null 2>&1 && command -v zypper >/dev/null 2>&1; then
  log "installing the audit package for syscall tracing (diagnostic tooling only)"
  timeout 120 zypper --non-interactive install -y audit >>"$LCHOWN_FORENSICS" 2>&1 || true
elif ! command -v auditctl >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
  log "installing the auditd package for syscall tracing (diagnostic tooling only)"
  timeout 120 apt-get install -y auditd >>"$LCHOWN_FORENSICS" 2>&1 || true
fi
if command -v auditctl >/dev/null 2>&1 \
  && auditctl -a always,exit -F arch=b64 -S lchown -F a1=0 -F a2=42 -k r7lchown >>"$LCHOWN_FORENSICS" 2>&1 \
  && auditctl -a always,exit -F arch=b64 -S fchownat -F a2=0 -F a3=42 -k r7lchown >>"$LCHOWN_FORENSICS" 2>&1; then
  LCHOWN_TRACE=audit
  {
    echo "--- audit rules installed (key r7lchown):"
    auditctl -l 2>&1
    echo "--- auditctl -s:"
    auditctl -s 2>&1
  } >>"$LCHOWN_FORENSICS"
  # The image ships a blanket '-a never,task' rule: it matches every task
  # at creation and disables the audit context for them, so AVC records
  # still flow but SYSCALL records never do (diag run 39048041228: 82 AVC
  # records, zero SYSCALL records, while the lchown EPERM provably fired
  # and its always,exit rule was loaded). Remove it for the trace window
  # — this only enables kernel syscall-audit logging and changes no MAC
  # decision — and restore it in the teardown below.
  echo "--- removing the blanket never,task rule for the trace window:" >>"$LCHOWN_FORENSICS"
  auditctl -d never,task >>"$LCHOWN_FORENSICS" 2>&1 || true
  echo "--- rules after never,task removal:" >>"$LCHOWN_FORENSICS"
  auditctl -l >>"$LCHOWN_FORENSICS" 2>&1
fi
if [ "$LCHOWN_TRACE" = none ] && ! command -v strace >/dev/null 2>&1; then
  if command -v zypper >/dev/null 2>&1; then
    timeout 120 zypper --non-interactive install -y strace >>"$LCHOWN_FORENSICS" 2>&1 || true
  elif command -v apt-get >/dev/null 2>&1; then
    timeout 120 apt-get install -y strace >>"$LCHOWN_FORENSICS" 2>&1 || true
  fi
fi
EV_CONSUMER_PID=""
EV_SOURCE=none
if pgrep -x auditd >/dev/null 2>&1 && [ -r /var/log/audit/audit.log ]; then
  tail -n 0 -F /var/log/audit/audit.log >>"$EV_STREAM" 2>/dev/null &
  EV_CONSUMER_PID=$!
  EV_SOURCE=audit.log
elif command -v journalctl >/dev/null 2>&1; then
  journalctl -kf -o short-iso >>"$EV_STREAM" 2>/dev/null &
  EV_CONSUMER_PID=$!
  EV_SOURCE=journalctl-k
elif command -v dmesg >/dev/null 2>&1; then
  dmesg --follow >>"$EV_STREAM" 2>/dev/null &
  EV_CONSUMER_PID=$!
  EV_SOURCE=dmesg-follow
fi
echo "LCHOWN_TRACE=$LCHOWN_TRACE EV_SOURCE=$EV_SOURCE consumer_pid=${EV_CONSUMER_PID:-none}" >>"$LCHOWN_FORENSICS"
log "lchown trace mechanism: $LCHOWN_TRACE (event source: $EV_SOURCE)"

# The mapping capture must happen WHILE the flow's buildkitd process is
# alive: the diag VM can reboot mid-diagnosis (observed ~55s after boot,
# run 39006788899), so the forensic capture runs as a bounded background
# poller during the build instead of after it. The poller stops as soon
# as it has one full capture (or the deadline passes).
(
  deadline=$(( $(date +%s) + 180 ))
  samples=0
  exits=0
  while [ "$(date +%s)" -lt "$deadline" ] && [ "$samples" -lt 240 ]; do
    samples=$((samples + 1))
    # Match the BUILDKITD process by its exact comm (pgrep -f also
    # matches the rootlesskit wrapper's argv and the rootlesskit setup
    # chain's transient fork churn). The buildkitd process exists from
    # the namespace setup until the build's end.
    BPID="$(pgrep -x buildkitd | head -1)"
    if [ -n "$BPID" ]; then
      {
        # The pgrep match is the rootlesskit WRAPPER (its argv names
        # buildkitd); the launcher chain's child processes (the real
        # buildkitd, inside the child user namespace) are its
        # descendants. Capture the wrapper AND every descendant's
        # namespace view: the wrapper stays in the init userns by
        # design; the namespace mapping lives on the descendants.
        echo "matched pid=$BPID"
        descend() {
          local p="$1" depth="$2" i pad
          pad=""; i=0; while [ $i -lt $depth ]; do pad="$pad  "; i=$((i+1)); done
          echo "${pad}pid=$p"
          echo "${pad}  comm=$(cat "/proc/$p/comm" 2>/dev/null)"
          echo "${pad}  attr/current=$(cat "/proc/$p/attr/current" 2>/dev/null)"
          echo "${pad}  uid_map:"; sed "s/^/${pad}    /" "/proc/$p/uid_map" 2>&1
          echo "${pad}  gid_map:"; sed "s/^/${pad}    /" "/proc/$p/gid_map" 2>&1
          echo "${pad}  caps=$(grep -hE '^CapEff' "/proc/$p/status" 2>/dev/null)"
          echo "${pad}  groups=$(grep -h '^Groups' "/proc/$p/status" 2>/dev/null)"
          echo "${pad}  mountinfo (raw, unfiltered - the definitive view):"
          sed "s/^/${pad}    /" "/proc/$p/mountinfo" 2>&1
          for c in $(cat "/proc/$p/task/*/children" 2>/dev/null); do
            descend "$c" $((depth + 1))
          done
        }
        descend "$BPID" 0
      } >>"$EVIDENCE_DIR/r7-mapping-buildkitd.log" 2>&1
      kids=""
      {
        echo "--- sample $(date +%H:%M:%S) ---"
        echo "matched pid=$BPID children=$kids"
        for c in $kids; do
          echo "child pid=$c"
          echo "  comm=$(cat "/proc/$c/comm" 2>/dev/null)"
          echo "  attr/current=$(cat "/proc/$c/attr/current" 2>/dev/null)"
          echo "  uid_map:"; sed 's/^/    /' "/proc/$c/uid_map" 2>&1
          echo "  gid_map:"; sed 's/^/    /' "/proc/$c/gid_map" 2>&1
          echo "  caps=$(grep -hE '^CapEff' "/proc/$c/status" 2>/dev/null)"
          echo "  groups=$(grep -h '^Groups' "/proc/$c/status" 2>/dev/null)"
          gkids="$(cat "/proc/$c/task/"*"/children" 2>/dev/null | tr '\n' ' ')"
          for g in $gkids; do
            echo "grandchild pid=$g"
            echo "  comm=$(cat "/proc/$g/comm" 2>/dev/null)"
            echo "  attr/current=$(cat "/proc/$g/attr/current" 2>/dev/null)"
            echo "  uid_map:"; sed 's/^/    /' "/proc/$g/uid_map" 2>&1
            echo "  gid_map:"; sed 's/^/    /' "/proc/$g/gid_map" 2>&1
            echo "  caps=$(grep -hE '^CapEff' "/proc/$g/status" 2>/dev/null)"
          done
        done
      } >>"$EVIDENCE_DIR/r7-mapping-buildkitd.log" 2>&1
      # Do NOT break on the first match: the RUN step's mounts (the
      # overlay snapshot mounts and the containerd-mount binds) are
      # TRANSIENT (they live only while the callback runs). Sample
      # fast and keep the raw mountinfo of every sample so the failing
      # window's mount structure is captured.
      sleep 0.5
    fi
    # The build command has returned: take a few trailing samples (they
    # document the teardown) and finish cleanly instead of waiting out
    # the full deadline.
    if [ -f "$STATE_DIR/build-done" ]; then
      exits=$((exits + 1))
      if [ "$exits" -ge 6 ]; then
        echo "== mapping-poller exit: build-done observed" >>"$EVIDENCE_DIR/r7-mapping-buildkitd.log"
        break
      fi
    fi
    sleep 0.3
  done
) &
MAP_POLLER=$!

# R7-A ownership-forensics poller: capture the /etc/shadow inode's
# identity from BOTH sides of the build namespace boundary WHILE the
# mount callback runs, so the first failing kernel predicate of the
# lchown(0,42) EPERM can be named from recorded facts alone:
#   * the in-namespace view — the stat itself is executed INSIDE the
#     real buildkitd's user and mount namespaces (nsenter -t <pid>
#     -U -m -- stat ...): the presentation the callback's own lchown
#     acts on. (The previous revision ran the INNS-* stat in the diag
#     shell's own namespace — fixed here; nsenter/stat errors are
#     recorded verbatim and are never masked as MISSING.)
#   * the host view — the same path through /proc/<pid>/root (path
#     resolution inside the child mount namespace, ids presented in
#     the reader's user namespace, i.e. the host's), the bind SOURCE
#     (the state-tree snapshot), and the diag shell's own view of the
#     runtime tree.
#   * two-sided proof is claimed ONLY when both views of a pair
#     resolved to the same st_dev + st_ino; then both views' numeric
#     uid/gid are recorded. Mismatches and stat/nsenter errors are
#     recorded as unproven, with the raw error text preserved.
#   * the mountinfo lines naming the bind (an "idmapped" option marker,
#     if the kernel applied an id mapping to the mount) plus this VM's
#     idmapped-mount kernel support.
# The mount callback window is sub-second: a cheap /proc/<pid>/mountinfo
# check gates the expensive in-namespace stat so the full sample fires
# the moment the bind appears, while the state-tree (HOSTSRC) timeline
# keeps a 40ms cadence throughout. The same cycle consumes the lchown
# trace stream (audit or strace) and snapshots /proc/<tid> the moment a
# matching syscall event appears. When the build command has returned
# (build-done marker), the poller drains the trace stream for a short
# grace window and finishes cleanly instead of waiting out its full
# deadline.
(
  deadline=$(( $(date +%s) + 300 ))
  HOST_RT_ROOT=/run/docker-helper-builder/ops
  ST_ROOT=/var/lib/docker-helper-builder/ops
  EV_LINENO=0
  STRACE_LINENO=0
  STRACE_PID=""
  DONE_SINCE=""
  BKPID_CURRENT=""
  EVENTS_PROCESSED=0
  SEEN_EVENTS=0
  declare -A SEEN_SERIALS=()
  statline() { # $1 = view label, $2 = path (read in the diag shell's own namespace)
    local out rc
    if [ ! -e "$2" ]; then printf '%s %s MISSING\n' "$1" "$2"; return; fi
    out="$(stat -L -c '%D %i %u %g %F' "$2" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
      printf '%s %s %s\n' "$1" "$2" "$out"
    else
      printf '%s %s STAT-ERROR rc=%d: %s\n' "$1" "$2" "$rc" "$out"
    fi
  }
  # The stat itself MUST run inside the target's user and mount
  # namespaces: the containerd-mount bind exists only in the buildkitd
  # mount namespace, and that is the presentation the lchown acts on.
  nsstatline() { # $1 = view label, $2 = target pid, $3 = path
    local out rc
    out="$(nsenter -t "$2" -U -m -- stat -L -c '%D %i %u %g %F' "$3" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
      printf '%s %s %s\n' "$1" "$3" "$out"
    else
      printf '%s %s STAT-ERROR rc=%d: %s\n' "$1" "$3" "$rc" "$out"
    fi
  }
  # Two-sided identity verdict for one INNS/HOSTROOT pair: proven only
  # when both views parsed AND resolved to the same st_dev+st_ino; then
  # both views' numeric uid/gid are recorded side by side. A view error,
  # an absent view, or an inode mismatch is recorded as unproven.
  pairverdict() { # $1 = pair label, $2 = INNS line, $3 = HOSTROOT line
    printf '%s %s\n' "$1" "$(printf '%s\n%s\n' "$2" "$3" | awk '
      { if ($3 == "MISSING" || $3 == "STAT-ERROR") bad = 1
        if (NR == 1) { d1 = $3; i1 = $4; u1 = $5; g1 = $6 }
        if (NR == 2) { d2 = $3; i2 = $4; u2 = $5; g2 = $6 } }
      END {
        if (bad) { print "twosided-proof=NO (a view errored or missing; raw views recorded above)"; exit 0 }
        if (d1 == "" || d2 == "") { print "twosided-proof=NO (a view absent)"; exit 0 }
        if (d1 != d2 || i1 != i2) { printf "twosided-proof=NO (inode mismatch: inns=(%s,%s) host=(%s,%s))\n", d1, i1, d2, i2; exit 0 }
        printf "inode-match=YES twosided-proof=YES inns=(dev=%s ino=%s uid=%s gid=%s) host=(dev=%s ino=%s uid=%s gid=%s)\n", d1, i1, u1, g1, d2, i2, u2, g2
      }')"
  }
  # Snapshot one task's identity: its OWN user/mount namespaces, its OWN
  # credentials and capabilities (Uid/Gid/CapEff from the per-thread
  # status — the main PID's CapEff is NOT evidence for the callback
  # thread), the actual uid_map/gid_map, and the mountinfo lines (mount
  # IDs included) for the containerd-mount binds. When the TID has
  # already exited (observed: the failing fchownat ran on the buildkitd
  # leader thread and the whole process exited ~126ms after the EPERM),
  # the process context is captured instead via the poller's live
  # buildkitd pid, explicitly marked as a fallback.
  snapshot_task() { # $1 = tid, $2 = reason label
    local t="$1" why="$2" tgid wt w
    if [ ! -d "/proc/$t" ]; then
      echo "-- task snapshot tid=$t reason=$why ts=$(date +%s.%N): TID already exited (the flow process tears down within ~100ms of the failed callback); capturing the process context instead" >>"$LCHOWN_FORENSICS"
      t="$BKPID_CURRENT"
      if [ -z "$t" ] || [ ! -d "/proc/$t" ]; then
        echo "-- process-context fallback unavailable: no live buildkitd pid" >>"$LCHOWN_FORENSICS"
        return
      fi
      why="$why +process-context-fallback"
    fi
    {
      echo "-- task snapshot tid=$t reason=$why ts=$(date +%s.%N)"
      echo "ns-user: $(readlink "/proc/$t/ns/user" 2>&1)"
      echo "ns-mnt: $(readlink "/proc/$t/ns/mnt" 2>&1)"
      grep -E '^(Name|Tgid|Pid|NSpid|Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb):' "/proc/$t/status" 2>&1 | sed 's/^/status: /'
      echo "uid_map:"; sed 's/^/  /' "/proc/$t/uid_map" 2>&1
      echo "gid_map:"; sed 's/^/  /' "/proc/$t/gid_map" 2>&1
      echo "mountinfo-containerd: $(grep -E 'containerd-mount' "/proc/$t/mountinfo" 2>/dev/null | head -4 | tr '\n' '|')"
      echo "mountinfo-mount-id: $(grep -E 'containerd-mount' "/proc/$t/mountinfo" 2>/dev/null | awk '{print $1}' | head -4 | tr '\n' ' ')"
      tgid="$(awk '/^Tgid:/{print $2}' "/proc/$t/status" 2>/dev/null)"
      echo "tgid: ${tgid:-unknown}"
      if [ -n "$tgid" ] && [ -d "/proc/$tgid" ]; then
        if [ "$tgid" != "$t" ]; then
          echo "-- main-thread comparison (the callback thread's own status above, the main thread's below):"
          echo "main-ns-user: $(readlink "/proc/$tgid/ns/user" 2>&1)"
          echo "main-ns-mnt: $(readlink "/proc/$tgid/ns/mnt" 2>&1)"
          grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb):' "/proc/$tgid/status" 2>&1 | sed 's/^/main-status: /'
          echo "main-uid_map:"; sed 's/^/  /' "/proc/$tgid/uid_map" 2>&1
          echo "main-gid_map:"; sed 's/^/  /' "/proc/$tgid/gid_map" 2>&1
        fi
        echo "thread-ns-inventory:"
        for wt in "/proc/$tgid/task/"*; do
          w="${wt##*/}"
          echo "  tid=$w ns-user=$(readlink "$wt/ns/user" 2>&1) comm=$(cat "$wt/comm" 2>/dev/null) capEff=$(awk '/^CapEff:/{print $2}' "$wt/status" 2>/dev/null)"
        done
      fi
    } >>"$LCHOWN_FORENSICS" 2>&1
  }
  # Consume the newly arrived audit trace lines and process every
  # complete lchown/fchownat event once. Audit records group by their
  # event serial (msg=audit(...:SERIAL)) in every transport (auditd's
  # audit.log and the kernel-printk fallbacks alike), so the whole
  # serial group is recorded and the SYSCALL record (identified by its
  # syscall= field, not by transport-specific type names) is parsed for
  # the caller TID, the verified arguments and the result. The target
  # inode comes from the serial's PATH records. Line-count tracking
  # consumes only newline-terminated lines, so a partially written line
  # is picked up on the next cycle instead of being parsed in half.
  process_event_bytes() { # $1 = complete new lines
    local serial evline w v syscall a1 a2 a3 apid ok mode
    printf '%s\n' "$1" >>"$EV_SEEN"
    for serial in $(printf '%s\n' "$1" | grep -oE 'msg=audit\([0-9]+\.[0-9]+:[0-9]+' | sed 's/.*://' | sort -u); do
      # audit.log renders the syscall field NUMERICALLY (94=lchown,
      # 260=fchownat on x86_64; ausearch -i renders it symbolically).
      evline="$(printf '%s\n' "$1" | grep -F -- ":$serial)" | grep -E 'syscall=(lchown|fchownat|94|260)' | head -1)"
      mode=""
      [ -n "$evline" ] && mode=syscall
      if [ -z "$mode" ]; then
        # Fallback trigger: the LSM face of the same check. If a blanket
        # never,task rule survives, the capability check still emits its
        # AVC: denied { chown } on tclass=cap_userns is the SELinux gate
        # of ns_capable(<userns>, CAP_CHOWN) — the exact predicate the
        # lchown EPERM lives behind. The AVC's pid= is the triggering
        # task's TID.
        evline="$(printf '%s\n' "$1" | grep -F -- ":$serial)" | grep 'tclass=cap_userns' | grep 'denied  { chown }' | head -1)"
        [ -n "$evline" ] && mode=cap_userns
        [ -n "$mode" ] || continue
      fi
      [ -n "${SEEN_SERIALS[$serial]:-}" ] || SEEN_SERIALS[$serial]=1 || true
      {
        echo "== lchown-trace event serial=$serial mechanism=$LCHOWN_TRACE mode=$mode ts=$(date +%s.%N)"
        printf '%s\n' "$1" | grep -F -- ":$serial)" | sed 's/^/event: /'
      } >>"$LCHOWN_FORENSICS"
      syscall=""; a1=""; a2=""; a3=""; apid=""
      for w in $evline; do
        case "$w" in
          syscall=*) syscall="${w#syscall=}";;
          a1=*) v="$(printf '%d' "0x${w#a1=}")" && a1="$v";;
          a2=*) v="$(printf '%d' "0x${w#a2=}")" && a2="$v";;
          a3=*) v="$(printf '%d' "0x${w#a3=}")" && a3="$v";;
          pid=*) apid="${w#pid=}";;
        esac
      done
      ok=no
      if [ "$mode" = syscall ]; then
        if { [ "$syscall" = lchown ] || [ "$syscall" = 94 ]; } && [ "$a1" = 0 ] && [ "$a2" = 42 ] && [ -n "$apid" ]; then ok=yes; fi
        if { [ "$syscall" = fchownat ] || [ "$syscall" = 260 ]; } && [ "$a2" = 0 ] && [ "$a3" = 42 ] && [ -n "$apid" ]; then ok=yes; fi
      elif [ "$mode" = cap_userns ]; then
        for w in $evline; do
          case "$w" in
            capability=0)
              # CAP_CHOWN. The record proves the LSM gate of the
              # capability check was the failing predicate for this TID.
              echo "-- cap_userns chown-denial trigger (CAP_CHOWN, capability=0): caller tid=$apid" >>"$LCHOWN_FORENSICS"
              ok=yes;;
          esac
        done
      fi
      if [ "$ok" = yes ] && [ -n "$apid" ]; then
        if [ "$mode" = cap_userns ]; then
          echo "-- verified cap_userns chown-denial event (CAP_CHOWN): caller tid=$apid" >>"$LCHOWN_FORENSICS"
        else
          echo "-- verified $syscall(uid=0,gid=42) event: caller tid=$apid" >>"$LCHOWN_FORENSICS"
        fi
        EVENTS_PROCESSED=$((EVENTS_PROCESSED + 1))
        snapshot_task "$apid" "lchown-trace-serial-$serial"
      else
        echo "-- unverified trace record (args/parse mismatch, no snapshot): syscall=$syscall a1=$a1 a2=$a2 a3=$a3 pid=$apid" >>"$LCHOWN_FORENSICS"
      fi
    done
  }
  while [ "$(date +%s)" -lt "$deadline" ]; do
    # --- lchown trace stream consumption (audit or strace) -------------
    if [ "$LCHOWN_TRACE" = audit ]; then
      total="$(wc -l <"$EV_STREAM" 2>/dev/null || echo 0)"
      if [ "$total" -lt "$EV_LINENO" ]; then EV_LINENO=0; fi
      if [ "$total" -gt "$EV_LINENO" ]; then
        # head -n caps the chunk to the newline-terminated lines wc -l
        # counted: tail alone would leak the trailing partial line (and
        # re-emit it once it is completed).
        chunk="$(tail -n +"$((EV_LINENO + 1))" "$EV_STREAM" 2>/dev/null | head -n "$total")"
        EV_LINENO="$total"
        process_event_bytes "$chunk"
      fi
    elif [ "$LCHOWN_TRACE" = strace ]; then
      total="$(wc -l <"$STRACE_LOG" 2>/dev/null || echo 0)"
      if [ "$total" -lt "$STRACE_LINENO" ]; then STRACE_LINENO=0; fi
      if [ "$total" -gt "$STRACE_LINENO" ]; then
        chunk="$(tail -n +"$((STRACE_LINENO + 1))" "$STRACE_LOG" 2>/dev/null | head -n "$total")"
        STRACE_LINENO="$total"
        printf '%s\n' "$chunk" >>"$EV_SEEN"
        for t in $(printf '%s\n' "$chunk" | grep -E '(l|f)chown(at)?\(' | sed -E 's/^\[pid +([0-9]+)\].*/\1/;t;s/^([0-9]+)\b.*/\1/'); do
          echo "== strace lchown/fchownat observed: tid=$t ts=$(date +%s.%N)" >>"$LCHOWN_FORENSICS"
          snapshot_task "$t" "strace-lchown"
        done
      fi
    fi
    if [ -f "$STATE_DIR/build-done" ]; then
      # The build command has returned: keep only draining the trace
      # stream for a short grace window (the audit record lands before
      # buildctl exits, so this rarely waits), then finish cleanly.
      if [ -z "$DONE_SINCE" ]; then DONE_SINCE="$(date +%s)"; fi
      if [ "$(( $(date +%s) - DONE_SINCE ))" -ge 5 ]; then
        echo "== ownership-poller exit: build-done observed (trace drained)" >>"$LCHOWN_FORENSICS"
        break
      fi
      sleep 0.04
      continue
    fi
    # The real buildkitd: a pgrep -x buildkitd match whose uid_map
    # carries the child user namespace (>= 2 mapping lines). The
    # rootlesskit wrapper stays in the init userns.
    P=""
    for cand in $(pgrep -x buildkitd); do
      if [ "$(grep -c . "/proc/$cand/uid_map" 2>/dev/null)" -ge 2 ]; then P="$cand"; break; fi
    done
    if [ -n "$P" ]; then
      BKPID_CURRENT="$P"
    elif [ -n "$BKPID_CURRENT" ]; then
      # Guard against pid reuse: only keep the fallback pid while it is
      # still a live buildkitd.
      if [ "$(cat "/proc/$BKPID_CURRENT/comm" 2>/dev/null)" != buildkitd ]; then BKPID_CURRENT=""; fi
    fi
    # strace fallback: attach the moment the real buildkitd appears. The
    # repeated -p list covers the threads that already exist; -f follows
    # threads created after the attach.
    if [ "$LCHOWN_TRACE" = strace ] && [ -n "$P" ] && [ -z "$STRACE_PID" ]; then
      PARGS=""
      for t in "/proc/$P/task/"*; do PARGS="$PARGS -p ${t##*/}"; done
      strace -f -qq -tt -s 400 -e trace=lchown,fchownat,chown,fchown $PARGS \
        -o "$STRACE_LOG" 2>"$EVIDENCE_DIR/r7-lchown-strace.err" &
      STRACE_PID=$!
      echo "strace attached: pid=$STRACE_PID tasks:$PARGS" >>"$LCHOWN_FORENSICS"
    fi
    # An event just landed: process it immediately (the flow process can
    # exit ~100ms after the failed callback — the snapshot races the
    # teardown), and only then resume the inode sampling cadence.
    if [ "$EVENTS_PROCESSED" -gt "$SEEN_EVENTS" ]; then
      SEEN_EVENTS="$EVENTS_PROCESSED"
      continue
    fi
    TS="$(date +%s.%N)"
    {
      echo "== sample ts=$TS bkpid=${P:-none}"
      # The state-tree timeline is sampled every cycle: it records when
      # each snapshot's /etc/shadow first appears and with which
      # host-side uid/gid (extraction-time vs post-remap evidence).
      for s in "$ST_ROOT"/*/root/runc-*/snapshots/snapshots/*; do
        [ -d "$s" ] || continue
        if [ -d "$s/fs" ]; then SD="$s/fs"; else SD="$s"; fi
        statline "HOSTSRC-shadow " "$SD/etc/shadow"
        statline "HOSTSRC-dir " "$s"
      done
      if [ -z "$P" ]; then
        echo "buildkitd: absent"
      else
        OP="$(tr '\0' '\n' <"/proc/$P/cmdline" | sed -n 's/^--root=//p' | head -1)"
        OP="$(basename "$(dirname "$OP")" 2>/dev/null)"
        [ -n "$OP" ] || OP=UNKNOWN
        # Cheap window gate: the containerd-mount BIND exists only while
        # the mount callback runs (the bare dir also shows up in the
        # host's tmpfs view, but the bind is the lchown's presentation).
        BINDS="$(grep -E 'containerd-mount' "/proc/$P/mountinfo" 2>/dev/null || true)"
        echo "bind-window: $([ -n "$BINDS" ] && echo LIVE || echo absent)"
        echo "runtime-mount-dirs(host-view): $(for d in "$HOST_RT_ROOT"/"$OP"/containerd-mount*; do [ -e "$d" ] && printf '%s ' "$d"; done)"
        statline "HOST-direct-runtime " "$HOST_RT_ROOT/$OP"
        if [ -n "$BINDS" ]; then
          MDIRS="$(printf '%s\n' "$BINDS" | awk '$5 ~ /containerd-mount/ {print $5}')"
          for d in $MDIRS; do
            echo "bind-mountinfo: $(printf '%s\n' "$BINDS" | grep -F " $d " | head -2 | tr '\n' '|')"
            inns_dir="$(nsstatline "INNS-dir " "$P" "$d")"; printf '%s\n' "$inns_dir"
            inns_sh="$(nsstatline "INNS-shadow " "$P" "$d/etc/shadow")"; printf '%s\n' "$inns_sh"
            host_dir="$(statline "HOSTROOT-dir " "/proc/$P/root$d")"; printf '%s\n' "$host_dir"
            host_sh="$(statline "HOSTROOT-shadow " "/proc/$P/root$d/etc/shadow")"; printf '%s\n' "$host_sh"
            pairverdict "PAIR-dir:" "$inns_dir" "$host_dir"
            pairverdict "PAIR-shadow:" "$inns_sh" "$host_sh"
          done
        fi
      fi
      # One-time idmapped-mount support evidence (first sample only).
      if [ ! -s "$EVIDENCE_DIR/r7-idmap-support.txt" ]; then
        {
          echo "kernel=$(uname -r)"
          zgrep -hE 'CONFIG_IDMAP_MOUNTS|CONFIG_XFS_FS|CONFIG_OVERLAY_FS|CONFIG_TMPFS_XATTR|CONFIG_SHIFT_FS' /proc/config.gz 2>/dev/null || true
          grep -hE 'CONFIG_IDMAP_MOUNTS|CONFIG_XFS_FS|CONFIG_OVERLAY_FS|CONFIG_TMPFS_XATTR|CONFIG_SHIFT_FS' "/boot/config-$(uname -r)" 2>/dev/null || true
          echo "--- findmnt state tree:"; findmnt -T "$ST_ROOT" -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1 || true
          echo "--- findmnt runtime tree:"; findmnt -T "$HOST_RT_ROOT" -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1 || true
          echo "--- any live idmapped mounts:"; grep -h 'idmapped' /proc/[0-9]*/mountinfo 2>/dev/null | head -5 || echo none
        } >"$EVIDENCE_DIR/r7-idmap-support.txt" 2>&1
      fi
    } >>"$EVIDENCE_DIR/r7-ownership-forensics.log" 2>&1
    sleep 0.04
  done
) &
OWN_POLLER=$!

BUILD_START_EPOCH="$(date +%s)"
set +e
docker-helper build buildctx --dockerfile Dockerfile --image r7diag:alpine3.24 \
  >"$EVIDENCE_DIR/r7-build-cli.log" 2>&1
BUILD_RC=$?
set -e
BUILD_END_EPOCH="$(date +%s)"
# Signal both pollers to finish their evidence collection and exit
# cleanly (short grace windows) instead of waiting out their full
# deadlines after the build is already over.
touch "$STATE_DIR/build-done"
printf '%s\n' "$BUILD_RC" >"$STATE_DIR/build-rc"
wait "$MAP_POLLER" 2>/dev/null || true
wait "$OWN_POLLER" 2>/dev/null || true
# Trace teardown: stop the event stream consumer, stop any strace
# attach, remove the audit rules (the VM keeps no diag residue), and
# pull the audit-side recovery net for the trace window.
if [ -n "$EV_CONSUMER_PID" ]; then kill "$EV_CONSUMER_PID" 2>/dev/null || true; fi
if [ -n "$STRACE_PID" ]; then kill "$STRACE_PID" 2>/dev/null || true; fi
if [ "$LCHOWN_TRACE" = audit ]; then
  {
    auditctl -d always,exit -F arch=b64 -S lchown -F a1=0 -F a2=42 -k r7lchown 2>&1 || true
    auditctl -d always,exit -F arch=b64 -S fchownat -F a2=0 -F a3=42 -k r7lchown 2>&1 || true
    echo "--- restoring the blanket never,task rule:"
    auditctl -a never,task 2>&1 || true
    echo "--- audit rules after cleanup:"
    auditctl -l 2>&1 || true
    if command -v ausearch >/dev/null 2>&1; then
      echo "--- ausearch -k r7lchown (recovery net over the trace window):"
      ausearch -k r7lchown -i --start recent 2>&1 || true
    fi
  } >>"$LCHOWN_FORENSICS" 2>&1
fi
log "BUILD RC=$BUILD_RC (elapsed $((BUILD_END_EPOCH - BUILD_START_EPOCH))s)"
fi
if [ -s "$EVIDENCE_DIR/r7-mapping-buildkitd.log" ]; then
  log "--- r7-mapping-buildkitd (captured during the build) ---"
  cat "$EVIDENCE_DIR/r7-mapping-buildkitd.log"
fi
if [ -s "$EVIDENCE_DIR/r7-ownership-forensics.log" ]; then
  log "--- r7-ownership-forensics (captured during the build) ---"
  cat "$EVIDENCE_DIR/r7-ownership-forensics.log"
fi
if [ -s "$EVIDENCE_DIR/r7-lchown-forensics.log" ]; then
  log "--- r7-lchown-forensics (lchown TID + namespace/capability context) ---"
  cat "$EVIDENCE_DIR/r7-lchown-forensics.log"
fi
if [ -s "$EVIDENCE_DIR/r7-idmap-support.txt" ]; then
  log "--- r7-idmap-support ---"
  cat "$EVIDENCE_DIR/r7-idmap-support.txt"
fi
head -n 40 "$EVIDENCE_DIR/r7-build-cli.log"

# ============================================================================
# Section 5: post-build evidence (AVCs, journals, live process contexts)
# ============================================================================
log "=== section 5: post-build evidence ==="
# R7-C core FIRST: the manager's own diag lines live in the builder service
# journal (StandardError=journal); capture the journals before any
# potentially slower evidence step.
cap r7-builder-journal 200 bash -c "journalctl -u docker-helper-builder.service --no-pager | tail -200"
cap r7-daemon-journal 120 bash -c "journalctl -u docker-helper.service --no-pager | tail -120"
if command -v ausearch >/dev/null 2>&1; then
  cap r7-avc-full 400 ausearch -m AVC -m USER_AVC --start recent
else
  cap r7-avc-journal 200 bash -c "journalctl -k --no-pager 2>/dev/null | grep -iE 'avc|apparmor=' | tail -200 || true"
fi
if [ "$BACKEND" = "selinux" ]; then
  cap r7-process-contexts 40 bash -c 'ps -eZ 2>/dev/null | grep -E "docker-helper|buildkit|rootlesskit|slirp4netns|newuidmap|newgidmap" || true'
  cap r7-sesearch-builder-signal 30 bash -c 'sesearch -A -s docker_helper_builder_t -c process 2>/dev/null | head -30 || true'
elif [ "$BACKEND" = "apparmor" ]; then
  cap r7-process-contexts 40 bash -c 'ps auxZ 2>/dev/null | grep -E "docker-helper|buildkit|rootlesskit|slirp4netns|newuidmap|newgidmap" || true'
fi
cap r7-kernel-audit-tail 80 bash -c "dmesg 2>/dev/null | tail -80 || journalctl -k --no-pager | tail -80"
# The lchown trace records land in the disk-backed audit.log, which
# survives the diag VM's mid-run reboot; this recovery net runs on every
# invocation (also the re-entry that skips the build) so a trace window
# cut short by the reboot is still recovered.
if command -v ausearch >/dev/null 2>&1; then
  cap r7-lchown-ausearch 200 ausearch -k r7lchown -i --start today
fi
cap r7-lchown-events-head 120 bash -c "head -n 120 '$EVIDENCE_DIR/r7-lchown-events-seen.log' 2>/dev/null || true"
cap r7-builder-unit 20 bash -c 'systemctl cat docker-helper-builder.service 2>/dev/null || true'

# R7 mapping forensics: the lchown(0,42) EPERM class needs the build
# namespace's ACTUAL id mapping. The in-build capture above covers the
# live buildkitd process (r7-mapping-buildkitd.log, written by the map
# poller while the process was alive — this post-build capture is a
# separate file so it never truncates the live one); the captures below
# cover the environment-side facts (the subid files' labels and the
# range lookups) and survive the build either way. Every step survives
# absence (the forensic evidence is the deliverable, not an assertion).
cap r7-mapping-buildkitd-postbuild 20 bash -c '
  BPID="$(pgrep -f "buildkitd" | head -1)"
  echo "buildkitd pid=$BPID"
  if [ -n "$BPID" ]; then
    echo "--- /proc/$BPID/uid_map"; cat "/proc/$BPID/uid_map" 2>&1
    echo "--- /proc/$BPID/gid_map"; cat "/proc/$BPID/gid_map" 2>&1
    echo "--- caps"; grep -iE "^Cap(Eff|Bnd|Prm)" "/proc/$BPID/status" 2>&1
    echo "--- groups"; grep "^Groups:" "/proc/$BPID/status" 2>&1
  fi'
cap r7-mapping-flow 20 bash -c '
  FPID="$(pgrep -f "rootlesskit" | head -1)"
  echo "rootlesskit pid=$FPID"
  if [ -n "$FPID" ]; then
    echo "--- /proc/$FPID/uid_map"; cat "/proc/$FPID/uid_map" 2>&1
    echo "--- /proc/$FPID/gid_map"; cat "/proc/$FPID/gid_map" 2>&1
  fi'
cap r7-mapping-subid 20 bash -c '
  ls -lZ /etc/subuid /etc/subgid /etc/passwd /etc/group 2>&1
  for f in /etc/subuid /etc/subgid /etc/passwd /etc/group; do echo "matchpathcon -V $f: $(matchpathcon -V "$f" 2>&1)"; done
  echo "--- getsubids"; command -v getsubids >/dev/null 2>&1 && getsubids docker-helper-builder 2>&1 || echo "(getsubids absent)"
  echo "--- getent"; getent subuid docker-helper-builder 2>&1; getent subgid docker-helper-builder 2>&1
  echo "--- flow groups"; id docker-helper-builder 2>&1'
cap r7-mapping-probe 40 bash -s <<'R7PROBE'
# The direct kernel probe for the exact failing operation: inside a NEW
# user namespace backed by the provisioned subid ranges, chown a probe
# file to 0:42 and report the errno. This isolates the kernel check from
# buildkit entirely.
set +e
UN="$(command -v unshare || true)"
NU="$(command -v newuidmap || true)"
NG="$(command -v newgidmap || true)"
echo "prereqs: unshare=$UN newuidmap=$NU newgidmap=$NG"
T="$(mktemp /tmp/r7-map-probe.XXXXXX)"
chmod 666 "$T" 2>/dev/null || true
if [ -n "$UN" ]; then
  unshare -U --map-user=0 --map-group=0 sh -c "
    echo probe > $T 2>/dev/null || true
    chown 0:42 $T && echo chown-0:42-inside-self-map-ns:OK || echo chown-0:42-inside-self-map-ns:FAILED
  " 2>&1 || true
fi
U="$(id -u docker-helper-builder 2>/dev/null)"
G="$(id -g docker-helper-builder 2>/dev/null)"
# getent has no subuid/subgid database on this distro; getsubids is the
# shadow tool that resolves the provisioned ranges.
UR="$(getsubids -u docker-helper-builder 2>/dev/null | awk '{print $3, $4}')"
GR="$(getsubids -g docker-helper-builder 2>/dev/null | awk '{print $3, $4}')"
echo "flow uid=$U gid=$G subuid=[$UR] subgid=[$GR]"
if [ -n "$UN" ] && [ -n "$NU" ] && [ -n "$NG" ] && [ -n "$UR" ] && [ -n "$GR" ]; then
  child="$(unshare -U sh -c 'echo $$; exec sleep 12' 2>/dev/null | head -1)"
  if [ -n "$child" ]; then
    newuidmap "$child" 0 "$U" 1 $UR >/dev/null 2>&1 || echo "newuidmap rc=$?"
    newgidmap "$child" 0 "$G" 1 $GR >/dev/null 2>&1 || echo "newgidmap rc=$?"
    nsenter -U -t "$child" sh -c "echo probe > $T; chown 0:42 $T && echo chown-0:42-full-range-ns:OK || echo chown-0:42-full-range-ns:FAILED" 2>&1 || true
    kill "$child" 2>/dev/null || true
  else
    echo "(unshare -U child could not be started)"
  fi
fi
rm -f "$T"
R7PROBE

# ============================================================================
# Section 6: verdict
# ============================================================================
log "=== section 6: verdict ==="
printf 'R7-DIAG-BUILD-RC=%s\n' "$BUILD_RC"
if [ "$EXPECT" = "fail" ] && [ "$BUILD_RC" -ne 0 ]; then
  printf 'R7-DIAG-RESULT=REPRODUCED\n'
  exit 0
elif [ "$EXPECT" = "ok" ] && [ "$BUILD_RC" -eq 0 ]; then
  printf 'R7-DIAG-RESULT=BUILD-OK\n'
  exit 0
fi
printf 'R7-DIAG-RESULT=UNEXPECTED\n'
exit 1
