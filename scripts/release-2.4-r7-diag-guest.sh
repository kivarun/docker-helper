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
log "=== section 1: platform + dependency evidence (R7-B) ==="
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

# ============================================================================
# Section 2: exact candidate install (never rebuilds)
# ============================================================================
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

# ============================================================================
# Section 4: minimal build reproduction through the REAL daemon
# ============================================================================
log "=== section 4: build reproduction ==="
# The diag VM reboots mid-diagnosis (observed ~55s after boot, runs
# 39006788899+). Every phase writes a marker; a re-entry (the runner
# re-invokes this script over a fresh SSH session after the reboot)
# skips completed phases and finishes the remaining ones. The runner
# loops the invocation until the verdict appears.
STATE_DIR=/tmp/r7-diag-state
mkdir -p "$STATE_DIR"
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

# The mapping capture must happen WHILE the flow's buildkitd process is
# alive: the diag VM can reboot mid-diagnosis (observed ~55s after boot,
# run 39006788899), so the forensic capture runs as a bounded background
# poller during the build instead of after it. The poller stops as soon
# as it has one full capture (or the deadline passes).
(
  deadline=$(( $(date +%s) + 180 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
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
          for c in $(cat "/proc/$p/task/*/children" 2>/dev/null); do
            descend "$c" $((depth + 1))
          done
        }
        descend "$BPID" 0
      } >"$EVIDENCE_DIR/r7-mapping-buildkitd.log" 2>&1
      {
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
      break
    fi
    sleep 1
  done
) &
MAP_POLLER=$!

BUILD_START_EPOCH="$(date +%s)"
set +e
docker-helper build buildctx --dockerfile Dockerfile --image r7diag:alpine3.24 \
  >"$EVIDENCE_DIR/r7-build-cli.log" 2>&1
BUILD_RC=$?
set -e
wait "$MAP_POLLER" 2>/dev/null || true
BUILD_END_EPOCH="$(date +%s)"
log "BUILD RC=$BUILD_RC (elapsed $((BUILD_END_EPOCH - BUILD_START_EPOCH))s)"
printf '%s\n' "$BUILD_RC" >"$STATE_DIR/build-rc"
touch "$STATE_DIR/build-done"
fi
if [ -s "$EVIDENCE_DIR/r7-mapping-buildkitd.log" ]; then
  log "--- r7-mapping-buildkitd (captured during the build) ---"
  cat "$EVIDENCE_DIR/r7-mapping-buildkitd.log"
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
cap r7-builder-unit 20 bash -c 'systemctl cat docker-helper-builder.service 2>/dev/null || true'

# R7 mapping forensics: the lchown(0,42) EPERM class needs the build
# namespace's ACTUAL id mapping. The in-build capture above covers the
# live buildkitd process; the captures below cover the environment-side
# facts (the subid files' labels and the range lookups) and survive the
# build either way. Every step survives absence (the forensic evidence
# is the deliverable, not an assertion).
cap r7-mapping-buildkitd 20 bash -c '
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
UR="$(getent subuid docker-helper-builder 2>/dev/null | cut -d: -f2-)"
GR="$(getent subgid docker-helper-builder 2>/dev/null | cut -d: -f2-)"
echo "flow uid=$U gid=$G subuid=$UR subgid=$GR"
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
