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
  local name="$1" maxn="$2"; shift 2
  "$@" >"$EVIDENCE_DIR/$name.log" 2>&1
  log "--- $name (evidence: $EVIDENCE_DIR/$name.log, first $maxn lines) ---"
  head -n "$maxn" "$EVIDENCE_DIR/$name.log"
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
elif [ "$INSTALL_FMT" = "tarball" ]; then
  EXTRACT="$(mktemp -d /tmp/r7-bundle.XXXXXX)"
  tar xzf "$ARTIFACT" -C "$EXTRACT" || fail "tar extraction failed"
  BUNDLE="$(find "$EXTRACT" -maxdepth 1 -type d -name 'docker-helper-*' | head -1)"
  [ -n "$BUNDLE" ] && [ -x "$BUNDLE/install-system.sh" ] || fail "bundle/install-system.sh not found"
  (cd "$BUNDLE" && ./install-system.sh --yes --allowed-root "$ALLOWED_ROOT") \
    || fail "install-system.sh failed"
  log "tarball install complete"
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
# sequence the UAT scenario runs).
docker-helper principal create --no-credential "$PRINCIPAL" \
  || fail "principal create failed"
docker-helper principal allowed-root add "$PRINCIPAL" "$ALLOWED_ROOT" \
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

BUILD_START_EPOCH="$(date +%s)"
set +e
docker-helper build buildctx --dockerfile Dockerfile --image r7diag:alpine3.24 \
  >"$EVIDENCE_DIR/r7-build-cli.log" 2>&1
BUILD_RC=$?
set -e
BUILD_END_EPOCH="$(date +%s)"
log "BUILD RC=$BUILD_RC (elapsed $((BUILD_END_EPOCH - BUILD_START_EPOCH))s)"
head -n 40 "$EVIDENCE_DIR/r7-build-cli.log"

# ============================================================================
# Section 5: post-build evidence (AVCs, journals, live process contexts)
# ============================================================================
log "=== section 5: post-build evidence ==="
if command -v ausearch >/dev/null 2>&1; then
  cap r7-avc-full 400 ausearch -m AVC -m USER_AVC --start recent
else
  cap r7-avc-journal 200 bash -c "journalctl -k --no-pager --since \"@$BUILD_START_EPOCH\" 2>/dev/null | grep -i 'avc' || true"
fi
cap r7-daemon-journal 120 bash -c "journalctl -u docker-helper.service --no-pager --since \"@$BUILD_START_EPOCH\" | tail -120"
# R7-C core: the manager's own diag lines live in the builder service journal.
cap r7-builder-journal 200 bash -c "journalctl -u docker-helper-builder.service --no-pager --since \"@$BUILD_START_EPOCH\" | tail -200"
if [ "$BACKEND" = "selinux" ]; then
  cap r7-process-contexts 40 bash -c 'ps -eZ 2>/dev/null | grep -E "docker-helper|buildkit|rootlesskit|slirp4netns|newuidmap|newgidmap" || true'
  cap r7-sesearch-builder-signal 30 bash -c 'sesearch -A -s docker_helper_builder_t -c process 2>/dev/null | head -30 || true'
elif [ "$BACKEND" = "apparmor" ]; then
  cap r7-process-contexts 40 bash -c 'ps auxZ 2>/dev/null | grep -E "docker-helper|buildkit|rootlesskit|slirp4netns|newuidmap|newgidmap" || true'
fi
cap r7-kernel-audit-tail 80 bash -c "dmesg 2>/dev/null | tail -80 || journalctl -k --no-pager | tail -80"
cap r7-builder-unit 20 bash -c 'systemctl cat docker-helper-builder.service 2>/dev/null || true'

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
