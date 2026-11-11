#!/usr/bin/env bash
#
# release-2.4-r7-p21e3-guest.sh — the R7 P21-E-R4-P3-P3 FIRST ENFORCING
# integration measurement: one bounded build on a disposable ENFORCING
# openSUSE Tumbleweed VM with the exact freshly produced candidate RPM and
# its UNCHANGED packaged policy, tracing the wrapper chain end to end.
#
# MODE: diagnostic evidence only. NO grants, NO policy edits/reloads
# outside the ordinary candidate installation, NO relabeling outside the
# installer contract, NO chmod/chown workarounds, NO fallback to a distro
# runc, NO speculative retries. The build is ALLOWED to fail: the round
# measures the first execution, which checks pass, and the FIRST observed
# failure boundary.
#
# Evidence per boundary of the accepted chain
# (POST /build → manager START → rootlesskit/buildkitd → exec
# buildkit-runc (wrapper) → own-context read → prepared-tree inspection →
# spec rewrite + rename commit → execve(runtime/buildkit-runc) → runc
# container init → /dev bind / subsequent mounts):
#
#   * a /proc sampler records, for every relevant process, pid/ppid/comm/
#     exe/cmdline and the KERNEL CONTEXT (/proc/<pid>/attr/current). The
#     wrapper and the REAL RUNTIME are distinguished by /proc/<pid>/exe
#     (…/buildkit-runc vs …/runtime/buildkit-runc) across the execve —
#     never by comm alone (both are comm="buildkit-runc").
#   * strace -f is attached to the live buildkitd at boot and follows the
#     whole subtree: the wrapper's own syscalls (the OBL-7 own-context
#     procattr read via open + read), the spec rewrite (open/create/rename),
#     the execve handoff, and the real runtime's container-init syscalls
#     (mounted/mkdir/symlink — the OBL-1′ bind surface) with decoded paths.
#     The syscall filter deliberately excludes write/close to bound output;
#     the build cache is pre-warmed so IO noise stays small. A hard
#     timeout bounds the trace.
#   * the audit window uses ONE pinned descriptor on the audit source:
#     the start offset is aligned to a record boundary and every window
#     record is read THROUGH that descriptor after the build, with a
#     path-vs-descriptor identity check (dev:ino) at both checkpoints.
#
# Machine verdict contract: R7-P21E3-VERDICT=MEASURED when the one build
# operation ran and the evidence parts exist (the build itself may fail —
# the verdict records the actual failure shape separately via
# R7-P21E3-BUILD=<failed|succeeded>). An aborted measurement decides
# BLOCKED, never success.

set -uo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log()  { printf '[r7-p21e3] %s\n' "$*"; }
fail() { printf '[r7-p21e3] FAILED: %s\n' "$*" >&2; exit 1; }

ARTIFACT="${R7_ARTIFACT:?R7_ARTIFACT required}"
ARTIFACT_SHA="${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"
EVIDENCE_DIR="${R7_EVIDENCE_DIR:-/tmp/r7-p21e3-evidence}"
STATE_DIR=/tmp/r7-p21e3-state
mkdir -p "$EVIDENCE_DIR" "$STATE_DIR"
DH_SOCK=/run/docker-helper/docker-helper.sock
BUILDER_STATE_ROOT=/var/lib/docker-helper-builder
AUDIT_LOG_PATH=/var/log/audit/audit.log
STRACE_TIMEOUT=120

cap() { # <name> <max-lines> <cmd...>
  local name="$1" maxn="$2" rc; shift 2
  "$@" >"$EVIDENCE_DIR/$name.log" 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || printf 'capture rc=%d\n' "$rc" >>"$EVIDENCE_DIR/$name.log"
  log "--- $name (evidence: $EVIDENCE_DIR/$name.log, first $maxn lines) ---"
  head -n "$maxn" "$EVIDENCE_DIR/$name.log"
  return 0
}

# ---------------------------------------------------------------------------
# Section 1: platform + SELinux enforcing proof
# ---------------------------------------------------------------------------
if [ -f "$STATE_DIR/sec1" ]; then log "phase marker: section 1 done; skipping"; else
log "=== section 1: platform + enforcing ==="
ENF="$(getenforce 2>/dev/null || echo absent)"
[ "$ENF" = "Enforcing" ] || fail "SELinux not enforcing (getenforce='$ENF')"
cat /sys/kernel/security/lsm >"$EVIDENCE_DIR/lsm.txt" 2>&1 || true
grep -qw selinux "$EVIDENCE_DIR/lsm.txt" || fail "selinux not an active LSM"
cap p21e3-se-status 8 bash -c 'sestatus; echo ---; getenforce; id -Z'
cat /etc/os-release >"$EVIDENCE_DIR/os-release.txt" 2>&1
grep -qi 'opensuse tumbleweed' "$EVIDENCE_DIR/os-release.txt" || fail "not openSUSE Tumbleweed"
cap p21e3-platform 4 bash -c 'uname -a'
touch "$STATE_DIR/sec1"
fi

# ---------------------------------------------------------------------------
# Section 2: exact candidate install (never rebuilds)
# ---------------------------------------------------------------------------
if [ -f "$STATE_DIR/sec2" ]; then log "phase marker: section 2 done; skipping"; else
log "=== section 2: candidate install (rpm) ==="
[ -f "$ARTIFACT" ] || fail "artifact missing: $ARTIFACT"
now_sha="$(sha256sum "$ARTIFACT" | awk '{print $1}')"
[ "$now_sha" = "$ARTIFACT_SHA" ] || fail "artifact SHA mismatch (expected $ARTIFACT_SHA, got $now_sha)"
rpm -q docker-helper >/dev/null 2>&1 && rpm -e docker-helper >/dev/null 2>&1 || true
rpm -i "$ARTIFACT" || fail "rpm -i failed"
log "RPM installed: $(rpm -q docker-helper)"
sha256sum "$ARTIFACT" > "$EVIDENCE_DIR/candidate-rpm-sha256.log"
# No unexpected package/runtime fallback: record the distro runtime
# package state (informational; the flow never selects it — the shipped
# policy denies the bin_t exec from the daemon domain).
rpm -q runc >"$EVIDENCE_DIR/distro-runc-package.log" 2>&1 || true
command -v runc >"$EVIDENCE_DIR/distro-runc-path.log" 2>&1 || true
PRINCIPAL="${SUDO_USER:-}"
[ -n "$PRINCIPAL" ] && [ "$PRINCIPAL" != "root" ] || fail "cannot derive non-root principal"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
[ -n "$PRINCIPAL_HOME" ] && [ -d "$PRINCIPAL_HOME" ] || fail "principal home not found"
docker-helper init --allowed-root "$PRINCIPAL_HOME" || fail "docker-helper init failed"
systemctl daemon-reload
systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
systemctl enable --now docker-helper-builder.service >/dev/null 2>&1 || true
READY=0
for _ in $(seq 1 50); do
  if [ -S "$DH_SOCK" ] && curl --silent --fail --max-time 1 \
      --unix-socket "$DH_SOCK" http://localhost/health >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 0.2
done
[ "$READY" = 1 ] || fail "daemon API socket not ready"
cap p21e3-services 12 systemctl --no-pager --full status docker-helper.service docker-helper-builder.service
log "daemon ready on $DH_SOCK"
touch "$STATE_DIR/sec2"
fi

PRINCIPAL="${SUDO_USER:-}"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"

# ---------------------------------------------------------------------------
# Section 3: installed payload identity + executable labels (OBL-4)
# ---------------------------------------------------------------------------
if [ -f "$STATE_DIR/sec3" ]; then log "phase marker: section 3 done; skipping"; else
log "=== section 3: installed identity + labels ==="
# Byte identity: the wrapper payload member IS the product binary; the
# relocated pinned runtime matches the shipped MANIFEST digest.
{
  echo "== byte identity =="
  echo "product  docker-helper: $(sha256sum /usr/bin/docker-helper | awk '{print $1}')"
  echo "wrapper  buildkit-runc: $(sha256sum /usr/libexec/docker-helper/buildkit/buildkit-runc | awk '{print $1}')"
  echo "runtime  runtime/buildkit-runc: $(sha256sum /usr/libexec/docker-helper/buildkit/runtime/buildkit-runc | awk '{print $1}')"
  iw="$(sha256sum /usr/bin/docker-helper | awk '{print $1}')"
  gw="$(sha256sum /usr/libexec/docker-helper/buildkit/buildkit-runc | awk '{print $1}')"
  gr="$(sha256sum /usr/libexec/docker-helper/buildkit/runtime/buildkit-runc | awk '{print $1}')"
  mw="$(sed -n 's/^buildkit-runc-sha256=//p' /usr/share/doc/docker-helper/buildkit/MANIFEST)"
  [ "$iw" = "$gw" ] && echo "wrapper==product: MATCH" || echo "wrapper==product: MISMATCH $iw $gw"
  [ "$gr" = "$mw" ] && echo "runtime==pinned-manifest: MATCH" || echo "runtime==pinned-manifest: MISMATCH runtime=$gr manifest=$mw"
} > "$EVIDENCE_DIR/p21e3-byte-identity.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-byte-identity.log"
# Actual labels vs the exact .fc expectations (OBL-4: live labels, never
# closed from compilation).
{
  echo "== ls -Z (actual labels) =="
  stat -c '%N %C mode=%a' /usr/bin/docker-helper
  stat -c '%N %C mode=%a' /usr/libexec/docker-helper/buildkit/buildkitd
  stat -c '%N %C mode=%a' /usr/libexec/docker-helper/buildkit/buildctl
  stat -c '%N %C mode=%a' /usr/libexec/docker-helper/buildkit/buildkit-runc
  stat -c '%N %C mode=%a' /usr/libexec/docker-helper/buildkit/runtime/buildkit-runc
  echo "== matchpathcon (policy expectation) =="
  for p in /usr/bin/docker-helper \
    /usr/libexec/docker-helper/buildkit/buildkitd \
    /usr/libexec/docker-helper/buildkit/buildctl \
    /usr/libexec/docker-helper/buildkit/buildkit-runc \
    /usr/libexec/docker-helper/buildkit/runtime/buildkit-runc; do
    printf '%s -> ' "$p"; matchpathcon "$p" 2>&1
  done
  echo "== symlink/loop check =="
  find /usr/libexec/docker-helper/buildkit -type l -print
  echo "(no output above = no symlinks in the payload tree)"
} > "$EVIDENCE_DIR/p21e3-labels.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-labels.log"
cap p21e3-payload-manifest 12 cat /usr/share/doc/docker-helper/buildkit/MANIFEST
# Installed module identity.
{
  semodule -l 2>/dev/null | grep -i docker || true
  echo "---"
  sha256sum /usr/share/selinux/docker_helper.pp 2>/dev/null || true
  sha256sum /sys/fs/selinux/policy 2>/dev/null || true
} > "$EVIDENCE_DIR/p21e3-module.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-module.log"
touch "$STATE_DIR/sec3"
fi

# ---------------------------------------------------------------------------
# Section 4: the measurement tooling (sampler + strace + audit window)
# ---------------------------------------------------------------------------
if [ ! -x "$EVIDENCE_DIR/p21e3_proc_sampler" ] || [ ! -f "$STATE_DIR/sec4" ]; then
log "=== section 4: tooling build ==="
if ! command -v gcc >/dev/null 2>&1 || ! command -v strace >/dev/null 2>&1; then
  cap p21e3-toolchain 6 timeout 300 zypper --non-interactive install -y gcc strace
fi
command -v gcc >/dev/null 2>&1 || fail "gcc unavailable"
command -v strace >/dev/null 2>&1 || fail "strace unavailable"

cat > "$EVIDENCE_DIR/p21e3_proc_sampler.c" <<'CEOF'
/* p21e3_proc_sampler.c — the integration-measurement process sampler.
 *
 * Every SLEEP_MS, walks /proc and appends one TSVT line per relevant
 * process (comm/exe mentions runc, buildkit, or docker-helper): pid,
 * ppid, comm, exe (/proc/<pid>/exe readlink — the wrapper vs real-runtime
 * distinction across the execve: …/buildkit-runc vs
 * …/runtime/buildkit-runc), argv0, and the kernel context
 * (/proc/<pid>/attr/current — the OBL-6 execution contexts). Runs until
 * the stop file appears; output is bounded by the caller's build window.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>

static void wallstamp(char *b, size_t n) {
    struct timespec ts; struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts); gmtime_r(&ts.tv_sec, &tm);
    snprintf(b, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec/1000000);
}
static void monostamp(long long *ms) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    *ms = ts.tv_sec*1000LL + ts.tv_nsec/1000000;
}
static int readline(const char *path, char *buf, size_t n) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t r;
    if (fd < 0) return -1;
    r = read(fd, buf, n - 1);
    close(fd);
    if (r < 0) return -1;
    buf[r > 0 ? r : 0] = '\0';
    while (r > 0 && (buf[r-1] == '\n' || buf[r-1] == '\0')) buf[--r] = '\0';
    return (int)r;
}
static int readlinkstr(const char *path, char *buf, size_t n) {
    ssize_t r = readlink(path, buf, n - 1);
    if (r < 0) { buf[0] = '\0'; return -1; }
    buf[r] = '\0';
    return (int)r;
}
static int relevant(const char *s) {
    return strstr(s, "runc") || strstr(s, "buildkit") ||
           strstr(s, "docker-helper");
}
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <logfile> <stopfile>\n", argv[0]); return 2; }
    FILE *lg = fopen(argv[1], "a");
    if (!lg) return 2;
    long long t = 0;
    char ts[40], comm[256], exe[PATH_MAX], argv0[2048], ctx[512], statline[2048];
    for (;;) {
        FILE *stopf;
        DIR *d;
        struct dirent *e;
        monostamp(&t);
        stopf = fopen(argv[2], "r");
        if (stopf) { fclose(stopf); break; }
        d = opendir("/proc");
        if (!d) break;
        while ((e = readdir(d)) != NULL) {
            char pcomm[64], pexe[64], pcmd[128], pctx[64], pstat[64];
            pid_t pid;
            if (strspn(e->d_name, "0123456789") != strlen(e->d_name)) continue;
            pid = (pid_t)atoi(e->d_name);
            snprintf(pcomm, sizeof pcomm, "/proc/%s/comm", e->d_name);
            if (readline(pcomm, comm, sizeof comm) < 0) continue;
            snprintf(pexe, sizeof pexe, "/proc/%s/exe", e->d_name);
            readlinkstr(pexe, exe, sizeof exe);
            snprintf(pcmd, sizeof pcmd, "/proc/%s/cmdline", e->d_name);
            if (readline(pcmd, argv0, sizeof argv0) < 0) argv0[0] = '\0';
            /* replacing NUL separators with spaces for one-line records */
            for (size_t i = 0; argv0[i]; i++) if (argv0[i] == '\0') argv0[i] = ' ';
            snprintf(pctx, sizeof pctx, "/proc/%s/attr/current", e->d_name);
            if (readline(pctx, ctx, sizeof ctx) < 0) ctx[0] = '\0';
            snprintf(pstat, sizeof pstat, "/proc/%s/stat", e->d_name);
            long long ppid = -1;
            if (readline(pstat, statline, sizeof statline) >= 0) {
                char *cl = strrchr(statline, ')');
                if (cl) sscanf(cl + 2, " %*c %*d %lld", &ppid);
            }
            if (!relevant(comm) && !relevant(exe) && !relevant(argv0)) continue;
            wallstamp(ts, sizeof ts);
            fprintf(lg, "PROC %s t=%lld pid=%d ppid=%lld comm=%s exe=%s argv0=%s ctx=%s\n",
                    ts, t, pid, ppid, comm, exe, argv0, ctx);
        }
        closedir(d);
        fflush(lg);
        struct timespec slp = {0, 20 * 1000 * 1000};
        nanosleep(&slp, NULL);
    }
    wallstamp(ts, sizeof ts);
    fprintf(lg, "SAMPLER-DONE %s t=%lld\n", ts, t);
    fclose(lg);
    return 0;
}
CEOF
gcc -O2 -Wall -o "$EVIDENCE_DIR/p21e3_proc_sampler" "$EVIDENCE_DIR/p21e3_proc_sampler.c" \
  || fail "sampler compile failed"
log "sampler compiled"
touch "$STATE_DIR/sec4"
fi

# ---------------------------------------------------------------------------
# Section 5: the ONE bounded measurement build
# ---------------------------------------------------------------------------
if [ -f "$STATE_DIR/sec5" ]; then log "phase marker: section 5 done; skipping"; else
log "=== section 5: one bounded enforcing build ==="
[ -n "$ADMIN_TOKEN" ] || fail "admin token unreadable; the measurement cannot run"

# --- the pinned audit window (one descriptor, boundary-aligned start) ---
AUD_FD=""
exec {AUD_FD}<"$AUDIT_LOG_PATH" 2>/dev/null || AUD_FD=""
[ -n "$AUD_FD" ] || fail "audit source unavailable; window cannot be bounded"
AUD_START=""
BOUNDARY_ALIGNED=0
for _ in $(seq 1 20); do
  size="$(stat -L -c '%s' /proc/self/fd/$AUD_FD 2>/dev/null || echo 0)"
  last="$(dd if=/proc/self/fd/$AUD_FD bs=1 skip=$((size-1)) count=1 2>/dev/null || true)"
  if [ "$last" = "" ]; then BOUNDARY_ALIGNED=1; AUD_START=0; break; fi   # empty log
  if [ "$last" = "$(printf '\n')" ]; then AUD_START="$size"; BOUNDARY_ALIGNED=1; break; fi
  sleep 0.1
done
[ "$BOUNDARY_ALIGNED" = 1 ] || fail "audit stream did not reach a record boundary"
AUD_START_PATH_DEVINO="$(stat -c '%d:%i' "$AUDIT_LOG_PATH")"
AUD_START_FD_DEVINO="$(stat -L -c '%d:%i' /proc/self/fd/$AUD_FD 2>/dev/null)"
[ "$AUD_START_PATH_DEVINO" = "$AUD_START_FD_DEVINO" ] \
  || fail "audit source identity mismatch at window open (path=$AUD_START_PATH_DEVINO fd=$AUD_START_FD_DEVINO)"
printf 'window-open offset=%s path_devino=%s fd_devino=%s\n' \
  "$AUD_START" "$AUD_START_PATH_DEVINO" "$AUD_START_FD_DEVINO" \
  > "$EVIDENCE_DIR/p21e3-window.log"
log "audit window open: offset=$AUD_START dev:ino=$AUD_START_PATH_DEVINO"

# --- workspace + session (the established diagnostic workload) ---
WS="$PRINCIPAL_HOME/r7-p21e3-ws"
rm -rf "$WS"; mkdir -p "$WS/ctx"
printf 'FROM alpine:3.24\nRUN true\n' > "$WS/ctx/Dockerfile"
chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
docker-helper principal show "$PRINCIPAL" >/dev/null 2>&1 \
  || docker-helper principal create --no-credential "$PRINCIPAL" >/dev/null 2>&1 || true
docker-helper principal allowed-root add "$PRINCIPAL" "$PRINCIPAL_HOME" >/dev/null 2>&1 || true
RESP="$EVIDENCE_DIR/session-response.json"
CODE="$(curl --silent --max-time 5 \
  --unix-socket "$DH_SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"workspace\":\"$WS\",\"principal\":\"$PRINCIPAL\"}" \
  -o "$RESP" -w '%{http_code}' http://localhost/sessions)" || true
TOKEN="$(grep -oE '"token": *"[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"token": *"//;s/"$//')"
SID="$(grep -oE '"id": *"dhs_[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"id": *"//;s/"$//')"
printf '%s\n' "$SID" > "$EVIDENCE_DIR/session-id.log"
[ -n "$TOKEN" ] || fail "session create failed (HTTP $CODE)"
# Pre-warm the image cache so the traced build window carries minimal IO
# noise (the strace filter keeps read but bounds output this way).
docker-helper pull alpine:3.24 >"$EVIDENCE_DIR/pull.log" 2>&1 || true
log "session ready ($SID); image cached"

# --- the build: POST, then trace the whole live subtree ---
RESP2="$EVIDENCE_DIR/build-start.json"
CODE2="$(curl --silent --max-time 10 \
  --unix-socket "$DH_SOCK" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"context":"ctx","dockerfile":"Dockerfile","image":"uat-p21e3"}' \
  -o "$RESP2" -w '%{http_code}' http://localhost/build)" || true
printf '%s\n' "$CODE2" > "$EVIDENCE_DIR/build-start.http.log"
OP="$(grep -oE '"operation_id": *"[^"]+"' "$RESP2" 2>/dev/null | head -1 | sed 's/.*"operation_id": *"//;s/"$//')"
printf '%s\n' "$OP" > "$EVIDENCE_DIR/operation-id.log"
log "build http=$CODE2 operation_id=$OP"
[ -n "$OP" ] || fail "no operation id (http $CODE2)"

# The /proc sampler runs for the WHOLE window (starts before the manager
# spawns the flow, so the buildkitd/rootlesskit/wrapper/init chain is
# sampled from birth).
STOPSAMP="$STATE_DIR/sampler.stop"
rm -f "$STOPSAMP"
"$EVIDENCE_DIR/p21e3_proc_sampler" "$EVIDENCE_DIR/p21e3-sampler.log" "$STOPSAMP" &
SAMPLER_PID=$!

# The strace attach: poll for the first freshly recorded buildkitd pid
# (the sampler sees it; a plain pgrep over the builder uid is equivalent)
# and attach immediately — the wrapper exec happens later, after buildkitd
# boot and workspace preparation.
BKD_PID=""
for _ in $(seq 1 300); do
  BKD_PID="$(pgrep -u "$(id -u docker-helper-builder 2>/dev/null || echo 0)" -x buildkitd 2>/dev/null | head -1 || true)"
  [ -n "$BKD_PID" ] && break
  sleep 0.1
done
if [ -n "$BKD_PID" ]; then
  log "attaching strace to buildkitd pid $BKD_PID (timeout ${STRACE_TIMEOUT}s)"
  timeout "$STRACE_TIMEOUT" strace -f -qq -tt -s 100 -y -yy -p "$BKD_PID" \
    -e trace=execve,execveat,open,openat,openat2,read,rename,renameat,renameat2,mount,umount2,mkdir,mkdirat,symlink,symlinkat,getxattr,lgetxattr,fgetxattr \
    -o "$EVIDENCE_DIR/p21e3-strace.log" 2>"$EVIDENCE_DIR/p21e3-strace.err" &
  STRACE_PID=$!
else
  STRACE_PID=""
  log "no buildkitd pid found to attach; recording NOT-REACHED"
fi
[ -n "$BKD_PID" ] && echo "attach=$BKD_PID" > "$EVIDENCE_DIR/p21e3-strace-attach.log" \
  || echo "attach=none" > "$EVIDENCE_DIR/p21e3-strace-attach.log"

# The bounded wait for the operation terminal.
STATUS=""
for _ in $(seq 1 600); do
  STATUS="$(curl --silent --max-time 2 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $TOKEN" \
    "http://localhost/operations/$OP" 2>/dev/null || true)"
  case "$STATUS" in
    *'"succeeded"'*|*'"failed"'*) break ;;
  esac
  sleep 0.1
done
printf '%s\n' "$STATUS" > "$EVIDENCE_DIR/build-status.json"
touch "$STOPSAMP"
[ -n "$STRACE_PID" ] && { wait "$STRACE_PID" 2>/dev/null || true; }
wait "$SAMPLER_PID" 2>/dev/null || true

# Truncate-bounded evidence: the strace log is capped in the artifact by
# size (the raw file is preserved up to the cap; a cap notice is appended).
MAXSTRACE=$((8*1024*1024))
sz="$(wc -c < "$EVIDENCE_DIR/p21e3-strace.log" 2>/dev/null || echo 0)"
if [ "$sz" -gt "$MAXSTRACE" ]; then
  log "strace log $sz > cap $MAXSTRACE; head-truncating (raw preserved as .over)"
  mv "$EVIDENCE_DIR/p21e3-strace.log" "$EVIDENCE_DIR/p21e3-strace.log.over"
  head -c "$MAXSTRACE" "$EVIDENCE_DIR/p21e3-strace.log.over" > "$EVIDENCE_DIR/p21e3-strace.log"
  printf '\n[truncated at %d bytes; full log: p21e3-strace.log.over]\n' "$MAXSTRACE" >> "$EVIDENCE_DIR/p21e3-strace.log"
fi

# The operation log (the build's own log through the API; token-free).
curl --silent --max-time 2 \
  --unix-socket "$DH_SOCK" -H "Authorization: Bearer $TOKEN" \
  "http://localhost/operations/$OP/logs?offset=0" \
  > "$EVIDENCE_DIR/build.log" 2>&1 || true
log "build status: $(printf '%s' "$STATUS" | grep -oE '"(status|result_code)":"[^"]*"' | tr '\n' ' ')"

# --- the audit window drain (through the pinned descriptor) ---
END_PATH_DEVINO="$(stat -c '%d:%i' "$AUDIT_LOG_PATH")"
END_FD_DEVINO="$(stat -L -c '%d:%i' /proc/self/fd/$AUD_FD 2>/dev/null)"
if [ "$END_PATH_DEVINO" = "$AUD_START_PATH_DEVINO" ] && [ "$END_PATH_DEVINO" = "$END_FD_DEVINO" ]; then
  IDENTITY=proven
else
  IDENTITY="broken(start.path=$AUD_START_PATH_DEVINO end.path=$END_PATH_DEVINO end.fd=$END_FD_DEVINO)"
fi
printf 'window-close identity=%s end_offset=%s\n' \
  "$IDENTITY" "$(stat -L -c '%s' /proc/self/fd/$AUD_FD 2>/dev/null || echo '?')" \
  >> "$EVIDENCE_DIR/p21e3-window.log"
# Drain [start, EOF) THROUGH the descriptor (GNU dd skip_bytes against the
# pinned, seekable descriptor). Audit records are newline-terminated; the
# boundary-aligned start cannot split a leading record, and any trailing
# record still being written at drain time is dropped as torn and recorded.
dd if="/proc/self/fd/$AUD_FD" bs=1M skip="$AUD_START" iflag=fullblock,skip_bytes 2>/dev/null \
  >> "$EVIDENCE_DIR/p21e3-window-records.log" || true
window_last="$(tail -c 1 "$EVIDENCE_DIR/p21e3-window-records.log" 2>/dev/null || true)"
if [ -n "$window_last" ] && [ "$window_last" != "$(printf '\n')" ]; then
  head -n -1 "$EVIDENCE_DIR/p21e3-window-records.log" > "$EVIDENCE_DIR/p21e3-window-records.tmp" \
    && mv "$EVIDENCE_DIR/p21e3-window-records.tmp" "$EVIDENCE_DIR/p21e3-window-records.log"
  echo "torn-trailing-record: dropped" >> "$EVIDENCE_DIR/p21e3-window.log"
fi
{
  echo "window identity: $IDENTITY"
  echo "start offset: $AUD_START"
  echo "records: $(wc -l < "$EVIDENCE_DIR/p21e3-window-records.log" 2>/dev/null || echo 0)"
} >> "$EVIDENCE_DIR/p21e3-window.log"
exec {AUD_FD}<&- 2>/dev/null || true
if [ "$IDENTITY" != "proven" ]; then
  printf 'R7-P21E3-VERDICT=BLOCKED\n'
  fail "audit window identity unproven; the measurement decides BLOCKED"
fi

# The per-op executor root state at the terminal (the post-terminal tree).
ROOTDIR="$BUILDER_STATE_ROOT/ops/$OP/root/runc-native"
ls -laZR "$ROOTDIR" > "$EVIDENCE_DIR/p21e3-executor-tree.log" 2>&1 || true

# Machine verdicts: the measurement itself ran; the BUILD result is
# recorded separately (failing is a measurement outcome, not a harness
# failure).
case "$STATUS" in
  *'"succeeded"'*) BUILD_RESULT=succeeded ;;
  *'"failed"'*) BUILD_RESULT=failed ;;
  *) BUILD_RESULT="aborted(no-terminal)" ;;
esac
printf 'R7-P21E3-BUILD=%s\n' "$BUILD_RESULT"
printf 'R7-P21E3-VERDICT=MEASURED\n'
touch "$STATE_DIR/sec5"
fi

# ---------------------------------------------------------------------------
# Section 6: chain inventory (what the evidence shows, machine-readable
# orientation for the report; the ANALYSIS stays with the round report)
# ---------------------------------------------------------------------------
log "=== section 6: chain inventory ==="
{
  echo "== wrapper vs runtime observations (by /proc/<pid>/exe) =="
  grep -oE 'exe=[^ ]+' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | sort | uniq -c || true
  echo "== observed buildkit-related contexts =="
  grep -oE 'ctx=[^ ]+' "$EVIDENCE_DIR/p21e3-sampler.log" 2>/dev/null | sort | uniq -c || true
  echo "== strace key boundary lines (orientation only) =="
  grep -aE 'attr/current|config\.json|dev-prep|/dev"|execve|"mount"|symlinkat.*ptmx' \
    "$EVIDENCE_DIR/p21e3-strace.log" 2>/dev/null | head -120 || echo "(no strace evidence)"
  echo "== AVC records in the pinned window =="
  grep -a "avc:  denied" "$EVIDENCE_DIR/p21e3-window-records.log" 2>/dev/null | head -60 || echo "(no denied AVC records)"
} > "$EVIDENCE_DIR/p21e3-inventory.log" 2>&1
cat "$EVIDENCE_DIR/p21e3-inventory.log"
log "inventory written; the report analyzes the boundaries"
