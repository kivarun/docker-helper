#!/usr/bin/env bash
#
# release-2.4-r7-p21e-guest.sh — the R7 P21-E OBL-8 live capture: one genuine
# BuildKit-generated bundle config.json from the CURRENT pre-integration
# runtime path, on a disposable ENFORCING openSUSE Tumbleweed VM (candidate
# RPM; no wrapper, no policy change, no production change).
#
# MODE: evidence-only capture. The specimen is preserved byte-exact into the
# evidence directory and NEVER printed to the console (the OCI spec carries
# the container's full process section); the console and the report carry
# only paths, sizes, SHA-256 digests and the extracted MOUNT list.
#
# THE VERIFIED PRODUCER LIFECYCLE (pinned buildkit v0.33.0,
# worker/runcexecutor/executor.go, local pinned copy /tmp/opencode/bkp21/
# executor.go — line refs from that copy):
#   L259-262  bundle := <root>/<id>; os.Mkdir(bundle, 0o711)
#   L264      defer os.RemoveAll(bundle)            <- bundle removal at
#                                                    Run RETURN
#   L294      f := os.Create(bundle/config.json); defer f.Close()
#                                                    <- close fires at Run
#                                                    RETURN, BEFORE the
#                                                    RemoveAll (LIFO: the
#                                                    later-registered
#                                                    f.Close runs first)
#   L334      spec generated (oci.GenerateSpec)
#   L363      json.NewEncoder(f).Encode(spec)       <- THE generation point:
#                                                    one Encoder.Encode
#                                                    write of the complete
#                                                    document + '\n'
#   L375      w.run(...)                            <- runc consumes the
#                                                    spec; the run lasts
#                                                    until the step ends
#
# The exact generation interval is therefore [Encode, Run return), and
# IN_CLOSE_WRITE fires only at the FAR END of that interval (immediately
# before the bundle removal) — it must NOT be the sole trigger. The poller
# therefore captures on IN_MODIFY (the Encode write itself, which for one
# Encoder.Encode is one write of the whole buffer), recaptures on
# IN_CLOSE_WRITE (final bytes), and backs both with a bounded sweep that
# recaptures whenever the observed size changes while the bundle still
# exists. Every capture is read-only (O_RDONLY|O_NOFOLLOW); the production
# spec is never edited, renamed, replaced or delayed by mutation. The last
# capture per bundle is the specimen the host-side validator judges.
#
# Machine verdict contract (no separate gate evaluator; the VM script gates
# inline): R7-P21E-VERDICT=CAPTURED=<n> with n>=1 required; the host-side
# validator additionally requires every specimen to be one complete JSON
# object with no trailing data (the producer's terminal '\n' allowed).
# An incomplete, truncated or unproven capture fails the gate — it is never
# reported as success.

set -uo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log()  { printf '[r7-p21e] %s\n' "$*"; }
fail() { printf '[r7-p21e] FAILED: %s\n' "$*" >&2; exit 1; }

ARTIFACT="${R7_ARTIFACT:?R7_ARTIFACT required}"
ARTIFACT_SHA="${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"
EVIDENCE_DIR="${R7_EVIDENCE_DIR:-/tmp/r7-p21e-evidence}"
STATE_DIR=/tmp/r7-p21e-state
mkdir -p "$EVIDENCE_DIR" "$STATE_DIR"
DH_SOCK=/run/docker-helper/docker-helper.sock

BUILDER_STATE_ROOT=/var/lib/docker-helper-builder
# Bounded capture: at most three sequential build cycles, a per-poller
# specimen ceiling, and a fixed poller deadline — no endless polling.
BUILD_CYCLES=3
SPECIMEN_CEILING=4
POLLER_DEADLINE=150

cap() { # <name> <max-lines> <cmd...>
  local name="$1" maxn="$2" rc; shift 2
  "$@" >"$EVIDENCE_DIR/$name.log" 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || printf 'capture rc=%d\n' "$rc" >>"$EVIDENCE_DIR/$name.log"
  log "--- $name (evidence: $EVIDENCE_DIR/$name.log, first $maxn lines) ---"
  head -n "$maxn" "$EVIDENCE_DIR/$name.log"
  return 0
}

# ============================================================================
# Section 1: platform + SELinux enforcing proof
# ============================================================================
if [ -f "$STATE_DIR/sec1" ]; then log "phase marker: section 1 done; skipping"; else
log "=== section 1: platform + SELinux state ==="
ENF="$(getenforce 2>/dev/null || echo absent)"
[ "$ENF" = "Enforcing" ] || fail "SELinux not enforcing (getenforce='$ENF')"
cat /sys/kernel/security/lsm >"$EVIDENCE_DIR/lsm.txt" 2>&1 || true
grep -qw selinux "$EVIDENCE_DIR/lsm.txt" || fail "selinux not an active LSM"
cap p21e-se-status 8 bash -c 'sestatus; echo ---; getenforce; id -Z'
cat /etc/os-release >"$EVIDENCE_DIR/os-release.txt" 2>&1
grep -qi 'opensuse tumbleweed' "$EVIDENCE_DIR/os-release.txt" || fail "not openSUSE Tumbleweed"
cap p21e-platform 4 bash -c 'uname -a'
touch "$STATE_DIR/sec1"
fi

# ============================================================================
# Section 2: exact candidate install (never rebuilds)
# ============================================================================
if [ -f "$STATE_DIR/sec2" ]; then log "phase marker: section 2 done; skipping"; else
log "=== section 2: candidate install (rpm) ==="
[ -f "$ARTIFACT" ] || fail "artifact missing: $ARTIFACT"
now_sha="$(sha256sum "$ARTIFACT" | awk '{print $1}')"
[ "$now_sha" = "$ARTIFACT_SHA" ] || fail "artifact SHA mismatch (expected $ARTIFACT_SHA, got $now_sha)"
rpm -q docker-helper >/dev/null 2>&1 && rpm -e docker-helper >/dev/null 2>&1 || true
rpm -i "$ARTIFACT" || fail "rpm -i failed"
log "RPM installed: $(rpm -q docker-helper)"
sha256sum "$ARTIFACT" > "$EVIDENCE_DIR/candidate-rpm-sha256.log"
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
log "daemon ready on $DH_SOCK"
touch "$STATE_DIR/sec2"
fi

PRINCIPAL="${SUDO_USER:-}"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"

# ============================================================================
# Section 3: toolchain + the pinned-payload provenance
# ============================================================================
if [ -f "$STATE_DIR/sec3" ]; then log "phase marker: section 3 done; skipping"; else
log "=== section 3: toolchain + payload provenance ==="
if ! command -v gcc >/dev/null 2>&1; then
  cap p21e-toolchain 6 timeout 300 zypper --non-interactive install -y gcc
fi
command -v gcc >/dev/null 2>&1 || fail "gcc unavailable"
# The pinned BuildKit payload provenance: the shipped MANIFEST (version +
# verified digests) and the staged payload binaries' actual digests — the
# specimen's producer identity.
cap p21e-payload-manifest 12 cat /usr/share/doc/docker-helper/buildkit/MANIFEST
{
  echo "== staged payload digests vs the shipped MANIFEST =="
  for member in buildkitd buildctl buildkit-runc; do
    want="$(sed -n "s/^${member}-sha256=//p" /usr/share/doc/docker-helper/buildkit/MANIFEST)"
    got="$(sha256sum "/usr/libexec/docker-helper/buildkit/$member" | awk '{print $1}')"
    if [ -n "$want" ] && [ "$want" = "$got" ]; then
      echo "$member: MATCH $got"
    else
      echo "$member: MISMATCH manifest=$want staged=$got"
    fi
  done
} > "$EVIDENCE_DIR/p21e-payload-digests.log" 2>&1
cat "$EVIDENCE_DIR/p21e-payload-digests.log"
touch "$STATE_DIR/sec3"
fi

# ============================================================================
# Section 4: the read-only inotify specimen poller
# ============================================================================
if [ ! -x "$EVIDENCE_DIR/p21e_spec_poller" ]; then
log "=== section 4: specimen poller build ==="
cat > "$EVIDENCE_DIR/p21e_spec_poller.c" <<'CEOF'
/* p21e_spec_poller.c — the OBL-8 read-only specimen poller.
 *
 * Watches one buildkitd executor root (…/ops/<op>/root/runc-native/
 * executor) with inotify and copies every bundle's config.json into the
 * evidence directory, byte-exact and WITHOUT ever opening the production
 * file for writing, renaming, or replacing it. Triggers: IN_MODIFY (the
 * pinned producer's single Encode write — the generation point),
 * IN_CLOSE_WRITE (the deferred close immediately before the bundle
 * removal), and a bounded sweep fallback that recaptures whenever the
 * observed size changes while the bundle still exists (covers the
 * nonrecursive-watch add race when a bundle directory appears between the
 * root watch registration and its first events). Every action is bounded:
 * fixed bundle/capture/specimen ceilings and a hard wall-clock deadline.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define EVBUF (64 * 1024)
#define MAXBUNDLES 32
#define MAXREAD (1u << 20)   /* capture ceiling: 1 MiB */
#define MAXCAPTURES 64

static const char *root_dir, *out_dir, *stop_file;
static long max_specimens;
static long long deadline_ms;
static FILE *lg;
static long total_captures, total_specimens;
static int capture_enabled = 1;

struct bundle {
    char id[NAME_MAX + 1];
    int wd;             /* inotify watch descriptor; -1 unwatched */
    long captured_size; /* -1 = never captured */
    int removed_logged;
};
static struct bundle bundles[MAXBUNDLES];
static int nbundles;

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}
static void wallstamp(char *buf, size_t n) {
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tm);
    snprintf(buf, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);
}
static void logline(const char *fmt, ...) {
    char ts[40];
    va_list ap;
    wallstamp(ts, sizeof ts);
    fprintf(lg, "%s ", ts);
    va_start(ap, fmt);
    vfprintf(lg, fmt, ap);
    va_end(ap);
    fputc('\n', lg);
    fflush(lg);
}

static struct bundle *find_bundle(const char *id) {
    for (int i = 0; i < nbundles; i++)
        if (strcmp(bundles[i].id, id) == 0) return &bundles[i];
    return NULL;
}
static struct bundle *add_bundle(const char *id) {
    struct bundle *b = find_bundle(id);
    if (b) return b;
    if (nbundles >= MAXBUNDLES) return NULL;
    b = &bundles[nbundles++];
    snprintf(b->id, sizeof b->id, "%s", id);
    b->wd = -1;
    b->captured_size = -1;
    b->removed_logged = 0;
    return b;
}

static void capture(struct bundle *b, const char *reason) {
    char path[PATH_MAX], out[PATH_MAX];
    if (!capture_enabled || !b) return;
    snprintf(path, sizeof path, "%s/%s/config.json", root_dir, b->id);
    snprintf(out, sizeof out, "%s/spec-%s.json", out_dir, b->id);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        logline("READ-FAIL %s bundle=%s errno=%d", reason, b->id, errno);
        return;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        logline("NOT-REGULAR %s bundle=%s errno=%d", reason, b->id, errno);
        close(fd);
        return;
    }
    if (st.st_size == 0) {
        close(fd);
        return; /* created, not yet encoded: retry on a later trigger */
    }
    if (st.st_size > (off_t)MAXREAD) {
        close(fd);
        logline("TOO-BIG %s bundle=%s size=%lld", reason, b->id, (long long)st.st_size);
        return;
    }
    static char buf[MAXREAD];
    ssize_t got = 0, n = 0;
    while (got < st.st_size) {
        n = read(fd, buf + got, (size_t)(st.st_size - got));
        if (n <= 0) break;
        got += n;
    }
    int rderrno = (n < 0) ? errno : 0;
    close(fd);
    if (got != st.st_size) {
        logline("SHORT-READ %s bundle=%s got=%zd want=%lld errno=%d",
                reason, b->id, got, (long long)st.st_size, rderrno);
        return;
    }
    int ofd = open(out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (ofd < 0) {
        logline("OUT-FAIL %s bundle=%s errno=%d", reason, b->id, errno);
        return;
    }
    ssize_t off = 0;
    while (off < got) {
        ssize_t w = write(ofd, buf + off, (size_t)(got - off));
        if (w < 0) { off = -1; break; }
        off += w;
    }
    int werrno = errno;
    if (off != got || close(ofd) < 0) {
        logline("OUT-WRITE-FAIL %s bundle=%s wrote=%zd errno=%d", reason, b->id, off, werrno);
        return;
    }
    char ts[40];
    wallstamp(ts, sizeof ts);
    logline("CAPTURE %s bundle=%s bytes=%zd t_mono=%lld t_wall=%s",
            reason, b->id, got, now_ms(), ts);
    total_captures++;
    if (b->captured_size != (long)st.st_size) {
        b->captured_size = (long)st.st_size;
        total_specimens++;
        if (total_specimens >= max_specimens) {
            capture_enabled = 0;
            logline("SPECIMEN-CEILING-REACHED %ld", max_specimens);
        }
    }
    if (total_captures >= MAXCAPTURES) {
        capture_enabled = 0;
        logline("CAPTURE-CEILING-REACHED %d", MAXCAPTURES);
    }
}

static void watch_bundle(int ifd, struct bundle *b) {
    if (!b || b->wd >= 0) return;
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", root_dir, b->id);
    int wd = inotify_add_watch(ifd, path, IN_MODIFY | IN_CLOSE_WRITE);
    if (wd < 0) {
        b->wd = -1;
        if (errno != ENOENT)
            logline("BUNDLE-WATCH-FAIL bundle=%s errno=%d", b->id, errno);
        return; /* ENOENT: the sweep handles short-lived bundles */
    }
    b->wd = wd;
    logline("BUNDLE-WATCHED bundle=%s", b->id);
    /* The bundle may have been created and encoded between the root event
     * and this watch registration: capture immediately (the sweep and the
     * event stream recapture if this read raced the Encode). */
    capture(b, "watch-adopt");
}

static void sweep(int ifd) {
    char p[PATH_MAX];
    DIR *d = opendir(root_dir);
    if (!d) return; /* root not present yet (or vanished) */
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        snprintf(p, sizeof p, "%s/%s", root_dir, e->d_name);
        struct stat st;
        if (stat(p, &st) < 0 || !S_ISDIR(st.st_mode)) continue;
        struct bundle *b = add_bundle(e->d_name);
        if (!b) continue;
        if (b->wd < 0) {
            watch_bundle(ifd, b);
        } else {
            /* recapture when the observed content grew (partial read) */
            char c[PATH_MAX];
            snprintf(c, sizeof c, "%s/config.json", p);
            struct stat cs;
            if (stat(c, &cs) == 0 && S_ISREG(cs.st_mode) &&
                (long)cs.st_size != b->captured_size)
                capture(b, "sweep-size-change");
        }
    }
    closedir(d);
    /* bundle-removal markers: a tracked bundle whose directory is gone */
    for (int i = 0; i < nbundles; i++) {
        struct bundle *b = &bundles[i];
        if (b->removed_logged) continue;
        snprintf(p, sizeof p, "%s/%s", root_dir, b->id);
        struct stat st;
        if (stat(p, &st) < 0 && errno == ENOENT) {
            char ts[40];
            wallstamp(ts, sizeof ts);
            logline("REMOVED bundle=%s t_mono=%lld t_wall=%s", b->id, now_ms(), ts);
            b->removed_logged = 1;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr, "usage: %s <executor-root> <outdir> <stopfile> "
                        "<max-specimens> <deadline-s> <logfile>\n", argv[0]);
        return 2;
    }
    root_dir = argv[1];
    out_dir = argv[2];
    stop_file = argv[3];
    max_specimens = strtol(argv[4], NULL, 10);
    long long deadline_s = strtoll(argv[5], NULL, 10);
    lg = fopen(argv[6], "a");
    if (!lg) return 2;
    deadline_ms = now_ms() + deadline_s * 1000LL;

    int ifd = inotify_init1(IN_CLOEXEC);
    if (ifd < 0) {
        logline("INOTIFY-INIT-FAIL errno=%d", errno);
        return 1;
    }
    int root_wd = -1;
    static char evbuf[EVBUF];
    long long last_sweep = 0;

    for (;;) {
        long long now = now_ms();
        if (now >= deadline_ms) { logline("DEADLINE"); break; }
        if (access(stop_file, F_OK) == 0) { logline("STOP-FILE"); break; }

        if (root_wd < 0) {
            struct stat st;
            if (stat(root_dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
                struct pollfd p = { .fd = -1, .events = 0, .revents = 0 };
                poll(&p, 1, 50);
                continue;
            }
            root_wd = inotify_add_watch(ifd, root_dir, IN_CREATE | IN_MOVED_TO);
            if (root_wd < 0) {
                if (errno != ENOENT)
                    logline("ROOT-WATCH-FAIL errno=%d", errno);
                struct pollfd p = { .fd = -1, .events = 0, .revents = 0 };
                poll(&p, 1, 50);
                continue;
            }
            logline("ROOT-WATCHED %s", root_dir);
            sweep(ifd);
            last_sweep = now;
        }

        long long next_sweep = last_sweep + 200;
        int timeout = (next_sweep <= now) ? 0 : (int)(next_sweep - now);
        struct pollfd pfd = { .fd = ifd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, timeout);
        now = now_ms();
        if (now >= deadline_ms) { logline("DEADLINE"); break; }
        if (access(stop_file, F_OK) == 0) { logline("STOP-FILE"); break; }

        if (pr > 0 && (pfd.revents & POLLIN)) {
            ssize_t len = read(ifd, evbuf, sizeof evbuf);
            if (len <= 0) {
                if (len < 0 && errno != EINTR)
                    logline("INOTIFY-READ-FAIL errno=%d", errno);
            } else {
                char *p = evbuf;
                while (p < evbuf + len) {
                    struct inotify_event *ev = (struct inotify_event *)p;
                    if (ev->wd == root_wd) {
                        if ((ev->mask & (IN_CREATE | IN_MOVED_TO)) &&
                            (ev->mask & IN_ISDIR) && ev->len) {
                            struct bundle *b = add_bundle(ev->name);
                            watch_bundle(ifd, b);
                        }
                    } else if (ev->mask & IN_IGNORED) {
                        for (int i = 0; i < nbundles; i++)
                            if (bundles[i].wd == ev->wd) bundles[i].wd = -1;
                    } else if (ev->mask & (IN_MODIFY | IN_CLOSE_WRITE)) {
                        struct bundle *b = NULL;
                        for (int i = 0; i < nbundles; i++)
                            if (bundles[i].wd == ev->wd) { b = &bundles[i]; break; }
                        if (b && ev->len && strcmp(ev->name, "config.json") == 0) {
                            if (ev->mask & IN_CLOSE_WRITE)
                                logline("CLOSE-MARKER bundle=%s t_mono=%lld",
                                        b->id, now_ms());
                            capture(b, (ev->mask & IN_CLOSE_WRITE) ? "close-write"
                                                                   : "modify");
                        }
                    }
                    p += sizeof(struct inotify_event) + ev->len;
                }
            }
        }
        if (now - last_sweep >= 200) {
            sweep(ifd);
            last_sweep = now;
        }
    }
    logline("SUMMARY specimens=%ld captures=%ld bundles=%d", total_specimens,
            total_captures, nbundles);
    fclose(lg);
    return 0;
}
CEOF
log "poller source written: $EVIDENCE_DIR/p21e_spec_poller.c"
gcc -O2 -Wall -o "$EVIDENCE_DIR/p21e_spec_poller" "$EVIDENCE_DIR/p21e_spec_poller.c" \
  || fail "poller compile failed"
log "poller compiled: $EVIDENCE_DIR/p21e_spec_poller"
fi

# ============================================================================
# Section 5: the bounded capture cycles (three sequential builds)
# ============================================================================
if [ -f "$STATE_DIR/sec5" ]; then log "phase marker: section 5 done; skipping"; else
log "=== section 5: bounded capture cycles ==="
[ -n "$ADMIN_TOKEN" ] || fail "admin token unreadable; the live capture cannot run"

make_session() { # <tag> — workspace + principal + session + pull; sets
  # SESSION_TOKEN for the caller; the token is NEVER written to evidence.
  local tag="$1"
  local WS="$PRINCIPAL_HOME/r7-p21e-ws-$tag"
  rm -rf "$WS"; mkdir -p "$WS/ctx"
  printf 'FROM alpine:3.24\nRUN true\n' > "$WS/ctx/Dockerfile"
  chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
  docker-helper principal show "$PRINCIPAL" >/dev/null 2>&1 \
    || docker-helper principal create --no-credential "$PRINCIPAL" >/dev/null 2>&1 || true
  docker-helper principal allowed-root add "$PRINCIPAL" "$PRINCIPAL_HOME" >/dev/null 2>&1 || true
  local RESP="$EVIDENCE_DIR/session-response-$tag.json"
  local CODE
  CODE="$(curl --silent --max-time 5 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"workspace\":\"$WS\",\"principal\":\"$PRINCIPAL\"}" \
    -o "$RESP" -w '%{http_code}' http://localhost/sessions)" || true
  local TOKEN SID
  TOKEN="$(grep -oE '"token": *"[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"token": *"//;s/"$//')"
  SID="$(grep -oE '"id": *"dhs_[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"id": *"//;s/"$//')"
  printf '%s\n' "$SID" > "$EVIDENCE_DIR/session-id-$tag.log"
  SESSION_TOKEN="$TOKEN"
  if [ -z "$TOKEN" ]; then
    log "session create failed for $tag (HTTP $CODE); skipping this cycle"
    return 1
  fi
  docker-helper pull alpine:3.24 >"$EVIDENCE_DIR/pull-$tag.log" 2>&1 || true
  return 0
}

capture_cycle() { # <tag>
  local tag="$1"
  make_session "$tag" || return 1
  local RESP="$EVIDENCE_DIR/build-start-$tag.json"
  local CODE
  CODE="$(curl --silent --max-time 10 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $SESSION_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"context":"ctx","dockerfile":"Dockerfile","image":"uat-p21e:'"$tag"'"}' \
    -o "$RESP" -w '%{http_code}' http://localhost/build)" || true
  printf '%s\n' "$CODE" > "$EVIDENCE_DIR/build-start-$tag.http.log"
  local OP
  OP="$(grep -oE '"operation_id": *"[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"operation_id": *"//;s/"$//')"
  printf '%s\n' "$OP" > "$EVIDENCE_DIR/operation-id-$tag.log"
  log "cycle $tag http=$CODE operation_id=$OP"
  [ -n "$OP" ] || { log "cycle $tag: no operation id (http $CODE)"; return 1; }
  case "$OP" in
    op_[0-9a-f]*) ;;
    *) log "cycle $tag: operation id is not canonical: $OP"; return 1 ;;
  esac

  local EXROOT="$BUILDER_STATE_ROOT/ops/$OP/root/runc-native/executor"
  local OUT="$EVIDENCE_DIR/spec-$tag"
  mkdir -p "$OUT"
  local STOPF="$STATE_DIR/poller-$tag.stop"
  rm -f "$STOPF"
  "$EVIDENCE_DIR/p21e_spec_poller" "$EXROOT" "$OUT" "$STOPF" \
    "$SPECIMEN_CEILING" "$POLLER_DEADLINE" "$OUT/poller.log" &
  local POLLER_PID=$!
  log "poller started for $EXROOT (pid $POLLER_PID, ceiling $SPECIMEN_CEILING, deadline ${POLLER_DEADLINE}s)"

  local STATUS=""
  for _ in $(seq 1 400); do
    STATUS="$(curl --silent --max-time 2 \
      --unix-socket "$DH_SOCK" -H "Authorization: Bearer $SESSION_TOKEN" \
      "http://localhost/operations/$OP" 2>/dev/null || true)"
    case "$STATUS" in
      *'"succeeded"'*|*'"failed"'*) break ;;
    esac
    sleep 0.05
  done
  printf '%s\n' "$STATUS" > "$EVIDENCE_DIR/build-status-$tag.json"
  touch "$STOPF"
  wait "$POLLER_PID" 2>/dev/null || true

  curl --silent --max-time 2 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $SESSION_TOKEN" \
    "http://localhost/operations/$OP/logs?offset=0" \
    > "$EVIDENCE_DIR/build-$tag.log" 2>&1 || true
  log "cycle $tag status: $(printf '%s' "$STATUS" | grep -oE '"(status|result_code)":"[^"]*"' | tr '\n' ' ')"
  # The executor root after the terminal: the pinned producer removes the
  # bundle at Run return (executor.go:264); the post-terminal state
  # documents that removal behavior.
  ls -laZ "$EXROOT" > "$EVIDENCE_DIR/executor-root-after-$tag.log" 2>&1 || true
  return 0
}

CYCLES_OK=0
for t in c1 c2 c3; do
  if capture_cycle "$t"; then CYCLES_OK=$((CYCLES_OK+1)); fi
done
log "capture cycles completed: $CYCLES_OK/$BUILD_CYCLES"
touch "$STATE_DIR/sec5"
fi

# ============================================================================
# Section 6: specimen inventory + provenance + machine verdict
# ============================================================================
log "=== section 6: specimen inventory + provenance ==="
N=0
: > "$EVIDENCE_DIR/p21e-specimens.log"
for f in "$EVIDENCE_DIR"/spec-*/spec-*.json; do
  [ -s "$f" ] || continue
  tag="$(printf '%s' "$f" | sed 's/.*spec-\(c[0-9]\)\/spec-.*/\1/')"
  op="$(cat "$EVIDENCE_DIR/operation-id-$tag.log" 2>/dev/null)"
  sz="$(wc -c < "$f")"
  sha="$(sha256sum "$f" | awk '{print $1}')"
  N=$((N+1))
  printf 'SPECIMEN file=%s cycle=%s operation=%s size=%s sha256=%s\n' \
    "$(basename "$f")" "$tag" "$op" "$sz" "$sha" >> "$EVIDENCE_DIR/p21e-specimens.log"
done
cat "$EVIDENCE_DIR/p21e-specimens.log"
# Console hygiene: specimen BYTES are never printed (the OCI process section
# carries the container environment); only the inventory above is public.
log "specimens captured: $N (ceiling: $SPECIMEN_CEILING per poller, deadline ${POLLER_DEADLINE}s)"
if [ "$N" -ge 1 ]; then
  printf 'R7-P21E-VERDICT=CAPTURED=%d\n' "$N"
else
  printf 'R7-P21E-VERDICT=CAPTURED=0\n'
  fail "no specimen captured; the capture gate must fail closed"
fi
