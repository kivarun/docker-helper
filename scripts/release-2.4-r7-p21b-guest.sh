#!/usr/bin/env bash
#
# release-2.4-r7-p21b-guest.sh — the R7 P21-B dedicated device-placeholder
# type verification on a disposable ENFORCING openSUSE Tumbleweed VM
# (candidate RPM built at the P21-B SHA; the policy IS the candidate —
# no diagnostic module is loaded anywhere).
#
# MODE: acceptance evidence for the accepted P21-A option E1. NO production
# change, NO diagnostic grant, NO merge/RC/tag. The candidate policy carries
# exactly:
#
#   type docker_helper_devnode_t;                                   (bare)
#   type_transition docker_helper_buildkitd_t tmpfs_t:file
#         docker_helper_devnode_t "null"|"zero"|"full"|"random"|
#         "urandom"|"tty";                                          (six)
#   allow docker_helper_buildkitd_t docker_helper_devnode_t:file create;
#   allow docker_helper_devnode_t tmpfs_t:filesystem associate;
#
# and NOTHING else changed relative to the P20 policy (the bare memfd
# transition and the six P1-P6 runc_memfd allows are untouched).
#
# THE QUESTIONS (P21-B acceptance):
#   1. Transition scope: all six names divert to docker_helper_devnode_t;
#      an arbitrary basename and the nameless (memfd) creation keep the
#      bare docker_helper_runc_memfd_t transition.
#   2. Memfd regression: the P1-P6 chain is intact — the live flow's
#      container init (comm="runc:[2:INIT]") exists ONLY after the sealed
#      memfd clone exec completed, so reaching the device-node stage proves
#      the memfd path; the runc_memfd_t:file create (P20) and tmpfs_t:file
#      write (pre-B') terminals must be absent from the AVC window.
#   3. Authority audit: the full compiled/loaded allow surface of the new
#      type for EVERY subject (exactly two rules; no attribute expansion).
#   4. Cross-operation: the kernel-AV matrix for s0:c1 and s0:c2 sources —
#      create ALLOW (both), every content permission DENIED (both).
#   5. Shared /dev/shm: the venue inventory + the filename-transition
#      consequences for same-named objects (content-dead by authority) and
#      the orphan side effect of a failed openat(O_CREAT) (no rollback).
#   6. Runtime: the enforcing flow's actual next terminal after
#      create+associate.
#
# Machine verdict contract:
#   R7-P21B-VERDICT=SCOPE=<six-names-ok|drift>;MEMFD=<intact|regressed>;\
#     NEXT-TERMINAL=<...>;CROSSOP-CONTENT=<closed|open>;ROLLBACK=<n/a>

set -uo pipefail

ARTIFACT="${R7_ARTIFACT:?R7_ARTIFACT required}"
ARTIFACT_SHA="${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log()  { printf '[r7-p21b] %s\n' "$*"; }
fail() { printf '[r7-p21b] FAILED: %s\n' "$*" >&2; exit 1; }

EVIDENCE_DIR="${R7_EVIDENCE_DIR:-/tmp/r7-p21b-evidence}"
mkdir -p "$EVIDENCE_DIR"
STATE_DIR=/tmp/r7-p21b-state
mkdir -p "$STATE_DIR"
DH_SOCK=/run/docker-helper/docker-helper.sock

cap() { # <name> <max-lines> <cmd...>
  local name="$1" maxn="$2" rc; shift 2
  "$@" >"$EVIDENCE_DIR/$name.log" 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || printf 'capture rc=%d\n' "$rc" >>"$EVIDENCE_DIR/$name.log"
  log "--- $name (evidence: $EVIDENCE_DIR/$name.log, first $maxn lines) ---"
  head -n "$maxn" "$EVIDENCE_DIR/$name.log"
  return 0
}

avc_tail() { # <label>
  : > "$EVIDENCE_DIR/$1.log"
  if command -v ausearch >/dev/null 2>&1 && pgrep -x auditd >/dev/null 2>&1; then
    ausearch -m AVC -m USER_AVC --start recent 2>/dev/null >> "$EVIDENCE_DIR/$1.log" || true
  fi
  if [ -f /var/log/audit/audit.log ]; then
    tail -n 800 /var/log/audit/audit.log >> "$EVIDENCE_DIR/$1.log" 2>/dev/null || true
  fi
  {
    command -v auditctl >/dev/null 2>&1 && auditctl -s 2>&1 | head -3
    wc -l /var/log/audit/audit.log 2>/dev/null || echo "audit.log: absent"
  } > "$EVIDENCE_DIR/$1-audit-state.log" 2>&1 || true
  if [ ! -s "$EVIDENCE_DIR/$1.log" ]; then
    printf '(no AVC records captured)\n' > "$EVIDENCE_DIR/$1.log"
  fi
  log "avc capture [$1]: $(wc -l < "$EVIDENCE_DIR/$1.log") lines"
}

[ "$(id -u)" = "0" ] || fail "must run as root"
[ -f "$ARTIFACT" ] || fail "artifact missing: $ARTIFACT"
now_sha="$(sha256sum "$ARTIFACT" | awk '{print $1}')"
[ "$now_sha" = "$ARTIFACT_SHA" ] || fail "artifact SHA mismatch (expected $ARTIFACT_SHA, got $now_sha)"

# ============================================================================
# Section 1: platform + SELinux enforcing proof
# ============================================================================
if [ -f "$STATE_DIR/sec1" ]; then log "phase marker: section 1 done; skipping"; else
log "=== section 1: platform + SELinux state ==="
ENF="$(getenforce 2>/dev/null || echo absent)"
[ "$ENF" = "Enforcing" ] || fail "SELinux not enforcing (getenforce='$ENF')"
cat /sys/kernel/security/lsm >"$EVIDENCE_DIR/lsm.txt" 2>&1 || true
grep -qw selinux "$EVIDENCE_DIR/lsm.txt" || fail "selinux not an active LSM"
cap p21b-se-status 14 bash -c 'sestatus; echo ---; getenforce; id -Z'
cat /etc/os-release >"$EVIDENCE_DIR/os-release.txt" 2>&1
grep -qi 'opensuse tumbleweed' "$EVIDENCE_DIR/os-release.txt" || fail "not openSUSE Tumbleweed"
cap p21b-platform 8 bash -c 'uname -a'
touch "$STATE_DIR/sec1"
fi

# ============================================================================
# Section 2: exact candidate install (never rebuilds)
# ============================================================================
if [ -f "$STATE_DIR/sec2" ]; then log "phase marker: section 2 done; skipping"; else
log "=== section 2: candidate install (rpm) ==="
rpm -q docker-helper >/dev/null 2>&1 && rpm -e docker-helper >/dev/null 2>&1 || true
rpm -i "$ARTIFACT" || fail "rpm -i failed"
log "RPM installed: $(rpm -q docker-helper)"
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
# Section 3: tooling + the LOADED candidate-policy inventory
# ============================================================================
if [ -f "$STATE_DIR/sec3" ]; then log "phase marker: section 3 done; skipping"; else
log "=== section 3: tooling + loaded-policy inventory (candidate policy) ==="
command -v sesearch >/dev/null 2>&1 || { timeout 180 zypper --non-interactive install -y setools-console >/dev/null 2>&1 || true; }
if ! command -v gcc >/dev/null 2>&1; then
  cap p21b-toolchain 6 timeout 300 zypper --non-interactive install -y gcc libselinux-devel
fi
command -v gcc >/dev/null 2>&1 || fail "gcc unavailable"

# (1) TRANSITION SCOPE: the loaded transitions keyed on (buildkitd_t, tmpfs_t).
cap p21b-transitions 30 bash -c 'sesearch -T -s docker_helper_buildkitd_t -t tmpfs_t'
# (2) MEMFD REGRESSION (static): the memfd surface must be EXACTLY the six
# P1-P6 rules with NO create.
cap p21b-memfd-allows 20 bash -c 'sesearch -A -s docker_helper_buildkitd_t -t docker_helper_runc_memfd_t'
# (3) AUTHORITY AUDIT: the FULL surface of the new type — every subject,
# every direction, no attribute expansion possible (attribute-free).
cap p21b-devnode-subj 20 bash -c 'echo "# sesearch -A -s docker_helper_devnode_t (the associate singleton is the ONLY subject authority)"; sesearch -A -s docker_helper_devnode_t'
cap p21b-devnode-target 20 bash -c 'echo "# sesearch -A -t docker_helper_devnode_t (the create singleton is the ONLY target authority)"; sesearch -A -t docker_helper_devnode_t'
cap p21b-devnode-attrs 10 seinfo -x -t docker_helper_devnode_t
cap p21b-devnode-fs 20 bash -c 'echo "# sesearch -A -s docker_helper_devnode_t -c filesystem"; sesearch -A -s docker_helper_devnode_t -c filesystem'
# The standing tmpfs_t surface must be unchanged (no tmpfs_t:file grant).
cap p21b-bkd-tmpfs 40 bash -c 'sesearch -A -s docker_helper_buildkitd_t -t tmpfs_t'
# Constraints for the record.
cap p21b-constraints-file 20 seinfo --constrain file
cap p21b-constraints-fs 20 seinfo --constrain filesystem
cap p21b-fsuse 12 bash -c 'seinfo --fs_use | grep -E "tmpfs|shm|mqueue"'
cap p21b-defaults 8 seinfo --default file
sha256sum /sys/fs/selinux/policy | awk '{print $1}' > "$EVIDENCE_DIR/policy-sha.log"
log "candidate loaded policy sha256: $(cat "$EVIDENCE_DIR/policy-sha.log")"
touch "$STATE_DIR/sec3"
fi

# ============================================================================
# Section 4: kernel-decision helpers
# ============================================================================
if [ ! -x "$EVIDENCE_DIR/p21b_create_probe" ]; then
log "=== section 4: kernel-decision helpers build ==="
cat > "$EVIDENCE_DIR/p21b_create_probe.c" <<'CEOF'
/* p21b_create_probe.c — security_compute_create(_name)_raw on the LOADED
 * candidate policy: the would-be label of a creation transition, with the
 * exact basename (filename transitions) and with name=NULL (the memfd
 * lazy-labeling route). PRELIMINARY evidence only. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <selinux/selinux.h>

typedef int (*compute_create_name_fn)(const char *, const char *,
                                      security_class_t, const char *, char **);

int main(int argc, char **argv)
{
	compute_create_name_fn compute_name = NULL;
	void *h = dlopen(NULL, RTLD_LAZY);
	if (h)
		compute_name = (compute_create_name_fn)dlsym(
			h, "security_compute_create_name_raw");
	if (argc < 4) {
		fprintf(stderr,
			"usage: p21b_create_probe <source-ctx> <target-ctx> <class> [name [more triples]]\n");
		return 2;
	}
	for (int i = 1; i + 3 <= argc; i += 4) {
		char *out = NULL;
		security_class_t cl = string_to_security_class(argv[i + 2]);
		const char *name = argv[i + 3];
		int rc;
		if (!cl) {
			printf("CREATE %s x %s x %s [%s] -> CLASS-UNKNOWN\n",
			       argv[i], argv[i + 1], argv[i + 2], name);
			continue;
		}
		if (strcmp(name, "-") == 0 || !compute_name) {
			rc = security_compute_create_raw(argv[i], argv[i + 1], cl, &out);
		} else {
			rc = compute_name(argv[i], argv[i + 1], cl, name, &out);
		}
		if (rc == 0 && out)
			printf("CREATE %s x %s x %s [%s] -> %s\n",
			       argv[i], argv[i + 1], argv[i + 2], name, out);
		else
			printf("CREATE %s x %s x %s [%s] -> ERR rc=%d errno=%d (%s)\n",
			       argv[i], argv[i + 1], argv[i + 2], name, rc, errno,
			       strerror(errno));
		free(out);
	}
	return 0;
}
CEOF
gcc -O2 -o "$EVIDENCE_DIR/p21b_create_probe" "$EVIDENCE_DIR/p21b_create_probe.c" -lselinux -ldl \
  || fail "p21b_create_probe build failed"

cat > "$EVIDENCE_DIR/p21b_av_probe.c" <<'CEOF'
/* p21b_av_probe.c — kernel-decision matrix via security_compute_av_raw. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>

static const char *file_perms[] = {
	"create", "write", "append", "setattr", "execute",
	"execute_no_trans", "map", "open", "read", "getattr",
	"unlink", "rename", "link", "ioctl", "lock", NULL
};

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "usage: p21b_av_probe <source-ctx> <target-ctx> <class>\n");
		return 2;
	}
	security_class_t cl = string_to_security_class(argv[3]);
	if (!cl) { fprintf(stderr, "unknown class %s\n", argv[3]); return 2; }
	struct av_decision avd;
	if (strcmp(argv[3], "file") == 0) {
		for (int p = 0; file_perms[p]; p++) {
			access_vector_t bit = string_to_av_perm(cl, file_perms[p]);
			if (!bit) { printf("  %-16s UNKNOWN-PERM\n", file_perms[p]); continue; }
			int rc = security_compute_av_raw(argv[1], argv[2], cl, bit, &avd);
			if (rc)
				printf("  %-16s ERR rc=%d errno=%d\n", file_perms[p], rc, errno);
			else
				printf("  %-16s %s (allowed=0x%x decided=0x%x)\n",
				       file_perms[p],
				       (avd.allowed & bit) ? "ALLOW" : "DENY",
				       (unsigned)avd.allowed, (unsigned)avd.decided);
		}
	} else {
		access_vector_t bit = string_to_av_perm(cl, "associate");
		if (!bit) { printf("  associate UNKNOWN-PERM\n"); return 1; }
		int rc = security_compute_av_raw(argv[1], argv[2], cl, bit, &avd);
		if (rc)
			printf("  associate ERR rc=%d errno=%d\n", rc, errno);
		else
			printf("  associate %s (allowed=0x%x decided=0x%x)\n",
			       (avd.allowed & bit) ? "ALLOW" : "DENY",
			       (unsigned)avd.allowed, (unsigned)avd.decided);
	}
	return 0;
}
CEOF
gcc -O2 -o "$EVIDENCE_DIR/p21b_av_probe" "$EVIDENCE_DIR/p21b_av_probe.c" -lselinux \
  || fail "p21b_av_probe build failed"
log "kernel-decision helpers built"
touch "$STATE_DIR/sec4"
fi

BKD_CTX="system_u:system_r:docker_helper_buildkitd_t:s0:c1"
BKD_C2="system_u:system_r:docker_helper_buildkitd_t:s0:c2"
TMPFS_CTX="system_u:object_r:tmpfs_t:s0"
UNCONF_CTX="unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
DEVNODE="system_u:object_r:docker_helper_devnode_t:s0"
MEMFD="system_u:object_r:docker_helper_runc_memfd_t:s0"

create_matrix() { # <suffix>
  "$EVIDENCE_DIR/p21b_create_probe" \
    "$BKD_CTX" "$TMPFS_CTX" file null \
    "$BKD_CTX" "$TMPFS_CTX" file zero \
    "$BKD_CTX" "$TMPFS_CTX" file full \
    "$BKD_CTX" "$TMPFS_CTX" file random \
    "$BKD_CTX" "$TMPFS_CTX" file urandom \
    "$BKD_CTX" "$TMPFS_CTX" file tty \
    "$BKD_CTX" "$TMPFS_CTX" file someothername \
    "$BKD_CTX" "$TMPFS_CTX" file - \
    "$BKD_C2" "$TMPFS_CTX" file null \
    "$BKD_C2" "$TMPFS_CTX" file - \
    "$UNCONF_CTX" "$TMPFS_CTX" file null \
    "$UNCONF_CTX" "$TMPFS_CTX" file - \
    > "$EVIDENCE_DIR/create-matrix-$1.log" 2>&1
  cat "$EVIDENCE_DIR/create-matrix-$1.log"
}

av_matrix() { # <suffix>
  {
    echo "== buildkitd_t:s0:c1 -> docker_helper_devnode_t:s0 =="
    "$EVIDENCE_DIR/p21b_av_probe" "$BKD_CTX" "$DEVNODE" file
    echo "== CROSS-OP: buildkitd_t:s0:c2 -> docker_helper_devnode_t:s0 =="
    "$EVIDENCE_DIR/p21b_av_probe" "$BKD_C2" "$DEVNODE" file
    echo "== unconfined_t -> docker_helper_devnode_t:s0 =="
    "$EVIDENCE_DIR/p21b_av_probe" "$UNCONF_CTX" "$DEVNODE" file
    echo "== FILESYSTEM ASSOCIATE rows =="
    echo "-- devnode_t -> tmpfs_t (the granted singleton) --"
    "$EVIDENCE_DIR/p21b_av_probe" "system_u:object_r:docker_helper_devnode_t:s0" "$TMPFS_CTX" filesystem
    echo "-- runc_memfd_t -> tmpfs_t (must stay denied) --"
    "$EVIDENCE_DIR/p21b_av_probe" "$MEMFD" "$TMPFS_CTX" filesystem
    echo "-- tmpfs_t -> tmpfs_t (control) --"
    "$EVIDENCE_DIR/p21b_av_probe" "system_u:object_r:tmpfs_t:s0" "$TMPFS_CTX" filesystem
  } > "$EVIDENCE_DIR/av-matrix-$1.log" 2>&1
  cat "$EVIDENCE_DIR/av-matrix-$1.log"
}

# ============================================================================
# Section 5: decision matrices on the candidate policy
# ============================================================================
if [ -f "$STATE_DIR/sec5" ]; then log "phase marker: section 5 done; skipping"; else
log "=== section 5: create + AV matrices (candidate policy) ==="
create_matrix before
av_matrix before
touch "$STATE_DIR/sec5"
fi

# ============================================================================
# Section 6: live flow probes (the enforcing runtime; two operations)
# ============================================================================
run_one_build() { # <tag> <session-token>
  local tag="$1" token="$2"
  ( DOCKER_HELPER_SESSION_TOKEN="$token" docker-helper build ctx \
      --dockerfile Dockerfile --image "uat-p21b:$tag" \
      >"$EVIDENCE_DIR/build-$tag.log" 2>&1 ) &
  local BLD=$!
  for _ in $(seq 1 400); do
    local P; P="$(pgrep -x buildkitd | head -1 || true)"
    if [ -n "$P" ]; then
      {
        echo "== ns ids =="
        ls -l /proc/$P/ns/ 2>/dev/null
        echo "== uid_map =="
        cat /proc/$P/uid_map 2>/dev/null
        echo "== mountinfo (full) =="
        cat /proc/$P/mountinfo 2>/dev/null
      } > "$EVIDENCE_DIR/buildkitd-mountinfo-$tag.log" 2>&1 || true
      break
    fi
    kill -0 "$BLD" 2>/dev/null || break
    sleep 0.05
  done
  wait "$BLD"; local RC=$?
  log "build $tag rc=$RC (terminal failure expected — the next rung)"
  cap "build-$tag-tail" 8 tail -6 "$EVIDENCE_DIR/build-$tag.log"
  return $RC
}

make_session_build() { # <tag>
  local tag="$1"
  local WS="$PRINCIPAL_HOME/r7-p21b-ws-$tag"
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
  local TOKEN
  TOKEN="$(grep -oE '"token": *"[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"token": *"//;s/"$//')"
  if [ -z "$TOKEN" ]; then
    log "session create failed for $tag (HTTP $CODE); skipping this build"
    return 1
  fi
  docker-helper pull alpine:3.24 >"$EVIDENCE_DIR/pull-$tag.log" 2>&1 || true
  run_one_build "$tag" "$TOKEN" || true
  return 0
}

if [ -f "$STATE_DIR/sec6" ]; then log "phase marker: section 6 done; skipping"; else
log "=== section 6: live flow probes (candidate policy) ==="
for _ in $(seq 1 50); do
  [ -S "$DH_SOCK" ] && curl --silent --fail --max-time 1 \
    --unix-socket "$DH_SOCK" http://localhost/health >/dev/null 2>&1 && break
  sleep 0.2
done
[ -n "$ADMIN_TOKEN" ] || fail "admin token unreadable; the live proof cannot run"
cap p21b-host-venues 20 bash -c 'ls -ldZ /dev/shm /run/initramfs /tmp /var/tmp 2>&1'
make_session_build c1
avc_tail p21b-avc-c1
make_session_build c2
avc_tail p21b-avc-c2
# The terminal records and the regression controls, from BOTH windows.
{
  echo "== devnode-terminal runc-init AVCs (both windows) =="
  grep -ah 'runc:\[2:INIT\]' "$EVIDENCE_DIR/p21b-avc-c1.log" "$EVIDENCE_DIR/p21b-avc-c2.log" 2>/dev/null | head -10
  echo "== regression controls (must be EMPTY) =="
  echo "-- P20 terminal (runc_memfd_t:file create) --"
  grep -ah 'docker_helper_runc_memfd_t.*tclass=file' "$EVIDENCE_DIR/p21b-avc-c1.log" "$EVIDENCE_DIR/p21b-avc-c2.log" 2>/dev/null | grep -a '{ create }' | head -4
  echo "-- pre-B terminal (tmpfs_t:file write) --"
  grep -ah 'tcontext=system_u:object_r:tmpfs_t:s0 tclass=file' "$EVIDENCE_DIR/p21b-avc-c1.log" "$EVIDENCE_DIR/p21b-avc-c2.log" 2>/dev/null | grep -a '{ write }' | head -4
  echo "-- associate denials (must be EMPTY — the singleton is granted) --"
  grep -ah 'denied  { associate }' "$EVIDENCE_DIR/p21b-avc-c1.log" "$EVIDENCE_DIR/p21b-avc-c2.log" 2>/dev/null | head -4
} > "$EVIDENCE_DIR/p21b-terminals.log" 2>&1
cat "$EVIDENCE_DIR/p21b-terminals.log"
touch "$STATE_DIR/sec6"
fi

# ============================================================================
# Machine verdict
# ============================================================================
SCOPE="six-names-ok"
if ! grep -aq 'docker_helper_devnode_t:s0' "$EVIDENCE_DIR/create-matrix-before.log" 2>/dev/null; then
  SCOPE="drift"
fi
N_OK="$(grep -ac 'x docker_helper_devnode_t' "$EVIDENCE_DIR/create-matrix-before.log" 2>/dev/null || echo 0)"
if [ "${N_OK:-0}" -lt 6 ] 2>/dev/null; then SCOPE="drift"; fi
ARBITRARY_OK="no"
grep -aq 'x docker_helper_runc_memfd_t:s0' "$EVIDENCE_DIR/create-matrix-before.log" 2>/dev/null && ARBITRARY_OK="yes"
MEMFD="intact"
if grep -aq '{ create }' "$EVIDENCE_DIR/p21b-avc-c1.log" 2>/dev/null \
   && grep -ah '{ create }' "$EVIDENCE_DIR/p21b-avc-c1.log" "$EVIDENCE_DIR/p21b-avc-c2.log" 2>/dev/null \
      | grep -aq 'docker_helper_runc_memfd_t'; then
  MEMFD="regressed"
fi
CROSSOP_CONTENT="closed"
if awk '/CROSS-OP/{f=1} f && / (write|open|read|execute) /{if ($0 ~ /ALLOW/) {print; exit}}' \
     "$EVIDENCE_DIR/av-matrix-before.log" 2>/dev/null | grep -q ALLOW; then
  CROSSOP_CONTENT="open"
fi
NEXT_TERMINAL="(none)"
DEV_AVC="$(grep -ah 'runc:\[2:INIT\]' "$EVIDENCE_DIR/p21b-avc-c1.log" 2>/dev/null | grep -a 'docker_helper_devnode_t' | head -1 || true)"
if [ -n "$DEV_AVC" ]; then
  NEXT_TERMINAL="$DEV_AVC"
fi

printf 'R7-P21B-VERDICT=SCOPE=%s;ARBITRARY-NAME-KEEPS-MEMFD=%s;MEMFD=%s;CROSSOP-CONTENT=%s;NEXT-TERMINAL=<%s>\n' \
  "$SCOPE" "$ARBITRARY_OK" "$MEMFD" "$CROSSOP_CONTENT" "$NEXT_TERMINAL"
exit 0
