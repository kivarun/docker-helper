#!/usr/bin/env bash
#
# release-2.4-r7-p21a-guest.sh — the R7 P21-A memfd type-transition scope
# investigation on a disposable ENFORCING openSUSE Tumbleweed VM (RPM
# candidate).
#
# MODE: evidence-only investigation. NO production policy change, NO
# production Go/OCI change, NO merge/RC/tag. The EXPERIMENTAL policy module
# in section 7 (exactly ONE allow: buildkitd_t -> docker_helper_runc_memfd_t
# :file create — the P21 candidate grant under review) is loaded ONLY on
# this disposable VM and is REMOVED with a byte-identical policy-restoration
# proof before the script exits. Nothing diagnostic is ever copied into the
# release policy or the release artifacts.
#
# THE QUESTIONS (P21-A):
#   A. WHY does the memfd-intended type_transition
#      (docker_helper_buildkitd_t tmpfs_t:file docker_helper_runc_memfd_t)
#      fire on the runc /dev placeholder openat(O_CREAT)?  What object
#      population does it cover, and when does the result carry s0 vs the
#      operation's MCS category?
#   B. Which tmpfs_t:file creation venues are REACHABLE from
#      docker_helper_buildkitd_t?
#   C. What would granting file create add, given the standing type-wide
#      write/setattr/execute/execute_no_trans/read/open/map authority?
#   D. Does the grant create NEW cross-operation reachability?
#   E. What minimal narrowing separates the sealed runc memfd from ordinary
#      tmpfs files?
#
# The machine verdict contract:
#   R7-P21A-VERDICT=CREATE-GATE=<confirmed|absent>;NEXT-TERMINAL=<class:type perm
#     |none>;ASSOCIATE=<allowed|denied|untested>;CROSSOP-AV=<open|closed>;\
#     SHM-IN-BKD-NS=<yes|no|untested>;ROLLBACK=<restored|failed>

set -uo pipefail

ARTIFACT="${R7_ARTIFACT:?R7_ARTIFACT required}"
ARTIFACT_SHA="${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log()  { printf '[r7-p21a] %s\n' "$*"; }
fail() { printf '[r7-p21a] FAILED: %s\n' "$*" >&2; exit 1; }

EVIDENCE_DIR="${R7_EVIDENCE_DIR:-/tmp/r7-p21a-evidence}"
mkdir -p "$EVIDENCE_DIR"
STATE_DIR=/tmp/r7-p21a-state
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

avc_tail() { # <label> — recent AVC records (ausearch + raw log fallback)
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
cap p21a-se-status 14 bash -c 'sestatus; echo ---; getenforce; id -Z'
cat /etc/os-release >"$EVIDENCE_DIR/os-release.txt" 2>&1
grep -qi 'opensuse tumbleweed' "$EVIDENCE_DIR/os-release.txt" || fail "not openSUSE Tumbleweed"
cap p21a-platform 8 bash -c 'uname -a'
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

# Session-build inputs: recomputed on EVERY invocation so later sections
# still work after the mid-diagnosis VM reboot (phase markers skip 1-2).
PRINCIPAL="${SUDO_USER:-}"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"

# ============================================================================
# Section 3: tooling + the LOADED-policy inventory (the production policy,
# no diagnostic module yet)
# ============================================================================
if [ -f "$STATE_DIR/sec3" ]; then log "phase marker: section 3 done; skipping"; else
log "=== section 3: tooling + loaded-policy inventory ==="
command -v sesearch >/dev/null 2>&1 || { timeout 180 zypper --non-interactive install -y setools-console >/dev/null 2>&1 || true; }
if ! command -v gcc >/dev/null 2>&1; then
  cap p21a-toolchain 6 timeout 300 zypper --non-interactive install -y gcc libselinux-devel
fi
command -v gcc >/dev/null 2>&1 || fail "gcc unavailable"

cap p21a-fsuse 30 seinfo --fs_use
cap p21a-defaults 12 seinfo --default file
cap p21a-defaults-dir 12 seinfo --default dir
cap p21a-polcaps 20 bash -c 'seinfo --polcap 2>&1 || seinfo --polcap memfd_class 2>&1 || echo "(polcap inventory unavailable)"'
cap p21a-memfd-class 12 bash -c 'seinfo -c 2>/dev/null | grep -i memfd || echo "(no memfd class in the loaded policy)"'
# The runc_memfd type: attribute membership must be exactly NONE (bare type).
cap p21a-newtype-attrs 10 seinfo -x -t docker_helper_runc_memfd_t
# The full loaded buildkitd -> runc_memfd_t surface (the six merged rules).
cap p21a-newtype-allows 40 bash -c 'sesearch -A -s docker_helper_buildkitd_t -t docker_helper_runc_memfd_t'
# Any OTHER subject with authority on the type (expect: none beyond attribute
# expansions).
cap p21a-newtype-subj 40 bash -c 'sesearch -A -t docker_helper_runc_memfd_t'
# The buildkitd tmpfs_t surface (all classes) — the standing base dir surface
# plus the module singletons.
cap p21a-bkd-tmpfs 40 bash -c 'sesearch -A -s docker_helper_buildkitd_t -t tmpfs_t'
# The transition inventory.
cap p21a-bkd-transitions 30 bash -c 'sesearch -T -s docker_helper_buildkitd_t'
# Associate rules toward tmpfs_t:filesystem (the post-create gate inventory).
cap p21a-tmpfs-associate 40 bash -c 'sesearch -A -t tmpfs_t -c filesystem'
# Any associate authority for the bare new type specifically.
cap p21a-newtype-associate 20 bash -c 'echo "# sesearch -A -s docker_helper_runc_memfd_t -c filesystem (empty = the associate gate stays closed for the type)"; sesearch -A -s docker_helper_runc_memfd_t -c filesystem'
# Constraints: the file/dir/filesystem class expressions verbatim.
cap p21a-constraints-file 20 seinfo --constrain file
cap p21a-constraints-dir 20 seinfo --constrain dir
cap p21a-constraints-fs 20 seinfo --constrain filesystem
sha256sum /sys/fs/selinux/policy | awk '{print $1}' > "$EVIDENCE_DIR/policy-sha-before.log"
log "baseline policy sha256: $(cat "$EVIDENCE_DIR/policy-sha-before.log")"
touch "$STATE_DIR/sec3"
fi

# ============================================================================
# Section 4: kernel-decision helpers (create-name matrix + AV matrix)
# ============================================================================
if [ ! -x "$EVIDENCE_DIR/p21a_create_probe" ]; then
log "=== section 4: kernel-decision helpers build ==="
cat > "$EVIDENCE_DIR/p21a_create_probe.c" <<'CEOF'
/* p21a_create_probe.c — security_compute_create(_name)_raw on the LOADED
 * policy: the kernel's own would-be label for a creation transition.
 * The _name variant (when available in libselinux) also exercises filename
 * transitions with the exact placeholder basename. PRELIMINARY evidence
 * only — never a substitute for the live labeling proof. */
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
			"usage: p21a_create_probe <source-ctx> <target-ctx> <class> [name [more triples]]\n");
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
gcc -O2 -o "$EVIDENCE_DIR/p21a_create_probe" "$EVIDENCE_DIR/p21a_create_probe.c" -lselinux -ldl \
  || fail "p21a_create_probe build failed"

cat > "$EVIDENCE_DIR/p21a_av_probe.c" <<'CEOF'
/* p21a_av_probe.c — kernel-decision matrix via security_compute_av_raw for
 * file-class permissions and filesystem-class associate rows. */
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
		fprintf(stderr, "usage: p21a_av_probe <source-ctx> <target-ctx> <class>\n");
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
		/* filesystem: probe associate explicitly */
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
gcc -O2 -o "$EVIDENCE_DIR/p21a_av_probe" "$EVIDENCE_DIR/p21a_av_probe.c" -lselinux \
  || fail "p21a_av_probe build failed"
log "kernel-decision helpers built"
touch "$STATE_DIR/sec4"
fi

BKD_CTX="system_u:system_r:docker_helper_buildkitd_t:s0:c1"
BKD_C2="system_u:system_r:docker_helper_buildkitd_t:s0:c2"
TMPFS_CTX="system_u:object_r:tmpfs_t:s0"
UNCONF_CTX="unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
RT_CTX="system_u:object_r:docker_helper_builder_runtime_t:s0:c1"
STATE_CTX="system_u:object_r:docker_helper_builder_state_t:s0:c1"
NEW="system_u:object_r:docker_helper_runc_memfd_t:s0"

create_matrix() { # <suffix> — the create-decision matrix (with names)
  "$EVIDENCE_DIR/p21a_create_probe" \
    "$BKD_CTX" "$TMPFS_CTX" file - \
    "$BKD_C2" "$TMPFS_CTX" file - \
    "$BKD_CTX" "$TMPFS_CTX" file null \
    "$BKD_CTX" "$TMPFS_CTX" file icastats_0 \
    "$UNCONF_CTX" "$TMPFS_CTX" file - \
    "$BKD_CTX" "$RT_CTX" file - \
    "$BKD_CTX" "$STATE_CTX" file - \
    "$BKD_CTX" "$TMPFS_CTX" dir - \
    "$BKD_CTX" "$TMPFS_CTX" fifo_file - \
    "$BKD_CTX" "$TMPFS_CTX" lnk_file - \
    > "$EVIDENCE_DIR/create-matrix-$1.log" 2>&1
  cat "$EVIDENCE_DIR/create-matrix-$1.log"
}

av_matrix() { # <suffix> — the permission matrix on the loaded policy
  {
    "$EVIDENCE_DIR/p21a_av_probe" "$BKD_CTX" "$NEW" file
    echo "== CROSS-OP: buildkitd_t:s0:c2 -> runc_memfd_t:s0 =="
    "$EVIDENCE_DIR/p21a_av_probe" "$BKD_C2" "$NEW" file
    echo "== unconfined_t -> runc_memfd_t:s0 (the type is module-private) =="
    "$EVIDENCE_DIR/p21a_av_probe" "$UNCONF_CTX" "$NEW" file
    echo "== FILESYSTEM ASSOCIATE rows =="
    echo "-- runc_memfd_t -> tmpfs_t --"
    "$EVIDENCE_DIR/p21a_av_probe" "system_u:object_r:docker_helper_runc_memfd_t" "$TMPFS_CTX" filesystem
    echo "-- tmpfs_t -> tmpfs_t (control) --"
    "$EVIDENCE_DIR/p21a_av_probe" "system_u:object_r:tmpfs_t" "$TMPFS_CTX" filesystem
    echo "-- buildkitd_t -> tmpfs_t --"
    "$EVIDENCE_DIR/p21a_av_probe" "$BKD_CTX" "$TMPFS_CTX" filesystem
  } > "$EVIDENCE_DIR/av-matrix-$1.log" 2>&1
  cat "$EVIDENCE_DIR/av-matrix-$1.log"
}

# ============================================================================
# Section 5: PRE-load decision matrices (the shipped candidate policy)
# ============================================================================
if [ -f "$STATE_DIR/sec5" ]; then log "phase marker: section 5 done; skipping"; else
log "=== section 5: PRE-load create + AV matrices (shipped policy) ==="
create_matrix before
av_matrix before
touch "$STATE_DIR/sec5"
fi

# ============================================================================
# Section 6: venue reachability inventory + the shipped-policy flow probe
# ============================================================================
run_one_build() { # <tag> <session-token> — one production-shape build + evidence
  local tag="$1" token="$2"
  local STRACE_LOG="$EVIDENCE_DIR/p21a-strace-$tag.log"
  : > "$STRACE_LOG"
  ( DOCKER_HELPER_SESSION_TOKEN="$token" docker-helper build ctx \
      --dockerfile Dockerfile --image "uat-p21a:$tag" \
      >"$EVIDENCE_DIR/build-$tag.log" 2>&1 ) &
  local BLD=$!
  local SPID=""
  for _ in $(seq 1 400); do
    local P; P="$(pgrep -x buildkitd | head -1 || true)"
    if [ -n "$P" ]; then
      # Full memfd inventory + the exec/mount syscall record of the flow.
      strace -f -qq -tt -s 120 -y \
        -e trace=memfd_create,openat,mount,fsopen,fsconfig,execve \
        -p "$P" -o "$STRACE_LOG" \
        2>"$EVIDENCE_DIR/p21a-strace-$tag.err" &
      SPID=$!
      log "strace attached to buildkitd pid $P (build $tag)"
      # Venue inventory DURING the build: the buildkitd mount namespace.
      {
        echo "== ns ids =="
        ls -l /proc/$P/ns/ 2>/dev/null
        echo "== uid_map =="
        cat /proc/$P/uid_map 2>/dev/null
        echo "== mountinfo (full) =="
        cat /proc/$P/mountinfo 2>/dev/null
      } > "$EVIDENCE_DIR/buildkitd-mountinfo-$tag.log" 2>&1 || true
      {
        echo "== labels/modes inside the buildkitd mount namespace =="
        ls -ldZ /proc/$P/root/dev/shm /proc/$P/root/tmp /proc/$P/root/run/initramfs \
                /proc/$P/root/var/tmp /proc/$P/root/dev 2>&1
      } > "$EVIDENCE_DIR/buildkitd-ns-labels-$tag.log" 2>&1 || true
      # The container init child's mount namespace (runc:[2:INIT]) if live.
      RPID="$(pgrep -f 'runc:\[2:INIT\]' | head -1 || true)"
      if [ -n "$RPID" ]; then
        {
          echo "== container init pid $RPID ns/mountinfo =="
          ls -l /proc/$RPID/ns/ 2>/dev/null
          cat /proc/$RPID/mountinfo 2>/dev/null
          echo "== labels/modes inside the container mount namespace =="
          ls -ldZ /proc/$RPID/root/dev /proc/$RPID/root/dev/shm 2>&1
        } > "$EVIDENCE_DIR/container-init-ns-$tag.log" 2>&1 || true
      fi
      break
    fi
    kill -0 "$BLD" 2>/dev/null || break
    sleep 0.05
  done
  wait "$BLD"; local RC=$?
  [ -n "$SPID" ] && kill "$SPID" 2>/dev/null || true
  log "build $tag rc=$RC (terminal failure expected under the shipped policy)"
  cap "build-$tag-tail" 8 tail -6 "$EVIDENCE_DIR/build-$tag.log"
  grep -a 'memfd_create' "$STRACE_LOG" | head -20 \
    > "$EVIDENCE_DIR/p21a-memfd-inventory-$tag.log" 2>/dev/null || true
  log "memfd_create calls seen in build $tag: $(wc -l < "$EVIDENCE_DIR/p21a-memfd-inventory-$tag.log")"
  return $RC
}

make_session_build() { # <tag> — one session + one build attempt; echoes tag
  local tag="$1"
  local WS="$PRINCIPAL_HOME/r7-p21a-ws-$tag"
  rm -rf "$WS"; mkdir -p "$WS/ctx"
  cat > "$WS/ctx/Dockerfile" <<'EOF'
FROM alpine:3.24
RUN true
EOF
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
log "=== section 6: shipped-policy flow probe (the /dev/null create terminal) ==="
# After the mid-diagnosis reboot the daemon may still be starting: wait for
# the API socket before any build.
for _ in $(seq 1 50); do
  [ -S "$DH_SOCK" ] && curl --silent --fail --max-time 1 \
    --unix-socket "$DH_SOCK" http://localhost/health >/dev/null 2>&1 && break
  sleep 0.2
done
[ -n "$ADMIN_TOKEN" ] || fail "admin token unreadable; the live proof cannot run"

# Host-side venue inventory (labels + modes) taken before the flow probes.
cap p21a-host-venues 24 bash -c 'ls -ldZ /dev/shm /run/initramfs /tmp /var/tmp /run/lock /dev 2>&1; echo ---; findmnt -n -o TARGET,FSTYPE,OPTIONS -t tmpfs 2>/dev/null | head -12'
make_session_build shipped
avc_tail p21a-avc-shipped
# The terminal record: the createDevices openat(O_CREAT) denial.
grep -a 'runc:\[2:INIT\]' "$EVIDENCE_DIR/p21a-avc-shipped.log" | grep -a 'tclass=file' | head -6 \
  > "$EVIDENCE_DIR/p21a-terminal-shipped.log" 2>/dev/null || true
log "--- shipped-policy terminal (runc init file AVCs) ---"
head -6 "$EVIDENCE_DIR/p21a-terminal-shipped.log" 2>/dev/null | cut -c1-300 || true
touch "$STATE_DIR/sec6"
fi

# ============================================================================
# Section 7: the DIAGNOSTIC module (disposable VM only; rollback proven):
# exactly ONE allow — the P21 candidate grant under review.
# ============================================================================
if [ -f "$STATE_DIR/sec7" ]; then log "phase marker: section 7 done; skipping"; else
log "=== section 7: diagnostic module load (P21 candidate: file create ONLY) ==="
for _ in $(seq 1 50); do
  [ -S "$DH_SOCK" ] && curl --silent --fail --max-time 1 \
    --unix-socket "$DH_SOCK" http://localhost/health >/dev/null 2>&1 && break
  sleep 0.2
done
cat > "$EVIDENCE_DIR/docker_helper_r7p21a.cil" <<'CEOF'
; R7 P21-A EXPERIMENTAL MODULE — disposable VM only.
; Exactly ONE rule: the P21 candidate grant under review. No other
; permission, no type/attribute change, no transition change.
(allow docker_helper_buildkitd_t
       docker_helper_runc_memfd_t (file (create)))
CEOF
sha256sum "$EVIDENCE_DIR/docker_helper_r7p21a.cil" > "$EVIDENCE_DIR/module-sha"
semodule -i "$EVIDENCE_DIR/docker_helper_r7p21a.cil" || fail "diagnostic module load failed"
log "diagnostic module loaded"
# Verify the loaded surface moved by EXACTLY this one permission.
cap p21a-loaded-allows 40 bash -c 'sesearch -A -s docker_helper_buildkitd_t -t docker_helper_runc_memfd_t'
cap p21a-loaded-tmpfs 40 bash -c 'sesearch -A -s docker_helper_buildkitd_t -t tmpfs_t'
cap p21a-loaded-associate 20 bash -c 'echo "# sesearch -A -s docker_helper_runc_memfd_t -c filesystem (empty = associate still closed)"; sesearch -A -s docker_helper_runc_memfd_t -c filesystem'
sha256sum /sys/fs/selinux/policy | awk '{print $1}' > "$EVIDENCE_DIR/policy-sha-loaded.log"
log "loaded policy sha256: $(cat "$EVIDENCE_DIR/policy-sha-loaded.log")"
log "=== POST-load matrices (create now TE-allowed; associate state recorded) ==="
create_matrix after
av_matrix after
# The live probe: the flow advances to its NEXT terminal (predicted:
# the may_create step-4 associate gate on runc_memfd_t -> tmpfs_t, or the
# bind mounton if associate passes).
make_session_build diag
avc_tail p21a-avc-diag
grep -a 'runc:\[2:INIT\]' "$EVIDENCE_DIR/p21a-avc-diag.log" | grep -aE 'tclass=(file|filesystem)' | head -8 \
  > "$EVIDENCE_DIR/p21a-terminal-diag.log" 2>/dev/null || true
log "--- diagnostic-policy terminal (runc init file/filesystem AVCs) ---"
head -8 "$EVIDENCE_DIR/p21a-terminal-diag.log" 2>/dev/null | cut -c1-300 || true
touch "$STATE_DIR/sec7"
fi

# ============================================================================
# Section 8: ROLLBACK (removal + byte-identical restoration proof)
# ============================================================================
if [ -f "$STATE_DIR/sec8" ]; then log "phase marker: section 8 done; skipping"; else
log "=== section 8: rollback (module removal + restoration proof) ==="
semodule -r docker_helper_r7p21a || fail "diagnostic module removal failed"
if semodule -l 2>/dev/null | grep -qi p21a; then
  printf 'module-still-loaded\n' > "$EVIDENCE_DIR/rollback-module-list.log"
else
  printf 'module-removed\n' > "$EVIDENCE_DIR/rollback-module-list.log"
fi
log "module removal: $(cat "$EVIDENCE_DIR/rollback-module-list.log")"
sha256sum /sys/fs/selinux/policy | awk '{print $1}' > "$EVIDENCE_DIR/policy-sha-after-rollback.log"
log "post-rollback policy sha256: $(cat "$EVIDENCE_DIR/policy-sha-after-rollback.log")"
log "=== POST-rollback create matrix (must equal the PRE matrix) ==="
create_matrix rollback
touch "$STATE_DIR/sec8"
fi

# ============================================================================
# Machine verdict
# ============================================================================
CREATE_GATE="(absent)"
if grep -aq 'tcontext=system_u:object_r:docker_helper_runc_memfd_t:s0 tclass=file' \
     "$EVIDENCE_DIR/p21a-terminal-shipped.log" 2>/dev/null; then
  CREATE_GATE="(confirmed)"
fi
NEXT_TERMINAL="(none)"
if [ -s "$EVIDENCE_DIR/p21a-terminal-diag.log" ]; then
  NEXT_TERMINAL="$(grep -aoE 'denied +{ [a-z_ ]+ }.*tcontext=[^ ]+ tclass=[a-z_]+' \
    "$EVIDENCE_DIR/p21a-terminal-diag.log" | head -1 || true)"
  [ -n "$NEXT_TERMINAL" ] || NEXT_TERMINAL="(none)"
fi
ASSOCIATE="(untested)"
if [ -s "$EVIDENCE_DIR/av-matrix-after.log" ]; then
  ASSOCIATE_ROW="$(awk '/-- runc_memfd_t -> tmpfs_t --/{f=1} f && /^  associate/{print; exit}' "$EVIDENCE_DIR/av-matrix-after.log")"
  case "$ASSOCIATE_ROW" in
    *"ALLOW"*) ASSOCIATE="allowed" ;;
    *"DENY"*)  ASSOCIATE="denied" ;;
  esac
fi
CROSSOP_AV="(untested)"
if grep -aq 'CROSS-OP' "$EVIDENCE_DIR/av-matrix-before.log" 2>/dev/null; then
  if awk '/CROSS-OP/{f=1} f && / write /{print; exit}' "$EVIDENCE_DIR/av-matrix-before.log" | grep -q ALLOW; then
    CROSSOP_AV="open"
  else
    CROSSOP_AV="closed"
  fi
fi
SHM_IN_BKD="(untested)"
if grep -aq ' /dev/shm ' "$EVIDENCE_DIR/buildkitd-mountinfo-shipped.log" 2>/dev/null; then
  SHM_IN_BKD="yes"
else
  SHM_IN_BKD="no"
fi
ROLLBACK="restored"
if [ "$(cat "$EVIDENCE_DIR/rollback-module-list.log" 2>/dev/null)" != "module-removed" ]; then
  ROLLBACK="failed"
fi
if [ "$(cat "$EVIDENCE_DIR/policy-sha-after-rollback.log" 2>/dev/null)" != \
     "$(cat "$EVIDENCE_DIR/policy-sha-before.log" 2>/dev/null)" ]; then
  ROLLBACK="sha-mismatch"
fi

printf 'R7-P21A-VERDICT=CREATE-GATE=%s;NEXT-TERMINAL=<%s>;ASSOCIATE=%s;CROSSOP-AV=%s;SHM-IN-BKD-NS=%s;ROLLBACK=%s\n' \
  "$CREATE_GATE" "$NEXT_TERMINAL" "$ASSOCIATE" "$CROSSOP_AV" "$SHM_IN_BKD" "$ROLLBACK"
exit 0
