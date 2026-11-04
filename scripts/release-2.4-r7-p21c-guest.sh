#!/usr/bin/env bash
#
# release-2.4-r7-p21c-guest.sh — the R7 P21-C devnode open-completion rung
# verification on a disposable ENFORCING openSUSE Tumbleweed VM (candidate
# RPM built at the P21-C SHA; the policy IS the candidate — no diagnostic
# module is loaded anywhere).
#
# MODE: acceptance evidence for the ONE sanctioned P21-C rung. NO production
# change, NO diagnostic grant, NO merge/RC/tag. The candidate policy carries
# the P21-B devnode shape PLUS exactly one new rule:
#
#   type docker_helper_devnode_t;                                   (bare)
#   type_transition docker_helper_buildkitd_t tmpfs_t:file
#         docker_helper_devnode_t "null"|"zero"|"full"|"random"|
#         "urandom"|"tty";                                          (six)
#   allow docker_helper_buildkitd_t docker_helper_devnode_t:file create;
#   allow docker_helper_buildkitd_t docker_helper_devnode_t:file
#         { read open };                          (the P21-C rung — ONE rule)
#   allow docker_helper_devnode_t tmpfs_t:filesystem associate;
#
# and NOTHING else changed relative to the P21-B policy (the bare memfd
# transition and the six P1-P6 runc_memfd allows are untouched).
#
# THE QUESTIONS (P21-C acceptance):
#   1. Authority delta: the compiled/loaded devnode_t surface is EXACTLY the
#      three reviewed rules (create toward it, the { read open }
#      open-completion pair toward it, associate from it); the pair is the
#      open-completion check's own shape (P4 memfd precedent), NOT a
#      content authority — every write-class permission stays denied for
#      EVERY subject, so every object of the type stays a zero-length
#      content-dead placeholder.
#   2. Cross-operation: the created placeholders carry NO categories
#      (measured s0), so MCS never separated them; the file-read
#      constraint admits read/open for BOTH operation categories; the
#      shared tmpfs venue (e.g. /dev/shm) is NOT the isolation relied on —
#      the channel is closed at the POLICY level because no subject can
#      write content into the type (the open-completion check maps
#      FMODE_WRITE -> FILE__WRITE, so even a writable creation openat
#      fails; setattr/truncate and PROT_WRITE mmap need ungranted
#      authority). A cross-operation reader reads an EMPTY object:
#      name-presence only, the surface the P21-B create rung already
#      carried. The guest records the constraint text, the venue
#      inventory, and the kernel-AV write-class rows (c1/c2/unconfined
#      DENY) as the evidence; a live in-domain probe attempt is recorded
#      with its expected BLOCKED outcome.
#   3. Former terminal eliminated: the P21-B measured terminal
#      (denied { read open }, comm="runc:[2:INIT]", tcontext=
#      docker_helper_devnode_t:s0, permissive=0, per-op
#      .../rootfs/dev/null path) must be ABSENT from both live windows.
#   4. Runtime advanced: the flow reaches the same runc:[2:INIT] stage and
#      stops at a NEW kernel boundary — at least one further full-structure
#      denied AVC record (permissive=0, scontext=buildkitd_t:s0:cX,
#      comm="runc:[2:INIT]") that is NOT the granted devnode { read open }
#      shape. The exact next terminal is OBSERVED, never pre-granted: the
#      evaluator accepts any real new-flow record and the REPORT names it.
#      Absence of AVCs alone is NEVER a passing outcome (BLOCKED).
#   5. Regression controls: the P20 runc_memfd_t:file create terminal, the
#      pre-B' tmpfs_t:file write terminal, and the associate denial stay
#      absent from both windows; the six filename transitions, the
#      arbitrary-basename control, and the memfd P1-P6 surface stay
#      byte-intact on the loaded policy.
#
# Machine verdict contract (the evaluator is scripts/
# release-2.4-r7-p21c-verdict.sh — fail-closed, row-by-row; the P21-B
# evaluator remains untouched as the historical P21-B instrument):
#   R7-P21C-VERDICT=DECISION=P21C-MEASURED|P21C-FAIL|P21C-BLOCKED;\
#     SCOPE=<six-names-ok|not-established>;\
#     OPEN-COMPLETION=<eliminated|live|not-established>;\
#     MEMFD=<intact|regressed>;CROSSOP-CONTENT=<closed|open>;\
#     NEXT-TERMINAL=<...>

set -uo pipefail

ARTIFACT="${R7_ARTIFACT:?R7_ARTIFACT required}"
ARTIFACT_SHA="${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log()  { printf '[r7-p21c] %s\n' "$*"; }
fail() { printf '[r7-p21c] FAILED: %s\n' "$*" >&2; exit 1; }

EVIDENCE_DIR="${R7_EVIDENCE_DIR:-/tmp/r7-p21c-evidence}"
mkdir -p "$EVIDENCE_DIR"
STATE_DIR=/tmp/r7-p21c-state
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
cap p21c-se-status 14 bash -c 'sestatus; echo ---; getenforce; id -Z'
cat /etc/os-release >"$EVIDENCE_DIR/os-release.txt" 2>&1
grep -qi 'opensuse tumbleweed' "$EVIDENCE_DIR/os-release.txt" || fail "not openSUSE Tumbleweed"
cap p21c-platform 8 bash -c 'uname -a'
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
sha256sum "$ARTIFACT" > "$EVIDENCE_DIR/candidate-rpm-sha256.log"
log "candidate RPM sha256: $(cat "$EVIDENCE_DIR/candidate-rpm-sha256.log")"
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
  cap p21c-toolchain 6 timeout 300 zypper --non-interactive install -y gcc libselinux-devel
fi
command -v gcc >/dev/null 2>&1 || fail "gcc unavailable"

# (1) TRANSITION SCOPE: the loaded transitions keyed on (buildkitd_t, tmpfs_t).
cap p21c-transitions 30 bash -c 'sesearch -T -s docker_helper_buildkitd_t -t tmpfs_t'
# (2) MEMFD REGRESSION (static): the memfd surface must be EXACTLY the six
# P1-P6 rules with NO create.
cap p21c-memfd-allows 20 bash -c 'sesearch -A -s docker_helper_buildkitd_t -t docker_helper_runc_memfd_t'
# (3) AUTHORITY AUDIT: the FULL surface of the type — every subject, every
# direction, no attribute expansion possible (attribute-free). After the
# P21-C rung: as TARGET exactly the create singleton and the { read open }
# open-completion pair; as SOURCE exactly the associate singleton.
cap p21c-devnode-subj 20 bash -c 'echo "# sesearch -A -s docker_helper_devnode_t (the associate singleton is the ONLY subject authority)"; sesearch -A -s docker_helper_devnode_t'
cap p21c-devnode-target 20 bash -c 'echo "# sesearch -A -t docker_helper_devnode_t (the create singleton and the P21-C { read open } pair are the ONLY target authorities)"; sesearch -A -t docker_helper_devnode_t'
cap p21c-devnode-attrs 10 seinfo -x -t docker_helper_devnode_t
cap p21c-devnode-fs 20 bash -c 'echo "# sesearch -A -s docker_helper_devnode_t -c filesystem"; sesearch -A -s docker_helper_devnode_t -c filesystem'
# The standing tmpfs_t surface must be unchanged (no tmpfs_t:file grant).
cap p21c-bkd-tmpfs 40 bash -c 'sesearch -A -s docker_helper_buildkitd_t -t tmpfs_t'
# Constraints for the record (the cross-operation read constraint lives here).
cap p21c-constraints-file 20 seinfo --constrain file
cap p21c-constraints-fs 20 seinfo --constrain filesystem
cap p21c-fsuse 12 bash -c 'seinfo --fs_use | grep -E "tmpfs|shm|mqueue"'
cap p21c-defaults 8 seinfo --default file
sha256sum /sys/fs/selinux/policy | awk '{print $1}' > "$EVIDENCE_DIR/policy-sha.log"
log "candidate loaded policy sha256: $(cat "$EVIDENCE_DIR/policy-sha.log")"
touch "$STATE_DIR/sec3"
fi

# ============================================================================
# Section 4: kernel-decision helpers
# ============================================================================
if [ ! -x "$EVIDENCE_DIR/p21c_create_probe" ]; then
log "=== section 4: kernel-decision helpers build ==="
cat > "$EVIDENCE_DIR/p21c_create_probe.c" <<'CEOF'
/* p21c_create_probe.c — security_compute_create(_name)_raw on the LOADED
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
			"usage: p21c_create_probe <source-ctx> <target-ctx> <class> [name [more triples]]\n");
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
gcc -O2 -o "$EVIDENCE_DIR/p21c_create_probe" "$EVIDENCE_DIR/p21c_create_probe.c" -lselinux -ldl \
  || fail "p21c_create_probe build failed"

cat > "$EVIDENCE_DIR/p21c_av_probe.c" <<'CEOF'
/* p21c_av_probe.c — kernel-decision matrix via security_compute_av_raw. */
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
		fprintf(stderr, "usage: p21c_av_probe <source-ctx> <target-ctx> <class>\n");
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
gcc -O2 -o "$EVIDENCE_DIR/p21c_av_probe" "$EVIDENCE_DIR/p21c_av_probe.c" -lselinux \
  || fail "p21c_av_probe build failed"
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
  # The matrix the gate evaluator validates row-by-row (16 required rows):
  # all six basenames for BOTH operation categories (the diversion), the
  # arbitrary-basename control and the name=NULL (memfd) control for BOTH
  # categories (the bare transition), and the unconfined controls.
  "$EVIDENCE_DIR/p21c_create_probe" \
    "$BKD_CTX" "$TMPFS_CTX" file null \
    "$BKD_CTX" "$TMPFS_CTX" file zero \
    "$BKD_CTX" "$TMPFS_CTX" file full \
    "$BKD_CTX" "$TMPFS_CTX" file random \
    "$BKD_CTX" "$TMPFS_CTX" file urandom \
    "$BKD_CTX" "$TMPFS_CTX" file tty \
    "$BKD_C2" "$TMPFS_CTX" file null \
    "$BKD_C2" "$TMPFS_CTX" file zero \
    "$BKD_C2" "$TMPFS_CTX" file full \
    "$BKD_C2" "$TMPFS_CTX" file random \
    "$BKD_C2" "$TMPFS_CTX" file urandom \
    "$BKD_C2" "$TMPFS_CTX" file tty \
    "$BKD_CTX" "$TMPFS_CTX" file someothername \
    "$BKD_CTX" "$TMPFS_CTX" file - \
    "$BKD_C2" "$TMPFS_CTX" file someothername \
    "$BKD_C2" "$TMPFS_CTX" file - \
    "$UNCONF_CTX" "$TMPFS_CTX" file null \
    "$UNCONF_CTX" "$TMPFS_CTX" file - \
    > "$EVIDENCE_DIR/create-matrix-$1.log" 2>&1
  cat "$EVIDENCE_DIR/create-matrix-$1.log"
}

av_matrix() { # <suffix>
  {
    echo "== buildkitd_t:s0:c1 -> docker_helper_devnode_t:s0 =="
    "$EVIDENCE_DIR/p21c_av_probe" "$BKD_CTX" "$DEVNODE" file
    echo "== CROSS-OP: buildkitd_t:s0:c2 -> docker_helper_devnode_t:s0 =="
    "$EVIDENCE_DIR/p21c_av_probe" "$BKD_C2" "$DEVNODE" file
    echo "== unconfined_t -> docker_helper_devnode_t:s0 =="
    "$EVIDENCE_DIR/p21c_av_probe" "$UNCONF_CTX" "$DEVNODE" file
    echo "== FILESYSTEM ASSOCIATE rows =="
    echo "-- devnode_t -> tmpfs_t (the granted singleton) --"
    "$EVIDENCE_DIR/p21c_av_probe" "system_u:object_r:docker_helper_devnode_t:s0" "$TMPFS_CTX" filesystem
    echo "-- runc_memfd_t -> tmpfs_t (must stay denied) --"
    "$EVIDENCE_DIR/p21c_av_probe" "$MEMFD" "$TMPFS_CTX" filesystem
    echo "-- tmpfs_t -> tmpfs_t (control) --"
    "$EVIDENCE_DIR/p21c_av_probe" "system_u:object_r:tmpfs_t:s0" "$TMPFS_CTX" filesystem
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
# Section 6: cross-operation channel evidence (policy-level, not namespace)
# ============================================================================
if [ -f "$STATE_DIR/sec6" ]; then log "phase marker: section 6 done; skipping"; else
log "=== section 6: cross-operation channel evidence ==="
# The venues a same-named creation could land in (the filename transitions
# are name-keyed, not path-keyed — the recorded E1 limitation).
cap p21c-host-venues 20 bash -c 'ls -ldZ /dev/shm /dev/mqueue /run/initramfs /tmp /var/tmp 2>&1'
# The file-class constraint text (the read/open admission for both
# categories over an s0 object is the constraint's own decision; the
# kernel-AV matrix rows above carry the c1/c2 verdicts).
cap p21c-crossop-constraint 40 bash -c 'seinfo --constrain file | sed -n 1,40p'
# The kernel-AV write-class rows for the SHARED-CHANNEL question: every
# subject that could write content into a devnode_t object. Already
# captured in av-matrix-before.log; restate the write-class subset with an
# explicit section banner so the evidence file is self-contained.
{
  echo "== CROSS-OP CHANNEL: write-class kernel decisions (c1, c2, unconfined) =="
  echo "-- buildkitd_t:s0:c1 -> devnode_t (write/append/setattr/map must be DENY) --"
  "$EVIDENCE_DIR/p21c_av_probe" "$BKD_CTX" "$DEVNODE" file | grep -E '  (write|append|setattr|map) '
  echo "-- CROSS-OP buildkitd_t:s0:c2 -> devnode_t (write/append/setattr/map must be DENY) --"
  "$EVIDENCE_DIR/p21c_av_probe" "$BKD_C2" "$DEVNODE" file | grep -E '  (write|append|setattr|map) '
  echo "-- unconfined_t -> devnode_t (ALL must be DENY) --"
  "$EVIDENCE_DIR/p21c_av_probe" "$UNCONF_CTX" "$DEVNODE" file | grep -E '  (write|append|setattr|map) '
} > "$EVIDENCE_DIR/p21c-crossop-write.log" 2>&1
cat "$EVIDENCE_DIR/p21c-crossop-write.log"
# Live in-domain probe attempt (the mcs-audit precedent): a test process in
# the ACTUAL buildkitd domain is expected BLOCKED; the attempt and its
# denial are recorded, never a pass condition.
if OUT="$(runcon -r system_r -t docker_helper_buildkitd_t -l s0:c2 id -Z 2>"$EVIDENCE_DIR/runcon-bkd.err")"; then
  log "live probe: buildkitd-domain test process started ($OUT) — recording, not relying on it"
  printf '%s\n' "$OUT" > "$EVIDENCE_DIR/runcon-bkd.ok"
else
  log "live probe: buildkitd-domain test process DENIED (expected; the kernel-AV matrix carries the proof)"
fi
avc_tail p21c-runcon-avc || true
touch "$STATE_DIR/sec6"
fi

# ============================================================================
# Section 7: live flow probes (the enforcing runtime; two operations)
# ============================================================================
run_one_build() { # <tag> <session-token>
  local tag="$1" token="$2"
  # The build goes through the HTTP API so the daemon operation id is
  # captured verbatim in the evidence (the CLI streams logs only).
  local RESP="$EVIDENCE_DIR/build-start-$tag.json"
  local CODE
  CODE="$(curl --silent --max-time 10 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    -d '{"context":"ctx","dockerfile":"Dockerfile","image":"uat-p21c:'"$tag"'"}' \
    -o "$RESP" -w '%{http_code}' http://localhost/build)" || true
  local OP
  OP="$(grep -oE '"operation_id": *"[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"operation_id": *"//;s/"$//')"
  printf '%s\n' "$OP" > "$EVIDENCE_DIR/operation-id-$tag.log"
  log "build $tag http=$CODE operation_id=$OP"
  [ -n "$OP" ] || { log "build $tag: no operation id (http $CODE)"; return 1; }
  local STATUS=""
  for _ in $(seq 1 400); do
    STATUS="$(curl --silent --max-time 2 \
      --unix-socket "$DH_SOCK" -H "Authorization: Bearer $token" \
      "http://localhost/operations/$OP" 2>/dev/null || true)"
    case "$STATUS" in
      *'"succeeded"'*|*'"failed"'*) break ;;
    esac
    sleep 0.05
  done
  printf '%s\n' "$STATUS" > "$EVIDENCE_DIR/build-status-$tag.json"
  curl --silent --max-time 2 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $token" \
    "http://localhost/operations/$OP/logs?offset=0" \
    > "$EVIDENCE_DIR/build-$tag.log" 2>&1 || true
  log "build $tag status: $(printf '%s' "$STATUS" | grep -oE '"(status|result_code)":"[^"]*"' | tr '\n' ' ')"
  return 0
}

make_session_build() { # <tag>
  local tag="$1"
  local WS="$PRINCIPAL_HOME/r7-p21c-ws-$tag"
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

if [ -f "$STATE_DIR/sec7" ]; then log "phase marker: section 7 done; skipping"; else
log "=== section 7: live flow probes (candidate policy) ==="
for _ in $(seq 1 50); do
  [ -S "$DH_SOCK" ] && curl --silent --fail --max-time 1 \
    --unix-socket "$DH_SOCK" http://localhost/health >/dev/null 2>&1 && break
  sleep 0.2
done
[ -n "$ADMIN_TOKEN" ] || fail "admin token unreadable; the live proof cannot run"
make_session_build c1
avc_tail p21c-avc-c1
make_session_build c2
avc_tail p21c-avc-c2
# The terminal sections and the regression controls, from BOTH windows.
# The devnode-terminal section carries EVERY runc:[2:INIT] record of both
# windows: the evaluator requires the P21-B { read open } shape ABSENT
# from it, and the next-terminal section requires at least one further
# real record that is NOT that shape.
{
  echo "== devnode-terminal runc-init AVCs (both windows) =="
  grep -ah 'runc:\[2:INIT\]' "$EVIDENCE_DIR/p21c-avc-c1.log" "$EVIDENCE_DIR/p21c-avc-c2.log" 2>/dev/null | head -30
  echo "== next-terminal runc-init AVCs (both windows) =="
  grep -ah 'runc:\[2:INIT\]' "$EVIDENCE_DIR/p21c-avc-c1.log" "$EVIDENCE_DIR/p21c-avc-c2.log" 2>/dev/null | head -30
  echo "== regression controls (must be EMPTY) =="
  echo "-- P20 terminal (runc_memfd_t:file create) --"
  grep -ah 'docker_helper_runc_memfd_t.*tclass=file' "$EVIDENCE_DIR/p21c-avc-c1.log" "$EVIDENCE_DIR/p21c-avc-c2.log" 2>/dev/null | grep -a '{ create }' | head -4
  echo "-- pre-B terminal (tmpfs_t:file write) --"
  grep -ah 'tcontext=system_u:object_r:tmpfs_t:s0 tclass=file' "$EVIDENCE_DIR/p21c-avc-c1.log" "$EVIDENCE_DIR/p21c-avc-c2.log" 2>/dev/null | grep -a '{ write }' | head -4
  echo "-- associate denials (must be EMPTY — the singleton is granted) --"
  grep -ah 'denied  { associate }' "$EVIDENCE_DIR/p21c-avc-c1.log" "$EVIDENCE_DIR/p21c-avc-c2.log" 2>/dev/null | head -4
} > "$EVIDENCE_DIR/p21c-terminals.log" 2>&1
cat "$EVIDENCE_DIR/p21c-terminals.log"
touch "$STATE_DIR/sec7"
fi

# ============================================================================
# Machine verdict — the standalone fail-closed evaluator is the single
# authority (mirrors the P21-B guest/driver contract): the guest only runs
# it and records its verdict; the driver gates on DECISION=P21C-MEASURED.
# The P21-B evaluator stays untouched (the historical P21-B instrument).
# ============================================================================
if [ -r /tmp/r7-diag/release-2.4-r7-p21c-verdict.sh ]; then
  bash /tmp/r7-diag/release-2.4-r7-p21c-verdict.sh "$EVIDENCE_DIR" \
    > "$EVIDENCE_DIR/p21c-verdict.log" 2>&1
  VERDICT_RC=$?
  log "p21c evaluator exit=$VERDICT_RC"
  cat "$EVIDENCE_DIR/p21c-verdict.log"
else
  log "verdict evaluator missing from /tmp/r7-diag; recording BLOCKED"
  printf 'R7-P21C-VERDICT=DECISION=P21C-BLOCKED;REASON=evaluator-script-missing\n' \
    > "$EVIDENCE_DIR/p21c-verdict.log"
  cat "$EVIDENCE_DIR/p21c-verdict.log"
fi
exit 0
