#!/usr/bin/env bash
#
# release-2.4-r7-bprime-guest.sh — the R7 B′ isolated memfd type-transition
# proof on a disposable ENFORCING openSUSE Tumbleweed VM (RPM candidate).
#
# MODE: architecture validation. The EXPERIMENTAL policy module below is
# loaded ONLY on this disposable VM and is REMOVED (with byte-identical
# policy restoration proven) before the script exits. NO production policy
# change, NO production Go/OCI change, NO merge/RC/tag, and — explicitly —
# NO file:write / execute / map permission anywhere (the experimental type
# is deny-all; the only rule is ONE type_transition), and NO diagnostic
# permission to enter docker_helper_buildkitd_t from unconfined_t (the
# real buildkit-runc is exercised through the production launch chain).
#
# THE EXPERIMENT (B′): kernel v7.2 labels memfd inodes with NO creation-time
# label (the loaded policy lacks the memfd_class policycap and the
# memfd_file class, so selinux_inode_init_security_anon early-returns); the
# label is computed by the SECURITY_FS_USE_TRANS branch of
# inode_doinit_with_dentry as security_transition_sid(creator_sid,
# tmpfs_t:s0, file) — the superblock-keyed transition. The experiment loads:
#
#   type docker_helper_runc_memfd_t;
#   type_transition docker_helper_buildkitd_t tmpfs_t:file docker_helper_runc_memfd_t;
#
# and proves or disproves, on the REAL runc execution:
#   - the memfd write denial re-keys from tmpfs_t:file to the new type;
#   - the rule does NOT re-label pathname-created objects (parent-dir-keyed
#     creation transitions: exec.fifo stays builder_runtime_t, state files
#     stay builder_state_t, unconfined's /dev/shm files stay user_tmp_t);
#   - both operation categories (c1/c2 where the allocator emits them) get
#     the SAME type:s0 label — NOT per-operation MCS isolation (recorded as
#     such, never claimed otherwise);
#   - the deny-all type keeps every permission denied for every subject
#     (kernel-AV matrix), so nothing but the LABEL changes until a separate
#     grant decision.
#
# If the live memfd label does NOT become the new type -> BPRIME=FAIL.
# If objects outside the memfd population re-label -> the full blast radius
# is recorded and the verdict is never "narrow".
#
# Verdict contract:
#   R7-BPRIME-VERDICT=LIVE-LABEL=<observed|none>;OTHER-RELABEL=<none|list>;\
#     ROLLBACK=<restored|failed>;DECISION=BPRIME-VIABLE|BPRIME-FAIL|BPRIME-BLOCKED
#
# Env inputs (guest side):
#   R7_ARTIFACT / R7_ARTIFACT_SHA256  the exact candidate RPM + digest
#   R7_EVIDENCE_DIR                   guest evidence directory

set -uo pipefail

ARTIFACT="${R7_ARTIFACT:?R7_ARTIFACT required}"
ARTIFACT_SHA="${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log()  { printf '[r7-bprime] %s\n' "$*"; }
fail() { printf '[r7-bprime] FAILED: %s\n' "$*" >&2; exit 1; }

EVIDENCE_DIR="${R7_EVIDENCE_DIR:-/tmp/r7-bprime-evidence}"
mkdir -p "$EVIDENCE_DIR"
STATE_DIR=/tmp/r7-bprime-state
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
    tail -n 600 /var/log/audit/audit.log >> "$EVIDENCE_DIR/$1.log" 2>/dev/null || true
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
cap se-status 14 bash -c 'sestatus; echo ---; getenforce; id -Z'
cat /etc/os-release >"$EVIDENCE_DIR/os-release.txt" 2>&1
grep -qi 'opensuse tumbleweed' "$EVIDENCE_DIR/os-release.txt" || fail "not openSUSE Tumbleweed"
cap platform 8 bash -c 'uname -a'
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

# ============================================================================
# Section 3: tooling + PRE-state inventory (baseline policy)
# ============================================================================
if [ -f "$STATE_DIR/sec3" ]; then log "phase marker: section 3 done; skipping"; else
log "=== section 3: tooling + baseline inventory ==="
command -v sesearch >/dev/null 2>&1 || { timeout 180 zypper --non-interactive install -y setools-console >/dev/null 2>&1 || true; }
if ! command -v gcc >/dev/null 2>&1 || ! command -v strace >/dev/null 2>&1; then
  cap toolchain-install 6 timeout 300 zypper --non-interactive install -y gcc libselinux-devel strace
fi
command -v gcc >/dev/null 2>&1 || fail "gcc unavailable"
command -v strace >/dev/null 2>&1 || fail "strace unavailable"
# The COMPLETE fs_use table (the option-A breadth inventory input).
cap fsuse-full 40 seinfo --fs_use
cap class-defaults 12 seinfo --default file
# Baseline: NO type transition from buildkitd_t on tmpfs_t (the B′ delta).
cap baseline-transitions 20 bash -c 'sesearch -T -s docker_helper_buildkitd_t; echo ---; sesearch -T -t tmpfs_t -s docker_helper_buildkitd_t; echo "(empty above = no baseline transition)"'
sha256sum /sys/fs/selinux/policy | awk '{print $1}' > "$EVIDENCE_DIR/policy-sha-before.log"
log "baseline policy sha256: $(cat "$EVIDENCE_DIR/policy-sha-before.log")"
touch "$STATE_DIR/sec3"
fi

# ============================================================================
# Section 4: the create-decision helper (security_compute_create_raw)
# ============================================================================
if [ ! -x "$EVIDENCE_DIR/create_probe" ]; then
log "=== section 4: create-decision helper build ==="
cat > "$EVIDENCE_DIR/create_probe.c" <<'CEOF'
/* create_probe.c — R7 B′ preliminary create-decision matrix.
 * security_compute_create_raw on the LOADED policy: the kernel's own
 * would-be label for a creation transition. PRELIMINARY evidence only —
 * never a substitute for the live labeling proof. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <selinux/selinux.h>

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "usage: create_probe <source-ctx> <target-ctx> <class> [more triples]\n");
		return 2;
	}
	for (int i = 1; i + 3 <= argc; i += 3) {
		char *out = NULL;
		security_class_t cl = string_to_security_class(argv[i + 2]);
		if (!cl) {
			printf("CREATE %s x %s x %s -> CLASS-UNKNOWN\n",
			       argv[i], argv[i + 1], argv[i + 2]);
			continue;
		}
		int rc = security_compute_create_raw(argv[i], argv[i + 1], cl, &out);
		if (rc == 0 && out)
			printf("CREATE %s x %s x %s -> %s\n",
			       argv[i], argv[i + 1], argv[i + 2], out);
		else
			printf("CREATE %s x %s x %s -> ERR rc=%d errno=%d (%s)\n",
			       argv[i], argv[i + 1], argv[i + 2], rc, errno,
			       strerror(errno));
		free(out);
	}
	return 0;
}
CEOF
gcc -O2 -o "$EVIDENCE_DIR/create_probe" "$EVIDENCE_DIR/create_probe.c" -lselinux \
  || fail "create_probe build failed"
log "create-decision helper built"
fi

# The future-permission kernel-decision matrix (security_compute_av_raw):
# what WOULD be gated once write/execute/map/setattr grants are considered
# for the experimental type. Evidence for the MCS-isolation question (§4):
# every decision is a TE denial today; the matrix shows which of them the
# loaded mlsconstrain would NOT gate once an allow exists (h1 dom h2 passes
# for an s0 target — recorded honestly, never claimed as isolation).
if [ ! -x "$EVIDENCE_DIR/av_probe" ]; then
cat > "$EVIDENCE_DIR/av_probe.c" <<'CEOF'
/* av_probe.c — kernel-decision matrix via security_compute_av_raw. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: av_probe <source-ctx> <target-ctx>\n");
		return 2;
	}
	const char *perms[] = { "write", "execute", "map", "setattr",
	                        "open", "read", "append", NULL };
	security_class_t cl = string_to_security_class("file");
	struct av_decision avd;
	for (int i = 1; i + 1 < argc; i += 2) {
		printf("== %s -> %s (class file)\n", argv[i], argv[i + 1]);
		for (int p = 0; perms[p]; p++) {
			access_vector_t bit = string_to_av_perm(cl, perms[p]);
			if (!bit) { printf("  %-8s UNKNOWN-PERM\n", perms[p]); continue; }
			int rc = security_compute_av_raw(argv[i], argv[i + 1], cl,
			                                 bit, &avd);
			if (rc)
				printf("  %-8s ERR rc=%d errno=%d\n", perms[p], rc, errno);
			else
				printf("  %-8s %s (allowed=0x%x decided=0x%x)\n",
				       perms[p],
				       (avd.allowed & bit) ? "ALLOW" : "DENY",
				       (unsigned)avd.allowed, (unsigned)avd.decided);
		}
	}
	return 0;
}
CEOF
gcc -O2 -o "$EVIDENCE_DIR/av_probe" "$EVIDENCE_DIR/av_probe.c" -lselinux \
  || fail "av_probe build failed"
log "kernel-decision helper built"
fi

av_matrix() { # <suffix> — the future-permission matrix on the loaded policy
  "$EVIDENCE_DIR/av_probe" \
    "$BKD_CTX" "system_u:object_r:docker_helper_runc_memfd_t:s0" \
    "$BKD_C2" "system_u:object_r:docker_helper_runc_memfd_t:s0" \
    "$BKD_CTX" "system_u:object_r:docker_helper_runc_memfd_t:s0:c1" \
    > "$EVIDENCE_DIR/av-matrix-$1.log" 2>&1
  cat "$EVIDENCE_DIR/av-matrix-$1.log"
}

BKD_CTX="system_u:system_r:docker_helper_buildkitd_t:s0:c1"
BKD_C2="system_u:system_r:docker_helper_buildkitd_t:s0:c2"
TMPFS_CTX="system_u:object_r:tmpfs_t:s0"
UNCONF_CTX="unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
RT_CTX="system_u:object_r:docker_helper_builder_runtime_t:s0:c1"
STATE_CTX="system_u:object_r:docker_helper_builder_state_t:s0:c1"
NEW="docker_helper_runc_memfd_t"

create_matrix() { # <suffix> — the fixed create-decision matrix
  "$EVIDENCE_DIR/create_probe" \
    "$BKD_CTX" "$TMPFS_CTX" file \
    "$BKD_C2" "$TMPFS_CTX" file \
    "$UNCONF_CTX" "$TMPFS_CTX" file \
    "$BKD_CTX" "$RT_CTX" file \
    "$BKD_CTX" "$STATE_CTX" file \
    "$BKD_CTX" "$TMPFS_CTX" dir \
    "$BKD_CTX" "$TMPFS_CTX" fifo_file \
    "$BKD_CTX" "$TMPFS_CTX" lnk_file \
    > "$EVIDENCE_DIR/create-matrix-$1.log" 2>&1
  cat "$EVIDENCE_DIR/create-matrix-$1.log"
}

# ============================================================================
# Section 5: PRE-load decision matrix (baseline: no transition exists)
# ============================================================================
if [ -f "$STATE_DIR/sec5" ]; then log "phase marker: section 5 done; skipping"; else
log "=== section 5: PRE-load create-decision matrix (baseline) ==="
create_matrix before
touch "$STATE_DIR/sec5"
fi

# ============================================================================
# Section 6: the EXPERIMENTAL module (disposable VM only; rollback proven)
# ============================================================================
if [ -f "$STATE_DIR/sec6" ]; then log "phase marker: section 6 done; skipping"; else
log "=== section 6: experimental module load (deny-all type + ONE transition) ==="
cat > "$EVIDENCE_DIR/docker_helper_r7bprime.cil" <<'CEOF'
; R7 B′ EXPERIMENTAL MODULE — disposable VM only.
; ONE type (deny-all: no allow rule anywhere references it) and ONE
; type_transition. No write/execute/map/setattr permission is added; no
; attribute membership (deliberately NOT file_type — the base policy's
; attribute rules must not silently apply); no MCS/range change.
(type docker_helper_runc_memfd_t)
(typetransition docker_helper_buildkitd_t tmpfs_t file docker_helper_runc_memfd_t)
CEOF
sha256sum "$EVIDENCE_DIR/docker_helper_r7bprime.cil" > "$EVIDENCE_DIR/module-sha"
semodule -i "$EVIDENCE_DIR/docker_helper_r7bprime.cil" || fail "experimental module load failed"
log "experimental module loaded"
cap module-listed 6 bash -c 'semodule -l | grep -i bprime || semodule -lfull 2>/dev/null | grep -i bprime || echo "(module name not listed — check loaded policy below)"'
cap loaded-transition 10 bash -c 'sesearch -T -s docker_helper_buildkitd_t -t tmpfs_t -c file; echo ---ALL---; sesearch -T -t tmpfs_t -s docker_helper_buildkitd_t'
# THE CRITICAL NEGATIVE: the new type must be deny-all — zero allow rules.
# Raw output only (an empty result is the EXPECTED pass shape; the header
# keeps the file non-empty for the fail-closed evaluator).
cap newtype-allows 20 bash -c 'echo "# sesearch -A -t docker_helper_runc_memfd_t (empty = deny-all)"; sesearch -A -t docker_helper_runc_memfd_t; echo "# sesearch -A -s docker_helper_runc_memfd_t (empty = no subject authority)"; sesearch -A -s docker_helper_runc_memfd_t'
# The type must carry NO attribute membership (deliberately not file_type).
cap newtype-attrs 10 bash -c 'seinfo -x -t docker_helper_runc_memfd_t'
sha256sum /sys/fs/selinux/policy | awk '{print $1}' > "$EVIDENCE_DIR/policy-sha-loaded.log"
log "loaded policy sha256: $(cat "$EVIDENCE_DIR/policy-sha-loaded.log")"
log "=== POST-load create-decision matrix ==="
create_matrix after
log "=== POST-load future-permission kernel-decision matrix (all-DENY expected; MCS-gating facts) ==="
av_matrix loaded
touch "$STATE_DIR/sec6"
fi

# ============================================================================
# Section 7: the LIVE production-chain proof (two builds; strace + AVCs)
# ============================================================================
run_one_build() { # <tag> <session-token> — one production-shape build + evidence
  local tag="$1" token="$2"
  local STRACE_LOG="$EVIDENCE_DIR/bprime-strace-$tag.log"
  : > "$STRACE_LOG"
  ( DOCKER_HELPER_SESSION_TOKEN="$token" docker-helper build ctx \
      --dockerfile Dockerfile --image "uat-bprime:$tag" \
      >"$EVIDENCE_DIR/build-$tag.log" 2>&1 ) &
  local BLD=$!
  local SPID=""
  for _ in $(seq 1 400); do
    local P; P="$(pgrep -x buildkitd | head -1 || true)"
    if [ -n "$P" ]; then
      strace -f -qq -tt -s 120 -y \
        -e trace=fsopen,fsconfig,fsmount,memfd_create,sendfile,write,fchmod,fchmodat,fchmodat2,fchown,fchownat,execve,openat,readlink,statfs,fstatfs,fcntl \
        -p "$P" -o "$STRACE_LOG" \
        2>"$EVIDENCE_DIR/bprime-strace-$tag.err" &
      SPID=$!
      log "strace attached to buildkitd pid $P (build $tag)"
      break
    fi
    kill -0 "$BLD" 2>/dev/null || break
    sleep 0.05
  done
  wait "$BLD"; local RC=$?
  [ -n "$SPID" ] && kill "$SPID" 2>/dev/null || true
  log "build $tag rc=$RC (terminal failure expected)"
  cap "build-$tag-tail" 6 tail -4 "$EVIDENCE_DIR/build-$tag.log"
  grep -aE 'memfd_create|fsopen|fsconfig|sendfile|write\(' "$STRACE_LOG" \
    > "$EVIDENCE_DIR/bprime-sequence-$tag.log" 2>/dev/null || true
  return $RC
}

if [ -f "$STATE_DIR/sec7" ]; then log "phase marker: section 7 done; skipping"; else
log "=== section 7: LIVE production-chain proof (experimental policy LOADED) ==="
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
if [ -z "$ADMIN_TOKEN" ]; then
  fail "admin token unreadable; the live proof cannot run"
fi
PRINCIPAL="${SUDO_USER:-}"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"

make_session_build() { # <tag> — one session + one build attempt; echoes the tag rc
  local tag="$1"
  local WS="$PRINCIPAL_HOME/r7-bprime-ws-$tag"
  rm -rf "$WS"; mkdir -p "$WS/ctx"
  cat > "$WS/ctx/Dockerfile" <<'EOF'
FROM alpine:3.24
RUN sleep 10
USER 65534:65534
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
    echo "skip"
    return 0
  fi
  docker-helper pull alpine:3.24 >"$EVIDENCE_DIR/pull-$tag.log" 2>&1 || true
  run_one_build "$tag" "$TOKEN" || true
  echo "done"
}

make_session_build c1
avc_tail bprime-avc-c1
make_session_build c2
avc_tail bprime-avc-c2

# The live memfd label + scope records, extracted from BOTH windows.
for t in c1 c2; do
  grep -a 'comm="buildkit-runc"' "$EVIDENCE_DIR/bprime-avc-$t.log" \
    | grep -aE 'tclass=(file|fifo_file|dir)\b' | head -14 \
    > "$EVIDENCE_DIR/bprime-runc-avc-$t.log" 2>/dev/null || true
  log "--- buildkit-runc AVCs ($t): first 8 ---"
  head -8 "$EVIDENCE_DIR/bprime-runc-avc-$t.log" 2>/dev/null | cut -c1-260 || true
done

# The deny-all verification ON THE LIVE SYSTEM: every permission toward the
# new type stays denied even for unconfined root (bare type, no attribute).
touch /dev/shm/bprime-probe 2>/dev/null || true
cat /dev/shm/bprime-probe >/dev/null 2>&1 || true
rm -f /dev/shm/bprime-probe
avc_tail bprime-avc-probe
grep -a 'runc_memfd_t' "$EVIDENCE_DIR/bprime-avc-probe.log" \
  > "$EVIDENCE_DIR/bprime-newtype-avc.log" 2>/dev/null || true
printf '(new-type AVCs above if any pathname object carried it — expected: none)\n' >> "$EVIDENCE_DIR/bprime-newtype-avc.log"
touch "$STATE_DIR/sec7"
fi

# ============================================================================
# Section 8: ROLLBACK (removal + byte-identical restoration proof)
# ============================================================================
if [ -f "$STATE_DIR/sec8" ]; then log "phase marker: section 8 done; skipping"; else
log "=== section 8: rollback (module removal + restoration proof) ==="
semodule -r docker_helper_r7bprime || fail "experimental module removal failed"
if semodule -l 2>/dev/null | grep -qi bprime; then
  printf 'module-still-loaded\n' > "$EVIDENCE_DIR/rollback-module-list.log"
else
  printf 'module-removed\n' > "$EVIDENCE_DIR/rollback-module-list.log"
fi
log "module removal: $(cat "$EVIDENCE_DIR/rollback-module-list.log")"
# Raw sesearch output (the header keeps the file non-empty for the
# fail-closed evaluator; ANY new-type line here is a rollback failure).
{
  echo "# sesearch -T -s docker_helper_buildkitd_t -t tmpfs_t -c file (empty = transition removed)"
  sesearch -T -s docker_helper_buildkitd_t -t tmpfs_t -c file
} > "$EVIDENCE_DIR/rollback-transition.log" 2>&1
sha256sum /sys/fs/selinux/policy | awk '{print $1}' > "$EVIDENCE_DIR/policy-sha-after-rollback.log"
log "post-rollback policy sha256: $(cat "$EVIDENCE_DIR/policy-sha-after-rollback.log")"
log "=== POST-rollback create-decision matrix (must equal the PRE matrix) ==="
create_matrix rollback
# END-TO-END restoration proof: a fresh build must fail exactly as before
# (the memfd write denial back at tmpfs_t:file).
PRINCIPAL="${SUDO_USER:-}"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
WS="$PRINCIPAL_HOME/r7-bprime-ws-rollback"
rm -rf "$WS"; mkdir -p "$WS/ctx"
printf 'FROM alpine:3.24\nRUN sleep 10\nUSER 65534:65534\n' > "$WS/ctx/Dockerfile"
chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
RESP="$EVIDENCE_DIR/session-response-rollback.json"
CODE="$(curl --silent --max-time 5 \
  --unix-socket "$DH_SOCK" -H "Authorization: Bearer $(cat /etc/docker-helper/admin.token)" \
  -H 'Content-Type: application/json' \
  -d "{\"workspace\":\"$WS\",\"principal\":\"$PRINCIPAL\"}" \
  -o "$RESP" -w '%{http_code}' http://localhost/sessions)" || true
TOKEN="$(grep -oE '"token": *"[^"]+"' "$RESP" 2>/dev/null | head -1 | sed 's/.*"token": *"//;s/"$//')"
if [ -n "$TOKEN" ]; then
  run_one_build rollback "$TOKEN" || true
  avc_tail bprime-avc-rollback
  grep -a 'comm="buildkit-runc"' "$EVIDENCE_DIR/bprime-avc-rollback.log" \
    | grep -a 'tclass=file' | head -4 \
    > "$EVIDENCE_DIR/bprime-rollback-avc.log" 2>/dev/null || true
  log "--- rollback buildkit-runc file AVCs (expect tmpfs_t again) ---"
  head -4 "$EVIDENCE_DIR/bprime-rollback-avc.log" 2>/dev/null | cut -c1-260 || true
else
  log "rollback verification build skipped (session create HTTP $CODE)"
fi
touch "$STATE_DIR/sec8"
fi

# ============================================================================
# Verdict — the fail-closed ten-check evaluator (precise identity
# classification, audit dedup, rollback proof). The evaluator is the single
# authority for the machine-readable verdict; the guest only records it.
# ============================================================================
bash /tmp/r7-diag/release-2.4-r7-bprime-verdict.sh "$EVIDENCE_DIR" \
  > "$EVIDENCE_DIR/bprime-verdict.log" 2>&1
VERDICT_RC=$?
log "bprime evaluator exit=$VERDICT_RC"
cat "$EVIDENCE_DIR/bprime-verdict.log"
exit 0

