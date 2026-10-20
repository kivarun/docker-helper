#!/usr/bin/env bash
#
# release-2.4-r7-exeseal-guest.sh — the R7 exeseal boundary probe on a
# disposable ENFORCING openSUSE Tumbleweed VM (RPM candidate). Forensic /
# architecture-decision evidence only: NO policy grants, NO production
# changes, NO capability or mount-permission changes.
#
# WHY THIS PROBE EXISTS: after the exec.fifo create+setattr corrective, the
# enforcing UAT terminal moved to runc v1.4.3's CloneSelfExe:
#
#   runc run failed: unable to create new parent process: unable to create
#   safe /proc/self/exe clone for runc init: copy binary:
#   write /memfd:runc_cloned:/proc/self/exe: permission denied
#
# with AVCs (UAT 39374170774 serials 1329/1330; S15 10315/10316):
#   scontext=...docker_helper_buildkitd_t:s0:c1 tcontext=...tmpfs_t:s0
#   tclass=file perm=write path=/memfd:runc_cloned:/proc/self/exe (deleted)
#
# runc's CloneSelfExe FIRST tries sealedOverlayfs (fsopen/fsconfig/fsmount
# new-mount-API overlay, lower-only, over the binary dir + the state dir) and
# falls back to a memfd clone only on overlay failure. runc logs the overlay
# failure at DEBUG level only, so the UAT record shows the memfd fallback's
# denial but not the overlay failure itself. This probe captures BOTH:
#
#   1. LIVE REAL-PATH TRACE: strace -f attached to the per-op buildkitd
#      daemon before the build reaches the RUN stage; the bundled
#      buildkit-runc (runc 1.4.3) child's full exeseal syscall sequence with
#      exact errnos (fsopen/fsconfig/fsmount/memfd_create/sendfile/write),
#      the runc process's SELinux context, CapEff, NoNewPrivs, user/mount
#      namespaces, and the build-window AVC records.
#   2. SOURCE-FAITHFUL C PROBE (kernel-side baseline, run as the unconfined
#      root shell): the exact sealedOverlayfs syscall sequence with
#      per-step errno — distinguishing kernel/userns capability failures
#      from SELinux denials by construction (unconfined = full SELinux
#      allows; a probe errno there is a KERNEL verdict); the same sequence
#      inside a fresh unprivileged user namespace (overlayfs-in-userns
#      support); the memfd_create/fgetfilecon/write/chmod/seal sequence;
#      and the memfd-vs-pathname labeling differential under an
#      s0:c1-level subject (runcon -l only — no domain transition).
#   3. LOADED-POLICY INVENTORY (read-only): policycaps (memfd_class),
#      the memfd_file/anon_inode class presence, every allow touching
#      tmpfs_t:file (the option-C authority inventory), type transitions
#      involving buildkitd_t, the file/dir/fifo_file constraints, and the
#      guest's tmpfs mount/label surface.
#
# Verdict contract (observational only — no policy verdict is implied):
#   R7-EXESEAL-VERDICT=OVERLAY=<live-errno-or-ok>;\
#     MEMFD-LABEL=<observed-label>;MEMFD-WRITE=<rc>;STRACE=<collected|absent>
#
# Env inputs (guest side):
#   R7_ARTIFACT / R7_ARTIFACT_SHA256  the exact candidate RPM + digest
#   R7_EVIDENCE_DIR                   guest evidence directory

set -uo pipefail

ARTIFACT="${R7_ARTIFACT:?R7_ARTIFACT required}"
ARTIFACT_SHA="${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log()  { printf '[r7-exeseal] %s\n' "$*"; }
fail() { printf '[r7-exeseal] FAILED: %s\n' "$*" >&2; exit 1; }

EVIDENCE_DIR="${R7_EVIDENCE_DIR:-/tmp/r7-exeseal-evidence}"
mkdir -p "$EVIDENCE_DIR"
STATE_DIR=/tmp/r7-exeseal-state
mkdir -p "$STATE_DIR"

cap() { # <name> <max-lines> <cmd...> — evidence capture never aborts the probe
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
    tail -n 400 /var/log/audit/audit.log >> "$EVIDENCE_DIR/$1.log" 2>/dev/null || true
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

DH_SOCK=/run/docker-helper/docker-helper.sock

[ "$(id -u)" = "0" ] || fail "must run as root"
[ -f "$ARTIFACT" ] || fail "artifact missing: $ARTIFACT"
now_sha="$(sha256sum "$ARTIFACT" | awk '{print $1}')"
[ "$now_sha" = "$ARTIFACT_SHA" ] || fail "artifact SHA mismatch (expected $ARTIFACT_SHA, got $now_sha)"

# ============================================================================
# Section 1: platform + SELinux enforcing proof
# ============================================================================
if [ -f "$STATE_DIR/sec1" ]; then
  log "phase marker: section 1 done; skipping"
else
  log "=== section 1: platform + SELinux state ==="
  ENF="$(getenforce 2>/dev/null || echo absent)"
  [ "$ENF" = "Enforcing" ] || fail "SELinux not enforcing (getenforce='$ENF')"
  cat /sys/kernel/security/lsm >"$EVIDENCE_DIR/lsm.txt" 2>&1 || true
  grep -qw selinux "$EVIDENCE_DIR/lsm.txt" || fail "selinux not an active LSM: $(cat "$EVIDENCE_DIR/lsm.txt")"
  cap se-status 14 bash -c 'sestatus; echo ---; getenforce; id -Z'
  cat /etc/os-release >"$EVIDENCE_DIR/os-release.txt" 2>&1
  grep -qi 'opensuse tumbleweed' "$EVIDENCE_DIR/os-release.txt" || fail "not openSUSE Tumbleweed"
  cap platform 20 bash -c 'uname -a; grep -E "^(MemTotal|model name)" /proc/meminfo /proc/cpuinfo 2>/dev/null | head -3'
  cap sysctls 10 bash -c 'sysctl vm.memfd_noexec vm.unprivileged_userns_clone user.max_user_namespaces 2>&1 || true'
  # Kernel config for the overlay/memfd/userns questions (read-only).
  cap kernel-config 30 bash -c '
    zgrep -hE "^CONFIG_(OVERLAY_FS|TMPFS_XATTR|TMPFS_POSIX_ACL|USER_NS|MEMFD|SECURITY_SELINUX|FS_POSIX_ACL)=" /proc/config.gz 2>/dev/null || true
    grep -hE "^CONFIG_(OVERLAY_FS|TMPFS_XATTR|TMPFS_POSIX_ACL|USER_NS|MEMFD|SECURITY_SELINUX|FS_POSIX_ACL)=" "/boot/config-$(uname -r)" 2>/dev/null || true'
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
[ -n "$PRINCIPAL" ] && [ "$PRINCIPAL" != "root" ] || fail "cannot derive non-root principal (SUDO_USER='$SUDO_USER')"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
[ -n "$PRINCIPAL_HOME" ] && [ -d "$PRINCIPAL_HOME" ] || fail "principal home not found: $PRINCIPAL_HOME"
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
# Section 3: loaded-policy + filesystem inventory (read-only)
# ============================================================================
if [ -f "$STATE_DIR/sec3" ]; then log "phase marker: section 3 done; skipping"; else
log "=== section 3: loaded-policy + filesystem inventory ==="
command -v sesearch >/dev/null 2>&1 || { timeout 180 zypper --non-interactive install -y setools-console >/dev/null 2>&1 || true; }
# The memfd labeling capability and class presence (the option-B kernel gate).
cap policycaps 30 seinfo --polcap
cap memfd-class 10 bash -c 'seinfo -x -c memfd_file 2>&1; seinfo -x -c anon_inode 2>&1; echo ---; sesearch -A -c memfd_file 2>&1 | head -5; sesearch -A -c anon_inode 2>&1 | head -5'
# The tmpfs labeling model on the LOADED policy: the fs_use behavior, any
# genfscon fallback, and the per-class user/role/range defaults that govern
# object creation MLS (source vs target range).
cap fsuse-genfs 14 bash -c 'seinfo --fs_use tmpfs 2>&1; echo ---; seinfo --fs_use overlay 2>&1; echo ---; seinfo --genfscon tmpfs 2>&1 | head -4; seinfo --genfscon overlay 2>&1 | head -4'
cap class-defaults 20 bash -c 'seinfo --default file 2>&1; seinfo --default dir 2>&1; seinfo --default fifo_file 2>&1; seinfo --default filesystem 2>&1'
# Option-C authority inventory: EVERY allow that touches tmpfs_t:file and
# tmpfs_t:dir, and any type transition into/out of tmpfs_t.
cap tmpfs-allows 60 bash -c 'sesearch -A -t tmpfs_t -c file; echo ---DIR---; sesearch -A -t tmpfs_t -c dir; echo ---FS---; sesearch -A -t tmpfs_t -c filesystem'
cap tmpfs-transitions 30 bash -c 'sesearch -T -t tmpfs_t; echo ---FROM---; sesearch -T -s docker_helper_buildkitd_t'
cap buildkitd-tmpfs 12 bash -c 'sesearch -A -s docker_helper_buildkitd_t -t tmpfs_t || true; echo "(buildkitd_t -> tmpfs_t allows listed above, if any)"'
cap tmpfs-attrs 8 seinfo -x -t tmpfs_t
# The constraint expressions that govern the relevant classes.
cap constraints-file 40 seinfo --constrain file
cap constraints-dir 40 seinfo --constrain dir
cap constraints-fifo 40 seinfo --constrain fifo_file
cap constraints-fs 40 seinfo --constrain filesystem
# The guest tmpfs mount/label surface (what a generic tmpfs_t authority covers).
cap tmpfs-surface 40 bash -c 'findmnt -t tmpfs -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1; echo ---; ls -Zd /run /dev/shm /tmp 2>&1'
cap tmpfs-typed-files 30 bash -c 'find /run /dev/shm -maxdepth 2 -context "*tmpfs_t*" 2>/dev/null | head -20 || true; echo "(tmpfs_t-labeled live objects above, if any)"'
# Toolchain for the source-faithful C probe (gcc + libselinux, guest-side).
log "=== section 3b: probe toolchain ==="
if ! command -v gcc >/dev/null 2>&1 || ! command -v strace >/dev/null 2>&1; then
  cap toolchain-install 6 timeout 300 zypper --non-interactive install -y gcc libselinux-devel strace
fi
command -v gcc >/dev/null 2>&1 || fail "gcc unavailable for the C probe"
command -v strace >/dev/null 2>&1 || fail "strace unavailable for the live trace"
touch "$STATE_DIR/sec3"
fi

# ============================================================================
# Section 4: the C probe source (source-faithful; guest-side build)
# ============================================================================
if [ ! -x "$EVIDENCE_DIR/exeseal_probe" ]; then
log "=== section 4: exeseal C probe build ==="
cat > "$EVIDENCE_DIR/exeseal_probe.c" <<'CEOF'
/* exeseal_probe.c — R7 exeseal boundary probe (forensic evidence only).
 * Replicates the runc v1.4.3 libcontainer/exeseal syscall sequences
 * step-by-step and prints each step's result and errno verbatim. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <selinux/selinux.h>

#ifndef __NR_fsopen
#define __NR_fsopen 430
#endif
#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif
#ifndef __NR_fsmount
#define __NR_fsmount 432
#endif
#define FSOPEN_CLOEXEC 0x1
#define FSMOUNT_CLOEXEC 0x1
#define FSCONFIG_SET_STRING 1
#define FSCONFIG_CMD_CREATE 6
#define F_SEAL_SEAL 0x1
#define F_SEAL_SHRINK 0x2
#define F_SEAL_GROW 0x4
#define F_SEAL_WRITE 0x8
#define F_SEAL_EXEC 0x20
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif

static void step(const char *name, long rc)
{
	if (rc < 0)
		printf("STEP %-42s FAIL errno=%d (%s)\n", name, errno,
		       strerror(errno));
	else
		printf("STEP %-42s OK rc=%ld\n", name, rc);
}

static void report_caps(void)
{
	FILE *f = fopen("/proc/self/status", "r");
	char line[512];
	if (!f)
		return;
	while (fgets(line, sizeof(line), f))
		if (!strncmp(line, "CapEff:", 7) || !strncmp(line, "CapBnd:", 7) ||
		    !strncmp(line, "NoNewPrivs:", 11))
			fputs(line, stdout);
	fclose(f);
}

static void report_ns(void)
{
	char buf[256];
	const char *ns[] = { "user", "mnt", "pid", "net", NULL };
	for (int i = 0; ns[i]; i++) {
		snprintf(buf, sizeof(buf), "/proc/self/ns/%s", ns[i]);
		char link[128];
		ssize_t n = readlink(buf, link, sizeof(link) - 1);
		if (n > 0) {
			link[n] = 0;
			printf("NS %-5s %s\n", ns[i], link);
		}
	}
}

/* The probe's own real executable path (the runc-faithful binDir/name). */
static void self_exe_dir_name(char *dir, size_t dirsz, char *name, size_t namesz)
{
	char exe[1024];
	ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (n <= 0) {
		snprintf(dir, dirsz, "/usr/bin");
		snprintf(name, namesz, "true");
		return;
	}
	exe[n] = 0;
	char *slash = strrchr(exe, '/');
	if (!slash) {
		snprintf(dir, dirsz, ".");
		snprintf(name, namesz, "%s", exe);
		return;
	}
	snprintf(dir, dirsz, "%s", exe);
	dir[slash - exe] = 0;
	snprintf(name, namesz, "%s", slash + 1);
}

/* ovl <binary-dir> <dummy-lower-dir> <binary-name> — the exact
 * sealedOverlayfs sequence */
static int cmd_ovl(char **argv)
{
	const char *lower1 = argv[0];
	const char *lower2 = argv[1];
	const char *binname = argv[2];
	char lowerstr[4096];
	int ctx, mnt, exe;
	long rc;

	rc = syscall(__NR_fsopen, "overlay", FSOPEN_CLOEXEC);
	step("fsopen(overlay, FSOPEN_CLOEXEC)", rc);
	if (rc < 0)
		return 1;
	ctx = (int)rc;

	snprintf(lowerstr, sizeof(lowerstr), "%s:%s", lower1, lower2);
	rc = syscall(__NR_fsconfig, ctx, FSCONFIG_SET_STRING, "lowerdir",
		     lowerstr, 0);
	step("fsconfig(SET_STRING lowerdir=dir:dummy)", rc);
	if (rc < 0)
		return 1;

	rc = syscall(__NR_fsconfig, ctx, FSCONFIG_SET_STRING, "xino", "off", 0);
	step("fsconfig(SET_STRING xino=off) [ignored]", rc);

	rc = syscall(__NR_fsconfig, ctx, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	step("fsconfig(CMD_CREATE overlay superblock)", rc);
	if (rc < 0)
		return 1;

	rc = syscall(__NR_fsmount, ctx, FSMOUNT_CLOEXEC,
		     MS_RDONLY | MS_NODEV | MS_NOSUID);
	step("fsmount(FSMOUNT_CLOEXEC, RDONLY|NODEV|NOSUID)", rc);
	if (rc < 0)
		return 1;
	mnt = (int)rc;

	rc = openat(mnt, binname, O_PATH | O_NOFOLLOW | O_CLOEXEC, 0);
	step("openat(overlayfd, binname, O_PATH|O_NOFOLLOW)", rc);
	if (rc < 0)
		return 1;
	exe = (int)rc;
	close(exe);
	close(mnt);
	close(ctx);
	printf("OVL-SEQUENCE=COMPLETE\n");
	return 0;
}

/* memfd <name> — the exact ExecutableMemfd + sealMemfd sequence */
static int cmd_memfd(char **argv)
{
	const char *name = argv[0];
	char mname[256];
	int fd, fd2;
	char c = 'x';
	long rc;
	char *ctx = NULL;

	snprintf(mname, sizeof(mname), "runc_cloned:%s", name);

	/* ExecutableMemfd: MFD_EXEC first, retry without on EINVAL. */
	rc = syscall(__NR_memfd_create, mname,
		     MFD_ALLOW_SEALING | MFD_CLOEXEC | MFD_EXEC);
	step("memfd_create(MFD_ALLOW_SEALING|CLOEXEC|EXEC)", rc);
	if (rc < 0 && errno == EINVAL) {
		rc = syscall(__NR_memfd_create, mname,
			     MFD_ALLOW_SEALING | MFD_CLOEXEC);
		step("memfd_create(MFD_ALLOW_SEALING|CLOEXEC) [retry]", rc);
	}
	if (rc < 0)
		return 1;
	fd = (int)rc;

	if (fgetfilecon(fd, &ctx) == 0)
		printf("MEMFD-LABEL %s\n", ctx);
	else
		printf("STEP %-42s FAIL errno=%d (%s)\n", "fgetfilecon(memfd)",
		       errno, strerror(errno));

	rc = write(fd, &c, 1);
	step("write(memfd, 1 byte)", rc);
	rc = fchmod(fd, 0511);
	step("fchmod(memfd, 0511)", rc);
	rc = fcntl(fd, F_ADD_SEALS, F_SEAL_EXEC);
	step("fcntl(F_ADD_SEALS, F_SEAL_EXEC)", rc);
	rc = fcntl(fd, F_ADD_SEALS,
		   F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
	step("fcntl(F_ADD_SEALS, base seals)", rc);
	rc = fcntl(fd, F_GET_SEALS, 0);
	step("fcntl(F_GET_SEALS)", rc);
	close(fd);

	/* A second memfd WITHOUT MFD_EXEC (the pre-6.3 semantics probe). */
	rc = syscall(__NR_memfd_create, "probe_noexec", MFD_ALLOW_SEALING | MFD_CLOEXEC);
	step("memfd_create(no MFD_EXEC)", rc);
	if (rc >= 0) {
		fd2 = (int)rc;
		if (fgetfilecon(fd2, &ctx) == 0)
			printf("MEMFD2-LABEL %s\n", ctx);
		close(fd2);
	}
	return 0;
}

/* userns <binary-dir> <dummy-lower-dir> — ovl sequence inside a fresh
 * unprivileged user namespace (overlayfs-in-userns kernel support). */
static int cmd_userns(char **argv)
{
	pid_t p = fork();
	if (p < 0) {
		step("fork", -1);
		return 1;
	}
	if (p == 0) {
		if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
			step("unshare(NEWUSER|NEWNS)", -1);
			_exit(1);
		}
		int fd = open("/proc/self/uid_map", O_WRONLY);
		dprintf(fd, "0 %d 1\n", getuid());
		close(fd);
		fd = open("/proc/self/setgroups", O_WRONLY);
		dprintf(fd, "deny\n");
		close(fd);
		fd = open("/proc/self/gid_map", O_WRONLY);
		dprintf(fd, "0 %d 1\n", getgid());
		close(fd);
		printf("USERNS-ENTERED uid=%d\n", getuid());
		report_caps();
		int r = cmd_ovl(argv);
		fflush(stdout);
		_exit(r);
	}
	int st;
	waitpid(p, &st, 0);
	return WEXITSTATUS(st);
}

int main(int argc, char **argv)
{
	char *ctx = NULL;
	if (argc < 2)
		return 2;
	if (getcon(&ctx) == 0)
		printf("PROBE-CONTEXT %s\n", ctx);
	report_caps();
	report_ns();
	if (!strcmp(argv[1], "ovl")) {
		if (argc < 5)
			return 2;
		return cmd_ovl(argv + 2);
	}
	if (!strcmp(argv[1], "userns")) {
		if (argc < 5)
			return 2;
		return cmd_userns(argv + 2);
	}
	if (!strcmp(argv[1], "memfd")) {
		if (argc < 3)
			return 2;
		return cmd_memfd(argv + 2);
	}
	return 2;
}
CEOF
gcc -O2 -o "$EVIDENCE_DIR/exeseal_probe" "$EVIDENCE_DIR/exeseal_probe.c" -lselinux \
  || fail "exeseal_probe build failed"
log "exeseal probe built: $EVIDENCE_DIR/exeseal_probe"
fi

# ============================================================================
# Section 5: source-faithful probe matrix (unconfined = kernel-side baseline)
# ============================================================================
if [ -f "$STATE_DIR/sec5" ]; then log "phase marker: section 5 done; skipping"; else
log "=== section 5: probe matrix (kernel-side baselines) ==="
# runc-faithful binary-dir/name: the probe's own real /proc/self/exe path
# (sealedOverlayfs lowerdir=dirname:/tmpfs-dummy, openat name=basename).
SELF_EXE="$(readlink -f /proc/self/exe 2>/dev/null || echo /usr/bin/true)"
SELF_DIR="$(dirname "$SELF_EXE")"
SELF_NAME="$(basename "$SELF_EXE")"

# 5a. sealedOverlayfs sequence as unconfined root (full SELinux allows,
#     init-userns caps): every errno here is a KERNEL verdict, not SELinux.
cap probe-ovl-unconfined 20 "$EVIDENCE_DIR/exeseal_probe" ovl "$SELF_DIR" /dev/shm "$SELF_NAME"

# 5b. The same sequence inside a fresh unprivileged user namespace:
#     the overlayfs-in-userns kernel-support verdict for this kernel.
cap probe-ovl-userns 24 "$EVIDENCE_DIR/exeseal_probe" userns "$SELF_DIR" /dev/shm "$SELF_NAME"

# 5c. memfd sequence as unconfined root: create/label/write/chmod/seal.
cap probe-memfd-unconfined 20 "$EVIDENCE_DIR/exeseal_probe" memfd /proc/self/exe

# 5d. The memfd-vs-pathname labeling differential under an s0:c1-level
#     subject (runcon -l only — level change, no domain transition).
#     The probe binary must sit on an ENTRYPOINT-allowed executable type
#     for the level-constrained exec: /usr/local/bin is bin_t on this
#     distro (the /tmp placement was denied entrypoint in the first rung's
#     evidence — recorded honestly in probe-avc-window).
install -m 755 "$EVIDENCE_DIR/exeseal_probe" /usr/local/bin/r7-exeseal-probe
restorecon /usr/local/bin/r7-exeseal-probe >/dev/null 2>&1 || true
PROBE_BIN=/usr/local/bin/r7-exeseal-probe
ls -Z "$PROBE_BIN" >"$EVIDENCE_DIR/probe-bin-label.log" 2>&1
LEVEL_OK="$(runcon -l s0:c1 id -Z 2>/dev/null)" || LEVEL_OK=""
if [ -n "$LEVEL_OK" ]; then
  log "level-only runcon control: OK ($LEVEL_OK)"
  cap probe-memfd-c1 24 runcon -l s0:c1 "$PROBE_BIN" memfd /proc/self/exe
  rm -f /dev/shm/r7px /dev/shm/r7pd /dev/shm/r7pf
  cap probe-path-contrast-c1 24 runcon -l s0:c1 bash -c '
    touch /dev/shm/r7px; mkdir /dev/shm/r7pd; mkfifo /dev/shm/r7pf
    ls -Zd /dev/shm /dev/shm/r7px /dev/shm/r7pd /dev/shm/r7pf 2>&1
    id -Z'
  rm -f /dev/shm/r7px; rm -rf /dev/shm/r7pd; rm -f /dev/shm/r7pf
  cap probe-path-contrast-unconfined 12 bash -c 'touch /dev/shm/r7py; ls -Zd /dev/shm/r7py; rm -f /dev/shm/r7py'
  # The overlay sequence under the c1 level too (SELinux-side view from a
  # categorized unconfined subject).
  cap probe-ovl-c1 20 runcon -l s0:c1 "$PROBE_BIN" ovl "$SELF_DIR" /dev/shm "$SELF_NAME"
else
  log "level-only runcon control FAILED — differential skipped (evidence in probe-path-contrast log)"
  printf 'level-only runcon control failed; differential not run\n' >"$EVIDENCE_DIR/probe-memfd-c1.log"
  printf 'level-only runcon control failed; differential not run\n' >"$EVIDENCE_DIR/probe-path-contrast-c1.log"
fi

# 5e. The AVC window for the probe runs themselves (read-only): which
#     SELinux permissions the probe's own steps consumed or would need.
avc_tail probe-avc-window
rm -f "$PROBE_BIN"
touch "$STATE_DIR/sec5"
fi

# ============================================================================
# Section 6: the LIVE real-path reproduction with strace
# ============================================================================
log "=== section 6: live real-path strace reproduction ==="
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
STRACE_COLLECTED="absent"
MEMFD_LABEL_OBSERVED="unknown"
OVERLAY_OBSERVED="unknown"
if [ -n "$ADMIN_TOKEN" ]; then
  PRINCIPAL="${SUDO_USER:-}"
  PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
  WS="$PRINCIPAL_HOME/r7-exeseal-ws"
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
  SESS_JSON="$(curl --silent --max-time 5 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"workspace\":\"$WS\",\"principal\":\"$PRINCIPAL\"}" \
    -o "$EVIDENCE_DIR/session-response.json" -w '%{http_code}' http://localhost/sessions)" || true
  SESS_TOKEN="$(grep -oE '"token": *"[^"]+"' "$EVIDENCE_DIR/session-response.json" 2>/dev/null | head -1 | sed 's/.*"token": *"//;s/"$//')"
  if [ -n "$SESS_TOKEN" ]; then
    export DOCKER_HELPER_SESSION_TOKEN="$SESS_TOKEN"
    docker-helper pull alpine:3.24 >"$EVIDENCE_DIR/pull.log" 2>&1 || true

    STRACE_LOG="$EVIDENCE_DIR/runc-exeseal-strace.log"
    : > "$STRACE_LOG"
    ( DOCKER_HELPER_SESSION_TOKEN="$SESS_TOKEN" docker-helper build ctx \
        --dockerfile Dockerfile --image uat-exeseal:2.2 \
        >"$EVIDENCE_DIR/build.log" 2>&1 ) &
    BLD_JOB=$!

    # Attach strace -f the moment the REAL buildkitd daemon appears (comm
    # exactly "buildkitd" — pgrep -f also matches the rootlesskit wrapper's
    # cmdline, which attached to the wrong process in the first rung's
    # evidence and missed the exeseal window entirely). The RUN stage —
    # the runc spawn — is seconds behind the pull/extract stages.
    STRACE_PID=""
    for _ in $(seq 1 400); do
      BKD_PID="$(pgrep -x buildkitd | head -1 || true)"
      if [ -n "$BKD_PID" ]; then
        strace -f -qq -tt -s 120 -y \
          -e trace=fsopen,fsconfig,fsmount,move_mount,open_tree,mount,umount2,memfd_create,sendfile,pwrite64,write,fchmod,fchmodat,fchmodat2,fchown,fchownat,execve,execveat,openat,readlink,readlinkat,statfs,fstatfs,fcntl,unshare,setns,faccessat,faccessat2,mknod,mknodat,mount_setattr \
          -p "$BKD_PID" -o "$STRACE_LOG" \
          2>"$EVIDENCE_DIR/runc-exeseal-strace.err" &
        STRACE_PID=$!
        log "strace attached to buildkitd pid $BKD_PID (comm-exact)"
        break
      fi
      kill -0 "$BLD_JOB" 2>/dev/null || break
      sleep 0.05
    done

    # Daemon context/caps/namespace inventory (read-only /proc reads) for
    # the REAL buildkitd (comm-exact) and its rootlesskit wrapper.
    cap buildkitd-inventory 30 bash -c "
      p=\$(pgrep -x buildkitd | head -1)
      if [ -n \"\$p\" ]; then
        echo \"real-buildkitd pid=\$p\"
        cat /proc/\$p/attr/current 2>&1
        grep -E '^(Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|NSpid)' /proc/\$p/status
        ls -l /proc/\$p/ns/user /proc/\$p/ns/mnt 2>&1
        echo '--- uid_map:'; cat /proc/\$p/uid_map 2>&1
        echo '--- tmpfs/overlay mounts visible:'
        grep -E ' - (tmpfs|overlay) ' /proc/\$p/mountinfo 2>&1 | head -6
      else
        echo '(real buildkitd pid not observed)'
      fi
      w=\$(pgrep -f 'rootlesskit' | head -1)
      if [ -n \"\$w\" ]; then
        echo \"rootlesskit-wrapper pid=\$w\"
        cat /proc/\$w/attr/current 2>&1
        grep -E '^(CapEff|CapBnd|NoNewPrivs)' /proc/\$w/status
        ls -l /proc/\$w/ns/user /proc/\$w/ns/mnt 2>&1
      fi"

    # The buildkit-runc process poller: 10ms loop, one snapshot per pid.
    (
      echo "poller-start ts=$(date +%s.%N)" >"$EVIDENCE_DIR/runc-proc-inventory.log"
      SEEN=""
      for _ in $(seq 1 20000); do
        for p in $(pgrep -x buildkit-runc 2>/dev/null); do
          case "$SEEN" in *"|$p|"*) ;; *)
            SEEN="$SEEN|$p|"
            {
              echo "=== buildkit-runc pid=$p ts=$(date +%s.%N) ==="
              cat "/proc/$p/attr/current" 2>&1
              grep -E '^(Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs)' "/proc/$p/status" 2>&1
              echo "--- ns:"
              ls -l "/proc/$p/ns/user" "/proc/$p/ns/mnt" 2>&1
              echo "--- uid_map:"; cat "/proc/$p/uid_map" 2>&1
              echo "--- tmpfs/overlay/cgroup mounts visible:"
              grep -E ' - (tmpfs|overlay|cgroup2) ' "/proc/$p/mountinfo" 2>&1 | head -8
            } >>"$EVIDENCE_DIR/runc-proc-inventory.log" 2>&1
            ;;
          esac
        done
        kill -0 "$BLD_JOB" 2>/dev/null || break
        sleep 0.01
      done
      echo "poller-end seen=$SEEN" >>"$EVIDENCE_DIR/runc-proc-inventory.log"
      [ -s "$EVIDENCE_DIR/runc-proc-inventory.log" ] || echo "(no buildkit-runc pid observed)" >"$EVIDENCE_DIR/runc-proc-inventory.log"
    ) &
    RUNC_CAP=$!

    wait "$BLD_JOB"; BLD_RC=$?
    [ -n "$STRACE_PID" ] && kill "$STRACE_PID" 2>/dev/null || true
    wait "$RUNC_CAP" 2>/dev/null || true
    log "build rc=$BLD_RC (terminal failure expected)"
    cap build-tail 8 tail -6 "$EVIDENCE_DIR/build.log"
    cap runc-proc-inventory 40 cat "$EVIDENCE_DIR/runc-proc-inventory.log"

    # The exeseal syscall sequence, extracted verbatim from the trace:
    # the overlay attempt (fsopen/fsconfig/fsmount), the memfd sequence
    # (create/sendfile/fchmod/fcntl), and every failing syscall with its
    # errno, plus the writes/sendfiles decoded to their memfd target.
    grep -aE 'fsopen|fsconfig|fsmount|memfd_create|sendfile|fchmod|fchown|fcntl' "$STRACE_LOG" \
      > "$EVIDENCE_DIR/runc-exeseal-sequence.log" 2>/dev/null || true
    grep -aE 'fsopen|fsconfig|fsmount|memfd_create' "$STRACE_LOG" \
      > "$EVIDENCE_DIR/runc-exeseal-overlay-memfd.log" 2>/dev/null || true
    grep -aE '= -1 E(ACCES|PERM)' "$STRACE_LOG" \
      > "$EVIDENCE_DIR/runc-exeseal-errno.log" 2>/dev/null || true
    grep -aE '(write|sendfile)\([0-9]+</memfd:' "$STRACE_LOG" \
      > "$EVIDENCE_DIR/runc-exeseal-memfd-writes.log" 2>/dev/null || true
    grep -aE 'fsconfig' "$STRACE_LOG" \
      >> "$EVIDENCE_DIR/runc-exeseal-errno.log" 2>/dev/null || true
    if [ -s "$STRACE_LOG" ]; then
      STRACE_COLLECTED="collected"
      log "strace lines: $(wc -l < "$STRACE_LOG")"
      head -40 "$EVIDENCE_DIR/runc-exeseal-overlay-memfd.log" 2>/dev/null || true
    else
      log "strace log empty (attach may have missed the window)"
      printf '%s\n' "$EVIDENCE_DIR/runc-exeseal-strace.err" >/dev/null 2>&1 || true
    fi
    cap runc-exeseal-strace-err 6 cat "$EVIDENCE_DIR/runc-exeseal-strace.err"

    # The build-window AVC records (the authoritative target labels).
    avc_tail build-avc-window
    grep -a 'tmpfs_t' "$EVIDENCE_DIR/build-avc-window.log" \
      > "$EVIDENCE_DIR/build-avc-tmpfs.log" 2>/dev/null || true
    log "tmpfs-class AVCs this window: $(wc -l < "$EVIDENCE_DIR/build-avc-tmpfs.log")"
  else
    log "session token unavailable (HTTP $SESS_JSON); live reproduction skipped"
  fi
else
  log "admin token unreadable; live reproduction skipped"
fi

# The observed memfd label: prefer the LIVE AVC record, fall back to the probe.
if [ -s "$EVIDENCE_DIR/build-avc-tmpfs.log" ]; then
  AVC_LINE="$(grep -a 'denied.*write' "$EVIDENCE_DIR/build-avc-tmpfs.log" | grep -a 'tclass=file' | head -1)"
  [ -n "$AVC_LINE" ] && MEMFD_LABEL_OBSERVED="$AVC_LINE"
fi
[ "$MEMFD_LABEL_OBSERVED" = "unknown" ] && \
  MEMFD_LABEL_OBSERVED="$(grep -a 'MEMFD-LABEL' "$EVIDENCE_DIR/probe-memfd-c1.log" 2>/dev/null | head -1 || echo unknown)"

# The observed overlay failure: prefer the LIVE strace, fall back to the probe.
if [ "$STRACE_COLLECTED" = "collected" ] && grep -aq 'fsconfig' "$EVIDENCE_DIR/runc-exeseal-sequence.log" 2>/dev/null; then
  OVERLAY_OBSERVED="$(grep -aE 'fsopen|fsconfig|fsmount' "$EVIDENCE_DIR/runc-exeseal-overlay-memfd.log" 2>/dev/null | head -8 | tr '\n' ';')"
fi
[ "$OVERLAY_OBSERVED" = "unknown" ] && \
  OVERLAY_OBSERVED="$(grep -aE 'STEP fs' "$EVIDENCE_DIR/probe-ovl-unconfined.log" 2>/dev/null | head -8 | tr '\n' ';' || echo unknown)"

log "R7-EXESEAL-VERDICT=OVERLAY=$OVERLAY_OBSERVED;MEMFD-LABEL=$MEMFD_LABEL_OBSERVED;MEMFD-WRITE=live-AVC;STRACE=$STRACE_COLLECTED"
exit 0
