/* tun-cross-op-vehicle.c — the 4C-37 cross-operation isolation vehicle.
 *
 * Runs in the flow's slirp4netns helper domain through the composition's
 * own entry path (the harness's rename-swap mechanism puts this binary at
 * the labeled /usr/bin/slirp4netns path). Two invocations reach it: the
 * rootlesskit parent's `slirp4netns --help` feature-detection probe —
 * RootlessKit's DetectFeatures requires the literal --netns-type and
 * --disable-host-loopback feature strings in that combined output and
 * never parses the version line — and the REAL helper invocation, which
 * runs the whole proof.
 *
 * Zero policy delta: the vehicle uses ONLY the helper domain's existing
 * production authority — the proc/ns traversal grants, the nsfs
 * namespace-handle read/open, the self cap_userns { sys_ptrace sys_admin }
 * namespace-join authority, the tun_tap_device_t:chr_file { read write
 * open ioctl } + allowxperm { 0x54ca } device surface, and the two TUN
 * socket-relabel grants (cross-domain relabelfrom + self relabelto).
 *
// THE SLOT LAYOUT (the product's own concurrency fact, proven live in the
// 4C-37 diagnosis runs: `maxConcurrentBuildsGlobal = 2`, and RETAINED
// entries still count toward it): this vehicle runs as the SECOND
// operation's helper. Operation A (the canonical leg) is a REAL flow that
// stays alive with its attached TAP; the vehicle (operation B) is the
// second live operation. Its legs:
//   VERSION-CHECK invocation (`--help`): the rootlesskit parent runs it
//     BEFORE its own unshare, in the HOST namespace — the vehicle must
//     print the feature strings RootlessKit's DetectFeatures greps for
//     (--netns-type; --disable-host-loopback, which the composition's
//     canonical argv requests) so the rootlesskit parent proceeds with
//     the real launch (unshare, tap0 creation, helper spawn).
//   REAL invocation (`--mtu <N> -r <fd> <pid> <tap>`): runs INSIDE the
//     vehicle's own target namespaces (its target is the rootlesskit
//     ns-holder pid passed as the second-to-last argument). The control
//     attaches to its own freshly created tap0 (the full production
//     chain must return 0 — the same-operation baseline INSIDE this very
//     run). The attack legs repeat the SAME production access against
//     operation A's identity — the LIVE member of operation A's netns
//     (with the lifetime-stable BuildKit runtime the flow's persistent
//     member set is the buildkitd tree itself: the anchor class is
//     docker_helper_buildkitd_t:s0:c1, the same category the flow
//     carried); three surfaces, three legs: A's runtime socket, A's
//     state tree, and A's namespace set + attached TAP; step by step;
//     the FIRST failing syscall (SELinux EACCES/EPERM or any other real
//     boundary errno) STOPS the leg and is reported as BOUNDARY. An
//     ENOENT on the target path is NOT a boundary — it means the target
//     identity was stale (reported as IDENTITY-FAIL). The A→B mirror
//     direction is NOT runnable in this window: a third concurrent
//     operation exceeds the product's ceiling of 2 — the single live
//     cross direction plus the symmetric record set is the phase's
//     scope.
//
// Exit codes: 0 = control succeeded AND every attack leg stopped at a
// real boundary; 5 = the control leg failed (the baseline is broken);
// 6 = CROSS-OPERATION ISOLATION BROKEN (an attack leg completed its
// access path); 7 = the target delivery is broken; 9 = other.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef TUNSETIFF
#define TUNSETIFF _IOW('T', 202, int)
#endif
typedef char tunsetiff_pin[(TUNSETIFF == 0x400454ca) ? 1 : -1];

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif

static void step(const char *leg, const char *what, long rc, int err) {
	char buf[160];
	int n = snprintf(buf, sizeof buf, "VEHICLE-STEP leg=%s step=%s rc=%ld errno=%d\n",
			 leg, what, rc, err);
	if (n > 0) (void)write(2, buf, (size_t)n);
}

/* The 4C-37R attack surfaces. The original phase proved the
 * namespace/TUN surface only; the resumed phase (against the
 * lifetime-stable BuildKit runtime) must cover the operation's FULL
 * identity: the runtime tree's socket, the state tree, and the
 * namespace/attached-TAP set. Each leg is an independent open of one
 * of operation A's identity surfaces; the SELinux boundary fires at
 * the path walk or the object's own hook — the helper domain has NO
 * authority toward the per-op runtime/state planes (the PLANE G/H/I
 * and PLANE E/F rules are buildkitd_t pairs, never slirp4netns_t
 * pairs), so the walk denies before any object is reached. A success
 * would mean the policy stopped nothing (BROKEN). ENOENT means the
 * surface no longer exists (the target identity was stale — A's tree
 * is gone, never a boundary).
 *
 * One production attach leg against the target pid (the namespace
 * surface). Returns 0 = every step succeeded (the whole attach path
 * completed), 1 = stopped at a real boundary, 2 = the target identity
 * was stale (ENOENT on the proc path).
 */
static int attach_leg(const char *leg, int target_pid) {
	char path[64];
	int rc, err;

	snprintf(path, sizeof path, "/proc/%d/ns/net", target_pid);
	rc = open(path, O_RDONLY);
	err = errno;
	step(leg, "open-ns-net", rc, err);
	if (rc < 0) return err == ENOENT ? 2 : 1;
	int fd_net = rc;

	snprintf(path, sizeof path, "/proc/%d/ns/user", target_pid);
	rc = open(path, O_RDONLY);
	err = errno;
	step(leg, "open-ns-user", rc, err);
	if (rc < 0) { close(fd_net); return err == ENOENT ? 2 : 1; }
	int fd_user = rc;

	rc = setns(fd_user, CLONE_NEWUSER);
	err = errno;
	step(leg, "setns-user", rc, err);
	close(fd_user);
	if (rc < 0) { close(fd_net); return 1; }

	rc = setns(fd_net, CLONE_NEWNET);
	err = errno;
	step(leg, "setns-net", rc, err);
	close(fd_net);
	if (rc < 0) return 1;

	rc = open("/dev/net/tun", O_RDWR);
	err = errno;
	step(leg, "open-tun", rc, err);
	if (rc < 0) return 1;
	int fd_tun = rc;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof ifr);
	strcpy(ifr.ifr_name, "tap0");
	/* The production attach shape: the real slirp4netns requests the
	 * TAP device without the packet-information header. Flags 0 makes
	 * the kernel's TUNSETIFF return EINVAL before any attachment.
	 */
	ifr.ifr_flags = 0x0002 | 0x1000; /* IFF_TAP | IFF_NO_PI */
	errno = 0;
	rc = ioctl(fd_tun, TUNSETIFF, &ifr);
	err = errno;
	step(leg, "TUNSETIFF", rc, err);
	close(fd_tun);
	if (rc < 0) return 1;

	return 0;
}

/* One direct-access leg against one of operation A's filesystem
 * identity surfaces (the runtime socket or the state root). The same
 * leg shape serves both: one open(2) is the whole attempt — the
 * helper domain has no path authority toward the per-op planes, so
 * the walk itself must deny. Returns the leg shape like attach_leg,
 * plus 3 = the open was NOT policy-stopped: the walk and the object's
 * own hook passed and the kernel refused for its own socket-open
 * semantic (ENXIO — open(2) on a socket inode never returns a fd).
 * ENXIO is a compromise signal, never a boundary: the policy allowed
 * B to reach A's socket object.
 */
static int open_leg(const char *leg, const char *path, int flags) {
	int rc, err;

	rc = open(path, flags);
	err = errno;
	step(leg, "open-surface", rc, err);
	if (rc < 0) {
		if (err == ENOENT) return 2;
		if (err == ENXIO) return 3;
		return 1;
	}
	(void)close(rc);
	return 0;
}

int main(int argc, char **argv) {
	char buf[256];
	int err;

	/* VERSION-CHECK invocation: the rootlesskit parent runs `--help`
	 * BEFORE its unshare, in the HOST namespace. The fake help must
	 * carry the literal feature strings RootlessKit's DetectFeatures
	 * greps for: --netns-type (the >= v0.4.0 sentinel) and
	 * --disable-host-loopback (the composition's canonical argv
	 * requests it); the version line itself is never parsed.
	 */
	if (argc == 2 && strcmp(argv[1], "--help") == 0) {
		(void)printf("slirp4netns version 1.1.2\n");
		(void)printf("  --netns-type=fd|path\n");
		(void)printf("  --disable-host-loopback\n");
		return 0;
	}

	/* REAL invocation: `--mtu <N> -r <fd> <pid> <tap>` — the pid is the
	 * vehicle's own rootlesskit ns-holder (its CONTROL target).
	 */
	if (argc < 7) {
		(void)write(2, "VEHICLE-VERDICT INVOCATION=UNRECOGNIZED\n", 39);
		return 9;
	}
	int own_pid = 0;
	(void)sscanf(argv[argc - 2], "%d", &own_pid);
	if (own_pid <= 0) {
		(void)write(2, "VEHICLE-VERDICT INVOCATION=UNRECOGNIZED\n", 39);
		return 9;
	}

	/* The attack target: the tail of this vehicle's own installed
	 * binary (the helper's existing entry-file read authority).
	 */
	int fd = open("/usr/bin/slirp4netns", O_RDONLY);
	err = errno;
	step("targets", "open-own-binary", fd, err);
	if (fd < 0) {
		(void)write(2, "VEHICLE-VERDICT TARGETS=UNREADABLE\n", 34);
		return 7;
	}
	off_t size = lseek(fd, 0, SEEK_END);
	if (size < 64) {
		close(fd);
		(void)write(2, "VEHICLE-VERDICT TARGETS=UNREADABLE\n", 34);
		return 7;
	}
	(void)lseek(fd, size - 128, SEEK_SET);
	int total = (int)read(fd, buf, sizeof buf - 1);
	close(fd);
	if (total <= 0) {
		(void)write(2, "VEHICLE-VERDICT TARGETS=UNREADABLE\n", 34);
		return 7;
	}
	buf[total] = '\0';
	/* The tail's first bytes can be NUL binary padding, so search with
	 * memmem (a string search would stop at the first NUL byte).
	 */
	char *mark = memmem(buf, (size_t)total, "CROSS-OP-TARGETS", 16);
	if (mark == NULL) {
		(void)write(2, "VEHICLE-VERDICT TARGETS=MARKER-ABSENT\n", 37);
		return 7;
	}
	int pid_a = 0;
	char op_a[64];
	memset(op_a, 0, sizeof op_a);
	(void)sscanf(mark, "CROSS-OP-TARGETS %d %63s", &pid_a, op_a);
	if (pid_a <= 0 || op_a[0] == '\0') {
		(void)write(2, "VEHICLE-VERDICT TARGETS=BINDING-FAIL\n", 36);
		return 7;
	}
	/* The vehicle's identity bindings, recorded before any leg: the
	 * attack must never target the vehicle's own operation or its own
	 * parent (a self-targeted binding is a harness defect, not a
	 * cross-operation result; a stale target is caught by the ENOENT
	 * stop inside the attack legs themselves).
	 */
	int idn = snprintf(buf, sizeof buf,
			   "VEHICLE-ID self-pid=%d parent-pid=%d target-own=%d target-attack=%d target-op=%s\n",
			   (int)getpid(), (int)getppid(), own_pid, pid_a, op_a);
	if (idn > 0) (void)write(2, buf, (size_t)idn);
	if (pid_a == own_pid || pid_a == (int)getppid()) {
		(void)write(2, "VEHICLE-VERDICT TARGETS=SELF-TARGET\n", 35);
		return 7;
	}

	/* CONTROL: the production path against the vehicle's own ns-holder. */
	if (attach_leg("control", own_pid) != 0) {
		(void)write(2, "VEHICLE-VERDICT CONTROL=FAIL\n", 29);
		return 5;
	}
	(void)write(2, "VEHICLE-VERDICT CONTROL=SUCCESS\n", 31);

	/* ATTACK B->A: the vehicle is operation B (the second slot, c2);
	 * operation A is the first slot (c1), alive with its BuildKit
	 * runtime. Three independent identity surfaces, each its own leg
	 * and its own boundary:
	 *   attack-sock  — A's BuildKit runtime socket (the per-op
	 *                  runtime plane's sock_file identity);
	 *   attack-state — A's per-op state tree (the per-op state
	 *                  plane);
	 *   attack-a     — A's namespace set + attached TAP (the
	 *                  production attach path against A's anchor).
	 * The socket/state legs run FIRST: their openat is the whole
	 * attempt, and their boundary (EACCES at the path walk — the
	 * helper domain owns no authority toward the per-op planes) must
	 * not be masked by an earlier stop inside the ns leg.
	 */
	char sockpath[160];
	char statepath[160];
	(void)snprintf(sockpath, sizeof sockpath,
		       "/run/docker-helper-builder/ops/%s/buildkitd.sock", op_a);
	(void)snprintf(statepath, sizeof statepath,
		       "/var/lib/docker-helper-builder/ops/%s", op_a);
	int shape_sock = open_leg("attack-sock", sockpath, O_RDONLY);
	int shape_state = open_leg("attack-state", statepath, O_RDONLY | O_DIRECTORY);
	int shape_a = attach_leg("attack-a", pid_a);
	if (shape_sock == 0 || shape_sock == 3 ||
	    shape_state == 0 || shape_state == 3 ||
	    shape_a == 0) {
		(void)write(2, "VEHICLE-VERDICT CROSS-OPERATION-ISOLATION=BROKEN\n", 48);
		return 6;
	}
	if (shape_sock == 2 || shape_state == 2 || shape_a == 2) {
		(void)write(2, "VEHICLE-VERDICT ATTACK-TARGET=IDENTITY-FAIL\n", 43);
		return 9;
	}
	(void)write(2, "VEHICLE-VERDICT CROSS-OPERATION-ISOLATION=HOLDS\n", 47);
	/* The rootlesskit parent only logs the helper's captured stderr
	 * when the helper invocation FAILS (the "command failed" path),
	 * so the HOLDS verdict leaves the flow with a NON-ZERO exit (30):
	 * the journal entry is the verdict's delivery channel. The
	 * version-check invocation has already passed; this exit only
	 * aborts the ready-fd wait, which then converges and frees the
	 * slot.
	 */
	return 30;
}
