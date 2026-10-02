/* tun-cross-op-vehicle.c — the 4C-37 cross-operation isolation vehicle.
 *
 * Runs in the flow's slirp4netns helper domain through the composition's
 * own entry path (the harness's rename-swap mechanism puts this binary at
 * the labeled /usr/bin/slirp4netns path). It IGNORES argv, so the
 * rootlesskit parent's `slirp4netns --help` version-check invocation
 * performs the whole proof and the flow dies the same way the 4C-34
 * probe's flow did.
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
//     print a fake version line (>= 0.4.0) so the rootlesskit parent
//     proceeds with the real launch (unshare, tap0 creation, helper
//     spawn).
//   REAL invocation (`--mtu <N> -r <fd> <pid> <tap>`): runs INSIDE the
//     vehicle's own target namespaces (its parent is the rootlesskit
//     ns-holder). The control leg joins its own parent's namespaces and
//     attaches to its own freshly created tap0 (the full production
//     chain must return 0 — the same-operation baseline INSIDE this very
//     run). The attack leg repeats the SAME production path against
//     operation A's rootlesskit netns-owner pid; step by step; the FIRST
//     failing syscall (SELinux EACCES/EPERM or any other real boundary
//     errno) STOPS the leg and is reported as BOUNDARY. An ENOENT on the
//     proc path is NOT a boundary — it means the target identity was
//     stale (reported as IDENTITY-FAIL). The A→B mirror direction is NOT
//     runnable in this window: a third concurrent operation exceeds the
//     product's ceiling of 2 — the single live cross direction plus the
//     symmetric record set is the phase's scope.
//
// Exit codes: 0 = control succeeded AND the attack leg stopped at a real
// boundary; 5 = the control leg failed (the baseline is broken);
// 6 = CROSS-OPERATION ISOLATION BROKEN (the attack leg completed the whole
// attach path); 7 = the target delivery is broken; 9 = other.
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

/* One production attach leg against the target pid. Returns 0 = every
 * step succeeded (the whole attach path completed), 1 = stopped at a real
 * boundary, 2 = the target identity was stale (ENOENT on the proc path).
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
	errno = 0;
	rc = ioctl(fd_tun, TUNSETIFF, &ifr);
	err = errno;
	step(leg, "TUNSETIFF", rc, err);
	close(fd_tun);
	if (rc < 0) return 1;

	return 0;
}

int main(int argc, char **argv) {
	char buf[256];
	int err;

	/* VERSION-CHECK invocation: the rootlesskit parent runs `--help`
	 * BEFORE its unshare, in the HOST namespace. Print a fake version
	 * line so the launch proceeds; the proof belongs to the REAL
	 * invocation below.
	 */
	if (argc == 2 && strcmp(argv[1], "--help") == 0) {
		(void)printf("slirp4netns version 0.4.0\n");
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
	(void)lseek(fd, size - 96, SEEK_SET);
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
	(void)sscanf(mark, "CROSS-OP-TARGETS %d", &pid_a);
	if (pid_a <= 0) {
		(void)write(2, "VEHICLE-VERDICT TARGETS=BINDING-FAIL\n", 36);
		return 7;
	}

	/* CONTROL: the production path against the vehicle's own ns-holder. */
	if (attach_leg("control", own_pid) != 0) {
		(void)write(2, "VEHICLE-VERDICT CONTROL=FAIL\n", 29);
		return 5;
	}
	(void)write(2, "VEHICLE-VERDICT CONTROL=SUCCESS\n", 31);

	/* ATTACK B->A: the vehicle is operation B (the second slot, c2);
	 * operation A is the first slot (c1), alive with its attached TAP.
	 */
	int shape_a = attach_leg("attack-a", pid_a);
	if (shape_a == 0) {
		(void)write(2, "VEHICLE-VERDICT CROSS-OPERATION-ISOLATION=BROKEN\n", 48);
		return 6;
	}
	if (shape_a == 2) {
		(void)write(2, "VEHICLE-VERDICT ATTACK-TARGET=IDENTITY-FAIL\n", 43);
		return 9;
	}
	(void)write(2, "VEHICLE-VERDICT CROSS-OPERATION-ISOLATION=HOLDS\n", 47);
	return 0;
}
