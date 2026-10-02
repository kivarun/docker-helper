/* tun-command-probe.c — the 4C-34 negative command probe.
 *
 * Runs in the flow's slirp4netns helper domain through the composition's
 * own entry path: opens the global TUN device node (the granted chr_file
 * read/write/open surface) and issues ONE real TUN UAPI ioctl whose
 * command is NOT in the helper's allowxperm whitelist — TUNSETPERSIST
 * (0x54cb; the RootlessKit creator's persistence command, not part of
 * the helper's evidenced existing-TAP attach path). Expected causal
 * shape: the ORDINARY ioctl permission passes (the bit is granted), the
 * extended-permission bitmap denies command 0x54cb, ioctl exits EACCES,
 * and NO tun_socket/capability hook is reached. SELinux denies the
 * command inside selinux_file_ioctl() before the TUN driver sees it, so
 * the probe mutates nothing: the fd is never attached to a device and
 * the persistence request never reaches the driver.
 *
 * Static-linked so the confined exec needs nothing beyond the labeled
 * file itself (no loader, no libc's dlopen paths).
 *
 * Exit codes: 42 = the expected SELinux xperm denial shape (ioctl < 0,
 * errno == EACCES); 7 = UNEXPECTED: the probe ioctl COMPLETED (rc == 0);
 * 4 = the device open itself failed; 9 = any other outcome.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* TUNSETPERSIST from <linux/if_tun.h> (the UAPI value is fixed): defined
 * locally so the probe builds without kernel headers. _IOW('T', 203, int)
 * = 0x400454cb. The build-time check below pins it.
 */
#ifndef TUNSETPERSIST
#define TUNSETPERSIST _IOW('T', 203, int)
#endif

typedef char tunsetpersist_pin[(TUNSETPERSIST == 0x400454cb) ? 1 : -1];

int main(void) {
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		char buf[96];
		int n = snprintf(buf, sizeof buf, "tun-command-probe open rc=-1 errno=%d\n", errno);
		if (n > 0) {
			(void)write(1, buf, (size_t)n);
			(void)write(2, buf, (size_t)n);
		}
		return 4;
	}
	errno = 0;
	int rc = ioctl(fd, TUNSETPERSIST, 1);
	int err = errno;
	char buf[160];
	int n = snprintf(buf, sizeof buf,
			 "tun-command-probe fd=%d cmd=0x%x arg=1 rc=%d errno=%d\n",
			 fd, (unsigned int)TUNSETPERSIST, rc, err);
	if (n > 0) {
		(void)write(1, buf, (size_t)n);
		/* stderr too: the flow's version check consumes stdout, so the
		 * journaled child-output capture only sees the stderr copy —
		 * the phase's kernel-trace rings can be eaten by the manager's
		 * readiness-poll denials (the 4C-36 run's lost enter lines). */
		(void)write(2, buf, (size_t)n);
	}
	(void)close(fd);
	if (rc < 0 && err == EACCES) return 42;
	if (rc == 0) return 7;
	return 9;
}
