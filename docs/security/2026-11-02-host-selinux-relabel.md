# Security root-cause report — Docker Helper host SELinux relabel

Date: 2026-11-02 · Status: ROOT CAUSE REPRODUCED; CORRECTIVE PATCH FOR REVIEW ONLY

## Incident facts

Two incidents were reported: an earlier /etc/passwd label change while using
Docker Helper v2.3.1 on a physical host, followed by a host /etc label change
while testing v2.3.0 on a disposable SELinux VM. Both are credible filesystem
damage observations. Exact execution evidence below is from a fresh, independently
reproduced /etc incident with Docker Helper 2.3.1 built from release/2.3.

The v2.3.1 test repeatedly reproduced the same inode identity while changing
the SELinux type of host /etc from etc_t to docker_helper_runtime_t after a
build context containing hostetc -> /etc; the build itself returned
docker_build_failed. This is an integrity breach before and independent of
whether BuildKit accepts the Dockerfile COPY.

## Authoritative attribution

GitHub Actions SELinux Enforcing VM: run 41450062890,
https://github.com/kivarun/docker-helper/actions/runs/41450062890
Guest Docker Engine: 29.7.2-ce (openSUSE RPM docker-29.7.2_ce-41.1),
Buildx 0.36.1, containerd 2.4.2.

Linux audit was independently validated in run 41446427180. VM default
-a never,task suppressed observation in previously started processes.
After removing that guest-only filter, installing an xattr-syscall rule,
demonstrating file/directory/hardlink positive controls, and restarting dockerd
and docker-helper (both PIDs changed), the exact host inode write appeared:

  type=SYSCALL ... syscall=188 success=yes pid=4869 comm="dockerd"
      exe="/usr/bin/dockerd" subj=system_u:system_r:container_runtime_t:s0
      audit serial=1392
  type=PATH ... name="/var/lib/docker/containerd/daemon/
      io.containerd.snapshotter.v1.overlayfs/snapshots/32/fs/hostetc"
      inode=2228352 dev=fd:03 mode=040755 obj=system_u:object_r:etc_t:s0

The host /etc directory has exactly inode=2228352 on dev=fd:03; after the
build it has type docker_helper_runtime_t without changing inode. The audit
record proves direct attribution to dockerd's successful setxattr syscall.

## Source code root cause

Docker Helper staging_linux.go:copyEntry reads hostile symlink metadata with
O_PATH|O_NOFOLLOW/readlinkat, creates a copy via symlinkat and sets timestamps
with AT_SYMLINK_NOFOLLOW. It does NOT traverse the original symlink.

Docker Helper build.go passes the staged context to the Docker command.

Moby 29.7.2 vendor/github.com/tonistiigi/fsutil/diskwriter.go:
DiskWriter.HandleChange creates a received symlink with os.Symlink, then
calls rewriteMetadata(newPath, statCopy).

Moby 29.7.2 vendor/github.com/tonistiigi/fsutil/diskwriter_unix.go:
rewriteMetadata loops over stat.Xattrs and calls
sysx.Setxattr(p, key, value, 0) (not LSetxattr). The kernel resolves the
symlink as an xattr target; an absolute target /etc therefore refers to the
host pathname. The staged symlink carries the helper's runtime SELinux type.
Consequently, the unsafe Docker receiver applied that label to /etc.

The alternative rooted receiver in the same Moby version uses
root.LSetxattr, but the observed syscall=188 and path identify the
non-rooted Setxattr behavior in this reproducer.

## Security boundary and affected code

The Docker Helper trusted boundary is BEFORE submitting the staged build
context to an external privileged docker daemon. Build failure is NOT a
security boundary. Its no-follow staging guarantee alone did not prevent
later consumers from following preserved symlink targets.

The external-symlink admission in staging_linux.go is identical in
Docker Helper v2.3.0, v2.3.1, and release/2.4 as inspected on 2026-11-02.
A successful exploit is empirically proven for Docker Helper v2.3.1 +
Docker Engine 29.7.2-ce and reported for v2.3.0 / earlier v2.3.1 environments;
the exact Docker version of the original physical-host incident is unknown.
Do not extrapolate universal exploitability to all Docker versions without
testing their metadata receiver.

## Proposed minimum corrective

In staging_linux.go:copyEntry, before Symlinkat, refuse any absolute link
text or any relative link text whose lexical normalized destination climbs
outside the context root. Internal relative links continue as before.
Return typed build_context_symlink_escape / HTTP 400, before operation
registration / docker invocation; staged error cleanup remains owner.

Unit test: reject absolute /etc and /etc/passwd and relative escape paths;
accept links wholly within context including sub/../target; assert no staging
operation residue for rejections. Update the D1 UAT previously expecting
unsafe external links to be passed to BuildKit: now require typed pre-Docker
refusal, zero build.start, no staged residue and unchanged host /etc and
/etc/passwd SELinux contexts/inodes.

This is a downstream safety fence, NOT an upstream fix for the Moby/fsutil
Setxattr-versus-LSetxattr defect. Report upstream after coordinated review.

## Stop for review

Candidate changes are confined to the separate draft PR; no merge, tag,
release, or production deployment. A follow-up must review the changed
symlink compatibility contract and independently verify CI/UAT before acceptance.
