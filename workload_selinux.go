package main

// workload_selinux.go — the SELinux workload MAC backend (Release 2.2
// Phase 2.2.6, mechanism accepted by M0-S).
//
// For each accepted read-only exposure the backend creates a helper-owned
// writable bindfs passthrough projection from the existing pinned source and
// mounts it with the exact mount context
// system_u:object_r:docker_helper_ro_projection_t:s0. The container receives
// the projection at the requested target while production keeps the Docker
// bind read-only. An accepted read-write exposure remains a direct bind of
// the pinned source. No global source relabel ever happens; the backing
// tree keeps its labels, device, and inode.
//
// Each read-only exposure owns its own projection state (operation ID +
// mount index); projections are never deduplicated across Sessions or
// operations, so the same backing tree can be read-write to one Session and
// read-only to another without global interference.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// selinuxROProjectionType is the dedicated file type of every helper-owned
	// read-only projection. The shipped policy grants the workload no
	// mutation permission over it.
	selinuxROProjectionType = "docker_helper_ro_projection_t"
	// selinuxROProjectionContext is the exact mount context of a projection.
	selinuxROProjectionContext = "system_u:object_r:" + selinuxROProjectionType + ":s0"
	// bindfsBinary is the explicit SELinux system-mode runtime dependency.
	bindfsBinary = "bindfs"
	// selinuxSELinuxXattr carries the effective SELinux label.
	selinuxSELinuxXattr = "security.selinux"
	// selinuxDevFusePath is the FUSE device the projection worker needs.
	selinuxDevFusePath = "/dev/fuse"
)

// projectionWorker is one helper-owned projection worker process.
type projectionWorker interface {
	// alive reports whether the owned worker process is still running.
	alive() bool
	// waitExit waits for the owned worker to exit within a bounded budget.
	// Only meaningful for a worker this process started.
	waitExit(timeout time.Duration) error
}

// workloadMountOps abstracts the mount mechanics the SELinux backend needs.
// Production implements them with real Linux syscalls; tests inject a seam.
type workloadMountOps interface {
	// isMountpoint reports whether path is a mount point.
	isMountpoint(path string) (bool, error)
	// mountBind creates a bind mount of source at target.
	mountBind(source, target string) error
	// unmount removes the mount at path.
	unmount(path string) error
	// unmountLazy detaches the mount at path lazily.
	unmountLazy(path string) error
	// unmountPath unmounts one helper-owned projection path, preferring the
	// FUSE userspace helper and falling back to the kernel umount with a
	// lazy last resort.
	unmountPath(path string) error
	// selinuxTypeOf returns the SELinux type component of the effective
	// security.selinux xattr of path.
	selinuxTypeOf(path string) (string, error)
}

// productionMountOps implements workloadMountOps with real Linux syscalls.
type productionMountOps struct{}

// productionMountOpsValue is the production mount mechanics instance.
var productionMountOpsValue = productionMountOps{}

func (productionMountOps) isMountpoint(path string) (bool, error) {
	return procMountinfoContains(path)
}

// procMountinfoContains reports whether /proc/self/mountinfo lists path as
// a mount point. This matches the accepted mechanism's mountpoint proof and
// detects file bind mounts that dev/inode comparison cannot.
func procMountinfoContains(path string) (bool, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, fmt.Errorf("cannot read mount inventory: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if unescapeMountPath(fields[4]) == path {
			return true, nil
		}
	}
	return false, nil
}

// unescapeMountPath decodes the octal escapes /proc/self/mountinfo uses for
// whitespace, backslash, and tab in mount point paths.
func unescapeMountPath(path string) string {
	var sb strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] == '\\' && i+3 < len(path) {
			if v, ok := octalDigits3(path[i+1 : i+4]); ok {
				sb.WriteByte(v)
				i += 3
				continue
			}
		}
		sb.WriteByte(path[i])
	}
	return sb.String()
}

func octalDigits3(s string) (byte, bool) {
	if len(s) != 3 {
		return 0, false
	}
	v := 0
	for i := 0; i < 3; i++ {
		if s[i] < '0' || s[i] > '7' {
			return 0, false
		}
		v = v*8 + int(s[i]-'0')
	}
	return byte(v), true
}

func (productionMountOps) mountBind(source, target string) error {
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mount %s -> %s: %w", source, target, err)
	}
	return nil
}

func (productionMountOps) unmount(path string) error {
	if err := unix.Unmount(path, 0); err != nil {
		return fmt.Errorf("unmount %s: %w", path, err)
	}
	return nil
}

func (productionMountOps) unmountLazy(path string) error {
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("lazy unmount %s: %w", path, err)
	}
	return nil
}

func (productionMountOps) selinuxTypeOf(path string) (string, error) {
	value, err := getxattrSELinux(path)
	if err != nil {
		return "", err
	}
	parts := strings.SplitN(value, ":", 4)
	if len(parts) < 3 {
		return "", fmt.Errorf("unusable SELinux context %q", value)
	}
	return parts[2], nil
}

// unmountPathBestEffort unmounts one helper-owned mount path, tolerating
// the already-unmounted case, and is used for owned stale residue only.
func unmountPathBestEffort(path string) error {
	if err := unix.Unmount(path, 0); err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.EINVAL {
			return nil // not a mount point
		}
		if err := unix.Unmount(path, unix.MNT_DETACH); err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.EINVAL {
				return nil
			}
			return fmt.Errorf("unmount %s: %w", path, err)
		}
	}
	return nil
}

func getxattrSELinux(path string) (string, error) {
	buf := make([]byte, 256)
	size, err := unix.Getxattr(path, selinuxSELinuxXattr, buf)
	if err != nil {
		return "", fmt.Errorf("cannot read SELinux context of %s: %w", path, err)
	}
	return strings.TrimRight(string(buf[:size]), "\x00"), nil
}

// bindfsWorker is one helper-owned bindfs projection worker. It is a child
// process owned by this daemon instance, so waiting for it is ownership-safe.
// A stale worker observed after a daemon crash is never signaled: stale
// cleanup correlates by owned mount paths, never by a recorded PID.
type bindfsWorker struct {
	cmd  *exec.Cmd
	done chan error
	once sync.Once
}

// startBindfsWorker starts one foreground FUSE passthrough worker with the
// exact mount context of the accepted mechanism.
func startBindfsWorker(lookPath func(string) (string, error), backing, mountpoint, context string) (projectionWorker, error) {
	bindfs, err := lookPath(bindfsBinary)
	if err != nil {
		return nil, fmt.Errorf("%s is required for SELinux read-only projections: %w", bindfsBinary, err)
	}
	cmd := exec.Command(bindfs, "-f", "-o", "allow_other", "-o", "context="+context, backing, mountpoint)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cannot start %s projection worker: %w (stderr: %s)", bindfsBinary, err, strings.TrimSpace(stderr.String()))
	}
	w := &bindfsWorker{cmd: cmd, done: make(chan error, 1)}
	go func() {
		waitErr := cmd.Wait()
		if waitErr != nil {
			waitErr = fmt.Errorf("bindfs worker exited with error: %w (stderr: %s)", waitErr, strings.TrimSpace(stderr.String()))
		}
		w.once.Do(func() { w.done <- waitErr })
	}()
	return w, nil
}

func (w *bindfsWorker) alive() bool {
	if w == nil || w.cmd.Process == nil {
		return false
	}
	return w.cmd.Process.Signal(syscall.Signal(0)) == nil
}

func (w *bindfsWorker) waitExit(timeout time.Duration) error {
	select {
	case waitErr := <-w.done:
		return waitErr
	case <-time.After(timeout):
		return fmt.Errorf("bindfs worker did not exit after unmount")
	}
}

// selinuxProjectionKind distinguishes directory and regular-file sources.
type selinuxProjectionKind int

const (
	selinuxProjectionDirectory selinuxProjectionKind = iota
	selinuxProjectionFile
)

// projectionEntry holds one read-only exposure's materialization facts.
type projectionEntry struct {
	index     int
	kind      selinuxProjectionKind
	stateDir  string
	mountDir  string
	lowerItem string
	// dockerSource is the Docker bind source of the projection: the
	// projection mount root for a directory source, or the projected item
	// for a regular-file source.
	dockerSource string
	worker       projectionWorker
}

// workloadSELinuxBackend is the SELinux backend for workload MAC
// preparation: one helper-owned bindfs projection per accepted read-only
// exposure, built strictly from the pinned kernel materialization source.
type workloadSELinuxBackend struct {
	roType string
	// lookPath resolves the bindfs executable.
	lookPath func(string) (string, error)
	// devFusePresent reports whether /dev/fuse exists.
	devFusePresent func() bool
	// startWorker starts one foreground FUSE passthrough worker.
	startWorker func(lookPath func(string) (string, error), backing, mountpoint, context string) (projectionWorker, error)
	// ops performs the mount/unmount/xattr mechanics.
	ops workloadMountOps
}

func newWorkloadSELinuxBackend() *workloadSELinuxBackend {
	return &workloadSELinuxBackend{
		roType:         selinuxROProjectionType,
		lookPath:       exec.LookPath,
		devFusePresent: func() bool { return fileExists(selinuxDevFusePath) },
		startWorker:    startBindfsWorker,
		ops:            productionMountOpsValue,
	}
}

func (b *workloadSELinuxBackend) backend() LSMBackend {
	return LSMSELinux
}

// ensureDependencies fails closed with actionable operational errors when
// the accepted mechanism's runtime dependencies are missing. There is
// deliberately no fallback to a VFS-only bind: VFS-only does not provide
// MAC parity.
func (b *workloadSELinuxBackend) ensureDependencies() error {
	if _, err := b.lookPath(bindfsBinary); err != nil {
		return fmt.Errorf("bindfs is required for SELinux read-only projections and is not installed: %w", err)
	}
	if !b.devFusePresent() {
		return fmt.Errorf("/dev/fuse is unavailable; bindfs read-only projections cannot be created")
	}
	return nil
}

// prepare creates one helper-owned projection per accepted read-only
// exposure and returns the prepared bind sources. Every proof — mount
// exists, worker alive, effective SELinux type — must hold before
// preparation succeeds; any failure rolls back owned partial state and
// fails closed so no container can start.
func (b *workloadSELinuxBackend) prepare(p workloadPreparation) (*preparedWorkloadMAC, error) {
	if err := b.ensureDependencies(); err != nil {
		return nil, err
	}

	mountSources := make([]string, len(p.Exposures))
	var projections []*projectionEntry
	for i, exposure := range p.Exposures {
		if !exposure.RequestedReadOnly {
			// Accepted read-write: direct bind of the pinned source.
			mountSources[i] = p.PinnedSources[i]
			continue
		}
		entry, err := b.prepareProjection(p, i)
		if err != nil {
			b.cleanupOwnedProjections(projections)
			return nil, err
		}
		projections = append(projections, entry)
		mountSources[i] = entry.dockerSource
	}

	return &preparedWorkloadMAC{
		Backend:      LSMSELinux,
		SecurityOpts: []string{"label=type:docker_helper_container_t"},
		MountSources: mountSources,
		cleanup: func() error {
			if err := b.cleanupOwnedProjections(projections); err != nil {
				return err
			}
			return removeAllStateDirs(p)
		},
	}, nil
}

// prepareProjection materializes one read-only exposure. The projection is
// built strictly from the pinned source: the caller spelling and the
// original canonical pathname never enter this path.
func (b *workloadSELinuxBackend) prepareProjection(p workloadPreparation, index int) (*projectionEntry, error) {
	source := p.PinnedSources[index]
	info, err := os.Lstat(source)
	if err != nil {
		return nil, fmt.Errorf("cannot stat pinned source: %w", err)
	}

	projState := filepath.Join(p.RuntimeDir, fmt.Sprintf("mount-%d", index))
	mountDir := filepath.Join(projState, "mount")
	entry := &projectionEntry{index: index, stateDir: projState, mountDir: mountDir}

	if err := os.Mkdir(projState, workloadMACStateDirPerm); err != nil {
		return nil, fmt.Errorf("cannot create projection state: %w", err)
	}

	if info.IsDir() {
		// Directory source: bindfs projects the pinned directory itself.
		entry.kind = selinuxProjectionDirectory
		if err := os.Mkdir(mountDir, workloadMACStateDirPerm); err != nil {
			os.Remove(projState)
			return nil, fmt.Errorf("cannot create projection mountpoint: %w", err)
		}
	} else if info.Mode().IsRegular() {
		// Regular-file source: bind the exact pinned file onto a
		// helper-owned lower item, project the lower directory, and expose
		// the projected item. File contents are never copied and the source
		// is never relabeled.
		entry.kind = selinuxProjectionFile
		lowerDir := filepath.Join(projState, "lower")
		if err := os.Mkdir(lowerDir, workloadMACStateDirPerm); err != nil {
			os.RemoveAll(projState)
			return nil, fmt.Errorf("cannot create projection lower directory: %w", err)
		}
		item := filepath.Join(lowerDir, "item")
		if err := os.WriteFile(item, nil, 0600); err != nil {
			os.RemoveAll(projState)
			return nil, fmt.Errorf("cannot create projection lower item: %w", err)
		}
		if err := b.ops.mountBind(source, item); err != nil {
			os.RemoveAll(projState)
			return nil, err
		}
		entry.lowerItem = item
		entry.dockerSource = filepath.Join(mountDir, "item")
	} else {
		return nil, fmt.Errorf("pinned source is neither a directory nor a regular file")
	}

	backing := source
	if entry.kind == selinuxProjectionFile {
		backing = filepath.Join(projState, "lower")
	}
	worker, err := b.startWorker(b.lookPath, backing, mountDir, selinuxROProjectionContext)
	if err != nil {
		b.cleanupOwnedProjections([]*projectionEntry{entry})
		return nil, err
	}
	entry.worker = worker

	if err := b.awaitProjectionReady(entry); err != nil {
		b.cleanupOwnedProjections([]*projectionEntry{entry})
		return nil, err
	}
	if entry.kind == selinuxProjectionDirectory {
		entry.dockerSource = mountDir
	}
	return entry, nil
}

// awaitProjectionReady waits for the projection mount and proves it:
// mountpoint exists, the owned FUSE worker is alive, and the effective
// SELinux type is exactly the projection type. Any failed proof fails
// closed.
func (b *workloadSELinuxBackend) awaitProjectionReady(entry *projectionEntry) error {
	deadline := time.Now().Add(workloadMountReadyTimeout)
	for {
		mounted, err := b.ops.isMountpoint(entry.mountDir)
		if err == nil && mounted {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("bindfs projection did not mount in time")
		}
		if entry.worker != nil && !entry.worker.alive() {
			return fmt.Errorf("bindfs projection worker exited before the projection mounted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !entry.worker.alive() {
		return fmt.Errorf("bindfs projection worker is not alive")
	}
	probe := entry.mountDir
	if entry.kind == selinuxProjectionFile {
		probe = entry.dockerSource
	}
	effectiveType, err := b.ops.selinuxTypeOf(probe)
	if err != nil {
		return fmt.Errorf("cannot prove projection SELinux context: %w", err)
	}
	if effectiveType != b.roType {
		return fmt.Errorf("projection has wrong SELinux type %q, want %q", effectiveType, b.roType)
	}
	return nil
}

// cleanupOwnedProjections releases owned projections in reverse creation
// order: projection unmount, lower file bind unmount, owned worker exit,
// then state removal. It tolerates already-absent pieces; a real failure
// is returned so the caller retains dependent state.
func (b *workloadSELinuxBackend) cleanupOwnedProjections(projections []*projectionEntry) error {
	var errs []error
	for i := len(projections) - 1; i >= 0; i-- {
		entry := projections[i]
		if mounted, err := b.ops.isMountpoint(entry.mountDir); err == nil && mounted {
			if err := b.ops.unmountPath(entry.mountDir); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		if entry.lowerItem != "" {
			if mounted, err := b.ops.isMountpoint(entry.lowerItem); err == nil && mounted {
				if err := b.ops.unmountPath(entry.lowerItem); err != nil {
					errs = append(errs, err)
					continue
				}
			}
		}
		if entry.worker != nil {
			if err := entry.worker.waitExit(workloadWorkerExitTimeout); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		if err := os.RemoveAll(entry.stateDir); err != nil {
			errs = append(errs, err)
		}
	}
	return firstError(errs)
}

// validateOwnedState proves the durable SELinux workload state is exact:
// the record is a helper-owned SELinux record and carries no AppArmor
// profile. Runtime projection state is transient under the runtime
// directory; reconciliation correlates it by the deterministic layout,
// never by a recorded PID.
func (b *workloadSELinuxBackend) validateOwnedState(record workloadMACRecord) error {
	if record.Backend != string(LSMSELinux) {
		return fmt.Errorf("record backend %q is not selinux", record.Backend)
	}
	if record.ProfileName != "" {
		return fmt.Errorf("SELinux ownership record must not carry an AppArmor profile")
	}
	return nil
}

// cleanupOwnedState removes the transient projection runtime state of one
// owned record after its correlated container is proven absent. Unmount
// order is projection first, lower file bind second.
func (b *workloadSELinuxBackend) cleanupOwnedState(record workloadMACRecord) error {
	runtimeDir := record.RuntimeDirPath()
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot scan owned projection state: %w", err)
	}
	for _, e := range entries {
		projState := filepath.Join(runtimeDir, e.Name())
		if e.IsDir() && !isProjectionDirName(e.Name()) {
			return fmt.Errorf("unexpected non-projection state directory %q; refusing cleanup", e.Name())
		}
		mountDir := filepath.Join(projState, "mount")
		if mounted, err := productionMountOpsValue.isMountpoint(mountDir); err == nil && mounted {
			if err := b.ops.unmountPath(mountDir); err != nil {
				return fmt.Errorf("cannot unmount stale projection: %w", err)
			}
		}
		lowerItem := filepath.Join(projState, "lower", "item")
		if mounted, err := productionMountOpsValue.isMountpoint(lowerItem); err == nil && mounted {
			if err := b.ops.unmountPath(lowerItem); err != nil {
				return fmt.Errorf("cannot unmount stale lower file bind: %w", err)
			}
		}
		if err := os.RemoveAll(projState); err != nil {
			return fmt.Errorf("cannot remove stale projection state: %w", err)
		}
	}
	return nil
}

// isProjectionDirName reports whether a runtime state entry is a
// deterministic projection directory name (mount-<index>).
func isProjectionDirName(name string) bool {
	if !strings.HasPrefix(name, "mount-") || len(name) <= len("mount-") {
		return false
	}
	for _, r := range name[len("mount-"):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// unmountPath unmounts one helper-owned projection path, preferring the
// FUSE userspace helper exactly like the accepted mechanism and falling
// back to the kernel umount with a lazy last resort.
func (productionMountOps) unmountPath(path string) error {
	if err := runFusermountUnmount(path); err == nil {
		return nil
	}
	if err := unix.Unmount(path, 0); err != nil {
		if err := unix.Unmount(path, unix.MNT_DETACH); err != nil {
			return fmt.Errorf("unmount %s: %w", path, err)
		}
	}
	return nil
}

// runFusermountUnmount runs fusermount3 (or fusermount) -u on path.
func runFusermountUnmount(path string) error {
	helper, err := exec.LookPath("fusermount3")
	if err != nil {
		helper, err = exec.LookPath("fusermount")
		if err != nil {
			return fmt.Errorf("fusermount is unavailable: %w", err)
		}
	}
	cmd := exec.Command(helper, "-u", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("fusermount -u %s: %w", path, err)
	}
	return nil
}

// removeAllStateDirs removes both owned state directories of one prepared
// operation; absence is success.
func removeAllStateDirs(p workloadPreparation) error {
	var errs []error
	if err := os.RemoveAll(p.StateDir); err != nil {
		errs = append(errs, err)
	}
	if err := os.RemoveAll(p.RuntimeDir); err != nil {
		errs = append(errs, err)
	}
	return firstError(errs)
}

// firstError returns the first non-nil error, if any.
func firstError(errs []error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
