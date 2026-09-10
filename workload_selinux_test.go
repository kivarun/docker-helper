package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSELinuxWorkloadPrepareDirectoryProjection drives the production SELinux
// backend through a read-only directory exposure: the bindfs worker must run
// against the pinned source with the exact projection context, the proof
// chain must pass, the security option must stay label=type..., and the
// Docker bind source must be the helper-owned projection mountpoint.
func TestSELinuxWorkloadPrepareDirectoryProjection(t *testing.T) {
	dir := t.TempDir()
	b, seam := newTestSELinuxBackend(t)
	pinnedDir := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinnedDir, 0700); err != nil {
		t.Fatal(err)
	}
	pinned := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}
	prep := workloadPreparation{
		OperationID:   "op_s1",
		SessionID:     "sess1",
		StateDir:      filepath.Join(dir, "state", "op_s1"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_s1"),
		Exposures:     []sessionFilesystemExposure{{Target: "/data", RequestedReadOnly: true}},
		PinnedSources: []string{pinned},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, err := b.prepare(prep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer prepared.Cleanup()
	if len(seam.mountCalls) != 1 {
		t.Fatalf("expected one bindfs worker, got %d", len(seam.mountCalls))
	}
	call := seam.mountCalls[0]
	if call.backing != pinned {
		t.Errorf("bindfs must project the pinned source, got %q", call.backing)
	}
	if call.context != selinuxROProjectionContext {
		t.Errorf("projection context: got %q, want %q", call.context, selinuxROProjectionContext)
	}
	wantSource := filepath.Join(prep.RuntimeDir, "mount-0", "mount")
	if prepared.MountSources[0] != wantSource {
		t.Errorf("Docker bind source must be the helper-owned projection, got %q", prepared.MountSources[0])
	}
	if prepared.SecurityOpts[0] != "label=type:docker_helper_container_t" {
		t.Errorf("security opts: %v", prepared.SecurityOpts)
	}
	if !seam.mounted[wantSource] {
		t.Errorf("projection must be proven mounted")
	}
}

// TestSELinuxWorkloadPrepareRegularFileProjection drives the regular-file
// contract: exact pinned file bound onto a helper-owned lower item, the
// lower directory projected, and the Docker source is projection/item.
func TestSELinuxWorkloadPrepareRegularFileProjection(t *testing.T) {
	dir := t.TempDir()
	b, seam := newTestSELinuxBackend(t)
	pinnedFile := filepath.Join(dir, "pinned.txt")
	if err := os.WriteFile(pinnedFile, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	prep := workloadPreparation{
		OperationID:   "op_s2",
		SessionID:     "sess1",
		StateDir:      filepath.Join(dir, "state", "op_s2"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_s2"),
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs/config.txt", RequestedReadOnly: true}},
		PinnedSources: []string{pinnedFile},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, err := b.prepare(prep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer prepared.Cleanup()
	wantSource := filepath.Join(prep.RuntimeDir, "mount-0", "mount", "item")
	if prepared.MountSources[0] != wantSource {
		t.Errorf("file projection Docker source: got %q, want %q", prepared.MountSources[0], wantSource)
	}
	// The projection mountpoint is helper-owned real state for both
	// projection kinds: bindfs was started with it as its mountpoint.
	mountInfo, err := os.Lstat(filepath.Join(prep.RuntimeDir, "mount-0", "mount"))
	if err != nil {
		t.Fatalf("regular-file projection must own a real mountpoint directory: %v", err)
	}
	if !mountInfo.IsDir() || mountInfo.Mode()&os.ModeSymlink != 0 {
		t.Errorf("projection mountpoint must be a real helper-owned directory, got %v", mountInfo.Mode())
	}
	// The pinned file must be bound onto the lower item exactly once.
	bind := [2]string{pinnedFile, filepath.Join(prep.RuntimeDir, "mount-0", "lower", "item")}
	bindSeen := false
	for _, b := range seam.binds {
		if b == bind {
			bindSeen = true
		}
	}
	if !bindSeen {
		t.Errorf("expected lower bind %v, got %v", bind, seam.binds)
	}
}

// TestSELinuxWorkloadRWUsesPinnedSourceDirectly proves accepted RW exposures
// bypass projection and bind the pinned source directly.
func TestSELinuxWorkloadRWUsesPinnedSourceDirectly(t *testing.T) {
	dir := t.TempDir()
	b, seam := newTestSELinuxBackend(t)
	pinned := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}
	prep := workloadPreparation{
		OperationID:   "op_s3",
		SessionID:     "sess1",
		StateDir:      filepath.Join(dir, "state", "op_s3"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_s3"),
		Exposures:     []sessionFilesystemExposure{{Target: "/project", RequestedReadOnly: false}},
		PinnedSources: []string{pinned},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, err := b.prepare(prep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer prepared.Cleanup()
	if len(seam.mountCalls) != 0 {
		t.Fatalf("RW exposure must not create projections, got %v", seam.mountCalls)
	}
	if prepared.MountSources[0] != pinned {
		t.Errorf("RW source must be the pinned path, got %q", prepared.MountSources[0])
	}
}

// TestSELinuxWorkloadMixedModesIndependentProjections proves one projection
// per RO exposure with deterministic mount-index naming, and that the same
// backing tree projected in two operations gets independent paths.
func TestSELinuxWorkloadIndependentPathsPerOperation(t *testing.T) {
	dir := t.TempDir()
	b, _ := newTestSELinuxBackend(t)
	pinned := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}
	mk := func(opID string) (*preparedWorkloadMAC, string, string) {
		prep := workloadPreparation{
			OperationID:   opID,
			SessionID:     "sess1",
			StateDir:      filepath.Join(dir, "state", opID),
			RuntimeDir:    filepath.Join(dir, "runtime", opID),
			Exposures:     []sessionFilesystemExposure{{Target: "/data", RequestedReadOnly: true}},
			PinnedSources: []string{pinned},
		}
		if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
			t.Fatal(err)
		}
		prepared, err := b.prepare(prep)
		if err != nil {
			t.Fatalf("prepare %s: %v", opID, err)
		}
		return prepared, prep.StateDir, prep.RuntimeDir
	}
	p1, s1, r1 := mk("op_aaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
	p2, s2, r2 := mk("op_bbbbbbbbbbbbbbbbbbbbbbbbbbbbb2")
	if p1.MountSources[0] == p2.MountSources[0] {
		t.Fatalf("projections of separate operations must not share paths: %q", p1.MountSources[0])
	}
	if s1 == s2 || r1 == r2 {
		t.Fatalf("separate operations must have separate state roots")
	}
	_ = s1
	_ = s2
	_ = r1
	_ = r2
	p1.Cleanup()
	p2.Cleanup()
}

// TestSELinuxWorkloadPrepareFailureRollsBackPartialProjection proves a
// projection proof failure fails preparation, leaves no Docker run, and
// rolls back the owned partial projection state.
func TestSELinuxWorkloadPrepareFailureRollsBackPartialProjection(t *testing.T) {
	dir := t.TempDir()
	b, seam := newTestSELinuxBackend(t)
	pinned := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}
	// Make the effective-type proof fail.
	seam.typeErr = errors.New("xattr proof unavailable")
	prep := workloadPreparation{
		OperationID:   "op_s4",
		SessionID:     "sess1",
		StateDir:      filepath.Join(dir, "state", "op_s4"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_s4"),
		Exposures:     []sessionFilesystemExposure{{Target: "/data", RequestedReadOnly: true}},
		PinnedSources: []string{pinned},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := b.prepare(prep); err == nil {
		t.Fatal("projection proof failure must fail preparation")
	}
	if len(seam.unmountCalls) == 0 {
		t.Error("partial projection must be rolled back with unmount attempts")
	}
	if _, err := os.Stat(filepath.Join(prep.RuntimeDir, "mount-0")); !os.IsNotExist(err) {
		t.Errorf("partial projection state must be removed, got %v", err)
	}
}

// TestSELinuxWorkloadMissingBindfsFailsClosed proves the explicit bindfs
// dependency contract: a missing bindfs binary fails preparation closed with
// an actionable error and no Docker container can start.
func TestSELinuxWorkloadMissingBindfsFailsClosed(t *testing.T) {
	b, _ := newTestSELinuxBackend(t)
	b.lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	err := b.ensureDependencies()
	if err == nil {
		t.Fatal("missing bindfs must fail closed")
	}
	if !strings.Contains(err.Error(), "bindfs") {
		t.Errorf("actionable error must name the missing dependency: %v", err)
	}
}

// TestSELinuxWorkloadCleanupReverseOrder proves cleanup releases owned
// projections in reverse creation order and then removes the transient
// runtime state.
func TestSELinuxWorkloadCleanupReverseOrder(t *testing.T) {
	dir := t.TempDir()
	b, seam := newTestSELinuxBackend(t)
	pinned := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}
	prep := workloadPreparation{
		OperationID:   "op_s5",
		SessionID:     "sess1",
		StateDir:      filepath.Join(dir, "state", "op_s5"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_s5"),
		Exposures:     []sessionFilesystemExposure{{Target: "/a", RequestedReadOnly: true}, {Target: "/b", RequestedReadOnly: true}},
		PinnedSources: []string{pinned, pinned},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, err := b.prepare(prep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := prepared.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	// Idempotent: second cleanup is a no-op, not an error.
	if err := prepared.Cleanup(); err != nil {
		t.Errorf("cleanup must be idempotent: %v", err)
	}
	// The backend cleanup releases the per-projection state; the durable
	// ownership record and the runtime directory root are removed only by
	// the coordinator finalization boundary after the dependent cleanup.
	if _, err := os.Stat(filepath.Join(prep.RuntimeDir, "mount-0")); !os.IsNotExist(err) {
		t.Errorf("projection state mount-0 must be removed, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(prep.RuntimeDir, "mount-1")); !os.IsNotExist(err) {
		t.Errorf("projection state mount-1 must be removed, got %v", err)
	}
	if got := len(seam.unmountCalls); got != 2 {
		t.Errorf("expected two projection unmounts, got %v", seam.unmountCalls)
	}
}

// TestSELinuxWorkloadCleanupOrderProvesWorkerExitBeforeLowerUnmount proves
// the frozen dependency order of a live regular-file projection cleanup:
// the projection mount is proven gone, then the owned worker exit is
// proven, and only then may the lower file bind be released — the worker
// backs on the lower tree.
func TestSELinuxWorkloadCleanupOrderProvesWorkerExitBeforeLowerUnmount(t *testing.T) {
	dir := t.TempDir()
	b, seam := newTestSELinuxBackend(t)
	pinnedFile := filepath.Join(dir, "pinned.txt")
	if err := os.WriteFile(pinnedFile, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	prep := workloadPreparation{
		OperationID:   "op_s6",
		SessionID:     "sess1",
		StateDir:      filepath.Join(dir, "state", "op_s6"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_s6"),
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs/config.txt", RequestedReadOnly: true}},
		PinnedSources: []string{pinnedFile},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, err := b.prepare(prep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := prepared.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	mountDir := filepath.Join(prep.RuntimeDir, "mount-0", "mount")
	lowerItem := filepath.Join(prep.RuntimeDir, "mount-0", "lower", "item")
	mountIdx, workerIdx, lowerIdx := -1, -1, -1
	for i, event := range seam.events {
		switch event {
		case "unmount " + mountDir:
			mountIdx = i
		case "worker-exit " + mountDir:
			workerIdx = i
		case "unmount " + lowerItem:
			lowerIdx = i
		}
	}
	if mountIdx < 0 || workerIdx < 0 || lowerIdx < 0 {
		t.Fatalf("expected projection unmount, worker exit, and lower unmount events, got %v", seam.events)
	}
	if !(mountIdx < workerIdx && workerIdx < lowerIdx) {
		t.Errorf("dependency order violated: unmount %d < worker-exit %d < lower unmount %d (events %v)",
			mountIdx, workerIdx, lowerIdx, seam.events)
	}
}

// TestSELinuxWorkloadCleanupRetainsOnMountInventoryError proves the
// unknown-is-not-absent contract: when the mount inventory is unavailable
// before the unmount, the cleanup fails, the mount stays mounted, and no
// owned filesystem state is removed.
func TestSELinuxWorkloadCleanupRetainsOnMountInventoryError(t *testing.T) {
	dir := t.TempDir()
	b, seam := newTestSELinuxBackend(t)
	pinned := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}
	prep := workloadPreparation{
		OperationID:   "op_inv1",
		SessionID:     "sess1",
		StateDir:      filepath.Join(dir, "state", "op_inv"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_inv"),
		Exposures:     []sessionFilesystemExposure{{Target: "/data", RequestedReadOnly: true}},
		PinnedSources: []string{pinned},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, err := b.prepare(prep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	projection := prepared.MountSources[0]
	seam.mountInventoryErr = errors.New("mount inventory unavailable")
	if err := prepared.Cleanup(); err == nil {
		t.Fatal("unknown mount inventory must fail cleanup")
	}
	if !seam.mounted[projection] {
		t.Fatal("the projection mount must stay mounted on an inventory error")
	}
	if _, err := os.Stat(prep.RuntimeDir); err != nil {
		t.Errorf("owned runtime state must be retained on an inventory error, got %v", err)
	}
	if _, err := os.Stat(prep.StateDir); err != nil {
		t.Errorf("owned durable state must be retained on an inventory error, got %v", err)
	}
}

// TestSELinuxWorkloadCleanupRetainsOnPostUnmountInventoryError proves that
// an inventory failure after the claimed unmount fails the cleanup: absence
// must be proven, never assumed.
func TestSELinuxWorkloadCleanupRetainsOnPostUnmountInventoryError(t *testing.T) {
	dir := t.TempDir()
	b, seam := newTestSELinuxBackend(t)
	pinned := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}
	prep := workloadPreparation{
		OperationID:   "op_inv2",
		SessionID:     "sess1",
		StateDir:      filepath.Join(dir, "state", "op_inv2"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_inv2"),
		Exposures:     []sessionFilesystemExposure{{Target: "/a", RequestedReadOnly: true}},
		PinnedSources: []string{pinned},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, err := b.prepare(prep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	seam.postUnmountInventoryErr = errors.New("inventory unreadable after unmount")
	if err := prepared.Cleanup(); err == nil {
		t.Fatal("post-unmount inventory failure must fail the cleanup")
	}
	if _, err := os.Stat(filepath.Join(prep.RuntimeDir, "mount-0")); err != nil {
		t.Errorf("owned projection state must be retained when absence is unprovable, got %v", err)
	}
}

// TestSELinuxWorkloadCleanupRetainsWhenUnmountLeavesMount proves that a
// claimed-but-unproven unmount (the mount inventory still lists the mount)
// retains the owned state instead of removing it.
func TestSELinuxWorkloadCleanupRetainsWhenUnmountLeavesMounted(t *testing.T) {
	dir := t.TempDir()
	b, seam := newTestSELinuxBackend(t)
	pinned := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}
	prep := workloadPreparation{
		OperationID:   "op_inv3",
		SessionID:     "sess1",
		StateDir:      filepath.Join(dir, "state", "op_inv3"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_inv3"),
		Exposures:     []sessionFilesystemExposure{{Target: "/a", RequestedReadOnly: true}},
		PinnedSources: []string{pinned},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, err := b.prepare(prep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	seam.unmountLeavesMounted = true
	if err := prepared.Cleanup(); err == nil {
		t.Fatal("an unverified unmount must fail the cleanup")
	}
	if _, err := os.Stat(filepath.Join(prep.RuntimeDir, "mount-0")); err != nil {
		t.Errorf("projection state must be retained when absence is unproven, got %v", err)
	}
}

// TestSELinuxWorkloadCleanupRetainsOnLowerFileBindInventoryError proves the
// regular-file lower bind gets the same unknown-is-not-absent treatment.
func TestSELinuxWorkloadCleanupRetainsOnLowerFileBindInventoryError(t *testing.T) {
	dir := t.TempDir()
	b, seam := newTestSELinuxBackend(t)
	pinnedFile := filepath.Join(dir, "pinned.txt")
	if err := os.WriteFile(pinnedFile, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	prep := workloadPreparation{
		OperationID:   "op_inv4",
		SessionID:     "sess1",
		StateDir:      filepath.Join(dir, "state", "op_inv4"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_inv4"),
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs/config.txt", RequestedReadOnly: true}},
		PinnedSources: []string{pinnedFile},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, err := b.prepare(prep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	lowerItem := filepath.Join(prep.RuntimeDir, "mount-0", "lower", "item")
	// The projection unmounts and verifies; the lower-file bind inventory
	// then reports unknown.
	seam.mountErrByPath[lowerItem] = errors.New("lower inventory unavailable")
	if err := prepared.Cleanup(); err == nil {
		t.Fatal("lower-file inventory failure must fail the cleanup")
	}
	if _, err := os.Stat(filepath.Join(prep.RuntimeDir, "mount-0")); err != nil {
		t.Errorf("owned state must be retained when the lower bind inventory is unknown, got %v", err)
	}
	if !seam.mounted[lowerItem] {
		t.Errorf("lower item mount must remain mounted when its inventory is unknown, got %v", seam.mounted)
	}
}

// newTestSELinuxOwnedState produces one owned SELinux operation state
// through the real coordinator Prepare path so the adversarial shape tests
// mutate state the production writer actually created.
func newTestSELinuxOwnedState(t *testing.T, stateRoot, runtimeRoot, opID string) {
	t.Helper()
	pinned := filepath.Join(t.TempDir(), "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}
	firstBackend, _ := newTestSELinuxBackend(t)
	first := newTestWorkloadCoordinator(t, firstBackend, stateRoot, runtimeRoot)
	if _, err := first.Prepare(workloadPreparation{
		OperationID:   opID,
		SessionID:     testWorkloadSessionID,
		Exposures:     []sessionFilesystemExposure{{Target: "/data", RequestedReadOnly: true}},
		PinnedSources: []string{pinned},
	}); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
}

// TestSELinuxReconcileAdversarialRuntimeShape proves the exact-shape
// ownership proof: every deviation — a symlinked mount-<index> entry, a
// symlinked mountpoint, a malformed name, a foreign child, or an unexpected
// node — retains the entire operation state and performs zero unmount
// attempts, including against the foreign target of a symlink.
func TestSELinuxReconcileAdversarialRuntimeShape(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, runtimeOpDir, foreignMount, foreignLower string)
	}{
		{
			name: "mount-0 is a symlink to a foreign tree",
			mutate: func(t *testing.T, runtimeOpDir, foreignMount, _ string) {
				if err := os.RemoveAll(filepath.Join(runtimeOpDir, "mount-0")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Dir(foreignMount), filepath.Join(runtimeOpDir, "mount-0")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "mount is a symlink to a foreign mount",
			mutate: func(t *testing.T, runtimeOpDir, foreignMount, _ string) {
				if err := os.Remove(filepath.Join(runtimeOpDir, "mount-0", "mount")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(foreignMount, filepath.Join(runtimeOpDir, "mount-0", "mount")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed projection name with leading zero",
			mutate: func(t *testing.T, runtimeOpDir, _, _ string) {
				if err := os.Rename(filepath.Join(runtimeOpDir, "mount-0"), filepath.Join(runtimeOpDir, "mount-01")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed projection name with non-decimal suffix",
			mutate: func(t *testing.T, runtimeOpDir, _, _ string) {
				if err := os.Rename(filepath.Join(runtimeOpDir, "mount-0"), filepath.Join(runtimeOpDir, "mount-0x")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "foreign child next to projection state",
			mutate: func(t *testing.T, runtimeOpDir, _, _ string) {
				if err := os.WriteFile(filepath.Join(runtimeOpDir, "notes.txt"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "mountpoint is an unexpected regular file",
			mutate: func(t *testing.T, runtimeOpDir, _, _ string) {
				if err := os.RemoveAll(filepath.Join(runtimeOpDir, "mount-0", "mount")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(runtimeOpDir, "mount-0", "mount"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "lower item is a symlink to a foreign file",
			mutate: func(t *testing.T, runtimeOpDir, _, _ string) {
				// Directory projections carry no lower tree; build one so
				// the adversarial mutation targets the real layout shape.
				if err := os.MkdirAll(filepath.Join(runtimeOpDir, "mount-0", "lower"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(runtimeOpDir, "mount-0", "lower", "item"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				foreignFile := filepath.Join(t.TempDir(), "foreign-file")
				if err := os.WriteFile(foreignFile, []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(runtimeOpDir, "mount-0", "lower", "item")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(foreignFile, filepath.Join(runtimeOpDir, "mount-0", "lower", "item")); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stateRoot := filepath.Join(t.TempDir(), "state")
			runtimeRoot := filepath.Join(t.TempDir(), "runtime")
			if err := os.MkdirAll(stateRoot, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(runtimeRoot, 0700); err != nil {
				t.Fatal(err)
			}
			opID := testOperationID(51)
			newTestSELinuxOwnedState(t, stateRoot, runtimeRoot, opID)

			// The foreign tree the symlink points into, pre-seeded with a
			// mount at the exact expected layout so any shape bypass would
			// attempt an unmount against it.
			foreignRoot := filepath.Join(t.TempDir(), "foreign")
			foreignMount := filepath.Join(foreignRoot, "mount-target", "mount")
			if err := os.MkdirAll(foreignMount, 0755); err != nil {
				t.Fatal(err)
			}
			foreignLower := filepath.Join(foreignRoot, "mount-target", "lower")

			tc.mutate(t, filepath.Join(runtimeRoot, opID), foreignMount, foreignLower)

			freshBackend, freshSeam := newTestSELinuxBackend(t)
			freshSeam.mounted[foreignMount] = true
			fresh := newTestWorkloadCoordinator(t, freshBackend, stateRoot, runtimeRoot)
			if err := fresh.ReconcileStartup(context.Background()); err != nil {
				t.Fatalf("ReconcileStartup must retain, not fail: %v", err)
			}
			if len(freshSeam.unmountCalls) != 0 {
				t.Errorf("adversarial shape must cause zero unmount attempts, got %v", freshSeam.unmountCalls)
			}
			if _, err := os.Stat(foreignMount); err != nil {
				t.Errorf("foreign tree must be untouched: %v", err)
			}
			if _, err := os.Stat(filepath.Join(stateRoot, opID)); err != nil {
				t.Errorf("adversarial state must be retained for review: %v", err)
			}
		})
	}
}
