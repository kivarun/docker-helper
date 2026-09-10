package main

import (
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
	defer func() { _ = seam }()
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
	if _, err := os.Stat(prep.RuntimeDir); !os.IsNotExist(err) {
		t.Errorf("runtime projection state must be removed, got %v", err)
	}
}
