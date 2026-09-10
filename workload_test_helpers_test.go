package main

// Test-only harnesses for the 2.2.6 workload MAC backends. The fakes replace
// only the external dependencies (apparmor_parser, kernel profile inventory,
// FUSE worker, mount mechanics, Docker CLI); the production renderers,
// drivers, and lifecycle owners under test keep full ownership of the
// semantics.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testWorkloadSessionID is a Session ID in the canonical issued shape
// (`dhs_` + 32 lowercase hex), suitable for durable workload ownership
// records.
const testWorkloadSessionID = "dhs_0f1e2d3c4b5a69788796a5b4c3d2e1f0"

// testOperationID returns a canonical production operation ID
// (`op_` + 32 lowercase hex) with a unique deterministic hex tail per n,
// so tests exercise the exact durable-ownership identity shape.
func testOperationID(n int) string {
	return fmt.Sprintf("op_%032x", n)
}

// profileNameFromSource extracts the declared profile name from a generated
// profile source, mirroring how the kernel inventory names loaded profiles.
func profileNameFromSource(source string) string {
	const marker = "profile \""
	start := strings.Index(source, marker)
	if start < 0 {
		return ""
	}
	rest := source[start+len(marker):]
	if end := strings.IndexByte(rest, '"'); end >= 0 {
		return rest[:end]
	}
	return rest
}

// testAppArmorWorkloadHarness records the parser/inventory behavior of the
// AppArmor workload backend harness.
type testAppArmorWorkloadHarness struct {
	loaded      map[string]bool
	loadErr     error
	unloadErr   error
	parserCalls []string
}

// newTestAppArmorWorkloadBackend returns the production AppArmor backend
// with the parser and kernel-inventory seams replaced by the harness.
func newTestAppArmorWorkloadBackend(t *testing.T) (*workloadAppArmorBackend, *testAppArmorWorkloadHarness) {
	t.Helper()
	h := &testAppArmorWorkloadHarness{loaded: map[string]bool{}}
	b := newWorkloadAppArmorBackend()
	// Production parser availability check reads parserPath; point it at a
	// helper-owned regular file so the real check runs against the seam.
	parserPath := filepath.Join(t.TempDir(), "apparmor_parser")
	if err := os.WriteFile(parserPath, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatalf("cannot fake apparmor_parser: %v", err)
	}
	b.parserPath = parserPath
	b.abi30Present = func() bool { return false }
	b.runParser = func(parserPath string, args []string) error {
		if len(args) == 0 {
			return errors.New("parser invoked without arguments")
		}
		profilePath := args[len(args)-1]
		source, readErr := os.ReadFile(profilePath)
		var profileName string
		if readErr == nil {
			profileName = profileNameFromSource(string(source))
		} else if args[0] == "--remove" && os.IsNotExist(readErr) {
			// The profile source is already gone (raced removal); the
			// profile is provably absent in the fake inventory.
			h.parserCalls = append(h.parserCalls, args[0]+" "+profilePath)
			return nil
		} else {
			return readErr
		}
		switch args[0] {
		case "--replace":
			if h.loadErr != nil {
				return h.loadErr
			}
			h.loaded[profileName] = true
		case "--remove":
			if h.unloadErr != nil {
				return h.unloadErr
			}
			h.loaded[profileName] = false
		default:
			return errors.New("unexpected parser invocation: " + strings.Join(args, " "))
		}
		h.parserCalls = append(h.parserCalls, args[0]+" "+profileName)
		return nil
	}
	b.loadedProfiles = func() ([]string, error) {
		var names []string
		for name, ok := range h.loaded {
			if ok {
				names = append(names, name)
			}
		}
		return names, nil
	}
	return b, h
}

// testProjectionWorker is the fake projection worker of the SELinux harness.
type testProjectionWorker struct {
	isAlive    bool
	seam       *testSELinuxWorkloadSeam
	mountpoint string
}

func (w *testProjectionWorker) alive() bool { return w.isAlive }

func (w *testProjectionWorker) waitExit(timeout time.Duration) error {
	if w.seam != nil {
		w.seam.events = append(w.seam.events, "worker-exit "+w.mountpoint)
	}
	return nil
}

// testWorkerCall records one bindfs worker invocation.
type testWorkerCall struct {
	backing    string
	mountpoint string
	context    string
}

// testSELinuxWorkloadSeam fakes the FUSE worker, the mount mechanics, and
// the SELinux xattr proof for the production SELinux backend.
type testSELinuxWorkloadSeam struct {
	lookPathErr  error
	startErr     error
	mounted      map[string]bool
	binds        [][2]string
	unmountCalls []string
	typeByPath   map[string]string
	workers      []*testProjectionWorker
	mountCalls   []testWorkerCall
	// typeErr makes every xattr proof fail (proof-unavailable path).
	typeErr error
	// mountErrByPath fails the inventory proof for exactly those paths
	// (targeted unknown-inventory injection).
	mountErrByPath map[string]error
	// mountInventoryErr makes every isMountpoint proof fail
	// (inventory-unavailable path).
	mountInventoryErr error
	// unmountLeavesMounted makes unmountPath claim success while the
	// mount inventory keeps reporting the mount (verification-failure path).
	unmountLeavesMounted bool
	// postUnmountInventoryErr makes isMountpoint fail once at least one
	// unmount has been performed (post-unmount inventory path).
	postUnmountInventoryErr error
	unmountCount            int
	// events records the release-mechanics call order (unmounts and worker
	// exits) so tests can prove dependency ordering.
	events []string
}

// testMountOps is the fake workloadMountOps bound to the seam.
type testMountOps struct{ seam *testSELinuxWorkloadSeam }

func (m *testMountOps) isMountpoint(path string) (bool, error) {
	if err, ok := m.seam.mountErrByPath[path]; ok {
		return false, err
	}
	if m.seam.mountInventoryErr != nil {
		return false, m.seam.mountInventoryErr
	}
	if m.seam.postUnmountInventoryErr != nil && m.seam.unmountCount > 0 {
		return false, m.seam.postUnmountInventoryErr
	}
	return m.seam.mounted[path], nil
}

func (m *testMountOps) mountBind(source, target string) error {
	m.seam.binds = append(m.seam.binds, [2]string{source, target})
	m.seam.mounted[target] = true
	return nil
}

func (m *testMountOps) unmount(path string) error {
	m.seam.unmountCalls = append(m.seam.unmountCalls, path)
	delete(m.seam.mounted, path)
	return nil
}

func (m *testMountOps) unmountLazy(path string) error {
	m.seam.unmountCalls = append(m.seam.unmountCalls, path+" lazy")
	delete(m.seam.mounted, path)
	return nil
}

func (m *testMountOps) unmountPath(path string) error {
	m.seam.unmountCalls = append(m.seam.unmountCalls, "unmountPath "+path)
	m.seam.events = append(m.seam.events, "unmount "+path)
	m.seam.unmountCount++
	if !m.seam.unmountLeavesMounted {
		delete(m.seam.mounted, path)
	}
	return nil
}

func (m *testMountOps) selinuxTypeOf(path string) (string, error) {
	if m.seam.typeErr != nil {
		return "", m.seam.typeErr
	}
	if t, ok := m.seam.typeByPath[path]; ok {
		return t, nil
	}
	return selinuxROProjectionType, nil
}

// newTestSELinuxBackend returns the production SELinux backend with the
// FUSE worker, mount mechanics, and dependency seams replaced by the harness.
func newTestSELinuxBackend(t *testing.T) (*workloadSELinuxBackend, *testSELinuxWorkloadSeam) {
	t.Helper()
	seam := &testSELinuxWorkloadSeam{
		mounted:        map[string]bool{},
		mountErrByPath: map[string]error{},
		typeByPath:     map[string]string{},
	}
	b := newWorkloadSELinuxBackend()
	b.lookPath = func(string) (string, error) {
		if seam.lookPathErr != nil {
			return "", seam.lookPathErr
		}
		return "/usr/bin/bindfs", nil
	}
	b.devFusePresent = func() bool { return true }
	b.startWorker = func(lookPath func(string) (string, error), backing, mountpoint, context string) (projectionWorker, error) {
		if seam.startErr != nil {
			return nil, seam.startErr
		}
		worker := &testProjectionWorker{isAlive: true, seam: seam, mountpoint: mountpoint}
		seam.workers = append(seam.workers, worker)
		seam.mounted[mountpoint] = true
		seam.mountCalls = append(seam.mountCalls, testWorkerCall{backing: backing, mountpoint: mountpoint, context: context})
		return worker, nil
	}
	b.ops = &testMountOps{seam: seam}
	return b, seam
}

// installTestWorkloadMACForTest installs a real test-seamed workload MAC
// coordinator with the given backend on the app. Production renderers,
// drivers, and lifecycle owners run unchanged; only the parser, kernel
// inventory, mount mechanics, and Docker CLI are replaced by seams. The
// coordinator must be installed after the LSM seam is mocked.
func installTestWorkloadMACForTest(t *testing.T, app *App, backend LSMBackend) *workloadMACCoordinator {
	t.Helper()
	var backendImpl workloadMACBackend
	switch backend {
	case LSMAppArmor:
		backendImpl, _ = newTestAppArmorWorkloadBackend(t)
	case LSMSELinux:
		selBackend, _ := newTestSELinuxBackend(t)
		backendImpl = selBackend
	default:
		t.Fatalf("unsupported test workload backend: %s", backend)
	}
	c := &workloadMACCoordinator{
		backend:     backendImpl,
		stateRoot:   filepath.Join(app.Config.StateDir, workloadMACStateRootName),
		runtimeRoot: filepath.Join(app.Config.RuntimeDir, workloadMACStateRootName),
		inspectContainers: func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
			return nil, nil
		},
		removeContainer:  func(ctx context.Context, containerID string) error { return nil },
		cleanupStalePins: func(operationID string) error { return nil },
	}
	app.WorkloadMAC = c
	return c
}
