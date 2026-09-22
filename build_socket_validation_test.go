package main

// build_socket_validation_test.go proves the root-side independent
// validation of the deterministic BuildKit endpoint (Release-2.4 §6)
// against REAL Unix sockets on a test-scoped runtime root:
//
//   - the table of acceptance/refusal mechanics (exists, no symlink, a
//     Unix socket, owned by the expected builder identity, private mode);
//   - the driver-level consequence: a validation failure stops the
//     builder and never starts buildctl (the START round-trip is the
//     only manager RPC on that path).

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// builderSocketFixture redirects the shared P2 runtime-root owner to a
// test-scoped root and fixes the expected builder identity to the test
// process (the builderClientManagerUID seam): a socket this process binds
// is then exactly the expected builder-owned endpoint. It returns the
// runtime root.
func builderSocketFixture(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp(".", "bsv")
	if err != nil {
		t.Fatalf("cannot create test runtime root: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	rtRoot := filepath.Join(base, "run")
	if err := os.MkdirAll(rtRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	origRoot := builderRuntimeRoot
	builderRuntimeRoot = rtRoot
	t.Cleanup(func() { builderRuntimeRoot = origRoot })

	uid := os.Getuid()
	origUID := builderClientManagerUID
	builderClientManagerUID = func() (int, int, error) { return uid, uid, nil }
	t.Cleanup(func() { builderClientManagerUID = origUID })
	return rtRoot
}

// bindBuilderSocket binds a REAL Unix socket at the expected op endpoint
// with the given mode (0 = default), standing in for buildkitd's bind.
func bindBuilderSocket(t *testing.T, opID string, mode os.FileMode) string {
	t.Helper()
	dir := opRuntimeDir(opID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := opSocketPath(opID)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("cannot bind real socket: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	if mode != 0 {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// TestBuildSocketValidationTable drives validateBuildKitSocketPath
// (production body) over the validation table with REAL sockets.
func TestBuildSocketValidationTable(t *testing.T) {
	builderSocketFixture(t)
	identityOK := func() (int, int, error) { return os.Getuid(), os.Getgid(), nil }

	// Valid private socket owned by the expected identity: accepted.
	validOp := "op_0123456789abcdef0123456789abcdef"
	validPath := bindBuilderSocket(t, validOp, 0o600)
	if err := validateBuildKitSocketPath(validPath, identityOK); err != nil {
		t.Fatalf("valid private builder-owned socket refused: %v", err)
	}

	// Missing endpoint: refused.
	missingOp := "op_fedcba9876543210fedcba9876543210"
	missing := filepath.Join(opRuntimeDir(missingOp), "buildkitd.sock")
	err := validateBuildKitSocketPath(missing, identityOK)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing endpoint = %v, want missing-socket refusal", err)
	}

	// Symlink (even to a valid socket): refused — the endpoint must be the
	// deterministic path itself, not an alias.
	symlinkOp := "op_11111111111111111111111111111111"
	target := bindBuilderSocket(t, symlinkOp, 0o600)
	linkOp := "op_22222222222222222222222222222222"
	if err := os.MkdirAll(opRuntimeDir(linkOp), 0o700); err != nil {
		t.Fatal(err)
	}
	linkPath := opSocketPath(linkOp)
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatal(err)
	}
	if err := validateBuildKitSocketPath(linkPath, identityOK); err == nil {
		t.Fatal("symlinked endpoint accepted")
	}

	// Regular file at the endpoint: refused (not a socket).
	fileOp := "op_33333333333333333333333333333333"
	if err := os.MkdirAll(opRuntimeDir(fileOp), 0o700); err != nil {
		t.Fatal(err)
	}
	filePath := opSocketPath(fileOp)
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateBuildKitSocketPath(filePath, identityOK); err == nil {
		t.Fatal("regular file accepted as the BuildKit endpoint")
	}

	// Group-accessible mode: refused (the endpoint must stay private to
	// the builder identity).
	groupOp := "op_55555555555555555555555555555555"
	groupPath := bindBuilderSocket(t, groupOp, 0o660)
	if err := validateBuildKitSocketPath(groupPath, identityOK); err == nil {
		t.Fatal("group-accessible endpoint accepted")
	}

	// World-accessible mode: refused.
	worldOp := "op_66666666666666666666666666666666"
	worldPath := bindBuilderSocket(t, worldOp, 0o666)
	if err := validateBuildKitSocketPath(worldPath, identityOK); err == nil {
		t.Fatal("world-accessible endpoint accepted")
	}

	// The expected-owner resolver failing is a refusal (fail closed).
	resolverOp := "op_77777777777777777777777777777777"
	resolverPath := bindBuilderSocket(t, resolverOp, 0o600)
	resolverErr := errors.New("builder identity unavailable")
	if err := validateBuildKitSocketPath(resolverPath, func() (int, int, error) { return 0, 0, resolverErr }); !errors.Is(err, resolverErr) {
		t.Fatalf("failing identity resolver = %v, want the resolver error", err)
	}

	// The same valid socket refused for a DIFFERENT expected identity:
	// proves the UID check compares the resolver's answer against the
	// real socket owner (the ownership invariant), not os.Geteuid().
	if err := validateBuildKitSocketPath(validPath, func() (int, int, error) { return 9999, 9999, nil }); err == nil {
		t.Fatal("endpoint accepted for a different expected identity")
	}
}

// TestBuildSocketValidationDriverStopsBuilder proves the driver-level
// consequence through the production path: after manager START accepted,
// a socket-validation failure performs the mandatory STOP cleanup, never
// starts buildctl (or any child), and terminates the operation failed
// with the docker_build_failed result and no child exit code.
func TestBuildSocketValidationDriverStopsBuilder(t *testing.T) {
	app, _, result, manager, calls := setupBuildBackendTest(t)

	// Keep manager START accepting; make the root-side validation refuse.
	app.validateBuildKitSocketFn = func(string) error { return errors.New("buildkit socket is not private") }

	op := startBackendBuild(t, app, result.Token, nil)
	op.Wait()

	if got := manager.startCount(); got != 1 {
		t.Errorf("manager START count = %d, want 1 (validation is reached after START)", got)
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("manager STOP count = %d, want exactly 1 after validation failure", got)
	}
	if got := calls.count(); got != 0 {
		t.Errorf("children started = %d, want 0 (no buildctl/import after failed validation):\n%s", got, calls.all())
	}

	op.mu.Lock()
	state := op.State
	var rc string
	if op.ResultCode != nil {
		rc = *op.ResultCode
	}
	exitCode := op.ExitCode
	op.mu.Unlock()
	if state != operationFailed {
		t.Errorf("state = %q, want failed", state)
	}
	if rc != "docker_build_failed" {
		t.Errorf("result_code = %q, want docker_build_failed", rc)
	}
	if exitCode != nil {
		t.Errorf("exit_code = %v, want nil (validation is a no-child stage)", exitCode)
	}
}
