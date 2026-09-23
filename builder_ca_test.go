package main

// P3-D2a system CA boundary proofs. The frozen resolver order is proven
// over temporary fixtures (deterministic, host/UID-independent): the
// first existing readable candidate wins, missing/wrong-kind/dangling/
// unreadable candidates are skipped, no readable bundle fails START
// closed with no child spawn, and the actual builder child receives
// exactly the manager-built environment including the selected
// SSL_CERT_FILE (kernel-recorded). The resolver never modifies CA
// material (fixture permission assertions); a guarded host probe asserts
// real bundle permissions unchanged. Existing P2/M0 evidence (the
// TestBuilderResolveSystemCA host smoke and the M0 SSL_CERT_FILE record)
// is not duplicated.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// replaceCACandidates swaps the frozen candidate list for a fixture list
// and restores it on cleanup (package-global seam; never t.Parallel).
func replaceCACandidates(t *testing.T, candidates []string) {
	t.Helper()
	orig := builderSystemCABundleCandidates
	builderSystemCABundleCandidates = candidates
	t.Cleanup(func() { builderSystemCABundleCandidates = orig })
}

// fixtureCABundle writes a stub PEM bundle: the resolver proves
// existence and readability only; it never parses certificates.
func fixtureCABundle(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("-----BEGIN CERTIFICATE-----\nd2a fixture bundle\n-----END CERTIFICATE-----\n"), mode); err != nil {
		t.Fatalf("cannot write CA fixture %s: %v", path, err)
	}
}

// TestBuilderResolveSystemCAFixtureOrder proves the frozen candidate
// order over temporary fixtures: the first existing readable bundle wins
// and no readable bundle fails closed (always run), missing/wrong-kind/
// dangling/unreadable candidates are skipped (the unreadability sub-case
// alone is UID-dependent and skips on root), and the resolver never
// modifies fixture permissions.
func TestBuilderResolveSystemCAFixtureOrder(t *testing.T) {
	dir := t.TempDir()
	bundleA := filepath.Join(dir, "a.pem")
	bundleB := filepath.Join(dir, "b.pem")
	fixtureCABundle(t, bundleA, 0o644)
	fixtureCABundle(t, bundleB, 0o644)

	// An unreadable candidate (mode 0000). Root reads it, so only the
	// unreadability sub-case is UID-dependent: it runs when the current
	// identity cannot open the fixture and skips otherwise. The
	// first-readable and fail-closed sub-cases never depend on it.
	unreadable := filepath.Join(dir, "unreadable.pem")
	fixtureCABundle(t, unreadable, 0o000)
	unreadableUsable := false
	if f, err := os.Open(unreadable); err == nil {
		f.Close()
		unreadableUsable = true
	}

	// Wrong-kind and dangling-symlink candidates.
	wrongKind := filepath.Join(dir, "adir")
	if err := os.MkdirAll(wrongKind, 0o700); err != nil {
		t.Fatalf("cannot create directory fixture: %v", err)
	}
	dangling := filepath.Join(dir, "dangling.pem")
	if err := os.Symlink(filepath.Join(dir, "absent.pem"), dangling); err != nil {
		t.Fatalf("cannot create dangling symlink fixture: %v", err)
	}
	absent := filepath.Join(dir, "absent.pem")

	cases := []struct {
		name       string
		candidates []string
		wantPath   string
		wantOK     bool
	}{
		{
			name:       "first existing readable wins",
			candidates: []string{bundleA, bundleB},
			wantPath:   bundleA,
			wantOK:     true,
		},
		{
			name:       "no readable bundle fails closed",
			candidates: []string{absent, wrongKind, dangling},
			wantPath:   "",
			wantOK:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			replaceCACandidates(t, tc.candidates)
			env, ok := builderResolveSystemCA()
			if ok != tc.wantOK {
				t.Fatalf("resolver ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				if env != nil {
					t.Errorf("fail-closed resolver returned env %v, want nil", env)
				}
				return
			}
			if len(env) != 1 || env[0] != "SSL_CERT_FILE="+tc.wantPath {
				t.Errorf("resolver env = %v, want exactly [SSL_CERT_FILE=%s]", env, tc.wantPath)
			}
		})
	}

	// The UID-dependent unreadability sub-case: only here the fixture's
	// unreadability (non-root) is load-bearing.
	t.Run("unreadable candidate skipped", func(t *testing.T) {
		if unreadableUsable {
			t.Skip("unreadable-fixture sub-case needs non-root (the fixture is readable)")
		}
		replaceCACandidates(t, []string{absent, wrongKind, dangling, unreadable, bundleB})
		env, ok := builderResolveSystemCA()
		if !ok {
			t.Fatalf("resolver refused with a readable later candidate: ok=%v", ok)
		}
		if len(env) != 1 || env[0] != "SSL_CERT_FILE="+bundleB {
			t.Errorf("resolver env = %v, want exactly [SSL_CERT_FILE=%s]", env, bundleB)
		}
	})

	// The resolver only reads: fixture permissions are unchanged.
	if info, err := os.Stat(bundleA); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("readable fixture permissions changed by resolve: %v (%v)", info, err)
	}
	if info, err := os.Stat(unreadable); err != nil || info.Mode().Perm() != 0o000 {
		t.Errorf("unreadable fixture permissions changed by resolve: %v (%v)", info, err)
	}
}

// TestBuilderResolveSystemCAHostPermissionsUnchanged proves on the REAL
// host bundle (skipped when the host has none) that a resolve leaves its
// permissions untouched.
func TestBuilderResolveSystemCAHostPermissionsUnchanged(t *testing.T) {
	orig := builderResolveSystemCAFunc
	builderResolveSystemCAFunc = builderResolveSystemCA
	t.Cleanup(func() { builderResolveSystemCAFunc = orig })

	env, ok := builderResolveSystemCA()
	if !ok {
		t.Skip("no supported system CA bundle on this host")
	}
	path := strings.TrimPrefix(env[0], "SSL_CERT_FILE=")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("cannot stat host bundle: %v", err)
	}
	if _, ok := builderResolveSystemCA(); !ok {
		t.Fatal("second resolve stopped seeing the same host bundle")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("cannot stat host bundle after resolve: %v", err)
	}
	if before.Mode() != after.Mode() {
		t.Errorf("host bundle mode changed by resolve: %v -> %v", before.Mode(), after.Mode())
	}
}

// TestBuilderManagerStartWithoutCABundleFailsClosed proves the START
// fail-closed contract through the real manager start path: with no
// readable supported bundle, START reports internal, converges the
// reservation/dirs, and never spawns a builder child.
func TestBuilderManagerStartWithoutCABundleFailsClosed(t *testing.T) {
	m, _, _ := processTestManager(t)
	replaceCACandidates(t, []string{filepath.Join(t.TempDir(), "absent.pem")})

	spawned := false
	origSpawn := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(string, string, string, []string) *exec.Cmd {
		spawned = true
		return exec.Command("true")
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = origSpawn })

	opID := "op_0123456789abcdef0123456789abcdef"
	if resp := m.start(opID); resp != builderManagerRespInternal {
		t.Fatalf("START without a readable CA bundle = %q, want internal (fail closed)", resp)
	}
	if spawned {
		t.Error("START spawned a builder child without a readable CA bundle")
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("fail-closed START did not converge the reservation")
	}
	for _, path := range []string{opRuntimeDir(opID), opStateDir(opID)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("instance dir %s not removed after fail-closed START: %v", path, err)
		}
	}
}

// TestBuilderManagerChildReceivesSelectedCABundleEnv proves through the
// real launch path that the actual builder child's kernel-recorded
// environment is exactly the fixed manager-owned entries plus the
// SELECTED system CA bundle: no os.Environ() inheritance, no Session
// credential/config material, and the first existing readable candidate
// (not a missing first candidate) is the one passed as SSL_CERT_FILE.
func TestBuilderManagerChildReceivesSelectedCABundleEnv(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca-bundle.pem")
	fixtureCABundle(t, bundle, 0o644)
	replaceCACandidates(t, []string{filepath.Join(dir, "absent.pem"), bundle})

	m, _, _ := processTestManager(t)

	// Mount the synthetic leader THROUGH the production command seam: the
	// production seam's environment assignment is kept, only the binary
	// is retargeted to the bounded synthetic leader child.
	orig := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(opID, rtDir, stDir string, env []string) *exec.Cmd {
		cmd := orig(opID, rtDir, stDir, env)
		cmd.Path = "/bin/sh"
		cmd.Args = []string{"/bin/sh", "-c", boundedSleepScript()}
		return cmd
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })

	opID := "op_0123456789abcdef0123456789abcdef"
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("START did not reserve the map entry")
	}
	bindFakeBuildkitdSocket(t, opID)
	if resp := <-respCh; resp != builderManagerRespOK {
		t.Fatalf("START = %q, want OK", resp)
	}

	m.mu.Lock()
	inst := m.instances[opID]
	m.mu.Unlock()
	pid := waitLeaderPid(t, inst)

	// The kernel-recorded environment of the actual builder child.
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		t.Fatalf("cannot read builder child environment: %v", err)
	}
	got := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	want := []string{
		"HOME=" + builderManagerStateRoot,
		"XDG_RUNTIME_DIR=" + opRuntimeDir(opID),
		"PATH=" + builderManagerChildPath,
		"SSL_CERT_FILE=" + bundle,
	}
	if !equalStrings(got, want) {
		t.Errorf("builder child environment = %v, want exactly %v (selected CA bundle, no inherited environment)", got, want)
	}
}
