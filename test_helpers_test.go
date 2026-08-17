package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testAllowedRootDir creates a unique directory that is valid as a workspace
// root and returns it in canonical form, matching what loadConfig stores in
// Config.AllowedRoot. Candidate bases are tried in order: the user's home
// directory, the test process working directory, and "/" as a last resort.
// A base does not have to be policy-legal itself (root's home is /root, a
// forbidden system tree); the created directory is what must pass the
// production workspace-root policy. Cleanup removes only the specific
// directory returned; tests must never remove a shared parent.
func testAllowedRootDir(t *testing.T) string {
	t.Helper()
	var candidates []string
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, home)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	candidates = append(candidates, "/")

	dir, err := allocateTestWorkspaceRoot(candidates)
	if err != nil {
		t.Fatalf("cannot allocate workspace root test dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// allocateTestWorkspaceRoot tries each candidate base in order and returns
// the first unique directory it can create there that passes the production
// workspace-root policy. A base that does not exist, is not writable, or
// whose created child is policy-forbidden is skipped; a created-but-rejected
// directory is removed before moving to the next candidate.
func allocateTestWorkspaceRoot(candidates []string) (string, error) {
	for _, c := range candidates {
		base, err := filepath.EvalSymlinks(c)
		if err != nil {
			continue
		}
		dir, err := os.MkdirTemp(base, ".docker-helper-test-*")
		if err != nil {
			continue
		}
		canonical, err := filepath.EvalSymlinks(dir)
		if err != nil {
			os.RemoveAll(dir)
			continue
		}
		if err := validateWorkspaceRootPolicy(canonical); err != nil {
			os.RemoveAll(dir)
			continue
		}
		return canonical, nil
	}
	return "", fmt.Errorf("no workspace root test dir could be allocated from candidates %v", candidates)
}

// TestWorkspaceRootAllocationForbiddenCandidates verifies the allocator's
// core invariant with a controlled candidate list: the bases themselves need
// not be policy-legal workspace roots. Both regular candidates here are
// forbidden system trees (the root scenario: HOME=/root, cwd=/root/...), so
// the allocator must skip them and return a policy-valid root created under
// the fallback base.
func TestWorkspaceRootAllocationForbiddenCandidates(t *testing.T) {
	// Pick a policy-legal, writable fallback base for the controlled
	// candidate list (t.TempDir() is unusable: /tmp is a forbidden tree).
	selectGoodBase := func(c string) (string, bool) {
		canonical, err := filepath.EvalSymlinks(c)
		if err != nil {
			return "", false
		}
		if err := validateWorkspaceRootPolicy(canonical); err != nil {
			return "", false
		}
		probe, err := os.MkdirTemp(canonical, ".docker-helper-test-*")
		if err != nil {
			return "", false
		}
		os.RemoveAll(probe)
		return canonical, true
	}
	var goodBase string
	var candidateBases []string
	if home, err := os.UserHomeDir(); err == nil {
		candidateBases = append(candidateBases, home)
	}
	if wd, err := os.Getwd(); err == nil {
		candidateBases = append(candidateBases, wd)
	}
	for _, c := range candidateBases {
		if base, ok := selectGoodBase(c); ok {
			goodBase = base
			break
		}
	}
	if goodBase == "" {
		t.Skip("no policy-legal, writable base available for the controlled test")
	}

	rejectedBefore := testWorkspaceRootPrefixCount(t, "/tmp")

	dir, err := allocateTestWorkspaceRoot([]string{"/tmp", "/root", goodBase})
	if err != nil {
		t.Fatalf("allocateTestWorkspaceRoot: %v", err)
	}
	defer os.RemoveAll(dir)

	if err := validateWorkspaceRootPolicy(dir); err != nil {
		t.Fatalf("allocated root %q rejected by production policy: %v", dir, err)
	}
	if !strings.HasPrefix(dir, goodBase+string(filepath.Separator)) {
		t.Fatalf("allocated root %q, want under fallback base %s", dir, goodBase)
	}
	// The policy-rejected /tmp child must not linger.
	if rejectedAfter := testWorkspaceRootPrefixCount(t, "/tmp"); rejectedAfter != rejectedBefore {
		t.Errorf("policy-rejected /tmp child not removed (before=%d after=%d)", rejectedBefore, rejectedAfter)
	}
}

// TestWorkspaceRootAllocationForbiddenHome verifies the default candidate
// list with a root-like $HOME that is a forbidden system tree: the home
// candidate's created child must be rejected by the policy gate and a later
// candidate used. /tmp is world-writable, so the rejection comes from the
// policy, not from permissions, making this deterministic without UID 0.
func TestWorkspaceRootAllocationForbiddenHome(t *testing.T) {
	if _, err := os.Stat("/tmp"); err != nil {
		t.Skipf("/tmp not available: %v", err)
	}
	t.Setenv("HOME", "/tmp")

	root := testAllowedRootDir(t)

	if err := validateWorkspaceRootPolicy(root); err != nil {
		t.Fatalf("workspace root %q rejected by production policy: %v", root, err)
	}
	if strings.HasPrefix(root, "/tmp/") {
		t.Fatalf("workspace root %q must not be under forbidden /tmp", root)
	}
}

// TestWorkspaceRootAllocationRootFallback verifies the root scenario end to
// end: both regular candidates are forbidden (HOME=/root, cwd=/root/...), and
// the "/" fallback yields a valid root-level workspace root. It requires the
// ability to create directories directly under "/" and is skipped otherwise.
func TestWorkspaceRootAllocationRootFallback(t *testing.T) {
	// Probe whether "/" is writable so non-root runs skip cleanly.
	probe, err := os.MkdirTemp("/", ".docker-helper-allocator-probe-*")
	if err != nil {
		t.Skipf("cannot create directories in /: %v (root fallback not exercisable)", err)
	}
	os.RemoveAll(probe)

	dir, err := allocateTestWorkspaceRoot([]string{"/root", "/tmp", "/"})
	if err != nil {
		t.Fatalf("allocateTestWorkspaceRoot: %v", err)
	}
	defer os.RemoveAll(dir)

	if err := validateWorkspaceRootPolicy(dir); err != nil {
		t.Fatalf("allocated root %q rejected by production policy: %v", dir, err)
	}
	if !strings.HasPrefix(dir, "/.docker-helper-test-") {
		t.Fatalf("expected root-level fallback dir, got %q", dir)
	}
}

// testWorkspaceRootPrefixCount counts entries in dir whose names carry the
// test workspace-root prefix, to verify that rejected allocations are removed.
func testWorkspaceRootPrefixCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", dir, err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".docker-helper-test-") {
			n++
		}
	}
	return n
}

// waitForDialReady polls until a TCP/unix listener accepts connections.
// Use it after starting an in-process test server instead of a fixed sleep.
func waitForDialReady(t *testing.T, network, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial(network, addr)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("listener %s://%s not ready after 5s", network, addr)
}

// writeTestTokenFile writes a test admin/launcher token file, failing the
// test if the write fails. Security-sensitive fixtures must not proceed
// with a missing token file.
func writeTestTokenFile(t *testing.T, path, token string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatalf("cannot write token file %s: %v", path, err)
	}
}
