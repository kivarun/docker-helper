package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// safeTestBaseDir returns an existing, writable base directory that is
// acceptable as a workspace-root ancestor under the production policy
// (isForbiddenWorkspaceRoot). Unique workspace-root test directories are
// created inside it with os.MkdirTemp.
//
// Candidates are tried in order: the user's home directory, then the test
// process working directory. Home is the natural choice for normal users;
// for root (or any environment whose home is inside a forbidden system
// tree, e.g. /root) the helper falls back to the next candidate instead of
// returning a path the production policy would reject.
func safeTestBaseDir(t *testing.T) string {
	t.Helper()
	var candidates []string
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, home)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	for _, c := range candidates {
		canonical, err := filepath.EvalSymlinks(c)
		if err != nil {
			continue
		}
		if err := isForbiddenWorkspaceRoot(canonical); err != nil {
			continue
		}
		probe, err := os.MkdirTemp(canonical, ".docker-helper-write-probe-*")
		if err != nil {
			continue
		}
		os.RemoveAll(probe)
		return canonical
	}
	t.Fatalf("no writable, non-forbidden base directory found for workspace root tests")
	return ""
}

// testAllowedRootDir creates a unique directory that is valid as a workspace
// root (outside the forbidden trees) and returns it in canonical form,
// matching what loadConfig stores in Config.AllowedRoot. Cleanup removes only
// the specific directory returned; tests must never remove a shared parent.
func testAllowedRootDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(safeTestBaseDir(t), ".docker-helper-test-*")
	if err != nil {
		t.Fatalf("cannot create workspace root test dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("cannot canonicalize workspace root test dir: %v", err)
	}
	return canonical
}

// TestSafeTestBaseDirRootLikeHome simulates a root-like environment where
// $HOME itself is inside a forbidden system tree (root's home is /root,
// which the workspace root policy rejects). The helper must reject the home
// candidate and fall back to a base that passes the production policy, and
// workspace roots created under it must remain policy-legal. This exercises
// the fallback without requiring an actual UID 0 test run.
func TestSafeTestBaseDirRootLikeHome(t *testing.T) {
	for _, home := range []string{"/tmp", "/root"} {
		if _, err := os.Stat(home); err != nil {
			continue
		}
		t.Run(home, func(t *testing.T) {
			t.Setenv("HOME", home)

			base := safeTestBaseDir(t)
			if err := isForbiddenWorkspaceRoot(base); err != nil {
				t.Fatalf("selected base %q rejected by production policy: %v", base, err)
			}
			if base == home {
				t.Fatalf("selected base must not be the forbidden home %q", home)
			}

			root := testAllowedRootDir(t)
			if err := validateWorkspaceRootPolicy(root); err != nil {
				t.Fatalf("workspace root %q rejected by production policy: %v", root, err)
			}
		})
	}
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
