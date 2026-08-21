//go:build integration
// +build integration

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestStaticBuildProducesStaticBinary verifies that build-static.sh
// produces a static binary and correct version.
func TestStaticBuildProducesStaticBinary(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not available")
	}

	// Check canonical build prerequisites — must match build-static.sh logic.
	canBuild := false
	if _, err := exec.LookPath("musl-gcc"); err == nil {
		canBuild = true
	} else if _, err := os.Stat("/etc/alpine-release"); err == nil {
		if _, err := exec.LookPath("gcc"); err == nil {
			canBuild = true
		}
	}

	if !canBuild {
		t.Skip("canonical build prerequisites not met (need musl-gcc, or Alpine + gcc)")
	}

	// Canonical prerequisites are present — the build must succeed, not skip.
	testVersion := "test-" + t.Name()
	cmd := exec.Command("bash", "build-static.sh", testVersion)
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("static build failed with canonical prerequisites: %v\n%s", err, out)
	}

	binPath := "dist/docker-helper"

	// Verify binary exists and is executable
	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("binary not found: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Fatal("binary is not executable")
	}

	// Verify version
	cmd = exec.Command(binPath, "version")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != testVersion {
		t.Errorf("version = %q, want %q", got, testVersion)
	}

	// Verify static linking — must be confirmed, not skipped.
	cmd = exec.Command("file", binPath)
	out, err = cmd.Output()
	if err != nil {
		t.Fatalf("file command failed: %v", err)
	}
	if !strings.Contains(string(out), "statically linked") {
		t.Errorf("binary is not statically linked: %s", out)
	}
}

// TestBuildStaticCwdIndependence verifies build-static.sh works when
// invoked from a non-repo-root working directory.
func TestBuildStaticCwdIndependence(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not available")
	}

	canBuild := false
	if _, err := exec.LookPath("musl-gcc"); err == nil {
		canBuild = true
	} else if _, err := os.Stat("/etc/alpine-release"); err == nil {
		if _, err := exec.LookPath("gcc"); err == nil {
			canBuild = true
		}
	}
	if !canBuild {
		t.Skip("canonical build prerequisites not met")
	}

	// Run from a subdirectory, not the repo root.
	tempDir := t.TempDir()
	testVersion := "test-cwd-" + t.Name()

	// Use absolute path to the script so it's found from any cwd.
	scriptPath, err := filepath.Abs("build-static.sh")
	if err != nil {
		t.Fatalf("cannot resolve script path: %v", err)
	}

	cmd := exec.Command("bash", scriptPath, testVersion)
	cmd.Dir = tempDir

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build from non-root cwd failed: %v\n%s", err, out)
	}

	// The binary should be in dist/ relative to the repo, not tempDir.
	binPath := "dist/docker-helper"
	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("binary not found at repo dist/: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Fatal("binary is not executable")
	}

	// Verify version
	cmd = exec.Command(binPath, "version")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != testVersion {
		t.Errorf("version = %q, want %q", got, testVersion)
	}
}
