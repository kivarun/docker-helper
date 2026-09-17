package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runRepoHygieneGate runs the single canonical repository hygiene gate with
// the given working directory and returns its combined output and status.
func runRepoHygieneGate(t *testing.T, dir string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "scripts/check-repo-hygiene.sh")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestRepoHygieneGatePassesOnTree proves the canonical hygiene gate passes on
// the tracked tree: no accidental trailing whitespace and a final newline on
// every tracked text file.
func TestRepoHygieneGatePassesOnTree(t *testing.T) {
	out, err := runRepoHygieneGate(t, ".")
	if err != nil {
		t.Fatalf("repository hygiene gate must pass on the tracked tree: %v\n%s", err, out)
	}
}

// TestRepoHygieneGateDetectsViolations proves the gate actually detects both
// failure classes on a synthetic tracked tree instead of passing vacuously.
func TestRepoHygieneGateDetectsViolations(t *testing.T) {
	tmp := t.TempDir()
	script, err := os.ReadFile("scripts/check-repo-hygiene.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "scripts"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "scripts", "check-repo-hygiene.sh"), script, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "trailing.txt"), []byte("a \nb\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "no-lf.txt"), []byte("no final newline"), 0644); err != nil {
		t.Fatal(err)
	}
	gitInit := exec.Command("git", "init", "-q", ".")
	gitInit.Dir = tmp
	if out, err := gitInit.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v\n%s", err, out)
	}
	gitAdd := exec.Command("git", "add", "-A")
	gitAdd.Dir = tmp
	if out, err := gitAdd.CombinedOutput(); err != nil {
		t.Fatalf("git add failed: %v\n%s", err, out)
	}

	out, err := runRepoHygieneGate(t, tmp)
	if err == nil {
		t.Fatalf("the hygiene gate must fail on a tree with violations, output:\n%s", out)
	}
	if !strings.Contains(out, "trailing whitespace") || !strings.Contains(out, "trailing.txt") {
		t.Errorf("the gate must name the trailing-whitespace violation, output:\n%s", out)
	}
	if !strings.Contains(out, "final newline") || !strings.Contains(out, "no-lf.txt") {
		t.Errorf("the gate must name the missing-final-newline violation, output:\n%s", out)
	}
}

// TestRepoHygieneFixtureExceptionIsIntentional proves the documented gate
// exception is the byte-exact semanage producer capture and that the capture
// still carries the intentional captured bytes: its trailing-space column
// padding must never be "cleaned up" into normalized text.
func TestRepoHygieneFixtureExceptionIsIntentional(t *testing.T) {
	script, err := os.ReadFile("scripts/check-repo-hygiene.sh")
	if err != nil {
		t.Fatal(err)
	}
	const exception = "testdata/semanage-fcontext-producer-capture.txt"
	if n := strings.Count(string(script), exception); n != 2 {
		t.Fatalf("the hygiene gate must name the fixture exception exactly twice (header + both checks), got %d occurrences", n)
	}
	capture, err := os.ReadFile(exception)
	if err != nil {
		t.Fatalf("the exact-byte producer capture fixture must exist: %v", err)
	}
	trailing := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(capture), "\n"), "\n") {
		if line != strings.TrimRight(line, " \t") {
			trailing++
		}
	}
	if trailing == 0 {
		t.Fatal("the semanage producer capture must keep its intentional trailing-whitespace bytes; the exception is dead and the fixture was normalized")
	}
}
