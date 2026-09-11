package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Deterministic tests for the required live proof runner
// (scripts/release-2.2-live-proof-runner.sh): the runner must fail when a
// matched proof test skipped in required mode, when no proof test ran or
// passed (the all-skip case), and when a required evidence artifact is
// missing or empty; the happy path must pass. The --check form validates a
// captured -test.v output, which is the runner's own contract surface.

func runLiveProofRunnerCheck(t *testing.T, proofOutput string, evidenceFiles map[string]string) error {
	t.Helper()
	script := filepath.Join("scripts", "release-2.2-live-proof-runner.sh")
	dir := t.TempDir()
	evidenceDir := filepath.Join(dir, "evidence")
	if err := os.MkdirAll(evidenceDir, 0755); err != nil {
		t.Fatal(err)
	}
	for name, content := range evidenceFiles {
		if err := os.WriteFile(filepath.Join(evidenceDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	logfile := filepath.Join(dir, "proof-output.log")
	if err := os.WriteFile(logfile, []byte(proofOutput), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script, "--check", logfile, "--evidence", evidenceDir, "apparmor-denial.txt")
	out, err := cmd.CombinedOutput()
	t.Logf("runner output: %s", out)
	return err
}

func proofOutputLines(passes, skips []string) string {
	out := ""
	for _, name := range skips {
		out += "=== RUN   " + name + "\n"
		out += "--- SKIP: " + name + " (0.00s)\n"
	}
	for _, name := range passes {
		out += "=== RUN   " + name + "\n"
		out += "--- PASS: " + name + " (0.00s)\n"
	}
	return out
}

// TestLiveProofRunnerFailsOnSkip proves the runner fails when a required
// proof test closed through the skip path.
func TestLiveProofRunnerFailsOnSkip(t *testing.T) {
	err := runLiveProofRunnerCheck(t,
		proofOutputLines([]string{"TestLiveWorkloadAppArmorRegularFile"}, []string{"TestLiveWorkloadAppArmor"}),
		map[string]string{"apparmor-denial.txt": "denied\n"})
	if err == nil {
		t.Fatal("runner must fail when a required proof test skipped")
	}
}

// TestLiveProofRunnerFailsWhenAllProofTestsSkipped proves the runner fails
// when every matched proof test skipped (no test passed).
func TestLiveProofRunnerFailsWhenAllProofTestsSkipped(t *testing.T) {
	err := runLiveProofRunnerCheck(t,
		proofOutputLines(nil, []string{"TestLiveWorkloadAppArmor", "TestLiveWorkloadAppArmorRegularFile"}),
		map[string]string{"apparmor-denial.txt": "denied\n"})
	if err == nil {
		t.Fatal("runner must fail when no required proof test passed")
	}
}

// TestLiveProofRunnerFailsOnMissingEvidence proves the runner verifies the
// expected evidence artifacts, not only the process exit code.
func TestLiveProofRunnerFailsOnMissingEvidence(t *testing.T) {
	err := runLiveProofRunnerCheck(t,
		proofOutputLines([]string{"TestLiveWorkloadAppArmor"}, nil),
		nil)
	if err == nil {
		t.Fatal("runner must fail when the required evidence artifact is missing")
	}
	err = runLiveProofRunnerCheck(t,
		proofOutputLines([]string{"TestLiveWorkloadAppArmor"}, nil),
		map[string]string{"apparmor-denial.txt": ""})
	if err == nil {
		t.Fatal("runner must fail when the required evidence artifact is empty")
	}
}

// TestLiveProofRunnerPassesClosedProof proves the runner accepts a proof
// output whose tests passed and whose evidence artifacts are present.
func TestLiveProofRunnerPassesClosedProof(t *testing.T) {
	err := runLiveProofRunnerCheck(t,
		proofOutputLines([]string{"TestLiveWorkloadAppArmor", "TestLiveWorkloadAppArmorRegularFile"}, nil),
		map[string]string{"apparmor-denial.txt": "denied\n"})
	if err != nil {
		t.Fatalf("runner must pass a closed proof, error: %v", err)
	}
}

// TestLiveProofRunnerForwardsEvidenceDir proves the run form uses --evidence
// as the canonical artifact location for the proof process itself. This pins
// the contract that the runner both requests evidence from the test binary and
// verifies that same directory afterward.
func TestLiveProofRunnerForwardsEvidenceDir(t *testing.T) {
	script := filepath.Join("scripts", "release-2.2-live-proof-runner.sh")
	dir := t.TempDir()
	evidenceDir := filepath.Join(dir, "evidence")
	fakeProof := filepath.Join(dir, "proof.test")
	proof := `#!/usr/bin/env bash
set -eu
[ "${DOCKER_HELPER_LIVE_WORKLOAD_PROOF:-}" = "1" ] || exit 40
[ -n "${WORKLOAD_EVIDENCE_DIR:-}" ] || exit 41
mkdir -p "$WORKLOAD_EVIDENCE_DIR"
printf 'denied\n' > "$WORKLOAD_EVIDENCE_DIR/apparmor-denial.txt"
printf '%s\n' '=== RUN   TestProof' '--- PASS: TestProof (0.00s)'
`
	if err := os.WriteFile(fakeProof, []byte(proof), 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script,
		"--binary", fakeProof,
		"-run", "TestProof",
		"--evidence", evidenceDir,
		"apparmor-denial.txt",
	)
	out, err := cmd.CombinedOutput()
	t.Logf("runner output: %s", out)
	if err != nil {
		t.Fatalf("runner must forward required mode and evidence location to the proof binary: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(evidenceDir, "apparmor-denial.txt")); err != nil || string(got) != "denied\n" {
		t.Fatalf("runner evidence file: got %q err=%v", got, err)
	}
}
