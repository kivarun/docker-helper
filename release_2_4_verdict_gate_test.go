package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The P5-S2 verdict gate is the release gate's own production script: the
// tests drive scripts/release-2.4-p5s2-verdict-gate.sh through bash with
// synthetic guest logs, so every accepted/rejected verdict shape is the
// real gate code path, never a reimplementation (external review F4: a
// FAIL/INCOMPLETE guest outcome with exit 0 must fail the release
// workflow; the historical experiment mode keeps its measured-outcome
// contract).
const verdictGateScript = "scripts/release-2.4-p5s2-verdict-gate.sh"

// candidateManifest writes the exact candidate composition manifest the
// release gate transfers into the guest and records in the evidence: the
// candidate SHA, the tested binary hash, the canonical candidate artifact
// binding (re-review R3: release version, candidate tarball/DEB/RPM
// hashes, candidate binary hash), and the composition input hashes.
// Optional mutators distort individual fields for the negative cases.
func candidateManifest(t *testing.T, mutate ...func(map[string]string)) string {
	t.Helper()
	fields := map[string]string{
		"candidate_sha":            "0123456789abcdef0123456789abcdef01234567",
		"script_commit":            "0123456789abcdef0123456789abcdef01234567",
		"release_version":          "2.4.0",
		"binary_sha256":            strings.Repeat("a", 64),
		"candidate_binary_sha256":  strings.Repeat("a", 64),
		"candidate_tarball_sha256": strings.Repeat("f", 64),
		"candidate_deb_sha256":     strings.Repeat("0", 64),
		"candidate_rpm_sha256":     strings.Repeat("1", 64),
		"te_sha256":                strings.Repeat("b", 64),
		"fc_sha256":                strings.Repeat("c", 64),
		"unit_sha256":              strings.Repeat("d", 64),
		"provision_sha256":         strings.Repeat("e", 64),
	}
	for _, m := range mutate {
		m(fields)
	}
	order := []string{
		"candidate_sha", "script_commit", "release_version",
		"binary_sha256", "candidate_binary_sha256",
		"candidate_tarball_sha256", "candidate_deb_sha256", "candidate_rpm_sha256",
		"te_sha256", "fc_sha256", "unit_sha256", "provision_sha256",
	}
	lines := make([]string, 0, len(order))
	for _, key := range order {
		if value, ok := fields[key]; ok {
			lines = append(lines, key+"="+value)
		}
	}
	path := filepath.Join(t.TempDir(), "composition-manifest.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatalf("cannot write the candidate manifest: %v", err)
	}
	return path
}

func runVerdictGateManifest(t *testing.T, releaseGate string, guestLog string, guestRC string, manifest string) error {
	t.Helper()
	if _, err := os.Stat(verdictGateScript); err != nil {
		t.Fatalf("the verdict gate script is missing: %v", err)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash unavailable: %v", err)
	}
	cmd := exec.Command("bash", verdictGateScript, guestLog, guestRC, manifest)
	cmd.Env = append(os.Environ(), "PHASE4B_RELEASE_GATE="+releaseGate)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) > 0 {
		t.Logf("verdict gate output: %s", out)
	}
	return err
}

func runVerdictGate(t *testing.T, releaseGate string, guestLog string, guestRC string) error {
	t.Helper()
	return runVerdictGateManifest(t, releaseGate, guestLog, guestRC, candidateManifest(t))
}

func writeGuestLog(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guest.log")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatalf("cannot write the guest log: %v", err)
	}
	return path
}

func TestRelease24P5S2VerdictGate(t *testing.T) {
	pass := "some-prefix P5S2-P4B-RESULT=PASS"
	fail := "some-prefix P5S2-P4B-RESULT=FAIL"
	incomplete := "some-prefix P5S2-P4B-RESULT=INCOMPLETE"

	t.Run("release gate requires PASS", func(t *testing.T) {
		cases := []struct {
			name string
			log  string
		}{
			{"FAIL verdict with exit 0 fails the gate", fail},
			{"INCOMPLETE verdict with exit 0 fails the gate", incomplete},
			{"missing verdict fails the gate", "no terminal verdict here"},
			{"conflicting verdict lines fail the gate", pass + "\n" + fail},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if err := runVerdictGate(t, "1", writeGuestLog(t, tc.log), "0"); err == nil {
					t.Fatalf("the release gate accepted a non-PASS guest outcome: %q", tc.log)
				}
			})
		}
		t.Run("guest exit nonzero fails the gate", func(t *testing.T) {
			if err := runVerdictGate(t, "1", writeGuestLog(t, pass), "1"); err == nil {
				t.Fatal("the release gate accepted a nonzero guest exit")
			}
		})
		t.Run("PASS with the exact candidate manifest passes", func(t *testing.T) {
			if err := runVerdictGate(t, "1", writeGuestLog(t, pass), "0"); err != nil {
				t.Fatalf("the release gate refused the PASS verdict: %v", err)
			}
		})
		t.Run("PASS without a candidate manifest fails the gate", func(t *testing.T) {
			if _, err := os.Stat(verdictGateScript); err != nil {
				t.Fatalf("the verdict gate script is missing: %v", err)
			}
			if _, err := exec.LookPath("bash"); err != nil {
				t.Skipf("bash unavailable: %v", err)
			}
			cmd := exec.Command("bash", verdictGateScript, writeGuestLog(t, pass), "0",
				filepath.Join(t.TempDir(), "absent-manifest.txt"))
			cmd.Env = append(os.Environ(), "PHASE4B_RELEASE_GATE=1")
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("the release gate accepted a PASS verdict without a candidate manifest: %s", out)
			}
		})
		// Re-review R3: the PASS must belong to the exact bytes intended
		// for release — the gate refuses a manifest that does not bind the
		// tested binary to the canonical candidate artifact.
		t.Run("PASS without the candidate binary binding fails the gate", func(t *testing.T) {
			manifest := candidateManifest(t, func(m map[string]string) { delete(m, "candidate_binary_sha256") })
			if err := runVerdictGateManifest(t, "1", writeGuestLog(t, pass), "0", manifest); err == nil {
				t.Fatal("the release gate accepted a PASS verdict without the candidate binary binding")
			}
		})
		t.Run("PASS without the candidate artifact hashes fails the gate", func(t *testing.T) {
			for _, key := range []string{"candidate_tarball_sha256", "candidate_deb_sha256", "candidate_rpm_sha256"} {
				key := key
				t.Run(key, func(t *testing.T) {
					manifest := candidateManifest(t, func(m map[string]string) { delete(m, key) })
					if err := runVerdictGateManifest(t, "1", writeGuestLog(t, pass), "0", manifest); err == nil {
						t.Fatalf("the release gate accepted a PASS verdict without %s", key)
					}
				})
			}
		})
		t.Run("tested binary differing from the candidate binary fails the gate", func(t *testing.T) {
			manifest := candidateManifest(t, func(m map[string]string) {
				m["candidate_binary_sha256"] = strings.Repeat("9", 64)
			})
			if err := runVerdictGateManifest(t, "1", writeGuestLog(t, pass), "0", manifest); err == nil {
				t.Fatal("the release gate accepted a PASS verdict whose tested binary is not the candidate artifact binary")
			}
		})
	})

	t.Run("historical experiment mode keeps the measured-outcome contract", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			log  string
		}{
			{"FAIL is a valid measured outcome", fail},
			{"INCOMPLETE is a valid measured outcome", incomplete},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := runVerdictGate(t, "0", writeGuestLog(t, tc.log), "0"); err != nil {
					t.Fatalf("the experiment mode must accept the measured outcome: %v", err)
				}
			})
		}
		t.Run("a missing verdict still fails", func(t *testing.T) {
			if err := runVerdictGate(t, "0", writeGuestLog(t, "no terminal verdict here"), "0"); err == nil {
				t.Fatal("the experiment mode accepted a log without a terminal verdict")
			}
		})
	})
}
