package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readRepoFile reads a repository file relative to the test working
// directory (the package root) and fails the test when it cannot be read.
// A shipped repository artifact that is part of the release gate is a
// required test fixture; its disappearance is a regression, never a skip.
func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(".", rel))
	if err != nil {
		t.Fatalf("cannot read %s: %v", rel, err)
	}
	return string(data)
}

// requireAll asserts that the file content carries every required substring.
func requireAll(t *testing.T, rel, content string, required []string) {
	t.Helper()
	for _, want := range required {
		if !strings.Contains(content, want) {
			t.Errorf("%s lost its required gate wiring: %q is absent", rel, want)
		}
	}
}

// TestFinalGateUATWiringIsComplete protects the wiring invariant between the
// final security ledger (docs/release-2.2-security-closure.md, "Mandatory
// hostile exact-artifact security UAT") and the one canonical artifact gate
// (.github/workflows/artifact-gate.yml plus its runner scripts). Every
// mandatory final-security case must remain wired into the full gate; a
// silent removal of one of these references would make the final exact
// candidate pass without proving the required trust-boundary composition.
//
// The test asserts observable wiring only (which script runs which group and
// which hostile scenarios the workload matrices carry); it does not restate
// scenario semantics, which stay owned by the scripts themselves.
func TestFinalGateUATWiringIsComplete(t *testing.T) {
	// The artifact gate is the one canonical producer/consumer owner: it must
	// invoke the AppArmor workload-MAC acceptance, the SELinux guest UAT (the
	// only caller of the SELinux runner and workload matrix), and the Ubuntu
	// regression runner.
	gate := readRepoFile(t, filepath.Join(".github", "workflows", "artifact-gate.yml"))
	requireAll(t, ".github/workflows/artifact-gate.yml", gate, []string{
		"scripts/uat-workload-apparmor.sh",
		"scripts/uat-vm-opensuse-selinux.sh",
		"scripts/uat-regressions-runner-ubuntu.sh",
		"scripts/uat-blackbox.sh",
		"scripts/release-candidate.sh",
	})

	// C1+H9: the AppArmor workload matrix carries the hostile privilege and
	// helper-runtime composition scenarios W11-W13; the SELinux matrix
	// carries the equivalents S14-S16.
	wla := readRepoFile(t, filepath.Join("scripts", "uat-workload-apparmor.sh"))
	requireAll(t, "scripts/uat-workload-apparmor.sh", wla, []string{
		"W11: hostile SUID source image cannot elevate",
		"W12: helper-created build staging strips SUID/SGID",
		"W13: helper-socket hostile runtime composition",
	})
	wls := readRepoFile(t, filepath.Join("scripts", "uat-workload-selinux.sh"))
	requireAll(t, "scripts/uat-workload-selinux.sh", wls, []string{
		"S14: hostile SUID source image cannot elevate",
		"S15: helper-created build staging strips SUID/SGID",
		"S16: helper-socket hostile runtime composition",
	})

	// M13/H7/H4/H5/H8/H2: the Ubuntu regression runner owns groups 22-27.
	runner := readRepoFile(t, filepath.Join("scripts", "uat-regressions-runner-ubuntu.sh"))
	requireAll(t, "scripts/uat-regressions-runner-ubuntu.sh", runner, []string{
		"22:M13 Docker bind-mount serialization:uat-regression-bind-serialization.sh",
		"23:H7 hostile TCP port capture:uat-regression-h7-tcp-port-capture.sh",
		"24:H4 build staging ceilings:uat-regression-h4-build-staging-bounds.sh",
		"25:H5 fixed resource admission ceilings:uat-regression-h5-resource-admission.sh",
		"26:H8 bounded MAC-command liveness:uat-regression-h8-mac-liveness.sh",
		"27:H2 commit-boundary credential revocation race:uat-regression-h2-parked-revocation.sh",
	})

	// C3/H8/H2 on SELinux: the SELinux guest regression runner owns groups
	// 7-9 (the C3 descriptor-safe restorecon race, the H8 liveness proof,
	// and the H2 parked revocation race).
	selRunner := readRepoFile(t, filepath.Join("scripts", "uat-regressions-runner-selinux.sh"))
	requireAll(t, "scripts/uat-regressions-runner-selinux.sh", selRunner, []string{
		"7:SELinux C3 descriptor-safe restorecon:uat-regression-selinux-c3-restorecon-race.sh",
		"8:H8 bounded MAC-command liveness:uat-regression-h8-mac-liveness.sh",
		"9:H2 commit-boundary credential revocation race:uat-regression-h2-parked-revocation.sh",
	})

	// H6: the confined admin-token rotation proof stays part of the common
	// black-box UAT (both backends run uat-blackbox.sh, AppArmor on the
	// hosted runners and SELinux inside the guest).
	blackbox := readRepoFile(t, filepath.Join("scripts", "uat-blackbox.sh"))
	requireAll(t, "scripts/uat-blackbox.sh", blackbox, []string{
		"phase 7c: H6 admin-token rotation under confinement",
		"docker-helper admin-token rotate --system",
	})
}
