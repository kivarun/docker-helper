package main

import (
	"os"
	"strings"
	"testing"
)

// TestSELinuxPolicyKeepsGenericBinTExecBounded pins the narrow exception used
// by the semanage Python interpreter. Generic bin_t may be executed for that
// transition, but docker-helper must never receive same-domain execute_no_trans
// over the whole bin_t class.
func TestSELinuxPolicyKeepsGenericBinTExecBounded(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	policy := strings.Join(strings.Fields(string(data)), " ")
	want := "allow docker_helper_t bin_t:file { execute read open getattr map };"
	if !strings.Contains(policy, want) {
		t.Fatalf("SELinux policy must retain only the bounded semanage-interpreter bin_t exec grant: %s", want)
	}
	if strings.Contains(policy, "allow docker_helper_t bin_t:file { execute read open getattr map execute_no_trans };") ||
		strings.Contains(policy, "allow docker_helper_t bin_t:file { execute_no_trans") {
		t.Fatal("SELinux policy must not grant generic bin_t execute_no_trans")
	}

	capGrant := "allow docker_helper_t self:capability { dac_read_search dac_override sys_admin };"
	if got := strings.Count(policy, capGrant); got != 1 {
		t.Fatalf("daemon capability grant must have one canonical declaration, got %d", got)
	}
}

// TestSELinuxProjectionUnmountDoesNotExecFUSEHelper keeps workload cleanup on
// the kernel mount API. The system-mode backend already owns CAP_SYS_ADMIN and
// positively inventories the mount before and after unmount; executing a
// generic fusermount helper would only widen the daemon executable surface.
func TestSELinuxProjectionUnmountDoesNotExecFUSEHelper(t *testing.T) {
	data, err := os.ReadFile("workload_selinux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, forbidden := range []string{"runFusermountUnmount", `LookPath("fusermount3")`, `LookPath("fusermount")`} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("SELinux projection cleanup must not execute external FUSE unmount helpers: found %q", forbidden)
		}
	}
}

// TestUATScratchIsIgnored prevents local UAT credentials and state from being
// added to the repository again.
func TestUATScratchIsIgnored(t *testing.T) {
	data, err := os.ReadFile(".gitignore")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "/.uat-scratch/\n") {
		t.Fatal(".gitignore must exclude the repository-local UAT scratch tree")
	}
}
