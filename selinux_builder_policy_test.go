package main

// selinux_builder_policy_test.go protects the P5-S1 builder-domain SELinux
// invariants: the dedicated builder domain and its private file types exist,
// the domain is bound ONLY through the unit file's SELinuxContext (no global
// exec-type auto-transition of the shared binary), the daemon's access into
// the builder trees is exactly the manager-socket transport, the builder
// domain receives no grants toward any daemon-owned or forbidden surface,
// and the deployment lifecycle is the only relabeling owner for the
// builder-owned paths.

import (
	"os"
	"strings"
	"testing"
)

func readSELinuxPolicyFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s not found: %v", path, err)
	}
	return string(data)
}

// TestSELinuxPolicyBuilderDomainTypes verifies the .te declares the dedicated
// builder domain with its role membership and the private builder
// runtime/state/exec file types (each as plain file_type — the builder types
// are neither entrypoints for transitions nor relabeled workspaces).
func TestSELinuxPolicyBuilderDomainTypes(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, want := range []string{
		"type docker_helper_builder_t, domain;",
		"role system_r types docker_helper_builder_t;",
		"type docker_helper_builder_runtime_t, file_type;",
		"type docker_helper_builder_state_t, file_type;",
		"type docker_helper_rootlesskit_exec_t, file_type;",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("SELinux policy must declare %q", want)
		}
	}
}

// TestSELinuxPolicyBuilderNoGlobalExecTransition verifies the policy adds NO
// type_transition INTO the builder domain: the unit file's SELinuxContext= is
// the single binding owner. The destination token of a process-class
// transition is what would auto-flip execs into the builder domain; a
// transition whose SOURCE is the builder domain (the P5-S2 rootlesskit
// launch vehicle) is a different, legitimate shape and does not violate the
// invariant.
func TestSELinuxPolicyBuilderNoGlobalExecTransition(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(trimmed, "type_transition") {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(trimmed, ";"))
		// Process-class shape: "type_transition <source> <file>:process <dest>".
		if len(fields) == 4 && strings.Contains(fields[2], ":process") && fields[3] == "docker_helper_builder_t" {
			t.Errorf("no exec-type auto-transition into the builder domain may exist (the unit's SELinuxContext= is the single binding owner): %s", trimmed)
		}
	}
}

// TestSELinuxPolicyBuilderDaemonTransportExact verifies the daemon's access
// into the builder trees is exactly the manager-socket transport: directory
// traversal, the socket-file open/read/write/getattr for manager.sock and the
// per-op buildkitd sockets, and the connectto toward the builder domain — and
// no other docker_helper_t grant touches a builder type.
func TestSELinuxPolicyBuilderDaemonTransportExact(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	want := []string{
		"allow docker_helper_t docker_helper_builder_runtime_t:dir { search };",
		"allow docker_helper_t docker_helper_builder_runtime_t:sock_file { getattr open read write };",
		"allow docker_helper_t docker_helper_builder_t:unix_stream_socket { connectto };",
	}
	for _, line := range want {
		if !strings.Contains(policy, line) {
			t.Errorf("daemon transport grant missing: %q", line)
		}
	}
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(trimmed, "allow docker_helper_t docker_helper_builder") {
			continue
		}
		seen := false
		for _, w := range want {
			if trimmed == w {
				seen = true
				break
			}
		}
		if !seen {
			t.Errorf("unexpected daemon grant into the builder trees (transport only): %s", trimmed)
		}
	}
}

// forbiddenBuilderTargets are the surfaces the builder domain must never
// receive a grant toward: the daemon's own trees and types, the admin token
// and config, the Session workspace types (non-home managed and /home), the
// Docker socket and runtime, and the helper's projection/CA/bindfs machinery.
var forbiddenBuilderTargets = []string{
	"container_var_run_t",
	"container_runtime_t",
	"container_runtime_exec_t",
	"docker_helper_admin_token_t",
	"docker_helper_config_t",
	"docker_helper_state_t",
	"docker_helper_runtime_t",
	"docker_helper_workspace_t",
	"docker_helper_trusted_ca_t",
	"docker_helper_ro_projection_t",
	"docker_helper_bindfs_exec_t",
	"docker_helper_t",
	"user_home_type",
	"user_home_dir_t",
}

// allowTargetToken extracts the target type token of one
// "allow <subjectPrefix><target>:<class>" line, or "" when the line does not
// start with the subject prefix.
func allowTargetToken(trimmed, subjectPrefix string) string {
	if !strings.HasPrefix(trimmed, subjectPrefix) {
		return ""
	}
	rest := strings.TrimPrefix(trimmed, subjectPrefix)
	if idx := strings.IndexByte(rest, ':'); idx >= 0 {
		return rest[:idx]
	}
	return ""
}

// builderAllowTarget extracts the target type token of one
// "allow docker_helper_builder_t <target>:<class>" line, or "" when the line
// is not a builder-subject allow rule.
func builderAllowTarget(trimmed string) string {
	return allowTargetToken(trimmed, "allow docker_helper_builder_t ")
}

// TestSELinuxPolicyBuilderIsolation verifies the builder domain receives no
// allow rule toward any forbidden surface (word-exact target matching, so
// docker_helper_builder_state_t is not confused with docker_helper_state_t).
func TestSELinuxPolicyBuilderIsolation(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		target := builderAllowTarget(trimmed)
		if target == "" {
			continue
		}
		for _, forbidden := range forbiddenBuilderTargets {
			if target == forbidden {
				t.Errorf("builder domain must not receive a grant toward %s: %s", forbidden, trimmed)
			}
		}
	}
}

// TestSELinuxPolicyBuilderNoCapabilities verifies the builder domain carries
// no SELinux capability grants: the P4 unit proof froze the manager at
// CapEff 0; the capability floor is owned by the unit's bounding set alone.
func TestSELinuxPolicyBuilderNoCapabilities(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "allow docker_helper_builder_t self:capability") {
			t.Errorf("builder domain must hold no SELinux capability grants: %s", trimmed)
		}
	}
}

// TestSELinuxPolicyBuilderStateRules verifies the builder state-tree grants
// stay exact: the manager's dir rule unchanged from the P5-S1 proof (the
// startup purge's tree traversal + the per-op dir lifecycle) and the
// manager's file rule without the lock permission (the lock moved to the
// rootlesskit child domain, P5-S2). The child's own state-tree grants are
// the rootlesskit-attributed evidence surface: the rootlesskit-state dir
// lifecycle plus the state-lock flock, without unlink/rmdir (the purge owns
// removal) and with the child's own api.sock socket lifecycle.
func TestSELinuxPolicyBuilderStateRules(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, want := range []string{
		"allow docker_helper_builder_t docker_helper_builder_state_t:dir { getattr search read open write add_name remove_name create rmdir setattr };",
		"allow docker_helper_builder_t docker_helper_builder_state_t:file { create read write open getattr setattr unlink };",
		"allow docker_helper_rootlesskit_t docker_helper_builder_state_t:dir { search getattr read open write add_name remove_name lock };",
		"allow docker_helper_rootlesskit_t docker_helper_builder_state_t:file { create open read write getattr setattr lock };",
		"allow docker_helper_rootlesskit_t docker_helper_builder_state_t:sock_file { create unlink };",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the builder state-tree grant must be exact: %q", want)
		}
	}
}

// TestSELinuxPolicyRootlesskitDomainTransition verifies the P5-S2 exec
// transition: exactly one type_transition into the dedicated child domain,
// only from the builder domain on the rootlesskit exec type; the child's
// entry file carries the entrypoint plus loader access. The shared
// docker-helper binary (docker_helper_exec_t) has no transition into either
// special domain — the unit's SELinuxContext= stays the single builder
// binding owner.
func TestSELinuxPolicyRootlesskitDomainTransition(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, want := range []string{
		"type docker_helper_rootlesskit_t, domain;",
		"role system_r types docker_helper_rootlesskit_t;",
		"type_transition docker_helper_builder_t docker_helper_rootlesskit_exec_t:process docker_helper_rootlesskit_t;",
		"allow docker_helper_builder_t docker_helper_rootlesskit_t:process { transition };",
		"allow docker_helper_rootlesskit_t docker_helper_rootlesskit_exec_t:file { entrypoint read open execute getattr map };",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("SELinux policy must carry the rootlesskit transition rule: %q", want)
		}
	}
	// Exactly one type_transition may target the child domain.
	transitions := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "type_transition") && strings.Contains(trimmed, "docker_helper_rootlesskit_t") {
			transitions++
		}
	}
	if transitions != 1 {
		t.Errorf("exactly one type_transition into the rootlesskit child domain may exist, found %d", transitions)
	}
	// The manager's rootlesskit exec grant is transition-shaped: the old
	// no-transition shape (execute_no_trans) is dead under the transition
	// rule and must be gone.
	if strings.Contains(policy, "allow docker_helper_builder_t docker_helper_rootlesskit_exec_t:file { read open execute execute_no_trans getattr map };") {
		t.Error("the manager's rootlesskit exec grant must be execute-only under the transition rule")
	}
	if !strings.Contains(policy, "allow docker_helper_builder_t docker_helper_rootlesskit_exec_t:file { execute };") {
		t.Error("the manager must keep the execute grant needed to launch the rootlesskit vehicle")
	}
}

// TestSELinuxPolicyRootlesskitIsolation verifies the rootlesskit child
// domain receives no grant toward any forbidden surface (the same set the
// builder domain is denied), carries no capability grants, and — for both
// the manager and the child — holds no bin_t:file grant: the helper execs
// (slirp4netns, newuidmap/newgidmap) and the bundled buildkitd are
// deliberate P5-S2 boundaries.
func TestSELinuxPolicyRootlesskitIsolation(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, subject := range []string{"docker_helper_builder_t", "docker_helper_rootlesskit_t"} {
			target := allowTargetToken(trimmed, "allow "+subject+" ")
			if target == "" {
				continue
			}
			if target == "bin_t" {
				t.Errorf("no bin_t grant for %s (helper execs stay a P5-S2 boundary): %s", subject, trimmed)
			}
			for _, forbidden := range forbiddenBuilderTargets {
				if target == forbidden {
					t.Errorf("%s must not receive a grant toward %s: %s", subject, forbidden, trimmed)
				}
			}
		}
		if strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t self:capability") {
			t.Errorf("the rootlesskit child domain must hold no capability grants: %s", trimmed)
		}
	}
}

// TestSELinuxFCBuilderTrees verifies the .fc labels the builder-owned trees
// with the dedicated types and keeps the shared binary on docker_helper_exec_t
// (the unit's SELinuxContext= binding never needs a second binary label).
func TestSELinuxFCBuilderTrees(t *testing.T) {
	fc := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.fc")
	for _, want := range []string{
		"/var/lib/docker-helper-builder(/.*)?    system_u:object_r:docker_helper_builder_state_t:s0",
		"/run/docker-helper-builder(/.*)?        system_u:object_r:docker_helper_builder_runtime_t:s0",
		"/usr/bin/rootlesskit                --  system_u:object_r:docker_helper_rootlesskit_exec_t:s0",
	} {
		if !strings.Contains(fc, want) {
			t.Errorf("file contexts must carry the builder rule: %q", want)
		}
	}
	// The shared binary keeps its single daemon-exec label.
	if !strings.Contains(fc, "/usr/bin/docker-helper              --  system_u:object_r:docker_helper_exec_t:s0") {
		t.Error("the shared binary must stay labeled docker_helper_exec_t")
	}
	// The builder-owned trees must never be labeled with daemon-owned types.
	for _, line := range strings.Split(fc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.Contains(trimmed, "docker-helper-builder") {
			continue
		}
		for _, daemonType := range []string{"docker_helper_state_t:", "docker_helper_runtime_t:"} {
			if strings.Contains(trimmed, "object_r:"+daemonType) {
				t.Errorf("builder tree must not carry the daemon-owned type: %s", trimmed)
			}
		}
	}
}

// TestBuilderUnitSELinuxContextBinding verifies the builder unit pins its
// dedicated domain through SELinuxContext= and that the main unit keeps the
// daemon domain (the binding is per-unit, never global).
func TestBuilderUnitSELinuxContextBinding(t *testing.T) {
	builderUnit := readSELinuxPolicyFile(t, "packaging/systemd/system/docker-helper-builder.service")
	if !strings.Contains(builderUnit, "SELinuxContext=system_u:system_r:docker_helper_builder_t:s0") {
		t.Error("builder unit must bind its dedicated domain via SELinuxContext=system_u:system_r:docker_helper_builder_t:s0")
	}

	mainUnit := readSELinuxPolicyFile(t, "packaging/systemd/system/docker-helper.service")
	if !strings.Contains(mainUnit, "SELinuxContext=system_u:system_r:docker_helper_t:s0") {
		t.Error("main unit must keep the daemon domain binding")
	}
	if strings.Contains(mainUnit, "docker_helper_builder_t") {
		t.Error("main unit must not reference the builder domain")
	}
}

// TestDeploymentLifecycleIsOnlyBuilderRelabelOwner verifies the builder-owned
// path relabels live ONLY in the existing deployment lifecycle (RPM %posttrans
// scriptlet + tarball install-system.sh) and in no other script (no parallel
// relabeling owner; the provisioning script and the DEB scriptlets carry none).
func TestDeploymentLifecycleIsOnlyBuilderRelabelOwner(t *testing.T) {
	// Each owner's exact invocation spelling.
	owners := map[string][]string{
		"packaging/scripts/rpm/posttrans.sh": {
			"restorecon -R /run/docker-helper-builder",
			"restorecon -R /var/lib/docker-helper-builder",
			"restorecon /usr/bin/rootlesskit",
		},
		"packaging/install-system.sh": {
			"\"$RESTORECON\" -R /run/docker-helper-builder",
			"\"$RESTORECON\" -R /var/lib/docker-helper-builder",
			"\"$RESTORECON\" /usr/bin/rootlesskit",
		},
	}
	for path, wants := range owners {
		content := readSELinuxPolicyFile(t, path)
		for _, want := range wants {
			if !strings.Contains(content, want) {
				t.Errorf("%s must label builder-owned paths via restorecon: %q", path, want)
			}
		}
	}
	// Builder relabel patterns in both script spellings.
	builderRelabelPatterns := []string{
		"restorecon /run/docker-helper-builder",
		"restorecon -R /run/docker-helper-builder",
		"restorecon /var/lib/docker-helper-builder",
		"restorecon -R /var/lib/docker-helper-builder",
		"restorecon /usr/bin/rootlesskit",
		"RESTORECON\" /run/docker-helper-builder",
		"RESTORECON\" -R /run/docker-helper-builder",
		"RESTORECON\" /var/lib/docker-helper-builder",
		"RESTORECON\" -R /var/lib/docker-helper-builder",
		"RESTORECON\" /usr/bin/rootlesskit",
	}
	for _, path := range []string{
		"packaging/scripts/lib/provision-builder.sh",
		"packaging/scripts/deb/postinstall.sh",
		"packaging/scripts/deb/preremove.sh",
		"packaging/scripts/deb/postremove.sh",
		"packaging/scripts/rpm/postinstall.sh",
		"packaging/scripts/rpm/preremove.sh",
		"packaging/scripts/rpm/postremove.sh",
	} {
		content := readSELinuxPolicyFile(t, path)
		for _, pattern := range builderRelabelPatterns {
			if strings.Contains(content, pattern) {
				t.Errorf("%s must not carry a builder relabel (the deployment lifecycle owns it): %q", path, pattern)
			}
		}
	}
}

// TestSELinuxCheckCoversBuilderTrees verifies the installed-policy check
// validates the builder trees' file contexts (absent-till-first-run semantics
// unchanged).
func TestSELinuxCheckCoversBuilderTrees(t *testing.T) {
	found := map[string]bool{}
	for _, p := range selinuxCheckPaths {
		found[p] = true
	}
	for _, want := range []string{"/var/lib/docker-helper-builder", "/run/docker-helper-builder"} {
		if !found[want] {
			t.Errorf("selinux check must verify the builder tree %s", want)
		}
	}
}
