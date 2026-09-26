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
	"fmt"
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
		"allow docker_helper_rootlesskit_t docker_helper_rootlesskit_exec_t:file { entrypoint read open execute execute_no_trans getattr map };",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("SELinux policy must carry the rootlesskit transition rule: %q", want)
		}
	}
	// Exactly one type_transition may target the child domain.
	transitions := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "type_transition") && strings.HasSuffix(trimmed, ":process docker_helper_rootlesskit_t;") {
			transitions++
		}
	}
	if transitions != 1 {
		t.Errorf("exactly one type_transition into the rootlesskit child domain may exist, found %d", transitions)
	}
	// The manager's rootlesskit exec grant is transition-shaped: execute plus
	// the bprm read/open (the open/read checks run in the source domain), no
	// execute_no_trans (dead under the transition rule), no loader perms.
	if !strings.Contains(policy, "allow docker_helper_builder_t docker_helper_rootlesskit_exec_t:file { execute read open };") {
		t.Error("the manager's rootlesskit exec grant must be exactly { execute read open } under the transition rule")
	}
	if strings.Contains(policy, "allow docker_helper_builder_t docker_helper_rootlesskit_exec_t:file { read open execute execute_no_trans getattr map };") {
		t.Error("the manager's old no-transition rootlesskit exec grant must be gone")
	}
}

// TestSELinuxPolicyRootlesskitMovedAccess verifies the child domain's
// non-state grants are exactly the rootlesskit-attributed evidence surface:
// the Go-runtime startup reads mirrored from the proven manager rules
// (cgroup2 walk, net sysctl, passwd identity resolution), the
// user-namespace limit read, and the inst.diag output pipe. Nothing else.
func TestSELinuxPolicyRootlesskitMovedAccess(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, want := range []string{
		"allow docker_helper_rootlesskit_t cgroup_t:dir { search };",
		"allow docker_helper_rootlesskit_t cgroup_t:file { read open };",
		"allow docker_helper_rootlesskit_t sysctl_net_t:dir { search };",
		"allow docker_helper_rootlesskit_t sysctl_net_t:file { read open };",
		"allow docker_helper_rootlesskit_t passwd_file_t:file { read open getattr };",
		"allow docker_helper_rootlesskit_t sysctl_t:file { read open getattr };",
		"allow docker_helper_rootlesskit_t docker_helper_builder_t:fifo_file { write };",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the rootlesskit child domain's moved access must be exact: %q", want)
		}
	}
}

// TestSELinuxPolicySlirp4netnsExecType verifies the P5-S2 step-3 exec type:
// the type and its exact fcontext rule exist, execution is granted ONLY to
// the rootlesskit child domain (never the manager or the daemon, never a
// generic bin_t grant), and no other allow rule names the type.
func TestSELinuxPolicySlirp4netnsExecType(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	fc := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.fc")
	if !strings.Contains(policy, "type docker_helper_slirp4netns_exec_t, file_type;") {
		t.Error("SELinux policy must declare docker_helper_slirp4netns_exec_t")
	}
	if !strings.Contains(fc, "/usr/bin/slirp4netns                --  system_u:object_r:docker_helper_slirp4netns_exec_t:s0") {
		t.Error("file contexts must label /usr/bin/slirp4netns with the dedicated exec type")
	}
	want := "allow docker_helper_rootlesskit_t docker_helper_slirp4netns_exec_t:file { execute read open getattr };"
	if !strings.Contains(policy, want) {
		t.Errorf("the slirp4netns execution grant must be exactly the transition-exec source set: %q", want)
	}
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(trimmed, "allow ") || !strings.Contains(trimmed, "docker_helper_slirp4netns_exec_t:") {
			continue
		}
		// The helper domain's own entry/loader rule is legitimate; only the
		// exec grant must be unique to the rootlesskit child domain.
		if strings.HasPrefix(trimmed, "allow docker_helper_slirp4netns_t docker_helper_slirp4netns_exec_t:file { entrypoint read open execute getattr map };") {
			continue
		}
		if trimmed != want {
			t.Errorf("no other domain may receive a slirp4netns exec grant: %s", trimmed)
		}
	}
	// The manager must not gain the right to execute slirp4netns.
	if strings.Contains(policy, "allow docker_helper_builder_t docker_helper_slirp4netns_exec_t") {
		t.Error("the manager domain must not be able to execute slirp4netns")
	}
}

// TestSELinuxPolicySlirp4netnsDomain verifies the P5-S2 helper domain: it is
// declared and entered ONLY through the pointed transition from the
// rootlesskit child domain on the existing exec type, its entry rule carries
// exactly the transition-required entrypoint plus the loader access, and the
// domain is held to the same isolation surface as the other two builder
// domains (no bin_t, no Docker socket/admin token/workspace targets, and no
// capability, capability2, or cap_userns grants — the current enforcing
// boundary stays ungranted, as do any manager-side capability grants).
// builderPolicyAllowRule is one parsed "allow <source> <target>:<class> ..." rule.
type builderPolicyAllowRule struct {
	source, target, class string
}

// builderPolicyTransitionRule is one parsed
// "type_transition <source> <entry>:<class> <dest>" rule.
type builderPolicyTransitionRule struct {
	source, entry, class, dest string
}

// parseSELinuxRules extracts every non-comment allow and type_transition
// rule of the module text with its real fields (source, target/class for
// allows; source, entry type/class, destination for transitions). Malformed
// lines are skipped; the invariant checks below assert on exact field
// values, not on substrings.
func parseSELinuxRules(policy string) ([]builderPolicyAllowRule, []builderPolicyTransitionRule) {
	var allows []builderPolicyAllowRule
	var transitions []builderPolicyTransitionRule
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(trimmed, ";"))
		switch {
		case strings.HasPrefix(trimmed, "allow ") && len(fields) >= 3:
			if target, class, ok := strings.Cut(fields[2], ":"); ok {
				allows = append(allows, builderPolicyAllowRule{source: fields[1], target: target, class: class})
			}
		case strings.HasPrefix(trimmed, "type_transition ") && len(fields) >= 4:
			if entry, class, ok := strings.Cut(fields[2], ":"); ok {
				transitions = append(transitions, builderPolicyTransitionRule{source: fields[1], entry: entry, class: class, dest: fields[3]})
			}
		}
	}
	return allows, transitions
}

// helperDomainPolicyViolations scans the module's parsed rules against the
// helper-domain invariants and returns one human-readable violation per
// broken rule, empty when none:
//   - exactly one type_transition may enter docker_helper_slirp4netns_t, the
//     pointed rootlesskit-child path;
//   - the helper domain holds no bin_t grant and no forbidden-surface grant
//     (Docker socket, admin token, config/state/runtime, Session workspace);
//   - the manager and the helper domains hold no capability, capability2,
//     or cap_userns grants. The rootlesskit child domain is deliberately
//     NOT frozen here: its future cap_userns grant is the next boundary.
func helperDomainPolicyViolations(policy string) []string {
	var violations []string
	allows, transitions := parseSELinuxRules(policy)
	// Exactly one transition may enter the helper domain — count the
	// destination-matching rules, so a duplicate (even byte-identical)
	// transition also violates.
	selirpTransitions := 0
	for _, tr := range transitions {
		if tr.dest != "docker_helper_slirp4netns_t" {
			continue
		}
		selirpTransitions++
		if tr.source != "docker_helper_rootlesskit_t" || tr.entry != "docker_helper_slirp4netns_exec_t" || tr.class != "process" {
			violations = append(violations, fmt.Sprintf("the only transition into the helper domain is the rootlesskit child's exec of its entry type, got: type_transition %s %s:%s %s", tr.source, tr.entry, tr.class, tr.dest))
		}
	}
	if selirpTransitions > 1 {
		violations = append(violations, fmt.Sprintf("exactly one transition may enter the helper domain, found %d", selirpTransitions))
	}
	for _, rule := range allows {
		switch rule.source {
		case "docker_helper_slirp4netns_t":
			if rule.target == "bin_t" {
				violations = append(violations, fmt.Sprintf("no bin_t grant for the helper domain: allow %s %s:%s", rule.source, rule.target, rule.class))
			}
			for _, forbidden := range forbiddenBuilderTargets {
				if rule.target == forbidden {
					violations = append(violations, fmt.Sprintf("the helper domain must not receive a grant toward %s: allow %s %s:%s", forbidden, rule.source, rule.target, rule.class))
				}
			}
		}
		if rule.source == "docker_helper_builder_t" || rule.source == "docker_helper_slirp4netns_t" {
			if rule.target == "self" {
				switch rule.class {
				case "capability", "capability2", "cap_userns":
					violations = append(violations, fmt.Sprintf("%s must hold no capability/capability2/cap_userns grants: allow %s %s:%s", rule.source, rule.source, rule.target, rule.class))
				}
			}
		}
	}
	return violations
}

func TestSELinuxPolicySlirp4netnsDomain(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, want := range []string{
		"type docker_helper_slirp4netns_t, domain;",
		"role system_r types docker_helper_slirp4netns_t;",
		"type_transition docker_helper_rootlesskit_t docker_helper_slirp4netns_exec_t:process docker_helper_slirp4netns_t;",
		"allow docker_helper_rootlesskit_t docker_helper_slirp4netns_t:process { transition };",
		"allow docker_helper_slirp4netns_t docker_helper_slirp4netns_exec_t:file { entrypoint read open execute getattr map };",
		"allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:fifo_file { write getattr };",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("SELinux policy must contain exactly this rule: %s", want)
		}
	}
	if violations := helperDomainPolicyViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the helper-domain invariants: %v", violations)
	}
	// Mutation tests: each forbidden rule, appended to the module text, must
	// trip exactly the invariant that guards it.
	for _, mut := range []struct {
		name        string
		rule        string
		wantTripped string
	}{
		{"admin token grant to helper", "allow docker_helper_slirp4netns_t docker_helper_admin_token_t:file { read };", "docker_helper_admin_token_t"},
		{"generic bin_t execute for helper", "allow docker_helper_slirp4netns_t bin_t:file { execute };", "no bin_t grant for the helper domain"},
		{"manager-side transition into helper", "type_transition docker_helper_builder_t docker_helper_slirp4netns_exec_t:process docker_helper_slirp4netns_t;", "the only transition into the helper domain"},
		{"duplicate identical transition into helper", "type_transition docker_helper_rootlesskit_t docker_helper_slirp4netns_exec_t:process docker_helper_slirp4netns_t;", "exactly one transition may enter the helper domain"},
		{"cap_userns for manager", "allow docker_helper_builder_t self:cap_userns sys_admin;", "docker_helper_builder_t must hold no capability"},
		{"cap_userns for helper", "allow docker_helper_slirp4netns_t self:cap_userns sys_admin;", "docker_helper_slirp4netns_t must hold no capability"},
	} {
		mutated := policy + "\n" + mut.rule
		violations := helperDomainPolicyViolations(mutated)
		if len(violations) == 0 {
			t.Errorf("mutation %q must fail the helper-domain invariants", mut.name)
			continue
		}
		joined := strings.Join(violations, "\n")
		if !strings.Contains(joined, mut.wantTripped) {
			t.Errorf("mutation %q must trip the invariant naming %q, got violations: %v", mut.name, mut.wantTripped, violations)
		}
	}
}

// TestSELinuxPolicyNewuidmapDomainTransition verifies the P5-S2 UID-map
// helper domain: the exec type and the domain exist, the transition is the
// ONLY path in (from the rootlesskit child over the newuidmap entry type),
// the source-side exec set matches the proven sibling shape, the entry rule
// carries the transition-required entrypoint plus the loader access, the
// fcontext rule labels exactly /usr/bin/newuidmap, and the manager may not
// exec newuidmap.
func TestSELinuxPolicyNewuidmapDomainTransition(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	fc := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.fc")
	for _, want := range []string{
		"type docker_helper_newuidmap_exec_t, file_type;",
		"type docker_helper_newuidmap_t, domain;",
		"role system_r types docker_helper_newuidmap_t;",
		"type_transition docker_helper_rootlesskit_t docker_helper_newuidmap_exec_t:process docker_helper_newuidmap_t;",
		"allow docker_helper_rootlesskit_t docker_helper_newuidmap_t:process { transition };",
		"allow docker_helper_rootlesskit_t docker_helper_newuidmap_exec_t:file { execute read open getattr };",
		"allow docker_helper_newuidmap_t docker_helper_newuidmap_exec_t:file { entrypoint read open execute getattr map };",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("SELinux policy must contain exactly this rule: %s", want)
		}
	}
	if !strings.Contains(fc, "/usr/bin/newuidmap                  --  system_u:object_r:docker_helper_newuidmap_exec_t:s0") {
		t.Error("file contexts must label /usr/bin/newuidmap with the dedicated exec type")
	}
	// The transition into the UID-map helper domain is the ONLY path in.
	_, transitions := parseSELinuxRules(policy)
	newuidTransitions := 0
	for _, tr := range transitions {
		if tr.dest != "docker_helper_newuidmap_t" {
			continue
		}
		newuidTransitions++
		if tr.source != "docker_helper_rootlesskit_t" || tr.entry != "docker_helper_newuidmap_exec_t" || tr.class != "process" {
			t.Errorf("the only transition into the UID-map helper domain is the rootlesskit child's exec of its entry type, got: type_transition %s %s:%s %s", tr.source, tr.entry, tr.class, tr.dest)
		}
	}
	if newuidTransitions != 1 {
		t.Errorf("exactly one transition may enter the UID-map helper domain, found %d", newuidTransitions)
	}
	// The manager must not gain the right to execute newuidmap.
	if strings.Contains(policy, "allow docker_helper_builder_t docker_helper_newuidmap_exec_t") {
		t.Error("the manager domain must not be able to execute newuidmap")
	}
	// No bin_t execution grants for either builder-family domain.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, subject := range []string{"docker_helper_builder_t", "docker_helper_rootlesskit_t", "docker_helper_newuidmap_t", "docker_helper_slirp4netns_t"} {
			target := allowTargetToken(trimmed, "allow "+subject+" ")
			if target == "bin_t" {
				t.Errorf("no bin_t grant for %s: %s", subject, trimmed)
			}
		}
	}
}

// TestSELinuxPolicyNewuidmapIsolation verifies the UID-map helper domain's
// isolation surface: no Docker socket, admin token, config/state/runtime,
// or Session workspace grants; no capability, capability2, or cap_userns
// rules; and no transition or allow rule pointing into the domain other
// than the pinned ones.
func TestSELinuxPolicyNewuidmapIsolation(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, subject := range []string{"docker_helper_builder_t", "docker_helper_newuidmap_t"} {
			target := allowTargetToken(trimmed, "allow "+subject+" ")
			if target == "" {
				continue
			}
			for _, forbidden := range forbiddenBuilderTargets {
				if target == forbidden {
					t.Errorf("%s must not receive a grant toward %s: %s", subject, forbidden, trimmed)
				}
			}
		}
	}
	// The module's only cap_userns rule is the rootlesskit child's
	// evidenced sys_admin grant; the helper domain gets none.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, ":cap_userns ") && !strings.Contains(trimmed, "docker_helper_rootlesskit_t self:cap_userns sys_admin") {
			t.Errorf("no cap_userns grant may exist beyond the rootlesskit child's sys_admin rule: %s", trimmed)
		}
	}
	_, transitions := parseSELinuxRules(policy)
	for _, tr := range transitions {
		if tr.dest == "docker_helper_newuidmap_t" && (tr.source != "docker_helper_rootlesskit_t" || tr.entry != "docker_helper_newuidmap_exec_t") {
			t.Errorf("no other exec path may transition into the UID-map helper domain: type_transition %s %s:%s %s", tr.source, tr.entry, tr.class, tr.dest)
		}
	}
}

// newuidmapDomainSurface is the EXACT allow-rule surface of the UID-map
// helper domain: the entry/loader rule plus the live-AVC-evidenced surface
// grants (P5-S1 Tumbleweed runs 36229266623 and 36248541393 P6 windows).
// Any additional or widened rule is a policy regression.
var newuidmapDomainSurface = []string{
	"allow docker_helper_newuidmap_t docker_helper_newuidmap_exec_t:file { entrypoint read open execute getattr map };",
	"allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:fifo_file { write };",
	"allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:dir { read open };",
}

// newuidmapDomainPolicyViolations scans the module's parsed rules against
// the UID-map helper-domain surface invariants and returns one
// human-readable violation per broken rule, empty when none:
//   - the domain's allow-rule surface is EXACTLY newuidmapDomainSurface
//     (source-scoped, full-line equality, so widened permission sets and
//     extra grants both violate);
//   - the domain holds no self:capability, capability2, or cap_userns
//     grant (the privilege model stays the distro's chkstat-applied file
//     caps; the enforcing capability boundary stays ungranted).
func newuidmapDomainPolicyViolations(policy string) []string {
	var violations []string
	seen := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(trimmed, "allow docker_helper_newuidmap_t ") {
			continue
		}
		seen++
		matched := false
		for _, want := range newuidmapDomainSurface {
			if trimmed == want {
				matched = true
				break
			}
		}
		if !matched {
			violations = append(violations, fmt.Sprintf("the UID-map helper domain's surface is exact; unexpected rule: %s", trimmed))
		}
		if strings.HasPrefix(trimmed, "allow docker_helper_newuidmap_t self:") {
			for _, cls := range []string{"capability", "capability2", "cap_userns"} {
				if strings.Contains(trimmed, ":"+cls+" ") {
					violations = append(violations, fmt.Sprintf("the UID-map helper domain must hold no %s grant: %s", cls, trimmed))
				}
			}
		}
	}
	if seen != len(newuidmapDomainSurface) {
		violations = append(violations, fmt.Sprintf("the UID-map helper domain's surface must carry exactly %d allow rules, found %d", len(newuidmapDomainSurface), seen))
	}
	return violations
}

// TestSELinuxPolicyNewuidmapDomainSurface verifies the UID-map helper
// domain's own runtime surface is exactly the live-AVC-evidenced grants
// (fifo_file { write } on the inherited inst.diag pipe toward the
// rootlesskit child; dir { read open } on the /proc/<rootlesskit-pid>
// target of the uid_map write — the O_DIRECTORY open proven by run
// 36248541393) beside the entry rule — and nothing else. Mutation tests
// prove each guard fires: a widened dir grant, a regressed dir grant, any
// extra dir permission, and any capability, capability2, or cap_userns
// grant for the helper domain must trip the exact-surface invariant.
func TestSELinuxPolicyNewuidmapDomainSurface(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	if violations := newuidmapDomainPolicyViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the UID-map helper surface invariants: %v", violations)
	}
	for _, want := range newuidmapDomainSurface {
		if !strings.Contains(policy, want) {
			t.Errorf("SELinux policy must contain exactly this rule: %s", want)
		}
	}
	for _, mut := range []struct {
		name        string
		rule        string
		wantTripped string
	}{
		{"widened fifo grant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:fifo_file { write append };", "unexpected rule"},
		{"widened proc-dir grant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:dir { read open write };", "unexpected rule"},
		{"extra proc-dir getattr grant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:dir { read open getattr };", "unexpected rule"},
		{"regressed proc-dir open grant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:dir { read };", "unexpected rule"},
		{"unwarranted proc-dir search grant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:dir { search };", "unexpected rule"},
		{"cap_userns for helper", "allow docker_helper_newuidmap_t self:cap_userns sys_admin;", "no cap_userns grant"},
		{"capability for helper", "allow docker_helper_newuidmap_t self:capability sys_admin;", "no capability grant"},
		{"capability2 for helper", "allow docker_helper_newuidmap_t self:capability2 kill;", "no capability2 grant"},
	} {
		mutated := policy + "\n" + mut.rule
		violations := newuidmapDomainPolicyViolations(mutated)
		if len(violations) == 0 {
			t.Errorf("mutation %q must fail the UID-map helper surface invariants", mut.name)
			continue
		}
		joined := strings.Join(violations, "\n")
		if !strings.Contains(joined, mut.wantTripped) {
			t.Errorf("mutation %q must trip the invariant naming %q, got violations: %v", mut.name, mut.wantTripped, violations)
		}
	}
}

// TestSELinuxPolicyRootlesskitCapUserns verifies the P5-S2 cap_userns grant:
// exactly one cap_userns rule exists in the module, and it is exactly the
// rootlesskit child domain's self:cap_userns sys_admin (the in-namespace
// sys_admin bit needed to re-exec inside the new userns). The manager, the
// slirp4netns helper, and any other subject must hold no cap_userns rules,
// and the child keeps its zero self:capability/capability2 surface.
func TestSELinuxPolicyRootlesskitCapUserns(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	want := "allow docker_helper_rootlesskit_t self:cap_userns sys_admin;"
	if !strings.Contains(policy, want) {
		t.Errorf("the rootlesskit child domain must have exactly the evidenced cap_userns grant: %q", want)
	}
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, ":cap_userns ") && trimmed != want {
			t.Errorf("no other cap_userns rule may exist (the manager and slirp4netns get none): %s", trimmed)
		}
		if strings.Contains(trimmed, ":capability ") && strings.Contains(trimmed, "docker_helper_rootlesskit_t") {
			t.Errorf("the rootlesskit child domain must keep its zero self:capability surface: %s", trimmed)
		}
		if strings.Contains(trimmed, ":capability2 ") && strings.Contains(trimmed, "docker_helper_rootlesskit_t") {
			t.Errorf("the rootlesskit child domain must keep its zero self:capability2 surface: %s", trimmed)
		}
	}
}

// TestSELinuxPolicyRootlesskitUsernsCreate verifies the P5-S2 userns grant:
// exactly one self:user_namespace create rule exists, it belongs to the
// rootlesskit child domain only (never the manager or the daemon), and no
// rule in the module grants the rootlesskit child domain any unproven
// capability set (cap_userns, self:capability) beyond the previously
// established builder-domain capability surface.
func TestSELinuxPolicyRootlesskitUsernsCreate(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	want := "allow docker_helper_rootlesskit_t self:user_namespace create;"
	if !strings.Contains(policy, want) {
		t.Errorf("the rootlesskit child domain must have exactly the evidenced userns grant: %q", want)
	}
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, ":user_namespace ") && trimmed != want {
			t.Errorf("unexpected additional user_namespace rule: %s", trimmed)
		}
		if strings.Contains(trimmed, ":capability ") && strings.Contains(trimmed, "docker_helper_rootlesskit_t") {
			t.Errorf("the rootlesskit child domain must have no capability grant: %s", trimmed)
		}
		if strings.Contains(trimmed, ":capability2 ") && strings.Contains(trimmed, "docker_helper_rootlesskit_t") {
			t.Errorf("the rootlesskit child domain must have no capability2 grant: %s", trimmed)
		}
	}
	if strings.Contains(policy, "allow docker_helper_builder_t self:user_namespace") {
		t.Error("the manager domain must not gain user_namespace rights")
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
			"restorecon /usr/bin/slirp4netns",
			"restorecon /usr/bin/newuidmap",
		},
		"packaging/install-system.sh": {
			"\"$RESTORECON\" -R /run/docker-helper-builder",
			"\"$RESTORECON\" -R /var/lib/docker-helper-builder",
			"\"$RESTORECON\" /usr/bin/rootlesskit",
			"\"$RESTORECON\" /usr/bin/slirp4netns",
			"\"$RESTORECON\" /usr/bin/newuidmap",
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
	// Builder relabel patterns in both script spellings. These are
	// install-direction relabels: applying the builder-owned types to the
	// builder trees and the third-party binaries the deployment lifecycle
	// owns.
	builderRelabelPatterns := []string{
		"restorecon /run/docker-helper-builder",
		"restorecon -R /run/docker-helper-builder",
		"restorecon /var/lib/docker-helper-builder",
		"restorecon -R /var/lib/docker-helper-builder",
		"restorecon /usr/bin/rootlesskit",
		"restorecon /usr/bin/slirp4netns",
		"RESTORECON\" /run/docker-helper-builder",
		"RESTORECON\" -R /run/docker-helper-builder",
		"RESTORECON\" /var/lib/docker-helper-builder",
		"RESTORECON\" -R /var/lib/docker-helper-builder",
		"RESTORECON\" /usr/bin/rootlesskit",
		"RESTORECON\" /usr/bin/slirp4netns",
	}
	// The erase-direction cleanup is a different, documented operation: the
	// RPM preremove restores the third-party binaries' canonical labels
	// after the verified module removal (exact spelling checked positively
	// by the behavioral tests). The erase lifecycle still must never relabel
	// the builder TREES, so only the tree patterns apply there.
	builderTreeRelabelPatterns := []string{
		"restorecon /run/docker-helper-builder",
		"restorecon -R /run/docker-helper-builder",
		"restorecon /var/lib/docker-helper-builder",
		"restorecon -R /var/lib/docker-helper-builder",
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
		patterns := builderRelabelPatterns
		if path == "packaging/scripts/rpm/preremove.sh" {
			patterns = builderTreeRelabelPatterns
		}
		for _, pattern := range patterns {
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
