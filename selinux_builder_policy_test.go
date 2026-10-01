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
	"regexp"
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
// the single binding owner. A transition whose SOURCE is the builder domain
// (the G32 r3 launcher self-reexec) is a different, legitimate shape and does
// not violate the invariant.
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
// traversal, the socket-file open/read/write/getattr for manager.sock (the
// runtime ROOT type after the G32 r3 root split) and the per-op buildkitd
// sockets (the per-op runtime type), and the connectto toward the builder
// domain — and no other docker_helper_t grant touches a builder type. The
// daemon keeps zero grants on the operation state type.
func TestSELinuxPolicyBuilderDaemonTransportExact(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	want := []string{
		"allow docker_helper_t docker_helper_builder_runtime_root_t:dir { search };",
		"allow docker_helper_t docker_helper_builder_runtime_root_t:sock_file { getattr open read write };",
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

// TestSELinuxPolicyLauncherChainRootlesskitTransition verifies the G32 r3
// launch chain: the only production transition into the flow domain is the
// launcher edge (builder_t self-reexec -> docker_helper_builder_launcher_t
// -> rootlesskit_t, the forced setexeccon context), the legacy direct
// launch rules are gone, and the launcher domain carries exactly the
// structural chain grants.
func TestSELinuxPolicyLauncherChainRootlesskitTransition(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, want := range []string{
		"type docker_helper_rootlesskit_t, domain;",
		"role system_r types docker_helper_rootlesskit_t;",
		"type docker_helper_builder_launcher_t, domain;",
		"role system_r types docker_helper_builder_launcher_t;",
		// Hop 1: the manager's self-reexec transitions into the launcher domain.
		"type_transition docker_helper_builder_t docker_helper_exec_t:process docker_helper_builder_launcher_t;",
		"allow docker_helper_builder_t docker_helper_builder_launcher_t:process { transition };",
		// The R2 live startup grants: execute on the shared entry image and
		// the inherited inst.diag pipe write (launcher-stage mirror of the
		// rootlesskit diag contract below).
		"allow docker_helper_builder_launcher_t docker_helper_exec_t:file { entrypoint read open getattr map execute };",
		// The launcher's own forced-context write; the manager carries none.
		"allow docker_helper_builder_launcher_t self:process { setexec };",
		"allow docker_helper_builder_launcher_t docker_helper_builder_t:fifo_file { write };",
		// Hop 2: the only transition into the flow domain.
		"type_transition docker_helper_builder_launcher_t docker_helper_rootlesskit_exec_t:process docker_helper_rootlesskit_t;",
		"allow docker_helper_builder_launcher_t docker_helper_rootlesskit_t:process { transition };",
		"allow docker_helper_builder_launcher_t docker_helper_rootlesskit_exec_t:file { execute read open getattr };",
		// The flow domain's own entry file (keyed to the target domain; reused
		// unchanged by the launcher edge).
		"allow docker_helper_rootlesskit_t docker_helper_rootlesskit_exec_t:file { entrypoint read open execute execute_no_trans getattr map };",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("SELinux policy must carry the launch-chain rule: %q", want)
		}
	}
	// The legacy direct launch path must be GONE (G32 r3 I9): no manager
	// rootlesskit exec grant, no direct builder_t -> rootlesskit_t transition.
	for _, gone := range []string{
		"allow docker_helper_builder_t docker_helper_rootlesskit_exec_t:file { execute read open };",
		"type_transition docker_helper_builder_t docker_helper_rootlesskit_exec_t:process docker_helper_rootlesskit_t;",
		"allow docker_helper_builder_t docker_helper_rootlesskit_t:process { transition };",
		"allow docker_helper_builder_t docker_helper_rootlesskit_exec_t:file { read open execute execute_no_trans getattr map };",
	} {
		if strings.Contains(policy, gone) {
			t.Errorf("the legacy direct launch rule must not exist: %q", gone)
		}
	}
	// The manager must hold no setexec authority and no execute grant on the
	// rootlesskit entry type: the launch path is launcher-only.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "allow docker_helper_builder_t self:process") {
			t.Errorf("the manager domain must hold no self:process grant (setexec is launcher-only): %s", trimmed)
		}
		if strings.HasPrefix(trimmed, "allow docker_helper_builder_t docker_helper_rootlesskit_exec_t") {
			t.Errorf("the manager domain must hold no rootlesskit exec grant: %s", trimmed)
		}
	}
	// Single-entrypoint inventory: exactly one production type_transition
	// targets the flow domain, and it is the launcher edge on the
	// rootlesskit exec type.
	_, transitions := parseSELinuxRules(policy)
	rootlesskitTransitions := 0
	for _, tr := range transitions {
		if tr.dest != "docker_helper_rootlesskit_t" {
			continue
		}
		rootlesskitTransitions++
		if tr.source != "docker_helper_builder_launcher_t" || tr.entry != "docker_helper_rootlesskit_exec_t" || tr.class != "process" {
			t.Errorf("the only transition into the flow domain is the launcher edge, got: type_transition %s %s:%s %s", tr.source, tr.entry, tr.class, tr.dest)
		}
	}
	if rootlesskitTransitions != 1 {
		t.Errorf("exactly one type_transition into the flow domain may exist, found %d", rootlesskitTransitions)
	}
}

// TestSELinuxPolicyRootlesskitMovedAccess verifies the child domain's
// non-state grants are exactly the rootlesskit-attributed evidence surface:
// the Go-runtime startup reads mirrored from the proven manager rules
// (cgroup2 walk, net sysctl, passwd identity resolution), the
// user-namespace limit read, the inst.diag output pipe, the 4C-3
// same-domain nsenter exec grant, and the 4C-6 same-domain ip execution
// grant over the DISTRO's ifconfig_exec_t identity. The nsenter block is
// the exec-identity structural invariant: the dedicated type exists, the
// grant is exactly the 4C-2 boundary's source-side set (execute/read/open/
// execute_no_trans/getattr/map, NO entrypoint), nsenter stays IN the flow
// domain (no type_transition, no docker_helper_nsenter_t domain anywhere),
// no other subject holds an nsenter_exec_t allow, and no generic bin_t
// execution exists for the child (getsubids stays closed). The ip block is
// the second exec-identity structural invariant: the distro ifconfig_exec_t
// type is required, the grant is exactly the proven same-domain loader set,
// the shipped .fc carries NO delta for it (no custom ip exec type, no
// relabel of the distro inode), the module contains ZERO ifconfig_t
// references (no transition into the distro's broad administration domain,
// no entrypoint, no role addition, no range_transition, no copied
// capability/socket/tun/sysctl rules), no other subject holds an
// ifconfig_exec_t allow, no generic bin_t execution exists, and the child
// domain stays an mcs_constrained_type member. Mutations prove both
// shapes: type_transitions, entrypoint additions, widened perm sets
// (+entrypoint/+ioctl/+lock/+setattr), the missing execute and missing
// execute_no_trans regressions, generic bin_t execute grants, and grants
// for another subject all trip.
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
		"allow docker_helper_rootlesskit_t docker_helper_nsenter_exec_t:file { execute read open execute_no_trans getattr map };",
		// The 4C-6 same-domain ip execution over the DISTRO's shared
		// network-tool exec type; the require block must declare it.
		"type ifconfig_exec_t;",
		"allow docker_helper_rootlesskit_t ifconfig_exec_t:file { execute read open execute_no_trans getattr map };",
		// The domain's isolation shape (§6/§7 pins).
		"typeattribute docker_helper_rootlesskit_t mcs_constrained_type;",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the rootlesskit child domain's moved access must be exact: %q", want)
		}
	}
	if !strings.Contains(policy, "type docker_helper_nsenter_exec_t, file_type;") {
		t.Error("SELinux policy must declare docker_helper_nsenter_exec_t")
	}
	// nsenterViolations returns one violation per line of module text that
	// breaks the nsenter exec-identity invariants: no nsenter process
	// domain may exist, no transition may involve the nsenter exec type,
	// no generic bin_t execution for the flow child (getsubids stays
	// closed), and the nsenter exec grant is unique to the rootlesskit
	// child domain and exact.
	nsenterViolations := func(text string) []string {
		var violations []string
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, "type docker_helper_nsenter_t") {
				violations = append(violations, "nsenter must stay in the flow domain: no nsenter process domain may exist")
			}
			if strings.HasPrefix(trimmed, "type_transition ") && strings.Contains(trimmed, "docker_helper_nsenter") {
				violations = append(violations, "nsenter exec must not transition (execute_no_trans, same domain)")
			}
			if strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t bin_t:file") {
				violations = append(violations, "no generic bin_t execution for the flow child (getsubids stays closed)")
			}
			if strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, "docker_helper_nsenter_exec_t:") &&
				trimmed != "allow docker_helper_rootlesskit_t docker_helper_nsenter_exec_t:file { execute read open execute_no_trans getattr map };" {
				violations = append(violations, "the nsenter exec grant is unique to the rootlesskit child domain and must be exact")
			}
		}
		return violations
	}
	if violations := nsenterViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the nsenter exec-identity invariants: %v", violations)
	}
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"transition to a separate nsenter domain", "type_transition docker_helper_rootlesskit_t docker_helper_nsenter_exec_t:process docker_helper_nsenter_t;"},
		{"transition on the same-domain identity", "type_transition docker_helper_rootlesskit_t docker_helper_nsenter_exec_t:process docker_helper_rootlesskit_t;"},
		{"entrypoint addition", "allow docker_helper_rootlesskit_t docker_helper_nsenter_exec_t:file { execute read open execute_no_trans getattr map entrypoint };"},
		{"widened nsenter perms", "allow docker_helper_rootlesskit_t docker_helper_nsenter_exec_t:file { execute read open execute_no_trans getattr map setattr };"},
		{"generic bin_t execute", "allow docker_helper_rootlesskit_t bin_t:file { execute };"},
		{"nsenter exec for the manager", "allow docker_helper_builder_t docker_helper_nsenter_exec_t:file { execute read open execute_no_trans getattr map };"},
		{"nsenter exec for the launcher", "allow docker_helper_builder_launcher_t docker_helper_nsenter_exec_t:file { execute read open };"},
		{"nsenter exec for the UID-map helper", "allow docker_helper_newuidmap_t docker_helper_nsenter_exec_t:file { execute };"},
		{"nsenter exec for the GID-map helper", "allow docker_helper_newgidmap_t docker_helper_nsenter_exec_t:file { execute };"},
		{"nsenter exec for the network helper", "allow docker_helper_slirp4netns_t docker_helper_nsenter_exec_t:file { execute };"},
	} {
		if len(nsenterViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the nsenter exec-identity invariant", mut.name)
		}
	}
	// ipExecViolations returns one violation per line of module text that
	// breaks the ip execution-identity invariants: the distro ifconfig_t
	// administration domain must receive ZERO semantic references from
	// this module (no process transition, no entrypoint, no role addition,
	// no range_transition, no copied capability/socket/tun/sysctl rules —
	// the same-domain model only), no custom ip exec type may exist, no
	// generic bin_t execution for the flow child, the .fc must carry no
	// ip/ifconfig relabel, and the ifconfig_exec_t allow is unique to the
	// rootlesskit child domain and exact.
	fc := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.fc")
	if strings.Contains(fc, "ifconfig") {
		t.Errorf("the shipped .fc must carry no delta for the distro ip/ifconfig identity (the distro label stands): %q", "ifconfig")
	}
	ipExecViolations := func(text string) []string {
		var violations []string
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			// "ifconfig_t" is not a substring of "ifconfig_exec_t", so this
			// matches exactly the distro administration-domain references.
			if strings.Contains(trimmed, "ifconfig_t") {
				violations = append(violations, "the module must hold zero ifconfig_t references (same-domain execution, never the distro administration domain): "+trimmed)
			}
			if strings.Contains(trimmed, "docker_helper_ip_exec_t") {
				violations = append(violations, "no custom ip exec type may exist (the distro ifconfig_exec_t identity is used)")
			}
			if (strings.HasPrefix(trimmed, "type_transition ") || strings.HasPrefix(trimmed, "range_transition ")) &&
				strings.Contains(trimmed, "ifconfig_exec_t") {
				violations = append(violations, "the ip executable must not transition or carry a range_transition (execute_no_trans, same domain)")
			}
			if strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t bin_t:file") {
				violations = append(violations, "no generic bin_t execution for the flow child (the ip grant stays pointed)")
			}
			if strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, "ifconfig_exec_t:") &&
				trimmed != "allow docker_helper_rootlesskit_t ifconfig_exec_t:file { execute read open execute_no_trans getattr map };" {
				violations = append(violations, "the ip execution grant is unique to the rootlesskit child domain and must be exact")
			}
		}
		return violations
	}
	if violations := ipExecViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the ip execution-identity invariants: %v", violations)
	}
	// Missing-perm regressions: neither shortened shape is the evidenced
	// same-domain loader set.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing execute", "allow docker_helper_rootlesskit_t ifconfig_exec_t:file { read open execute_no_trans getattr map };"},
		{"missing execute_no_trans", "allow docker_helper_rootlesskit_t ifconfig_exec_t:file { execute read open getattr map };"},
	} {
		mutated := strings.Replace(policy,
			"allow docker_helper_rootlesskit_t ifconfig_exec_t:file { execute read open execute_no_trans getattr map };",
			regressed.rule, 1)
		if len(ipExecViolations(mutated)) == 0 {
			t.Errorf("the ip grant %q regression must trip the exec-identity invariant", regressed.name)
		}
	}
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"transition into the distro ifconfig_t domain", "type_transition docker_helper_rootlesskit_t ifconfig_exec_t:process ifconfig_t;"},
		{"process transition grant toward ifconfig_t", "allow docker_helper_rootlesskit_t ifconfig_t:process transition;"},
		{"entrypoint grant for ifconfig_t", "allow docker_helper_rootlesskit_t ifconfig_t:file entrypoint;"},
		{"role addition for ifconfig_t", "role system_r types ifconfig_t;"},
		{"range_transition into ifconfig_t", "range_transition docker_helper_rootlesskit_t ifconfig_exec_t:process s0;"},
		{"copied ifconfig_t netlink rule", "allow ifconfig_t self:netlink_route_socket { create };"},
		{"entrypoint addition", "allow docker_helper_rootlesskit_t ifconfig_exec_t:file { execute read open execute_no_trans getattr map entrypoint };"},
		{"ioctl addition", "allow docker_helper_rootlesskit_t ifconfig_exec_t:file { execute read open execute_no_trans getattr map ioctl };"},
		{"lock addition", "allow docker_helper_rootlesskit_t ifconfig_exec_t:file { execute read open execute_no_trans getattr map lock };"},
		{"setattr addition", "allow docker_helper_rootlesskit_t ifconfig_exec_t:file { execute read open execute_no_trans getattr map setattr };"},
		{"custom ip exec type", "type docker_helper_ip_exec_t, file_type;"},
		{"generic bin_t execute", "allow docker_helper_rootlesskit_t bin_t:file { execute };"},
		{"ip exec for the manager", "allow docker_helper_builder_t ifconfig_exec_t:file { execute read open execute_no_trans getattr map };"},
		{"ip exec for the launcher", "allow docker_helper_builder_launcher_t ifconfig_exec_t:file { execute read open };"},
		{"ip exec for the UID-map helper", "allow docker_helper_newuidmap_t ifconfig_exec_t:file { execute };"},
		{"ip exec for the GID-map helper", "allow docker_helper_newgidmap_t ifconfig_exec_t:file { execute };"},
		{"ip exec for the network helper", "allow docker_helper_slirp4netns_t ifconfig_exec_t:file { execute };"},
	} {
		if len(ipExecViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the ip exec-identity invariant", mut.name)
		}
	}
	// The 4C-11/4C-12/4C-14/4C-17 TUN/TAP device-node invariant: the
	// require block declares the DISTRO-owned type tun_tap_device_t
	// (unchanged; chr_file already required ioctl — require delta zero),
	// and the rootlesskit child domain holds EXACTLY ONE allow on it —
	// the evidenced open(O_RDWR) chain EXTENDED by the ordinary ioctl bit
	// ({ read write open ioctl }; selinux_inode_permission() passed
	// { read write }, selinux_file_open() -> open_file_to_av() needed
	// `open`, and the canonical 4C-13 enforcing run 36731429729 proved
	// the ioctl gate at ioctlcmd=0x54ca = TUNSETIFF) — plus EXACTLY ONE
	// allowxperm rule pinning the extended-permission command authority
	// to { 0x54ca 0x54cb } (TUNSETIFF + TUNSETPERSIST, the two
	// live-proven create-the-tap commands: TUNSETIFF at the 4C-13
	// boundary and TUNSETPERSIST at the 4C-16 boundary — the iproute2
	// tap_add_ioctl() sequence's only two ioctls for this invocation;
	// every other chr_file ioctl command stays closed — no third value,
	// no range 0x5400-0x54ff / 0x54ca-0x54cc, no complement
	// ~{ 0x54ca 0x54cb }; an ordinary ioctl bit with no allowxperm for
	// the tuple would be UNRESTRICTED command authority). No other
	// permission of chr_file (getattr/append/lock/create/setattr all stay
	// closed), no distro macro import (corenet_rw_tun_tap_dev() expands
	// far beyond the observed chain AND carries no allowxperm — a macro
	// import would grant unrestricted ioctl), no custom tun device type,
	// no .fc relabel of the global node, no capability surface (the TUN
	// driver's ns_capable check is carried by the child's own cap_userns
	// rule), and no other subject holds a tun_tap_device_t allow or xperm
	// rule.
	for _, want := range []string{
		"type tun_tap_device_t;",
		"allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read write open ioctl };",
		"allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x54cb };",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the tun-tap device-node { read write open ioctl } + TUNSETIFF/TUNSETPERSIST xperm grant must be present: %q", want)
		}
	}
	if strings.Contains(fc, "/dev/net/tun") {
		t.Errorf("the shipped .fc must carry no delta for the global distro TUN node (the distro label stands): %q", "/dev/net/tun")
	}
	tunViolations := func(text string) []string {
		var violations []string
		rootlesskitTunRules := 0
		rootlesskitTunXpermRules := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			switch {
			case strings.Contains(trimmed, "corenet_rw_tun_tap_dev"):
				violations = append(violations, "the distro macro must not be used (its rw_chr_file_perms expansion carries getattr/append/ioctl/lock beyond the observed chain, and a macro carries no allowxperm — an imported macro would grant unrestricted ioctl command authority): "+trimmed)
			case strings.Contains(trimmed, "docker_helper_tun_exec_t") || strings.Contains(trimmed, "docker_helper_tun_device_t"):
				violations = append(violations, "no custom tun device type may exist (the distro tun_tap_device_t identity is used): "+trimmed)
			case strings.HasPrefix(trimmed, "allowxperm ") && strings.Contains(trimmed, "tun_tap_device_t"):
				if trimmed == "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x54cb };" {
					rootlesskitTunXpermRules++
				} else {
					violations = append(violations, fmt.Sprintf("the tun_tap_device_t ioctl xperm surface is exactly the rootlesskit child's single { 0x54ca 0x54cb } TUNSETIFF+TUNSETPERSIST rule (no third command, no range, no complement, no other subject): %s", trimmed))
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, "tun_tap_device_t:chr_file"):
				if trimmed == "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read write open ioctl };" {
					rootlesskitTunRules++
				} else {
					violations = append(violations, fmt.Sprintf("the tun_tap_device_t surface is exactly the rootlesskit child's { read write open ioctl } rule plus its single TUNSETIFF xperm rule (no other permission, no other subject): %s", trimmed))
				}
			case strings.Contains(trimmed, "docker_helper_rootlesskit_t") && (strings.Contains(trimmed, "capability net_admin") || strings.Contains(trimmed, "capability net_raw") || strings.Contains(trimmed, "cap_userns net_admin")):
				violations = append(violations, fmt.Sprintf("no capability surface accompanies the tun open (the TUN driver's ns_capable check stays a separate live boundary): %s", trimmed))
			}
		}
		if rootlesskitTunRules != 1 {
			violations = append(violations, fmt.Sprintf("the rootlesskit child domain must hold exactly one tun_tap_device_t rule — the evidenced { read write open ioctl } grant — found %d", rootlesskitTunRules))
		}
		if rootlesskitTunXpermRules != 1 {
			violations = append(violations, fmt.Sprintf("the rootlesskit child domain must hold exactly one tun_tap_device_t ioctl xperm rule — the evidenced { 0x54ca 0x54cb } TUNSETIFF+TUNSETPERSIST rule — found %d", rootlesskitTunXpermRules))
		}
		return violations
	}
	if violations := tunViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the tun-tap device-node invariants: %v", violations)
	}
	// Missing-perm regressions: no shortened shape is the evidenced
	// open(O_RDWR)+TUNSETIFF chain.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing open", "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read write ioctl };"},
		{"missing write", "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read open ioctl };"},
		{"missing read", "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { write open ioctl };"},
		{"missing ioctl (the 4C-12 shape must trip again)", "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read write open };"},
	} {
		mutated := strings.Replace(policy,
			"allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read write open ioctl };",
			regressed.rule, 1)
		if len(tunViolations(mutated)) == 0 {
			t.Errorf("the tun grant %q regression must trip the device-node invariant", regressed.name)
		}
	}
	// Xperm regressions: the TUNSETIFF+TUNSETPERSIST xperm rule must
	// exist exactly once, exactly as pinned — removal, a missing
	// 0x54ca, a missing 0x54cb (the pre-4C-17 shape), and a wrong value
	// all destroy the exact two-command authority.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing allowxperm", ""},
		{"missing 0x54ca", "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl { 0x54c8 };"},
		{"missing 0x54cb (the pre-4C-17 { 0x54ca } shape must trip again)", "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl { 0x54ca };"},
	} {
		mutated := strings.Replace(policy,
			"allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x54cb };",
			regressed.rule, 1)
		if len(tunViolations(mutated)) == 0 {
			t.Errorf("the tun xperm grant %q regression must trip the device-node invariant", regressed.name)
		}
	}
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"widened getattr", "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read write open ioctl getattr };"},
		{"widened append", "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read write open ioctl append };"},
		{"widened lock", "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read write open ioctl lock };"},
		{"widened create", "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read write open ioctl create };"},
		{"widened setattr", "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read write open ioctl setattr };"},
		{"xperm duplicate rule", "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x54cb };"},
		{"xperm parallel 0x54ca rule", "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl 0x54ca;"},
		{"xperm parallel 0x54cb rule", "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl 0x54cb;"},
		{"xperm widened +0x54c8", "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl 0x54c8;"},
		{"xperm widened +0x54c9", "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl 0x54c9;"},
		{"xperm widened +0x54cc (any third command)", "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl 0x54cc;"},
		{"xperm widened set +0x54cc", "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x54cb 0x54cc };"},
		{"xperm widened range 0x5400-0x54ff", "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl 0x5400-0x54ff;"},
		{"xperm widened range 0x54ca-0x54cc", "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl 0x54ca-0x54cc;"},
		{"xperm widened complement ~{ 0x54ca 0x54cb }", "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl ~{ 0x54ca 0x54cb };"},
		{"distro macro import", "corenet_rw_tun_tap_dev(docker_helper_rootlesskit_t)"},
		{"custom tun device type", "type docker_helper_tun_device_t, file_type;"},
		{"custom tun device rule", "allow docker_helper_rootlesskit_t docker_helper_tun_device_t:chr_file { read write open ioctl };"},
		{"duplicate tun rule", "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read write open ioctl };"},
		{"parallel tun open rule", "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file open;"},
		{"cap_userns net_admin for the flow domain", "allow docker_helper_rootlesskit_t self:cap_userns net_admin;"},
		{"plain capability net_admin for the flow domain", "allow docker_helper_rootlesskit_t self:capability net_admin;"},
		{"plain capability net_raw for the flow domain", "allow docker_helper_rootlesskit_t self:capability net_raw;"},
		{"tun open for the manager", "allow docker_helper_builder_t tun_tap_device_t:chr_file { read write open ioctl };"},
		{"tun open for the launcher", "allow docker_helper_builder_launcher_t tun_tap_device_t:chr_file { read write open ioctl };"},
		{"tun open for the UID-map helper", "allow docker_helper_newuidmap_t tun_tap_device_t:chr_file { read write open ioctl };"},
		{"tun open for the GID-map helper", "allow docker_helper_newgidmap_t tun_tap_device_t:chr_file { read write open ioctl };"},
		{"tun open for the network helper", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write open ioctl };"},
	} {
		if len(tunViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the tun-tap device-node invariant", mut.name)
		}
	}
	// The 4C-7/4C-8/4C-9/4C-10/4C-19/4C-20/4C-21 NETLINK_ROUTE socket
	// invariant: the require block declares exactly { create setopt bind
	// getattr write nlmsg_read read }, the rootlesskit child domain holds
	// EXACTLY ONE netlink_route_socket allow — the evidenced
	// create+setopt+bind+getattr+write+nlmsg_read+read rule (setopt: the
	// ONE class-level permission behind the SO_SNDBUF/SO_RCVBUF/
	// NETLINK_EXT_ACK sequence; bind: the local socket binding; getattr:
	// the getsockname metadata query; write: the GENERIC socket-level
	// send permission the sendmsg syscall path requires — hidden in the
	// canonical window by the distro base policy's domain-wide
	// `dontaudit domain domain:netlink_route_socket { read write };`
	// catch-all and proven in the 4C-18 dontaudit-disabled runs;
	// nlmsg_read: the message-class check the kernel's Netlink send path
	// requires for a read-class request (the RTM_GETLINK lookup) —
	// audible in the canonical 4C-19 run 36772822101 record 1306;
	// read: the GENERIC receive-side permission the kernel's reply path
	// checks via recvmsg → security_socket_recvmsg → selinux_socket_recvmsg
	// → sock_has_perm(SOCKET__READ) — the 4C-20 run 36823922085 proved the
	// lookup send succeeded (sendmsg fd 4, exit=52) and the failure moved
	// to the receive side (recvmsg exit=-13 twice, userspace "netlink
	// receive error Permission denied (13)"), exposed by the -DB
	// companion as record 32519) — no other permission of the class
	// (the mutation-class nlmsg_write, connect, getopt, ioctl/shutdown
	// all stay closed: nlmsg_write owns the later RTM_NEWLINK mutation
	// boundary), no capability surface (net_admin/net_raw stay closed;
	// capability mediation is a separate live boundary), and no other
	// subject holds a netlink_route_socket allow. This is the module's
	// only explicit route-netlink object surface: send+lookup+receive is
	// still not route-mutation authority.
	for _, want := range []string{
		"class netlink_route_socket { create setopt bind getattr write nlmsg_read read nlmsg_write };",
		"allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind getattr write nlmsg_read read nlmsg_write };",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the netlink-route send+lookup+receive-surface grant must be present: %q", want)
		}
	}
	netlinkViolations := func(text string) []string {
		var violations []string
		rootlesskitNetlinkRules := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			switch {
			case strings.Contains(trimmed, "class netlink_route_socket "):
				if trimmed != "class netlink_route_socket { create setopt bind getattr write nlmsg_read read nlmsg_write };" {
					violations = append(violations, fmt.Sprintf("the require block's netlink_route_socket declaration is exactly the eight evidenced permissions: %s", trimmed))
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, ":netlink_route_socket"):
				if trimmed == "allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind getattr write nlmsg_read read nlmsg_write };" {
					rootlesskitNetlinkRules++
				} else {
					violations = append(violations, fmt.Sprintf("the netlink_route_socket surface is exactly the rootlesskit child's create+setopt+bind+getattr+write+nlmsg_read+read+nlmsg_write rule (no other permission, no other subject): %s", trimmed))
				}
			case strings.Contains(trimmed, "docker_helper_rootlesskit_t") && (strings.Contains(trimmed, "capability net_admin") || strings.Contains(trimmed, "capability net_raw") || strings.Contains(trimmed, "cap_userns net_admin")):
				violations = append(violations, fmt.Sprintf("no capability surface accompanies the socket create (capability mediation is a separate live boundary): %s", trimmed))
			}
		}
		if rootlesskitNetlinkRules != 1 {
			violations = append(violations, fmt.Sprintf("the rootlesskit child domain must hold exactly one netlink_route_socket rule — the evidenced create+setopt+bind+getattr+write+nlmsg_read+read+nlmsg_write grant — found %d", rootlesskitNetlinkRules))
		}
		return violations
	}
	if violations := netlinkViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the netlink-route invariants: %v", violations)
	}
	// Missing-perm regressions: no shortened shape is the evidenced
	// create+setopt+bind+getattr+write+nlmsg_read+read+nlmsg_write surface.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing nlmsg_write (the pre-4C-22 seven-permission shape must trip again)", "allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind getattr write nlmsg_read read };"},
		{"missing read (the pre-4C-21 six-permission shape must trip again)", "allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind getattr write nlmsg_read nlmsg_write };"},
		{"missing nlmsg_read", "allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind getattr write read nlmsg_write };"},
		{"missing write", "allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind getattr nlmsg_read read nlmsg_write };"},
		{"missing getattr", "allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind write nlmsg_read read nlmsg_write };"},
		{"missing bind", "allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt getattr write nlmsg_read read nlmsg_write };"},
		{"missing setopt", "allow docker_helper_rootlesskit_t self:netlink_route_socket { create bind getattr write nlmsg_read read nlmsg_write };"},
		{"missing create", "allow docker_helper_rootlesskit_t self:netlink_route_socket { setopt bind getattr write nlmsg_read read nlmsg_write };"},
	} {
		mutated := strings.Replace(policy,
			"allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind getattr write nlmsg_read read nlmsg_write };",
			regressed.rule, 1)
		if len(netlinkViolations(mutated)) == 0 {
			t.Errorf("the netlink grant %q regression must trip the create invariant", regressed.name)
		}
	}
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"widened getopt", "allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind getattr write nlmsg_read read nlmsg_write getopt };"},
		{"widened connect", "allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind getattr write nlmsg_read read nlmsg_write connect };"},
		{"widened ioctl", "allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind getattr write nlmsg_read read nlmsg_write ioctl };"},
		{"widened shutdown", "allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind getattr write nlmsg_read read nlmsg_write shutdown };"},
		{"widened require declaration", "class netlink_route_socket { create setopt bind getattr write nlmsg_read read nlmsg_write getopt };"},
		{"duplicate exact netlink send rule", "allow docker_helper_rootlesskit_t self:netlink_route_socket { create setopt bind getattr write nlmsg_read read nlmsg_write };"},
		{"parallel netlink nlmsg_write rule", "allow docker_helper_rootlesskit_t self:netlink_route_socket nlmsg_write;"},
		{"parallel netlink read rule", "allow docker_helper_rootlesskit_t self:netlink_route_socket read;"},
		{"parallel netlink write rule", "allow docker_helper_rootlesskit_t self:netlink_route_socket write;"},
		{"parallel netlink nlmsg_read rule", "allow docker_helper_rootlesskit_t self:netlink_route_socket nlmsg_read;"},
		{"parallel netlink getattr rule", "allow docker_helper_rootlesskit_t self:netlink_route_socket getattr;"},
		{"cap_userns net_admin for the flow domain", "allow docker_helper_rootlesskit_t self:cap_userns net_admin;"},
		{"plain capability net_admin for the flow domain", "allow docker_helper_rootlesskit_t self:capability net_admin;"},
		{"plain capability net_raw for the flow domain", "allow docker_helper_rootlesskit_t self:capability net_raw;"},
		{"netlink send for the manager", "allow docker_helper_builder_t self:netlink_route_socket write;"},
		{"netlink send for the launcher", "allow docker_helper_builder_launcher_t self:netlink_route_socket write;"},
		{"netlink send for the UID-map helper", "allow docker_helper_newuidmap_t self:netlink_route_socket write;"},
		{"netlink send for the GID-map helper", "allow docker_helper_newgidmap_t self:netlink_route_socket write;"},
		{"netlink send for the network helper", "allow docker_helper_slirp4netns_t self:netlink_route_socket write;"},
		{"netlink lookup for the manager", "allow docker_helper_builder_t self:netlink_route_socket nlmsg_read;"},
		{"netlink mutation for the launcher", "allow docker_helper_builder_launcher_t self:netlink_route_socket nlmsg_write;"},
	} {
		if len(netlinkViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the netlink-route create invariant", mut.name)
		}
	}
	// The 4C-16 TUN-socket create invariant: the require block declares
	// exactly { create } on tun_socket, and the rootlesskit child domain
	// holds EXACTLY ONE self:tun_socket allow — the evidenced
	// security_tun_dev_create() boundary of the NEW-device TUNSETIFF path
	// (the canonical 4C-15 enforcing run 36755379800, audit record 422:
	// denied { create } comm="ip" self->self tclass=tun_socket
	// permissive=0, after the chr_file ioctl+xperm gate and the
	// cap_userns net_admin check both passed) — no attach_queue (the
	// TUNSETQUEUE/queue-attachment path, not the new-device creation), no
	// relabelfrom/relabelto (the attach-to-an-existing-TUN-object path),
	// no inherited generic socket permission, no distro
	// create_socket_perms-style macro, and no other subject holds a
	// tun_socket allow.
	for _, want := range []string{
		"class tun_socket { create };",
		"allow docker_helper_rootlesskit_t self:tun_socket create;",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the tun-socket create grant must be present: %q", want)
		}
	}
	tunSocketViolations := func(text string) []string {
		var violations []string
		tunSocketRequireDecls := 0
		rootlesskitTunSocketRules := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			switch {
			case strings.Contains(trimmed, "create_socket_perms"):
				violations = append(violations, "the distro socket macros are banned (create_socket_perms expands far beyond the evidenced new-device creation boundary): "+trimmed)
			case strings.Contains(trimmed, "class tun_socket "):
				if trimmed == "class tun_socket { create };" {
					tunSocketRequireDecls++
				} else {
					violations = append(violations, fmt.Sprintf("the require block's tun_socket declaration is exactly the one evidenced creation permission: %s", trimmed))
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, ":tun_socket"):
				if trimmed == "allow docker_helper_rootlesskit_t self:tun_socket create;" {
					rootlesskitTunSocketRules++
				} else {
					violations = append(violations, fmt.Sprintf("the tun_socket surface is exactly the rootlesskit child's single self-create rule (no attach_queue, no relabel*, no inherited socket permission, no other subject): %s", trimmed))
				}
			}
		}
		if tunSocketRequireDecls != 1 {
			violations = append(violations, fmt.Sprintf("the require block must declare tun_socket exactly once as { create } — found %d", tunSocketRequireDecls))
		}
		if rootlesskitTunSocketRules != 1 {
			violations = append(violations, fmt.Sprintf("the rootlesskit child domain must hold exactly one tun_socket rule — the evidenced self:tun_socket create grant — found %d", rootlesskitTunSocketRules))
		}
		return violations
	}
	if violations := tunSocketViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the tun-socket create invariants: %v", violations)
	}
	// Regressions: neither the require declaration nor the rule may lose
	// its evidenced shape.
	for _, regressed := range []struct {
		name string
		pin  string
	}{
		{"missing require create", "class tun_socket { create };"},
		{"missing allow create", "allow docker_helper_rootlesskit_t self:tun_socket create;"},
	} {
		mutated := strings.Replace(policy, regressed.pin, "", 1)
		if len(tunSocketViolations(mutated)) == 0 {
			t.Errorf("the tun-socket %q regression must trip the create invariant", regressed.name)
		}
	}
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"duplicate create rule", "allow docker_helper_rootlesskit_t self:tun_socket create;"},
		{"parallel create rule (braced form)", "allow docker_helper_rootlesskit_t self:tun_socket { create };"},
		{"widened attach_queue", "allow docker_helper_rootlesskit_t self:tun_socket attach_queue;"},
		{"widened relabelfrom", "allow docker_helper_rootlesskit_t self:tun_socket relabelfrom;"},
		{"widened relabelto", "allow docker_helper_rootlesskit_t self:tun_socket relabelto;"},
		{"distro create_socket_perms macro", "create_socket_perms(docker_helper_rootlesskit_t)"},
		{"widened require declaration", "class tun_socket { create attach_queue };"},
		{"tun_socket for the manager", "allow docker_helper_builder_t self:tun_socket create;"},
		{"tun_socket for the launcher", "allow docker_helper_builder_launcher_t self:tun_socket create;"},
		{"tun_socket for the network helper", "allow docker_helper_slirp4netns_t self:tun_socket create;"},
		{"tun_socket for the UID-map helper", "allow docker_helper_newuidmap_t self:tun_socket create;"},
		{"tun_socket for the GID-map helper", "allow docker_helper_newgidmap_t self:tun_socket create;"},
	} {
		if len(tunSocketViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the tun-socket create invariant", mut.name)
		}
	}
}

// TestSELinuxPolicyMCSMembership verifies the G32 r3 §6.A constrained
// membership: the managed-container domain (its own accepted boundary) and
// exactly the four flow-side domains are members of mcs_constrained_type
// (the G26 minimal set plus the G28-revised slirp4netns), and the trusted
// control planes / launch child stay OUT — their cross-category
// reachability is the measured escape mechanics the launch chain and the
// lifecycle depend on.
func TestSELinuxPolicyMCSMembership(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	want := []string{
		"docker_helper_container_t",
		"docker_helper_rootlesskit_t",
		"docker_helper_newuidmap_t",
		"docker_helper_newgidmap_t",
		"docker_helper_slirp4netns_t",
	}
	var members []string
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "typeattribute ") {
			continue
		}
		if !strings.HasSuffix(trimmed, " mcs_constrained_type;") {
			continue
		}
		members = append(members, strings.Fields(strings.TrimSuffix(trimmed, " mcs_constrained_type;"))[1])
	}
	if len(members) != len(want) {
		t.Errorf("exactly %d domains may be mcs_constrained_type members, found %d: %v", len(want), len(members), members)
	}
	for _, domain := range want {
		found := false
		for _, member := range members {
			if member == domain {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the flow-side domain must be a mcs_constrained_type member: %s", domain)
		}
	}
	for _, excluded := range []string{
		"docker_helper_t",
		"docker_helper_builder_t",
		"docker_helper_builder_launcher_t",
	} {
		for _, member := range members {
			if member == excluded {
				t.Errorf("the trusted control plane / launch child must NOT be mcs_constrained: %s", excluded)
			}
		}
	}
}

// TestSELinuxPolicyLauncherDomainSurface verifies the launcher domain is
// authority-free by construction: its only grants are the structural chain
// surface (its own entry file, the rootlesskit entry file's exec checks, its
// own setexec, and the two transitions) plus the two R2-live-evidence
// startup grants (execute on the shared entry image and the inherited
// inst.diag fifo write), it receives no grant toward any forbidden surface,
// and it is not an MCS member.
func TestSELinuxPolicyLauncherDomainSurface(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		target := allowTargetToken(trimmed, "allow docker_helper_builder_launcher_t ")
		if target == "" {
			continue
		}
		switch {
		case trimmed == "allow docker_helper_builder_launcher_t docker_helper_exec_t:file { entrypoint read open getattr map execute };",
			trimmed == "allow docker_helper_builder_launcher_t docker_helper_rootlesskit_exec_t:file { execute read open getattr };",
			// The launcher-stage mirror of the rootlesskit inst.diag contract
			// (R2 live evidence); exactly this rule and nothing else toward
			// the builder domain.
			trimmed == "allow docker_helper_builder_launcher_t docker_helper_builder_t:fifo_file { write };",
			// The structural chain's transitions (hop 2 lives here).
			trimmed == "allow docker_helper_builder_launcher_t docker_helper_rootlesskit_t:process { transition };":
			// The structural chain's entry/bprm/transition grants.
		case target == "self" && trimmed == "allow docker_helper_builder_launcher_t self:process { setexec };":
			// The launcher's own forced-context write (self rule).
		default:
			t.Errorf("unexpected launcher-domain grant (the launcher stays authority-free): %s", trimmed)
		}
	}
	// The launcher may complete the shared entry image's own mapping
	// startup (execute), but it must never exec the docker-helper binary
	// and REMAIN in the launcher domain: no execute_no_trans on the
	// docker-helper exec type.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "docker_helper_builder_launcher_t docker_helper_exec_t:file") &&
			strings.Contains(trimmed, "execute_no_trans") {
			t.Errorf("the launcher must not carry execute_no_trans on the shared binary (the only in-domain exec is the rootlesskit entry): %s", trimmed)
		}
	}
	// The launcher's only grant toward the builder domain is the inherited
	// diag pipe write: every launcher_t -> docker_helper_builder_t rule must
	// be exactly that fifo_file write.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "allow docker_helper_builder_launcher_t docker_helper_builder_t:") &&
			trimmed != "allow docker_helper_builder_launcher_t docker_helper_builder_t:fifo_file { write };" {
			t.Errorf("the launcher's builder-domain surface is exactly the diag fifo write: %s", trimmed)
		}
	}
	for _, forbidden := range forbiddenBuilderTargets {
		if strings.Contains(policy, "allow docker_helper_builder_launcher_t "+forbidden+":") {
			t.Errorf("the launcher domain must not receive a grant toward %s", forbidden)
		}
	}
	// The setexec authority is launcher-owned: exactly one self:process
	// setexec rule exists in the module and it names the launcher domain
	// (the manager must never gain setexec — its range never changes).
	setexecRules := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "self:process { setexec };") {
			setexecRules++
			if !strings.HasPrefix(trimmed, "allow docker_helper_builder_launcher_t self:process { setexec };") {
				t.Errorf("the setexec authority must stay launcher-owned: %s", trimmed)
			}
		}
	}
	if setexecRules != 1 {
		t.Errorf("exactly one setexec rule may exist (launcher-owned), found %d", setexecRules)
	}
}

// TestSELinuxPolicyBuilderSELinuxStatusRead pins the Phase 4B-R1
// correction: the manager's per-START MAC-backend detection
// (builderProvisionGate -> detectLSM -> selinuxEnabled -> the
// /sys/fs/selinux/enforce read; Phase 4B run 36598995674 live evidence,
// the manager's own EACCES diagnostic) carries exactly the daemon's
// proven grant shape — and the correction widens nothing: exactly one
// builder_t security_t rule exists in the module, and the launcher and
// the flow domain receive no security_t grant from it.
func TestSELinuxPolicyBuilderSELinuxStatusRead(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	want := "allow docker_helper_builder_t security_t:file { read open getattr };"
	if !strings.Contains(policy, want) {
		t.Errorf("the builder MAC-detection grant must be exact: %q", want)
	}
	found := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "allow docker_helper_builder_t security_t:") {
			found++
			if trimmed != want {
				t.Errorf("the builder security_t surface is exactly the status read; unexpected rule: %s", trimmed)
			}
		}
	}
	if found != 1 {
		t.Errorf("exactly one builder_t security_t rule may exist, found %d", found)
	}
	for _, subject := range []string{"docker_helper_builder_launcher_t", "docker_helper_rootlesskit_t"} {
		for _, line := range strings.Split(policy, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "allow "+subject+" security_t:") {
				t.Errorf("%s must receive no security_t grant from the MAC-detection correction: %s", subject, trimmed)
			}
		}
	}
}

// TestSELinuxPolicyBuilderRootTypes verifies the G32 r3 root split: the
// dedicated root types exist; the manager's root-level surface is exactly
// the roots' verify/ops-container/manager.sock operations; systemd's root
// mirrors exist; and the flow child gets exactly traversal (search) — no
// create/add_name/unlink on the root plane.
func TestSELinuxPolicyBuilderRootTypes(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, want := range []string{
		"type docker_helper_builder_state_root_t, file_type;",
		"type docker_helper_builder_runtime_root_t, file_type;",
		// The manager's root-level surface (rmdir covers the
		// pre-provisioning window: a per-op dir created before its relabel
		// inherits the root type and the manager's cleanup must remove it).
		"allow docker_helper_builder_t docker_helper_builder_runtime_root_t:dir { getattr search read open write add_name remove_name create rmdir };",
		"allow docker_helper_builder_t docker_helper_builder_runtime_root_t:sock_file { create getattr setattr unlink };",
		"allow docker_helper_builder_t docker_helper_builder_state_root_t:dir { getattr search read open write add_name remove_name create rmdir };",
		// systemd's root mirrors (the root dirs carry the unit directory
		// operations; the mounton grants were re-pointed by the split).
		"allow init_t docker_helper_builder_runtime_root_t:dir { create rmdir write remove_name setattr };",
		"allow init_t docker_helper_builder_state_root_t:dir { create rmdir write remove_name setattr };",
		"allow init_t docker_helper_builder_runtime_root_t:file { unlink };",
		"allow init_t docker_helper_builder_runtime_root_t:lnk_file { unlink };",
		"allow init_t docker_helper_builder_runtime_root_t:sock_file { unlink };",
		"allow init_t docker_helper_builder_state_root_t:file { unlink };",
		"allow init_t docker_helper_builder_state_root_t:lnk_file { unlink };",
		"allow init_t docker_helper_builder_runtime_root_t:dir { mounton };",
		"allow init_t docker_helper_builder_state_root_t:dir { mounton };",
		// The flow child's minimal traversal.
		"allow docker_helper_rootlesskit_t docker_helper_builder_state_root_t:dir { search };",
		"allow docker_helper_rootlesskit_t docker_helper_builder_runtime_root_t:dir { search };",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the root-split policy surface is missing: %q", want)
		}
	}
	// The flow child's root-plane surface stays traversal-only: every
	// rootlesskit_t rule toward a root type must carry exactly { search }.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t docker_helper_builder_") {
			continue
		}
		if !strings.Contains(trimmed, "_root_t:") {
			continue
		}
		if trimmed != "allow docker_helper_rootlesskit_t docker_helper_builder_state_root_t:dir { search };" &&
			trimmed != "allow docker_helper_rootlesskit_t docker_helper_builder_runtime_root_t:dir { search };" {
			t.Errorf("the flow child's root-plane surface must stay traversal-only: %s", trimmed)
		}
	}
}

// TestSELinuxPolicyBuilderContextFoundation verifies the context type is
// declared as the G32 r3 policy foundation: the type exists, NO fc rule
// assigns it (the Phase 5 runtime ingress relabel — type plus the
// operation's MCS category, after a successful START — is the only
// assignment owner; a broad fc pattern would pre-type the staging tree and
// widen the context grant surface), no access grant names it yet, and the
// daemon holds zero grants on the operation state type.
func TestSELinuxPolicyBuilderContextFoundation(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	if !strings.Contains(policy, "type docker_helper_builder_context_t, file_type;") {
		t.Error("SELinux policy must declare docker_helper_builder_context_t")
	}
	fc := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.fc")
	for _, line := range strings.Split(fc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "docker_helper_builder_context_t") {
			t.Errorf("the fc must not assign the context type (the Phase 5 runtime relabel owns the assignment): %s", trimmed)
		}
	}
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "docker_helper_builder_context_t:") {
			t.Errorf("no access grant may name the context type before the ingress implementation: %s", trimmed)
		}
		if strings.HasPrefix(trimmed, "allow docker_helper_t docker_helper_builder_state_t") {
			t.Errorf("the daemon must keep zero grants on the operation state type: %s", trimmed)
		}
	}
}

// TestSELinuxPolicyManagerFlowSignalVocabulary pins the launch/signal
// separation: any manager grant toward a flow-side process class must be
// the STOP-path signal vocabulary only, never a transition (the launch
// path is launcher-only). The signal grants themselves arrive with the
// payload-ledger phase (G28 manager control-plane rules); until then the
// invariant holds vacuously on the allow rules and structurally on the
// transitions.
func TestSELinuxPolicyManagerFlowSignalVocabulary(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, flowDomain := range []string{"docker_helper_rootlesskit_t", "docker_helper_slirp4netns_t", "docker_helper_newuidmap_t", "docker_helper_newgidmap_t"} {
			prefix := "allow docker_helper_builder_t " + flowDomain + ":process "
			if !strings.HasPrefix(trimmed, prefix) {
				continue
			}
			perms := strings.TrimSuffix(strings.TrimPrefix(trimmed, prefix), ";")
			for _, perm := range strings.Fields(strings.Trim(perms, "{} ")) {
				switch perm {
				case "sigkill", "signal", "signull":
					// STOP-path vocabulary.
				default:
					t.Errorf("manager grants toward a flow process must stay the STOP-path signal vocabulary: %s", trimmed)
				}
			}
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
//     NOT frozen here: its cap_userns surface is owned by the dedicated
//     cap_userns shape test, not by this helper-invariant owner.
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
	// The 4C-23 traversal grant exists exactly once per its triple; a
	// duplicate (even byte-identical) rule also violates.
	slirpTargetDirRules := 0
	for _, rule := range allows {
		if rule.source == "docker_helper_slirp4netns_t" && rule.target == "docker_helper_rootlesskit_t" && rule.class == "dir" {
			slirpTargetDirRules++
		}
	}
	if slirpTargetDirRules != 1 {
		violations = append(violations, fmt.Sprintf("exactly one dir-search grant may exist from the helper toward the rootlesskit namespace target, found %d", slirpTargetDirRules))
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
			// The 4C-23 namespace-target traversal invariant: the
			// helper's cross-domain DIR authority toward the rootlesskit
			// target is exactly the single search rule; any other dir
			// shape (widened perms, another target domain) is a widening.
			if rule.class == "dir" && rule.target != "docker_helper_rootlesskit_t" {
				violations = append(violations, fmt.Sprintf("the helper domain holds no dir authority toward any target other than the rootlesskit namespace target: allow %s %s:%s", rule.source, rule.target, rule.class))
			}
			// The namespace-path OPEN (file/lnk_file on the proc target)
			// is the NEXT live boundary; no pre-grant.
			if rule.target == "docker_helper_rootlesskit_t" && (rule.class == "file" || rule.class == "lnk_file") {
				violations = append(violations, fmt.Sprintf("the helper domain holds no file/lnk_file authority toward the rootlesskit namespace target (the /proc/<pid>/ns open is the next live boundary): allow %s %s:%s", rule.source, rule.target, rule.class))
			}
		}
		if rule.source == "docker_helper_rootlesskit_t" && rule.target == "docker_helper_slirp4netns_t" && rule.class == "dir" {
			violations = append(violations, fmt.Sprintf("no reversed proc-traversal direction (the target child gains no dir authority over the helper domain): allow %s %s:%s", rule.source, rule.target, rule.class))
		}
		if rule.target == "docker_helper_slirp4netns_t" && rule.class == "dir" {
			violations = append(violations, fmt.Sprintf("no proc-traversal authority into the helper domain's own proc tree from any subject: allow %s %s:%s", rule.source, rule.target, rule.class))
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
		"allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir search;",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("SELinux policy must contain exactly this rule: %s", want)
		}
	}
	if violations := helperDomainPolicyViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the helper-domain invariants: %v", violations)
	}
	// The 4C-23 namespace-target traversal: exactly ONE cross-domain dir
	// rule toward the rootlesskit target, in the exact searched-only
	// shape.
	pinnedDirRule := "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir search;"
	countPinnedDir := func(text string) int {
		n := 0
		for _, line := range strings.Split(text, "\n") {
			if strings.TrimSpace(line) == pinnedDirRule {
				n++
			}
		}
		return n
	}
	if countPinnedDir(policy) != 1 {
		t.Errorf("the helper's namespace-target traversal must be exactly one `dir search` rule toward the rootlesskit target, found %d", countPinnedDir(policy))
	}
	// Regression: the traversal rule must exist; removing it, or
	// replacing it with a search-less dir shape, must break the
	// exactly-one invariant the count guard asserts.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing traversal rule", ""},
		{"missing search (getattr-only shape)", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir getattr;"},
	} {
		mutated := strings.Replace(policy, pinnedDirRule, regressed.rule, 1)
		if countPinnedDir(mutated) == 1 {
			t.Errorf("the traversal regression %q was not applied", regressed.name)
		}
	}
	// Structural and widening mutations: appended or replacement rules
	// around the single traversal grant must trip.
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"duplicate identical traversal rule", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir search;"},
		{"parallel search rule (brace form)", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir { search };"},
		{"widened { search getattr }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir { search getattr };"},
		{"widened { search read }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir { search read };"},
		{"widened { search open }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir { search open };"},
		{"widened { search write }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir { search write };"},
		{"widened { search ioctl }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir { search ioctl };"},
		{"widened uid-map helper's dir shape copied to the network helper", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir { read open getattr search };"},
		{"wrong-target dir search toward the UID-map helper", "allow docker_helper_slirp4netns_t docker_helper_newuidmap_t:dir search;"},
		{"wrong-source reversed direction", "allow docker_helper_rootlesskit_t docker_helper_slirp4netns_t:dir search;"},
		{"wrong-source uid-map helper gains network-helper traversal", "allow docker_helper_newuidmap_t docker_helper_slirp4netns_t:dir search;"},
		{"namespace-path file pre-grant", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:file { read open };"},
		{"namespace-path lnk_file pre-grant", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:lnk_file { read };"},
	} {
		mutated := policy + "\n" + mut.rule
		violations := helperDomainPolicyViolations(mutated)
		if len(violations) == 0 {
			t.Errorf("mutation %q must fail the helper-domain invariants", mut.name)
		}
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
	// No bin_t execution grants for any builder-family domain.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, subject := range []string{"docker_helper_builder_t", "docker_helper_rootlesskit_t", "docker_helper_newuidmap_t", "docker_helper_newgidmap_t", "docker_helper_slirp4netns_t"} {
			target := allowTargetToken(trimmed, "allow "+subject+" ")
			if target == "bin_t" {
				t.Errorf("no bin_t grant for %s: %s", subject, trimmed)
			}
		}
	}
}

// TestSELinuxPolicyNewuidmapIsolation verifies the UID-map helper domain's
// isolation surface: no Docker socket, admin token, config/state/runtime,
// or Session workspace grants; no cap_userns rule beyond the one evidenced
// sys_admin grant and no plain capability surface beyond the one evidenced
// setuid grant; and no transition or allow rule pointing into the domain
// other than the pinned ones.
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
	// The module's cap_userns rules are EXACTLY the three evidenced grants:
	// the rootlesskit child's { sys_admin sys_ptrace sys_chroot net_admin }
	// set, the UID-map helper's sys_admin bit, and the GID-map helper's
	// sys_admin bit (all in-namespace, all self-targeted; the GID bit is
	// the R5 gid_map-write boundary, the child's sys_ptrace bit is the
	// 4C-3 nsenter ptrace_may_access boundary, its sys_chroot bit is the
	// 4C-4 mount-namespace reassociation boundary, and its net_admin bit
	// is the 4C-15 tun_set_iff() CAP_NET_ADMIN boundary). No other subject
	// — the manager, the launcher, slirp4netns, the daemon, or any other
	// helper — gets a cap_userns rule.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, ":cap_userns ") {
			switch trimmed {
			case "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin };",
				"allow docker_helper_newuidmap_t self:cap_userns sys_admin;",
				"allow docker_helper_newgidmap_t self:cap_userns sys_admin;":
			default:
				t.Errorf("no cap_userns grant may exist beyond the three evidenced in-namespace grants (rootlesskit { sys_admin sys_ptrace sys_chroot net_admin }, UID-map helper sys_admin, GID-map helper sys_admin): %s", trimmed)
			}
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
// grants (P5-S1 Tumbleweed runs 36229266623, 36248541393, and 36250310697
// P6 windows). Any additional or widened rule is a policy regression.
var newuidmapDomainSurface = []string{
	"allow docker_helper_newuidmap_t docker_helper_newuidmap_exec_t:file { entrypoint read open execute getattr map };",
	"allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:fifo_file { write };",
	"allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:dir { read open getattr search };",
	"allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:file { write open };",
	"allow docker_helper_newuidmap_t self:cap_userns sys_admin;",
	"allow docker_helper_newuidmap_t self:capability setuid;",
	"allow docker_helper_newuidmap_t passwd_file_t:file { read open };",
}

// newuidmapDomainPolicyViolations scans the module's parsed rules against
// the UID-map helper-domain surface invariants and returns one
// human-readable violation per broken rule, empty when none:
//   - the domain's allow-rule surface is EXACTLY newuidmapDomainSurface
//     (source-scoped, full-line equality, so widened permission sets and
//     extra grants both violate);
//   - the domain's plain self:capability surface is EXACTLY the evidenced
//     { setuid } bit (the uid_map write's out-of-namespace check; the
//     privilege owner stays the distro's chkstat-applied file caps), any
//     widening or additional bit violates, and every capability2 grant
//     violates; its cap_userns surface is exactly the evidenced
//     { sys_admin } in-namespace bit;
//   - the domain holds no grant toward any forbidden surface (same set as
//     the builder domain);
//   - the domain holds NO process-class grant toward
//     docker_helper_rootlesskit_t: the mem file's kernel
//     PTRACE_MODE_ATTACH check maps to process:ptrace between the
//     domains, and that barrier (signal/ptrace alike) stays closed — the
//     file-write grant must never be read as enabling memory writes.
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
			if strings.Contains(trimmed, ":capability2 ") {
				violations = append(violations, fmt.Sprintf("the UID-map helper domain must hold no capability2 grant: %s", trimmed))
			}
			if strings.Contains(trimmed, ":capability ") && trimmed != "allow docker_helper_newuidmap_t self:capability setuid;" {
				// The plain out-of-namespace surface is exactly the one
				// evidenced setuid bit (the uid_map write's kernel check,
				// enforcing run 36265505542 record 569); any widening or
				// additional capability bit is a violation.
				violations = append(violations, fmt.Sprintf("the UID-map helper domain's plain capability surface is exactly { setuid }: %s", trimmed))
			}
			// The in-namespace sys_admin bit is the one evidenced capability
			// surface (the uid_map write's cap_userns check, enforcing run
			// 36263531925 record 560); any other cap_userns permission —
			// including setuid — is a widening violation.
			if strings.Contains(trimmed, ":cap_userns ") && trimmed != "allow docker_helper_newuidmap_t self:cap_userns sys_admin;" {
				violations = append(violations, fmt.Sprintf("the UID-map helper domain's cap_userns surface is exactly { sys_admin }: %s", trimmed))
			}
		}
		if target, class, ok := strings.Cut(strings.TrimPrefix(trimmed, "allow docker_helper_newuidmap_t "), ":"); ok {
			class = strings.Fields(class)[0]
			// The helper's target allowlist: its own entry type, the
			// rootlesskit child domain (fifo/dir/file surface), the passwd
			// lookup file type, and the self-targets the surface scan
			// already pins. ANY other target type — daemon or builder trees,
			// the Docker socket, workspaces, or a sibling helper — is a
			// violation.
			switch target {
			case "docker_helper_newuidmap_exec_t", "docker_helper_rootlesskit_t", "passwd_file_t", "self":
			default:
				violations = append(violations, fmt.Sprintf("the UID-map helper domain must not receive a grant toward %s (unexpected target type): %s", target, trimmed))
			}
			if class == "process" && target == "docker_helper_rootlesskit_t" {
				violations = append(violations, fmt.Sprintf("the UID-map helper domain must hold no process-class grant toward the rootlesskit child domain (the mem file's ptrace barrier stays closed): %s", trimmed))
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
// rootlesskit child; dir { read open getattr search } on the
// /proc/<rootlesskit-pid> target of the uid_map write — the O_DIRECTORY
// open proven by run 36248541393, the target stat by run 36253390898, and
// the traversal by run 36256089858; passwd_file_t:file { read open } for
// the getpwuid caller lookup — the open(2) proven by run 36251483787)
// beside the entry rule — and nothing else. Mutation tests prove each
// guard fires: widened or regressed dir and passwd grants, extra
// dir/passwd permissions, capability/cap_userns widening or additional
// bits (only the evidenced setuid/sys_admin shapes are tolerated), and
// capability2 grants for the helper domain must trip the exact-surface
// invariant.
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
		{"widened proc-dir grant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:dir { read open getattr search write };", "unexpected rule"},
		{"regressed proc-dir search grant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:dir { read open getattr };", "unexpected rule"},
		{"widened uid_map file grant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:file { write open append };", "unexpected rule"},
		{"regressed uid_map file write grant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:file { open };", "unexpected rule"},
		{"regressed uid_map file open grant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:file { write };", "unexpected rule"},
		{"process ptrace toward the child domain", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:process ptrace;", "no process-class grant toward the rootlesskit child domain"},
		{"process signal toward the child domain", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:process signal;", "no process-class grant toward the rootlesskit child domain"},
		{"extra target type (builder state tree)", "allow docker_helper_newuidmap_t docker_helper_builder_state_t:file { write };", "unexpected target type"},
		{"widened passwd grant", "allow docker_helper_newuidmap_t passwd_file_t:file { read open getattr };", "unexpected rule"},
		{"extra passwd getattr grant", "allow docker_helper_newuidmap_t passwd_file_t:file { read getattr };", "unexpected rule"},
		{"regressed passwd open grant", "allow docker_helper_newuidmap_t passwd_file_t:file { read };", "unexpected rule"},
		{"widened helper cap_userns", "allow docker_helper_newuidmap_t self:cap_userns { sys_admin setuid };", "cap_userns surface is exactly"},
		{"extra helper cap_userns permission", "allow docker_helper_newuidmap_t self:cap_userns setuid;", "cap_userns surface is exactly"},
		{"widened helper setuid capability", "allow docker_helper_newuidmap_t self:capability { setuid sys_admin };", "plain capability surface is exactly"},
		{"extended helper setuid capability", "allow docker_helper_newuidmap_t self:capability { setuid dac_override };", "plain capability surface is exactly"},
		{"extra helper capability bit", "allow docker_helper_newuidmap_t self:capability sys_admin;", "plain capability surface is exactly"},
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

// TestSELinuxPolicyNewgidmapDomainTransition verifies the P5-S2 GID-map
// helper domain: the exec type and the domain exist, the transition is the
// ONLY path in (from the rootlesskit child over the newgidmap entry type),
// the source-side exec set matches the proven newuidmap shape, the entry
// rule carries the transition-required entrypoint plus the loader access,
// the fcontext rule labels exactly /usr/bin/newgidmap, and the manager may
// not exec newgidmap.
func TestSELinuxPolicyNewgidmapDomainTransition(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	fc := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.fc")
	for _, want := range []string{
		"type docker_helper_newgidmap_exec_t, file_type;",
		"type docker_helper_newgidmap_t, domain;",
		"role system_r types docker_helper_newgidmap_t;",
		"type_transition docker_helper_rootlesskit_t docker_helper_newgidmap_exec_t:process docker_helper_newgidmap_t;",
		"allow docker_helper_rootlesskit_t docker_helper_newgidmap_t:process { transition };",
		"allow docker_helper_rootlesskit_t docker_helper_newgidmap_exec_t:file { execute read open getattr };",
		"allow docker_helper_newgidmap_t docker_helper_newgidmap_exec_t:file { entrypoint read open execute getattr map };",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("SELinux policy must contain exactly this rule: %s", want)
		}
	}
	if !strings.Contains(fc, "/usr/bin/newgidmap                  --  system_u:object_r:docker_helper_newgidmap_exec_t:s0") {
		t.Error("file contexts must label /usr/bin/newgidmap with the dedicated exec type")
	}
	// The transition into the GID-map helper domain is the ONLY path in.
	_, transitions := parseSELinuxRules(policy)
	newgidTransitions := 0
	for _, tr := range transitions {
		if tr.dest != "docker_helper_newgidmap_t" {
			continue
		}
		newgidTransitions++
		if tr.source != "docker_helper_rootlesskit_t" || tr.entry != "docker_helper_newgidmap_exec_t" || tr.class != "process" {
			t.Errorf("the only transition into the GID-map helper domain is the rootlesskit child's exec of its entry type, got: type_transition %s %s:%s %s", tr.source, tr.entry, tr.class, tr.dest)
		}
	}
	if newgidTransitions != 1 {
		t.Errorf("exactly one transition may enter the GID-map helper domain, found %d", newgidTransitions)
	}
	// The manager must not gain the right to execute newgidmap.
	if strings.Contains(policy, "allow docker_helper_builder_t docker_helper_newgidmap_exec_t") {
		t.Error("the manager domain must not be able to execute newgidmap")
	}
	// No bin_t execution grants for any builder-family domain.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, subject := range []string{"docker_helper_builder_t", "docker_helper_rootlesskit_t", "docker_helper_newuidmap_t", "docker_helper_newgidmap_t", "docker_helper_slirp4netns_t"} {
			target := allowTargetToken(trimmed, "allow "+subject+" ")
			if target == "bin_t" {
				t.Errorf("no bin_t grant for %s: %s", subject, trimmed)
			}
		}
	}
}

// newgidmapDomainSurface is the EXACT allow-rule surface of the GID-map
// helper domain: the entry/loader rule plus the six live-AVC-evidenced
// runtime grants (the inherited-stdio fifo write, the /proc
// target-directory read-open-getattr-search, the gid_map file write-open,
// the getpwuid passwd read-open, the in-namespace sys_admin cap_userns
// bit — the R5 gid_map write's capability boundary — and the
// out-of-namespace setgid capability bit — the 4C-1 run's next boundary).
// The domain holds NO other capability surface: no userdb fallback, no
// passwd getattr, no file read/append, no setuid, no capability2 (the
// privilege model otherwise stays the distro's chkstat-applied cap_setgid
// file capability). Any additional or widened rule is a policy regression.
var newgidmapDomainSurface = []string{
	"allow docker_helper_newgidmap_t docker_helper_newgidmap_exec_t:file { entrypoint read open execute getattr map };",
	"allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:fifo_file { write };",
	"allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:dir { read open getattr search };",
	"allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:file { write open };",
	"allow docker_helper_newgidmap_t passwd_file_t:file { read open };",
	"allow docker_helper_newgidmap_t self:cap_userns sys_admin;",
	"allow docker_helper_newgidmap_t self:capability setgid;",
}

// newgidmapDomainPolicyViolations scans the module's parsed rules against
// the GID-map helper-domain invariants and returns one human-readable
// violation per broken rule, empty when none:
//   - the domain's allow-rule surface is EXACTLY newgidmapDomainSurface
//     (source-scoped, full-line equality, so widened permission sets and
//     extra grants both violate);
//   - the domain's only self-targeted grants are the evidenced
//     self:cap_userns sys_admin bit and the self:capability setgid bit
//     (any other self-targeted rule — setuid, a widened set, capability2,
//     or another cap_userns shape — violates);
//   - the domain's only runtime grants toward docker_helper_rootlesskit_t
//     are the inherited-stdio fifo { write }, the /proc target-dir
//     { read open getattr search }, and the gid_map file { write open }
//     rules; any other shape toward the child (the file read/append/
//     getattr/setattr surfaces) and ANY process-class grant (the mem
//     file's kernel PTRACE_MODE_ATTACH check maps to process:ptrace —
//     signal/ptrace alike) violate; every other target type except the
//     passwd lookup file (the passwd_file_t:file { read open } rule is
//     the one evidenced grant) is a violation (daemon/Docker/workspace/
//     state surfaces by construction);
//   - the ONLY transition into the domain is the rootlesskit child's exec
//     of the newgidmap entry type (duplicates, manager-side or daemon-side
//     entries violate), and the manager holds no exec grant for the
//     newgidmap entry type.
func newgidmapDomainPolicyViolations(policy string) []string {
	var violations []string
	seen := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "allow docker_helper_newgidmap_t ") {
			seen++
			matched := false
			for _, want := range newgidmapDomainSurface {
				if trimmed == want {
					matched = true
					break
				}
			}
			if !matched {
				violations = append(violations, fmt.Sprintf("the GID-map helper domain's surface is exact; unexpected rule: %s", trimmed))
			}
			if strings.HasPrefix(trimmed, "allow docker_helper_newgidmap_t self:") {
				if trimmed != "allow docker_helper_newgidmap_t self:cap_userns sys_admin;" &&
					trimmed != "allow docker_helper_newgidmap_t self:capability setgid;" {
					violations = append(violations, fmt.Sprintf("the GID-map helper domain's only self-targeted grants are the evidenced cap_userns sys_admin bit and the capability setgid bit (no setuid, no widened sets, no capability2): %s", trimmed))
				}
			}
			if target, class, ok := strings.Cut(strings.TrimPrefix(trimmed, "allow docker_helper_newgidmap_t "), ":"); ok {
				class = strings.Fields(class)[0]
				switch target {
				case "docker_helper_newgidmap_exec_t", "self", "docker_helper_rootlesskit_t", "passwd_file_t":
				default:
					violations = append(violations, fmt.Sprintf("the GID-map helper domain must not receive a grant toward %s (unexpected target type): %s", target, trimmed))
				}
				if target == "docker_helper_rootlesskit_t" {
					if class == "process" {
						violations = append(violations, fmt.Sprintf("the GID-map helper domain must hold no process-class grant toward the rootlesskit child domain (the mem file's ptrace barrier stays closed): %s", trimmed))
					} else if trimmed != "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:fifo_file { write };" &&
						trimmed != "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:dir { read open getattr search };" &&
						trimmed != "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:file { write open };" {
						violations = append(violations, fmt.Sprintf("the GID-map helper domain's rootlesskit-child surface is exactly the inherited-stdio fifo { write }, the /proc target-dir { read open getattr search }, and the gid_map file { write open } (the file read/append/getattr/setattr surfaces stay ungranted): %s", trimmed))
					}
				}
			}
		}
		// The manager may not execute the GID-map helper binary (the entry
		// transition is child-domain-only; the daemon's own exec of the
		// shared binary never touches this entry type).
		if strings.HasPrefix(trimmed, "allow docker_helper_builder_t docker_helper_newgidmap_exec_t") {
			violations = append(violations, fmt.Sprintf("the manager domain must not be able to execute newgidmap: %s", trimmed))
		}
	}
	if seen != len(newgidmapDomainSurface) {
		violations = append(violations, fmt.Sprintf("the GID-map helper domain's surface must carry exactly %d allow rule, found %d", len(newgidmapDomainSurface), seen))
	}
	_, transitions := parseSELinuxRules(policy)
	for _, tr := range transitions {
		if tr.dest != "docker_helper_newgidmap_t" {
			continue
		}
		if tr.source != "docker_helper_rootlesskit_t" || tr.entry != "docker_helper_newgidmap_exec_t" || tr.class != "process" {
			violations = append(violations, fmt.Sprintf("the only transition into the GID-map helper domain is the rootlesskit child's exec of its entry type, got: type_transition %s %s:%s %s", tr.source, tr.entry, tr.class, tr.dest))
		}
	}
	newgidTransitions := 0
	for _, tr := range transitions {
		if tr.dest == "docker_helper_newgidmap_t" {
			newgidTransitions++
		}
	}
	if newgidTransitions != 1 {
		violations = append(violations, fmt.Sprintf("exactly one transition may enter the GID-map helper domain, found %d", newgidTransitions))
	}
	return violations
}

// TestSELinuxPolicyNewgidmapDomainSurface verifies the GID-map helper
// domain's runtime surface is EXACTLY the entry rule plus the five
// evidenced runtime grants (the inherited-stdio fifo write, the /proc
// target-dir read-open-getattr-search, the gid_map file write-open, the
// getpwuid passwd read-open, and the in-namespace sys_admin cap_userns
// bit) and nothing else — no userdb fallback, no passwd getattr, no file
// read/append, no plain capability/capability2 rule. Mutation tests
// prove each guard fires: extra entry paths (a manager-side transition, a
// duplicate transition, a manager exec grant), the passwd read/open
// regressions, the passwd grant's removal and its getattr extension, the
// userdb fallback shapes (the systemd-var-run dir search and the self
// unix dgram socket), the dir read/open/getattr/search regressions and
// the dir grant's removal, the dir surface widening, the gid_map file
// grant's narrowing (each perm dropped), removal and widening, the fifo
// widening/removal, forbidden surfaces (builder state, daemon runtime,
// Docker socket, workspace), widened entry sets, process ptrace/signal
// toward the child, and any self-targeted grant beyond the two evidenced
// bits (a setuid capability, a widened setgid set, an extra capability
// bit, a widened/extra cap_userns shape, a duplicate identical rule, a
// capability2 grant) must trip the invariants.
func TestSELinuxPolicyNewgidmapDomainSurface(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	if violations := newgidmapDomainPolicyViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the GID-map helper surface invariants: %v", violations)
	}
	for _, want := range newgidmapDomainSurface {
		if !strings.Contains(policy, want) {
			t.Errorf("SELinux policy must contain exactly this rule: %s", want)
		}
	}
	for _, mut := range []struct {
		name        string
		rule        string
		removeRule  string
		wantTripped string
	}{
		{"manager-side transition into the domain", "type_transition docker_helper_builder_t docker_helper_newgidmap_exec_t:process docker_helper_newgidmap_t;", "", "the only transition into the GID-map helper domain"},
		{"duplicate identical transition", "type_transition docker_helper_rootlesskit_t docker_helper_newgidmap_exec_t:process docker_helper_newgidmap_t;", "", "exactly one transition may enter the GID-map helper domain"},
		{"manager exec of the helper binary", "allow docker_helper_builder_t docker_helper_newgidmap_exec_t:file { execute read open };", "", "the manager domain must not be able to execute newgidmap"},
		{"widened entry rule", "allow docker_helper_newgidmap_t docker_helper_newgidmap_exec_t:file { entrypoint read open execute getattr map append };", "", "unexpected rule"},
		{"regressed entry map permission", "allow docker_helper_newgidmap_t docker_helper_newgidmap_exec_t:file { entrypoint read open execute getattr };", "", "unexpected rule"},
		{"widened fifo grant (getattr added)", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:fifo_file { write getattr };", "", "rootlesskit-child surface is exactly"},
		{"widened fifo grant (append added)", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:fifo_file { write append };", "", "rootlesskit-child surface is exactly"},
		{"removed fifo grant", "", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:fifo_file { write };\n", "must carry exactly 7 allow rule"},
		{"regressed proc-dir read grant", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:dir { open getattr search };", "", "rootlesskit-child surface is exactly"},
		{"regressed proc-dir open grant", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:dir { read getattr search };", "", "rootlesskit-child surface is exactly"},
		{"regressed proc-dir getattr grant", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:dir { read open search };", "", "rootlesskit-child surface is exactly"},
		{"regressed proc-dir search grant", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:dir { read open getattr };", "", "rootlesskit-child surface is exactly"},
		{"removed proc-dir grant", "", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:dir { read open getattr search };\n", "must carry exactly 7 allow rule"},
		{"widened proc-dir grant", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:dir { read open getattr search write };", "", "rootlesskit-child surface is exactly"},
		{"regressed gid_map file grant (open dropped)", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:file { write };", "", "rootlesskit-child surface is exactly"},
		{"regressed gid_map file grant (write dropped)", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:file { open };", "", "rootlesskit-child surface is exactly"},
		{"removed gid_map file grant", "", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:file { write open };\n", "must carry exactly 7 allow rule"},
		{"widened gid_map file grant (append added)", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:file { write open append };", "", "rootlesskit-child surface is exactly"},
		{"widened gid_map file grant (getattr added)", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:file { write open getattr };", "", "rootlesskit-child surface is exactly"},
		{"process ptrace toward the child domain", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:process ptrace;", "", "no process-class grant toward the rootlesskit child domain"},
		{"process signal toward the child domain", "allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:process signal;", "", "no process-class grant toward the rootlesskit child domain"},
		{"regressed passwd read grant", "allow docker_helper_newgidmap_t passwd_file_t:file { read };", "", "unexpected rule"},
		{"regressed passwd open grant", "allow docker_helper_newgidmap_t passwd_file_t:file { open };", "", "unexpected rule"},
		{"widened passwd grant (getattr added)", "allow docker_helper_newgidmap_t passwd_file_t:file { read open getattr };", "", "unexpected rule"},
		{"removed passwd grant", "", "allow docker_helper_newgidmap_t passwd_file_t:file { read open };\n", "must carry exactly 7 allow rule"},
		{"userdb fallback dir search", "allow docker_helper_newgidmap_t init_var_run_t:dir { search };", "", "unexpected target type"},
		{"userdb fallback unix_dgram_socket", "allow docker_helper_newgidmap_t self:unix_dgram_socket { create };", "", "only self-targeted grants"},
		{"builder state tree", "allow docker_helper_newgidmap_t docker_helper_builder_state_t:file { write };", "", "unexpected target type"},
		{"daemon runtime tree", "allow docker_helper_newgidmap_t docker_helper_runtime_t:file { read };", "", "unexpected target type"},
		{"Docker socket", "allow docker_helper_newgidmap_t container_var_run_t:sock_file { write };", "", "unexpected target type"},
		{"Session workspace", "allow docker_helper_newgidmap_t docker_helper_workspace_t:file { read };", "", "unexpected target type"},
		{"setuid capability", "allow docker_helper_newgidmap_t self:capability setuid;", "", "only self-targeted grants"},
		{"widened setgid capability set", "allow docker_helper_newgidmap_t self:capability { setgid setuid };", "", "only self-targeted grants"},
		{"extra capability bit", "allow docker_helper_newgidmap_t self:capability dac_override;", "", "only self-targeted grants"},
		{"duplicate setgid capability", "allow docker_helper_newgidmap_t self:capability setgid;", "", "must carry exactly 7 allow rule"},
		{"widened cap_userns grant", "allow docker_helper_newgidmap_t self:cap_userns { sys_admin setuid };", "", "surface is exact"},
		{"extra cap_userns permission", "allow docker_helper_newgidmap_t self:cap_userns setuid;", "", "surface is exact"},
		{"duplicate cap_userns grant", "allow docker_helper_newgidmap_t self:cap_userns sys_admin;", "", "must carry exactly 7 allow rule"},
		{"capability2 grant", "allow docker_helper_newgidmap_t self:capability2 kill;", "", "only self-targeted grants"},
	} {
		var mutated string
		if mut.removeRule != "" {
			mutated = strings.Replace(policy, mut.removeRule, "", 1)
		} else {
			mutated = policy + "\n" + mut.rule
		}
		violations := newgidmapDomainPolicyViolations(mutated)
		if len(violations) == 0 {
			t.Errorf("mutation %q must fail the GID-map helper surface invariants", mut.name)
			continue
		}
		joined := strings.Join(violations, "\n")
		if !strings.Contains(joined, mut.wantTripped) {
			t.Errorf("mutation %q must trip the invariant naming %q, got violations: %v", mut.name, mut.wantTripped, violations)
		}
	}
}

// TestSELinuxPolicyCapUsernsShape verifies the global capability-shape
// invariant: the module carries EXACTLY THREE cap_userns rules — the
// rootlesskit child domain's evidenced
// { sys_admin sys_ptrace sys_chroot net_admin } set (the P5-S1 userns
// re-exec boundary, the 4C-3 nsenter ptrace_may_access boundary, the 4C-4
// mount-namespace reassociation boundary of the composite setns, and the
// 4C-15 tun_set_iff() in-namespace CAP_NET_ADMIN boundary), the UID-map
// helper domain's evidenced sys_admin bit (the uid_map write's in-namespace
// check), and the GID-map helper domain's evidenced sys_admin bit (the
// gid_map write's in-namespace check, the 4C-1 boundary) — with the require
// block declaring exactly { sys_admin sys_ptrace sys_chroot net_admin } on
// cap_userns. EXACTLY TWO plain self:capability rules: the UID-map helper's
// evidenced setuid (the uid_map write's out-of-namespace check) and the
// GID-map helper's evidenced setgid (the gid_map write's out-of-namespace
// check, the 4C-1 boundary). The manager, the launcher, the slirp4netns
// helper, and every other subject hold no cap_userns rules; the rootlesskit
// child keeps exactly one cap_userns rule (no duplicate/parallel rule) and
// a zero plain self:capability surface — plain CAP_SYS_PTRACE, plain
// CAP_SYS_CHROOT, plain CAP_NET_ADMIN, and plain CAP_NET_RAW in particular
// stay closed because the live AVCs name cap_userns, not capability; the
// net_admin bit is the in-namespace network-administration authority the
// 4C-15 live cap_userns boundary proved (materially broader than
// tap-creation — the cross-operation c1-vs-c2 namespace-authority proof
// stays mandatory); newuidmap keeps exactly setuid (no setgid, no
// sys_ptrace, no sys_chroot, no net_admin) and newgidmap keeps exactly
// setgid (no setuid, no sys_ptrace, no sys_chroot, no net_admin); all three
// subjects keep zero self:capability2 surfaces; and the module carries no
// process:ptrace grant and no capability2 grant at all, while the
// rootlesskit child domain stays an mcs_constrained_type member. Mutations
// prove the carve-out is narrow: any capability-class grant for the
// rootlesskit child, a setgid grant for the UID-map helper, a setuid grant
// for the GID-map helper, widened/extra helper capability sets, helper
// capability2 grants, duplicate/parallel rootlesskit cap_userns rules, the
// missing-bit regressions (sys_admin/sys_ptrace/sys_chroot/net_admin), any
// additional cap_userns bit (net_raw/sys_module/sys_boot/sys_time/
// sys_resource/setuid/setgid), a widened require declaration,
// process:ptrace grants, and cap_userns grants for the control-plane
// subjects all trip.
func TestSELinuxPolicyCapUsernsShape(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	// capUsernsShapeViolations returns one violation per line of text that
	// breaks the shape invariant: a cap_userns rule beyond the three
	// evidenced grants, a cap_userns require declaration beyond the three
	// evidenced bits, a plain capability grant that is not one of the two
	// helpers' single evidenced bits (setuid for the UID-map helper, setgid
	// for the GID-map helper; the rootlesskit child keeps zero), any
	// capability2 or process:ptrace grant, and a rootlesskit cap_userns
	// rule count other than exactly one.
	capUsernsShapeViolations := func(text string) []string {
		var violations []string
		rootlesskitCapUsernsRules := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			switch {
			case strings.Contains(trimmed, "class cap_userns "):
				if trimmed != "class cap_userns { sys_admin sys_ptrace sys_chroot net_admin };" {
					violations = append(violations, fmt.Sprintf("the require block's cap_userns declaration is exactly the four evidenced in-namespace bits: %s", trimmed))
				}
			case strings.Contains(trimmed, ":cap_userns "):
				switch trimmed {
				case "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin };":
					rootlesskitCapUsernsRules++
				case "allow docker_helper_newuidmap_t self:cap_userns sys_admin;",
					"allow docker_helper_newgidmap_t self:cap_userns sys_admin;":
				default:
					violations = append(violations, fmt.Sprintf("no cap_userns rule may exist beyond the three evidenced in-namespace grants (rootlesskit { sys_admin sys_ptrace sys_chroot net_admin }, newuidmap sys_admin, newgidmap sys_admin; the manager, the launcher, slirp4netns, and other subjects get none): %s", trimmed))
				}
			case strings.Contains(trimmed, ":capability ") && strings.Contains(trimmed, "docker_helper_rootlesskit_t"):
				violations = append(violations, fmt.Sprintf("the rootlesskit child domain must keep zero plain self:capability surfaces (no plain sys_ptrace/sys_chroot: the live AVCs name cap_userns): %s", trimmed))
			case strings.Contains(trimmed, ":capability ") && strings.Contains(trimmed, "docker_helper_newgidmap_t") && trimmed != "allow docker_helper_newgidmap_t self:capability setgid;":
				violations = append(violations, fmt.Sprintf("the GID-map helper's only plain capability grant is the evidenced setgid bit (no setuid, no sys_ptrace, no sys_chroot, no widened sets): %s", trimmed))
			case strings.Contains(trimmed, ":capability ") && strings.Contains(trimmed, "docker_helper_newuidmap_t") && trimmed != "allow docker_helper_newuidmap_t self:capability setuid;":
				violations = append(violations, fmt.Sprintf("the UID-map helper's only plain capability grant is the evidenced setuid bit (no setgid, no sys_ptrace, no sys_chroot, no widened sets): %s", trimmed))
			case strings.Contains(trimmed, ":capability2 ") && strings.HasPrefix(trimmed, "allow "):
				violations = append(violations, fmt.Sprintf("no capability2 grant may exist (the capability2 surface stays unchanged): %s", trimmed))
			case strings.Contains(trimmed, ":process ") && strings.Contains(trimmed, "ptrace"):
				violations = append(violations, fmt.Sprintf("no process:ptrace grant may exist: %s", trimmed))
			}
		}
		if rootlesskitCapUsernsRules != 1 {
			violations = append(violations, fmt.Sprintf("the rootlesskit child domain must hold exactly one cap_userns rule — the evidenced { sys_admin sys_ptrace sys_chroot net_admin } set — found %d", rootlesskitCapUsernsRules))
		}
		return violations
	}
	if violations := capUsernsShapeViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the cap_userns/capability shape invariants: %v", violations)
	}
	for _, rule := range []string{
		"class cap_userns { sys_admin sys_ptrace sys_chroot net_admin };",
		"allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin };",
		"allow docker_helper_newuidmap_t self:cap_userns sys_admin;",
		"allow docker_helper_newgidmap_t self:cap_userns sys_admin;",
		"allow docker_helper_newuidmap_t self:capability setuid;",
		"allow docker_helper_newgidmap_t self:capability setgid;",
		"typeattribute docker_helper_rootlesskit_t mcs_constrained_type;",
	} {
		if !strings.Contains(policy, rule) {
			t.Errorf("the evidenced capability grant must be present: %q", rule)
		}
	}
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"setuid capability for the rootlesskit child", "allow docker_helper_rootlesskit_t self:capability setuid;"},
		{"plain sys_admin capability for the rootlesskit child", "allow docker_helper_rootlesskit_t self:capability sys_admin;"},
		{"plain sys_ptrace capability for the rootlesskit child", "allow docker_helper_rootlesskit_t self:capability sys_ptrace;"},
		{"plain sys_chroot capability for the rootlesskit child", "allow docker_helper_rootlesskit_t self:capability sys_chroot;"},
		{"plain capability net_admin for the rootlesskit child", "allow docker_helper_rootlesskit_t self:capability net_admin;"},
		{"plain capability net_raw for the rootlesskit child", "allow docker_helper_rootlesskit_t self:capability net_raw;"},
		{"widened rootlesskit cap_userns +net_raw", "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin net_raw };"},
		{"widened rootlesskit cap_userns +sys_module", "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin sys_module };"},
		{"widened rootlesskit cap_userns +sys_boot", "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin sys_boot };"},
		{"widened rootlesskit cap_userns +sys_time", "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin sys_time };"},
		{"widened rootlesskit cap_userns +sys_resource", "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin sys_resource };"},
		{"widened rootlesskit cap_userns +setuid", "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin setuid };"},
		{"widened rootlesskit cap_userns +setgid", "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin setgid };"},
		{"duplicate rootlesskit cap_userns rule", "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin };"},
		{"parallel rootlesskit cap_userns net_admin rule", "allow docker_helper_rootlesskit_t self:cap_userns net_admin;"},
		{"parallel rootlesskit cap_userns rule", "allow docker_helper_rootlesskit_t self:cap_userns sys_chroot;"},
		{"net_admin cap_userns for the UID-map helper", "allow docker_helper_newuidmap_t self:cap_userns net_admin;"},
		{"net_admin cap_userns for the GID-map helper", "allow docker_helper_newgidmap_t self:cap_userns net_admin;"},
		{"net_admin cap_userns for the manager", "allow docker_helper_builder_t self:cap_userns net_admin;"},
		{"net_admin cap_userns for the launcher", "allow docker_helper_builder_launcher_t self:cap_userns net_admin;"},
		{"net_admin cap_userns for slirp4netns", "allow docker_helper_slirp4netns_t self:cap_userns net_admin;"},
		{"sys_chroot cap_userns for the UID-map helper", "allow docker_helper_newuidmap_t self:cap_userns sys_chroot;"},
		{"sys_chroot cap_userns for the GID-map helper", "allow docker_helper_newgidmap_t self:cap_userns sys_chroot;"},
		{"sys_ptrace cap_userns for the UID-map helper", "allow docker_helper_newuidmap_t self:cap_userns sys_ptrace;"},
		{"sys_ptrace cap_userns for the GID-map helper", "allow docker_helper_newgidmap_t self:cap_userns sys_ptrace;"},
		{"sys_chroot cap_userns for the manager", "allow docker_helper_builder_t self:cap_userns sys_chroot;"},
		{"sys_chroot cap_userns for the launcher", "allow docker_helper_builder_launcher_t self:cap_userns sys_chroot;"},
		{"sys_chroot cap_userns for slirp4netns", "allow docker_helper_slirp4netns_t self:cap_userns sys_chroot;"},
		{"sys_ptrace cap_userns for the manager", "allow docker_helper_builder_t self:cap_userns sys_ptrace;"},
		{"sys_ptrace cap_userns for the launcher", "allow docker_helper_builder_launcher_t self:cap_userns sys_ptrace;"},
		{"sys_ptrace cap_userns for slirp4netns", "allow docker_helper_slirp4netns_t self:cap_userns sys_ptrace;"},
		{"setgid capability for the UID-map helper", "allow docker_helper_newuidmap_t self:capability setgid;"},
		{"widened UID-map helper capability set", "allow docker_helper_newuidmap_t self:capability { setuid setgid };"},
		{"additional UID-map helper capability bit", "allow docker_helper_newuidmap_t self:capability dac_override;"},
		{"setuid capability for the GID-map helper", "allow docker_helper_newgidmap_t self:capability setuid;"},
		{"widened GID-map helper capability set", "allow docker_helper_newgidmap_t self:capability { setgid setuid };"},
		{"process ptrace grant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:process ptrace;"},
		{"widened cap_userns require declaration", "class cap_userns { sys_admin sys_ptrace sys_chroot net_admin net_raw };"},
		{"capability2 for the UID-map helper", "allow docker_helper_newuidmap_t self:capability2 kill;"},
		{"capability2 for the GID-map helper", "allow docker_helper_newgidmap_t self:capability2 kill;"},
		{"cap_userns for the manager", "allow docker_helper_builder_t self:cap_userns sys_admin;"},
		{"cap_userns for the launcher", "allow docker_helper_builder_launcher_t self:cap_userns sys_admin;"},
		{"cap_userns for slirp4netns", "allow docker_helper_slirp4netns_t self:cap_userns sys_admin;"},
	} {
		if violations := capUsernsShapeViolations(policy + "\n" + mut.rule); len(violations) == 0 {
			t.Errorf("mutation %q must fail the cap_userns/capability shape invariant", mut.name)
		}
	}
	// The missing-bit regressions (the pre-4C-4/pre-4C-5 shapes and the
	// pre-4C-15 shape) must fail the shape invariant: no shortened set is
	// the evidenced four-bit grant.
	for _, regressed := range []struct {
		name    string
		oldRule string
	}{
		{"missing sys_admin", "allow docker_helper_rootlesskit_t self:cap_userns { sys_ptrace sys_chroot net_admin };"},
		{"missing sys_ptrace", "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_chroot net_admin };"},
		{"missing sys_chroot", "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace net_admin };"},
		{"missing net_admin (the pre-4C-15 shape must trip again)", "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot };"},
	} {
		mutated := strings.Replace(policy,
			"allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin };",
			regressed.oldRule, 1)
		if violations := capUsernsShapeViolations(mutated); len(violations) == 0 {
			t.Errorf("the %q rootlesskit cap_userns shape must fail the shape invariant", regressed.name)
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
// builder domain is denied), carries no plain capability grants, and — for
// both the manager and the child — holds no bin_t:file grant: the helper
// execs run through their dedicated exec types only (slirp4netns,
// newuidmap, newgidmap) and the bundled buildkitd stays a deliberate
// P5-S2 boundary.
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
// with the G32 r3 split geometry: the tree roots AND the shared ops
// containers carry the dedicated root types, ONLY the children of ops/ carry
// the per-op tree types, and the shared binary keeps docker_helper_exec_t
// (the unit's SELinuxContext= binding never needs a second binary label).
func TestSELinuxFCBuilderTrees(t *testing.T) {
	fc := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.fc")
	for _, want := range []string{
		"/var/lib/docker-helper-builder/ops/.*   system_u:object_r:docker_helper_builder_state_t:s0",
		"/var/lib/docker-helper-builder(/.*)?    system_u:object_r:docker_helper_builder_state_root_t:s0",
		"/run/docker-helper-builder/ops/.*       system_u:object_r:docker_helper_builder_runtime_t:s0",
		"/run/docker-helper-builder(/.*)?        system_u:object_r:docker_helper_builder_runtime_root_t:s0",
		"/usr/bin/rootlesskit                --  system_u:object_r:docker_helper_rootlesskit_exec_t:s0",
		"/usr/bin/nsenter                    --  system_u:object_r:docker_helper_nsenter_exec_t:s0",
	} {
		if !strings.Contains(fc, want) {
			t.Errorf("file contexts must carry the builder rule: %q", want)
		}
	}
	// The nsenter file-context rule binds exactly the verified packaged
	// path (the 4C-3 stand probe: Tumbleweed ships nsenter only at
	// /usr/bin/nsenter): no wildcard, no alias form.
	nsenterFcLines := 0
	for _, line := range strings.Split(fc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.Contains(trimmed, "docker_helper_nsenter_exec_t") {
			continue
		}
		nsenterFcLines++
		pattern := strings.Fields(trimmed)[0]
		if pattern != "/usr/bin/nsenter" {
			t.Errorf("the nsenter fc rule must bind exactly the verified packaged path, no wildcard: %s", trimmed)
		}
	}
	if nsenterFcLines != 1 {
		t.Errorf("exactly one nsenter fc rule must exist, found %d", nsenterFcLines)
	}
	// The shared binary keeps its single daemon-exec label.
	if !strings.Contains(fc, "/usr/bin/docker-helper              --  system_u:object_r:docker_helper_exec_t:s0") {
		t.Error("the shared binary must stay labeled docker_helper_exec_t")
	}
	// The per-op regex must require the /ops/ literal prefix: a bare
	// ops(/.*)? form would match the SHARED ops container and hand the flow
	// child create/add_name on it (the G32 r2 geometry bug; regression for
	// the shared container).
	for _, line := range strings.Split(fc, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "docker-helper-builder/ops") {
			continue
		}
		pattern := strings.Fields(trimmed)[0]
		if strings.Contains(pattern, "/ops(/.*)") || !strings.Contains(pattern, "/ops/") {
			t.Errorf("the per-op fc pattern must match children of ops only (require the /ops/ prefix): %s", pattern)
		}
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

// TestSELinuxFCFirstMatchShape evaluates the shipped .fc rules over the
// representative path shapes of the G32 r3 geometry: roots and shared ops
// containers land on the root types, per-op children land on the per-op
// tree types, the daemon's ordinary staging tree keeps the pre-existing
// daemon runtime type (the context type is assigned by the Phase 5 runtime
// ingress relabel, never by fc), and foreign paths are untouched. The
// evaluation models the real file-context ranking (libselinux selabel_file:
// exact non-meta rules first, then regex rules by longest literal stem,
// file order within a stem) — a naive file-order first match is NOT the
// real semantics (the shipped trusted-ca rule outranks the generic daemon
// runtime rule by stem length). This is the static/textual shape gate; the
// real loaded-policy lookup (matchpathcon/selabel_lookup) stays the VM
// implementation gate (G32 r3 §9.5).
func TestSELinuxFCFirstMatchShape(t *testing.T) {
	fc := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.fc")
	type fcRule struct {
		pattern  string
		fileType string
		stem     string // literal prefix up to the first regex metacharacter
		exact    bool   // no metacharacters: exact-match rule
	}
	parse := func(pattern string) fcRule {
		stem := pattern
		for i, r := range stem {
			if strings.ContainsRune(`.+?[]()|^$\`, r) {
				stem = stem[:i]
				break
			}
		}
		return fcRule{
			pattern:  pattern,
			stem:     stem,
			exact:    stem == pattern,
			fileType: "",
		}
	}
	var rules []fcRule
	for _, line := range strings.Split(fc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		typeToken := fields[1]
		if typeToken == "--" {
			if len(fields) < 3 {
				continue
			}
			typeToken = fields[2]
		}
		rule := parse(fields[0])
		rule.fileType = strings.TrimSuffix(strings.TrimPrefix(typeToken, "system_u:object_r:"), ":s0")
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		t.Fatal("no file-context rules parsed")
	}
	lookup := func(t *testing.T, path string) string {
		t.Helper()
		for _, rule := range rules {
			if rule.exact && rule.pattern == path {
				return rule.fileType
			}
		}
		best := -1
		bestRule := fcRule{}
		for i, rule := range rules {
			if rule.exact {
				continue
			}
			re, err := regexp.Compile("^" + rule.pattern + "$")
			if err != nil {
				t.Fatalf("unparseable fc pattern %q: %v", rule.pattern, err)
			}
			if !re.MatchString(path) {
				continue
			}
			if best == -1 || len(rule.stem) > len(bestRule.stem) {
				best, bestRule = i, rule
			}
		}
		return bestRule.fileType
	}
	for _, tc := range []struct {
		path string
		want string
	}{
		{"/var/lib/docker-helper-builder", "docker_helper_builder_state_root_t"},
		{"/var/lib/docker-helper-builder/ops", "docker_helper_builder_state_root_t"},
		{"/var/lib/docker-helper-builder/ops/op_ac4cbdc1ae4d4d3fa39943de5fcf2e6f", "docker_helper_builder_state_t"},
		{"/var/lib/docker-helper-builder/ops/op_ac4cbdc1ae4d4d3fa39943de5fcf2e6f/root", "docker_helper_builder_state_t"},
		{"/var/lib/docker-helper-builder/ops/op_ac4cbdc1ae4d4d3fa39943de5fcf2e6f/rootlesskit-state", "docker_helper_builder_state_t"},
		{"/var/lib/docker-helper-builder/.config/buildkit/buildkitd.toml", "docker_helper_builder_state_root_t"},
		{"/run/docker-helper-builder", "docker_helper_builder_runtime_root_t"},
		{"/run/docker-helper-builder/ops", "docker_helper_builder_runtime_root_t"},
		{"/run/docker-helper-builder/ops/op_ac4cbdc1ae4d4d3fa39943de5fcf2e6f", "docker_helper_builder_runtime_t"},
		{"/run/docker-helper-builder/ops/op_ac4cbdc1ae4d4d3fa39943de5fcf2e6f/buildkitd.sock", "docker_helper_builder_runtime_t"},
		{"/run/docker-helper-builder/manager.sock", "docker_helper_builder_runtime_root_t"},
		{"/run/docker-helper/builds/op_ac4cbdc1ae4d4d3fa39943de5fcf2e6f/context/Dockerfile", "docker_helper_runtime_t"},
		{"/run/docker-helper/builds/op_ac4cbdc1ae4d4d3fa39943de5fcf2e6f/context", "docker_helper_runtime_t"},
		{"/run/docker-helper/builds", "docker_helper_runtime_t"},
		{"/run/docker-helper/manager.sock", "docker_helper_runtime_t"},
	} {
		if got := lookup(t, tc.path); got != tc.want {
			t.Errorf("fc first-match for %q: got %q, want %q", tc.path, got, tc.want)
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

// TestSELinuxPolicyProvisioningRelabelShape pins the Phase 3 provisioning
// relabel surface (G32 r3 §4.2): the manager holds the exact relabel pair —
// the source-side relabelfrom on the two root DIR types (the freshly
// created directories inherit them) and the target-side relabelto on the
// two per-op DIR types — and nothing else. Negative invariants: root types
// carry no relabelto, per-op types receive no manager relabelfrom, non-dir
// classes receive no provisioning relabel authority, the flow child gains
// neither permission, the daemon keeps zero grants on the operation state
// type, and the legacy direct-launch denial (I9) remains.
func TestSELinuxPolicyProvisioningRelabelShape(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	want := []string{
		// Source side: the old types (root types) relabeled FROM.
		"allow docker_helper_builder_t docker_helper_builder_runtime_root_t:dir { relabelfrom };",
		"allow docker_helper_builder_t docker_helper_builder_state_root_t:dir { relabelfrom };",
		// Target side: the new types (per-op types) relabeled TO.
		"allow docker_helper_builder_t docker_helper_builder_runtime_t:dir { relabelto };",
		"allow docker_helper_builder_t docker_helper_builder_state_t:dir { relabelto };",
	}
	for _, line := range want {
		if !strings.Contains(policy, line) {
			t.Errorf("the provisioning relabel grant is missing: %q", line)
		}
	}
	// The manager's provisioning relabel surface is exactly the four
	// grants above; any other manager-subject relabelto/relabelfrom —
	// root-type relabelto, per-op relabelfrom, or any non-dir class — is a
	// violation. (The daemon's pre-existing trusted-CA relabelto rules are
	// a different, already-pinned owner and out of scope here.)
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.HasPrefix(trimmed, "allow docker_helper_builder_t ") {
			continue
		}
		relabelFrom := strings.Contains(trimmed, " relabelfrom")
		relabelTo := strings.Contains(trimmed, " relabelto")
		if !relabelFrom && !relabelTo {
			continue
		}
		permitted := false
		for _, w := range want {
			if trimmed == w {
				permitted = true
				break
			}
		}
		if !permitted {
			t.Errorf("unexpected manager relabel grant (the provisioning surface is exact): %s", trimmed)
		}
	}
	// No relabel authority may name a root type as its relabelto target,
	// and the flow child never gains either permission.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.HasPrefix(trimmed, "allow ") {
			continue
		}
		if !strings.Contains(trimmed, "relabelto") && !strings.Contains(trimmed, "relabelfrom") {
			continue
		}
		if strings.Contains(trimmed, "relabelto") && strings.Contains(trimmed, "_root_t:") {
			t.Errorf("relabelto authority must not name a root type: %s", trimmed)
		}
		if strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t") &&
			(strings.Contains(trimmed, "relabelto") || strings.Contains(trimmed, "relabelfrom")) {
			t.Errorf("the flow child must never gain relabel authority: %s", trimmed)
		}
	}
	// The daemon keeps zero grants on the operation state type.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "allow docker_helper_t docker_helper_builder_state_t") {
			t.Errorf("the daemon must keep zero grants on the operation state type: %s", trimmed)
		}
	}
	// I9: the legacy direct launch rules stay gone.
	for _, gone := range []string{
		"type_transition docker_helper_builder_t docker_helper_rootlesskit_exec_t:process docker_helper_rootlesskit_t;",
		"allow docker_helper_builder_t docker_helper_rootlesskit_t:process { transition };",
		"allow docker_helper_builder_t docker_helper_rootlesskit_exec_t:file { execute read open };",
	} {
		if strings.Contains(policy, gone) {
			t.Errorf("the legacy direct launch rule must not exist: %q", gone)
		}
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
