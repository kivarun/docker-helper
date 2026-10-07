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
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	// rule), no other subject holds a tun_tap_device_t ioctl xperm rule —
	// the 4C-34 helper's independent single-command { 0x54ca } whitelist
	// is owned by the slirp4netns helper test, not by this rootlesskit
	// surface's owner — and no subject beyond the two TUN users holds a
	// tun_tap_device_t allow rule — the 4C-31/4C-32/4C-33 helper's
	// independent ordinary staircase is owned by the slirp4netns helper
	// test.
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
				switch trimmed {
				case "allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x54cb };":
					rootlesskitTunXpermRules++
				case "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl 0x54ca;":
					// The 4C-34 helper rule: an independent single-command
					// whitelist owned by the slirp4netns helper test
					// (not re-pinned here — no shared TUN abstraction).
				default:
					violations = append(violations, fmt.Sprintf("the tun_tap_device_t ioctl xperm surface is exactly the two TUN users' own pinned rules — the rootlesskit child's { 0x54ca 0x54cb } and the 4C-34 helper's { 0x54ca } — no third command, no range, no complement, no other subject: %s", trimmed))
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, "tun_tap_device_t:chr_file"):
				switch trimmed {
				case "allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { read write open ioctl };":
					rootlesskitTunRules++
				case "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write open ioctl };":
					// The 4C-33 helper rule: an independent TUN
					// staircase owned by the slirp4netns helper test
					// (not re-pinned here — no shared TUN abstraction).
				default:
					violations = append(violations, fmt.Sprintf("the tun_tap_device_t surface is exactly the two TUN users' own pinned rules — the rootlesskit child's { read write open ioctl } plus its xperm and the 4C-33 helper { read write open ioctl } (the helper holds NO xperm) — no other permission, no other subject: %s", trimmed))
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
		{"the rootlesskit TUN xperm copied to the network helper", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x54cb };"},
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
		"class tun_socket { create relabelfrom relabelto };",
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
				if trimmed == "class tun_socket { create relabelfrom relabelto };" {
					tunSocketRequireDecls++
				} else {
					violations = append(violations, fmt.Sprintf("the require block's tun_socket declaration is exactly the three evidenced socket permissions — the rootlesskit child's evidenced creation permission plus the network helper's evidenced cross-domain attach relabel permission and self-targeted relabelto: %s", trimmed))
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, ":tun_socket"):
				switch trimmed {
				case "allow docker_helper_rootlesskit_t self:tun_socket create;":
					rootlesskitTunSocketRules++
				case "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket relabelfrom;",
					"allow docker_helper_slirp4netns_t self:tun_socket relabelto;":
					// Routed: the network helper's TUN socket-relabel
					// surface (the cross-domain relabelfrom + the
					// self-targeted relabelto) has its own owner — the
					// helper domain's tun-socket invariants (counts,
					// targets, shapes, and every forbidden widening)
					// live in helperDomainPolicyViolations and the
					// slirp4netns domain test; this owner must not
					// mask them.
				default:
					violations = append(violations, fmt.Sprintf("the tun_socket surface is exactly the rootlesskit child's single self-create rule plus the network helper's single cross-domain relabelfrom rule and single self-relabelto rule (no attach_queue, no other relabel*, no inherited socket permission, no other subject, no other target): %s", trimmed))
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
		{"missing require create", "class tun_socket { create relabelfrom relabelto };"},
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
		{"require without relabelto (the pre-4C-36 shape)", "class tun_socket { create relabelfrom };"},
		{"duplicate create rule", "allow docker_helper_rootlesskit_t self:tun_socket create;"},
		{"parallel create rule (braced form)", "allow docker_helper_rootlesskit_t self:tun_socket { create };"},
		{"widened attach_queue", "allow docker_helper_rootlesskit_t self:tun_socket attach_queue;"},
		{"widened relabelfrom", "allow docker_helper_rootlesskit_t self:tun_socket relabelfrom;"},
		{"reversed cross-domain relabel (rootlesskit source, helper-target socket)", "allow docker_helper_rootlesskit_t docker_helper_slirp4netns_t:tun_socket relabelfrom;"},
		{"reversed relabelto (rootlesskit source, helper-target socket)", "allow docker_helper_rootlesskit_t docker_helper_slirp4netns_t:tun_socket relabelto;"},
		{"widened relabelto", "allow docker_helper_rootlesskit_t self:tun_socket relabelto;"},
		{"distro create_socket_perms macro", "create_socket_perms(docker_helper_rootlesskit_t)"},
		{"widened require declaration", "class tun_socket { create attach_queue };"},
		{"widened require declaration (relabelfrom only)", "class tun_socket { relabelfrom };"},
		{"widened require declaration (all four)", "class tun_socket { create relabelfrom relabelto attach_queue };"},
		{"widened require declaration (all three)", "class tun_socket { create relabelfrom attach_queue };"},
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

// mcsMembershipViolations scans the policy against the mcs_constrained_type
// membership contract (the exact canonical single-attribute form, each
// wanted domain a member exactly once, the trusted control planes and the
// launch child out) and returns one human-readable violation per broken
// shape, empty when none.
func mcsMembershipViolations(policy string, want []string) []string {
	var violations []string
	var members []string
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "typeattribute ") || !strings.Contains(trimmed, "mcs_constrained_type") {
			continue
		}
		if !strings.HasSuffix(trimmed, " mcs_constrained_type;") {
			violations = append(violations, "membership in mcs_constrained_type must use the exact canonical single-attribute form: "+trimmed)
			continue
		}
		members = append(members, strings.Fields(strings.TrimSuffix(trimmed, " mcs_constrained_type;"))[1])
	}
	seen := map[string]int{}
	for _, member := range members {
		seen[member]++
	}
	for domain, n := range seen {
		if n > 1 {
			violations = append(violations, fmt.Sprintf("the mcs_constrained_type membership must not be duplicated: %s appears %d times", domain, n))
		}
	}
	for _, domain := range want {
		if seen[domain] != 1 {
			violations = append(violations, fmt.Sprintf("the flow-side domain must be a mcs_constrained_type member (exactly once): %s", domain))
		}
	}
	for _, member := range members {
		if seen[member] == 1 {
			found := false
			for _, domain := range want {
				if domain == member {
					found = true
					break
				}
			}
			if !found {
				violations = append(violations, fmt.Sprintf("no domain outside the accepted membership set may join mcs_constrained_type: %s", member))
			}
		}
	}
	for _, excluded := range []string{
		"docker_helper_t",
		"docker_helper_builder_t",
		"docker_helper_builder_launcher_t",
	} {
		for _, member := range members {
			if member == excluded {
				violations = append(violations, "the trusted control plane / launch child must NOT be mcs_constrained: "+excluded)
			}
		}
	}
	return violations
}

// TestSELinuxPolicyMCSMembership verifies the G32 r3 §6.A constrained
// membership: the managed-container domain (its own accepted boundary) and
// exactly the five flow-side domains are members of mcs_constrained_type
// (the G26 minimal set, the G28-revised slirp4netns, and the 4C-59
// structural foundation correction's buildkitd_t — the domain joins
// BEFORE it ever becomes reachable), and the trusted control planes /
// launch child stay OUT — their cross-category reachability is the
// measured escape mechanics the launch chain and the lifecycle depend on.
// The owner catches: a missing member, the removal of any standing member,
// the addition of a trusted control plane, the addition of an arbitrary
// unrelated docker-helper domain, and a duplicate or malformed membership
// line (membership must be declared in the exact canonical single-attribute
// form).
func TestSELinuxPolicyMCSMembership(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	want := []string{
		"docker_helper_container_t",
		"docker_helper_rootlesskit_t",
		"docker_helper_newuidmap_t",
		"docker_helper_newgidmap_t",
		"docker_helper_slirp4netns_t",
		"docker_helper_buildkitd_t",
	}
	if violations := mcsMembershipViolations(policy, want); len(violations) > 0 {
		t.Errorf("the committed policy violates the MCS membership invariants: %v", violations)
	}
	// Removal mutation: the policy without one standing member must trip.
	removed := strings.Replace(policy, "typeattribute docker_helper_slirp4netns_t mcs_constrained_type;\n", "", 1)
	if removed == policy {
		t.Fatal("the standing slirp4netns membership line was not found for the removal mutation")
	}
	if violations := mcsMembershipViolations(removed, want); len(violations) == 0 {
		t.Error("the removal mutation must trip the MCS membership invariants")
	}
	// Mutation guards: every forbidden membership shape must trip.
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"trusted control plane joined", "typeattribute docker_helper_builder_t mcs_constrained_type;"},
		{"daemon joined", "typeattribute docker_helper_t mcs_constrained_type;"},
		{"launch child joined", "typeattribute docker_helper_builder_launcher_t mcs_constrained_type;"},
		{"arbitrary unrelated docker-helper domain joined", "typeattribute docker_helper_nsenter_t mcs_constrained_type;"},
		{"duplicate membership line", "typeattribute docker_helper_buildkitd_t mcs_constrained_type;"},
		{"malformed multi-attribute membership", "typeattribute docker_helper_rootlesskit_t mcs_constrained_type, container_net_domain;"},
	} {
		if violations := mcsMembershipViolations(policy+"\n"+mut.rule, want); len(violations) == 0 {
			t.Errorf("mutation %q must trip the MCS membership invariants", mut.name)
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
//   - the helper's TUN device-node authority is exactly one
//     tun_tap_device_t:chr_file { read write open ioctl } allow plus
//     exactly one tun_tap_device_t:chr_file ioctl 0x54ca allowxperm
//     (the 4C-31 read/write + 4C-32 open + 4C-33 generic-ioctl grants
//     and the 4C-34 TUNSETIFF command whitelist; no other ioctl
//     command, no allowxperm on any other type, and no
//     getattr/append/lock/create/setattr, exactly TWO helper tun_socket
//     grants: the cross-domain relabelfrom toward the rootlesskit target
//     and the self relabelto
//     — the RootlessKit TUN staircase is owned by the rootlesskit
//     test's tun owner);
//   - the manager domain holds no capability, capability2, or cap_userns
//     grants, and the helper domain holds no plain capability or
//     capability2 grant (the helper's single self:cap_userns rule is
//     pinned by the slirp4netns test's string scan). The rootlesskit
//     child domain is deliberately NOT frozen here: its cap_userns
//     surface is owned by the dedicated cap_userns shape test, not by
//     this helper-invariant owner.
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
	slirpTargetLnkRules := 0
	for _, rule := range allows {
		if rule.source == "docker_helper_slirp4netns_t" && rule.target == "docker_helper_rootlesskit_t" && rule.class == "lnk_file" {
			slirpTargetLnkRules++
		}
	}
	if slirpTargetLnkRules != 1 {
		violations = append(violations, fmt.Sprintf("exactly one lnk_file-read grant may exist from the helper toward the rootlesskit namespace target, found %d", slirpTargetLnkRules))
	}
	// The 4C-26 target-SID ptrace READ grant exists exactly once per its
	// triple; a duplicate (even byte-identical) rule also violates.
	slirpTargetFileRules := 0
	for _, rule := range allows {
		if rule.source == "docker_helper_slirp4netns_t" && rule.target == "docker_helper_rootlesskit_t" && rule.class == "file" {
			slirpTargetFileRules++
		}
	}
	if slirpTargetFileRules != 1 {
		violations = append(violations, fmt.Sprintf("exactly one file-read grant may exist from the helper toward the rootlesskit namespace target (the PTRACE_MODE_READ target-SID check), found %d", slirpTargetFileRules))
	}
	// The helper's own entry-file rule exists exactly once per its triple;
	// a widened duplicate also violates.
	slirpEntryFileRules := 0
	for _, rule := range allows {
		if rule.source == "docker_helper_slirp4netns_t" && rule.target == "docker_helper_slirp4netns_exec_t" && rule.class == "file" {
			slirpEntryFileRules++
		}
	}
	if slirpEntryFileRules != 1 {
		violations = append(violations, fmt.Sprintf("exactly one entry-file rule may exist for the helper domain, found %d", slirpEntryFileRules))
	}
	// The 4C-29 nsfs namespace-handle { read open } grant: exactly ONE
	// allow line may name slirp4netns_t -> nsfs_t:file, in the exact
	// brace shape { read open } (no bare read, no bare open, no split
	// into two rules, no extra perms). nsfs_t is globally labelled; the
	// categorized proc-target layer is what must keep the access
	// pointed (see the .te scope note).
	slirpNsfsFileLines := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "allow docker_helper_slirp4netns_t nsfs_t:file") {
			slirpNsfsFileLines++
			if trimmed != "allow docker_helper_slirp4netns_t nsfs_t:file { read open };" {
				violations = append(violations, fmt.Sprintf("the helper's nsfs namespace-handle grant must be the exact { read open } shape (no bare-read, no bare-open, no split rules, no extra perms): %s", trimmed))
			}
		}
	}
	if slirpNsfsFileLines != 1 {
		violations = append(violations, fmt.Sprintf("exactly one nsfs:file-read grant may exist from the helper toward the namespace magic-link target, found %d", slirpNsfsFileLines))
	}
	// The 4C-31/4C-32/4C-33/4C-34 TUN device-node grant: exactly ONE
	// allow line may name slirp4netns_t -> tun_tap_device_t:chr_file, in
	// the exact brace shape { read write open ioctl } (no bare
	// read/write/open/ioctl, no split into
	// multiple rules, no getattr/append/lock/create/setattr), and the
	// allowxperm guard below pins the command whitelist: exactly ONE
	// allowxperm line, the exact 0x54ca (TUNSETIFF) shape — the 4C-34
	// hardening of the bitmap-less intermediate the 4C-33 run proved
	// command-unrestricted.
	// tun_tap_device_t
	// is globally labelled; the rule is NOT operation/category scoped
	// (see the .te scope note). The independent RootlessKit TUN surface
	// is owned by the rootlesskit test's tun owner.
	slirpTunFileLines := 0
	slirpTunXpermLines := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file") {
			slirpTunFileLines++
			if trimmed != "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write open ioctl };" {
				violations = append(violations, fmt.Sprintf("the helper's tun_tap_device_t grant must be the exact { read write open ioctl } shape (no bare-read/write/open/ioctl, no split rules, no getattr/append/lock/create/setattr): %s", trimmed))
			}
		}
		if strings.HasPrefix(trimmed, "allowxperm docker_helper_slirp4netns_t") {
			slirpTunXpermLines++
			if trimmed != "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl 0x54ca;" {
				violations = append(violations, fmt.Sprintf("the helper's allowxperm surface must be exactly one tun_tap_device_t:chr_file ioctl 0x54ca rule (the single live-proven TUNSETIFF command; no 0x54cb, no third command, no range, no complement, no other type): %s", trimmed))
			}
		}
	}
	if slirpTunFileLines != 1 {
		violations = append(violations, fmt.Sprintf("exactly one tun_tap_device_t:chr_file grant may exist for the helper domain, found %d", slirpTunFileLines))
	}
	if slirpTunXpermLines != 1 {
		violations = append(violations, fmt.Sprintf("exactly one tun_tap_device_t:chr_file allowxperm rule may exist for the helper domain, found %d", slirpTunXpermLines))
	}
	// The 4C-35/4C-36 cross-domain + self TUN socket-relabel grants: the
	// attach path's relabel stage is ONE semantic owned by ONE block —
	// exactly ONE allow line may name slirp4netns_t ->
	// docker_helper_rootlesskit_t:tun_socket, in the exact bare-relabelfrom
	// shape (the 4C-34 canonical run's terminal boundary, record 2339 —
	// the relabelfrom check on the stored rootlesskit_t socket SID), and
	// exactly ONE allow line may name slirp4netns_t -> self:tun_socket, in
	// the exact bare-relabelto shape (the 4C-35 canonical run's terminal
	// boundary, record 2309 — a SELF-TARGETED relabelto: both recorded
	// SIDs are the helper's own). attach_queue, create, getattr, and every
	// other socket permission is ungranted; a second/split rule, a
	// relabelto toward the rootlesskit target, or a reverse-direction
	// rule is a pre-grant of an unproven boundary. The subject-scoped
	// class-level routing lives in the rootlesskit test's tun owner
	// (which routes both pinned helper rules explicitly so it cannot mask
	// the rootlesskit child's own invariants).
	slirpTunSocketLines := 0
	slirpTunRelabeltoLines := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket") {
			slirpTunSocketLines++
			if trimmed != "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket relabelfrom;" {
				violations = append(violations, fmt.Sprintf("the helper's cross-domain TUN socket grant must be the exact bare-relabelfrom shape (no brace form, no split rules, no relabelto/attach_queue/create/getattr/read/write, no other permission): %s", trimmed))
			}
		}
		if strings.HasPrefix(trimmed, "allow docker_helper_slirp4netns_t self:tun_socket") {
			slirpTunRelabeltoLines++
			if trimmed != "allow docker_helper_slirp4netns_t self:tun_socket relabelto;" {
				violations = append(violations, fmt.Sprintf("the helper's self TUN socket grant must be the exact bare-relabelto shape (no brace form, no split rules, no relabelfrom/attach_queue/create/getattr/read/write, no other permission): %s", trimmed))
			}
		}
	}
	if slirpTunSocketLines != 1 {
		violations = append(violations, fmt.Sprintf("exactly one cross-domain tun_socket relabelfrom grant may exist from the helper toward the rootlesskit target, found %d", slirpTunSocketLines))
	}
	if slirpTunRelabeltoLines != 1 {
		violations = append(violations, fmt.Sprintf("exactly one self tun_socket relabelto grant may exist for the helper domain, found %d", slirpTunRelabeltoLines))
	}
	// The 4C-28 distro-nsfs-macro exclusion, identified structurally at
	// SOURCE level (a macro's name does not exist after policy
	// compilation — sesearch sees only the expanded rules — the same
	// rationale as the 4C-12 macro-provenance note): the module is
	// standalone-compiled and the distro fs_read_nsfs_files() interface
	// (and its read_file_perms expansion, { open getattr read ioctl
	// lock }) is materially broader than the evidenced nsfs_t:file
	// read. Any use of the interface name in the module text is a
	// widening; comment mentions document the exclusion and are
	// skipped.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "fs_read_nsfs_files") {
			violations = append(violations, fmt.Sprintf("the distro fs_read_nsfs_files interface must not be used (its read_file_perms expansion is broader than the evidenced nsfs_t:file read): %s", trimmed))
		}
	}
	// The 4C-25/4C-30 helper capability invariant: the helper's ONLY
	// cap_userns rule is the single self:cap_userns rule widened to
	// { sys_ptrace sys_admin } by 4C-30 (the namespace-join authority).
	// The exact shape is asserted by the string scan in the slirp4netns
	// test; here the triple count and the forbidden class forms are
	// enforced.
	slirpSelfCapUsernsRules := 0
	for _, rule := range allows {
		if rule.source == "docker_helper_slirp4netns_t" && rule.target == "self" && rule.class == "cap_userns" {
			slirpSelfCapUsernsRules++
		}
	}
	if slirpSelfCapUsernsRules != 1 {
		violations = append(violations, fmt.Sprintf("exactly one self:cap_userns rule may exist for the helper domain, found %d", slirpSelfCapUsernsRules))
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
			// The 4C-23/4C-24/4C-26 namespace-target authority: dir
			// search (the traversal), lnk_file read (the magic-link
			// open), and file read (the SELinux ptrace READ target-SID
			// check) toward the rootlesskit target, exactly; any other
			// dir/lnk shape (widened perms, another target domain) is
			// a widening.
			if rule.class == "dir" && rule.target != "docker_helper_rootlesskit_t" {
				violations = append(violations, fmt.Sprintf("the helper domain holds no dir authority toward any target other than the rootlesskit namespace target: allow %s %s:%s", rule.source, rule.target, rule.class))
			}
			if rule.class == "lnk_file" && rule.target != "docker_helper_rootlesskit_t" {
				violations = append(violations, fmt.Sprintf("the helper domain holds no lnk_file authority toward any target other than the rootlesskit namespace target: allow %s %s:%s", rule.source, rule.target, rule.class))
			}
			// The helper's FILE authority is its own entry type plus the
			// single target-SID ptrace READ rule and the nsfs
			// namespace-handle read (count and exact shape enforced by
			// the count clauses and the slirp4netns test's string
			// scans); a file grant toward any OTHER target is a
			// pre-grant of an unproven boundary.
			if rule.class == "file" && rule.target != "docker_helper_slirp4netns_exec_t" && rule.target != "docker_helper_rootlesskit_t" && rule.target != "nsfs_t" {
				violations = append(violations, fmt.Sprintf("the helper domain's file authority is only its own entry type plus the rootlesskit target-SID read (no other file target): allow %s %s:%s", rule.source, rule.target, rule.class))
			}
			// The helper's capability surface: no plain capability/
			// capability2 grant of any target; the only cap_userns
			// authority is self (the exact sys_ptrace-only shape is
			// pinned by the slirp4netns test's string scan).
			if rule.class == "capability" || rule.class == "capability2" {
				violations = append(violations, fmt.Sprintf("the helper domain must hold no plain capability/capability2 grants: allow %s %s:%s", rule.source, rule.target, rule.class))
			}
			if rule.class == "cap_userns" && rule.target != "self" {
				violations = append(violations, fmt.Sprintf("the helper domain holds no cap_userns authority toward any target other than itself: allow %s %s:%s", rule.source, rule.target, rule.class))
			}
			// The 4C-35/4C-36 scope: the helper's attach path mediates
			// the EXISTING TAP's stored socket SID, so the helper
			// holds exactly TWO tun_socket authorities — the
			// cross-domain relabelfrom toward the rootlesskit target
			// (the 4C-34 canonical run's terminal boundary, record
			// 2339) and the SELF-targeted relabelto (the 4C-35
			// canonical run's terminal boundary, record 2309; the
			// rules' exact perm shapes are pinned by the slirp4netns
			// test's string scans). A tun_socket grant toward any
			// OTHER target (a second domain's socket, anything else)
			// is a pre-grant of an unproven boundary.
			if rule.class == "tun_socket" && rule.target != "docker_helper_rootlesskit_t" && rule.target != "self" {
				violations = append(violations, fmt.Sprintf("the helper domain's tun_socket authority is only the cross-domain relabelfrom toward the rootlesskit target and the self relabelto (no other target): allow %s %s:%s", rule.source, rule.target, rule.class))
			}
		}
		if rule.source == "docker_helper_rootlesskit_t" && rule.target == "docker_helper_slirp4netns_t" && rule.class == "dir" {
			violations = append(violations, fmt.Sprintf("no reversed proc-traversal direction (the target child gains no dir authority over the helper domain): allow %s %s:%s", rule.source, rule.target, rule.class))
		}
		if rule.target == "docker_helper_slirp4netns_t" && rule.class == "dir" {
			violations = append(violations, fmt.Sprintf("no proc-traversal authority into the helper domain's own proc tree from any subject: allow %s %s:%s", rule.source, rule.target, rule.class))
		}
		if rule.source == "docker_helper_builder_t" && rule.target == "self" {
			switch rule.class {
			case "capability", "capability2", "cap_userns":
				violations = append(violations, fmt.Sprintf("%s must hold no capability/capability2/cap_userns grants: allow %s %s:%s", rule.source, rule.source, rule.target, rule.class))
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
		"allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:lnk_file read;",
		"allow docker_helper_slirp4netns_t self:cap_userns { sys_ptrace sys_admin };",
		"allow docker_helper_slirp4netns_t nsfs_t:file { read open };",
		"allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write open ioctl };",
		"allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl 0x54ca;",
		"allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket relabelfrom;",
		"allow docker_helper_slirp4netns_t self:tun_socket relabelto;",
		"type nsfs_t;",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("SELinux policy must contain exactly this rule: %s", want)
		}
	}
	if violations := helperDomainPolicyViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the helper-domain invariants: %v", violations)
	}
	// The 4C-23/4C-24 namespace-target authority: exactly ONE dir-search
	// rule and exactly ONE lnk_file-read rule toward the rootlesskit
	// target, in the exact pinned shapes.
	pinnedDirRule := "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir search;"
	pinnedLnkRule := "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:lnk_file read;"
	pinnedCapRule := "allow docker_helper_slirp4netns_t self:cap_userns { sys_ptrace sys_admin };"
	pinnedFileRule := "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:file read;"
	pinnedNsfsRule := "allow docker_helper_slirp4netns_t nsfs_t:file { read open };"
	pinnedTunRule := "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write open ioctl };"
	pinnedTunXpermRule := "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl 0x54ca;"
	pinnedTunSocketRule := "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket relabelfrom;"
	pinnedTunRelabeltoRule := "allow docker_helper_slirp4netns_t self:tun_socket relabelto;"
	pinnedNsfsRequire := "type nsfs_t;"
	countPinned := func(text, rule string) int {
		n := 0
		for _, line := range strings.Split(text, "\n") {
			if strings.TrimSpace(line) == rule {
				n++
			}
		}
		return n
	}
	if countPinned(policy, pinnedDirRule) != 1 {
		t.Errorf("the helper's namespace-target traversal must be exactly one `dir search` rule toward the rootlesskit target, found %d", countPinned(policy, pinnedDirRule))
	}
	if countPinned(policy, pinnedLnkRule) != 1 {
		t.Errorf("the helper's namespace magic-link open must be exactly one `lnk_file read` rule toward the rootlesskit target, found %d", countPinned(policy, pinnedLnkRule))
	}
	if countPinned(policy, pinnedCapRule) != 1 {
		t.Errorf("the helper's capability surface must be exactly one `self:cap_userns { sys_ptrace sys_admin }` rule (the namespace-join widening, 4C-30), found %d", countPinned(policy, pinnedCapRule))
	}
	if countPinned(policy, pinnedFileRule) != 1 {
		t.Errorf("the helper's target-SID ptrace READ authority must be exactly one `rootlesskit_t:file read` rule, found %d", countPinned(policy, pinnedFileRule))
	}
	if countPinned(policy, pinnedNsfsRule) != 1 {
		t.Errorf("the helper's namespace-handle authority must be exactly one `nsfs_t:file { read open }` rule (the magic-link target's VFS read+open), found %d", countPinned(policy, pinnedNsfsRule))
	}
	if countPinned(policy, pinnedNsfsRequire) != 1 {
		t.Errorf("the module's external-type require set must declare nsfs_t exactly once, found %d", countPinned(policy, pinnedNsfsRequire))
	}
	if countPinned(policy, pinnedTunRule) != 1 {
		t.Errorf("the helper's TUN device-node authority must be exactly one `tun_tap_device_t:chr_file { read write open ioctl }` rule (the 4C-31 read/write + 4C-32 open + 4C-33 generic-ioctl grants, with NO allowxperm), found %d", countPinned(policy, pinnedTunRule))
	}
	if countPinned(policy, pinnedTunXpermRule) != 1 {
		t.Errorf("the helper's TUN command whitelist must be exactly one `allowxperm ... ioctl 0x54ca` rule (the 4C-34 TUNSETIFF hardening; no 0x54cb, no third command), found %d", countPinned(policy, pinnedTunXpermRule))
	}
	if countPinned(policy, pinnedTunSocketRule) != 1 {
		t.Errorf("the helper's cross-domain TUN socket authority must be exactly one `rootlesskit_t:tun_socket relabelfrom` rule (the 4C-35 attach-path grant; no relabelto, no attach_queue, no create, no second rule), found %d", countPinned(policy, pinnedTunSocketRule))
	}
	if countPinned(policy, pinnedTunRelabeltoRule) != 1 {
		t.Errorf("the helper's self TUN socket authority must be exactly one `self:tun_socket relabelto` rule (the 4C-36 self-targeted attach grant; no relabelfrom, no attach_queue, no create, no second rule), found %d", countPinned(policy, pinnedTunRelabeltoRule))
	}
	// Regression: each grant must exist; removing it, or replacing it
	// with a wrong-shape, must break the exactly-one invariant the count
	// guard asserts.
	for _, regressed := range []struct {
		name string
		old  string
		rule string
	}{
		{"missing traversal rule", pinnedDirRule, ""},
		{"missing search (getattr-only shape)", pinnedDirRule, "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir getattr;"},
		{"missing lnk_file rule", pinnedLnkRule, ""},
		{"missing lnk_file read (getattr-only shape)", pinnedLnkRule, "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:lnk_file getattr;"},
		{"missing cap_userns rule", pinnedCapRule, ""},
		{"missing sys_admin (pre-4C-30 ptrace-only shape)", pinnedCapRule, "allow docker_helper_slirp4netns_t self:cap_userns sys_ptrace;"},
		{"missing sys_ptrace (sys_admin-only shape)", pinnedCapRule, "allow docker_helper_slirp4netns_t self:cap_userns sys_admin;"},
		{"missing target-file rule", pinnedFileRule, ""},
		{"missing target-file read (getattr-only shape)", pinnedFileRule, "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:file getattr;"},
		{"missing nsfs namespace-handle rule", pinnedNsfsRule, ""},
		{"missing nsfs open (pre-4C-29 bare-read shape)", pinnedNsfsRule, "allow docker_helper_slirp4netns_t nsfs_t:file read;"},
		{"missing nsfs read (bare-open-only shape)", pinnedNsfsRule, "allow docker_helper_slirp4netns_t nsfs_t:file open;"},
		{"missing nsfs_t require declaration", pinnedNsfsRequire, ""},
	} {
		mutated := strings.Replace(policy, regressed.old, regressed.rule, 1)
		if countPinned(mutated, regressed.old) == 1 {
			t.Errorf("the traversal/lnk/cap/file regression %q was not applied", regressed.name)
		}
	}
	// The 4C-31/4C-32 TUN device-node removal regressions: each removal
	// must APPLY and must actually trip the helper invariants (the
	// exact-shape/count guards above) — the owner pins the effective
	// surface, so any shortened shape fails it.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing whole helper TUN device-node rule", ""},
		{"missing TUN read ({ write open ioctl }-only shape)", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { write open ioctl };"},
		{"missing TUN write ({ read open ioctl }-only shape)", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read open ioctl };"},
		{"missing TUN open ({ read write ioctl }-only shape)", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write ioctl };"},
		{"missing TUN ioctl (the pre-4C-33 { read write open } shape must trip again)", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write open };"},
	} {
		mutated := strings.Replace(policy, pinnedTunRule, regressed.rule, 1)
		if countPinned(mutated, pinnedTunRule) == 1 {
			t.Errorf("the TUN regression %q was not applied", regressed.name)
			continue
		}
		if len(helperDomainPolicyViolations(mutated)) == 0 {
			t.Errorf("the TUN regression %q must fail the helper-domain invariants", regressed.name)
		}
	}
	// The 4C-34 xperm removal regression: the command whitelist must
	// exist; removing it (the pre-4C-34 bitmap-less shape — live-proven
	// command-unrestricted) must APPLY and must trip the invariants.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing xperm command rule (the pre-4C-34 bitmap-less shape must trip again)", ""},
	} {
		mutated := strings.Replace(policy, pinnedTunXpermRule, regressed.rule, 1)
		if countPinned(mutated, pinnedTunXpermRule) == 1 {
			t.Errorf("the TUN xperm regression %q was not applied", regressed.name)
			continue
		}
		if len(helperDomainPolicyViolations(mutated)) == 0 {
			t.Errorf("the TUN xperm regression %q must fail the helper-domain invariants", regressed.name)
		}
	}
	// The 4C-35 cross-domain TUN socket-relabel removal regressions: each
	// removal/replacement must APPLY and must actually trip the helper
	// invariants (the exact-shape/count guards above) — the owner pins
	// the effective surface, so any other shape fails it.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing whole cross-domain tun_socket rule (the pre-4C-35 boundary must trip again)", ""},
		{"missing relabelfrom (relabelto-only shape — the ungranted mirror permission)", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket relabelto;"},
		{"missing relabelfrom (attach_queue-only shape)", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket attach_queue;"},
		{"missing relabelfrom (create-only shape — the creator's own grant)", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket create;"},
	} {
		mutated := strings.Replace(policy, pinnedTunSocketRule, regressed.rule, 1)
		if countPinned(mutated, pinnedTunSocketRule) == 1 {
			t.Errorf("the TUN socket regression %q was not applied", regressed.name)
			continue
		}
		if len(helperDomainPolicyViolations(mutated)) == 0 {
			t.Errorf("the TUN socket regression %q must fail the helper-domain invariants", regressed.name)
		}
	}
	// The 4C-36 self relabelto removal regressions: each
	// removal/replacement must APPLY and must actually trip the helper
	// invariants — the owner pins the effective surface, so any other
	// shape fails it.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing whole self relabelto rule (the pre-4C-36 boundary must trip again)", ""},
		{"missing relabelto (self relabelfrom-only shape — the ungranted self-side permission)", "allow docker_helper_slirp4netns_t self:tun_socket relabelfrom;"},
		{"missing relabelto (self attach_queue-only shape)", "allow docker_helper_slirp4netns_t self:tun_socket attach_queue;"},
	} {
		mutated := strings.Replace(policy, pinnedTunRelabeltoRule, regressed.rule, 1)
		if countPinned(mutated, pinnedTunRelabeltoRule) == 1 {
			t.Errorf("the TUN relabelto regression %q was not applied", regressed.name)
			continue
		}
		if len(helperDomainPolicyViolations(mutated)) == 0 {
			t.Errorf("the TUN relabelto regression %q must fail the helper-domain invariants", regressed.name)
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
		{"namespace-path lnk_file pre-grant (widened lnk shape)", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:lnk_file { read getattr };"},
		{"lnk_file structural: duplicate identical magic-link rule", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:lnk_file read;"},
		{"lnk_file structural: parallel read rule (brace form)", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:lnk_file { read };"},
		{"lnk_file widened { read write }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:lnk_file { read write };"},
		{"lnk_file widened { read ioctl }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:lnk_file { read ioctl };"},
		{"lnk_file widened { read lock }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:lnk_file { read lock };"},
		{"nsfs structural: duplicate identical namespace-handle rule", "allow docker_helper_slirp4netns_t nsfs_t:file { read open };"},
		{"nsfs structural: parallel read rule (brace form)", "allow docker_helper_slirp4netns_t nsfs_t:file { read };"},
		{"nsfs structural: parallel open rule", "allow docker_helper_slirp4netns_t nsfs_t:file open;"},
		{"nsfs structural: read/open split across two rules", "allow docker_helper_slirp4netns_t nsfs_t:file read;\nallow docker_helper_slirp4netns_t nsfs_t:file open;"},
		{"nsfs widened { read open getattr }", "allow docker_helper_slirp4netns_t nsfs_t:file { read open getattr };"},
		{"nsfs widened { read open ioctl }", "allow docker_helper_slirp4netns_t nsfs_t:file { read open ioctl };"},
		{"nsfs widened { read open lock }", "allow docker_helper_slirp4netns_t nsfs_t:file { read open lock };"},
		{"nsfs widened { read open write }", "allow docker_helper_slirp4netns_t nsfs_t:file { read open write };"},
		{"nsfs widened { read open map }", "allow docker_helper_slirp4netns_t nsfs_t:file { read open map };"},
		{"nsfs widened { read open execute }", "allow docker_helper_slirp4netns_t nsfs_t:file { read open execute };"},
		{"nsfs distro-macro expansion equivalent", "allow docker_helper_slirp4netns_t nsfs_t:file { open getattr read ioctl lock };"},
		{"nsfs distro-macro use (fs_read_nsfs_files interface call)", "fs_read_nsfs_files(docker_helper_slirp4netns_t);"},
		{"tun structural: duplicate identical device-node rule", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write open ioctl };"},
		{"tun structural: parallel read rule (brace form)", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read };"},
		{"tun structural: parallel write rule", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file write;"},
		{"tun structural: parallel open rule", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file open;"},
		{"tun structural: parallel ioctl rule", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl;"},
		{"tun structural: read/write split across two rules (union lacks the granted open/ioctl)", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file read;\nallow docker_helper_slirp4netns_t tun_tap_device_t:chr_file write;"},
		{"tun structural: read/write/open split across three rules (union lacks the granted ioctl)", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file read;\nallow docker_helper_slirp4netns_t tun_tap_device_t:chr_file write;\nallow docker_helper_slirp4netns_t tun_tap_device_t:chr_file open;"},
		{"tun structural: read/write/open/ioctl split across four rules (union = the granted surface)", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file read;\nallow docker_helper_slirp4netns_t tun_tap_device_t:chr_file write;\nallow docker_helper_slirp4netns_t tun_tap_device_t:chr_file open;\nallow docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl;"},
		{"tun widened +getattr", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write open ioctl getattr };"},
		{"tun widened +append", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write open ioctl append };"},
		{"tun widened +lock", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write open ioctl lock };"},
		{"tun widened +create", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write open ioctl create };"},
		{"tun widened +setattr", "allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { read write open ioctl setattr };"},
		{"xperm structural: duplicate identical TUNSETIFF whitelist rule", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl 0x54ca;"},
		{"xperm structural: parallel TUNSETIFF whitelist rule (brace form)", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl { 0x54ca };"},
		{"xperm structural: TUNSETIFF split across two rules (union = the surface, wrong shape)", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl { 0x54ca };\nallowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl 0x54ca;"},
		{"xperm widened set { 0x54ca 0x54cb } (the RootlessKit set is NOT the helper's)", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x54cb };"},
		{"xperm widened +0x54cc (any third TUN command)", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x54cc };"},
		{"xperm widened +0x54c9", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x54c9 };"},
		{"xperm widened +0x1234 (an arbitrary non-TUN command)", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x1234 };"},
		{"xperm widened range 0x54ca-0x54cb", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl 0x54ca-0x54cb;"},
		{"xperm widened complement ~{ 0x54ca }", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl ~{ 0x54ca };"},
		{"xperm replaced by 0x54cb only (TUNSETPERSIST)", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl 0x54cb;"},
		{"xperm replaced by 0x54c9 only (wrong single command)", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl 0x54c9;"},
		{"helper tun_socket create pre-grant", "allow docker_helper_slirp4netns_t self:tun_socket create;"},
		{"helper tun_socket attach_queue pre-grant", "allow docker_helper_slirp4netns_t self:tun_socket attach_queue;"},
		{"helper tun_socket relabel pre-grant", "allow docker_helper_slirp4netns_t self:tun_socket { relabelfrom relabelto };"},
		{"cross-domain tun_socket structural: duplicate identical relabel rule", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket relabelfrom;"},
		{"cross-domain tun_socket structural: parallel relabel rule (brace form)", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket { relabelfrom };"},
		{"cross-domain tun_socket structural: relabel split across two rules", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket relabelfrom;\nallow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket relabelfrom;"},
		{"cross-domain tun_socket widened +relabelto", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket { relabelfrom relabelto };"},
		{"cross-domain tun_socket widened +attach_queue", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket { relabelfrom attach_queue };"},
		{"cross-domain tun_socket widened +create", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket { relabelfrom create };"},
		{"cross-domain tun_socket widened +getattr", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket { relabelfrom getattr };"},
		{"cross-domain tun_socket widened +read/write", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket { relabelfrom read write };"},
		{"cross-domain tun_socket wrong target (self)", "allow docker_helper_slirp4netns_t self:tun_socket relabelfrom;"},
		{"cross-domain tun_socket wrong target (uid-map helper)", "allow docker_helper_slirp4netns_t docker_helper_newuidmap_t:tun_socket relabelfrom;"},
		{"self tun_socket structural: duplicate identical relabelto rule", "allow docker_helper_slirp4netns_t self:tun_socket relabelto;"},
		{"self tun_socket structural: parallel relabelto rule (brace form)", "allow docker_helper_slirp4netns_t self:tun_socket { relabelto };"},
		{"self tun_socket structural: relabelto split across two rules", "allow docker_helper_slirp4netns_t self:tun_socket relabelto;\nallow docker_helper_slirp4netns_t self:tun_socket relabelto;"},
		{"self tun_socket relabelto on the rootlesskit target instead of self", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket relabelto;"},
		{"self tun_socket relabelfrom (the ungranted self-side permission)", "allow docker_helper_slirp4netns_t self:tun_socket relabelfrom;"},
		{"self tun_socket widened +attach_queue", "allow docker_helper_slirp4netns_t self:tun_socket { relabelto attach_queue };"},
		{"self tun_socket widened +create", "allow docker_helper_slirp4netns_t self:tun_socket { relabelto create };"},
		{"self tun_socket widened +getattr", "allow docker_helper_slirp4netns_t self:tun_socket { relabelto getattr };"},
		{"self tun_socket widened both-side relabel brace set", "allow docker_helper_slirp4netns_t self:tun_socket { relabelfrom relabelto };"},
		{"cap_userns net_admin copy from the RootlessKit path", "allow docker_helper_slirp4netns_t self:cap_userns net_admin;"},
		{"plain capability net_admin for the helper", "allow docker_helper_slirp4netns_t self:capability net_admin;"},
		{"cap_userns pre-grant toward the target", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:cap_userns sys_admin;"},
		{"plain capability pre-grant for the helper", "allow docker_helper_slirp4netns_t self:capability sys_admin;"},
		{"cap_userns structural: duplicate identical namespace-join rule", "allow docker_helper_slirp4netns_t self:cap_userns { sys_ptrace sys_admin };"},
		{"cap_userns structural: parallel sys_ptrace rule", "allow docker_helper_slirp4netns_t self:cap_userns sys_ptrace;"},
		{"cap_userns structural: parallel sys_admin rule", "allow docker_helper_slirp4netns_t self:cap_userns sys_admin;"},
		{"cap_userns structural: sys_ptrace/sys_admin split across two rules", "allow docker_helper_slirp4netns_t self:cap_userns sys_ptrace;\nallow docker_helper_slirp4netns_t self:cap_userns sys_admin;"},
		{"cap_userns structural: parallel rule (brace form)", "allow docker_helper_slirp4netns_t self:cap_userns { sys_ptrace };"},
		{"cap_userns widened +sys_chroot", "allow docker_helper_slirp4netns_t self:cap_userns { sys_ptrace sys_admin sys_chroot };"},
		{"cap_userns widened +net_admin", "allow docker_helper_slirp4netns_t self:cap_userns { sys_ptrace sys_admin net_admin };"},
		{"plain capability sys_ptrace for the helper", "allow docker_helper_slirp4netns_t self:capability sys_ptrace;"},
		{"file-read structural: duplicate identical target rule", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:file read;"},
		{"file-read structural: parallel read rule (brace form)", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:file { read };"},
		{"file widened { read open }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:file { read open };"},
		{"file widened { read getattr }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:file { read getattr };"},
		{"file widened { read write }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:file { read write };"},
		{"file widened { read ioctl }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:file { read ioctl };"},
		{"file widened { read execute }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:file { read execute };"},
		{"file widened { read map }", "allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:file { read map };"},
		{"file widened for the entry type", "allow docker_helper_slirp4netns_t docker_helper_slirp4netns_exec_t:file { entrypoint read open execute getattr map ioctl };"},
		{"wrong-target file read toward the uid-map helper", "allow docker_helper_slirp4netns_t docker_helper_newuidmap_t:file read;"},
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
		{"cap_userns sys_admin for helper", "allow docker_helper_slirp4netns_t self:cap_userns sys_admin;", "exactly one self:cap_userns rule may exist for the helper domain"},
		{"helper xperm widened set pre-grant", "allowxperm docker_helper_slirp4netns_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x54cb };", "must be exactly one tun_tap_device_t:chr_file ioctl 0x54ca rule"},
		{"helper tun_socket pre-grant", "allow docker_helper_slirp4netns_t self:tun_socket create;", "no other permission"},
		{"helper plain capability net_admin", "allow docker_helper_slirp4netns_t self:capability net_admin;", "must hold no plain capability/capability2 grants"},
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
	// The UID-map helper's target file surface toward the rootlesskit
	// namespace owner is exactly { write open }; a read/widened variant
	// trips (the 4C-26 target-SID ptrace READ rule is the network
	// helper's boundary, not this domain's).
	newuidPinnedFile := "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:file { write open };"
	countNewuidFile := func(text string) int {
		n := 0
		for _, line := range strings.Split(text, "\n") {
			if strings.TrimSpace(line) == newuidPinnedFile {
				n++
			}
		}
		return n
	}
	if countNewuidFile(policy) != 1 {
		t.Errorf("the UID-map helper's target file grant must be exactly one `{ write open }` rule, found %d", countNewuidFile(policy))
	}
	for _, wrong := range []struct {
		name string
		rule string
	}{
		{"file read variant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:file read;"},
		{"file widened read variant", "allow docker_helper_newuidmap_t docker_helper_rootlesskit_t:file { read open write };"},
	} {
		mutated := strings.Replace(policy, newuidPinnedFile, wrong.rule, 1)
		if countNewuidFile(mutated) == 1 {
			t.Errorf("the UID-map helper's target-file regression %q was not applied", wrong.name)
		}
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
	// The module's cap_userns rules are EXACTLY the four evidenced
	// grants: the rootlesskit child's { sys_admin sys_ptrace sys_chroot
	// net_admin } set, the UID-map helper's sys_admin bit, the GID-map
	// helper's sys_admin bit, and the slirp4netns helper's sys_ptrace
	// bit (all in-namespace, all self-targeted; the GID bit is the R5
	// gid_map-write boundary, the child's sys_ptrace bit is the 4C-3
	// nsenter ptrace_may_access boundary, its sys_chroot bit is the 4C-4
	// mount-namespace reassociation boundary, its net_admin bit is the
	// 4C-15 tun_set_iff() CAP_NET_ADMIN boundary, and the helper's
	// sys_ptrace bit is the 4C-25 proc-namespace-link dereference's
	// ptrace-may-access prerequisite). No other subject — the manager,
	// the launcher, the daemon, or any other helper — gets a cap_userns
	// rule.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, ":cap_userns ") {
			switch trimmed {
			case "allow docker_helper_rootlesskit_t self:cap_userns { sys_admin sys_ptrace sys_chroot net_admin };",
				"allow docker_helper_newuidmap_t self:cap_userns sys_admin;",
				"allow docker_helper_newgidmap_t self:cap_userns sys_admin;",
				"allow docker_helper_slirp4netns_t self:cap_userns { sys_ptrace sys_admin };":
			default:
				t.Errorf("no cap_userns grant may exist beyond the four evidenced in-namespace grants (rootlesskit { sys_admin sys_ptrace sys_chroot net_admin }, UID-map helper sys_admin, GID-map helper sys_admin, slirp4netns { sys_ptrace sys_admin }): %s", trimmed)
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
					"allow docker_helper_newgidmap_t self:cap_userns sys_admin;",
					"allow docker_helper_slirp4netns_t self:cap_userns { sys_ptrace sys_admin };":
				default:
					violations = append(violations, fmt.Sprintf("no cap_userns rule may exist beyond the four evidenced in-namespace grants (rootlesskit { sys_admin sys_ptrace sys_chroot net_admin }, newuidmap sys_admin, newgidmap sys_admin, slirp4netns { sys_ptrace sys_admin }; the manager, the launcher, and other subjects get none): %s", trimmed))
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

// TestSELinuxPolicyRootlesskitRootMounton owns the exact surface of the
// 4C-39 root mount-propagation grant: docker_helper_rootlesskit_t ->
// root_t:dir { mounton }. The grant exists because the rootlesskit
// child's mount-namespace setup issues mount("none", "/", ...) — the
// "share mount point: /" step — and the canonical 4C-38 run's primary
// boundary was exactly this check (denied 0x10000, result=-13, 39µs
// before the holder's exit(1), rootlesskit's "failed to share mount
// point: /: permission denied"). The surface is exact: one rule, one
// permission. relabelto is the 4C-38 DECODER MISREAD of the same
// record's 0x10000 mask (dir:relabelto is 0x100, dir:mounton is
// 0x10000 — see TestSELinuxPermissionNumericValues) and must never
// become policy; no other domain may receive root_t authority from
// this module, and the flow child's dir-mounton authority is unique to
// the root mount.
func TestSELinuxPolicyRootlesskitRootMounton(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, want := range []string{
		"type root_t;",
		"allow docker_helper_rootlesskit_t root_t:dir mounton;",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the rootlesskit child domain's root mount-propagation surface must be exact: %q", want)
		}
	}
	pinnedRootMounton := "allow docker_helper_rootlesskit_t root_t:dir mounton;"
	countExact := func(text, rule string) int {
		n := 0
		for _, line := range strings.Split(text, "\n") {
			if strings.TrimSpace(line) == rule {
				n++
			}
		}
		return n
	}
	// rootMountonViolations returns one violation per line of module text
	// that breaks the grant's invariants: exactly one allow rule may name
	// docker_helper_rootlesskit_t -> root_t, in the exact bare-mounton
	// dir shape (no brace form, no split rules, no duplicates); no other
	// permission (relabelto first) and no other class may ride the
	// rootlesskit_t -> root_t pair; no other subject may receive root_t
	// authority from this module; and the flow child's dir-mounton
	// authority is granted on exactly THREE targets — root_t (this rule,
	// 4C-39), tmp_t (the copy-up bind-mount target, owned by
	// TestSELinuxPolicyRootlesskitTmpDirWrite since 4C-43) and etc_t (the
	// tmpfs-mount target, owned by TestSELinuxPolicyRootlesskitEtcMounton
	// since 4C-44) — any other target stays ungranted.
	rootMountonViolations := func(text string) []string {
		var violations []string
		count := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			switch {
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t root_t:"):
				count++
				if trimmed != pinnedRootMounton {
					violations = append(violations, "the root mount-propagation grant must be the exact bare-mounton dir shape (no brace form, no split rules, no second permission — relabelto is the 4C-38 decoder misread and must never become policy): "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " root_t:"):
				violations = append(violations, "root_t authority is unique to the rootlesskit child domain: "+trimmed)
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t ") &&
				strings.Contains(trimmed, ":dir ") && strings.Contains(trimmed, "mounton") &&
				!strings.Contains(trimmed, " tmp_t:") && !strings.Contains(trimmed, " etc_t:") &&
				!strings.Contains(trimmed, " tmpfs_t:") && !strings.Contains(trimmed, " cgroup_t:"):
				violations = append(violations, "the flow child's dir mounton authority is granted only on root_t (4C-39), tmp_t (the copy-up owner), etc_t (the tmpfs-mount owner), tmpfs_t (the 4C-47 move-mount owner) and cgroup_t (the 4C-49 cgroup-preservation move owner) — any other target is ungranted: "+trimmed)
			}
		}
		if count == 0 {
			violations = append(violations, "the root mount-propagation grant (rootlesskit_t -> root_t:dir mounton) is missing")
		} else if count > 1 {
			violations = append(violations, fmt.Sprintf("exactly one root_t grant may exist for the rootlesskit child domain, found %d", count))
		}
		return violations
	}
	if violations := rootMountonViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the root mount-propagation invariants: %v", violations)
	}
	// The replacement regressions: each replacement must APPLY (the
	// pinned rule's count changes) and must actually trip the
	// invariants — the owner pins the effective surface, so any other
	// shape fails it.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing whole rule", ""},
		{"missing mounton (relabelto-only shape — the 4C-38 decoder misread)", "allow docker_helper_rootlesskit_t root_t:dir relabelto;"},
		{"relabelto instead of mounton", "allow docker_helper_rootlesskit_t root_t:dir relabelto;"},
		{"mounton + relabelto brace set", "allow docker_helper_rootlesskit_t root_t:dir { mounton relabelto };"},
		{"duplicate identical rule", pinnedRootMounton + "\n" + pinnedRootMounton},
		{"parallel mounton rule (brace form)", pinnedRootMounton + "\nallow docker_helper_rootlesskit_t root_t:dir { mounton };"},
		{"equivalent brace-single-perm shape", "allow docker_helper_rootlesskit_t root_t:dir { mounton };"},
		{"wrong target type", "allow docker_helper_rootlesskit_t var_t:dir mounton;"},
	} {
		mutated := strings.Replace(policy, pinnedRootMounton, regressed.rule, 1)
		applied := func() bool {
			if regressed.rule == "" {
				return countExact(mutated, pinnedRootMounton) == 0
			}
			return strings.Contains(mutated, regressed.rule)
		}
		if !applied() {
			t.Errorf("the root-mounton regression %q was not applied", regressed.name)
			continue
		}
		if len(rootMountonViolations(mutated)) == 0 {
			t.Errorf("the root-mounton regression %q must fail the root mount-propagation invariants", regressed.name)
		}
	}
	// The widening sweep: { mounton <X> } for every other dir permission
	// — relabelto first — must fail the invariants in every case.
	for _, extra := range []string{
		"relabelto", "setattr", "write", "create", "search", "add_name",
		"remove_name", "rmdir", "reparent", "getattr", "open", "read",
		"ioctl", "lock", "link", "unlink", "rename", "map",
		"execmod", "audit_access",
	} {
		mutated := strings.Replace(policy, pinnedRootMounton,
			fmt.Sprintf("allow docker_helper_rootlesskit_t root_t:dir { mounton %s };", extra), 1)
		if countExact(mutated, pinnedRootMounton) == 1 {
			t.Errorf("the root-mounton widening +%s was not applied", extra)
			continue
		}
		if len(rootMountonViolations(mutated)) == 0 {
			t.Errorf("the root-mounton widening +%s must fail the root mount-propagation invariants", extra)
		}
	}
	// The subject regressions: no other domain may gain root_t authority
	// (the manager/launcher/helper shapes, the misread's relabelto
	// included), appended beside the real grant.
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"root mounton for the manager", "allow docker_helper_builder_t root_t:dir mounton;"},
		{"root mounton for the launcher", "allow docker_helper_builder_launcher_t root_t:dir mounton;"},
		{"root mounton for the network helper", "allow docker_helper_slirp4netns_t root_t:dir mounton;"},
		{"root relabelto for the manager (the misdecode widened)", "allow docker_helper_builder_t root_t:dir relabelto;"},
		{"root relabelto for the network helper", "allow docker_helper_slirp4netns_t root_t:dir relabelto;"},
	} {
		if len(rootMountonViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the root mount-propagation invariants", mut.name)
		}
	}
}

// TestSELinuxPolicyRootlesskitTmpDirWrite owns the exact surface of the
// tmp copy-up grant as widened by 4C-43: docker_helper_rootlesskit_t ->
// tmp_t:dir { write add_name create mounton }. The grant exists because
// the rootlesskit child's copy-up path on /tmp — the MkdirTemp mkdir(2)
// and the bind mount onto the created temp dir — is mediated by exactly
// these four dir permissions, each from its own live enforcing boundary:
// write was the canonical 4C-39 run's (37101080574) causal boundary
// (denied 0x4), add_name the canonical 4C-40 run's (37104707444) —
// denied 0x4000000 inside the SAME sys_mkdirat window, create the
// canonical 4C-41 run's (37107847258) — denied 0x8 in the same window
// with the target type LIVE-PROVEN as tmp_t (mkdirat then returned 0x0 —
// the ROOTLESSKIT-BIND0-CREATE milestone, the residue's real SID
// confirmed), mounton the canonical 4C-42 run's (37109745209) — denied
// 0x10000 INSIDE the failing bind-mount window
// (sys_mount("/etc", "/tmp/rootlesskit-b...", MS_BIND|MS_REC) -> -13),
// 175µs before the holder's exit(1). All raw kernel decisions, the
// audit slice silent in all windows (the measured userspace-audit gap),
// all decodes pinned by the kernel's own static classmap
// (TestSELinuxPermissionKernelClassmapDecode). The surface is exact:
// one rule, exactly these four permissions. The 4C-39 write record's
// requested mask carried 0x20000000 (dir:search) NOT denied — search
// passed on the base policy's standing surface and must NOT ride this
// grant. The failed launches' RemoveAll surface (remove_name/read) must
// NOT ride this grant — those denials sit AFTER the failing mount and
// are POST-FAILURE/CLEANUP (the 4C-42 report's correction); no other
// class may be granted on tmp_t from this module; no other subject may
// receive tmp_t authority; and a confusable sibling target (user_tmp_t)
// is not the evidenced pair.
func TestSELinuxPolicyRootlesskitTmpDirWrite(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, want := range []string{
		"type tmp_t;",
		"allow docker_helper_rootlesskit_t tmp_t:dir { write add_name create mounton };",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the rootlesskit child domain's tmp copy-up surface must be exact: %q", want)
		}
	}
	pinnedTmpDirWrite := "allow docker_helper_rootlesskit_t tmp_t:dir { write add_name create mounton };"
	countExact := func(text, rule string) int {
		n := 0
		for _, line := range strings.Split(text, "\n") {
			if strings.TrimSpace(line) == rule {
				n++
			}
		}
		return n
	}
	// tmpDirWriteViolations returns one violation per line of module text
	// that breaks the grant's invariants: exactly one allow rule may name
	// docker_helper_rootlesskit_t -> tmp_t, in the exact brace dir shape
	// { write add_name create mounton } (no split rules, no duplicates,
	// no fifth permission — search rides the base policy's standing
	// surface, remove_name/read/rmdir are the RemoveAll cleanup surface,
	// setattr/rename and every other dir permission are ungranted); no
	// other class (file/lnk_file/sock_file/...) may ride the
	// rootlesskit_t -> tmp_t pair; no other subject may receive tmp_t
	// authority from this module; and a rootlesskit-subject rule naming a
	// tmp_t-suffixed sibling target (user_tmp_t) is a confusable shape
	// the evidenced pair does not cover.
	tmpDirWriteViolations := func(text string) []string {
		var violations []string
		count := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			switch {
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmp_t:"):
				count++
				if trimmed != pinnedTmpDirWrite {
					violations = append(violations, "the tmp copy-up grant must be the exact { write add_name create mounton } dir shape (no split rules, no duplicates, no fifth permission — search rides the standing base surface, the RemoveAll surface stays cleanup): "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " tmp_t:"):
				violations = append(violations, "tmp_t authority is unique to the rootlesskit child domain: "+trimmed)
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t ") &&
				strings.Contains(trimmed, "tmp_t:") && !strings.Contains(trimmed, " tmp_t:"):
				violations = append(violations, "the flow child's tmp copy-up authority names a confusable sibling target (user_tmp_t is not the evidenced tmp_t): "+trimmed)
			}
		}
		if count == 0 {
			violations = append(violations, "the tmp copy-up grant (rootlesskit_t -> tmp_t:dir { write add_name create mounton }) is missing")
		} else if count > 1 {
			violations = append(violations, fmt.Sprintf("exactly one tmp_t grant may exist for the rootlesskit child domain, found %d", count))
		}
		return violations
	}
	if violations := tmpDirWriteViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the tmp copy-up invariants: %v", violations)
	}
	// The replacement regressions: each replacement must APPLY (the
	// pinned rule's count changes) and must actually trip the
	// invariants — the owner pins the effective surface, so any other
	// shape fails it.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing whole rule", ""},
		{"missing write", "allow docker_helper_rootlesskit_t tmp_t:dir { add_name create mounton };"},
		{"missing add_name", "allow docker_helper_rootlesskit_t tmp_t:dir { write create mounton };"},
		{"missing create", "allow docker_helper_rootlesskit_t tmp_t:dir { write add_name mounton };"},
		{"missing mounton (the pre-4C-43 { write add_name create } shape)", "allow docker_helper_rootlesskit_t tmp_t:dir { write add_name create };"},
		{"mounton-only", "allow docker_helper_rootlesskit_t tmp_t:dir mounton;"},
		{"relabelto instead of mounton", "allow docker_helper_rootlesskit_t tmp_t:dir { write add_name create relabelto };"},
		{"write add_name create relabelto brace set", "allow docker_helper_rootlesskit_t tmp_t:dir { write add_name create relabelto };"},
		{"+ remove_name", "allow docker_helper_rootlesskit_t tmp_t:dir { write add_name create mounton remove_name };"},
		{"+ read", "allow docker_helper_rootlesskit_t tmp_t:dir { write add_name create mounton read };"},
		{"+ rmdir", "allow docker_helper_rootlesskit_t tmp_t:dir { write add_name create mounton rmdir };"},
		{"+ setattr", "allow docker_helper_rootlesskit_t tmp_t:dir { write add_name create mounton setattr };"},
		{"duplicate identical rule", pinnedTmpDirWrite + "\n" + pinnedTmpDirWrite},
		{"parallel mounton rule (bare form)", pinnedTmpDirWrite + "\nallow docker_helper_rootlesskit_t tmp_t:dir mounton;"},
		{"split mounton rule", pinnedTmpDirWrite + "\nallow docker_helper_rootlesskit_t tmp_t:dir { mounton };"},
		{"structural brace-single equivalent", "allow docker_helper_rootlesskit_t tmp_t:dir { write add_name };\nallow docker_helper_rootlesskit_t tmp_t:dir { create mounton };"},
		{"wrong target type", "allow docker_helper_rootlesskit_t var_t:dir { write add_name create mounton };"},
		{"confusable sibling target (user_tmp_t)", "allow docker_helper_rootlesskit_t user_tmp_t:dir { write add_name create mounton };"},
	} {
		mutated := strings.Replace(policy, pinnedTmpDirWrite, regressed.rule, 1)
		applied := func() bool {
			if regressed.rule == "" {
				return countExact(mutated, pinnedTmpDirWrite) == 0
			}
			return strings.Contains(mutated, regressed.rule)
		}
		if !applied() {
			t.Errorf("the tmp-dir-write regression %q was not applied", regressed.name)
			continue
		}
		if len(tmpDirWriteViolations(mutated)) == 0 {
			t.Errorf("the tmp-dir-write regression %q must fail the tmp copy-up invariants", regressed.name)
		}
	}
	// The widening sweep: { write add_name create mounton <X> } for every
	// other dir permission — the RemoveAll cleanup surface first — must
	// fail the invariants in every case.
	for _, extra := range []string{
		"remove_name", "read", "rmdir", "search", "setattr", "reparent",
		"getattr", "open", "ioctl", "lock", "link", "unlink", "rename",
		"map", "relabelfrom", "relabelto", "execmod", "audit_access",
	} {
		mutated := strings.Replace(policy, pinnedTmpDirWrite,
			fmt.Sprintf("allow docker_helper_rootlesskit_t tmp_t:dir { write add_name create mounton %s };", extra), 1)
		if countExact(mutated, pinnedTmpDirWrite) == 1 {
			t.Errorf("the tmp-dir-write widening +%s was not applied", extra)
			continue
		}
		if len(tmpDirWriteViolations(mutated)) == 0 {
			t.Errorf("the tmp-dir-write widening +%s must fail the tmp copy-up invariants", extra)
		}
	}
	// The subject regressions: no other domain may gain tmp_t authority
	// (the manager/launcher/helper shapes), appended beside the real
	// grant.
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"tmp dir quartet for the manager", "allow docker_helper_builder_t tmp_t:dir { write add_name create mounton };"},
		{"tmp dir quartet for the launcher", "allow docker_helper_builder_launcher_t tmp_t:dir { write add_name create mounton };"},
		{"tmp dir quartet for the network helper", "allow docker_helper_slirp4netns_t tmp_t:dir { write add_name create mounton };"},
		{"tmp dir quartet for the uid-map helper", "allow docker_helper_newuidmap_t tmp_t:dir { write add_name create mounton };"},
		{"tmp dir quartet for the gid-map helper", "allow docker_helper_newgidmap_t tmp_t:dir { write add_name create mounton };"},
		{"tmp file write for the flow child (no other class rides the pair)", "allow docker_helper_rootlesskit_t tmp_t:file write;"},
		{"parallel mounton-only rule (bare)", "allow docker_helper_rootlesskit_t tmp_t:dir mounton;"},
		{"tmp dir remove_name for the flow child (the RemoveAll cleanup stays forbidden)", "allow docker_helper_rootlesskit_t tmp_t:dir remove_name;"},
	} {
		if len(tmpDirWriteViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the tmp copy-up invariants", mut.name)
		}
	}
}

// TestSELinuxPolicyRootlesskitEtcMounton owns the exact surface of the
// 4C-44 etc copy-up grant: docker_helper_rootlesskit_t -> etc_t:dir
// { mounton }. The grant exists because the copy-up flow's tmpfs mount
// over the source directory issues mount("none", "/etc", "tmpfs", 0)
// and the canonical 4C-43 run's (37143508859) next causal boundary was
// exactly this check (requested=0x10000 denied=0x10000, result=-13,
// tcontext=etc_t:s0, INSIDE the C-mount's sys_mount window, 21µs before
// the first failing syscall exit, T0+3ms). The target type is the
// distro's own /etc label etc_t — NOT root_t and NOT tmp_t; a NEW
// evidenced pair granted as its OWN rule (the three mounton targets —
// root_t/tmp_t/etc_t — stay three distinct evidenced pairs). The
// surface is exact: one rule, one permission. Deliberately NOT granted:
// etc_t:dir write/add_name/create (the .ro creation — the NEXT
// boundaries, whose target types materialize live), read/remove_name/
// rmdir/setattr/rename (the scan/rebuild steps), any filesystem-class
// permission (a superblock hook, if reached, owns its own phase —
// never auto-converted), every other etc_t permission, any new
// tmp_t/root_t grant, any other class, any other subject.
func TestSELinuxPolicyRootlesskitEtcMounton(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, want := range []string{
		"type etc_t;",
		"allow docker_helper_rootlesskit_t etc_t:dir mounton;",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the rootlesskit child domain's etc copy-up surface must be exact: %q", want)
		}
	}
	pinnedEtcMounton := "allow docker_helper_rootlesskit_t etc_t:dir mounton;"
	countExact := func(text, rule string) int {
		n := 0
		for _, line := range strings.Split(text, "\n") {
			if strings.TrimSpace(line) == rule {
				n++
			}
		}
		return n
	}
	// etcMountonViolations returns one violation per line of module text
	// that breaks the grant's invariants: exactly one allow rule may name
	// docker_helper_rootlesskit_t -> etc_t, in the exact bare-mounton
	// dir shape (no brace form, no split rules, no second permission);
	// no other subject may receive etc_t authority from this module; and
	// the sibling-family confusion (user_tmp_t-style confusables have no
	// etc_t sibling here, but a root_t/tmp_t target mixed into the rule
	// would be a different pair's authority) is covered by the exact
	// line pin.
	etcMountonViolations := func(text string) []string {
		var violations []string
		count := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			switch {
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t etc_t:"):
				count++
				if trimmed != pinnedEtcMounton {
					violations = append(violations, "the etc copy-up grant must be the exact bare-mounton dir shape (no brace form, no split rules, no second permission — the .ro/scan steps are the NEXT boundaries): "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " etc_t:"):
				violations = append(violations, "etc_t authority is unique to the rootlesskit child domain: "+trimmed)
			}
		}
		if count == 0 {
			violations = append(violations, "the etc copy-up grant (rootlesskit_t -> etc_t:dir mounton) is missing")
		} else if count > 1 {
			violations = append(violations, fmt.Sprintf("exactly one etc_t grant may exist for the rootlesskit child domain, found %d", count))
		}
		return violations
	}
	if violations := etcMountonViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the etc copy-up invariants: %v", violations)
	}
	// The replacement regressions: each replacement must APPLY and must
	// actually trip the invariants.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing whole rule", ""},
		{"missing mounton (mounton-less standing-only shape)", "allow docker_helper_rootlesskit_t etc_t:dir getattr;"},
		{"relabelto instead of mounton", "allow docker_helper_rootlesskit_t etc_t:dir relabelto;"},
		{"mounton relabelto brace set", "allow docker_helper_rootlesskit_t etc_t:dir { mounton relabelto };"},
		{"duplicate identical rule", pinnedEtcMounton + "\n" + pinnedEtcMounton},
		{"parallel mounton rule (brace form)", pinnedEtcMounton + "\nallow docker_helper_rootlesskit_t etc_t:dir { mounton };"},
		{"equivalent brace-single-perm shape", "allow docker_helper_rootlesskit_t etc_t:dir { mounton };"},
		{"wrong target type (root_t)", "allow docker_helper_rootlesskit_t root_t:dir mounton;"},
		{"wrong target type (tmp_t)", "allow docker_helper_rootlesskit_t tmp_t:dir mounton;"},
		{"wrong target type (var_t)", "allow docker_helper_rootlesskit_t var_t:dir mounton;"},
	} {
		mutated := strings.Replace(policy, pinnedEtcMounton, regressed.rule, 1)
		applied := func() bool {
			if regressed.rule == "" {
				return countExact(mutated, pinnedEtcMounton) == 0
			}
			return strings.Contains(mutated, regressed.rule)
		}
		if !applied() {
			t.Errorf("the etc-mounton regression %q was not applied", regressed.name)
			continue
		}
		if len(etcMountonViolations(mutated)) == 0 {
			t.Errorf("the etc-mounton regression %q must fail the etc copy-up invariants", regressed.name)
		}
	}
	// The widening sweep: { mounton <X> } for every other dir permission
	// — the .ro/scan surfaces first — must fail the invariants in every
	// case.
	for _, extra := range []string{
		"write", "add_name", "create", "remove_name", "read", "rmdir",
		"search", "setattr", "reparent", "getattr", "open", "ioctl",
		"lock", "link", "unlink", "rename", "map", "relabelfrom",
		"relabelto", "execmod", "audit_access",
	} {
		mutated := strings.Replace(policy, pinnedEtcMounton,
			fmt.Sprintf("allow docker_helper_rootlesskit_t etc_t:dir { mounton %s };", extra), 1)
		if countExact(mutated, pinnedEtcMounton) == 1 {
			t.Errorf("the etc-mounton widening +%s was not applied", extra)
			continue
		}
		if len(etcMountonViolations(mutated)) == 0 {
			t.Errorf("the etc-mounton widening +%s must fail the etc copy-up invariants", extra)
		}
	}
	// The subject regressions: no other domain may gain etc_t authority
	// (the manager/launcher/helper shapes), appended beside the real
	// grant.
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"etc mounton for the manager", "allow docker_helper_builder_t etc_t:dir mounton;"},
		{"etc mounton for the launcher", "allow docker_helper_builder_launcher_t etc_t:dir mounton;"},
		{"etc mounton for the network helper", "allow docker_helper_slirp4netns_t etc_t:dir mounton;"},
		{"etc mounton for the uid-map helper", "allow docker_helper_newuidmap_t etc_t:dir mounton;"},
		{"etc mounton for the gid-map helper", "allow docker_helper_newgidmap_t etc_t:dir mounton;"},
	} {
		if len(etcMountonViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the etc copy-up invariants", mut.name)
		}
	}
}

// TestSELinuxPolicyRootlesskitTmpfsFilesystemMount owns the exact surface
// of the 4C-45 tmpfs superblock grant: docker_helper_rootlesskit_t ->
// tmpfs_t:filesystem { mount }. The grant exists because the copy-up
// flow's tmpfs mount over /etc — after PASSING the granted etc_t:dir
// mounton stage (4C-44's progression proof) — is denied at the NEW
// superblock's own filesystem-class check: the canonical 4C-44 run
// (37145319964) recorded requested=0x1 denied=0x1 result=-13
// tcontext=tmpfs_t:s0 tclass=filesystem INSIDE the C-mount window
// (mount("none", "/etc", "tmpfs", 0) -> -13), 14µs before the first
// failing syscall exit. The class is the evidence — filesystem, never a
// dir permission; the target is the superblock's own type tmpfs_t.
// SCOPE — a GLOBAL-TYPE grant: tmpfs_t:s0 carries no per-operation MCS
// category, so this allow is not operation-scoped (the nsfs_t scope
// shape); the cross-operation gate stays mandatory. The surface is
// exact: one rule, one permission. Deliberately NOT granted:
// remount/unmount/getattr/associate/mounton/relabelfrom/relabelto on
// this pair, any second filesystem rule, any dir/file surface of the
// next copy-up steps (their target types materialize live — after the
// tmpfs mount the labels are NOT assumed), any other class, any other
// subject.
func TestSELinuxPolicyRootlesskitTmpfsFilesystemMount(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	for _, want := range []string{
		"allow docker_helper_rootlesskit_t tmpfs_t:filesystem mount;",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the rootlesskit child domain's tmpfs superblock surface must be exact: %q", want)
		}
	}
	pinnedTmpfsMount := "allow docker_helper_rootlesskit_t tmpfs_t:filesystem mount;"
	countExact := func(text, rule string) int {
		n := 0
		for _, line := range strings.Split(text, "\n") {
			if strings.TrimSpace(line) == rule {
				n++
			}
		}
		return n
	}
	// tmpfsMountViolations returns one violation per line of module text
	// that breaks the grant's invariants: exactly one allow rule may name
	// docker_helper_rootlesskit_t -> tmpfs_t:filesystem, in the exact
	// bare-mount shape (no brace form, no split rules, no second
	// filesystem permission — remount/unmount/getattr/associate/mounton/
	// relabel* are distinct hooks); no tmpfs_t:dir mounton may ride (the
	// dir-class confusion); no other subject may receive tmpfs_t
	// filesystem authority from this module.
	tmpfsMountViolations := func(text string) []string {
		var violations []string
		count := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			switch {
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:filesystem"):
				count++
				if trimmed != pinnedTmpfsMount {
					violations = append(violations, "the tmpfs superblock grant must be the exact bare-mount filesystem shape (no brace form, no split rules, no second permission — remount/unmount/getattr/associate/mounton/relabel* are distinct hooks): "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " tmpfs_t:filesystem"):
				// The daemon's own getattr grant (the trusted-CA era,
				// pre-existing) is the one other tmpfs_t:filesystem
				// rule; any other subject or a widened daemon rule is
				// module-borne authority beyond the two evidenced
				// surfaces.
				if trimmed != "allow docker_helper_t tmpfs_t:filesystem { getattr };" {
					violations = append(violations, "tmpfs_t filesystem authority outside the two evidenced rules (the flow child's mount and the daemon's getattr) is forbidden: "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:") &&
				!strings.Contains(trimmed, " tmpfs_t:dir ") &&
				!strings.Contains(trimmed, " tmpfs_t:lnk_file ") &&
				!strings.Contains(trimmed, " tmpfs_t:file "):
				// The dir-class surface of tmpfs_t has its own owner
				// (the 4C-46 .ro create grant — TestSELinuxPolicy-
				// RootlesskitTmpfsDir); the file-class surface has
				// its own owner too (the 4C-54/55 replacement-file
				// surface — TestSELinuxPolicyRootlesskitTmpfsFile);
				// this filesystem pair's invariant is only
				// that no OTHER-class surface rides here. The
				// trailing space keeps "tmpfs_t:file" from matching
				// "tmpfs_t:filesystem" (this case's own class).
				violations = append(violations, "the flow child's tmpfs_t authority beyond the evidenced filesystem-mount and dir-create pairs is forbidden: "+trimmed)
			}
		}
		if count == 0 {
			violations = append(violations, "the tmpfs superblock grant (rootlesskit_t -> tmpfs_t:filesystem mount) is missing")
		} else if count > 1 {
			violations = append(violations, fmt.Sprintf("exactly one tmpfs_t:filesystem grant may exist for the rootlesskit child domain, found %d", count))
		}
		return violations
	}
	if violations := tmpfsMountViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the tmpfs superblock invariants: %v", violations)
	}
	// The replacement regressions: each replacement must APPLY and must
	// actually trip the invariants.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing whole rule", ""},
		{"missing mount (getattr-only shape)", "allow docker_helper_rootlesskit_t tmpfs_t:filesystem getattr;"},
		{"remount instead of mount", "allow docker_helper_rootlesskit_t tmpfs_t:filesystem remount;"},
		{"mount remount brace set", "allow docker_helper_rootlesskit_t tmpfs_t:filesystem { mount remount };"},
		{"mount unmount brace set", "allow docker_helper_rootlesskit_t tmpfs_t:filesystem { mount unmount };"},
		{"mount getattr brace set", "allow docker_helper_rootlesskit_t tmpfs_t:filesystem { mount getattr };"},
		{"mount associate brace set", "allow docker_helper_rootlesskit_t tmpfs_t:filesystem { mount associate };"},
		{"duplicate identical rule", pinnedTmpfsMount + "\n" + pinnedTmpfsMount},
		{"parallel mount rule (brace form)", pinnedTmpfsMount + "\nallow docker_helper_rootlesskit_t tmpfs_t:filesystem { mount };"},
		{"equivalent brace-single-perm shape", "allow docker_helper_rootlesskit_t tmpfs_t:filesystem { mount };"},
		{"wrong target filesystem type (fs_t)", "allow docker_helper_rootlesskit_t fs_t:filesystem mount;"},
		{"wrong class (tmpfs_t:dir mounton)", "allow docker_helper_rootlesskit_t tmpfs_t:dir mounton;"},
	} {
		mutated := strings.Replace(policy, pinnedTmpfsMount, regressed.rule, 1)
		applied := func() bool {
			if regressed.rule == "" {
				return countExact(mutated, pinnedTmpfsMount) == 0
			}
			return strings.Contains(mutated, regressed.rule)
		}
		if !applied() {
			t.Errorf("the tmpfs-mount regression %q was not applied", regressed.name)
			continue
		}
		if len(tmpfsMountViolations(mutated)) == 0 {
			t.Errorf("the tmpfs-mount regression %q must fail the tmpfs superblock invariants", regressed.name)
		}
	}
	// The widening sweep: { mount <X> } for every other filesystem
	// permission must fail the invariants in every case.
	for _, extra := range []string{
		"remount", "unmount", "getattr", "associate", "mounton",
		"relabelfrom", "relabelto",
	} {
		mutated := strings.Replace(policy, pinnedTmpfsMount,
			fmt.Sprintf("allow docker_helper_rootlesskit_t tmpfs_t:filesystem { mount %s };", extra), 1)
		if countExact(mutated, pinnedTmpfsMount) == 1 {
			t.Errorf("the tmpfs-mount widening +%s was not applied", extra)
			continue
		}
		if len(tmpfsMountViolations(mutated)) == 0 {
			t.Errorf("the tmpfs-mount widening +%s must fail the tmpfs superblock invariants", extra)
		}
	}
	// The subject regressions: no other domain may gain tmpfs_t
	// filesystem authority (the manager/launcher/helper shapes and the
	// dir-class confusion), appended beside the real grant.
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"tmpfs filesystem mount for the manager", "allow docker_helper_builder_t tmpfs_t:filesystem mount;"},
		{"tmpfs filesystem mount for the launcher", "allow docker_helper_builder_launcher_t tmpfs_t:filesystem mount;"},
		{"tmpfs filesystem mount for the network helper", "allow docker_helper_slirp4netns_t tmpfs_t:filesystem mount;"},
	} {
		if len(tmpfsMountViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the tmpfs superblock invariants", mut.name)
		}
	}
}

// TestSELinuxPolicyRootlesskitTmpfsDir owns the whole evidenced module
// surface of the copy-up `.ro` dir pair: docker_helper_rootlesskit_t ->
// tmpfs_t:dir = exactly { create mounton }. Provenance stays per-perm:
//
//   - create — the canonical 4C-45 run (37147831964) recorded
//     requested=0x8 denied=0x8 result=-13 tcontext=tmpfs_t:s0
//     tclass=dir INSIDE the .ro mkdirat window
//     (mkdirat(AT_FDCWD, "/etc/.ro1295760542", 0700) -> -13), 25µs
//     before the first failing syscall exit; the child SID is
//     inherited from the tmpfs root's own label tmpfs_t:s0 (the
//     live-proven pair, NOT an assumed etc_t/tmp_t); added by 4C-46.
//   - mounton — the canonical 4C-46 run (37151310682) recorded
//     requested=0x10000 denied=0x10000 result=-13 tcontext=tmpfs_t:s0
//     tclass=dir INSIDE the move-mount window
//     (mount("/tmp/rootlesskit-b806505358", "/etc/.ro1982736738", "",
//     MS_MOVE, 0) -> -13), 25µs before the first failing syscall
//     exit; the target-dir mediation of the moved mount's own label;
//     added by 4C-47.
//
// The class is the evidence — a dir pair, never the filesystem pair's
// rule (4C-45's separate owner); the two tmpfs_t rules stay separate
// owners (different classes, different hooks, different provenance).
// The parent-side add_name/remove_name/write are already STANDING
// base-policy attribute authority — this module must not copy them.
// SCOPE — a GLOBAL-TYPE grant (tmpfs_t:s0): not operation-scoped (the
// nsfs_t scope shape); the cross-operation gate stays mandatory.
// Deliberately NOT granted: add_name/write/remove_name/rmdir/read/
// setattr/rename/relabel* on this pair, any file/lnk_file/blk/chr
// surface of the tmpfs (the rebuild stages' target types materialize
// live), any second dir rule, any filesystem-class permission, any
// other class, any other subject.
func TestSELinuxPolicyRootlesskitTmpfsDir(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	pinnedTmpfsDirCreate := "allow docker_helper_rootlesskit_t tmpfs_t:dir { create mounton };"
	if !strings.Contains(policy, pinnedTmpfsDirCreate) {
		t.Fatalf("the rootlesskit child domain's .ro dir-create surface must be exact: %q", pinnedTmpfsDirCreate)
	}
	// tmpfsDirViolations returns one violation per line of module text
	// that breaks the grant's invariants: exactly one allow rule may name
	// docker_helper_rootlesskit_t -> tmpfs_t:dir, in the exact brace-pair
	// shape { create mounton } (no split rules, no second dir permission
	// — add_name/write/remove_name/rmdir/read/setattr/rename/relabel*
	// are distinct hooks; the first three are STANDING base-policy
	// authority and must not be copied into this module); no other
	// subject may receive tmpfs_t:dir authority from this module; no
	// tmpfs_t:filesystem create/mounton may ride (the class confusion).
	tmpfsDirViolations := func(text string) []string {
		var violations []string
		count := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			switch {
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:dir"):
				count++
				if trimmed != pinnedTmpfsDirCreate {
					violations = append(violations, "the .ro dir grant must be the exact brace-pair shape { create mounton } (no split rules, no second permission — add_name/write/remove_name/rmdir/read/setattr/rename/relabel* are distinct hooks; the first three are standing base-policy authority, not module content): "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " tmpfs_t:dir"):
				violations = append(violations, "tmpfs_t dir authority is unique to the rootlesskit child domain's pinned pair rule: "+trimmed)
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:filesystem") && strings.Contains(trimmed, " create"):
				violations = append(violations, "the class confusion is forbidden — create is a dir-class permission, the filesystem pair's rule stays bare-mount: "+trimmed)
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:filesystem") && strings.Contains(trimmed, " mounton"):
				violations = append(violations, "the class confusion is forbidden — mounton is a dir-class permission here, the filesystem pair's rule stays bare-mount: "+trimmed)
			}
		}
		if count == 0 {
			violations = append(violations, "the .ro dir grant (rootlesskit_t -> tmpfs_t:dir { create mounton }) is missing")
		} else if count > 1 {
			violations = append(violations, fmt.Sprintf("exactly one tmpfs_t:dir grant may exist for the rootlesskit child domain, found %d", count))
		}
		return violations
	}
	if violations := tmpfsDirViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the .ro dir invariants: %v", violations)
	}
	// The replacement regressions: each replacement must APPLY and must
	// actually trip the invariants.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing whole rule", ""},
		{"pre-4C-47 shape (create only)", "allow docker_helper_rootlesskit_t tmpfs_t:dir { create };"},
		{"pre-4C-47 shape (bare create)", "allow docker_helper_rootlesskit_t tmpfs_t:dir create;"},
		{"missing create (mounton-only)", "allow docker_helper_rootlesskit_t tmpfs_t:dir { mounton };"},
		{"missing mounton (create-only)", "allow docker_helper_rootlesskit_t tmpfs_t:dir { create };"},
		{"mounton-only bare shape", "allow docker_helper_rootlesskit_t tmpfs_t:dir mounton;"},
		{"relabelto instead of mounton", "allow docker_helper_rootlesskit_t tmpfs_t:dir { create relabelto };"},
		{"widened add_name", "allow docker_helper_rootlesskit_t tmpfs_t:dir { create mounton add_name };"},
		{"widened write", "allow docker_helper_rootlesskit_t tmpfs_t:dir { create mounton write };"},
		{"widened remove_name", "allow docker_helper_rootlesskit_t tmpfs_t:dir { create mounton remove_name };"},
		{"widened setattr", "allow docker_helper_rootlesskit_t tmpfs_t:dir { create mounton setattr };"},
		{"widened rename", "allow docker_helper_rootlesskit_t tmpfs_t:dir { create mounton rename };"},
		{"duplicate identical rule", pinnedTmpfsDirCreate + "\n" + pinnedTmpfsDirCreate},
		{"parallel old-shape rule", pinnedTmpfsDirCreate + "\nallow docker_helper_rootlesskit_t tmpfs_t:dir { create };"},
		{"split into two bare rules", "allow docker_helper_rootlesskit_t tmpfs_t:dir create;\nallow docker_helper_rootlesskit_t tmpfs_t:dir mounton;"},
		{"split into two bare rules (reversed)", "allow docker_helper_rootlesskit_t tmpfs_t:dir mounton;\nallow docker_helper_rootlesskit_t tmpfs_t:dir create;"},
		{"wrong target type (tmp_t — the standing quartet's own pair)", "allow docker_helper_rootlesskit_t tmp_t:dir create;"},
		{"wrong target type (etc_t)", "allow docker_helper_rootlesskit_t etc_t:dir create;"},
		{"wrong class (tmpfs_t:filesystem create)", "allow docker_helper_rootlesskit_t tmpfs_t:filesystem create;"},
		{"wrong class (tmpfs_t:filesystem mounton)", "allow docker_helper_rootlesskit_t tmpfs_t:filesystem mounton;"},
	} {
		mutated := strings.Replace(policy, pinnedTmpfsDirCreate, regressed.rule, 1)
		applied := func() bool {
			if regressed.rule == "" {
				return !strings.Contains(mutated, pinnedTmpfsDirCreate)
			}
			return strings.Contains(mutated, regressed.rule)
		}
		if !applied() {
			t.Errorf("the .ro dir regression %q was not applied", regressed.name)
			continue
		}
		if len(tmpfsDirViolations(mutated)) == 0 {
			t.Errorf("the .ro dir regression %q must fail the .ro dir invariants", regressed.name)
		}
	}
	// The widening sweep: { create mounton <X> } for every other dir
	// permission must fail the invariants in every case.
	for _, extra := range []string{
		"add_name", "remove_name", "rmdir", "read", "setattr",
		"rename", "write", "unlink", "symlink", "search", "getattr",
		"relabelto", "reparent", "watch", "watch_reads", "quotaget",
		"quotamod", "ioctl", "lock", "execmod",
	} {
		mutated := strings.Replace(policy, pinnedTmpfsDirCreate,
			fmt.Sprintf("allow docker_helper_rootlesskit_t tmpfs_t:dir { create mounton %s };", extra), 1)
		if !strings.Contains(mutated, fmt.Sprintf("allow docker_helper_rootlesskit_t tmpfs_t:dir { create mounton %s };", extra)) {
			t.Errorf("the .ro dir widening +%s was not applied", extra)
			continue
		}
		if len(tmpfsDirViolations(mutated)) == 0 {
			t.Errorf("the .ro dir widening +%s must fail the .ro dir invariants", extra)
		}
	}
	// The subject regressions: no other domain may gain tmpfs_t dir
	// authority, appended beside the real grant.
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"tmpfs dir pair for the manager", "allow docker_helper_builder_t tmpfs_t:dir { create mounton };"},
		{"tmpfs dir pair for the launcher", "allow docker_helper_builder_launcher_t tmpfs_t:dir { create mounton };"},
		{"tmpfs dir pair for the network helper", "allow docker_helper_slirp4netns_t tmpfs_t:dir { create mounton };"},
		{"tmpfs dir pair for the daemon", "allow docker_helper_t tmpfs_t:dir { create mounton };"},
	} {
		if len(tmpfsDirViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the .ro dir invariants", mut.name)
		}
	}
}

// TestSELinuxPolicyRootlesskitTmpfsSymlink owns the whole evidenced
// module surface of the rebuild-symlink triple: docker_helper_rootlesskit_t
// -> tmpfs_t:lnk_file = exactly { create read unlink }. ONE pair, ONE rule,
// widened IN PLACE per phase — never two parallel owners for the same
// pair/class. Provenance stays per-perm:
//
//   - create — the canonical 4C-47 run (37153317223) recorded
//     requested=0x8 denied=0x8 result=-13 tcontext=tmpfs_t:s0
//     tclass=lnk_file INSIDE the symlinkat(".ro2286969802/.pwd.lock" ->
//     "/etc/.pwd.lock") window, 16µs before the failing exit; the
//     symlink object's own creation check (may_create with
//     SECCLASS_LNK_FILE, the SID inherited from the parent dir's label
//     tmpfs_t:s0); added by 4C-48.
//   - read — the canonical 4C-49 run (37191972618) recorded
//     requested=0x2 denied=0x2 result=-13 tcontext=tmpfs_t:s0
//     tclass=lnk_file INSIDE the openat("/etc/hosts", O_RDONLY|
//     O_CLOEXEC) window — generateEtcHosts()'s os.ReadFile, the
//     startup's first /etc read — 9µs before the failing exit; the link
//     traversal's own read hook (followed-symlink mediation), the same
//     pair/class shape the flow's earlier /etc/localtime openat hit as a
//     HANDLED/NON-TERMINAL probe; added by 4C-50.
//   - unlink — the canonical 4C-52 run's terminal boundary (the 4C-52
//     phase-end record NEXT-STARTUP-BOUNDARY: scontext=
//     docker_helper_rootlesskit_t:s0:c1 tcontext=tmpfs_t:s0
//     tclass=lnk_file, denied { unlink }) INSIDE the
//     RemoveAll("/etc/resolv.conf") stage's own unlinkat("/etc/
//     resolv.conf", 0) window — the setupNet resolv-replacement step's
//     DESTINATION symlink-removal hook, the SAME pair the create and
//     read hooks own; added by 4C-53.
//
// The read is the LINK-TRAVERSAL hook, not the resolved target's own
// file access: the original /etc file behind the rebuilt link (on the
// .ro mount's own labels) mediates on its own type/class and its
// read/open pair is the net_conf_t:file owner's separate grant (4C-51/
// 4C-52). The class is the evidence — an lnk_file triple, never the
// tmpfs_t:dir { create mounton } pair (4C-46/47's separate owner),
// never the tmpfs_t:filesystem mount rule (4C-45's separate owner),
// never a tmpfs_t:file surface. SCOPE — a GLOBAL-TYPE grant (tmpfs_t:
// s0): not operation-scoped (the nsfs_t scope shape); the
// cross-operation gate stays mandatory. Deliberately NOT granted:
// write/getattr/setattr/link/rename/relabelfrom/relabelto or any other
// lnk_file permission on this pair (each a distinct hook — the link()
// stage's own link permission is NOT this create, and the setupNet
// replacement stages' write hooks stay ungranted), any
// dir/file/filesystem permission, any other type's lnk_file surface,
// any other class, any other subject.
func TestSELinuxPolicyRootlesskitTmpfsSymlink(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	pinnedSymlinkTriple := "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read unlink };"
	pinnedTmpfsDirPair := "allow docker_helper_rootlesskit_t tmpfs_t:dir { create mounton };"
	pinnedTmpfsFsMount := "allow docker_helper_rootlesskit_t tmpfs_t:filesystem mount;"
	pinnedTmpfsFileCreate := "allow docker_helper_rootlesskit_t tmpfs_t:file { create write open mounton };"
	if !strings.Contains(policy, pinnedSymlinkTriple) {
		t.Fatalf("the rootlesskit child domain's rebuild-symlink surface must be exact: %q", pinnedSymlinkTriple)
	}
	// symlinkTripleViolations returns one violation per line of module
	// text that breaks the grant invariants: exactly one allow rule may
	// name docker_helper_rootlesskit_t -> tmpfs_t:lnk_file, in the exact
	// brace-triple shape { create read unlink } (no bare single-perm
	// shape, no split rules, no reordering — { read create unlink } is a
	// different written shape, no missing member — the pre-4C-53
	// { create read } shape is the old boundary that must not return,
	// and unlink-only/create+unlink/read+unlink shapes are incomplete
	// hook sets — no fourth permission — write/getattr/setattr/link/
	// rename/relabel* are distinct hooks); no other subject may receive
	// tmpfs_t:lnk_file authority from this module; no tmpfs_t:file
	// surface may ride (the class confusion); the tmpfs_t:dir and
	// tmpfs_t:filesystem surfaces stay their own owners' exact rules.
	symlinkTripleViolations := func(text string) []string {
		var violations []string
		count := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			switch {
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file"):
				count++
				if trimmed != pinnedSymlinkTriple {
					violations = append(violations, "the rebuild-symlink grant must be the exact brace-triple lnk_file shape { create read unlink } (no bare shape, no split rules, no reorder, no missing member — the pre-4C-53 pair shape is the old unlink boundary — and no fourth permission — write/getattr/setattr/link/rename/relabel* are distinct hooks): "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " tmpfs_t:lnk_file"):
				violations = append(violations, "tmpfs_t lnk_file authority is unique to the rootlesskit child domain's pinned triple rule: "+trimmed)
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:file "):
				// The 4C-54/55: the tmpfs_t:file surface has its OWN
				// owner now (the replacement resolv.conf regular-file
				// surface rule, widened in place to the exact brace
				// triple { create write open }) — the class confusion
				// is no longer "any file-class rule"; the file surface
				// must be exactly the file owner's pinned triple rule,
				// and any other file shape is forbidden here. The
				// trailing space in the prefix keeps "tmpfs_t:file"
				// from matching "tmpfs_t:filesystem".
				if trimmed != pinnedTmpfsFileCreate {
					violations = append(violations, "the tmpfs_t:file surface belongs to the 4C-54/55/56 owner's exact brace quartet { create write open mounton }; any other file shape is forbidden here: "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:dir"):
				if trimmed != pinnedTmpfsDirPair {
					violations = append(violations, "the tmpfs_t:dir surface belongs to the 4C-46/47 owner's exact pair; any other dir shape is forbidden here: "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:filesystem"):
				if trimmed != pinnedTmpfsFsMount {
					violations = append(violations, "the tmpfs_t:filesystem surface belongs to the 4C-45 owner's exact bare-mount rule; any other filesystem shape is forbidden here: "+trimmed)
				}
			}
		}
		if count == 0 {
			violations = append(violations, "the rebuild-symlink grant (rootlesskit_t -> tmpfs_t:lnk_file { create read unlink }) is missing")
		} else if count > 1 {
			violations = append(violations, fmt.Sprintf("exactly one tmpfs_t:lnk_file grant may exist for the rootlesskit child domain, found %d", count))
		}
		return violations
	}
	if violations := symlinkTripleViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the rebuild-symlink invariants: %v", violations)
	}
	// The replacement regressions: each replacement must APPLY and must
	// actually trip the invariants.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing whole rule", ""},
		{"pre-4C-50 shape (bare create)", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file create;"},
		{"pre-4C-50 shape (brace create)", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create };"},
		{"pre-4C-53 shape (the 4C-52-era pair, missing unlink)", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read };"},
		{"missing create (read-only bare shape)", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file read;"},
		{"missing create (read-only brace shape)", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { read };"},
		{"unlink-only shape (missing create read)", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file unlink;"},
		{"unlink-only brace shape (missing create read)", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { unlink };"},
		{"create unlink without read", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create unlink };"},
		{"read unlink without create", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { read unlink };"},
		{"write instead of read", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create write };"},
		{"getattr instead of read", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create getattr };"},
		{"write instead of unlink", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read write };"},
		{"getattr instead of unlink", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read getattr };"},
		{"setattr instead of unlink", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read setattr };"},
		{"link instead of unlink", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read link };"},
		{"rename instead of unlink", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read rename };"},
		{"create read unlink write brace set", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read unlink write };"},
		{"create read unlink getattr brace set", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read unlink getattr };"},
		{"create read unlink link brace set", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read unlink link };"},
		{"create read unlink rename brace set", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read unlink rename };"},
		{"duplicate identical rule", pinnedSymlinkTriple + "\n" + pinnedSymlinkTriple},
		{"parallel pair rule (brace form)", pinnedSymlinkTriple + "\nallow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read };"},
		{"split into two bare rules (create, read)", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file create;\nallow docker_helper_rootlesskit_t tmpfs_t:lnk_file read;"},
		{"split into two bare rules (read, create)", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file read;\nallow docker_helper_rootlesskit_t tmpfs_t:lnk_file create;"},
		{"split into bare create and parallel brace-read rule", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file create;\nallow docker_helper_rootlesskit_t tmpfs_t:lnk_file { read };"},
		{"split into bare read and parallel brace-unlink rule", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file read;\nallow docker_helper_rootlesskit_t tmpfs_t:lnk_file { unlink };"},
		{"reordered brace content (read create unlink)", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { read create unlink };"},
		{"wrong class (tmpfs_t:file read)", "allow docker_helper_rootlesskit_t tmpfs_t:file read;"},
		{"wrong class (tmpfs_t:dir read)", "allow docker_helper_rootlesskit_t tmpfs_t:dir read;"},
		{"wrong target type (tmp_t)", "allow docker_helper_rootlesskit_t tmp_t:lnk_file { create read unlink };"},
		{"wrong target type (etc_t)", "allow docker_helper_rootlesskit_t etc_t:lnk_file { create read unlink };"},
	} {
		mutated := strings.Replace(policy, pinnedSymlinkTriple, regressed.rule, 1)
		applied := func() bool {
			if regressed.rule == "" {
				return !strings.Contains(mutated, pinnedSymlinkTriple)
			}
			return strings.Contains(mutated, regressed.rule)
		}
		if !applied() {
			t.Errorf("the rebuild-symlink regression %q was not applied", regressed.name)
			continue
		}
		if len(symlinkTripleViolations(mutated)) == 0 {
			t.Errorf("the rebuild-symlink regression %q must fail the rebuild-symlink invariants", regressed.name)
		}
	}
	// The widening sweep: { create read unlink <X> } for every other
	// lnk_file permission must fail the invariants in every case (the
	// fourth-permission sweep; the third-permission sweep — unlink
	// replaced by another hook — is covered by the regressions above).
	for _, extra := range []string{
		"write", "getattr", "setattr", "lock", "relabelfrom", "relabelto",
		"append", "map", "link", "rename", "execute", "quotaon",
		"mounton", "audit_access", "open", "execmod",
	} {
		mutated := strings.Replace(policy, pinnedSymlinkTriple,
			fmt.Sprintf("allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read unlink %s };", extra), 1)
		if !strings.Contains(mutated, fmt.Sprintf("allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read unlink %s };", extra)) {
			t.Errorf("the rebuild-symlink widening +%s was not applied", extra)
			continue
		}
		if len(symlinkTripleViolations(mutated)) == 0 {
			t.Errorf("the rebuild-symlink widening +%s must fail the rebuild-symlink invariants", extra)
		}
	}
	// The subject regressions: no other domain may gain tmpfs_t lnk_file
	// authority, appended beside the real grant.
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"tmpfs lnk_file triple for the manager", "allow docker_helper_builder_t tmpfs_t:lnk_file { create read unlink };"},
		{"tmpfs lnk_file triple for the launcher", "allow docker_helper_builder_launcher_t tmpfs_t:lnk_file { create read unlink };"},
		{"tmpfs lnk_file triple for the network helper", "allow docker_helper_slirp4netns_t tmpfs_t:lnk_file { create read unlink };"},
		{"tmpfs lnk_file triple for the daemon", "allow docker_helper_t tmpfs_t:lnk_file { create read unlink };"},
		{"tmpfs lnk_file bare unlink for the manager", "allow docker_helper_builder_t tmpfs_t:lnk_file unlink;"},
	} {
		if len(symlinkTripleViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the rebuild-symlink invariants", mut.name)
		}
	}
}

// TestSELinuxPolicyRootlesskitTmpfsFile owns the whole evidenced module
// surface of the replacement /etc/resolv.conf regular-file creation:
// docker_helper_rootlesskit_t -> tmpfs_t:file = exactly the brace
// quartet { create write open mounton } (4C-54 granted exactly
// { create }; 4C-55 widened the SAME rule in place with the combined
// write|open boundary; 4C-56 widened it again in place with the bind
// mount's mounton boundary — one owner, no second rule). A NEW
// pair/class surface — never merged into the tmpfs_t:lnk_file
// { create read unlink } triple (the 4C-48/50/53 owner), the
// tmpfs_t:dir { create mounton } pair (the 4C-46/47 owner), or the
// tmpfs_t:filesystem mount (the 4C-45 owner).
//
// Live enforcing evidence, canonical 4C-53 run 37350350345: with the
// lnk_file unlink removal hook granted, the resolv-replacement stage's
// RemoveAll completed (the rebuilt destination symlink actually
// removed: the AT_FDCWD unlinkat("/etc/resolv.conf", 0) pair ret 0x0 at
// trace-ts 234.517271..234.517283; the fresh run's first pass was
// legitimately -ENOENT — RemoveAll's own contract makes "the path does
// not exist" a completed removal) and the flow's very next production
// step — the replacement file's own creation — failed at the file's own
// create hook:
//
//	sys_openat(dfd: AT_FDCWD, filename: "/etc/resolv.conf",
//	flags: O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, mode: 0644)
//	enter trace-ts 234.517284, exit 234.517318
//
// with the denial INSIDE the openat(2) window (trace-ts 234.517307,
// 11µs before the failing openat exit; T0 = the attach at trace-ts
// 234.476447, the failing exit at T0+0.041s, no later production
// progress): requested=0x8 denied=0x8 audited=0x8 result=-13 (EACCES)
// scontext=system_u:system_r:docker_helper_rootlesskit_t:s0:c1
// tcontext=system_u:object_r:tmpfs_t:s0 tclass=file.
//
// THE DECODER CORRECTION this owner pins: the kernel's AVC bitmap for
// the file class follows COMMON_FILE_PERMS — ioctl=0x1 read=0x2
// write=0x4 create=0x8 getattr=0x10 — the same kernel-classmap order
// every live-proven association of this staircase uses. Raw 0x8 on
// tclass=file is the CREATE hook, not write (the 4C-53 deliverable's
// raw {write} decode was produced from the loaded policy's perms-file
// VALUES — the policy's own numbering, with the distro's swapon entry
// diverging from the kernel's file common — and is corrected; the
// classmap fixture below and TestSELinuxPermissionKernelClassmapDecode
// pin the authoritative decode).
//
// THE 4C-55 COMBINED-BOUNDARY DELTA this owner pins: the canonical
// 4C-54 run 37370262779's SAME openat(O_CREAT) window (enter trace-ts
// 186.870735, exit 186.870759, ret 0xfffffffffffffff3, who exe-24175)
// carried ONE combined decision, trace-ts 186.870752: requested=0x40004
// denied=0x40004 audited=0x40004 result=-13 (EACCES)
// tcontext=system_u:object_r:tmpfs_t:s0 tclass=file — decoded per
// COMMON_FILE_PERMS as exactly { write open } (write=bit 2, open=bit
// 18). One audited decision, denied simultaneously, inside one terminal
// openat, neither permission ever granted before — one evidenced
// boundary, widened as one grant, no one-bit-per-phase split and no bit
// beyond the denied mask. The hooks: the open-completion hook
// (security_file_open → selinux_file_open) requests FILE__OPEN with the
// f_mode-derived FILE__WRITE in ONE check; the kernel's own do_open()
// strips O_TRUNC and zeroes acc_mode for freshly created (FMODE_CREATED)
// files, so the O_TRUNC setattr hook (0x20) is NOT on the fresh-file
// path and the openat returns fd >= 0 once create+write+open are
// granted. Deliberately NOT granted: read/getattr/setattr/append/map/
// unlink/link/rename/execute/lock or any other file permission — each
// a distinct hook, and this is deliberately NOT the typical file-RW
// bundle (read stays ungranted: the file is written blind, never read
// back); the fd is REQUIRED for the 4C-55 recreate milestone (the
// replacement regular file successfully created/opened), while the
// write(2) syscall is NOT (the SELinux file:write permission was
// already checked at the open-completion hook via the file's f_mode;
// a zero-length payload legitimately has no write(2)).
//
// THE 4C-56 MOUNTON DELTA this owner pins: the canonical 4C-55 run
// 37414244341's SAME replacement stage completed the whole recreate
// chain (the resolv openat ret 0x3 = fd 3 at trace-ts
// 173.273944..173.273963 with the zero-length write ret 0x0 and the
// close ret 0x0; the hosts equivalents on the SAME surfaces: the
// unlinkat ret 0x0 on the standing lnk_file unlink, the openat ret 0x3
// with NO denial) and then failed at the flow's next production step —
// the generated-file bind mount:
//
//	sys_mount(dev_name: ... "/var/lib/docker-helper-builder/ops/
//	op_2290e535.../resolv.conf", dir_name: ... "/etc/resolv.conf",
//	flags: 0x1000 (MS_BIND), data: 0)
//	enter trace-ts 173.274006, exit 173.274025
//
// with the denial INSIDE the mount(2) window (trace-ts 173.274015,
// 10µs before the failing mount exit; T0 = the attach at trace-ts
// 173.241903, the failing exit at T0+0.032s, no later production
// progress): requested=0x10000 denied=0x10000 audited=0x10000
// result=-13 (EACCES)
// scontext=system_u:system_r:docker_helper_rootlesskit_t:s0:c1
// tcontext=system_u:object_r:tmpfs_t:s0 tclass=file. The hook:
// security_mount → selinux_mount → path_has_perm() on the MOUNTPOINT
// — FILE__MOUNTON = bit 16 = 0x10000 of COMMON_FILE_PERMS (quotaon bit
// 15 = 0x8000, audit_access bit 17 = 0x20000, open bit 18 = 0x40000);
// the denial's tcontext is the just-recreated replacement file's own
// LIVE type (tmpfs_t — the created inode inherited the parent dir's
// type; not a pathname-derived assumption). The source-side lookup ran
// before and passed (no source-side denial exists in the window; no
// source-side permission is granted here). SCOPE CAVEAT: type-wide TE
// authority — NOT path-scoped, NOT operation-scoped (tmpfs_t:s0
// carries no per-operation MCS category); the acceptance re-proves per
// canonical run: the holder's mount namespace is its own and distinct
// from every manager-side reference, the recursive-private propagation
// pair precedes the moves, and the host-side mount table stays CLEAN.
// PROVEN: the observed mount operation is confined to the production
// holder's private mount namespace. NOT PROVEN: tmpfs_t:file mounton
// is cross-operation safe as type-wide TE authority (the
// cross-operation gate stays OPEN/Critical; the Release GO stays
// CLOSED).
func TestSELinuxPolicyRootlesskitTmpfsFile(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	pinnedTmpfsFileSurface := "allow docker_helper_rootlesskit_t tmpfs_t:file { create write open mounton };"
	pinnedSymlinkTriple := "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read unlink };"
	pinnedTmpfsDirPair := "allow docker_helper_rootlesskit_t tmpfs_t:dir { create mounton };"
	pinnedTmpfsFsMount := "allow docker_helper_rootlesskit_t tmpfs_t:filesystem mount;"
	pinnedNetconfPair := "allow docker_helper_rootlesskit_t net_conf_t:file { read open };"
	if !strings.Contains(policy, pinnedTmpfsFileSurface) {
		t.Fatalf("the rootlesskit child domain's replacement-file surface must be exact: %q", pinnedTmpfsFileSurface)
	}
	// fileSurfaceViolations returns one violation per line of module
	// text that breaks the grant invariants: exactly one allow rule may
	// name docker_helper_rootlesskit_t -> tmpfs_t:file, in the exact
	// brace-quartet shape { create write open mounton } (no bare
	// single-perm shape — mounton-only is the pre-4C-56 boundary; no
	// pre-4C-56 triple shape — { create write open } is the old
	// boundary that must not return; no missing member — any
	// three-of-four set is an incomplete hook set, and the 4C-54
	// phase's own forbidden shape { create write } stays forbidden as
	// the missing-open form; no fifth permission — read/getattr/
	// setattr/append/map/unlink/link/rename/execute/lock are distinct
	// hooks and this is deliberately NOT the file-RW bundle; no split
	// rules — bare or brace pairs reconstruct the same surface as
	// separate grants; no duplicate; no reorder — a different written
	// shape). No other subject may receive tmpfs_t:file
	// authority from this module; the lnk_file/dir/filesystem surfaces
	// stay their own owners' exact rules; the net_conf_t:file pair
	// stays the 4C-51/52 owner's exact rule.
	fileSurfaceViolations := func(text string) []string {
		var violations []string
		count := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			switch {
			// "file " (with the trailing space) — "tmpfs_t:file" is a
			// prefix of "tmpfs_t:filesystem"; the class token's own
			// boundary discriminates them.
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:file "):
				count++
				if trimmed != pinnedTmpfsFileSurface {
					violations = append(violations, "the replacement-file grant must be the exact brace quartet { create write open mounton } (no bare shape — the pre-4C-56 mounton-only boundary, no pre-4C-56 triple — { create write open } is the old boundary that must not return, no split rules, no duplicate, no reorder, no missing member — any three-of-four set is an incomplete hook set, no fifth permission — read/getattr/setattr/append/map/unlink/link/rename/execute/lock are distinct hooks and this is deliberately NOT the file-RW bundle): "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " tmpfs_t:file "):
				violations = append(violations, "tmpfs_t file authority is unique to the rootlesskit child domain's pinned replacement-file surface rule: "+trimmed)
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file"):
				if trimmed != pinnedSymlinkTriple {
					violations = append(violations, "the tmpfs_t:lnk_file surface belongs to the 4C-48/50/53 owner's exact triple; any other lnk_file shape is forbidden here: "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:dir"):
				if trimmed != pinnedTmpfsDirPair {
					violations = append(violations, "the tmpfs_t:dir surface belongs to the 4C-46/47 owner's exact pair; any other dir shape is forbidden here: "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t tmpfs_t:filesystem"):
				if trimmed != pinnedTmpfsFsMount {
					violations = append(violations, "the tmpfs_t:filesystem surface belongs to the 4C-45 owner's exact bare-mount rule; any other filesystem shape is forbidden here: "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t net_conf_t:file"):
				if trimmed != pinnedNetconfPair {
					violations = append(violations, "the net_conf_t:file surface belongs to the 4C-51/52 owner's exact pair; any other net_conf file shape is forbidden here: "+trimmed)
				}
			}
		}
		if count == 0 {
			violations = append(violations, "the replacement-file surface grant (rootlesskit_t -> tmpfs_t:file { create write open mounton }) is missing")
		} else if count > 1 {
			violations = append(violations, fmt.Sprintf("exactly one tmpfs_t:file grant may exist for the rootlesskit child domain, found %d", count))
		}
		return violations
	}
	if violations := fileSurfaceViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the replacement-file surface invariants: %v", violations)
	}
	// The replacement regressions: each replacement must APPLY and must
	// actually trip the invariants.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing whole rule", ""},
		{"the pre-4C-55 bare create shape", "allow docker_helper_rootlesskit_t tmpfs_t:file create;"},
		{"the pre-4C-55 brace-create shape", "allow docker_helper_rootlesskit_t tmpfs_t:file { create };"},
		{"the pre-4C-56 triple shape (the old boundary must not return)", "allow docker_helper_rootlesskit_t tmpfs_t:file { create write open };"},
		{"missing mounton (create write open)", "allow docker_helper_rootlesskit_t tmpfs_t:file { create write open };"},
		{"missing create (write open mounton)", "allow docker_helper_rootlesskit_t tmpfs_t:file { write open mounton };"},
		{"missing write (create open mounton)", "allow docker_helper_rootlesskit_t tmpfs_t:file { create open mounton };"},
		{"missing open (create write mounton)", "allow docker_helper_rootlesskit_t tmpfs_t:file { create write mounton };"},
		{"mounton-only", "allow docker_helper_rootlesskit_t tmpfs_t:file mounton;"},
		{"mounton replaced by getattr", "allow docker_helper_rootlesskit_t tmpfs_t:file { create write open getattr };"},
		{"mounton replaced by setattr", "allow docker_helper_rootlesskit_t tmpfs_t:file { create write open setattr };"},
		{"mounton replaced by relabelto", "allow docker_helper_rootlesskit_t tmpfs_t:file { create write open relabelto };"},
		{"fifth perm getattr", "allow docker_helper_rootlesskit_t tmpfs_t:file { create write open mounton getattr };"},
		{"fifth perm setattr", "allow docker_helper_rootlesskit_t tmpfs_t:file { create write open mounton setattr };"},
		{"fifth perm unlink", "allow docker_helper_rootlesskit_t tmpfs_t:file { create write open mounton unlink };"},
		{"duplicate identical rule", pinnedTmpfsFileSurface + "\n" + pinnedTmpfsFileSurface},
		{"parallel brace rule", pinnedTmpfsFileSurface + "\nallow docker_helper_rootlesskit_t tmpfs_t:file { create write open mounton };"},
		{"reordered brace quartet", "allow docker_helper_rootlesskit_t tmpfs_t:file { mounton open write create };"},
		{"split into bare mounton and parallel brace triple", "allow docker_helper_rootlesskit_t tmpfs_t:file mounton;\nallow docker_helper_rootlesskit_t tmpfs_t:file { create write open };"},
		{"split into two brace pairs", "allow docker_helper_rootlesskit_t tmpfs_t:file { create write };\nallow docker_helper_rootlesskit_t tmpfs_t:file { open mounton };"},
		{"wrong class (tmpfs_t:dir mounton)", "allow docker_helper_rootlesskit_t tmpfs_t:dir mounton;"},
		{"wrong class (tmpfs_t:lnk_file mounton)", "allow docker_helper_rootlesskit_t tmpfs_t:lnk_file mounton;"},
		{"wrong target type (tmp_t)", "allow docker_helper_rootlesskit_t tmp_t:file { create write open mounton };"},
		{"wrong target type (net_conf_t)", "allow docker_helper_rootlesskit_t net_conf_t:file { create write open mounton };"},
	} {
		mutated := strings.Replace(policy, pinnedTmpfsFileSurface, regressed.rule, 1)
		applied := func() bool {
			if regressed.rule == "" {
				return !strings.Contains(mutated, pinnedTmpfsFileSurface)
			}
			return strings.Contains(mutated, regressed.rule)
		}
		if !applied() {
			t.Errorf("the replacement-file surface regression %q was not applied", regressed.name)
			continue
		}
		if len(fileSurfaceViolations(mutated)) == 0 {
			t.Errorf("the replacement-file surface regression %q must fail the replacement-file surface invariants", regressed.name)
		}
	}
	// The widening sweep: { create write open mounton <X> } for every
	// other file-class permission must fail the invariants in every
	// case (the fifth-permission sweep; the single/pair/triple
	// replacements are covered by the regressions above).
	for _, extra := range []string{
		"ioctl", "read", "getattr", "setattr", "lock",
		"relabelfrom", "relabelto", "append", "map", "unlink", "link",
		"rename", "execute", "quotaon", "audit_access",
		"execmod", "watch", "watch_mount", "watch_sb",
		"watch_with_perm", "watch_reads", "watch_mountns",
		"execute_no_trans", "entrypoint",
	} {
		mutated := strings.Replace(policy, pinnedTmpfsFileSurface,
			fmt.Sprintf("allow docker_helper_rootlesskit_t tmpfs_t:file { create write open mounton %s };", extra), 1)
		if !strings.Contains(mutated, fmt.Sprintf("allow docker_helper_rootlesskit_t tmpfs_t:file { create write open mounton %s };", extra)) {
			t.Errorf("the replacement-file widening +%s was not applied", extra)
			continue
		}
		if len(fileSurfaceViolations(mutated)) == 0 {
			t.Errorf("the replacement-file widening +%s must fail the replacement-file surface invariants", extra)
		}
	}
	// The subject regressions: no other domain may gain tmpfs_t file
	// authority, appended beside the real grant.
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"tmpfs file quartet for the manager", "allow docker_helper_builder_t tmpfs_t:file { create write open mounton };"},
		{"tmpfs file quartet for the launcher", "allow docker_helper_builder_launcher_t tmpfs_t:file { create write open mounton };"},
		{"tmpfs file quartet for the network helper", "allow docker_helper_slirp4netns_t tmpfs_t:file { create write open mounton };"},
		{"tmpfs file quartet for the daemon", "allow docker_helper_t tmpfs_t:file { create write open mounton };"},
		{"tmpfs file bare mounton for the manager", "allow docker_helper_builder_t tmpfs_t:file mounton;"},
		{"tmpfs file bare write for the manager", "allow docker_helper_builder_t tmpfs_t:file write;"},
		{"tmpfs file bare create for the manager (the old boundary)", "allow docker_helper_builder_t tmpfs_t:file create;"},
	} {
		if len(fileSurfaceViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the replacement-file surface invariants", mut.name)
		}
	}
}

// TestSELinuxPolicyRootlesskitNetconfFile owns the whole evidenced module
// surface of the resolved /etc/hosts configuration-file read:
// docker_helper_rootlesskit_t -> net_conf_t:file = exactly { read }. The
// RESOLVED TARGET's own regular-file read after the 4C-50 link-traversal
// read passed: the rebuilt /etc/hosts symlink (tmpfs_t:lnk_file, the
// 4C-48/4C-50 pair's owner) traversal succeeded and the SAME
// openat("/etc/hosts", O_RDONLY|O_CLOEXEC) advanced into the resolved
// object's own file-class mediation.
//
// Live enforcing evidence, canonical 4C-50 run 37264978329: the kernel
// decision INSIDE the openat window (trace-ts 279.786326, 13µs before the
// failing exit 279.786339; T0 = the attach at trace-ts 279.762339):
// requested=0x2 denied=0x2 audited=0x2 result=-13 (EACCES)
// scontext=system_u:system_r:docker_helper_rootlesskit_t:s0:c1
// tcontext=system_u:object_r:net_conf_t:s0 tclass=file, with the direct
// userspace failure "[rootlesskit:child ] error: open /etc/hosts:
// permission denied." and exit_group(1). Confirmed in three observations:
// the 4C-50 harness run 37263373116's canonical window (c1, exe-3796,
// trace-ts 181.091658, the machinery's STARTUP-CAUSAL owner record), the
// canonical run's own window (c1), and the canonical run's companion
// dontaudit-disabled window (c2, exe-15530, trace-ts 379.143815).
//
// The target type is LIVE-PROVEN — the kernel's own tcontext for the
// RESOLVED object (the original /etc/hosts entry behind the rebuilt
// symlink, the moved original /etc tree's label net_conf_t), never a
// pathname inference. The class is the evidence — file, never
// net_conf_t:lnk_file (the traversal's own hook, the tmpfs_t pair's
// owner) and never net_conf_t:dir. The OPEN completion hook ({ open } —
// the separate two-hook open structure the 4C-11/4C-32 boundaries
// proved) is NOT granted here: if it materializes live it owns the next
// phase. SCOPE — a GLOBAL-TYPE grant (net_conf_t:s0, the distro's
// /etc-network-configuration file label): not operation-scoped (the
// nsfs/tmpfs scope shape); the cross-operation gate stays OPEN/Critical.
// Deliberately NOT granted: open/getattr/write/append/lock/create/
// setattr/unlink/rename/link/execute/map/relabelfrom/relabelto or any
// other file permission on this pair, any net_conf_t lnk_file/dir
// surface, any other subject's bare-read shape (the daemon's own braced
// rule { read open getattr } is the prior live-evidenced contribution
// and stays intact), any other class, any other subject.
func TestSELinuxPolicyRootlesskitNetconfFile(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	pinnedNetconfPair := "allow docker_helper_rootlesskit_t net_conf_t:file { read open };"
	pinnedDaemonNetconf := "allow docker_helper_t net_conf_t:file { read open getattr };"
	if !strings.Contains(policy, pinnedNetconfPair) {
		t.Fatalf("the rootlesskit child domain's resolved-/etc read-open pair must be exact: %q", pinnedNetconfPair)
	}
	// netconfPairViolations returns one violation per line of module text
	// that breaks the pair invariants: exactly one allow rule may name
	// docker_helper_rootlesskit_t -> net_conf_t:file, in the exact brace
	// pair shape { read open } (the 4C-50 read evidence and the 4C-51
	// open evidence are the pair's two recorded provenances; no bare
	// single-perm form, no split read/open rules, no reordered brace
	// form, no second rule — getattr/write/append/setattr/create/unlink/
	// rename/link/execute/map/relabel* are distinct hooks, and the
	// pre-4C-52 read-only shape is the old boundary that must not
	// return); no other subject may name net_conf_t:file with anything
	// but the daemon's braced { read open getattr } rule (the prior
	// live-evidenced contribution, exactly once); no net_conf_t:lnk_file
	// or net_conf_t:dir surface may exist for any subject (the class
	// confusion).
	netconfPairViolations := func(text string) []string {
		var violations []string
		pairCount := 0
		daemonCount := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			switch {
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t net_conf_t:file"):
				pairCount++
				if trimmed != pinnedNetconfPair {
					violations = append(violations, "the resolved-/etc read-open pair must be the exact brace pair shape (no bare single-perm form, no split read/open rules, no reordering, no second rule — getattr/write/append/setattr/create/unlink/rename/link/execute/map/relabel* are distinct hooks): "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " net_conf_t:file"):
				if trimmed == pinnedDaemonNetconf {
					daemonCount++
				} else {
					violations = append(violations, "the daemon's braced net_conf_t:file { read open getattr } rule is the module's only other net_conf_t:file surface: "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " net_conf_t:lnk_file"):
				violations = append(violations, "the class confusion is forbidden — the lnk_file class surface of net_conf_t is not this pair: "+trimmed)
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " net_conf_t:dir"):
				violations = append(violations, "the class confusion is forbidden — the dir class surface of net_conf_t is not this pair: "+trimmed)
			}
		}
		if pairCount == 0 {
			violations = append(violations, "the resolved-/etc read-open pair (rootlesskit_t -> net_conf_t:file { read open }) is missing")
		} else if pairCount > 1 {
			violations = append(violations, fmt.Sprintf("exactly one net_conf_t:file read-open pair may exist for the rootlesskit child domain, found %d", pairCount))
		}
		if daemonCount != 1 {
			violations = append(violations, fmt.Sprintf("the module's own standing daemon net_conf_t read-open-getattr rule must appear exactly once, found %d", daemonCount))
		}
		return violations
	}
	if violations := netconfPairViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the resolved-/etc pair invariants: %v", violations)
	}
	// The replacement regressions: each replacement must APPLY and must
	// actually trip the invariants.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing whole rule", ""},
		{"pre-4C-52 read-only shape (missing open)", "allow docker_helper_rootlesskit_t net_conf_t:file read;"},
		{"open-only shape (missing read)", "allow docker_helper_rootlesskit_t net_conf_t:file open;"},
		{"getattr instead of open", "allow docker_helper_rootlesskit_t net_conf_t:file { read getattr };"},
		{"write instead of open", "allow docker_helper_rootlesskit_t net_conf_t:file { read write };"},
		{"execute instead of open", "allow docker_helper_rootlesskit_t net_conf_t:file { read execute };"},
		{"read open getattr bundle", "allow docker_helper_rootlesskit_t net_conf_t:file { read open getattr };"},
		{"read open write", "allow docker_helper_rootlesskit_t net_conf_t:file { read open write };"},
		{"read open setattr", "allow docker_helper_rootlesskit_t net_conf_t:file { read open setattr };"},
		{"read open execute", "allow docker_helper_rootlesskit_t net_conf_t:file { read open execute };"},
		{"duplicate identical pair rule", pinnedNetconfPair + "\n" + pinnedNetconfPair},
		{"parallel pair rule", pinnedNetconfPair + "\nallow docker_helper_rootlesskit_t net_conf_t:file { open read };"},
		{"reordered brace form (open read)", "allow docker_helper_rootlesskit_t net_conf_t:file { open read };"},
		{"split read/open bare rules", "allow docker_helper_rootlesskit_t net_conf_t:file read;\nallow docker_helper_rootlesskit_t net_conf_t:file open;"},
		{"wrong class (net_conf_t:lnk_file open)", "allow docker_helper_rootlesskit_t net_conf_t:lnk_file open;"},
		{"wrong class (net_conf_t:dir open)", "allow docker_helper_rootlesskit_t net_conf_t:dir open;"},
		{"wrong target type (tmpfs_t)", "allow docker_helper_rootlesskit_t tmpfs_t:file { read open };"},
		{"wrong target type (etc_t)", "allow docker_helper_rootlesskit_t etc_t:file { read open };"},
	} {
		mutated := strings.Replace(policy, pinnedNetconfPair, regressed.rule, 1)
		applied := func() bool {
			if regressed.rule == "" {
				return !strings.Contains(mutated, pinnedNetconfPair)
			}
			return strings.Contains(mutated, regressed.rule)
		}
		if !applied() {
			t.Errorf("the resolved-/etc pair regression %q was not applied", regressed.name)
			continue
		}
		if len(netconfPairViolations(mutated)) == 0 {
			t.Errorf("the resolved-/etc pair regression %q must fail the resolved-/etc pair invariants", regressed.name)
		}
	}
	// The widening sweep: { read open <X> } for every other file
	// permission must fail the invariants in every case.
	for _, extra := range []string{
		"getattr", "setattr", "lock", "append", "create", "unlink", "link",
		"rename", "execute", "execute_no_trans", "map", "execmod", "ioctl",
		"audit_access", "mounton", "quotaon", "swapon", "entrypoint",
		"relabelfrom", "relabelto", "watch", "watch_mount", "watch_mountns",
		"watch_reads", "watch_sb", "watch_with_perm",
	} {
		mutated := strings.Replace(policy, pinnedNetconfPair,
			fmt.Sprintf("allow docker_helper_rootlesskit_t net_conf_t:file { read open %s };", extra), 1)
		if !strings.Contains(mutated, fmt.Sprintf("allow docker_helper_rootlesskit_t net_conf_t:file { read open %s };", extra)) {
			t.Errorf("the resolved-/etc pair widening +%s was not applied", extra)
			continue
		}
		if len(netconfPairViolations(mutated)) == 0 {
			t.Errorf("the resolved-/etc pair widening +%s must fail the resolved-/etc pair invariants", extra)
		}
	}
	// The subject regressions: no other domain may gain the pair shape,
	// appended beside the real pair rule.
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"pair for the manager", "allow docker_helper_builder_t net_conf_t:file { read open };"},
		{"pair for the launcher", "allow docker_helper_builder_launcher_t net_conf_t:file { read open };"},
		{"pair for the network helper", "allow docker_helper_slirp4netns_t net_conf_t:file { read open };"},
		{"pair for the uid-map shim", "allow docker_helper_newuidmap_t net_conf_t:file { read open };"},
		{"bare open for the daemon", "allow docker_helper_t net_conf_t:file open;"},
		{"bare read for the daemon", "allow docker_helper_t net_conf_t:file read;"},
		{"brace read for the daemon", "allow docker_helper_t net_conf_t:file { read };"},
		{"duplicate daemon rule", "allow docker_helper_t net_conf_t:file { read open getattr };"},
	} {
		if len(netconfPairViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the resolved-/etc pair invariants", mut.name)
		}
	}
}

// TestSELinuxPolicyRootlesskitCgroupMounton pins the cgroup preservation
// move-mount's own grant: the rootlesskit child domain's move of its rksys
// bind onto /sys/fs/cgroup (the canonical 4C-48 run's denial: the MS_MOVE
// window's cgroup_t:dir mounton, mask 0x10000 = bit 16 of the kernel's
// static dir classmap, 12us before the failing exit). This is a NEW
// global target type pair with its own security scope, so the grant gets
// its own rule — never folded into the module's own standing cgroup_t:dir
// { search } rule (the P5-S1 cgroup2-root-walk contribution) or into any
// other mounton surface. cgroup_t:s0 is a global label and mounton is
// path-insensitive TE authority; the confinement of the observed mount
// side effect is the production holder's own mount namespace (the 4C-49
// gate's live proof), not this rule.
func TestSELinuxPolicyRootlesskitCgroupMounton(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	pinnedCgroupMounton := "allow docker_helper_rootlesskit_t cgroup_t:dir mounton;"
	pinnedCgroupSearch := "allow docker_helper_rootlesskit_t cgroup_t:dir { search };"
	pinnedCgroupFilePair := "allow docker_helper_rootlesskit_t cgroup_t:file { read open };"
	if !strings.Contains(policy, pinnedCgroupMounton) {
		t.Fatalf("the rootlesskit child domain's cgroup move-mount surface must be exact: %q", pinnedCgroupMounton)
	}
	if !strings.Contains(policy, pinnedCgroupSearch) {
		t.Fatalf("the module's own standing cgroup2-root-walk rule must stay intact: %q", pinnedCgroupSearch)
	}
	if !strings.Contains(policy, pinnedCgroupFilePair) {
		t.Fatalf("the module's own standing cgroup file pair must stay intact: %q", pinnedCgroupFilePair)
	}
	// cgroupMountonViolations returns one violation per line of module
	// text that breaks the grant invariants: exactly one allow rule may
	// name docker_helper_rootlesskit_t -> cgroup_t:dir with the mounton
	// permission, in the exact bare shape (no brace form, no split
	// rules, no second mounton-naming rule — write/add_name/create/
	// remove_name/rmdir/rename/setattr/relabel* are distinct hooks);
	// no other subject may receive the cgroup_t:dir MOUNTON shape (the
	// module's own standing cgroup search/read surfaces for the daemon
	// and the builder are prior live-evidenced contributions, not part
	// of this grant); the standing search rule and the file pair must
	// each appear exactly once; no cgroup_t:file permission beyond the
	// standing pairs and no cgroup_t:filesystem surface may ride (the
	// class confusion).
	cgroupMountonViolations := func(text string) []string {
		var violations []string
		mountonCount := 0
		searchCount := 0
		fileCount := 0
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			switch {
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t cgroup_t:dir"):
				if strings.Contains(trimmed, "mounton") {
					mountonCount++
					if trimmed != pinnedCgroupMounton {
						violations = append(violations, "the cgroup move-mount grant must be the exact bare mounton shape (no brace form, no split rules, no second mounton permission — write/add_name/create/remove_name/rmdir/rename/setattr/relabel* are distinct hooks): "+trimmed)
					}
				} else if trimmed == pinnedCgroupSearch {
					searchCount++
				} else {
					violations = append(violations, "the standing cgroup2-root-walk rule is the only other cgroup_t:dir surface this module may carry: "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " cgroup_t:dir") && strings.Contains(trimmed, "mounton"):
				violations = append(violations, "the cgroup_t:dir mounton shape is unique to the rootlesskit child domain's pinned grant: "+trimmed)
			case strings.HasPrefix(trimmed, "allow docker_helper_rootlesskit_t cgroup_t:file"):
				fileCount++
				if trimmed != pinnedCgroupFilePair {
					violations = append(violations, "the standing cgroup file pair { read open } is the module's only cgroup_t:file surface for the rootlesskit child: "+trimmed)
				}
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " cgroup_t:file") && strings.Contains(trimmed, "mounton"):
				violations = append(violations, "no cgroup_t:file mounton shape may exist for any subject: "+trimmed)
			case strings.HasPrefix(trimmed, "allow ") && strings.Contains(trimmed, " cgroup_t:filesystem"):
				violations = append(violations, "the class confusion is forbidden — the filesystem class surface of cgroup_t (mount/remount/unmount) is not this grant: "+trimmed)
			}
		}
		if mountonCount == 0 {
			violations = append(violations, "the cgroup move-mount grant (rootlesskit_t -> cgroup_t:dir mounton) is missing")
		} else if mountonCount > 1 {
			violations = append(violations, fmt.Sprintf("exactly one cgroup_t:dir mounton grant may exist for the rootlesskit child domain, found %d", mountonCount))
		}
		if searchCount != 1 {
			violations = append(violations, fmt.Sprintf("the module's own standing cgroup2-root-walk rule must appear exactly once, found %d", searchCount))
		}
		if fileCount != 1 {
			violations = append(violations, fmt.Sprintf("the module's own standing cgroup file pair must appear exactly once, found %d", fileCount))
		}
		return violations
	}
	if violations := cgroupMountonViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the cgroup move-mount invariants: %v", violations)
	}
	// The replacement regressions: each replacement must APPLY and must
	// actually trip the invariants.
	for _, regressed := range []struct {
		name string
		rule string
	}{
		{"missing whole rule", ""},
		{"missing mounton (write-only shape)", "allow docker_helper_rootlesskit_t cgroup_t:dir write;"},
		{"write instead of mounton", "allow docker_helper_rootlesskit_t cgroup_t:dir write;"},
		{"relabelto instead of mounton", "allow docker_helper_rootlesskit_t cgroup_t:dir relabelto;"},
		{"create instead of mounton", "allow docker_helper_rootlesskit_t cgroup_t:dir create;"},
		{"setattr instead of mounton", "allow docker_helper_rootlesskit_t cgroup_t:dir setattr;"},
		{"mounton relabelto brace set", "allow docker_helper_rootlesskit_t cgroup_t:dir { mounton relabelto };"},
		{"mounton write brace set", "allow docker_helper_rootlesskit_t cgroup_t:dir { mounton write };"},
		{"mounton create brace set", "allow docker_helper_rootlesskit_t cgroup_t:dir { mounton create };"},
		{"duplicate identical rule", pinnedCgroupMounton + "\n" + pinnedCgroupMounton},
		{"parallel mounton rule (brace form)", pinnedCgroupMounton + "\nallow docker_helper_rootlesskit_t cgroup_t:dir { mounton };"},
		{"equivalent brace-single-perm shape", "allow docker_helper_rootlesskit_t cgroup_t:dir { mounton };"},
		{"wrong class (cgroup_t:filesystem mount)", "allow docker_helper_rootlesskit_t cgroup_t:filesystem mount;"},
		{"wrong class (cgroup_t:file mounton)", "allow docker_helper_rootlesskit_t cgroup_t:file mounton;"},
		{"wrong target type (root_t)", "allow docker_helper_rootlesskit_t root_t:dir mounton;"},
		{"wrong target type (tmp_t)", "allow docker_helper_rootlesskit_t tmp_t:dir mounton;"},
		{"wrong target type (etc_t)", "allow docker_helper_rootlesskit_t etc_t:dir mounton;"},
		{"wrong target type (tmpfs_t)", "allow docker_helper_rootlesskit_t tmpfs_t:dir mounton;"},
	} {
		mutated := strings.Replace(policy, pinnedCgroupMounton, regressed.rule, 1)
		applied := func() bool {
			if regressed.rule == "" {
				return !strings.Contains(mutated, pinnedCgroupMounton)
			}
			return strings.Contains(mutated, regressed.rule)
		}
		if !applied() {
			t.Errorf("the cgroup move-mount regression %q was not applied", regressed.name)
			continue
		}
		if len(cgroupMountonViolations(mutated)) == 0 {
			t.Errorf("the cgroup move-mount regression %q must fail the cgroup move-mount invariants", regressed.name)
		}
	}
	// The widening sweep: { mounton <X> } for every other dir permission
	// must fail the invariants in every case.
	for _, extra := range []string{
		"read", "write", "getattr", "setattr", "lock", "open", "append",
		"map", "execmod", "audit_access", "execute", "reparent", "create",
		"rmdir", "add_name", "remove_name", "rename", "relabelfrom",
		"relabelto", "search", "watch", "audit",
	} {
		mutated := strings.Replace(policy, pinnedCgroupMounton,
			fmt.Sprintf("allow docker_helper_rootlesskit_t cgroup_t:dir { mounton %s };", extra), 1)
		if !strings.Contains(mutated, fmt.Sprintf("allow docker_helper_rootlesskit_t cgroup_t:dir { mounton %s };", extra)) {
			t.Errorf("the cgroup move-mount widening +%s was not applied", extra)
			continue
		}
		if len(cgroupMountonViolations(mutated)) == 0 {
			t.Errorf("the cgroup move-mount widening +%s must fail the cgroup move-mount invariants", extra)
		}
	}
	// The subject regressions: no other domain may gain cgroup_t dir
	// authority, appended beside the real grant.
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"cgroup dir mounton for the manager", "allow docker_helper_builder_t cgroup_t:dir mounton;"},
		{"cgroup dir mounton for the launcher", "allow docker_helper_builder_launcher_t cgroup_t:dir mounton;"},
		{"cgroup dir mounton for the network helper", "allow docker_helper_slirp4netns_t cgroup_t:dir mounton;"},
		{"cgroup dir mounton for the daemon", "allow docker_helper_t cgroup_t:dir mounton;"},
	} {
		if len(cgroupMountonViolations(policy+"\n"+mut.rule)) == 0 {
			t.Errorf("mutation %q must trip the cgroup move-mount invariants", mut.name)
		}
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

// buildkitdIdentityViolations scans the module's parsed rules against the
// 4C-57 identity + 4C-58/4C-59 source-exec + 4C-60 process-transition +
// 4C-61 target-entrypoint authority invariants and returns one
// human-readable violation per broken rule, empty when none. THREE distinct
// authority planes, each owned separately (never coalesced into one "exec
// bundle"):
//
//			A. the source executable surface: rootlesskit_t ->
//			   buildkitd_exec_t:file — exactly the { execute read open } rule;
//			B. the process transition surface: rootlesskit_t ->
//			   buildkitd_t:process — exactly the bare { transition } rule;
//	  C. the target executable surface: buildkitd_t ->
//	     buildkitd_exec_t:file — exactly the { entrypoint read execute }
//	     rule (the 4C-61 entrypoint widened IN PLACE by the 4C-62
//	     combined image-load boundary, ONE rule on one pair, never split;
//	     the conventional entry bundle is NOT copied);
//	  D. the shared state-root surface: buildkitd_t ->
//	     builder_state_root_t:dir — exactly the ONE { getattr search }
//	     rule (the 4C-63 getattr widened IN PLACE by the 4C-63 canonical
//	     run's own terminal search boundary, ONE rule on one pair, never
//	     split; the standing RootlessKit state-root search rule is a
//	     different subject and a different owner and stays untouched);
//	  E. the categorized operation-state dir surface: buildkitd_t ->
//	     builder_state_t:dir — exactly the { getattr search write add_name }
//	     rule (the 4C-65 getattr is the 4C-64 run's terminal-causal owner, the
//	     4C-66 search is the 4C-65 canonical run's own terminal boundary, the
//	     4C-67 write is the 4C-66 canonical run's own terminal boundary, the
//	     4C-68 add_name is the 4C-67 canonical run's own terminal boundary —
//	     the DENIED bit of the requested 0x24000000 { search add_name }
//	     decision, never the whole requested mask; ONE rule, never split; the
//	     other subjects' standing builder_state_t:dir rules are their own
//	     owners and never count as this owner's contribution);
//	  F. the categorized operation-state FILE surface: buildkitd_t ->
//	     builder_state_t:file — exactly the bare { create } rule (the 4C-69
//	     grant is the 4C-68 canonical run's own terminal boundary — the
//	     class-aware pair (tclass=file, 0x8), the same bit number on the dir
//	     class being dir:create and a DIFFERENT authority; a NEW pair+class
//	     plane, NEVER a widening of the dir rule; file:create is NOT a
//	     file-IO bundle — open/read/write/getattr/setattr/lock/unlink/append/
//	     map/execute stay their own live-evidence phases; the companion
//	     init_t/builder_t/rootlesskit_t builder_state_t:file rules are their
//	     own owners and never count as this owner's contribution).
//			- any other allow rule naming a buildkitd type (any source, any
//			  target, any class, any permission set) violates;
//			- the rootlesskit child holds no bin_t:file grant; its exec/transition
//			  surfaces toward the standing sibling identities stay exactly the
//			  existing owners' rules (a re-granted subset line duplicates an
//			  existing owner);
//			- no range_transition may exist anywhere.
func buildkitdIdentityViolations(policy string) []string {
	const canonicalExec = "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { execute read open };"
	const canonicalTransition = "allow docker_helper_rootlesskit_t docker_helper_buildkitd_t:process transition;"
	const canonicalEntry = "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint read execute };"
	const canonicalStateRoot = "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr search };"
	const canonicalStateTree = "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search write add_name };"
	const canonicalStateFile = "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file create;"
	// The categorized state-tree dir surface's standing owners (the
	// exact module lines): the daemon does NOT own one; every other
	// subject's existing rule is its own owner and must stay unchanged —
	// any NEW or reshaped rule on the pair trips.
	standingStateTreeDirRules := map[string]bool{
		"allow init_t docker_helper_builder_state_t:dir { create rmdir write remove_name setattr };":                                                    true,
		"allow docker_helper_builder_t docker_helper_builder_state_t:dir { relabelto };":                                                                true,
		"allow docker_helper_builder_t docker_helper_builder_state_t:dir { getattr search read open write add_name remove_name create rmdir setattr };": true,
		"allow docker_helper_rootlesskit_t docker_helper_builder_state_t:dir { search getattr read open write add_name remove_name lock };":             true,
		canonicalStateTree: true,
	}
	// The categorized state-tree file surface's standing owners (the
	// exact module lines): the daemon's own ONE create rule (the 4C-69
	// grant) plus the three other subjects' standing rules — every other
	// subject's existing rule is its own owner and must stay unchanged
	// (the RootlessKit seven-perm shape is NOT a template for BuildKitd;
	// any NEW or reshaped rule on the pair trips).
	standingStateTreeFileRules := map[string]bool{
		"allow init_t docker_helper_builder_state_t:file { unlink };":                                                           true,
		"allow docker_helper_builder_t docker_helper_builder_state_t:file { create read write open getattr setattr unlink };":   true,
		"allow docker_helper_rootlesskit_t docker_helper_builder_state_t:file { create open read write getattr setattr lock };": true,
		canonicalStateFile: true,
	}
	standingRootlesskitExecRules := map[string]string{
		"docker_helper_rootlesskit_exec_t": "allow docker_helper_rootlesskit_t docker_helper_rootlesskit_exec_t:file { entrypoint read open execute execute_no_trans getattr map };",
		"docker_helper_slirp4netns_exec_t": "allow docker_helper_rootlesskit_t docker_helper_slirp4netns_exec_t:file { execute read open getattr };",
	}
	standingRootlesskitTransitionRules := map[string]string{
		"docker_helper_slirp4netns_t": "allow docker_helper_rootlesskit_t docker_helper_slirp4netns_t:process { transition };",
		"docker_helper_newuidmap_t":   "allow docker_helper_rootlesskit_t docker_helper_newuidmap_t:process { transition };",
		"docker_helper_newgidmap_t":   "allow docker_helper_rootlesskit_t docker_helper_newgidmap_t:process { transition };",
	}
	standingRootlesskitStateRoot := "allow docker_helper_rootlesskit_t docker_helper_builder_state_root_t:dir { search };"
	var violations []string
	canonicalCount := 0
	transitionCount := 0
	entryCount := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == canonicalExec {
			canonicalCount++
		}
		if trimmed == canonicalTransition {
			transitionCount++
		}
		if trimmed == canonicalEntry {
			entryCount++
		}
	}
	if canonicalCount != 1 {
		violations = append(violations, fmt.Sprintf("the buildkitd source-exec grant must exist exactly once in the exact canonical form, found %d: %s", canonicalCount, canonicalExec))
	}
	if transitionCount != 1 {
		violations = append(violations, fmt.Sprintf("the buildkitd process-transition grant must exist exactly once in the exact canonical form, found %d: %s", transitionCount, canonicalTransition))
	}
	if entryCount != 1 {
		violations = append(violations, fmt.Sprintf("the buildkitd target-entrypoint grant must exist exactly once in the exact canonical form, found %d: %s", entryCount, canonicalEntry))
	}
	stateRootCount := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == canonicalStateRoot {
			stateRootCount++
		}
	}
	if stateRootCount != 1 {
		violations = append(violations, fmt.Sprintf("the buildkitd state-root { getattr search } grant must exist exactly once in the exact canonical form, found %d: %s", stateRootCount, canonicalStateRoot))
	}
	stateTreeCount := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == canonicalStateTree {
			stateTreeCount++
		}
	}
	if stateTreeCount != 1 {
		violations = append(violations, fmt.Sprintf("the buildkitd categorized state-tree { getattr search write add_name } grant must exist exactly once in the exact canonical form, found %d: %s", stateTreeCount, canonicalStateTree))
	}
	stateFileCount := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == canonicalStateFile {
			stateFileCount++
		}
	}
	if stateFileCount != 1 {
		violations = append(violations, fmt.Sprintf("the buildkitd categorized state-tree file create grant must exist exactly once in the exact canonical form, found %d: %s", stateFileCount, canonicalStateFile))
	}
	// The exact module-borne allow-rule total naming a buildkitd type:
	// the six planes only (A source-exec, B transition, C target-side,
	// D shared state-root, E categorized state-tree dir, F categorized
	// state-tree file create) — never "at least".
	buildkitdNamedAllow := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "allow ") {
			continue
		}
		if strings.Contains(trimmed, "docker_helper_buildkitd") {
			buildkitdNamedAllow++
		}
	}
	if buildkitdNamedAllow != 6 {
		violations = append(violations, fmt.Sprintf("the module must carry exactly the six buildkitd-named allow rules (the source-exec triple, the bare transition, the target-side { entrypoint read execute }, the shared state-root { getattr search }, the categorized state-tree dir { getattr search write add_name }, the categorized state-tree file create), found %d", buildkitdNamedAllow))
	}
	// The categorized state-tree dir surface has exactly the standing
	// owners above; a NEW or reshaped rule on the pair (any source,
	// including attribute/broad forms) trips here.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.HasPrefix(trimmed, "allow ") {
			continue
		}
		if strings.Contains(trimmed, " docker_helper_builder_state_t:dir ") && !standingStateTreeDirRules[trimmed] {
			violations = append(violations, "the categorized state-tree dir surface has exactly the standing owners (init_t, the manager, the flow, the buildkitd quadruple rule) — every other shape on the pair violates: "+trimmed)
		}
	}
	// The categorized state-tree file surface has exactly the standing
	// owners above (the daemon's ONE create rule + the three other
	// subjects' standing rules); a NEW or reshaped rule on the pair (any
	// source, including attribute/broad forms) trips here. The dir-class
	// check above never judges a file-class rule and vice versa — the
	// class is part of each rule's identity.
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.HasPrefix(trimmed, "allow ") {
			continue
		}
		if strings.Contains(trimmed, " docker_helper_builder_state_t:file ") && !standingStateTreeFileRules[trimmed] {
			violations = append(violations, "the categorized state-tree file surface has exactly the standing owners (init_t, the manager, the flow, the buildkitd create rule) — every other shape on the pair violates: "+trimmed)
		}
	}
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "allow ") {
			if strings.Contains(trimmed, "docker_helper_buildkitd_exec_t") && trimmed != canonicalExec && trimmed != canonicalEntry {
				violations = append(violations, "the only allow rules naming the buildkitd exec type are the exact source-exec grant { execute read open } and the exact target-side { entrypoint read execute } grant: "+trimmed)
			}
			if strings.Contains(trimmed, "docker_helper_buildkitd_t") && trimmed != canonicalTransition && trimmed != canonicalEntry && trimmed != canonicalStateRoot && trimmed != canonicalStateTree && trimmed != canonicalStateFile {
				violations = append(violations, "the only allow rules toward the buildkitd domain are the exact process transition grant, the exact target-entrypoint grant, and the exact state surfaces: "+trimmed)
			}
			fields := strings.Fields(trimmed)
			if len(fields) >= 3 && fields[1] == "docker_helper_rootlesskit_t" && strings.Contains(fields[2], ":file") {
				target := strings.SplitN(fields[2], ":", 2)[0]
				if target == "bin_t" {
					violations = append(violations, "the rootlesskit flow domain must hold no bin_t:file grant (the generic buildkitd boundary stays closed; a narrowed private identity, never a generic bundle): "+trimmed)
				}
				if standing, ok := standingRootlesskitExecRules[target]; ok && trimmed != standing {
					violations = append(violations, "no second permission sweep toward the standing sibling exec identity (the existing owner's rule must stay unchanged): "+trimmed)
				}
			}
			if len(fields) >= 3 && fields[1] == "docker_helper_rootlesskit_t" && strings.Contains(fields[2], ":dir") && strings.HasPrefix(fields[2], "docker_helper_builder_state_root_t") {
				if trimmed != standingRootlesskitStateRoot {
					violations = append(violations, "no second permission sweep toward the standing flow state-root dir rule (the existing owner's rule must stay unchanged): "+trimmed)
				}
			}
			if len(fields) >= 3 && fields[1] == "docker_helper_rootlesskit_t" && strings.Contains(fields[2], ":process") {
				target := strings.SplitN(fields[2], ":", 2)[0]
				if target == "docker_helper_buildkitd_t" {
					if trimmed != canonicalTransition {
						violations = append(violations, "the buildkitd process-transition grant must be the exact bare { transition } form: "+trimmed)
					}
				} else if standing, ok := standingRootlesskitTransitionRules[target]; ok {
					if trimmed != standing {
						violations = append(violations, "no second permission sweep toward the standing helper transition (the existing owner's rule must stay unchanged): "+trimmed)
					}
				} else {
					violations = append(violations, "the rootlesskit child's process-transition surface is the pointed set (the three launch helpers + the buildkitd edge); a transition toward another domain is an escalation shape: "+trimmed)
				}
			}
		}
		if strings.HasPrefix(trimmed, "range_transition") {
			violations = append(violations, "no range_transition may be declared (category preservation is a live proof, not a pre-declared map): "+trimmed)
		}
	}
	return violations
}

// TestSELinuxPolicyBuildkitdExecIdentity verifies the Phase 4C-57
// identity-narrowing foundation plus the Phase 4C-58 source-execute
// authority: the bundled BuildKit daemon carries a dedicated executable
// type and the dedicated process domain exists, and the rootlesskit child
// domain holds EXACTLY ONE permission on the private exec type. The
// invariant set:
//   - the exact type declarations, each exactly once (the exec type with
//     file_type + exec_type, the domain, the system_r role membership);
//   - exactly ONE pointed type_transition declaration naming the pair
//     (rootlesskit_t + buildkitd_exec_t -> buildkitd_t, class process) —
//     the routing map only: no transition permission, no entrypoint, no
//     execute_no_trans/read/open/getattr/map on the exec type from ANY
//     domain, no permission toward the domain from ANY domain, no
//     capability/cap_userns surface, no range_transition (the MCS
//     category preservation is a live-transition-phase proof);
//   - the 4C-59 grant: allow docker_helper_rootlesskit_t
//     docker_helper_buildkitd_exec_t:file { execute read open }; — exactly
//     once, in the exact brace form (the source-exec authority for the
//     private buildkitd identity: the 4C-58 execute hook widened in place
//     by the 4C-59 executable-image read/open hooks; nothing else in the
//     exec chain is granted — the transition bundle is deliberately NOT
//     finished);
//   - the 4C-60 grant: allow docker_helper_rootlesskit_t
//     docker_helper_buildkitd_t:process transition; — exactly once, in
//     the exact bare form (the pointed routing edge's own authority; no
//     siginh/noatsecure/rlimitinh/dyntransition/setexec — the
//     conventional transition bundle is NOT copied; no process2
//     surface; the rootlesskit child's process-transition surface stays
//     the pointed set: the three launch helpers' standing brace rules +
//     this edge);
//   - the exact .fc entry labels exactly the canonical buildkitd path —
//     one rule, the `--` regular-file form, no directory regex, no
//     sibling (buildctl/buildkit-runc keep their distro labels);
//   - the canonical path identity: the manager constant, the
//     RootlessKit argv target, the packaged payload destination, and the
//     .fc pattern are all exactly /usr/libexec/docker-helper/buildkit/
//     buildkitd;
//   - the generic bin_t execution boundary stays absent for the
//     rootlesskit child domain (any rootlesskit_t -> bin_t:file grant —
//     the compensating generic bundle the phase forbids — violates;
//     the narrowed private identity is never papered over with a
//     generic grant).
func TestSELinuxPolicyBuildkitdExecIdentity(t *testing.T) {
	policy := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.te")
	fc := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.fc")

	// The exact structural declarations, each exactly once.
	declarations := []string{
		"type docker_helper_buildkitd_exec_t, file_type, exec_type;",
		"type docker_helper_buildkitd_t, domain;",
		"role system_r types docker_helper_buildkitd_t;",
		"type_transition docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:process docker_helper_buildkitd_t;",
	}
	for _, decl := range declarations {
		if got := strings.Count(policy, decl); got != 1 {
			t.Errorf("the buildkitd identity structure must declare %q exactly once, found %d", decl, got)
		}
	}

	// The pointed transition is the ONLY transition into the domain (the
	// exact rootlesskit edge; duplicates and parallel sources violate).
	_, transitions := parseSELinuxRules(policy)
	buildkitdTransitions := 0
	for _, tr := range transitions {
		if tr.dest != "docker_helper_buildkitd_t" {
			continue
		}
		buildkitdTransitions++
		if tr.source != "docker_helper_rootlesskit_t" || tr.entry != "docker_helper_buildkitd_exec_t" || tr.class != "process" {
			t.Errorf("the only transition into the buildkitd domain is the rootlesskit child's exec of its entry type, got: type_transition %s %s:%s %s", tr.source, tr.entry, tr.class, tr.dest)
		}
	}
	if buildkitdTransitions != 1 {
		t.Errorf("exactly one (structural) transition may name the buildkitd domain, found %d", buildkitdTransitions)
	}

	// The exact .fc entry: one rule, the canonical path, the `--` form;
	// no rule other than the exact buildkitd path may carry the type (no
	// directory regex, no sibling).
	fcLines := 0
	for _, line := range strings.Split(fc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.Contains(trimmed, "docker_helper_buildkitd_exec_t") {
			continue
		}
		fcLines++
		if trimmed != "/usr/libexec/docker-helper/buildkit/buildkitd  --  system_u:object_r:docker_helper_buildkitd_exec_t:s0" {
			t.Errorf("the buildkitd fc rule must be the exact canonical path in the `--` form: %s", trimmed)
		}
	}
	if fcLines != 1 {
		t.Errorf("exactly one buildkitd fc rule must exist, found %d", fcLines)
	}

	// The canonical path identity (the phase's four-congruent-owners
	// proof): the manager constant, the RootlessKit argv target, the
	// packaged payload destination, and the .fc pattern are the SAME
	// path.
	if builderManagerBuildkitd != "/usr/libexec/docker-helper/buildkit/buildkitd" {
		t.Errorf("the canonical buildkitd constant drifted: %q", builderManagerBuildkitd)
	}
	argv := builderRootlessKitArgv("op_0123456789abcdef0123456789abcdef",
		opRuntimeDir("op_0123456789abcdef0123456789abcdef"),
		opStateDir("op_0123456789abcdef0123456789abcdef"))
	argvHits := 0
	for _, a := range argv {
		if a == builderManagerBuildkitd {
			argvHits++
		}
	}
	if argvHits != 1 {
		t.Errorf("the canonical RootlessKit argv must carry the canonical buildkitd target exactly once, found %d", argvHits)
	}
	nfpm, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(nfpm), "dst: /usr/libexec/docker-helper/buildkit/buildkitd") != 1 {
		t.Error("the package payload destination must be exactly the canonical buildkitd path (nfpm.yaml)")
	}

	// The 4C-59 source-exec grant: exactly the canonical brace triple,
	// once (non-comment lines only — the provenance comment mentions the
	// rule).
	const canonicalExec = "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { execute read open };"
	var withoutExec []string
	canonicalCount := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == canonicalExec {
			canonicalCount++
			continue
		}
		withoutExec = append(withoutExec, line)
	}
	if canonicalCount != 1 {
		t.Errorf("the buildkitd source-exec grant must exist exactly once, found %d", canonicalCount)
	}

	// The committed policy violates nothing.
	if violations := buildkitdIdentityViolations(policy); len(violations) > 0 {
		t.Errorf("the committed policy violates the buildkitd authority invariants: %v", violations)
	}

	// Missing-rule mutation: removing the canonical grant must trip.
	if violations := buildkitdIdentityViolations(strings.Join(withoutExec, "\n")); len(violations) == 0 {
		t.Error("the missing-rule mutation must trip the buildkitd authority invariants")
	}

	// The 4C-60 process-transition grant: exactly the canonical bare
	// rule, once (non-comment lines only — the provenance comment
	// mentions the rule).
	const canonicalTransition = "allow docker_helper_rootlesskit_t docker_helper_buildkitd_t:process transition;"
	var withoutTransition []string
	transitionCount := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == canonicalTransition {
			transitionCount++
			continue
		}
		withoutTransition = append(withoutTransition, line)
	}
	if transitionCount != 1 {
		t.Errorf("the buildkitd process-transition grant must exist exactly once, found %d", transitionCount)
	}

	// Missing-rule mutation: removing the canonical grant must trip.
	if violations := buildkitdIdentityViolations(strings.Join(withoutTransition, "\n")); len(violations) == 0 {
		t.Error("the missing-transition mutation must trip the buildkitd authority invariants")
	}

	// The 4C-61 target-entrypoint grant: exactly the canonical bare
	// rule, once (non-comment lines only).
	const canonicalEntry = "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint read execute };"
	var withoutEntry []string
	entryCount := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == canonicalEntry {
			entryCount++
			continue
		}
		withoutEntry = append(withoutEntry, line)
	}
	if entryCount != 1 {
		t.Errorf("the buildkitd target-entrypoint grant must exist exactly once, found %d", entryCount)
	}

	// Missing-rule mutation: removing the canonical grant must trip.
	if violations := buildkitdIdentityViolations(strings.Join(withoutEntry, "\n")); len(violations) == 0 {
		t.Error("the missing-entrypoint mutation must trip the buildkitd authority invariants")
	}

	// The 4C-64 state-root plane: exactly the ONE { getattr search }
	// rule, once (the 4C-63 getattr widened IN PLACE by the 4C-63
	// canonical run's own terminal search boundary).
	const canonicalStateRoot = "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr search };"
	var withoutStateRoot []string
	stateRootCount := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == canonicalStateRoot {
			stateRootCount++
			continue
		}
		withoutStateRoot = append(withoutStateRoot, line)
	}
	if stateRootCount != 1 {
		t.Errorf("the buildkitd state-root { getattr search } grant must exist exactly once, found %d", stateRootCount)
	}
	if violations := buildkitdIdentityViolations(strings.Join(withoutStateRoot, "\n")); len(violations) == 0 {
		t.Error("the missing-state-root mutation must trip the buildkitd authority invariants")
	}

	// The 4C-68 categorized state-tree plane: exactly the
	// { getattr search write add_name } rule, once (the 4C-65 getattr is
	// the 4C-64 run's terminal-causal owner; the 4C-66 search is the
	// 4C-65 canonical run's own terminal boundary; the 4C-67 write is the
	// 4C-66 canonical run's own terminal boundary; the 4C-68 add_name is
	// the 4C-67 canonical run's own terminal boundary — the DENIED bit of
	// the requested 0x24000000 decision — the 4C-67 rule widened IN
	// PLACE, never split).
	const canonicalStateTree = "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search write add_name };"
	var withoutStateTree []string
	stateTreeCount := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == canonicalStateTree {
			stateTreeCount++
			continue
		}
		withoutStateTree = append(withoutStateTree, line)
	}
	if stateTreeCount != 1 {
		t.Errorf("the buildkitd categorized state-tree grant must exist exactly once, found %d", stateTreeCount)
	}
	if violations := buildkitdIdentityViolations(strings.Join(withoutStateTree, "\n")); len(violations) == 0 {
		t.Error("the missing-state-tree mutation must trip the buildkitd authority invariants")
	}

	// The 4C-69 categorized state-tree FILE plane: exactly the bare
	// create rule, once (the 4C-68 canonical run's own terminal boundary
	// — the class-aware pair (tclass=file, 0x8); a NEW pair+class plane,
	// NEVER a widening of the dir rule, which stays byte-for-semantics
	// the { getattr search write add_name } quadruple).
	const canonicalStateFile = "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file create;"
	var withoutStateFile []string
	stateFileCount := 0
	for _, line := range strings.Split(policy, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == canonicalStateFile {
			stateFileCount++
			continue
		}
		withoutStateFile = append(withoutStateFile, line)
	}
	if stateFileCount != 1 {
		t.Errorf("the buildkitd categorized state-tree file create grant must exist exactly once, found %d", stateFileCount)
	}
	if violations := buildkitdIdentityViolations(strings.Join(withoutStateFile, "\n")); len(violations) == 0 {
		t.Error("the missing-state-file mutation must trip the buildkitd authority invariants")
	}

	// Mutation guards: every forbidden authority shape appended to the
	// module must trip the authority invariants; transition mutations
	// must trip the exactly-one edge invariant.
	for _, mut := range []struct {
		name string
		rule string
	}{
		// the older, narrower shapes (missing read/open)
		{"the bare 4C-58 form (missing read+open)", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file execute;"},
		{"execute + read (missing open)", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { execute read };"},
		{"execute + open (missing read)", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { execute open };"},
		// missing members of the triple
		{"missing execute (read+open only)", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { read open };"},
		// forbidden additions
		{"execute_no_trans instead", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file execute_no_trans;"},
		{"execute_no_trans additionally", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { execute read open execute_no_trans };"},
		{"getattr addition", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { execute read open getattr };"},
		{"map addition", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { execute read open map };"},
		{"entrypoint addition", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { execute read open entrypoint };"},
		{"fourth permission sweep (full exec bundle)", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { execute read open getattr map };"},
		// the generic bin_t bundle
		{"generic bin_t execute for the flow", "allow docker_helper_rootlesskit_t bin_t:file { execute };"},
		{"generic bin_t read+open for the flow", "allow docker_helper_rootlesskit_t bin_t:file { read open };"},
		{"generic bin_t execute_no_trans for the flow", "allow docker_helper_rootlesskit_t bin_t:file execute_no_trans;"},
		{"generic bin_t full bundle for the flow", "allow docker_helper_rootlesskit_t bin_t:file { execute read open getattr map };"},
		// wrong sources on the exec type
		{"daemon execute on the exec type", "allow docker_helper_t docker_helper_buildkitd_exec_t:file execute;"},
		{"manager execute on the exec type", "allow docker_helper_builder_t docker_helper_buildkitd_exec_t:file execute;"},
		{"launcher execute on the exec type", "allow docker_helper_builder_launcher_t docker_helper_buildkitd_exec_t:file execute;"},
		{"slirp4netns execute on the exec type", "allow docker_helper_slirp4netns_t docker_helper_buildkitd_exec_t:file execute;"},
		{"buildkitd domain execute on its own exec type", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file execute;"},
		// wrong targets from the flow domain
		{"self re-exec re-grant", "allow docker_helper_rootlesskit_t docker_helper_rootlesskit_exec_t:file execute;"},
		{"slirp4netns exec re-grant", "allow docker_helper_rootlesskit_t docker_helper_slirp4netns_exec_t:file execute;"},
		// the transition bundle stays closed
		{"process transition toward the domain with the conventional bundle", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_t:process { transition siginh };"},
		{"process transition + noatsecure", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_t:process { transition noatsecure };"},
		{"process transition + rlimitinh", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_t:process { transition rlimitinh };"},
		{"process transition + setexec", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_t:process { transition setexec };"},
		{"fork instead of transition", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_t:process fork;"},
		{"dyntransition instead of transition", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_t:process dyntransition;"},
		{"process2 nnp_transition toward the domain", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_t:process2 nnp_transition;"},
		{"wrong-class transition shape", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_t:file transition;"},
		{"wrong-source transition from the manager", "allow docker_helper_builder_t docker_helper_buildkitd_t:process transition;"},
		{"wrong-source transition from the launcher", "allow docker_helper_builder_launcher_t docker_helper_buildkitd_t:process transition;"},
		{"wrong-source transition from the daemon", "allow docker_helper_t docker_helper_buildkitd_t:process transition;"},
		{"wrong-source transition from slirp4netns", "allow docker_helper_slirp4netns_t docker_helper_buildkitd_t:process transition;"},
		{"wrong-target transition into the daemon", "allow docker_helper_rootlesskit_t docker_helper_t:process transition;"},
		{"wrong-target transition into the container domain", "allow docker_helper_rootlesskit_t docker_helper_container_t:process transition;"},
		{"target entrypoint rule", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint execute read open getattr map };"},
		{"target capability grant", "allow docker_helper_buildkitd_t self:capability sys_admin;"},
		{"target cap_userns grant", "allow docker_helper_buildkitd_t self:cap_userns sys_admin;"},
		// the 4C-62 target-plane mutations (the conventional entry bundle is NOT copied)
		{"the old 4C-61 bare entrypoint form", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file entrypoint;"},
		{"entrypoint + read only", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint read };"},
		{"entrypoint + execute only", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint execute };"},
		{"missing entrypoint", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { read execute };"},
		{"missing read", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint execute };"},
		{"missing execute", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint read };"},
		{"open instead of read", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint open execute };"},
		{"getattr instead of execute", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint read getattr };"},
		{"map instead of execute", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint read map };"},
		{"fourth permission open", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint read execute open };"},
		{"fourth permission getattr", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint read execute getattr };"},
		{"fourth permission map", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint read execute map };"},
		{"fourth permission execute_no_trans", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint read execute execute_no_trans };"},
		{"fourth permission execmod", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint read execute execmod };"},
		{"the slirp-style entry bundle copied whole", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint read open execute getattr map };"},
		{"target grant from the wrong source (the flow)", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { entrypoint read execute };"},
		{"target grant from the manager", "allow docker_helper_builder_t docker_helper_buildkitd_exec_t:file { entrypoint read execute };"},
		{"target grant toward the wrong target", "allow docker_helper_buildkitd_t bin_t:file { entrypoint read execute };"},
		{"target grant toward the slirp4netns exec type", "allow docker_helper_buildkitd_t docker_helper_slirp4netns_exec_t:file { entrypoint read execute };"},
		{"target grant on the wrong class", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:process { entrypoint read execute };"},
		{"brace equivalent of the target rule", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { entrypoint };"},
		{"reordered brace form of the target rule", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { execute entrypoint read };"},
		{"split target grant", "allow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file entrypoint;\nallow docker_helper_buildkitd_t docker_helper_buildkitd_exec_t:file { read execute };"},
		{"duplicate of the target-side rule", canonicalEntry},
		// the 4C-64 state-root plane (the ONE { getattr search } rule; the
		// missing-rule case is covered by the withoutStateRoot removal above)
		{"the old 4C-63 bare getattr form (missing search)", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir getattr;"},
		{"search-only (missing getattr)", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir search;"},
		{"missing search (bare-getattr shape)", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr };"},
		{"missing getattr (search-only shape)", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { search };"},
		{"read instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir read;"},
		{"open instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir open;"},
		{"write instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir write;"},
		{"third permission read", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr search read };"},
		{"third permission open", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr search open };"},
		{"third permission write", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr search write };"},
		{"third permission setattr", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr search setattr };"},
		{"third permission add_name", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr search add_name };"},
		{"third permission remove_name", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr search remove_name };"},
		{"third permission create", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr search create };"},
		{"third permission rmdir", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr search rmdir };"},
		{"third permission mounton", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr search mounton };"},
		{"third permission lock", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { getattr search lock };"},
		{"state-root grant from the wrong source", "allow docker_helper_rootlesskit_t docker_helper_builder_state_root_t:dir getattr;"},
		{"state-root grant from the wrong source (the pair form)", "allow docker_helper_rootlesskit_t docker_helper_builder_state_root_t:dir { getattr search };"},
		{"state-root grant toward the wrong target (builder_state_t)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search };"},
		{"state-root grant toward the wrong target (builder_runtime_root_t)", "allow docker_helper_buildkitd_t docker_helper_builder_runtime_root_t:dir { getattr search };"},
		{"state-root grant toward the wrong target (builder_runtime_t)", "allow docker_helper_buildkitd_t docker_helper_builder_runtime_t:dir { getattr search };"},
		{"state-root grant on the wrong class", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:file { getattr search };"},
		{"reordered brace form of the state-root rule", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir { search getattr };"},
		{"parallel bare getattr rule beside the canonical pair", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir getattr;"},
		{"parallel bare search rule beside the canonical pair", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir search;"},
		{"split state-root grant", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir getattr;\nallow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir search;"},
		{"duplicate of the state-root rule", canonicalStateRoot},
		// the 4C-68 categorized state-tree plane (exactly the
		// { getattr search write add_name } quadruple; the missing-rule
		// case is covered by the withoutStateTree removal above)
		{"the old 4C-67 triple form (missing add_name)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search write };"},
		{"the old 4C-66 pair form (missing write+add_name)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search };"},
		{"the brace search-write form (missing getattr+add_name)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { search write };"},
		{"the brace getattr-write form (missing search+add_name)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr write };"},
		{"the brace search-add_name form (missing getattr+write)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { search add_name };"},
		{"the old 4C-65 bare getattr form (missing search+write+add_name)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir getattr;"},
		{"the brace getattr-only form (missing search+write+add_name)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr };"},
		{"search-only (missing getattr+write+add_name)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir search;"},
		{"the brace search-only form (missing getattr+write+add_name)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { search };"},
		{"write-only (missing getattr+search+add_name)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir write;"},
		{"the brace write-only form (missing getattr+search+add_name)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { write };"},
		{"add_name-only (missing getattr+search+write)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir add_name;"},
		{"the brace add_name-only form (missing getattr+search+write)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { add_name };"},
		{"create instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir create;"},
		{"remove_name instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir remove_name;"},
		{"read instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir read;"},
		{"open instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir open;"},
		{"setattr instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir setattr;"},
		{"rmdir instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir rmdir;"},
		{"mounton instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir mounton;"},
		{"lock instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir lock;"},
		// the fifth-permission sweep on the quadruple: dir:add_name is
		// NOT a creation bundle — the kernel emits each entry-mutation
		// hook as its own decision and none rides the add_name grant
		{"the quadruple + remove_name", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search write add_name remove_name };"},
		{"the quadruple + create", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search write add_name create };"},
		{"the quadruple + setattr", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search write add_name setattr };"},
		{"the quadruple + rmdir", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search write add_name rmdir };"},
		{"the quadruple + read", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search write add_name read };"},
		{"the quadruple + open", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search write add_name open };"},
		{"the quadruple + lock", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search write add_name lock };"},
		{"the quadruple + mounton", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search write add_name mounton };"},
		{"state-tree grant from the wrong source (the flow)", "allow docker_helper_rootlesskit_t docker_helper_builder_state_t:dir getattr;"},
		{"state-tree grant from the wrong source (the manager)", "allow docker_helper_builder_t docker_helper_builder_state_t:dir getattr;"},
		{"state-tree grant from the wrong source (the daemon)", "allow docker_helper_t docker_helper_builder_state_t:dir getattr;"},
		{"state-tree grant from the wrong source (the launcher)", "allow docker_helper_builder_launcher_t docker_helper_builder_state_t:dir getattr;"},
		{"state-tree grant toward the wrong target (builder_state_root_t)", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:dir getattr;"},
		{"state-tree grant toward the wrong target (builder_t)", "allow docker_helper_buildkitd_t docker_helper_builder_t:dir getattr;"},
		{"state-tree grant toward the wrong target (builder_runtime_t)", "allow docker_helper_buildkitd_t docker_helper_builder_runtime_t:dir getattr;"},
		{"state-tree grant toward the wrong target (builder_runtime_root_t)", "allow docker_helper_buildkitd_t docker_helper_builder_runtime_root_t:dir getattr;"},
		{"state-tree grant on the wrong class (file)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file getattr;"},
		{"state-tree grant on the wrong class (file, add_name shape)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file add_name;"},
		{"reordered brace of the state-tree quadruple", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { search write add_name getattr };"},
		{"split state-tree grant (getattr+search rule + write add_name rule)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { getattr search };\nallow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { write add_name };"},
		{"split state-tree grant (getattr rule + search write add_name rule)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir getattr;\nallow docker_helper_buildkitd_t docker_helper_builder_state_t:dir { search write add_name };"},
		{"parallel bare write rule beside the canonical quadruple", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir write;"},
		{"parallel bare add_name rule beside the canonical quadruple", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir add_name;"},
		{"duplicate of the state-tree rule", canonicalStateTree},
		// the 4C-69 categorized state-tree FILE plane (exactly the bare
		// create rule; the missing-rule case is covered by the
		// withoutStateFile removal above; the dir rule above stays
		// byte-for-semantics the quadruple — a permission added to the
		// dir rule is a dir-plane mutation, never the file plane)
		{"the state-file read instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file read;"},
		{"the state-file write instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file write;"},
		{"the state-file open instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file open;"},
		{"the state-file getattr instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file getattr;"},
		{"the state-file setattr instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file setattr;"},
		{"the state-file lock instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file lock;"},
		{"the state-file unlink instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file unlink;"},
		{"the state-file append instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file append;"},
		{"the state-file map instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file map;"},
		{"the state-file execute instead", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file execute;"},
		// file:create is NOT a file-IO bundle: every create+X partial is
		// a forbidden bundle shape, and the RootlessKit seven-perm shape
		// copied whole is the explicit anti-template case
		{"the state-file pair { create open }", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file { create open };"},
		{"the state-file pair { create write }", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file { create write };"},
		{"the state-file pair { create getattr }", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file { create getattr };"},
		{"the state-file pair { create setattr }", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file { create setattr };"},
		{"the state-file pair { create read }", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file { create read };"},
		{"the state-file triple { create open write }", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file { create open write };"},
		{"the writable-file bundle { create open write getattr setattr }", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file { create open write getattr setattr };"},
		{"the RootlessKit shape copied whole", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file { create open read write getattr setattr lock };"},
		// the class boundary: the authority is the pair (tclass=file, 0x8)
		// — the same bit number on the OTHER classes is a DIFFERENT
		// authority and stays forbidden (dir:create would widen the dir
		// rule's class plane; lnk_file/sock_file are other classes of the
		// per-op tree)
		{"the wrong class (dir:create)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:dir create;"},
		{"the wrong class (lnk_file:create)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:lnk_file create;"},
		{"the wrong class (sock_file:create)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:sock_file create;"},
		{"state-file grant from the wrong source (the flow)", "allow docker_helper_rootlesskit_t docker_helper_builder_state_t:file create;"},
		{"state-file grant from the wrong source (the manager)", "allow docker_helper_builder_t docker_helper_builder_state_t:file create;"},
		{"state-file grant from the wrong source (the daemon)", "allow docker_helper_t docker_helper_builder_state_t:file create;"},
		{"state-file grant from the wrong source (the launcher)", "allow docker_helper_builder_launcher_t docker_helper_builder_state_t:file create;"},
		{"state-file grant toward the wrong target (builder_state_root_t)", "allow docker_helper_buildkitd_t docker_helper_builder_state_root_t:file create;"},
		{"state-file grant toward the wrong target (builder_t)", "allow docker_helper_buildkitd_t docker_helper_builder_t:file create;"},
		{"state-file grant toward the wrong target (builder_runtime_t)", "allow docker_helper_buildkitd_t docker_helper_builder_runtime_t:file create;"},
		{"state-file grant toward the wrong target (builder_runtime_root_t)", "allow docker_helper_buildkitd_t docker_helper_builder_runtime_root_t:file create;"},
		{"brace equivalent of the state-file rule", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file { create };"},
		{"second create rule beside the canonical one (a split second rule)", "allow docker_helper_buildkitd_t docker_helper_builder_state_t:file create;\nallow docker_helper_buildkitd_t docker_helper_builder_state_t:file create;"},
		{"duplicate of the state-file rule", canonicalStateFile},
		{"broad attribute target on the file plane", "allow docker_helper_buildkitd_t file_type:file create;"},
		{"broad attribute source on the file plane", "allow domain docker_helper_builder_state_t:file create;"},
		{"broad attribute target", "allow docker_helper_buildkitd_t file_type:dir getattr;"},
		{"broad attribute source", "allow domain docker_helper_builder_state_t:dir getattr;"},
		{"multi-target brace form", "allow docker_helper_buildkitd_t { docker_helper_builder_state_t docker_helper_builder_state_root_t }:dir getattr;"},
		// parallel / split / duplicate / order shapes
		{"split grant (execute; then read open)", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file execute;\nallow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { read open };"},
		{"reordered brace equivalent", "allow docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:file { open read execute };"},
		{"duplicate of the canonical rule", canonicalExec},
		{"range_transition declaration", "range_transition docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:process s0:c1;"},
	} {
		if violations := buildkitdIdentityViolations(policy + "\n" + mut.rule); len(violations) == 0 {
			t.Errorf("mutation %q must trip the buildkitd authority invariants", mut.name)
		}
	}
	for _, mut := range []struct {
		name string
		rule string
	}{
		{"duplicate transition declaration", "type_transition docker_helper_rootlesskit_t docker_helper_buildkitd_exec_t:process docker_helper_buildkitd_t;"},
		{"parallel transition from the manager", "type_transition docker_helper_builder_t docker_helper_buildkitd_exec_t:process docker_helper_buildkitd_t;"},
		{"parallel transition from the launcher", "type_transition docker_helper_builder_launcher_t docker_helper_buildkitd_exec_t:process docker_helper_buildkitd_t;"},
	} {
		_, mutTransitions := parseSELinuxRules(policy + "\n" + mut.rule)
		count := 0
		for _, tr := range mutTransitions {
			if tr.dest == "docker_helper_buildkitd_t" {
				count++
			}
		}
		if count != 2 {
			t.Errorf("mutation %q must produce a second transition into the buildkitd domain (the exactly-one edge invariant), got %d", mut.name, count)
		}
	}
}

// TestSELinuxPolicyBuildkitdExecIdentitySiblingLabels verifies the negative
// sibling-label invariants of the 4C-57 .fc entry: the shipped rules must
// NOT label the payload siblings or the directory itself — buildctl,
// buildkit-runc, and an arbitrary sibling file under the buildkit tree keep
// their distro labels (each is a separate future executable boundary), and
// the /usr/bin rules stay unaffected.
func TestSELinuxPolicyBuildkitdExecIdentitySiblingLabels(t *testing.T) {
	fc := readSELinuxPolicyFile(t, "packaging/selinux/docker-helper.fc")
	for _, line := range strings.Split(fc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		pattern := fields[0]
		for _, forbidden := range []string{
			"/usr/libexec/docker-helper/buildkit(/.*)?",
			"/usr/libexec/docker-helper/buildkit/buildctl",
			"/usr/libexec/docker-helper/buildkit/buildkit-runc",
			"/usr/libexec/docker-helper(/.*)?",
		} {
			if pattern == forbidden {
				t.Errorf("no shipped fc rule may cover the buildkit siblings or the payload tree (separate future boundaries): %s", trimmed)
			}
		}
	}
	// The /usr/bin rules stay unaffected: the exact-label set is unchanged.
	for _, want := range []string{
		"/usr/bin/docker-helper              --  system_u:object_r:docker_helper_exec_t:s0",
		"/usr/bin/rootlesskit                --  system_u:object_r:docker_helper_rootlesskit_exec_t:s0",
		"/usr/bin/nsenter                    --  system_u:object_r:docker_helper_nsenter_exec_t:s0",
	} {
		if !strings.Contains(fc, want) {
			t.Errorf("the /usr/bin exec identity set must stay unchanged: %q", want)
		}
	}
}

// kernelCommonFilePerms mirrors the kernel's static file-family permission
// order (linux/security/selinux/include/classmap.h): COMMON_FILE_SOCK_PERMS
// (ioctl read write create getattr setattr lock relabelfrom relabelto
// append map), then COMMON_FILE_PERMS (unlink link rename execute quotaon
// mounton audit_access open execmod watch watch_mount watch_sb
// watch_with_perm watch_reads watch_mountns). The selinux_audited masks the
// harness's traces record are numbered by THIS kernel-side order; the loaded
// policy's perms files carry their own numbering and are NEVER the AVC-mask
// decoder (the recorded 4C-53/4C-58 distinction).
var kernelCommonFilePerms = []string{
	"ioctl", "read", "write", "create", "getattr", "setattr", "lock",
	"relabelfrom", "relabelto", "append", "map",
	"unlink", "link", "rename", "execute", "quotaon", "mounton",
	"audit_access", "open", "execmod",
	"watch", "watch_mount", "watch_sb", "watch_with_perm", "watch_reads",
	"watch_mountns",
}

// kernelFileOnlyPerms and kernelDirOnlyPerms mirror the class-specific
// tails: only file (and memfd_file) carry execute_no_trans/entrypoint; only
// dir carries add_name/remove_name/reparent/search/rmdir.
var kernelFileOnlyPerms = []string{"execute_no_trans", "entrypoint"}
var kernelDirOnlyPerms = []string{"add_name", "remove_name", "reparent", "search", "rmdir"}

// kernelProcessPerms mirrors the kernel's static process-class permission
// order (linux/security/selinux/include/classmap.h: fork transition sigchld
// sigkill sigstop signull signal ptrace getsched setsched getsession getpgid
// setpgid getcap setcap share getattr setexec setfscreate noatsecure siginh
// setrlimit rlimitinh dyntransition setcurrent execmem execstack execheap
// setkeycreate setsockcreate getrlimit). The selinux_audited masks the
// harness's traces record for tclass=process are numbered by THIS order.
var kernelProcessPerms = []string{
	"fork", "transition", "sigchld", "sigkill", "sigstop", "signull",
	"signal", "ptrace", "getsched", "setsched", "getsession", "getpgid",
	"setpgid", "getcap", "setcap", "share", "getattr", "setexec",
	"setfscreate", "noatsecure", "siginh", "setrlimit", "rlimitinh",
	"dyntransition", "setcurrent", "execmem", "execstack", "execheap",
	"setkeycreate", "setsockcreate", "getrlimit",
}

// TestSELinuxPolicyKernelClassmapMaskPins pins the kernel-side AVC mask
// decode the staircase's gone-gates and boundary records depend on. The
// masks are derived from the kernel's static classmap order above and
// cross-checked against the values the live canonical runs recorded:
//   - the 4C-58 pins: file:rename=0x2000, file:execute=0x4000,
//     file:quotaon=0x8000 (the 4C-57 canonical run's boundary record
//     denied=0x4000 inside the canonical buildkitd execve window is
//     exactly file:execute);
//   - the live-proven members: read=0x2, write=0x4, create=0x8,
//     getattr=0x10, unlink=0x800, mounton=0x10000, audit_access=0x20000,
//     open=0x40000;
//   - the dir-class companions: add_name=0x4000000, search=0x20000000;
//   - the 4C-66 dir-class write pin: decode(dir, 0x4) == exactly {
//     write } (the tmp_t:dir quarantine records' own bit — the 4C-65
//     deliverable's getattr misdecode corrected in prose; the committed
//     machinery now pins the correct decode);
//   - the 4C-68 dir-class entry-mutation pins: decode(dir, 0x4000000)
//     == exactly { add_name }, decode(dir, 0x8000000) == exactly {
//     remove_name } (the neighbor bit — the next dir-entry boundary
//     must never collide with add_name), decode(dir, 0x24000000) ==
//     exactly { add_name search } (the 4C-67 canonical run's terminal
//     requested mask);
//   - the 4C-69 file-class hard pins + the CLASS-AWARE DECODE
//     REGRESSION: file:write=0x4, file:create=0x8, file:getattr=0x10,
//     file:open=0x40000; decode(file, 0x8) and decode(dir, 0x8) each
//     recover exactly { create }, but the decoder's output preserves
//     the (tclass, permission-set) TUPLE and the two tuples are
//     DISTINCT authorities — (class=file,0x8) != (class=dir,0x8) (the
//     4C-68 canonical run's terminal record is the FILE tuple; a
//     decoder that drops the class loses the security boundary).
func TestSELinuxPolicyKernelClassmapMaskPins(t *testing.T) {
	fileIndex := func(perm string) int {
		for i, p := range append(append([]string{}, kernelCommonFilePerms...), kernelFileOnlyPerms...) {
			if p == perm {
				return i
			}
		}
		return -1
	}
	dirIndex := func(perm string) int {
		for i, p := range append(append([]string{}, kernelCommonFilePerms...), kernelDirOnlyPerms...) {
			if p == perm {
				return i
			}
		}
		return -1
	}
	processIndex := func(perm string) int {
		for i, p := range kernelProcessPerms {
			if p == perm {
				return i
			}
		}
		return -1
	}
	for _, pin := range []struct {
		perm  string
		want  uint
		index int
	}{
		// the 4C-58 decode pins
		{"rename", 0x2000, fileIndex("rename")},
		{"execute", 0x4000, fileIndex("execute")},
		{"quotaon", 0x8000, fileIndex("quotaon")},
		// the live-proven members
		{"read", 0x2, fileIndex("read")},
		{"write", 0x4, fileIndex("write")},
		{"create", 0x8, fileIndex("create")},
		{"getattr", 0x10, fileIndex("getattr")},
		{"unlink", 0x800, fileIndex("unlink")},
		{"mounton", 0x10000, fileIndex("mounton")},
		{"audit_access", 0x20000, fileIndex("audit_access")},
		{"open", 0x40000, fileIndex("open")},
		{"execute_no_trans", 0x4000000, fileIndex("execute_no_trans")},
		{"entrypoint", 0x8000000, fileIndex("entrypoint")},
		// the dir-class companions
		{"add_name", 0x4000000, dirIndex("add_name")},
		{"remove_name", 0x8000000, dirIndex("remove_name")},
		{"search", 0x20000000, dirIndex("search")},
		// the process-class companions (the 4C-60 boundary pin: the
		// transition stage's own denial is process:transition=0x2)
		{"fork", 0x1, processIndex("fork")},
		{"transition", 0x2, processIndex("transition")},
		{"sigchld", 0x4, processIndex("sigchld")},
		{"sigkill", 0x8, processIndex("sigkill")},
		{"signull", 0x20, processIndex("signull")},
		{"signal", 0x40, processIndex("signal")},
		{"getattr", 0x10000, processIndex("getattr")},
		{"setexec", 0x20000, processIndex("setexec")},
		{"dyntransition", 0x800000, processIndex("dyntransition")},
	} {
		if pin.index < 0 {
			t.Errorf("perm %q must exist in the kernel classmap mirror", pin.perm)
			continue
		}
		if got := uint(1) << uint(pin.index); got != pin.want {
			t.Errorf("kernel classmap pin: file-family %q must decode to %#x, mirror gives %#x (index %d)", pin.perm, pin.want, got, pin.index)
		}
	}
	// The combined-mask decode regression (the 4C-59 boundary): the
	// kernel's masks are BIT ORs of the per-perm values, and the decode
	// must recover EXACTLY the granted/denied permission set.
	decode := func(mask uint) []string {
		var out []string
		for i, perm := range append(append([]string{}, kernelCommonFilePerms...), kernelFileOnlyPerms...) {
			if mask&(uint(1)<<uint(i)) != 0 {
				out = append(out, perm)
			}
		}
		return out
	}
	samePerms := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	// decode(file, 0x40002) == exactly { read open } (open=0x40000 |
	// read=0x2) — the 4C-58 canonical run's live boundary record.
	if got := decode(0x40002); !samePerms(got, []string{"read", "open"}) {
		t.Errorf("kernel classmap decode: file mask 0x40002 must decode to exactly { read open }, got %v", got)
	}
	// Negative discrimination: the neighboring combined masks decode to
	// DIFFERENT permission sets — never { read open }.
	if got := decode(0x40004); !samePerms(got, []string{"write", "open"}) {
		t.Errorf("kernel classmap decode: file mask 0x40004 must decode to { write open }, got %v", got)
	}
	if got := decode(0x40008); !samePerms(got, []string{"create", "open"}) {
		t.Errorf("kernel classmap decode: file mask 0x40008 must decode to { create open }, got %v", got)
	}
	if got := decode(0x40002); samePerms(got, []string{"write", "open"}) || samePerms(got, []string{"create", "open"}) {
		t.Errorf("kernel classmap decode: 0x40002 must not decode to a write/create-open set, got %v", got)
	}
	// The 4C-61 target-boundary decode: decode(file, 0x8000000) ==
	// exactly { entrypoint } — and the anti-shift discrimination: the
	// one-shift-down neighbor 0x80000 is execmod, NOT entrypoint.
	if got := decode(0x8000000); !samePerms(got, []string{"entrypoint"}) {
		t.Errorf("kernel classmap decode: file mask 0x8000000 must decode to exactly { entrypoint }, got %v", got)
	}
	if got := decode(0x4000000); !samePerms(got, []string{"execute_no_trans"}) {
		t.Errorf("kernel classmap decode: file mask 0x4000000 must decode to exactly { execute_no_trans }, got %v", got)
	}
	if got := decode(0x80000); !samePerms(got, []string{"execmod"}) {
		t.Errorf("kernel classmap decode: file mask 0x80000 must decode to exactly { execmod } (the anti-shift neighbor), got %v", got)
	}
	// The 4C-62 combined image-load decode: decode(file, 0x4002) ==
	// exactly { read execute } — one terminal decision, never split.
	// Negative discrimination: none of the neighboring/earlier masks
	// decodes to { read execute }: 0x40002={ read open }, 0x4000={
	// execute }, 0x2={ read }.
	if got := decode(0x4002); !samePerms(got, []string{"read", "execute"}) {
		t.Errorf("kernel classmap decode: file mask 0x4002 must decode to exactly { read execute }, got %v", got)
	}
	if got := decode(0x40002); samePerms(got, []string{"read", "execute"}) {
		t.Errorf("kernel classmap decode: 0x40002 must not decode to { read execute } (it is { read open }), got %v", got)
	}
	if got := decode(0x4000); samePerms(got, []string{"read", "execute"}) {
		t.Errorf("kernel classmap decode: 0x4000 must not decode to { read execute } (it is { execute }), got %v", got)
	}
	if got := decode(0x2); samePerms(got, []string{"read", "execute"}) {
		t.Errorf("kernel classmap decode: 0x2 must not decode to { read execute } (it is { read }), got %v", got)
	}
	// The 4C-63 dir-class decode: decode(dir, 0x10) == exactly { getattr
	// } and decode(dir, 0x20000000) == exactly { search } — the
	// terminal-causal getattr and the non-owning search must never
	// collide (0x10 != search, 0x20000000 != getattr).
	dirDecode := func(mask uint) []string {
		var out []string
		for i, perm := range append(append([]string{}, kernelCommonFilePerms...), kernelDirOnlyPerms...) {
			if mask&(uint(1)<<uint(i)) != 0 {
				out = append(out, perm)
			}
		}
		return out
	}
	if got := dirDecode(0x10); !samePerms(got, []string{"getattr"}) {
		t.Errorf("kernel classmap decode: dir mask 0x10 must decode to exactly { getattr }, got %v", got)
	}
	if got := dirDecode(0x20000000); !samePerms(got, []string{"search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x20000000 must decode to exactly { search }, got %v", got)
	}
	if got := dirDecode(0x10); samePerms(got, []string{"search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x10 must not decode to { search }, got %v", got)
	}
	if got := dirDecode(0x20000000); samePerms(got, []string{"getattr"}) {
		t.Errorf("kernel classmap decode: dir mask 0x20000000 must not decode to { getattr }, got %v", got)
	}
	// The 4C-64 combined dir-class decode: decode(dir, 0x20000010) ==
	// exactly { getattr search } — the ONE widened rule's two bits must
	// decode together, and neither single-bit shape may equal the pair
	// (0x20000010 != { search }, 0x20000010 != { getattr }).
	if got := dirDecode(0x20000010); !samePerms(got, []string{"getattr", "search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x20000010 must decode to exactly { getattr search }, got %v", got)
	}
	if got := dirDecode(0x20000010); samePerms(got, []string{"search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x20000010 must not decode to { search } alone, got %v", got)
	}
	if got := dirDecode(0x20000010); samePerms(got, []string{"getattr"}) {
		t.Errorf("kernel classmap decode: dir mask 0x20000010 must not decode to { getattr } alone, got %v", got)
	}
	// The 4C-66 dir-class write pin: decode(dir, 0x4) == exactly {
	// write } — the dir write bit pinned EXPLICITLY so the 4C-65
	// deliverable's tmp_t:dir 0x4 prose misdecode as getattr cannot
	// re-enter the machinery (the loaded-policy numbering stays
	// non-authoritative for AVC masks; the tmp_t:dir quarantine records
	// are write denials, never getattr).
	if got := dirDecode(0x4); !samePerms(got, []string{"write"}) {
		t.Errorf("kernel classmap decode: dir mask 0x4 must decode to exactly { write }, got %v", got)
	}
	if got := dirDecode(0x4); samePerms(got, []string{"getattr"}) {
		t.Errorf("kernel classmap decode: dir mask 0x4 must not decode to { getattr }, got %v", got)
	}
	if got := dirDecode(0x4); samePerms(got, []string{"search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x4 must not decode to { search }, got %v", got)
	}
	if got := dirDecode(0x4); samePerms(got, []string{"getattr", "search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x4 must not decode to { getattr search }, got %v", got)
	}
	if got := dirDecode(0x10); samePerms(got, []string{"write"}) {
		t.Errorf("kernel classmap decode: dir mask 0x10 must not decode to { write }, got %v", got)
	}
	if got := dirDecode(0x20000010); samePerms(got, []string{"write"}) {
		t.Errorf("kernel classmap decode: dir mask 0x20000010 must not decode to containing write, got %v", got)
	}
	// The 4C-67 combined dir-class decode: decode(dir, 0x20000004) ==
	// exactly { search write } — the 4C-66 terminal decision's requested
	// mask decodes to exactly its two members; no third bit rides.
	if got := dirDecode(0x20000004); !samePerms(got, []string{"write", "search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x20000004 must decode to exactly { search write }, got %v", got)
	}
	if got := dirDecode(0x20000004); samePerms(got, []string{"search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x20000004 must not decode to { search } alone, got %v", got)
	}
	if got := dirDecode(0x20000004); samePerms(got, []string{"write"}) {
		t.Errorf("kernel classmap decode: dir mask 0x20000004 must not decode to { write } alone, got %v", got)
	}
	if got := dirDecode(0x20000004); samePerms(got, []string{"getattr", "search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x20000004 must not decode to { getattr search }, got %v", got)
	}
	if got := dirDecode(0x20000004); samePerms(got, []string{"getattr", "search", "write"}) {
		t.Errorf("kernel classmap decode: dir mask 0x20000004 must not decode to { getattr search write }, got %v", got)
	}
	// The 4C-67 requested-vs-denied boundary regression: the GRANT
	// CANDIDATE is decode(DENIED) — exactly { write } — and NEVER
	// decode(requested); granting the requested mask wholesale would
	// re-grant the standing search permission as if it were new
	// authority (the 4C-66 search stays the standing grant, not the
	// delta). The derivation pin: requested minus the standing granted
	// pair { getattr search } equals exactly the denied decode.
	requestedDecode := dirDecode(0x20000004)
	deniedDecode := dirDecode(0x4)
	if !samePerms(deniedDecode, []string{"write"}) {
		t.Errorf("kernel classmap decode: the 4C-66 terminal record's denied=0x4 must be the grant candidate, exactly { write }, got %v", deniedDecode)
	}
	if samePerms(requestedDecode, deniedDecode) {
		t.Error("kernel classmap decode: the requested mask 0x20000004 must never equal the grant candidate decode(denied)=0x4 (the grant-requested-mask error)")
	}
	standing := map[string]bool{"getattr": true, "search": true}
	var delta []string
	for _, p := range requestedDecode {
		if !standing[p] {
			delta = append(delta, p)
		}
	}
	if !samePerms(delta, deniedDecode) {
		t.Errorf("kernel classmap decode: requested(0x20000004) minus the standing { getattr search } must equal the denied decode exactly { write }, got %v (denied decode %v)", delta, deniedDecode)
	}
	// The 4C-68 dir-class add_name pin: decode(dir, 0x4000000) ==
	// exactly { add_name } — the 4C-67 canonical run's own terminal
	// denied bit (the first dir-only tail bit after the common file/sock
	// prefix); the neighbor remove_name=0x8000000 (bit 27) is the NEXT
	// dir-entry boundary and must never collide with it.
	if got := dirDecode(0x4000000); !samePerms(got, []string{"add_name"}) {
		t.Errorf("kernel classmap decode: dir mask 0x4000000 must decode to exactly { add_name }, got %v", got)
	}
	if got := dirDecode(0x4000000); samePerms(got, []string{"remove_name"}) {
		t.Errorf("kernel classmap decode: dir mask 0x4000000 must not decode to { remove_name }, got %v", got)
	}
	if got := dirDecode(0x4000000); samePerms(got, []string{"search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x4000000 must not decode to { search }, got %v", got)
	}
	if got := dirDecode(0x4000000); samePerms(got, []string{"write"}) {
		t.Errorf("kernel classmap decode: dir mask 0x4000000 must not decode to { write }, got %v", got)
	}
	if got := dirDecode(0x8000000); !samePerms(got, []string{"remove_name"}) {
		t.Errorf("kernel classmap decode: dir mask 0x8000000 must decode to exactly { remove_name }, got %v", got)
	}
	if got := dirDecode(0x8000000); samePerms(got, []string{"add_name"}) {
		t.Errorf("kernel classmap decode: dir mask 0x8000000 must not decode to { add_name } (the anti-shift neighbor), got %v", got)
	}
	// The 4C-68 combined dir-class decode: decode(dir, 0x24000000) ==
	// exactly { add_name search } — the 4C-67 terminal decision's
	// requested mask decodes to exactly its two members; no third bit
	// rides.
	if got := dirDecode(0x24000000); !samePerms(got, []string{"add_name", "search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x24000000 must decode to exactly { add_name search }, got %v", got)
	}
	if got := dirDecode(0x24000000); samePerms(got, []string{"add_name"}) {
		t.Errorf("kernel classmap decode: dir mask 0x24000000 must not decode to { add_name } alone, got %v", got)
	}
	if got := dirDecode(0x24000000); samePerms(got, []string{"search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x24000000 must not decode to { search } alone, got %v", got)
	}
	if got := dirDecode(0x24000000); samePerms(got, []string{"getattr", "search"}) {
		t.Errorf("kernel classmap decode: dir mask 0x24000000 must not decode to { getattr search }, got %v", got)
	}
	// The 4C-68 requested-vs-denied boundary regression: the GRANT
	// CANDIDATE is decode(DENIED) — exactly { add_name } — and NEVER
	// decode(requested); granting the requested mask wholesale would
	// re-grant the standing search permission as if it were new
	// authority (the 4C-66 search stays the standing grant, not the
	// delta). The derivation pin: requested minus the standing granted
	// state-tree set { getattr search write } equals exactly the denied
	// decode.
	requestedDecode68 := dirDecode(0x24000000)
	deniedDecode68 := dirDecode(0x4000000)
	if !samePerms(deniedDecode68, []string{"add_name"}) {
		t.Errorf("kernel classmap decode: the 4C-67 terminal record's denied=0x4000000 must be the grant candidate, exactly { add_name }, got %v", deniedDecode68)
	}
	if samePerms(requestedDecode68, deniedDecode68) {
		t.Error("kernel classmap decode: the requested mask 0x24000000 must never equal the grant candidate decode(denied)=0x4000000 (the grant-requested-mask error)")
	}
	standing68 := map[string]bool{"getattr": true, "search": true, "write": true}
	var delta68 []string
	for _, p := range requestedDecode68 {
		if !standing68[p] {
			delta68 = append(delta68, p)
		}
	}
	if !samePerms(delta68, deniedDecode68) {
		t.Errorf("kernel classmap decode: requested(0x24000000) minus the standing { getattr search write } must equal the denied decode exactly { add_name }, got %v (denied decode %v)", delta68, deniedDecode68)
	}
	// The 4C-69 file-class hard pins + THE CLASS-AWARE DECODE
	// REGRESSION. The 4C-68 canonical run's terminal record carried
	// tclass=file requested=denied=0x8: the same bit NUMBER exists on
	// every file-family class (the common file/sock prefix bit 3), so a
	// decoder that drops the class and returns the permission set alone
	// LOSES the security boundary — the authority is the TUPLE
	// (tclass, permission-set), never the permission set alone. The
	// pins: file:write=0x4, file:create=0x8, file:getattr=0x10,
	// file:open=0x40000 (the kernel classmap's file-class numbering).
	// The class-aware decode: decode(file, mask) vs decode(dir, mask)
	// each recover exactly { create } for 0x8 — but the TUPLES differ,
	// and equating them is the tclass-loss error this regression pins.
	classDecode := func(class string, mask uint) string {
		var perms []string
		switch class {
		case "file":
			perms = decode(mask)
		case "dir":
			perms = dirDecode(mask)
		default:
			perms = nil
		}
		// The tuple's canonical form: (class, kernel-bit-order set).
		return "(" + class + ", " + strings.Join(perms, " ") + ")"
	}
	// The file-class hard pins decode to exactly their single members.
	if got := classDecode("file", 0x4); got != "(file, write)" {
		t.Errorf("kernel classmap decode: file mask 0x4 must decode to the tuple (file, { write }), got %s", got)
	}
	if got := classDecode("file", 0x8); got != "(file, create)" {
		t.Errorf("kernel classmap decode: file mask 0x8 must decode to the tuple (file, { create }), got %s", got)
	}
	if got := classDecode("file", 0x10); got != "(file, getattr)" {
		t.Errorf("kernel classmap decode: file mask 0x10 must decode to the tuple (file, { getattr }), got %s", got)
	}
	if got := classDecode("file", 0x40000); got != "(file, open)" {
		t.Errorf("kernel classmap decode: file mask 0x40000 must decode to the tuple (file, { open }), got %s", got)
	}
	// The dir-class same-bit companion: decode(dir, 0x8) also recovers
	// exactly { create } (the shared prefix bit), but as the DIR tuple.
	if got := classDecode("dir", 0x8); got != "(dir, create)" {
		t.Errorf("kernel classmap decode: dir mask 0x8 must decode to the tuple (dir, { create }), got %s", got)
	}
	// THE CLASS BOUNDARY (the 4C-69 security regression): the two
	// tuples are DISTINCT authorities even though their permission
	// sets are identical — (class=file,0x8) != (class=dir,0x8). A
	// decoder output that preserved only the permission set would make
	// these two compare equal (the tclass-loss error).
	if classDecode("file", 0x8) == classDecode("dir", 0x8) {
		t.Error("kernel classmap decode: the tuples (file, 0x8) and (dir, 0x8) must stay DISTINCT authorities (the tclass-loss error) — the decoder output must preserve the (tclass, permission-set) tuple, never the permission set alone")
	}
	// The same tuple discipline on the other pinned bits: same set,
	// different class, never equal.
	for _, pair := range []struct{ mask uint }{{0x4}, {0x10}, {0x40000}} {
		if classDecode("file", pair.mask) == classDecode("dir", pair.mask) {
			t.Errorf("kernel classmap decode: the file/dir tuples for mask %#x must stay distinct authorities (the tclass-loss error)", pair.mask)
		}
	}
	// The 4C-69 grant-candidate pin: the 4C-68 canonical run's terminal
	// decision is the FILE tuple — decode(tclass=file, denied=0x8) ==
	// exactly { create } ON file — and never the dir tuple (granting
	// dir:create for a file-class denial is the wrong-class error).
	if got := classDecode("file", 0x8); got == "(dir, create)" {
		t.Error("kernel classmap decode: the 4C-69 grant candidate must be the file tuple (file, { create }), never the dir tuple (dir, { create }) (the wrong-class error)")
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
		// 4C-57: the exact buildkitd exec identity and the negative
		// siblings — ONLY the canonical daemon binary carries the type;
		// the payload siblings and the directory itself keep their distro
		// labels (no shipped rule matches them), and the /usr/bin exec
		// identities stay unaffected.
		{"/usr/libexec/docker-helper/buildkit/buildkitd", "docker_helper_buildkitd_exec_t"},
		{"/usr/libexec/docker-helper/buildkit/buildctl", ""},
		{"/usr/libexec/docker-helper/buildkit/buildkit-runc", ""},
		{"/usr/libexec/docker-helper/buildkit/sibling-arbitrary", ""},
		{"/usr/libexec/docker-helper/buildkit", ""},
		{"/usr/bin/docker-helper", "docker_helper_exec_t"},
		{"/usr/bin/rootlesskit", "docker_helper_rootlesskit_exec_t"},
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
			"restorecon /usr/libexec/docker-helper/buildkit/buildkitd",
		},
		"packaging/install-system.sh": {
			"\"$RESTORECON\" -R /run/docker-helper-builder",
			"\"$RESTORECON\" -R /var/lib/docker-helper-builder",
			"\"$RESTORECON\" /usr/bin/rootlesskit",
			"\"$RESTORECON\" /usr/bin/slirp4netns",
			"\"$RESTORECON\" /usr/bin/newuidmap",
			"\"$RESTORECON\" /usr/libexec/docker-helper/buildkit/buildkitd",
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

// TestSELinuxPermsFilesArePolicyNumbering verifies the runtime interface
// form the harness's numeric permission map is built from: every
// /sys/fs/selinux/class/<class>/perms/<permission> file carries a decimal
// index of the LOADED POLICY's class definition, and the staircase's
// permission names exist as files. The perms files are the recorded
// interface fact — they are NOT the kernel's AVC-mask decode (the two
// numberings differ on the target kernel/policy pair; the kernel's own
// calibrated records pin that: dir:search = 0x20000000 and
// dir:mounton = 0x10000 as AVC masks while the perms files number search
// 31 and mounton 18, run 37099264752's preflight inventory). The test
// runs only where SELinuxfs exists; elsewhere there is no runtime
// interface to check.
func TestSELinuxPermsFilesArePolicyNumbering(t *testing.T) {
	permsRoot := "/sys/fs/selinux/class"
	if _, err := os.Stat(filepath.Join(permsRoot, "dir", "perms")); err != nil {
		t.Skipf("selinuxfs class perms unavailable on this host: %v", err)
	}
	for _, want := range []string{"mounton", "relabelto", "search"} {
		b, err := os.ReadFile(filepath.Join(permsRoot, "dir", "perms", want))
		if err != nil {
			t.Fatalf("the dir class's perms file for %s must exist: %v", want, err)
		}
		if _, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err != nil {
			t.Errorf("the dir class's perms file for %s must carry a decimal index, got %q: %v", want, strings.TrimSpace(string(b)), err)
		}
	}
	for _, want := range []string{"relabelfrom", "relabelto"} {
		if _, err := os.Stat(filepath.Join(permsRoot, "tun_socket", "perms", want)); err != nil {
			t.Fatalf("the tun_socket class's perms file for %s must exist: %v", want, err)
		}
	}
}

// TestSELinuxPermissionKernelClassmapDecode verifies the AVC-mask decode
// rule: the masks the kernel's access decisions and the selinux_audited
// tracepoint carry follow the KERNEL'S OWN STATIC class/perm numbering
// (security/selinux/include/classmap.h), and the staircase's decode facts
// are each pinned by the kernel's own records. The fixture carries the
// kernel's class lists for dir, file, and tun_socket; the asserted decodes
// are the calibrated facts: dir:relabelto = 0x100 and dir:mounton =
// 0x10000 (run 37050894858's audit slice names mounton for the
// rootlesskit child's mount("/") denial — the 4C-38 boundary pair), and
// tun_socket:relabelfrom = 0x80 / tun_socket:relabelto = 0x100 (the
// 4C-35/4C-36 co-captured pairs), with dir:search = 0x20000000 and
// file:getattr = 0x10 as the same-numbering cross-checks, and
// dir:add_name = 0x4000000 — the 4C-41 boundary of the canonical 4C-40
// run 37104707444 (denied 0x4000000 inside
// sys_mkdirat("/tmp/rootlesskit-b1515496009", 0700), the mkdir's
// name-creation mediation after the granted write), and dir:create =
// 0x8 — the 4C-42 boundary of the canonical 4C-41 run 37107847258
// (denied 0x8 in the same window, the new-directory-object hook with the
// target type live-proven as tmp_t — the inherited parent label, no type
// transition). The corrected
// direction must hold in BOTH directions: the 4C-38 listing-order misread
// (0x10000 as relabelto) and the policy's own perms-file numbering
// (mounton indexed 18 on the target's loaded policy; 1<<26 claimed as
// watch_reads for the add_name mask) must never come back as AVC decodes.
func TestSELinuxPermissionKernelClassmapDecode(t *testing.T) {
	fixtures := []struct {
		class string
		index map[string]int
	}{
		{
			// The kernel's dir class: COMMON_FILE_PERMS (11 common
			// file/sock perms + 15 file-only perms) + dir's own five.
			class: "dir",
			index: map[string]int{
				"ioctl": 0, "read": 1, "write": 2, "create": 3, "getattr": 4,
				"setattr": 5, "lock": 6, "relabelfrom": 7, "relabelto": 8,
				"append": 9, "map": 10, "unlink": 11, "link": 12, "rename": 13,
				"execute": 14, "quotaon": 15, "mounton": 16, "audit_access": 17,
				"open": 18, "execmod": 19, "watch": 20, "watch_mount": 21,
				"watch_sb": 22, "watch_with_perm": 23, "watch_reads": 24,
				"watch_mountns": 25, "add_name": 26, "remove_name": 27,
				"reparent": 28, "search": 29, "rmdir": 30,
			},
		},
		{
			// The kernel's file class: COMMON_FILE_PERMS +
			// execute_no_trans + entrypoint.
			class: "file",
			index: map[string]int{
				"ioctl": 0, "read": 1, "write": 2, "create": 3, "getattr": 4,
				"setattr": 5, "lock": 6, "relabelfrom": 7, "relabelto": 8,
				"append": 9, "map": 10, "unlink": 11, "link": 12, "rename": 13,
				"execute": 14, "quotaon": 15, "mounton": 16, "audit_access": 17,
				"open": 18, "execmod": 19, "watch": 20, "watch_mount": 21,
				"watch_sb": 22, "watch_with_perm": 23, "watch_reads": 24,
				"watch_mountns": 25, "execute_no_trans": 26, "entrypoint": 27,
			},
		},
		{
			// The kernel's lnk_file class: COMMON_FILE_PERMS (the
			// same common layout as the file class — symlinks carry
			// the full common perm set including read/write at the
			// shared indices, even when those perms are rarely
			// exercised on a symlink object). The 4C-48 asserted
			// decodes pin the common neighbors for anti-shift:
			// lnk_file:create = 0x8 — the canonical 4C-47 run
			// (37153317223) recorded requested=0x8 denied=0x8
			// tcontext=tmpfs_t:s0 tclass=lnk_file INSIDE the
			// symlinkat(".ro2286969802/.pwd.lock" -> "/etc/.pwd.lock")
			// window, 16µs before its failing exit — the symlink
			// object's own creation check on the inherited parent
			// label. The 4C-53 unlink decode pins the removal
			// neighbors: the canonical 4C-52 run's RemoveAll("/etc/
			// resolv.conf") boundary record named { unlink } on the
			// tmpfs_t:lnk_file pair.
			class: "lnk_file",
			index: map[string]int{
				"ioctl": 0, "read": 1, "write": 2, "create": 3, "getattr": 4,
				"setattr": 5, "lock": 6, "relabelfrom": 7, "relabelto": 8,
				"append": 9, "map": 10, "unlink": 11, "link": 12, "rename": 13,
				"execute": 14, "quotaon": 15, "mounton": 16, "audit_access": 17,
				"open": 18, "execmod": 19, "watch": 20, "watch_mount": 21,
				"watch_sb": 22, "watch_with_perm": 23, "watch_reads": 24,
				"watch_mountns": 25, "execute_no_trans": 26, "entrypoint": 27,
			},
		},
		{
			// The kernel's tun_socket class: COMMON_SOCK_PERMS +
			// attach_queue.
			class: "tun_socket",
			index: map[string]int{
				"ioctl": 0, "read": 1, "write": 2, "create": 3, "getattr": 4,
				"setattr": 5, "lock": 6, "relabelfrom": 7, "relabelto": 8,
				"append": 9, "map": 10, "bind": 11, "connect": 12, "listen": 13,
				"accept": 14, "getopt": 15, "setopt": 16, "shutdown": 17,
				"recvfrom": 18, "sendto": 19, "name_bind": 20, "attach_queue": 21,
			},
		},
	}
	classmap := map[string]map[string]uint64{}
	for _, f := range fixtures {
		m := make(map[string]uint64, len(f.index))
		for name, idx := range f.index {
			m[name] = uint64(1) << uint(idx)
		}
		classmap[f.class] = m
	}
	decode := func(class string, mask uint64) []string {
		var decoded []string
		for name, value := range classmap[class] {
			if mask&value != 0 {
				decoded = append(decoded, name)
			}
		}
		return decoded
	}
	one := func(class string, mask uint64, want string) {
		t.Helper()
		got := decode(class, mask)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s mask %#x must decode to exactly { %s } (the kernel's own static classmap), got %v", class, mask, want, got)
		}
	}
	one("dir", 0x10000, "mounton")
	one("dir", 0x100, "relabelto")
	one("dir", 0x20000000, "search")
	one("dir", 0x4000000, "add_name")
	one("dir", 0x8, "create")
	one("tun_socket", 0x80, "relabelfrom")
	one("tun_socket", 0x100, "relabelto")
	one("file", 0x10, "getattr")
	one("file", 0x4000, "execute")
	// The 4C-54 file-class decodes — the DECODER CORRECTION's own
	// regression: the canonical 4C-53 run 37350350345's terminal
	// boundary carried requested=0x8 denied=0x8 tcontext=tmpfs_t:s0
	// tclass=file INSIDE the openat("/etc/resolv.conf",
	// O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC) window — and the 4C-53
	// deliverable decoded that mask as { write } from the loaded
	// policy's perms-file VALUES (the policy's own numbering, the
	// distro's swapon entry diverging from the kernel's file common).
	// The kernel's own AVC numbering — COMMON_FILE_PERMS — puts create
	// at bit 3 (0x8) and write at bit 2 (0x4); the granted permission is
	// therefore exactly create. These pins catch exactly that
	// value-as-bit error: a re-decode of 0x8 as write, or 0x4 as read,
	// must fail here.
	one("file", 0x2, "read")
	one("file", 0x4, "write")
	one("file", 0x8, "create")
	// The 4C-55 open decode: the combined write|open boundary's own
	// open bit — the canonical 4C-54 run 37370262779's terminal record
	// (requested=0x40004 denied=0x40004 tclass=file) decoded per
	// COMMON_FILE_PERMS puts open at bit 18 (0x40000); the 4C-54
	// harness's in-window decode line carried 0x80000 for the
	// open-completion hook (bit 19 — the file class's execmod, never
	// matched by the union mask and never exercised) and that wrong
	// value must not come back: open is 0x40000.
	one("file", 0x40000, "open")
	// The 4C-56 mounton decode and its neighbors: the canonical 4C-55
	// run 37414244341's terminal boundary carried requested=0x10000
	// denied=0x10000 tcontext=tmpfs_t:s0 tclass=file INSIDE the
	// sys_mount(<op-state>/resolv.conf, "/etc/resolv.conf", MS_BIND)
	// window — the mountpoint's own FILE__MOUNTON hook (bit 16). The
	// quotaon/audit_access neighbors are pinned alongside so no
	// listing-order or perms-file shift can move the decode (the
	// perms-file values are the recorded interface fact, never the AVC
	// decode).
	one("file", 0x8000, "quotaon")
	one("file", 0x10000, "mounton")
	one("file", 0x20000, "audit_access")
	// The 4C-48 lnk_file decodes: the common neighbors pinned for
	// anti-shift (the symlink object's own creation check was the
	// canonical 4C-47 run's boundary record). The 4C-50 read decode: the
	// canonical 4C-49 run's openat("/etc/hosts") boundary carried
	// denied=0x2 tclass=lnk_file — the link traversal's own read hook
	// (bit 1 of the static classmap's common layout).
	one("lnk_file", 0x2, "read")
	one("lnk_file", 0x4, "write")
	one("lnk_file", 0x8, "create")
	one("lnk_file", 0x10, "getattr")
	one("lnk_file", 0x20, "setattr")
	// The 4C-53 unlink decode and its anti-shift neighbors (bit 10..13
	// of the static classmap's common layout): the 4C-52 canonical run's
	// RemoveAll("/etc/resolv.conf") unlinkat boundary record named
	// { unlink } on the tmpfs_t:lnk_file pair — the removal hook the
	// 4C-53 widening carries. The map/link/rename neighbors are pinned
	// alongside so no listing-order or perms-file shift can move the
	// decode (the perms files' own numbering is the recorded interface
	// fact, never the AVC decode).
	one("lnk_file", 0x400, "map")
	one("lnk_file", 0x800, "unlink")
	one("lnk_file", 0x1000, "link")
	one("lnk_file", 0x2000, "rename")
	// The 4C-41 boundary's full requested mask: the canonical 4C-40 run
	// 37104707444's record (inside sys_mkdirat("/tmp/rootlesskit-b...",
	// 0700)) carried requested=0x24000000 denied=0x4000000 — the
	// requested pair is the standing search PASSED plus the denied
	// add_name, and the policy's own perms-file numbering would claim
	// 1<<26 for watch_reads (inotify family, impossible on a mkdir
	// path) — the exact add_name decode is pinned as the calibration.
	// (The decode walks a map, so the compared set is order-insensitive.)
	equalPermSet := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		gotSorted := append([]string(nil), got...)
		wantSorted := append([]string(nil), want...)
		sort.Strings(gotSorted)
		sort.Strings(wantSorted)
		for i := range gotSorted {
			if gotSorted[i] != wantSorted[i] {
				return false
			}
		}
		return true
	}
	if got := decode("dir", 0x24000000); !equalPermSet(got, []string{"add_name", "search"}) {
		t.Errorf("dir mask %#x must decode to exactly { add_name search } (the kernel's own static classmap), got %v", uint64(0x24000000), got)
	}
	if got := decode("dir", 0x10000); len(got) == 1 && got[0] == "relabelto" {
		t.Error("the 4C-38 listing-order misread must not come back: dir mask 0x10000 is mounton, not relabelto")
	}
	if got := decode("dir", 0x100); len(got) == 1 && got[0] == "mounton" {
		t.Error("dir mask 0x100 is relabelto, not mounton")
	}
	// The 4C-55 combined-mask regression: the canonical 4C-54 run
	// 37370262779's terminal boundary carried requested=0x40004
	// denied=0x40004 tclass=file INSIDE the same openat(O_CREAT) window
	// — ONE audited decision covering BOTH the open-completion hook's
	// FILE__OPEN and its f_mode-derived FILE__WRITE; the decoded set is
	// exactly { write open } — one evidenced boundary, not two phases.
	if got := decode("file", 0x40004); !equalPermSet(got, []string{"write", "open"}) {
		t.Errorf("file mask 0x40004 must decode to exactly { write open } (the kernel's own static classmap; one audited decision = one boundary), got %v", got)
	}
	// The negatives: the decoder discriminates create (0x8) from write
	// (0x4) at the bit level — the perms-file numbering must never
	// resurface here. 0x40008 = open|create, NOT { write open }; and
	// 0x40004 must never decode as { create open } (the 4C-53
	// deliverable's perms-file misread shape must not come back).
	if got := decode("file", 0x40008); !equalPermSet(got, []string{"create", "open"}) {
		t.Errorf("file mask 0x40008 must decode to exactly { create open } (the create/write bit discrimination), got %v", got)
	}
	if equalPermSet(decode("file", 0x40004), []string{"create", "open"}) {
		t.Error("file mask 0x40004 is { write open }, not { create open } — the perms-file misread must not come back")
	}
	if equalPermSet(decode("file", 0x40008), []string{"write", "open"}) {
		t.Error("file mask 0x40008 is { create open }, not { write open } — the create/write bit discrimination must hold")
	}
	// The 4C-56 exact decode regression: file mask 0x10000 is the
	// bind-mount mountpoint's own mounton hook — exactly { mounton }.
	if got := decode("file", 0x10000); !equalPermSet(got, []string{"mounton"}) {
		t.Errorf("file mask 0x10000 must decode to exactly { mounton } (the kernel's own static classmap), got %v", got)
	}
	if got := decode("file", 0x10000); equalPermSet(got, []string{"quotaon"}) || equalPermSet(got, []string{"audit_access"}) {
		t.Error("file mask 0x10000 is mounton, not quotaon/audit_access — the perms-file misread must not come back")
	}
}

// TestPhase4BVerdictBoundaryDecodeKernelSourced pins the phase-4B
// harness's boundary decode to the kernel's own symbolic statements: the
// verdict names a boundary only from a same-shape AVC record in the audit
// slice, records the loaded policy's numeric perms-file map as the
// policy-numbering interface fact, and the removed decode-from-listing
// order claim and the deleted perms-file mask decoder stay removed.
func TestPhase4BVerdictBoundaryDecodeKernelSourced(t *testing.T) {
	data, err := os.ReadFile("scripts/release-2.4-p5s2-phase4b-launcher-tw.sh")
	if err != nil {
		t.Fatalf("the phase-4B harness not found: %v", err)
	}
	script := string(data)
	for _, want := range []string{
		`"/sys/fs/selinux/class/$class/perms"`,
		"the kernel's own symbolic records for the same shape",
		"numeric_perms_map",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the harness's boundary decode must carry the kernel-sourced decode machinery: %q", want)
		}
	}
	for _, gone := range []string{
		"the Nth listed perm",
		"bitmap-order",
		"numeric_decode",
	} {
		if strings.Contains(script, gone) {
			t.Errorf("the harness must not decode AVC masks from a listing order or from the policy's perms-file numbering (the 4C-38 misread and its perms-file twin): %q", gone)
		}
	}
}
