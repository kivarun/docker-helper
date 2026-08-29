package main

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// newTestManager creates a selinuxFcontextManager with the given selinuxActive
// seam and a no-op lock (for single-threaded tests). readMountinfo defaults to
// an empty mount table (no mount points at or below any workspace), so the
// relabel-boundary guard passes by default; tests that exercise the guard
// override it.
func newTestManager(active func() (bool, bool, error)) *selinuxFcontextManager {
	return &selinuxFcontextManager{
		selinuxActive: active,
		acquireLock: func() (func() error, error) {
			return func() error { return nil }, nil
		},
		readMountinfo: func() ([]byte, error) { return []byte{}, nil },
	}
}

// --- Policy/static tests ---

func TestSELinuxPolicyHasWorkspaceType(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "type docker_helper_workspace_t, file_type;") {
		t.Error("policy must define docker_helper_workspace_t as file_type")
	}
}

func TestSELinuxPolicyDaemonWorkspaceAccess(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, rule := range []string{
		"allow docker_helper_t docker_helper_workspace_t:dir",
		"allow docker_helper_t docker_helper_workspace_t:file",
		"allow docker_helper_t docker_helper_workspace_t:lnk_file",
	} {
		if !strings.Contains(content, rule) {
			t.Errorf("policy must grant: %s", rule)
		}
	}
}

func TestSELinuxPolicyContainerWorkspaceAccess(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, rule := range []string{
		"allow docker_helper_container_t docker_helper_workspace_t:dir",
		"allow docker_helper_container_t docker_helper_workspace_t:file",
		"allow docker_helper_container_t docker_helper_workspace_t:lnk_file",
	} {
		if !strings.Contains(content, rule) {
			t.Errorf("policy must grant: %s", rule)
		}
	}
}

func TestSELinuxPolicyCgroupSearch(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	// Regression for the live enforcing AVC:
	//   scontext=docker_helper_t tcontext=cgroup_t tclass=dir denied { search } comm="docker"
	// The type must be required and only the minimal dir search granted.
	if !strings.Contains(content, "type cgroup_t;") {
		t.Error("policy must require type cgroup_t;")
	}
	if !strings.Contains(content, "allow docker_helper_t cgroup_t:dir { search };") {
		t.Error("policy must grant docker_helper_t cgroup_t:dir search")
	}
	// Regression for the live enforcing AVC:
	//   scontext=docker_helper_t tcontext=cgroup_t tclass=file denied { read } comm="docker" name=cpu.max
	//   scontext=docker_helper_t tcontext=cgroup_t tclass=file denied { open } path=.../docker-helper.service/cpu.max
	if !strings.Contains(content, "allow docker_helper_t cgroup_t:file { read open };") {
		t.Error("policy must grant docker_helper_t cgroup_t:file read open")
	}
}

func TestSELinuxPolicyContainerProcAndChrFile(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	// Regression for the live enforcing AVC:
	//   scontext=docker_helper_container_t tcontext=proc_t tclass=file denied { read } name=filesystems
	//   scontext=docker_helper_container_t tcontext=proc_t tclass=file denied { open } path=/proc/filesystems
	if !strings.Contains(content, "type proc_t;") {
		t.Error("policy must require type proc_t;")
	}
	if !strings.Contains(content, "allow docker_helper_container_t proc_t:file { read open };") {
		t.Error("policy must grant docker_helper_container_t proc_t:file read open")
	}
	// Regression for the live enforcing AVC:
	//   scontext=docker_helper_container_t tcontext=container_file_t tclass=chr_file denied { open } paths /dev/tty, /dev/null, /dev/zero
	// The chr_file class declaration and the container_file_t rule must both carry
	// open and write so the container can open/write its character devices.
	if !strings.Contains(content, "class chr_file { append create getattr ioctl read watch open write };") {
		t.Error("chr_file class declaration must include open and write")
	}
	if !strings.Contains(content, "allow docker_helper_container_t container_file_t:chr_file { create getattr read append ioctl watch open write };") {
		t.Error("container_file_t:chr_file rule must include open and write")
	}
}

func TestSELinuxPolicyInitTAndSystemPermissions(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	// Regression for the live enforcing AVC:
	//   scontext=init_t tcontext=docker_helper_runtime_t tclass=lnk_file denied { unlink } name=abba55a5.0
	// systemd RuntimeDirectory cleanup must be able to unlink its symlinks.
	if !strings.Contains(content, "allow init_t docker_helper_runtime_t:lnk_file { unlink };") {
		t.Error("policy must grant init_t docker_helper_runtime_t:lnk_file unlink")
	}
	// Regression for the live enforcing AVC:
	//   scontext=init_t tcontext=docker_helper_t tclass=process denied { siginh }
	// The process class declaration and the init_t -> docker_helper_t process
	// rule must both carry siginh.
	if !strings.Contains(content, "class process { transition siginh noatsecure rlimitinh };") {
		t.Error("process class declaration must include siginh (and the kernel-required noatsecure/rlimitinh)")
	}
	if !strings.Contains(content, "allow init_t docker_helper_t:process { transition siginh };") {
		t.Error("init_t -> docker_helper_t process rule must include siginh")
	}
	// Regression for the live enforcing AVC:
	//   scontext=docker_helper_t tcontext=security_t tclass=file denied { getattr } path=/sys/fs/selinux/enforce
	if !strings.Contains(content, "allow docker_helper_t security_t:file { read open getattr };") {
		t.Error("policy must grant docker_helper_t security_t:file read open getattr")
	}
	// Regression for the live enforcing AVC:
	//   scontext=docker_helper_t tcontext=sysctl_net_t tclass=dir denied { search } name=net
	// The type must be required and directory search granted.
	if !strings.Contains(content, "type sysctl_net_t;") {
		t.Error("policy must require type sysctl_net_t;")
	}
	if !strings.Contains(content, "allow docker_helper_t sysctl_net_t:dir { search };") {
		t.Error("policy must grant docker_helper_t sysctl_net_t:dir search")
	}
	// sysctl_net_t file read/open for the Go listener (proven in enforcing UAT).
	if !strings.Contains(content, "allow docker_helper_t sysctl_net_t:file { read open };") {
		t.Error("policy must grant docker_helper_t sysctl_net_t:file read open")
	}
}

func TestSELinuxPolicyContainerNetAndEntrypoint(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	// Container network egress must come from the standard container-selinux
	// container_net_domain attribute, not from custom per-socket allow rules.
	if !strings.Contains(content, "attribute container_net_domain;") {
		t.Error("policy must require attribute container_net_domain;")
	}
	if !strings.Contains(content, "typeattribute docker_helper_container_t container_net_domain;") {
		t.Error("docker_helper_container_t must be assigned container_net_domain")
	}
	// Workspace scripts must be executable as a container ENTRYPOINT.
	// Regression for: exec /qa/scripts/run_tests.sh: permission denied
	// The container workspace file rules must include entrypoint.
	if !strings.Contains(content, "allow docker_helper_container_t user_home_type:file {\n\tread write create getattr setattr lock open ioctl append\n\tunlink rename execute execute_no_trans map link entrypoint\n};") {
		t.Error("user_home_type:file rule must include entrypoint")
	}
	if !strings.Contains(content, "allow docker_helper_container_t docker_helper_workspace_t:file {\n\tread write create getattr setattr lock open ioctl append\n\tunlink rename execute execute_no_trans map link entrypoint\n};") {
		t.Error("docker_helper_workspace_t:file rule must include entrypoint")
	}
}

func TestSELinuxPolicyNoBroadHostTypeGrants(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	// default_t and var_t must receive no docker_helper_t access at all.
	for _, typ := range []string{"default_t", "var_t"} {
		if strings.Contains(content, "allow docker_helper_t "+typ) {
			t.Errorf("policy must NOT grant docker_helper_t broad access to %s", typ)
		}
	}
	// docker_helper_container_t must never access host usr_t objects.
	if strings.Contains(content, "allow docker_helper_container_t usr_t") {
		t.Error("policy must NOT grant docker_helper_container_t access to usr_t")
	}
	// docker_helper_t may access usr_t only through the narrow workspace-relabel
	// rules proven by AVC evidence (relabelfrom/relabelto, plus getattr on
	// fifo_file for restorecon label reads). Any other class or any
	// read/write/open/execute-style permission on usr_t would expand daemon
	// reach into host user files and must fail.
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "allow docker_helper_t usr_t:") {
			continue
		}
		for _, broad := range []string{"read", "write", "open", "execute", "create", "unlink", "rename", "setattr", "mounton", "append", "ioctl", "lock", "link", "reparent", "add_name", "remove_name", "rmdir", "search"} {
			if strings.Contains(line, broad) {
				t.Errorf("policy must NOT grant docker_helper_t broad access to usr_t: %s", line)
			}
		}
	}
}

func TestSELinuxPolicyUserHomeTypeUnchanged(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, rule := range []string{
		"allow docker_helper_t user_home_type:dir",
		"allow docker_helper_t user_home_type:file",
		"allow docker_helper_container_t user_home_type:dir",
		"allow docker_helper_container_t user_home_type:file",
	} {
		if !strings.Contains(content, rule) {
			t.Errorf("policy must retain: %s", rule)
		}
	}
}

func TestSELinuxPolicySemanageTransition(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	// The Session MAC preparation (ensureWorkspaceFcontext) lists and adds
	// local fcontext rules by executing semanage. Regression for the standard
	// semanage domtrans pattern plus the live enforcing AVC deltas:
	//   avc: denied { noatsecure } scontext=docker_helper_t tcontext=semanage_t tclass=process
	//   avc: denied { execute } scontext=docker_helper_t tcontext=bin_t name=python3.13 tclass=file
	for _, rule := range []string{
		"type semanage_t;",
		"type semanage_exec_t;",
		"type bin_t;",
		"type_transition docker_helper_t semanage_exec_t:process semanage_t;",
		"allow docker_helper_t semanage_t:process { transition siginh noatsecure rlimitinh };",
		"allow docker_helper_t semanage_t:process2 { nnp_transition };",
		"allow docker_helper_t semanage_exec_t:file { execute read open getattr map };",
		"allow semanage_t semanage_exec_t:file { execute read open getattr map entrypoint };",
		"allow docker_helper_t bin_t:file { execute read open getattr map };",
	} {
		if !strings.Contains(content, rule) {
			t.Errorf("policy must grant: %s", rule)
		}
	}
}

func TestSELinuxPolicySELinuxWorkspaceLock(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	// ensureWorkspaceFcontext acquires /run/lock/docker-helper-selinux.lock
	// (var_lock_t) before listing/adding fcontext rules. Regression for the
	// live enforcing AVC:
	//   avc: denied { write } scontext=docker_helper_t tcontext=var_lock_t name=lock tclass=dir
	if !strings.Contains(content, "type var_lock_t;") {
		t.Error("policy must require type var_lock_t;")
	}
	if !strings.Contains(content, "allow docker_helper_t var_lock_t:dir { write add_name };") {
		t.Error("policy must grant docker_helper_t var_lock_t:dir write add_name")
	}
	if !strings.Contains(content, "allow docker_helper_t var_lock_t:file { create open read write getattr lock };") {
		t.Error("policy must grant docker_helper_t var_lock_t:file create/open/read/write/getattr/lock")
	}
}

func TestSELinuxPolicyTrustedCARestartGetattr(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	// The daemon-restart trusted-CA re-preparation runs
	// `restorecon -R -m /run/docker-helper/trusted-ca` as docker_helper_t
	// (execute_no_trans on setfiles_exec_t). The existing hash symlink is
	// already labeled docker_helper_trusted_ca_t, so restorecon only needs to
	// READ its current label. Regression for the live enforcing AVC:
	//   avc: denied { getattr } scontext=docker_helper_t
	//     tcontext=docker_helper_trusted_ca_t tclass=lnk_file comm="restorecon"
	// Without getattr the RPM-reinstall restart fails with
	//   trusted CA restorecon failed: ... Could not set context for
	//   .../<hash>.0: Permission denied
	if !strings.Contains(content, "allow docker_helper_t docker_helper_trusted_ca_t:lnk_file { create read unlink getattr };") {
		t.Error("policy must grant docker_helper_t getattr on the trusted-CA hash symlink for the restart restorecon")
	}
}

// --- Home-path classification tests ---

func TestIsUnderHome(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/home", true},
		{"/home/alice", true},
		{"/home/alice/work", true},
		{"/opt", false},
		{"/data", false},
		{"/projects/agents", false},
		{"/srv", false},
		{"/mnt/storage", false},
		{"/", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := isUnderHome(tc.path); got != tc.want {
				t.Errorf("isUnderHome(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// --- Manager: escaping and pattern tests ---

func TestEscapeFcontextPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/data", "/data"},
		{"/opt", "/opt"},
		{"/projects/agents", "/projects/agents"},
		{"/data.test", "/data\\.test"},
		{"/data[0]", "/data\\[0\\]"},
		{"/foo+bar", "/foo\\+bar"},
		{"/foo*bar", "/foo\\*bar"},
		{"/foo?bar", "/foo\\?bar"},
		{"/foo|bar", "/foo\\|bar"},
		{"/foo^bar", "/foo\\^bar"},
		{"/foo$bar", "/foo\\$bar"},
		{"/foo{bar}", "/foo\\{bar\\}"},
		{"/foo(bar)", "/foo\\(bar\\)"},
		{"/foo\\bar", "/foo\\\\bar"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := escapeFcontextPath(tc.path); got != tc.want {
				t.Errorf("escapeFcontextPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestFcontextPattern(t *testing.T) {
	tests := []struct {
		boundary string
		want     string
	}{
		{"/data", "/data(/.*)?"},
		{"/opt", "/opt(/.*)?"},
		{"/projects/agents", "/projects/agents(/.*)?"},
		{"/data.test", "/data\\.test(/.*)?"},
	}
	for _, tc := range tests {
		t.Run(tc.boundary, func(t *testing.T) {
			if got := fcontextPattern(tc.boundary); got != tc.want {
				t.Errorf("fcontextPattern(%q) = %q, want %q", tc.boundary, got, tc.want)
			}
		})
	}
}

func TestFcontextStem(t *testing.T) {
	tests := []struct {
		pattern string
		want    string
	}{
		{"/data(/.*)?", "/data"},
		{"/data\\.test(/.*)?", "/data.test"},
		{"/projects/agents(/.*)?", "/projects/agents"},
		{"/opt(/.*)?", "/opt"},
		{"something_else", ""},
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			if got := fcontextStem(tc.pattern); got != tc.want {
				t.Errorf("fcontextStem(%q) = %q, want %q", tc.pattern, got, tc.want)
			}
		})
	}
}

// --- Manager: ensureWorkspaceFcontext tests ---

func TestEnsureWorkspaceFcontextNotEnforcing(t *testing.T) {
	mgr := newTestManager(func() (bool, bool, error) { return false, false, nil })
	created, err := mgr.ensureWorkspaceFcontext("/data")
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
	if created {
		t.Error("should not create mapping when SELinux not active")
	}
}

func TestEnsureWorkspaceFcontextPermissive(t *testing.T) {
	mgr := newTestManager(func() (bool, bool, error) { return true, false, nil })
	created, err := mgr.ensureWorkspaceFcontext("/data")
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
	if created {
		t.Error("should not create mapping in permissive mode")
	}
}

func TestEnsureWorkspaceFcontextNewRule(t *testing.T) {
	var calls [][]string
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		calls = append(calls, args)
		if len(args) > 0 && args[0] == "fcontext" {
			if args[1] == "-l" {
				return []byte{}, nil
			}
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}
	created, err := mgr.ensureWorkspaceFcontext("/data")
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
	if !created {
		t.Error("expected newly created mapping")
	}
	var addCall []string
	for _, c := range calls {
		if len(c) > 0 && c[0] == "fcontext" && c[1] == "-a" {
			addCall = c
			break
		}
	}
	if len(addCall) == 0 {
		t.Fatal("no fcontext -a call found")
	}
	if !reflect.DeepEqual(addCall, []string{"fcontext", "-a", "-t", selinuxWorkspaceType, "/data(/.*)?"}) {
		t.Errorf("add argv = %v", addCall)
	}
}

func TestEnsureWorkspaceFcontextIdempotent(t *testing.T) {
	var addCalled bool
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" {
			if args[1] == "-l" {
				return []byte("/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)"), nil
			}
			if args[1] == "-a" {
				addCalled = true
			}
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}
	created, err := mgr.ensureWorkspaceFcontext("/data")
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
	if created {
		t.Error("should not create new mapping when rule already exists")
	}
	if addCalled {
		t.Error("should not add rule when one already exists")
	}
}

func TestEnsureWorkspaceFcontextConflictingRule(t *testing.T) {
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && len(args) > 1 && args[1] == "-l" {
			return []byte("/data(/.*)?  gen_context(system_u:object_r:default_t:s0)"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for conflicting rule")
	}
	if !strings.Contains(err.Error(), "conflicting") {
		t.Errorf("expected 'conflicting' in error, got: %v", err)
	}
}

func TestEnsureWorkspaceFcontextRestoreconFails(t *testing.T) {
	var deleteCalled bool
	var restoreconCalls int
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" {
			if args[1] == "-l" {
				return []byte{}, nil
			}
			if args[1] == "-d" {
				deleteCalled = true
				return []byte{}, nil
			}
		}
		if len(args) > 0 && args[0] == "-R" {
			restoreconCalls++
			if restoreconCalls == 1 {
				return []byte{}, errors.New("restorecon failed")
			}
			return []byte{}, nil
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for restorecon failure")
	}
	if !deleteCalled {
		t.Error("fcontext rule should be removed on restorecon failure (internal rollback)")
	}
	if restoreconCalls != 2 {
		t.Errorf("expected 2 restorecon calls (original + rollback), got %d", restoreconCalls)
	}
}

func TestEnsureWorkspaceFcontextExistingMappingRunsRestorecon(t *testing.T) {
	var restoreconCalled bool
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" {
			if args[1] == "-l" {
				return []byte("/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)"), nil
			}
		}
		if len(args) > 0 && args[0] == "-R" {
			restoreconCalled = true
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}
	created, err := mgr.ensureWorkspaceFcontext("/data")
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
	if created {
		t.Error("should not create new mapping when rule already exists")
	}
	if !restoreconCalled {
		t.Error("restorecon should be called even for existing mapping")
	}
}

func TestEnsureWorkspaceFcontextExistingMappingVerifyFails(t *testing.T) {
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" {
			if args[1] == "-l" {
				return []byte("/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)"), nil
			}
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return "default_t", nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for type mismatch on existing mapping")
	}
	if strings.Contains(err.Error(), "rollback") {
		t.Error("pre-existing rule should not be removed on failure")
	}
}

// --- Overlap detection tests ---

func TestOverlapSiblingBoundaries(t *testing.T) {
	// /data vs /data2 should NOT conflict.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data2(/.*)?  gen_context(system_u:object_r:ssh_home_t:s0)"), nil
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}
	created, err := mgr.ensureWorkspaceFcontext("/data")
	if err != nil {
		t.Fatalf("sibling /data2 should not conflict with /data, got: %v", err)
	}
	if !created {
		t.Error("expected newly created mapping")
	}
}

func TestOverlapNestedOperatorRule(t *testing.T) {
	// /data/sub is inside /data: conflict.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data/sub(/.*)?  gen_context(system_u:object_r:ssh_home_t:s0)"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for nested operator rule")
	}
	if !strings.Contains(err.Error(), "overridden") {
		t.Errorf("expected 'overridden' in error, got: %v", err)
	}
}

func TestOverlapAncestorLocalRule(t *testing.T) {
	// /data is inside /projects: ancestor rule conflicts.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/projects(/.*)?  gen_context(system_u:object_r:usr_t:s0)"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/projects/data")
	if err == nil {
		t.Fatal("expected error for ancestor local rule")
	}
	if !strings.Contains(err.Error(), "ancestor") {
		t.Errorf("expected 'ancestor' in error, got: %v", err)
	}
}

func TestOverlapRegexUnclassifiable(t *testing.T) {
	// Arbitrary regex pattern: fail closed.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data[0-9]+(/.*)?  gen_context(system_u:object_r:usr_t:s0)"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for unclassifiable regex")
	}
	if !strings.Contains(err.Error(), "unclassifiable") {
		t.Errorf("expected 'unclassifiable' in error, got: %v", err)
	}
}

func TestOverlapEquivalenceRecord(t *testing.T) {
	// Equivalence record: fail closed.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data(/.*)?  <<None>>"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for equivalence record")
	}
	if !strings.Contains(err.Error(), "equivalence") {
		t.Errorf("expected 'equivalence' in error, got: %v", err)
	}
}

func TestOverlapUnparseableLocalCustomization(t *testing.T) {
	// Unparseable line: fail closed.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("this is not a valid fcontext line"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for unparseable local customization")
	}
	if !strings.Contains(err.Error(), "unparseable") {
		t.Errorf("expected 'unparseable' in error, got: %v", err)
	}
}

// --- Overlap: escaped path names ---

func TestOverlapEscapedPathNested(t *testing.T) {
	// /data.test/sub inside /data.test => conflict.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data\\.test/sub(/.*)?  gen_context(system_u:object_r:ssh_home_t:s0)"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data.test")
	if err == nil {
		t.Fatal("expected error for nested rule under /data.test")
	}
	if !strings.Contains(err.Error(), "overridden") {
		t.Errorf("expected 'overridden' in error, got: %v", err)
	}
}

func TestOverlapEscapedPathSibling(t *testing.T) {
	// /data.test2 vs /data.test => no conflict.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data\\.test2(/.*)?  gen_context(system_u:object_r:ssh_home_t:s0)"), nil
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}
	created, err := mgr.ensureWorkspaceFcontext("/data.test")
	if err != nil {
		t.Fatalf("sibling /data.test2 should not conflict with /data.test, got: %v", err)
	}
	if !created {
		t.Error("expected newly created mapping")
	}
}

func TestOverlapEscapedPathBracket(t *testing.T) {
	// /project[1]/sub inside /project[1] => conflict.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/project\\[1\\]/sub(/.*)?  gen_context(system_u:object_r:ssh_home_t:s0)"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/project[1]")
	if err == nil {
		t.Fatal("expected error for nested rule under /project[1]")
	}
	if !strings.Contains(err.Error(), "overridden") {
		t.Errorf("expected 'overridden' in error, got: %v", err)
	}
}

func TestOverlapEscapedPathPlusSibling(t *testing.T) {
	// /foo+bar2 vs /foo+bar => no conflict.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/foo\\+bar2(/.*)?  gen_context(system_u:object_r:ssh_home_t:s0)"), nil
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}
	created, err := mgr.ensureWorkspaceFcontext("/foo+bar")
	if err != nil {
		t.Fatalf("sibling /foo+bar2 should not conflict with /foo+bar, got: %v", err)
	}
	if !created {
		t.Error("expected newly created mapping")
	}
}

// --- Item 2: always check other local rules even when our exact rule exists ---

func TestEnsureWorkspaceFcontextExistingRuleWithNestedConflict(t *testing.T) {
	// existing: /data(/.*)? -> docker_helper_workspace_t
	// existing: /data/secrets(/.*)? -> operator_type
	// ensureWorkspaceFcontext("/data") MUST fail before restorecon.
	var restoreconCalled bool
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)\n/data/secrets(/.*)?  gen_context(system_u:object_r:ssh_home_t:s0)"), nil
		}
		if len(args) > 0 && args[0] == "-R" {
			restoreconCalled = true
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for nested operator rule alongside our exact rule")
	}
	if !strings.Contains(err.Error(), "overridden") {
		t.Errorf("expected 'overridden' in error, got: %v", err)
	}
	if restoreconCalled {
		t.Error("restorecon must NOT be called when overlap conflict is detected")
	}
}

func TestEnsureWorkspaceFcontextExistingRuleWithUnrelatedSibling(t *testing.T) {
	// existing: /data(/.*)? -> docker_helper_workspace_t
	// existing: /data2(/.*)? -> other_type
	// ensureWorkspaceFcontext("/data") => idempotent success.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)\n/data2(/.*)?  gen_context(system_u:object_r:ssh_home_t:s0)"), nil
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}
	created, err := mgr.ensureWorkspaceFcontext("/data")
	if err != nil {
		t.Fatalf("unrelated sibling should not conflict, got: %v", err)
	}
	if created {
		t.Error("should not create new mapping when rule already exists")
	}
}

// --- Manager: removeFcontextBoundary tests ---

func TestRemoveFcontextBoundary(t *testing.T) {
	var deleteCalled bool
	var restoreconCalled bool
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-d" {
			deleteCalled = true
		}
		if len(args) > 0 && args[0] == "-R" {
			restoreconCalled = true
		}
		return []byte{}, nil
	}
	if err := mgr.removeFcontextBoundary("/data"); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if !deleteCalled {
		t.Error("fcontext -d should be called")
	}
	if !restoreconCalled {
		t.Error("restorecon should be called during rollback")
	}
}

// --- Parse fcontext line tests ---

func TestParseFcontextLine(t *testing.T) {
	tests := []struct {
		line    string
		want    fcontextRule
		matched bool
	}{
		{
			"/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)",
			fcontextRule{pattern: "/data(/.*)?", fileType: "docker_helper_workspace_t"},
			true,
		},
		{
			"/opt(/.*)?  gen_context(system_u:object_r:default_t:s0)",
			fcontextRule{pattern: "/opt(/.*)?", fileType: "default_t"},
			true,
		},
		{
			"/data(/.*)?  system_u:object_r:default_t:s0",
			fcontextRule{pattern: "/data(/.*)?", fileType: "default_t"},
			true,
		},
		{
			"/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0:c100.c200)",
			fcontextRule{pattern: "/data(/.*)?", fileType: "docker_helper_workspace_t"},
			true,
		},
		{
			"/data(/.*)?  <<None>>",
			fcontextRule{pattern: "/data(/.*)?", isEquivalence: true},
			true,
		},
		{
			"invalid line",
			fcontextRule{},
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.line[:min(40, len(tc.line))], func(t *testing.T) {
			got, matched := parseFcontextLine(tc.line)
			if matched != tc.matched {
				t.Errorf("matched = %v, want %v", matched, tc.matched)
			}
			if matched {
				if got.pattern != tc.want.pattern {
					t.Errorf("pattern = %q, want %q", got.pattern, tc.want.pattern)
				}
				if got.fileType != tc.want.fileType {
					t.Errorf("fileType = %q, want %q", got.fileType, tc.want.fileType)
				}
				if got.isEquivalence != tc.want.isEquivalence {
					t.Errorf("isEquivalence = %v, want %v", got.isEquivalence, tc.want.isEquivalence)
				}
			}
		})
	}
}

// --- Fcontext argv tests ---

func TestFcontextAddExactArgv(t *testing.T) {
	var lastArgs []string
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		lastArgs = args
		return []byte{}, nil
	}
	if err := mgr.addFcontextRule("/data(/.*)?", selinuxWorkspaceType); err != nil {
		t.Fatal(err)
	}
	want := []string{"fcontext", "-a", "-t", selinuxWorkspaceType, "/data(/.*)?"}
	if !reflect.DeepEqual(lastArgs, want) {
		t.Errorf("argv = %v, want %v", lastArgs, want)
	}
}

func TestFcontextDeleteExactArgv(t *testing.T) {
	var lastArgs []string
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		lastArgs = args
		return []byte{}, nil
	}
	if err := mgr.removeFcontextRule("/data(/.*)?"); err != nil {
		t.Fatal(err)
	}
	want := []string{"fcontext", "-d", "/data(/.*)?"}
	if !reflect.DeepEqual(lastArgs, want) {
		t.Errorf("argv = %v, want %v", lastArgs, want)
	}
}

func TestFcontextListLocalArgv(t *testing.T) {
	var lastArgs []string
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		lastArgs = args
		return []byte{}, nil
	}
	if _, err := mgr.listLocalFcontextRules(); err != nil {
		t.Fatal(err)
	}
	want := []string{"fcontext", "-l", "-C", "-n"}
	if !reflect.DeepEqual(lastArgs, want) {
		t.Errorf("argv = %v, want %v", lastArgs, want)
	}
}

// TestRestoreconRecursiveArgv pins the exact canonical recursive restorecon
// invocation for workspaces. Rationale (restorecon(8), Tumbleweed
// policycoreutils 3.11-2.2):
//
//	-R  recursive relabel of the workspace boundary.
//	-m  do not read /proc/mounts for non-seclabel mount exclusion. Without it
//	    selinux_restorecon(3) statvfs()es every mounted filesystem, which in the
//	    confined docker_helper_t context requires filesystem getattr on many
//	    mount-scan types that the policy intentionally does not grant.
//	-x  do not cross filesystem boundaries (SELINUX_RESTORECON_XDEV: skip
//	    directories whose st_dev differs from the walk root). Prevents the
//	    recursive relabel from touching a different filesystem mounted beneath
//	    the workspace. Note: -x does NOT protect against same-filesystem bind
//	    mounts (they share st_dev); that case is pre-existing and documented.
//
// -F must never be used (type-only restorecon).
func TestRestoreconRecursiveArgv(t *testing.T) {
	var lastArgs []string
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		lastArgs = args
		return []byte{}, nil
	}
	if err := mgr.restoreconRecursive("/data"); err != nil {
		t.Fatal(err)
	}
	want := []string{"-R", "-m", "-x", "/data"}
	if !reflect.DeepEqual(lastArgs, want) {
		t.Errorf("argv = %v, want %v", lastArgs, want)
	}
	for _, a := range lastArgs {
		if a == "-F" {
			t.Error("restorecon must not use -F (type-only)")
		}
	}
}

// --- mountinfo parsing / workspace relabel-boundary guard tests ---

// mountinfoLine renders a single /proc/self/mountinfo line with the given
// mount point field (raw, kernel-escaped form) and mount source.
func mountinfoLine(mp, src string) string {
	return "36 35 98:0 / " + mp + " rw,relatime - ext4 " + src + " rw"
}

func TestUnescapeMountinfoPath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/opt/ws", "/opt/ws"},
		{"/opt/ws/with\\040space", "/opt/ws/with space"},
		{"/a\\011b", "/a\tb"},
		{"/a\\012b", "/a\nb"},
		{"/a\\134b", "/a\\b"},
		{"/opt/ws/with\\040space\\134dir", "/opt/ws/with space\\dir"},
	}
	for _, tc := range tests {
		if got := unescapeMountinfoPath(tc.in); got != tc.want {
			t.Errorf("unescapeMountinfoPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseMountinfoMountPoints(t *testing.T) {
	data := []byte(
		mountinfoLine("/", "/dev/sda1") + "\n" +
			mountinfoLine("/opt/ws/with\\040space", "/dev/sda2") + "\n" +
			mountinfoLine("/opt/ws/mnt", "/dev/sda2") + "\n")
	mps, err := parseMountinfoMountPoints(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/", "/opt/ws/with space", "/opt/ws/mnt"}
	if !reflect.DeepEqual(mps, want) {
		t.Errorf("mount points = %v, want %v", mps, want)
	}
}

func TestParseMountinfoMountPointsMalformed(t *testing.T) {
	for _, line := range []string{
		"this line has no field separator",
		"1 2 3:4 /opt - ext4 /dev/sda1 rw",
	} {
		if _, err := parseMountinfoMountPoints([]byte(line + "\n")); err == nil {
			t.Errorf("expected error for malformed line %q", line)
		}
	}
}

// TestCheckWorkspaceRelabelBoundary pins the fail-closed boundary
// classification used before any recursive workspace restorecon. The guard is
// deliberately filesystem-agnostic: any mount point at or strictly beneath the
// workspace is rejected, which is exactly what also closes the same-filesystem
// bind-mount alias (a bind mount shares st_dev, so restorecon -x cannot see it;
// the guard does not rely on st_dev).
func TestCheckWorkspaceRelabelBoundary(t *testing.T) {
	tests := []struct {
		name      string
		workspace string
		mounts    []string // raw (kernel-escaped) mount point fields
		wantErr   bool
		wantSub   string
	}{
		{"no mounts below workspace allowed", "/opt/ws", []string{"/"}, false, ""},
		{"parent filesystem mount only allowed", "/opt/ws", []string{"/", "/opt"}, false, ""},
		{"workspace itself mountpoint rejected", "/opt/ws", []string{"/", "/opt", "/opt/ws"}, true, "itself a mount point"},
		{"nested different-fs mount rejected", "/opt/ws", []string{"/", "/opt", "/opt/ws/mnt"}, true, "beneath workspace"},
		{"nested same-fs bind mount rejected", "/opt/ws", []string{"/", "/opt", "/opt/ws/mnt"}, true, "beneath workspace"},
		{"sibling mount allowed", "/opt/ws", []string{"/", "/opt", "/opt/ws-other"}, false, ""},
		{"path-prefix collision allowed", "/opt/ws", []string{"/", "/opt", "/opt/ws-other"}, false, ""},
		{"escaped mountpoint parsed correctly", "/opt/ws", []string{"/", "/opt", "/opt/ws/with\\040space"}, true, "beneath workspace"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var lines []string
			for _, mp := range tc.mounts {
				lines = append(lines, mountinfoLine(mp, "/dev/sda2"))
			}
			mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
			mgr.readMountinfo = func() ([]byte, error) {
				return []byte(strings.Join(lines, "\n") + "\n"), nil
			}
			err := mgr.checkWorkspaceRelabelBoundary(tc.workspace)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.wantSub) {
					t.Errorf("error %q does not contain %q", err, tc.wantSub)
				}
			} else if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

func TestRestoreconRecursiveRefusesNestedMount(t *testing.T) {
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.readMountinfo = func() ([]byte, error) {
		return []byte(mountinfoLine("/opt/ws/mnt", "/dev/sda2") + "\n"), nil
	}
	restoreconCalled := false
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		restoreconCalled = true
		return []byte{}, nil
	}
	err := mgr.restoreconRecursive("/opt/ws")
	if err == nil {
		t.Fatal("expected error for nested mount beneath workspace")
	}
	if !strings.Contains(err.Error(), "beneath workspace") {
		t.Errorf("expected 'beneath workspace' in error, got: %v", err)
	}
	if restoreconCalled {
		t.Error("restorecon must not run when a mount exists beneath the workspace")
	}
}

func TestEnsureWorkspaceFcontextUnsafeFailsClosed(t *testing.T) {
	// A workspace with a mount beneath it must be rejected BEFORE any
	// semanage/restorecon mutation: no fcontext rule is added, no restorecon
	// runs, and no creation is reported.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.readMountinfo = func() ([]byte, error) {
		return []byte(mountinfoLine("/opt/ws/mnt", "/dev/sda2") + "\n"), nil
	}
	mutation := false
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		mutation = true
		return []byte{}, nil
	}
	created, err := mgr.ensureWorkspaceFcontext("/opt/ws")
	if err == nil {
		t.Fatal("expected error for workspace with nested mount")
	}
	if !strings.Contains(err.Error(), "beneath workspace") {
		t.Errorf("expected 'beneath workspace' in error, got: %v", err)
	}
	if created {
		t.Error("must not report creation for an unsafe boundary")
	}
	if mutation {
		t.Error("no semanage/restorecon mutation must occur for an unsafe boundary")
	}
}

func TestRemoveFcontextBoundaryUnsafeKeepsRule(t *testing.T) {
	// Removal ordering contract: the mount-safety preflight must run BEFORE
	// deleting the persistent fcontext rule. When removal would be unsafe, the
	// rule and state must be left intact (fail closed).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.readMountinfo = func() ([]byte, error) {
		return []byte(mountinfoLine("/opt/ws/mnt", "/dev/sda2") + "\n"), nil
	}
	deleteCalled := false
	restoreconCalled := false
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && len(args) > 1 && args[1] == "-d" {
			deleteCalled = true
		}
		if len(args) > 0 && args[0] == "-R" {
			restoreconCalled = true
		}
		return []byte{}, nil
	}
	err := mgr.removeFcontextBoundary("/opt/ws")
	if err == nil {
		t.Fatal("expected error for unsafe removal boundary")
	}
	if deleteCalled {
		t.Error("fcontext rule must NOT be removed when the boundary cannot be safely restored")
	}
	if restoreconCalled {
		t.Error("restorecon must not run for an unsafe removal boundary")
	}
}

// --- Lock serialization test ---

func TestSELinuxWorkspaceLockSerializes(t *testing.T) {
	// Prove that two manager transitions cannot enter the mutation section
	// concurrently. Use a shared injected lock to serialize deterministically.
	var sharedMutex sync.Mutex
	var order []string

	// Per-caller "attempting" signal: closed immediately before calling
	// sharedMutex.Lock(), proving the caller has reached the lock acquisition
	// point but has not yet entered the critical section.
	firstAcquiring := make(chan struct{})
	secondAcquiring := make(chan struct{})

	// Shared lock used by both managers.
	firstAcquire := func() (func() error, error) {
		close(firstAcquiring)
		sharedMutex.Lock()
		return func() error {
			sharedMutex.Unlock()
			return nil
		}, nil
	}
	secondAcquire := func() (func() error, error) {
		close(secondAcquiring)
		sharedMutex.Lock()
		return func() error {
			sharedMutex.Unlock()
			return nil
		}, nil
	}

	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.acquireLock = firstAcquire

	// firstInCritical signals that first has entered the list/mutation section.
	firstInCritical := make(chan struct{})
	// firstRelease signals first to release the lock.
	firstRelease := make(chan struct{})

	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			order = append(order, "first-list")
			close(firstInCritical)
			return []byte{}, nil
		}
		if len(args) > 0 && args[0] == "-R" {
			<-firstRelease
			return []byte{}, nil
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}

	firstDone := make(chan struct{})
	go func() {
		_, _ = mgr.ensureWorkspaceFcontext("/data")
		close(firstDone)
	}()

	// Wait for first to signal it is acquiring the lock.
	<-firstAcquiring
	// Wait for first to enter the critical section.
	<-firstInCritical

	// Start second caller.
	mgr2 := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr2.acquireLock = secondAcquire

	secondInCritical := make(chan struct{})
	secondDone := make(chan struct{})

	mgr2.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			order = append(order, "second-list")
			close(secondInCritical)
			return []byte{}, nil
		}
		return []byte{}, nil
	}
	mgr2.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}

	go func() {
		_, _ = mgr2.ensureWorkspaceFcontext("/data")
		close(secondDone)
	}()

	// Wait for second to signal it is acquiring the lock.
	<-secondAcquiring
	// Now prove second has NOT entered the critical section yet.
	select {
	case <-secondInCritical:
		t.Fatal("second should not enter critical section while first holds the lock")
	default:
		// Expected: second is blocked on sharedMutex.Lock().
	}

	// Release first.
	close(firstRelease)
	<-firstDone
	<-secondDone

	// Verify ordering: first-list before second-list.
	if len(order) != 2 || order[0] != "first-list" || order[1] != "second-list" {
		t.Errorf("expected [first-list, second-list], got %v", order)
	}
}

func TestSELinuxWorkspaceLockAcquisitionFailure(t *testing.T) {
	// Lock acquisition failure: ensureWorkspaceFcontext returns error.
	// No semanage/restorecon mutation occurs after lock acquisition failure.
	var mutationOccurred bool

	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.acquireLock = func() (func() error, error) {
		return nil, errors.New("lock acquisition failed")
	}
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		mutationOccurred = true
		return []byte{}, nil
	}

	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for lock acquisition failure")
	}
	if !strings.Contains(err.Error(), "lock") {
		t.Errorf("expected 'lock' in error, got: %v", err)
	}
	if mutationOccurred {
		t.Error("no semanage/restorecon mutation should occur after lock acquisition failure")
	}
}

// --- Constant tests ---

// --- Item 1: canonical round-trip classification ---

func TestRoundTripBareDot(t *testing.T) {
	// Bare "." is a regex metacharacter, not escaped.
	// fcontextStem should return "" (unclassifiable).
	stem := fcontextStem("/data.test(/.*)?")
	if stem != "" {
		t.Errorf("bare '.' should be unclassifiable, got stem %q", stem)
	}
}

func TestRoundTripBareCaret(t *testing.T) {
	// Bare "^" is a regex metacharacter, not escaped.
	stem := fcontextStem("/data^test(/.*)?")
	if stem != "" {
		t.Errorf("bare '^' should be unclassifiable, got stem %q", stem)
	}
}

func TestRoundTripBareDollar(t *testing.T) {
	// Bare "$" is a regex metacharacter, not escaped.
	stem := fcontextStem("/data$test(/.*)?")
	if stem != "" {
		t.Errorf("bare '$' should be unclassifiable, got stem %q", stem)
	}
}

func TestRoundTripBarePipe(t *testing.T) {
	// Bare "|" is a regex metacharacter, not escaped.
	stem := fcontextStem("/data|test(/.*)?")
	if stem != "" {
		t.Errorf("bare '|' should be unclassifiable, got stem %q", stem)
	}
}

func TestRoundTripTrailingBackslash(t *testing.T) {
	// Trailing single "\" is malformed.
	stem := fcontextStem("/data\\(/.*)?")
	if stem != "" {
		t.Errorf("trailing backslash should be unclassifiable, got stem %q", stem)
	}
}

func TestRoundTripEscapedDot(t *testing.T) {
	// Escaped "." generated by escapeFcontextPath => accepted.
	stem := fcontextStem("/data\\.test(/.*)?")
	if stem != "/data.test" {
		t.Errorf("escaped '.' should be accepted, got stem %q", stem)
	}
}

func TestRoundTripEscapedBracket(t *testing.T) {
	// Escaped "[]" generated by escapeFcontextPath => accepted.
	stem := fcontextStem("/data\\[0\\](/.*)?")
	if stem != "/data[0]" {
		t.Errorf("escaped '[]' should be accepted, got stem %q", stem)
	}
}

func TestRoundTripEscapedPlus(t *testing.T) {
	// Escaped "+" generated by escapeFcontextPath => accepted.
	stem := fcontextStem("/data\\+test(/.*)?")
	if stem != "/data+test" {
		t.Errorf("escaped '+' should be accepted, got stem %q", stem)
	}
}

// --- Item 2: malformed/regex equivalence regressions ---

func TestEquivalenceRegexDestRejected(t *testing.T) {
	// Regex in DEST => fail closed (unparseable).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data[0-9]+ = /other"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for regex in equivalence DEST")
	}
	if !strings.Contains(err.Error(), "unparseable") {
		t.Errorf("expected 'unparseable' in error, got: %v", err)
	}
}

func TestEquivalenceRegexSourceRejected(t *testing.T) {
	// Regex in SOURCE => fail closed (unparseable).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/other = /data[0-9]+"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for regex in equivalence SOURCE")
	}
	if !strings.Contains(err.Error(), "unparseable") {
		t.Errorf("expected 'unparseable' in error, got: %v", err)
	}
}

func TestEquivalenceNonAbsDestRejected(t *testing.T) {
	// Non-absolute DEST => fail closed (unparseable).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("relative/path = /other"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for non-absolute equivalence DEST")
	}
	if !strings.Contains(err.Error(), "unparseable") {
		t.Errorf("expected 'unparseable' in error, got: %v", err)
	}
}

func TestEquivalenceEscapedDestRejected(t *testing.T) {
	// Escaped regex in DEST => fail closed (not a literal path).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data\\.test = /other"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for escaped regex in equivalence DEST")
	}
	if !strings.Contains(err.Error(), "unparseable") {
		t.Errorf("expected 'unparseable' in error, got: %v", err)
	}
}

// --- Item 1: strict backslash escape validation ---

func TestUnknownEscapeBackslashD(t *testing.T) {
	// \d is a PCRE escape, not generated by escapeFcontextPath.
	// Pattern should be unclassifiable.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data\\dtest(/.*)?  gen_context(system_u:object_r:usr_t:s0)"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for unknown escape \\d")
	}
	if !strings.Contains(err.Error(), "unclassifiable") {
		t.Errorf("expected 'unclassifiable' in error, got: %v", err)
	}
}

func TestUnknownEscapeBackslashW(t *testing.T) {
	// \w is a PCRE escape, not generated by escapeFcontextPath.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data\\wtest(/.*)?  gen_context(system_u:object_r:usr_t:s0)"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for unknown escape \\w")
	}
	if !strings.Contains(err.Error(), "unclassifiable") {
		t.Errorf("expected 'unclassifiable' in error, got: %v", err)
	}
}

func TestUnknownEscapeBackslashS(t *testing.T) {
	// \s is a PCRE escape, not generated by escapeFcontextPath.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data\\stest(/.*)?  gen_context(system_u:object_r:usr_t:s0)"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for unknown escape \\s")
	}
	if !strings.Contains(err.Error(), "unclassifiable") {
		t.Errorf("expected 'unclassifiable' in error, got: %v", err)
	}
}

func TestUnknownEscapeBackslashX2f(t *testing.T) {
	// \x2f is a PCRE hex escape, not generated by escapeFcontextPath.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data\\x2ftest(/.*)?  gen_context(system_u:object_r:usr_t:s0)"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for unknown escape \\x2f")
	}
	if !strings.Contains(err.Error(), "unclassifiable") {
		t.Errorf("expected 'unclassifiable' in error, got: %v", err)
	}
}

func TestUnknownEscapeBackslashQ(t *testing.T) {
	// \Q is a PCRE quoting escape, not generated by escapeFcontextPath.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data\\Qtest\\E(/.*)?  gen_context(system_u:object_r:usr_t:s0)"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for unknown escape \\Q")
	}
	if !strings.Contains(err.Error(), "unclassifiable") {
		t.Errorf("expected 'unclassifiable' in error, got: %v", err)
	}
}

// --- Item 2: equivalence record parsing and overlap ---

func TestParseEquivalenceRedirect(t *testing.T) {
	tests := []struct {
		line            string
		wantDest        string
		wantSource      string
		wantEquivalence bool
	}{
		{
			"/unrelated = /other",
			"/unrelated",
			"/other",
			true,
		},
		{
			"/data/sub = /other",
			"/data/sub",
			"/other",
			true,
		},
		{
			"/data = /other",
			"/data",
			"/other",
			true,
		},
		{
			"/other = /data",
			"/other",
			"/data",
			true,
		},
		{
			"not-an-equivalence",
			"",
			"",
			false,
		},
		{
			"/data(/.*)?  gen_context(system_u:object_r:usr_t:s0)",
			"",
			"",
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.line, func(t *testing.T) {
			got, ok := parseFcontextLine(tc.line)
			if tc.wantEquivalence {
				if !ok {
					t.Fatalf("expected parse success for %q", tc.line)
				}
				if !got.isEquivalence {
					t.Errorf("expected equivalence for %q", tc.line)
				}
				if got.equivalenceDest != tc.wantDest {
					t.Errorf("dest = %q, want %q", got.equivalenceDest, tc.wantDest)
				}
				if got.equivalenceSource != tc.wantSource {
					t.Errorf("source = %q, want %q", got.equivalenceSource, tc.wantSource)
				}
			} else {
				// Should not be parsed as equivalence redirect.
				if ok && got.isEquivalence && got.equivalenceDest != "" {
					t.Errorf("should not be equivalence redirect for %q", tc.line)
				}
			}
		})
	}
}

func TestEquivalenceDisjointAllowed(t *testing.T) {
	// /unrelated = /other with boundary=/data => allowed.
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/unrelated = /other"), nil
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}
	created, err := mgr.ensureWorkspaceFcontext("/data")
	if err != nil {
		t.Fatalf("disjoint equivalence should be allowed, got: %v", err)
	}
	if !created {
		t.Error("expected newly created mapping")
	}
}

func TestEquivalenceDestEqualsBoundary(t *testing.T) {
	// /data = /other => reject (DEST equals boundary).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data = /other"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for equivalence DEST equals boundary")
	}
	if !strings.Contains(err.Error(), "equivalence") {
		t.Errorf("expected 'equivalence' in error, got: %v", err)
	}
}

func TestEquivalenceDestDescendantOfBoundary(t *testing.T) {
	// /data/sub = /other => reject (DEST is descendant of boundary).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data/sub = /other"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for equivalence DEST descendant of boundary")
	}
	if !strings.Contains(err.Error(), "equivalence") {
		t.Errorf("expected 'equivalence' in error, got: %v", err)
	}
}

func TestEquivalenceSourceEqualsBoundary(t *testing.T) {
	// /other = /data => reject (SOURCE equals boundary).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/other = /data"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for equivalence SOURCE equals boundary")
	}
	if !strings.Contains(err.Error(), "equivalence") {
		t.Errorf("expected 'equivalence' in error, got: %v", err)
	}
}

func TestEquivalenceSourceDescendantOfBoundary(t *testing.T) {
	// /other = /data/sub => reject (SOURCE is descendant of boundary).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/other = /data/sub"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for equivalence SOURCE descendant of boundary")
	}
	if !strings.Contains(err.Error(), "equivalence") {
		t.Errorf("expected 'equivalence' in error, got: %v", err)
	}
}

func TestEquivalenceDestAncestorOfBoundary(t *testing.T) {
	// /parent = /other with boundary=/parent/data => reject (DEST is ancestor of boundary).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/parent = /other"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/parent/data")
	if err == nil {
		t.Fatal("expected error for equivalence DEST ancestor of boundary")
	}
	if !strings.Contains(err.Error(), "equivalence") {
		t.Errorf("expected 'equivalence' in error, got: %v", err)
	}
}

func TestEquivalenceSourceAncestorOfBoundary(t *testing.T) {
	// /other = /parent with boundary=/parent/data => reject (SOURCE is ancestor of boundary).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/other = /parent"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/parent/data")
	if err == nil {
		t.Fatal("expected error for equivalence SOURCE ancestor of boundary")
	}
	if !strings.Contains(err.Error(), "equivalence") {
		t.Errorf("expected 'equivalence' in error, got: %v", err)
	}
}

func TestSELinuxWorkspaceTypeConstant(t *testing.T) {
	if selinuxWorkspaceType != "docker_helper_workspace_t" {
		t.Errorf("selinuxWorkspaceType = %q, want %q", selinuxWorkspaceType, "docker_helper_workspace_t")
	}
}

// --- Fcontext regex no over-match ---

func TestFcontextRegexNoOverMatch(t *testing.T) {
	if pattern := fcontextPattern("/data"); pattern != "/data(/.*)?" {
		t.Errorf("pattern = %q, want %q", pattern, "/data(/.*)?")
	}
	if pattern := fcontextPattern("/data.test"); pattern != "/data\\.test(/.*)?" {
		t.Errorf("pattern = %q, want %q", pattern, "/data\\.test(/.*)?")
	}
}

// --- Packaging: semanage dependency ---

func TestRPMRequiresSemanageProvider(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "policycoreutils-python-utils") {
		t.Error("RPM must depend on policycoreutils-python-utils (provides semanage)")
	}
}

// =============================================================================
// SELinux "/" root-boundary regression tests
//
// These tests prove fail-closed behavior when an operator-local resource
// rooted at "/" overlaps a requested workspace. The canonical root-first
// containment API (pathStrictlyWithin) correctly treats "/" as an ancestor
// of every path.
// =============================================================================

func TestSELinuxRootSlashConflictingFcontext(t *testing.T) {
	// An operator-local fcontext rule at "/" must conflict with any workspace.
	// pathStrictlyWithin treats "/" as an ancestor of "/data".
	mgr := &selinuxFcontextManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if args[0] == "fcontext" {
				// Simulate an existing rule at "/" that maps to a different type.
				return []byte("/(/.*)?  gen_context(system_u:object_r:default_t:s0)"), nil
			}
			return nil, nil
		},
		readPathCon: func(path string) (string, error) {
			return "docker_helper_workspace_t", nil
		},
		selinuxActive: func() (bool, bool, error) {
			return true, true, nil
		},
		readMountinfo: func() ([]byte, error) { return []byte{}, nil },
		acquireLock: func() (func() error, error) {
			return func() error { return nil }, nil
		},
	}

	// /data is a proper descendant of "/". The "/" rule must conflict.
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("ensureWorkspaceFcontext must fail when operator-local rule at / overlaps /data")
	}
	if !strings.Contains(err.Error(), "ancestor") {
		t.Errorf("expected ancestor error, got: %v", err)
	}
}

func TestSELinuxRootSlashEquivalenceOverlap(t *testing.T) {
	// A redirect-style equivalence at "/" must overlap any workspace.
	mgr := &selinuxFcontextManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if args[0] == "fcontext" {
				// Simulate a redirect-style equivalence: / = /some/other/path
				return []byte("/ = /var/lib/some-namespace\n"), nil
			}
			return nil, nil
		},
		readPathCon: func(path string) (string, error) {
			return "docker_helper_workspace_t", nil
		},
		selinuxActive: func() (bool, bool, error) {
			return true, true, nil
		},
		readMountinfo: func() ([]byte, error) { return []byte{}, nil },
		acquireLock: func() (func() error, error) {
			return func() error { return nil }, nil
		},
	}

	// /data must conflict with the equivalence at "/".
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("ensureWorkspaceFcontext must fail when equivalence at / overlaps /data")
	}
	if !strings.Contains(err.Error(), "overlaps") {
		t.Errorf("expected overlap error, got: %v", err)
	}
}

func TestSELinuxRootSlashEquivalenceSourceOverlap(t *testing.T) {
	// An equivalence where SOURCE is "/" must overlap any workspace.
	mgr := &selinuxFcontextManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if args[0] == "fcontext" {
				// /some/dest = /
				return []byte("/some/dest = /\n"), nil
			}
			return nil, nil
		},
		readPathCon: func(path string) (string, error) {
			return "docker_helper_workspace_t", nil
		},
		selinuxActive: func() (bool, bool, error) {
			return true, true, nil
		},
		readMountinfo: func() ([]byte, error) { return []byte{}, nil },
		acquireLock: func() (func() error, error) {
			return func() error { return nil }, nil
		},
	}

	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("ensureWorkspaceFcontext must fail when equivalence source / overlaps /data")
	}
	if !strings.Contains(err.Error(), "overlaps") {
		t.Errorf("expected overlap error, got: %v", err)
	}
}

func TestSELinuxPolicyTrustedCATypeAndPermissions(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	// Dedicated CA type declaration.
	if !strings.Contains(content, "type docker_helper_trusted_ca_t, file_type;") {
		t.Error("policy must declare type docker_helper_trusted_ca_t")
	}
	// Type transitions for dynamic creation.
	if !strings.Contains(content, "type_transition docker_helper_t docker_helper_trusted_ca_t:dir docker_helper_trusted_ca_t;") {
		t.Error("policy must have type_transition for dir")
	}
	if !strings.Contains(content, "type_transition docker_helper_t docker_helper_trusted_ca_t:file docker_helper_trusted_ca_t;") {
		t.Error("policy must have type_transition for file")
	}
	if !strings.Contains(content, "type_transition docker_helper_t docker_helper_trusted_ca_t:lnk_file docker_helper_trusted_ca_t;") {
		t.Error("policy must have type_transition for lnk_file")
	}
	// docker_helper_t management perms.
	if !strings.Contains(content, "allow docker_helper_t docker_helper_trusted_ca_t:dir { create getattr search read open write add_name remove_name setattr };") {
		t.Error("policy must grant docker_helper_t trusted_ca_t dir management")
	}
	if !strings.Contains(content, "allow docker_helper_t docker_helper_trusted_ca_t:file { create read write open getattr setattr rename unlink };") {
		t.Error("policy must grant docker_helper_t trusted_ca_t file management")
	}
	if !strings.Contains(content, "allow docker_helper_t docker_helper_trusted_ca_t:lnk_file { create read unlink getattr };") {
		t.Error("policy must grant docker_helper_t trusted_ca_t lnk_file management (incl. getattr for restorecon on restart)")
	}
	// Container read-only perms.
	if !strings.Contains(content, "allow docker_helper_container_t docker_helper_trusted_ca_t:dir { getattr search read open };") {
		t.Error("policy must grant container trusted_ca_t dir read-only")
	}
	if !strings.Contains(content, "allow docker_helper_container_t docker_helper_trusted_ca_t:file { getattr read open };") {
		t.Error("policy must grant container trusted_ca_t file read-only")
	}
	if !strings.Contains(content, "allow docker_helper_container_t docker_helper_trusted_ca_t:lnk_file { getattr read };") {
		t.Error("policy must grant container trusted_ca_t lnk_file read-only")
	}
	// .fc file-context mapping.
	fcData, err := os.ReadFile("packaging/selinux/docker-helper.fc")
	if err != nil {
		t.Fatal(err)
	}
	fcContent := string(fcData)
	if !strings.Contains(fcContent, "/run/docker-helper/trusted-ca(/.*)?") {
		t.Error("fc file must contain trusted-ca mapping")
	}
	if !strings.Contains(fcContent, "docker_helper_trusted_ca_t") {
		t.Error("fc file must map trusted-ca to docker_helper_trusted_ca_t")
	}
	// Absence of general container -> runtime_t grants.
	if strings.Contains(content, "allow docker_helper_container_t docker_helper_runtime_t:") {
		t.Error("policy must NOT grant container general access to runtime_t")
	}
	// setfiles_exec_t for restorecon without transition.
	if !strings.Contains(content, "type setfiles_exec_t;") {
		t.Error("policy must require type setfiles_exec_t")
	}
	if !strings.Contains(content, "allow docker_helper_t setfiles_exec_t:file { getattr read open execute execute_no_trans map };") {
		t.Error("policy must grant docker_helper_t setfiles_exec_t execute_no_trans")
	}
	// init_t cleanup of trusted CA tree.
	if !strings.Contains(content, "allow init_t docker_helper_trusted_ca_t:dir { write remove_name rmdir };") {
		t.Error("policy must grant init_t trusted_ca_t dir cleanup")
	}
	if !strings.Contains(content, "allow init_t docker_helper_trusted_ca_t:file { unlink };") {
		t.Error("policy must grant init_t trusted_ca_t file unlink")
	}
	if !strings.Contains(content, "allow init_t docker_helper_trusted_ca_t:lnk_file { unlink };") {
		t.Error("policy must grant init_t trusted_ca_t lnk_file unlink")
	}
	// SELinux configuration access for restorecon (with -m, no mount scan).
	if !strings.Contains(content, "type selinux_config_t;") {
		t.Error("policy must require type selinux_config_t")
	}
	if !strings.Contains(content, "type default_context_t;") {
		t.Error("policy must require type default_context_t")
	}
	if !strings.Contains(content, "type file_context_t;") {
		t.Error("policy must require type file_context_t")
	}
	if !strings.Contains(content, "allow docker_helper_t selinux_config_t:file { read open getattr };") {
		t.Error("policy must grant docker_helper_t selinux_config_t read open getattr")
	}
	if !strings.Contains(content, "allow docker_helper_t default_context_t:dir { search };") {
		t.Error("policy must grant docker_helper_t default_context_t dir search")
	}
	if !strings.Contains(content, "allow docker_helper_t default_context_t:file { read open getattr };") {
		t.Error("policy must grant docker_helper_t default_context_t file read open getattr")
	}
	if !strings.Contains(content, "allow docker_helper_t file_context_t:dir { search };") {
		t.Error("policy must grant docker_helper_t file_context_t dir search")
	}
	if !strings.Contains(content, "allow docker_helper_t file_context_t:file { read open getattr };") {
		t.Error("policy must grant docker_helper_t file_context_t file read open getattr")
	}
	// restorecon relabel grants for the trusted CA tree.
	if !strings.Contains(content, "allow docker_helper_t docker_helper_runtime_t:dir { relabelfrom };") {
		t.Error("policy must grant docker_helper_t runtime_t dir relabelfrom")
	}
	if !strings.Contains(content, "allow docker_helper_t docker_helper_trusted_ca_t:dir { relabelto };") {
		t.Error("policy must grant docker_helper_t trusted_ca_t dir relabelto")
	}
	if !strings.Contains(content, "allow docker_helper_t docker_helper_runtime_t:lnk_file { getattr relabelfrom };") {
		t.Error("policy must grant docker_helper_t runtime_t lnk_file getattr relabelfrom")
	}
	if !strings.Contains(content, "allow docker_helper_t docker_helper_trusted_ca_t:lnk_file { relabelto };") {
		t.Error("policy must grant docker_helper_t trusted_ca_t lnk_file relabelto")
	}
	if !strings.Contains(content, "allow docker_helper_t docker_helper_runtime_t:file { relabelfrom };") {
		t.Error("policy must grant docker_helper_t runtime_t file relabelfrom")
	}
	if !strings.Contains(content, "allow docker_helper_t docker_helper_trusted_ca_t:file { relabelto };") {
		t.Error("policy must grant docker_helper_t trusted_ca_t file relabelto")
	}
	// sysctl_net_t file read/open for the Go listener (proven in enforcing UAT).
	if !strings.Contains(content, "allow docker_helper_t sysctl_net_t:file { read open };") {
		t.Error("policy must grant docker_helper_t sysctl_net_t file read open")
	}
	// tmpfs_t filesystem getattr is required for restorecon -R -m to statfs()
	// the target filesystem (trusted-ca lives on tmpfs). It is NOT a mount-scan
	// permission. Proven necessary by enforcing UAT:
	//   restorecon: statfs(/run/docker-helper/trusted-ca) failed: Permission denied
	if !strings.Contains(content, "allow docker_helper_t tmpfs_t:filesystem { getattr };") {
		t.Error("policy must grant docker_helper_t tmpfs_t:filesystem getattr for restorecon statfs")
	}
	// Absence of the temporary mount-scan grants that were only needed when
	// restorecon was run without -m. Assert the exact unwanted allow rules so
	// unrelated legitimate references to these types do not cause false
	// failures. fs_t:filesystem getattr is intentionally NOT in this list: it
	// is required (and asserted separately) for the workspace recursive
	// restorecon's target-path fstatfs, mirroring the tmpfs_t rule.
	for _, absent := range []string{
		"allow docker_helper_t device_t:filesystem { getattr };",
		"allow docker_helper_t devpts_t:filesystem { getattr };",
		"allow docker_helper_t cgroup_t:filesystem { getattr };",
		"allow docker_helper_t pstore_t:filesystem { getattr };",
		"allow docker_helper_t tracefs_t:filesystem { getattr };",
		"allow docker_helper_t hugetlbfs_t:filesystem { getattr };",
		"allow docker_helper_t debugfs_t:filesystem { getattr };",
		"allow docker_helper_t debugfs_t:dir { search };",
		"allow docker_helper_t container_var_lib_t:dir { search };",
	} {
		if strings.Contains(content, absent) {
			t.Errorf("policy must NOT contain temporary mount-scan grant %s", absent)
		}
	}
}

// TestSELinuxPolicyWorkspaceRestoreconFstatfs guards the single
// filesystem:getattr grant the confined workspace restorecon requires. The
// recursive restorecon (-R -m -x) unconditionally fstatfs()es its explicit
// target path (selinux_restorecon_common), and a non-home workspace lives on
// the root filesystem (fs_t). This mirrors the trusted-CA tmpfs_t rule; it is
// a target-path statfs grant, not a mount-scan grant. Proven necessary by the
// bounded scope=selinux run AFTER the invocation was corrected to -m -x:
//
//	restorecon -R -m -x: ...: statfs(/opt/uat-ws-*) failed: Permission denied
func TestSELinuxPolicyWorkspaceRestoreconFstatfs(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "allow docker_helper_t fs_t:filesystem { getattr };") {
		t.Error("policy must grant docker_helper_t fs_t:filesystem getattr for the workspace recursive restorecon target-path statfs")
	}
	if strings.Contains(content, "allow docker_helper_t fs_t:filesystem { unmount getattr };") {
		t.Error("fs_t filesystem grant must keep the mount-pin unmount and the target-path getattr as distinct narrow rules")
	}
}

// selinuxAllowRule is a parsed single-line allow rule from the shipped policy.
type selinuxAllowRule struct {
	target string
	class  string
	perms  string
}

// dockerHelperRelabelRules returns every allow rule from docker_helper_t that
// grants relabelfrom or relabelto on any class. The policy is written with one
// rule per line in the form:
//
//	allow docker_helper_t <target>:<class> { perms };
//
// so a line-based parse is sufficient and stays aligned with the shipped
// artifact. A rule not parsed this way would fail the positive assertions below
// rather than silently pass.
func dockerHelperRelabelRules(content string) []selinuxAllowRule {
	var rules []selinuxAllowRule
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "allow docker_helper_t ") {
			continue
		}
		if !strings.Contains(line, "relabelfrom") && !strings.Contains(line, "relabelto") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "allow docker_helper_t "))
		colon := strings.Index(rest, ":")
		brace := strings.Index(rest, "{")
		closeBrace := strings.LastIndex(rest, "}")
		if colon < 0 || brace < 0 || brace < colon || closeBrace < brace {
			rules = append(rules, selinuxAllowRule{target: "UNPARSEABLE", class: "UNPARSEABLE", perms: rest})
			continue
		}
		rules = append(rules, selinuxAllowRule{
			target: strings.TrimSpace(rest[:colon]),
			class:  strings.TrimSpace(rest[colon+1 : brace]),
			perms:  strings.TrimSpace(rest[brace+1 : closeBrace]),
		})
	}
	return rules
}

func findRelabelRule(rules []selinuxAllowRule, target, class string) (selinuxAllowRule, bool) {
	for _, r := range rules {
		if r.target == target && r.class == class {
			return r, true
		}
	}
	return selinuxAllowRule{}, false
}

// TestSELinuxPolicyWorkspaceRelabelRules asserts the exact AVC-proven relabel
// grants for the non-home workspace lifecycle: initial usr_t ->
// docker_helper_workspace_t and teardown docker_helper_workspace_t -> usr_t.
// Each rule must grant exactly the proven permissions (getattr only where
// restorecon must read an already-labeled object's current label before
// relabeling it).
func TestSELinuxPolicyWorkspaceRelabelRules(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	rules := dockerHelperRelabelRules(string(data))

	want := []struct {
		target, class, perms string
	}{
		{target: "usr_t", class: "dir", perms: "relabelfrom relabelto"},
		{target: "usr_t", class: "file", perms: "relabelfrom relabelto"},
		{target: "usr_t", class: "lnk_file", perms: "relabelfrom relabelto"},
		{target: "usr_t", class: "fifo_file", perms: "getattr relabelfrom relabelto"},
		{target: "docker_helper_workspace_t", class: "dir", perms: "relabelfrom relabelto"},
		{target: "docker_helper_workspace_t", class: "file", perms: "relabelfrom relabelto"},
		{target: "docker_helper_workspace_t", class: "lnk_file", perms: "getattr relabelfrom relabelto"},
		{target: "docker_helper_workspace_t", class: "fifo_file", perms: "getattr relabelfrom relabelto"},
	}
	for _, w := range want {
		got, ok := findRelabelRule(rules, w.target, w.class)
		if !ok {
			t.Errorf("policy must grant docker_helper_t %s:%s relabelfrom/relabelto", w.target, w.class)
			continue
		}
		if got.perms != w.perms {
			t.Errorf("docker_helper_t %s:%s perms = %q, want exactly %q", w.target, w.class, got.perms, w.perms)
		}
	}
}

// TestSELinuxPolicyNoFileTypeRelabel guards against granting relabelfrom or
// relabelto through the file_type attribute instead of the concrete types.
// A file_type-attribute relabel would be broader than the AVC-proven grant.
func TestSELinuxPolicyNoFileTypeRelabel(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	rules := dockerHelperRelabelRules(string(data))
	for _, r := range rules {
		if r.target == "file_type" {
			t.Errorf("policy must NOT grant relabel permissions via the file_type attribute: %s:%s {%s}", r.target, r.class, r.perms)
		}
	}
}

// TestSELinuxPolicyNoUnprovenClassRelabel guards that the workspace relabel
// grants stay confined to the AVC-proven object classes (dir/file/lnk_file/
// fifo_file). sock_file/chr_file/blk_file relabel on usr_t or
// docker_helper_workspace_t is not evidenced and must not be granted.
// It also guards that usr_t:lnk_file getattr is not added (not denied in the
// permissive evidence run; must be proven by an enforcing run before shipping).
func TestSELinuxPolicyNoUnprovenClassRelabel(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	rules := dockerHelperRelabelRules(string(data))
	for _, r := range rules {
		if r.target != "usr_t" && r.target != "docker_helper_workspace_t" {
			continue
		}
		switch r.class {
		case "sock_file", "chr_file", "blk_file":
			t.Errorf("policy must NOT grant relabel permissions on unproven class %s (target %s): {%s}", r.class, r.target, r.perms)
		}
		if r.target == "usr_t" && r.class == "lnk_file" && strings.Contains(r.perms, "getattr") {
			t.Error("policy must NOT grant usr_t:lnk_file getattr (not proven needed by an enforcing run)")
		}
	}
}
