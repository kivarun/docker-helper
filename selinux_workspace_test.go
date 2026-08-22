package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

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

func TestSELinuxPolicyNoBroadHostTypeGrants(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, typ := range []string{"usr_t", "default_t", "var_t"} {
		if strings.Contains(content, "allow docker_helper_t "+typ) {
			t.Errorf("policy must NOT grant docker_helper_t broad access to %s", typ)
		}
		if strings.Contains(content, "allow docker_helper_container_t "+typ) {
			t.Errorf("policy must NOT grant docker_helper_container_t broad access to %s", typ)
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

// --- Root classification tests ---

func TestIsHomeRoot(t *testing.T) {
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
			if got := isHomeRoot(tc.path); got != tc.want {
				t.Errorf("isHomeRoot(%q) = %v, want %v", tc.path, got, tc.want)
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
		root string
		want string
	}{
		{"/data", "/data(/.*)?"},
		{"/opt", "/opt(/.*)?"},
		{"/projects/agents", "/projects/agents(/.*)?"},
		{"/data.test", "/data\\.test(/.*)?"},
	}
	for _, tc := range tests {
		t.Run(tc.root, func(t *testing.T) {
			if got := fcontextPattern(tc.root); got != tc.want {
				t.Errorf("fcontextPattern(%q) = %q, want %q", tc.root, got, tc.want)
			}
		})
	}
}

// --- Manager: ensureWorkspaceLabel tests ---

func TestEnsureWorkspaceLabelNotEnforcing(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return false, false, nil },
	}
	created, err := mgr.ensureWorkspaceLabel("/data")
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
	if created {
		t.Error("should not create mapping when SELinux not active")
	}
}

func TestEnsureWorkspaceLabelPermissive(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, false, nil },
	}
	created, err := mgr.ensureWorkspaceLabel("/data")
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
	if created {
		t.Error("should not create mapping in permissive mode")
	}
}

func TestEnsureWorkspaceLabelNewRule(t *testing.T) {
	var calls [][]string
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			calls = append(calls, args)
			if len(args) > 0 && args[0] == "fcontext" {
				if args[1] == "-l" {
					return []byte{}, nil
				}
			}
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			return selinuxWorkspaceType, nil
		},
	}
	created, err := mgr.ensureWorkspaceLabel("/data")
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
	var restoreconCall []string
	for _, c := range calls {
		if len(c) > 0 && c[0] == "-R" {
			restoreconCall = c
			break
		}
	}
	if len(restoreconCall) == 0 {
		t.Error("restorecon should have been called")
	}
}

func TestEnsureWorkspaceLabelIdempotent(t *testing.T) {
	var addCalled bool
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "fcontext" {
				if args[1] == "-l" {
					return []byte("/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)"), nil
				}
				if args[1] == "-a" {
					addCalled = true
				}
			}
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			return selinuxWorkspaceType, nil
		},
	}
	created, err := mgr.ensureWorkspaceLabel("/data")
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

func TestEnsureWorkspaceLabelConflictingRule(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "fcontext" && len(args) > 1 && args[1] == "-l" {
				return []byte("/data(/.*)?  gen_context(system_u:object_r:default_t:s0)"), nil
			}
			return []byte{}, nil
		},
	}
	_, err := mgr.ensureWorkspaceLabel("/data")
	if err == nil {
		t.Fatal("expected error for conflicting rule")
	}
	if !strings.Contains(err.Error(), "conflicting") {
		t.Errorf("expected 'conflicting' in error, got: %v", err)
	}
}

func TestEnsureWorkspaceLabelNestedOperatorRule(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "fcontext" && len(args) > 1 && args[1] == "-l" {
				return []byte("/data/secrets(/.*)?  gen_context(system_u:object_r:ssh_home_t:s0)"), nil
			}
			return []byte{}, nil
		},
	}
	_, err := mgr.ensureWorkspaceLabel("/data")
	if err == nil {
		t.Fatal("expected error for nested operator rule")
	}
	if !strings.Contains(err.Error(), "overridden") {
		t.Errorf("expected 'overridden' in error, got: %v", err)
	}
}

func TestEnsureWorkspaceLabelRestoreconFails(t *testing.T) {
	var deleteCalled bool
	var restoreconCalls int
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
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
		},
		readPathCon: func(path string) (string, error) {
			return selinuxWorkspaceType, nil
		},
	}
	_, err := mgr.ensureWorkspaceLabel("/data")
	if err == nil {
		t.Fatal("expected error for restorecon failure")
	}
	if !deleteCalled {
		t.Error("fcontext rule should be removed on restorecon failure")
	}
	if restoreconCalls != 2 {
		t.Errorf("expected 2 restorecon calls, got %d", restoreconCalls)
	}
}

func TestEnsureWorkspaceLabelVerifyFails(t *testing.T) {
	var deleteCalled bool
	var restoreconCalls int
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
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
				return []byte{}, nil
			}
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			return "default_t", nil
		},
	}
	_, err := mgr.ensureWorkspaceLabel("/data")
	if err == nil {
		t.Fatal("expected error for type mismatch")
	}
	if !strings.Contains(err.Error(), "default_t") {
		t.Errorf("expected type in error, got: %v", err)
	}
	if !deleteCalled {
		t.Error("fcontext rule should be removed on verification failure")
	}
	if restoreconCalls != 2 {
		t.Errorf("expected 2 restorecon calls, got %d", restoreconCalls)
	}
}

func TestEnsureWorkspaceLabelExistingMappingRunsRestorecon(t *testing.T) {
	var restoreconCalled bool
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "fcontext" {
				if args[1] == "-l" {
					return []byte("/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)"), nil
				}
			}
			if len(args) > 0 && args[0] == "-R" {
				restoreconCalled = true
			}
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			return selinuxWorkspaceType, nil
		},
	}
	created, err := mgr.ensureWorkspaceLabel("/data")
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

func TestEnsureWorkspaceLabelExistingMappingVerifyFails(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "fcontext" {
				if args[1] == "-l" {
					return []byte("/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)"), nil
				}
			}
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			return "default_t", nil
		},
	}
	_, err := mgr.ensureWorkspaceLabel("/data")
	if err == nil {
		t.Fatal("expected error for type mismatch on existing mapping")
	}
	if strings.Contains(err.Error(), "rollback") {
		t.Error("pre-existing rule should not be removed on failure")
	}
}

// --- Manager: verifyWorkspaceLabel tests ---

func TestVerifyWorkspaceLabelOK(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		readPathCon: func(path string) (string, error) {
			return selinuxWorkspaceType, nil
		},
	}
	if err := mgr.verifyWorkspaceLabel("/data"); err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
}

func TestVerifyWorkspaceLabelWrongType(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		readPathCon: func(path string) (string, error) {
			return "default_t", nil
		},
	}
	err := mgr.verifyWorkspaceLabel("/data")
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
	if !strings.Contains(err.Error(), "default_t") {
		t.Errorf("expected type in error, got: %v", err)
	}
}

func TestVerifyWorkspaceLabelHomeRoot(t *testing.T) {
	var readCalled bool
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		readPathCon: func(path string) (string, error) {
			readCalled = true
			return "user_home_t", nil
		},
	}
	if err := mgr.verifyWorkspaceLabel("/home/alice"); err != nil {
		t.Fatalf("expected nil for home root, got: %v", err)
	}
	if readCalled {
		t.Error("should not read path context for home root")
	}
}

func TestVerifyWorkspaceLabelNotEnforcing(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return false, false, nil },
	}
	if err := mgr.verifyWorkspaceLabel("/data"); err != nil {
		t.Fatalf("expected nil when not enforcing, got: %v", err)
	}
}

func TestVerifyWorkspaceLabelNoMutation(t *testing.T) {
	var runCommandCalled bool
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			runCommandCalled = true
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			return selinuxWorkspaceType, nil
		},
	}
	if err := mgr.verifyWorkspaceLabel("/data"); err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
	if runCommandCalled {
		t.Error("verifyWorkspaceLabel must not call runCommand (no mutation)")
	}
}

// --- Manager: rollback tests ---

func TestRollbackWorkspaceLabel(t *testing.T) {
	var deleteCalled bool
	var restoreconCalled bool
	mgr := &selinuxWorkspaceManager{
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "fcontext" && args[1] == "-d" {
				deleteCalled = true
			}
			if len(args) > 0 && args[0] == "-R" {
				restoreconCalled = true
			}
			return []byte{}, nil
		},
	}
	if err := mgr.rollbackWorkspaceLabel("/data"); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if !deleteCalled {
		t.Error("fcontext -d should be called")
	}
	if !restoreconCalled {
		t.Error("restorecon should be called during rollback")
	}
}

func TestRollbackWorkspaceLabelError(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			return []byte{}, errors.New("semanage failed")
		},
	}
	err := mgr.rollbackWorkspaceLabel("/data")
	if err == nil {
		t.Fatal("expected error for rollback failure")
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
			"invalid line",
			fcontextRule{},
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.line[:min(30, len(tc.line))], func(t *testing.T) {
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
			}
		})
	}
}

// --- Fcontext argv tests ---

func TestFcontextAddExactArgv(t *testing.T) {
	var lastArgs []string
	mgr := &selinuxWorkspaceManager{
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			lastArgs = args
			return []byte{}, nil
		},
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
	mgr := &selinuxWorkspaceManager{
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			lastArgs = args
			return []byte{}, nil
		},
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
	mgr := &selinuxWorkspaceManager{
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			lastArgs = args
			return []byte{}, nil
		},
	}
	if _, err := mgr.listLocalFcontextRules(); err != nil {
		t.Fatal(err)
	}
	want := []string{"fcontext", "-l", "-C", "-n"}
	if !reflect.DeepEqual(lastArgs, want) {
		t.Errorf("argv = %v, want %v", lastArgs, want)
	}
}

// --- Init integration tests (using injection seams) ---

func syntheticResolveRoot(path string) (string, error) {
	return path, nil
}

func TestInitSELinuxNonHomeRootPreparesLabel(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	var ensureCalled bool
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
				return []byte{}, nil
			}
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			ensureCalled = true
			return selinuxWorkspaceType, nil
		},
	}

	var coreCalled bool
	err := initSystemSELinux("/data", &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			return nil
		},
		syntheticResolveRoot,
	)
	if err != nil {
		t.Fatalf("initSystemSELinux failed: %v", err)
	}
	if !ensureCalled {
		t.Error("ensureWorkspaceLabel should be called for non-home root")
	}
	if !coreCalled {
		t.Error("core should be called after SELinux preparation")
	}
}

func TestInitSELinuxHomeRootNoSELinuxPrep(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	var ensureCalled bool
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			ensureCalled = true
			return []byte{}, nil
		},
	}

	var coreCalled bool
	err := initSystemSELinux("/home/alice", &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			return nil
		},
		syntheticResolveRoot,
	)
	if err != nil {
		t.Fatalf("initSystemSELinux failed: %v", err)
	}
	if ensureCalled {
		t.Error("ensureWorkspaceLabel should NOT be called for home root")
	}
	if !coreCalled {
		t.Error("core should be called")
	}
}

func TestInitSELinuxPreparationFailureBlocksCore(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "fcontext" {
				if args[1] == "-l" {
					return []byte{}, nil
				}
				return []byte{}, errors.New("semanage failed")
			}
			return []byte{}, nil
		},
	}

	coreCalled := false
	err := initSystemSELinux("/data", &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			return nil
		},
		syntheticResolveRoot,
	)
	if err == nil {
		t.Fatal("expected error for SELinux preparation failure")
	}
	if coreCalled {
		t.Error("core should not be called when SELinux preparation fails")
	}
}

func TestInitSELinuxCoreFailureRollsBackNewMapping(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	var rollbackCalled bool
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "fcontext" {
				if args[1] == "-l" {
					return []byte{}, nil
				}
				if args[1] == "-d" {
					rollbackCalled = true
				}
			}
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			return selinuxWorkspaceType, nil
		},
	}

	err := initSystemSELinux("/data", &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		},
		syntheticResolveRoot,
	)
	if err == nil {
		t.Fatal("expected error for core failure")
	}
	if !rollbackCalled {
		t.Error("rollback should be called when core fails after new mapping")
	}
}

func TestInitSELinuxCoreFailureNoRollbackWhenNotNew(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	var rollbackCalled bool
	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "fcontext" {
				if args[1] == "-l" {
					return []byte("/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)"), nil
				}
				if args[1] == "-d" {
					rollbackCalled = true
				}
			}
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			return selinuxWorkspaceType, nil
		},
	}

	err := initSystemSELinux("/data", &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		},
		syntheticResolveRoot,
	)
	if err == nil {
		t.Fatal("expected error for core failure")
	}
	if rollbackCalled {
		t.Error("rollback should NOT be called when mapping already existed")
	}
}

func TestInitSELinuxNilManager(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	var coreCalled string
	err := initSystemSELinux("/data", &bytes.Buffer{}, &bytes.Buffer{},
		nil,
		func(ar string, so, se io.Writer) error {
			coreCalled = ar
			return nil
		},
		syntheticResolveRoot,
	)
	if err != nil {
		t.Fatalf("initSystemSELinux failed: %v", err)
	}
	if coreCalled != "/data" {
		t.Errorf("core called with %q, want %q", coreCalled, "/data")
	}
}

func TestInitSELinuxExistingConfigMatch(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	configPath := filepath.Join(dir, "config.json")
	configData := `{"allowed_root": "/data", "session_ttl": "12h"}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand:    func(cmd string, args ...string) ([]byte, error) { return []byte{}, nil },
		readPathCon:   func(path string) (string, error) { return selinuxWorkspaceType, nil },
	}

	var coreCalled bool
	err := initSystemSELinux("/data", &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			return nil
		},
		syntheticResolveRoot,
	)
	if err != nil {
		t.Fatalf("initSystemSELinux failed: %v", err)
	}
	if !coreCalled {
		t.Error("core should be called when config matches")
	}
}

func TestInitSELinuxExistingConfigMismatch(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	configPath := filepath.Join(dir, "config.json")
	configData := `{"allowed_root": "/old", "session_ttl": "12h"}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	mgr := &selinuxWorkspaceManager{
		selinuxActive: func() (bool, bool, error) { return true, true, nil },
		runCommand:    func(cmd string, args ...string) ([]byte, error) { return []byte{}, nil },
		readPathCon:   func(path string) (string, error) { return selinuxWorkspaceType, nil },
	}

	coreCalled := false
	err := initSystemSELinux("/data", &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			return nil
		},
		syntheticResolveRoot,
	)
	if err == nil {
		t.Fatal("expected error for config mismatch")
	}
	if coreCalled {
		t.Error("core should not be called on config mismatch")
	}
}

// --- Constant tests ---

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
