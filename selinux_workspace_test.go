package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return false, false, nil },
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
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, false, nil },
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
	var addedRules []string
	var restoreconCalled bool
	var allCalls []string
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			allCalls = append(allCalls, cmd+" "+strings.Join(args, " "))
			if strings.HasSuffix(cmd, "semanage") {
				if len(args) > 0 && args[0] == "fcontext" {
					if len(args) > 1 && args[1] == "-a" {
						addedRules = append(addedRules, strings.Join(args, " "))
					} else if len(args) > 1 && args[1] == "-l" {
						return []byte{}, nil
					}
				}
			}
			if strings.HasSuffix(cmd, "restorecon") {
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
	if !created {
		t.Error("expected newly created mapping")
	}
	if len(addedRules) != 1 {
		t.Errorf("expected 1 added rule, got %d (all calls: %v)", len(addedRules), allCalls)
	}
	if len(addedRules) > 0 && !strings.Contains(addedRules[0], "/data(/.*)?") {
		t.Errorf("rule should contain escaped path, got: %s", addedRules[0])
	}
	if !restoreconCalled {
		t.Error("restorecon should have been called")
	}
}

func TestEnsureWorkspaceLabelIdempotent(t *testing.T) {
	var addedRules []string
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if strings.HasSuffix(cmd, "semanage") && len(args) > 0 && args[0] == "fcontext" {
				if args[1] == "-a" {
					addedRules = append(addedRules, strings.Join(args, " "))
				} else if args[1] == "-l" {
					return []byte("/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)"), nil
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
	if len(addedRules) > 0 {
		t.Error("should not add rule when one already exists")
	}
}

func TestEnsureWorkspaceLabelConflictingRule(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if strings.HasSuffix(cmd, "semanage") && len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
				return []byte("/data(/.*)?  gen_context(system_u:object_r:default_t:s0)"), nil
			}
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			return "default_t", nil
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

func TestEnsureWorkspaceLabelRestoreconFails(t *testing.T) {
	var ruleRemoved bool
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if strings.HasSuffix(cmd, "semanage") && len(args) > 0 && args[0] == "fcontext" {
				if args[1] == "-l" {
					return []byte{}, nil
				} else if args[1] == "-a" {
					return []byte{}, nil
				} else if args[1] == "-d" {
					ruleRemoved = true
					return []byte{}, nil
				}
			}
			if strings.HasSuffix(cmd, "restorecon") {
				return []byte{}, errors.New("restorecon failed")
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
	if !ruleRemoved {
		t.Error("fcontext rule should be removed on restorecon failure")
	}
}

func TestEnsureWorkspaceLabelVerifyFails(t *testing.T) {
	var ruleRemoved bool
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if strings.HasSuffix(cmd, "semanage") && len(args) > 0 && args[0] == "fcontext" {
				if args[1] == "-l" {
					return []byte{}, nil
				} else if args[1] == "-a" {
					return []byte{}, nil
				} else if args[1] == "-d" {
					ruleRemoved = true
					return []byte{}, nil
				}
			}
			if strings.HasSuffix(cmd, "restorecon") {
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
	if !ruleRemoved {
		t.Error("fcontext rule should be removed on verification failure")
	}
}

func TestEnsureWorkspaceLabelMultiLineSemanageOutput(t *testing.T) {
	var addedRules []string
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if strings.HasSuffix(cmd, "semanage") && len(args) > 0 && args[0] == "fcontext" {
				if args[1] == "-l" {
					return []byte("/var/lib/docker-helper(/.*)?  gen_context(system_u:object_r:docker_helper_state_t:s0)\n/etc/docker-helper(/.*)?  gen_context(system_u:object_r:docker_helper_config_t:s0)"), nil
				} else if args[1] == "-a" {
					addedRules = append(addedRules, strings.Join(args, " "))
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
	if len(addedRules) != 1 {
		t.Errorf("expected 1 added rule, got %d", len(addedRules))
	}
}

// --- Manager: verifyWorkspaceLabel tests ---

func TestVerifyWorkspaceLabelOK(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
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
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
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
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
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
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return false, false, nil },
	}
	if err := mgr.verifyWorkspaceLabel("/data"); err != nil {
		t.Fatalf("expected nil when not enforcing, got: %v", err)
	}
}

func TestVerifyWorkspaceLabelNoMutation(t *testing.T) {
	var runCommandCalled bool
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
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
	var removedPatterns []string
	var restoreconCalled bool
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if strings.HasSuffix(cmd, "semanage") && len(args) > 0 && args[0] == "fcontext" && args[1] == "-d" {
				for _, a := range args {
					if a != "-d" && a != "-s" && len(a) > 0 && a[0] == '/' {
						removedPatterns = append(removedPatterns, a)
					}
				}
			}
			if strings.HasSuffix(cmd, "restorecon") {
				restoreconCalled = true
			}
			return []byte{}, nil
		},
	}
	if err := mgr.rollbackWorkspaceLabel("/data"); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if len(removedPatterns) != 1 {
		t.Errorf("expected 1 removed pattern, got %d", len(removedPatterns))
	}
	if removedPatterns[0] != "/data(/.*)?" {
		t.Errorf("removed pattern = %q, want %q", removedPatterns[0], "/data(/.*)?")
	}
	if !restoreconCalled {
		t.Error("restorecon should be called during rollback")
	}
}

func TestRollbackWorkspaceLabelError(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			return []byte{}, errors.New("semanage failed")
		},
	}
	err := mgr.rollbackWorkspaceLabel("/data")
	if err == nil {
		t.Fatal("expected error for rollback failure")
	}
}

// --- Manager: seam tests ---

func TestSELinuxManagerSeams(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand:     func(cmd string, args ...string) ([]byte, error) { return []byte{}, nil },
		readPathCon:    func(path string) (string, error) { return selinuxWorkspaceType, nil },
	}
	created, err := mgr.ensureWorkspaceLabel("/data")
	if err != nil {
		t.Fatalf("ensureWorkspaceLabel failed: %v", err)
	}
	if !created {
		t.Error("expected newly created mapping")
	}
	if err := mgr.verifyWorkspaceLabel("/data"); err != nil {
		t.Fatalf("verifyWorkspaceLabel failed: %v", err)
	}
	if err := mgr.rollbackWorkspaceLabel("/data"); err != nil {
		t.Fatalf("rollbackWorkspaceLabel failed: %v", err)
	}
}

func TestSELinuxManagerReadPathConError(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand:     func(cmd string, args ...string) ([]byte, error) { return []byte{}, nil },
		readPathCon:    func(path string) (string, error) { return "", errors.New("cannot read context") },
	}
	_, err := mgr.ensureWorkspaceLabel("/data")
	if err == nil {
		t.Fatal("expected error for readPathCon failure")
	}
	if !strings.Contains(err.Error(), "cannot read context") {
		t.Errorf("expected 'cannot read context' in error, got: %v", err)
	}
}

func TestSELinuxManagerSELinuxActiveError(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive: func() (bool, bool, error) {
			return false, false, errors.New("cannot read SELinux status")
		},
	}
	_, err := mgr.ensureWorkspaceLabel("/data")
	if err == nil {
		t.Fatal("expected error for SELinux status failure")
	}
	if !strings.Contains(err.Error(), "cannot read SELinux status") {
		t.Errorf("expected 'cannot read SELinux status' in error, got: %v", err)
	}
}

// --- Parse fcontext line tests ---

func TestParseFcontextLine(t *testing.T) {
	tests := []struct {
		line    string
		root    string
		want    fcontextRule
		matched bool
	}{
		{
			"/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)",
			"/data",
			fcontextRule{pattern: "/data(/.*)?", fileType: "docker_helper_workspace_t"},
			true,
		},
		{
			"/opt(/.*)?  gen_context(system_u:object_r:default_t:s0)",
			"/opt",
			fcontextRule{pattern: "/opt(/.*)?", fileType: "default_t"},
			true,
		},
		{
			"/var/lib(/.*)?  gen_context(system_u:object_r:var_t:s0)",
			"/data",
			fcontextRule{},
			false,
		},
		{
			"/data(/.*)?  system_u:object_r:default_t:s0",
			"/data",
			fcontextRule{pattern: "/data(/.*)?", fileType: "default_t"},
			true,
		},
		{
			"/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0:c100.c200)",
			"/data",
			fcontextRule{pattern: "/data(/.*)?", fileType: "docker_helper_workspace_t"},
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.line[:min(30, len(tc.line))], func(t *testing.T) {
			got, matched := parseFcontextLine(tc.line, tc.root)
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

// --- Init integration tests ---

func TestInitSELinuxNonHomeRootPreparesLabel(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Create a non-home root path explicitly (not under /home).
	// Use /workspace which is not a forbidden system tree.
	nonHomeRoot := "/workspace/test-selinux-nhroot"
	if err := os.MkdirAll(nonHomeRoot, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(nonHomeRoot) })

	var ensureCalled bool
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if strings.HasSuffix(cmd, "semanage") && len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
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
	err := initSystemSELinux(nonHomeRoot, &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			_, err := initCore(ar, so, se)
			return err
		},
	)
	if err != nil {
		t.Fatalf("initSystemSELinux failed: %v", err)
	}
	if !ensureCalled {
		t.Error("ensureWorkspaceLabel should be called for non-home root (readPathCon tracks this)")
	}
	if !coreCalled {
		t.Error("core should be called after SELinux preparation")
	}
}

func TestInitSELinuxHomeRootNoSELinuxPrep(t *testing.T) {
	origGetConfig := getConfigPathFunc
	allowedRoot := testAllowedRootDir(t)
	configPath := filepath.Join(allowedRoot, "config.json")
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	// nil manager skips SELinux prep entirely.
	var coreCalled bool
	err := initSystemSELinux(allowedRoot, &bytes.Buffer{}, &bytes.Buffer{},
		nil,
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			return nil
		},
	)
	if err != nil {
		t.Fatalf("initSystemSELinux failed: %v", err)
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

	// Create a non-home root path explicitly (not under /home).
	nonHomeRoot := "/workspace/test-selinux-prepfail"
	if err := os.MkdirAll(nonHomeRoot, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(nonHomeRoot) })

	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if strings.HasSuffix(cmd, "semanage") && len(args) > 0 && args[0] == "fcontext" {
				if len(args) > 1 && args[1] == "-l" {
					return []byte{}, nil
				}
				// Fail on -a call
				return []byte{}, errors.New("semanage failed")
			}
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			return selinuxWorkspaceType, nil
		},
	}

	coreCalled := false
	err := initSystemSELinux(nonHomeRoot, &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			return nil
		},
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

	// Create a non-home root path explicitly (not under /home).
	nonHomeRoot := "/workspace/test-selinux-rollback"
	if err := os.MkdirAll(nonHomeRoot, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(nonHomeRoot) })

	var rollbackCalled bool
	var allCalls []string
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			allCalls = append(allCalls, cmd+" "+strings.Join(args, " "))
			if strings.HasSuffix(cmd, "semanage") && len(args) > 0 && args[0] == "fcontext" {
				if len(args) > 1 && args[1] == "-l" {
					return []byte{}, nil
				}
				if len(args) > 1 && args[1] == "-a" {
					return []byte{}, nil
				}
				if len(args) > 1 && args[1] == "-d" {
					rollbackCalled = true
					return []byte{}, nil
				}
			}
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			return selinuxWorkspaceType, nil
		},
	}

	err := initSystemSELinux(nonHomeRoot, &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		},
	)
	if err == nil {
		t.Fatal("expected error for core failure")
	}
	if !rollbackCalled {
		t.Errorf("rollback should be called when core fails after new mapping (all calls: %v)", allCalls)
	}
}

func TestInitSELinuxCoreFailureNoRollbackWhenNotNew(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)
	nonHomeRoot := filepath.Join(rootDir, "data")
	if err := os.MkdirAll(nonHomeRoot, 0755); err != nil {
		t.Fatal(err)
	}

	var rollbackCalled bool
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			if strings.HasSuffix(cmd, "semanage") && len(args) > 0 && args[0] == "fcontext" {
				if args[1] == "-l" {
					return []byte("/data(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)"), nil
				} else if args[1] == "-d" {
					rollbackCalled = true
				}
			}
			return []byte{}, nil
		},
		readPathCon: func(path string) (string, error) {
			return selinuxWorkspaceType, nil
		},
	}

	err := initSystemSELinux(nonHomeRoot, &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		},
	)
	if err == nil {
		t.Fatal("expected error for core failure")
	}
	if rollbackCalled {
		t.Error("rollback should NOT be called when mapping already existed")
	}
}

func TestInitSELinuxNilManagerHomeRoot(t *testing.T) {
	origGetConfig := getConfigPathFunc
	allowedRoot := testAllowedRootDir(t)
	configPath := filepath.Join(allowedRoot, "config.json")
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	var coreCalled string
	err := initSystemSELinux(allowedRoot, &bytes.Buffer{}, &bytes.Buffer{},
		nil,
		func(ar string, so, se io.Writer) error {
			coreCalled = ar
			return nil
		},
	)
	if err != nil {
		t.Fatalf("initSystemSELinux failed: %v", err)
	}
	if coreCalled != allowedRoot {
		t.Errorf("core called with %q, want %q", coreCalled, allowedRoot)
	}
}

func TestInitSELinuxExistingConfigMatch(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)
	nonHomeRoot := filepath.Join(rootDir, "data")
	if err := os.MkdirAll(nonHomeRoot, 0755); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "config.json")
	configData := fmt.Sprintf(`{"allowed_root": %q, "session_ttl": "12h"}`, nonHomeRoot)
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand:     func(cmd string, args ...string) ([]byte, error) { return []byte{}, nil },
		readPathCon:    func(path string) (string, error) { return selinuxWorkspaceType, nil },
	}

	var coreCalled bool
	err := initSystemSELinux(nonHomeRoot, &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			_, err := initCore(ar, so, se)
			return err
		},
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

	baseDir := testAllowedRootDir(t)
	oldRoot := filepath.Join(baseDir, "old")
	newRoot := filepath.Join(baseDir, "new")
	for _, d := range []string{oldRoot, newRoot} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	configPath := filepath.Join(dir, "config.json")
	configData := fmt.Sprintf(`{"allowed_root": %q, "session_ttl": "12h"}`, oldRoot)
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		runCommand:     func(cmd string, args ...string) ([]byte, error) { return []byte{}, nil },
		readPathCon:    func(path string) (string, error) { return selinuxWorkspaceType, nil },
	}

	coreCalled := false
	err := initSystemSELinux(newRoot, &bytes.Buffer{}, &bytes.Buffer{},
		mgr,
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			return nil
		},
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

// --- Home root not required for docker_helper_workspace_t ---

func TestSELinuxWorkspaceTypeNotRequiredForHome(t *testing.T) {
	mgr := &selinuxWorkspaceManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		selinuxActive:  func() (bool, bool, error) { return true, true, nil },
		readPathCon: func(path string) (string, error) {
			return "user_home_t", nil
		},
	}
	if err := mgr.verifyWorkspaceLabel("/home"); err != nil {
		t.Fatalf("expected nil for /home, got: %v", err)
	}
	if err := mgr.verifyWorkspaceLabel("/home/alice"); err != nil {
		t.Fatalf("expected nil for /home/alice, got: %v", err)
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
