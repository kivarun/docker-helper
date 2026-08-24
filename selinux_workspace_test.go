package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// newTestManager creates a selinuxFcontextManager with the given selinuxActive
// seam and a no-op lock (for single-threaded tests).
func newTestManager(active func() (bool, bool, error)) *selinuxFcontextManager {
	return &selinuxFcontextManager{
		selinuxActive: active,
		acquireLock: func() (func() error, error) {
			return func() error { return nil }, nil
		},
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

func TestOverlapSiblingRoots(t *testing.T) {
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

// --- Manager: removeWorkspaceFcontext tests ---

func TestRemoveWorkspaceFcontext(t *testing.T) {
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
	if err := mgr.removeWorkspaceFcontext("/data"); err != nil {
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

func TestRestoreconTypeOnlyArgv(t *testing.T) {
	var lastArgs []string
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		lastArgs = args
		return []byte{}, nil
	}
	if err := mgr.restoreconRecursive("/data"); err != nil {
		t.Fatal(err)
	}
	want := []string{"-R", "/data"}
	if !reflect.DeepEqual(lastArgs, want) {
		t.Errorf("argv = %v, want %v", lastArgs, want)
	}
	for _, a := range lastArgs {
		if a == "-F" {
			t.Error("restorecon must not use -F (type-only)")
		}
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

// --- Init integration tests ---

func syntheticResolveRoot(path string) (string, error) {
	return path, nil
}

func TestInitSELinuxNoMACPreparation(t *testing.T) {
	// System init does not prepare MAC state; that happens at session creation.
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	var coreCalled bool
	err := initSystem("/data", &bytes.Buffer{}, &bytes.Buffer{},
		syntheticResolveRoot,
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			return nil
		},
	)
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}
	if !coreCalled {
		t.Error("core should be called during system init")
	}
}

func TestInitSELinuxCoreFailurePropagates(t *testing.T) {
	// Core failure during init propagates; no MAC state to roll back.
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	err := initSystem("/data", &bytes.Buffer{}, &bytes.Buffer{},
		syntheticResolveRoot,
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		},
	)
	if err == nil {
		t.Fatal("expected error for core failure")
	}
}

func TestInitSELinuxNilManager(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	var coreCalled string
	err := initSystem("/data", &bytes.Buffer{}, &bytes.Buffer{},
		syntheticResolveRoot,
		func(ar string, so, se io.Writer) error {
			coreCalled = ar
			return nil
		},
	)
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}
	if coreCalled != "/data" {
		t.Errorf("core called with %q, want %q", coreCalled, "/data")
	}
}

// --- Config lifecycle regression tests (deterministic) ---

// --- Detection regressions ---

func TestServeDetectLSMError(t *testing.T) {
	// runServe: detectLSM error => startup fails closed.
	origAA := appArmorLSMActive
	origSEL := selinuxEnabled
	appArmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) {
		return false, false, os.ErrPermission
	}
	defer func() {
		appArmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return "/nonexistent/config.json" }
	defer func() { getConfigPathFunc = origGetConfig }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"serve"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "cannot determine") {
		t.Errorf("expected detection error in output, got: %s", stderr.String())
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
	// /unrelated = /other with ROOT=/data => allowed.
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

func TestEquivalenceDestEqualsRoot(t *testing.T) {
	// /data = /other => reject (DEST equals ROOT).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data = /other"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for equivalence DEST equals ROOT")
	}
	if !strings.Contains(err.Error(), "equivalence") {
		t.Errorf("expected 'equivalence' in error, got: %v", err)
	}
}

func TestEquivalenceDestContainsRoot(t *testing.T) {
	// /data/sub = /other => reject (DEST is descendant of ROOT).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/data/sub = /other"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for equivalence DEST contains ROOT")
	}
	if !strings.Contains(err.Error(), "equivalence") {
		t.Errorf("expected 'equivalence' in error, got: %v", err)
	}
}

func TestEquivalenceSourceEqualsRoot(t *testing.T) {
	// /other = /data => reject (SOURCE equals ROOT).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/other = /data"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for equivalence SOURCE equals ROOT")
	}
	if !strings.Contains(err.Error(), "equivalence") {
		t.Errorf("expected 'equivalence' in error, got: %v", err)
	}
}

func TestEquivalenceSourceContainsRoot(t *testing.T) {
	// /other = /data/sub => reject (SOURCE is descendant of ROOT).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/other = /data/sub"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/data")
	if err == nil {
		t.Fatal("expected error for equivalence SOURCE contains ROOT")
	}
	if !strings.Contains(err.Error(), "equivalence") {
		t.Errorf("expected 'equivalence' in error, got: %v", err)
	}
}

func TestEquivalenceDestAncestorOfRoot(t *testing.T) {
	// /parent = /other with ROOT=/parent/data => reject (DEST is ancestor of ROOT).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/parent = /other"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/parent/data")
	if err == nil {
		t.Fatal("expected error for equivalence DEST ancestor of ROOT")
	}
	if !strings.Contains(err.Error(), "equivalence") {
		t.Errorf("expected 'equivalence' in error, got: %v", err)
	}
}

func TestEquivalenceSourceAncestorOfRoot(t *testing.T) {
	// /other = /parent with ROOT=/parent/data => reject (SOURCE is ancestor of ROOT).
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte("/other = /parent"), nil
		}
		return []byte{}, nil
	}
	_, err := mgr.ensureWorkspaceFcontext("/parent/data")
	if err == nil {
		t.Fatal("expected error for equivalence SOURCE ancestor of ROOT")
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
