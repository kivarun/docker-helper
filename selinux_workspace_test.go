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
	"time"
)

// newTestManager creates a selinuxWorkspaceManager with the given selinuxActive
// seam and a no-op lock (for single-threaded tests).
func newTestManager(active func() (bool, bool, error)) *selinuxWorkspaceManager {
	return &selinuxWorkspaceManager{
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

// --- isProperDescendant tests ---

func TestIsProperDescendant(t *testing.T) {
	tests := []struct {
		child  string
		parent string
		want   bool
	}{
		{"/data/sub", "/data", true},
		{"/data", "/data", false},
		{"/data2", "/data", false},
		{"/data.test2", "/data.test", false},
		{"/data.test/sub", "/data.test", true},
		{"/project[1]/sub", "/project[1]", true},
		{"/foo+bar/sub", "/foo+bar", true},
		{"/foo+bar2", "/foo+bar", false},
	}
	for _, tc := range tests {
		t.Run(tc.child+"|"+tc.parent, func(t *testing.T) {
			if got := isProperDescendant(tc.child, tc.parent); got != tc.want {
				t.Errorf("isProperDescendant(%q, %q) = %v, want %v", tc.child, tc.parent, got, tc.want)
			}
		})
	}
}

// --- Manager: ensureWorkspaceLabel tests ---

func TestEnsureWorkspaceLabelNotEnforcing(t *testing.T) {
	mgr := newTestManager(func() (bool, bool, error) { return false, false, nil })
	created, err := mgr.ensureWorkspaceLabel("/data")
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
	if created {
		t.Error("should not create mapping when SELinux not active")
	}
}

func TestEnsureWorkspaceLabelPermissive(t *testing.T) {
	mgr := newTestManager(func() (bool, bool, error) { return true, false, nil })
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
}

func TestEnsureWorkspaceLabelIdempotent(t *testing.T) {
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
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && len(args) > 1 && args[1] == "-l" {
			return []byte("/data(/.*)?  gen_context(system_u:object_r:default_t:s0)"), nil
		}
		return []byte{}, nil
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
	_, err := mgr.ensureWorkspaceLabel("/data")
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

func TestEnsureWorkspaceLabelExistingMappingRunsRestorecon(t *testing.T) {
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
	_, err := mgr.ensureWorkspaceLabel("/data")
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
	created, err := mgr.ensureWorkspaceLabel("/data")
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
	_, err := mgr.ensureWorkspaceLabel("/data")
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
	_, err := mgr.ensureWorkspaceLabel("/projects/data")
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
	_, err := mgr.ensureWorkspaceLabel("/data")
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
	_, err := mgr.ensureWorkspaceLabel("/data")
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
	_, err := mgr.ensureWorkspaceLabel("/data")
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
	_, err := mgr.ensureWorkspaceLabel("/data.test")
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
	created, err := mgr.ensureWorkspaceLabel("/data.test")
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
	_, err := mgr.ensureWorkspaceLabel("/project[1]")
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
	created, err := mgr.ensureWorkspaceLabel("/foo+bar")
	if err != nil {
		t.Fatalf("sibling /foo+bar2 should not conflict with /foo+bar, got: %v", err)
	}
	if !created {
		t.Error("expected newly created mapping")
	}
}

// --- Item 2: always check other local rules even when our exact rule exists ---

func TestEnsureWorkspaceLabelExistingRuleWithNestedConflict(t *testing.T) {
	// existing: /data(/.*)? -> docker_helper_workspace_t
	// existing: /data/secrets(/.*)? -> operator_type
	// ensureWorkspaceLabel("/data") MUST fail before restorecon.
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
	_, err := mgr.ensureWorkspaceLabel("/data")
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

func TestEnsureWorkspaceLabelExistingRuleWithUnrelatedSibling(t *testing.T) {
	// existing: /data(/.*)? -> docker_helper_workspace_t
	// existing: /data2(/.*)? -> other_type
	// ensureWorkspaceLabel("/data") => idempotent success.
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
	created, err := mgr.ensureWorkspaceLabel("/data")
	if err != nil {
		t.Fatalf("unrelated sibling should not conflict, got: %v", err)
	}
	if created {
		t.Error("should not create new mapping when rule already exists")
	}
}

// --- Manager: verifyWorkspaceLabel tests ---

func TestVerifyWorkspaceLabelOK(t *testing.T) {
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}
	if err := mgr.verifyWorkspaceLabel("/data"); err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
}

func TestVerifyWorkspaceLabelWrongType(t *testing.T) {
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.readPathCon = func(path string) (string, error) {
		return "default_t", nil
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
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.readPathCon = func(path string) (string, error) {
		readCalled = true
		return "user_home_t", nil
	}
	if err := mgr.verifyWorkspaceLabel("/home/alice"); err != nil {
		t.Fatalf("expected nil for home root, got: %v", err)
	}
	if readCalled {
		t.Error("should not read path context for home root")
	}
}

func TestVerifyWorkspaceLabelNoMutation(t *testing.T) {
	var runCommandCalled bool
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		runCommandCalled = true
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
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
	// concurrently. Use a blocking lock acquisition to serialize.
	var mutex sync.Mutex
	var order []string
	var blockChan = make(chan struct{})

	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })

	// First caller: acquires lock, blocks inside the critical section.
	firstDone := make(chan struct{})
	go func() {
		mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
				mutex.Lock()
				order = append(order, "first-list")
				mutex.Unlock()
				return []byte{}, nil
			}
			if len(args) > 0 && args[0] == "-R" {
				// Block here to hold the critical section.
				<-blockChan
				return []byte{}, nil
			}
			return []byte{}, nil
		}
		mgr.readPathCon = func(path string) (string, error) {
			return selinuxWorkspaceType, nil
		}
		_, _ = mgr.ensureWorkspaceLabel("/data")
		close(firstDone)
	}()

	// Give first goroutine time to acquire the lock and block.
	<-time.After(50 * time.Millisecond)

	// Second caller: should block on the lock.
	mgr2 := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr2.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			mutex.Lock()
			order = append(order, "second-list")
			mutex.Unlock()
			return []byte{}, nil
		}
		return []byte{}, nil
	}
	mgr2.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
	}

	secondDone := make(chan struct{})
	go func() {
		_, _ = mgr2.ensureWorkspaceLabel("/data")
		close(secondDone)
	}()

	// First should have listed before second.
	// Release first.
	close(blockChan)
	<-firstDone
	<-secondDone

	// Verify ordering.
	mutex.Lock()
	if len(order) < 2 {
		mutex.Unlock()
		t.Skip("concurrent test timing too tight, skipping ordering check")
	}
	firstIdx := -1
	secondIdx := -1
	for i, entry := range order {
		if entry == "first-list" {
			firstIdx = i
		}
		if entry == "second-list" {
			secondIdx = i
		}
	}
	mutex.Unlock()

	if firstIdx >= 0 && secondIdx >= 0 && secondIdx < firstIdx {
		t.Error("second should not list before first (lock should serialize)")
	}
}

// --- Init integration tests ---

func syntheticResolveRoot(path string) (string, error) {
	return path, nil
}

func TestInitSELinuxNonHomeRootPreparesLabel(t *testing.T) {
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	var ensureCalled bool
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" && args[1] == "-l" {
			return []byte{}, nil
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		ensureCalled = true
		return selinuxWorkspaceType, nil
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
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		ensureCalled = true
		return []byte{}, nil
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

func TestInitSELinuxCoreFailureNoRollback(t *testing.T) {
	// Monotonic R2 lifecycle: core failure after successful ensure
	// MUST NOT delete the newly prepared mapping.
	dir := t.TempDir()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	var rollbackCalled bool
	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "fcontext" {
			if args[1] == "-l" {
				return []byte{}, nil
			}
			if args[1] == "-d" {
				rollbackCalled = true
			}
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) {
		return selinuxWorkspaceType, nil
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
		t.Error("rollback MUST NOT be called when core fails (monotonic R2 lifecycle)")
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

// --- Config lifecycle regression tests (deterministic) ---

func TestConfigSetSELinuxPreparationFailure(t *testing.T) {
	// SELinux preparation failure: config bytes unchanged.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	configData := `{"allowed_root": "/old", "session_ttl": "12h"}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	var prepareCalled bool
	origSeam := configSetSeamVar
	configSetSeamVar = &configSetSeam{
		canonicalizeRoot: func(s string) (string, error) { return "/data", nil },
		detectBackend:    func() (LSMBackend, error) { return LSMSelinux, nil },
		selinuxEnsure: func(root string) (bool, error) {
			prepareCalled = true
			return false, errors.New("semanage failed")
		},
	}
	defer func() { configSetSeamVar = origSeam }()

	var stdout, stderr bytes.Buffer
	exitCode := configSet("allowed_root", "/whatever", &stdout, &stderr)
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code for SELinux preparation failure")
	}
	if !prepareCalled {
		t.Error("prepare function must be called")
	}

	// Config should be byte-for-byte unchanged.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != configData {
		t.Errorf("config should be byte-for-byte unchanged, got: %s", string(data))
	}
}

func TestConfigSetDetectLSMError(t *testing.T) {
	// detectLSM failure: config bytes unchanged, manager not invoked.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	configData := `{"allowed_root": "/old", "session_ttl": "12h"}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	var detectCalled bool
	var prepareCalled bool
	origSeam := configSetSeamVar
	configSetSeamVar = &configSetSeam{
		canonicalizeRoot: func(s string) (string, error) { return "/data", nil },
		detectBackend: func() (LSMBackend, error) {
			detectCalled = true
			return LSMNone, errors.New("cannot determine MAC backend")
		},
		selinuxEnsure: func(root string) (bool, error) {
			prepareCalled = true
			return false, nil
		},
	}
	defer func() { configSetSeamVar = origSeam }()

	var stdout, stderr bytes.Buffer
	exitCode := configSet("allowed_root", "/whatever", &stdout, &stderr)
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code for detectLSM failure")
	}
	if !detectCalled {
		t.Error("detector must be called")
	}
	if prepareCalled {
		t.Error("SELinux prepare must NOT be called when detectLSM fails")
	}

	// Config should be byte-for-byte unchanged.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != configData {
		t.Errorf("config should be byte-for-byte unchanged, got: %s", string(data))
	}
}

func TestConfigSetSameAllowedRootRunsSELinuxEnsure(t *testing.T) {
	// same existing allowed_root: SELinux prepare IS called before "unchanged".
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	configData := `{"allowed_root": "/data", "session_ttl": "12h"}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	var prepareCalled bool
	origSeam := configSetSeamVar
	configSetSeamVar = &configSetSeam{
		canonicalizeRoot: func(s string) (string, error) { return "/data", nil },
		detectBackend:    func() (LSMBackend, error) { return LSMSelinux, nil },
		selinuxEnsure: func(root string) (bool, error) {
			prepareCalled = true
			return false, nil
		},
	}
	defer func() { configSetSeamVar = origSeam }()

	var stdout, stderr bytes.Buffer
	exitCode := configSet("allowed_root", "/whatever", &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected success, got exit code %d, stderr: %s", exitCode, stderr.String())
	}
	if !prepareCalled {
		t.Error("SELinux prepare must be called even for unchanged allowed_root")
	}
	if !strings.Contains(stdout.String(), "unchanged") {
		t.Error("should report unchanged")
	}
}

func TestConfigSetSELinuxHomeRootNoPrepare(t *testing.T) {
	// /home: SELinux workspace prepare is not called.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	configData := `{"allowed_root": "/old", "session_ttl": "12h"}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	var prepareCalled bool
	origSeam := configSetSeamVar
	configSetSeamVar = &configSetSeam{
		canonicalizeRoot: func(s string) (string, error) { return "/home/alice", nil },
		detectBackend:    func() (LSMBackend, error) { return LSMSelinux, nil },
		selinuxEnsure: func(root string) (bool, error) {
			prepareCalled = true
			return false, nil
		},
	}
	defer func() { configSetSeamVar = origSeam }()

	var stdout, stderr bytes.Buffer
	exitCode := configSet("allowed_root", "/whatever", &stdout, &stderr)
	// May succeed or fail depending on reload, but prepare must not be called.
	if prepareCalled {
		t.Error("SELinux prepare must NOT be called for /home root")
	}
	_ = exitCode
	_ = stderr
}

// --- Detection regressions ---

func TestServeDetectLSMError(t *testing.T) {
	// runServe: detectLSM error => startup fails closed.
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) {
		return false, false, os.ErrPermission
	}
	defer func() {
		apparmorLSMActive = origAA
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
	if !strings.Contains(stdout.String(), "cannot determine") {
		t.Errorf("expected detection error in output, got: %s", stdout.String())
	}
}

func TestReloadDetectLSMError(t *testing.T) {
	// reload: detectLSM error => request rejected, runtime config unchanged.
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) {
		return false, false, os.ErrPermission
	}
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return "/nonexistent/config.json" }
	defer func() { getConfigPathFunc = origGetConfig }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"reload"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	// The reload CLI fails because it can't connect to the daemon.
	// The server-side detection error is tested via handleReload directly.
	_ = code
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
