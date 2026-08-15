package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func setupApparmorTest(t *testing.T) (dir string, mgr *apparmorManager, captured *[]string) {
	t.Helper()
	dir = t.TempDir()

	mainProfile := filepath.Join(dir, "docker-helper-system")
	managedFragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
	lockPath := filepath.Join(dir, "apparmor.lock")

	captured = &[]string{}
	runCount := 0
	fakeRunner := func(args []string) error {
		*captured = args
		runCount++
		return nil
	}

	mgr = newApparmorManager(
		mainProfile,
		managedFragment,
		lockPath,
		fakeRunner,
		func() error { return nil },
	)

	return dir, mgr, captured
}

func setupApparmorTestWithRunner(t *testing.T, runner func(args []string) error) (dir string, mgr *apparmorManager) {
	t.Helper()
	dir = t.TempDir()

	mainProfile := filepath.Join(dir, "docker-helper-system")
	managedFragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
	lockPath := filepath.Join(dir, "apparmor.lock")

	mgr = newApparmorManager(
		mainProfile,
		managedFragment,
		lockPath,
		runner,
		func() error { return nil },
	)

	return dir, mgr
}

// --- Command registration and help ---

func TestApparmorCommandRegistered(t *testing.T) {
	found := false
	for _, cmd := range rootCommand.Subcommands {
		if cmd.Name == "apparmor" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("apparmor command not registered in rootCommand")
	}
}

func TestApparmorHelpOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("apparmor --help exited %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Usage:") {
		t.Error("help output missing Usage:")
	}
	if !strings.Contains(out, "root") {
		t.Error("help output missing root subcommand")
	}
	if !strings.Contains(out, "check") {
		t.Error("help output missing check subcommand")
	}
}

func TestApparmorRootHelpOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("apparmor root --help exited %d", code)
	}
	out := stdout.String()
	for _, sub := range []string{"list", "add", "remove"} {
		if !strings.Contains(out, sub) {
			t.Errorf("help output missing %s subcommand", sub)
		}
	}
}

func TestApparmorCheckHelpOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "check", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("apparmor check --help exited %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Error("check help output missing Usage:")
	}
}

func TestApparmorRootListHelpOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "list", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("apparmor root list --help exited %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Error("list help output missing Usage:")
	}
}

func TestApparmorRootAddHelpOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "add", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("apparmor root add --help exited %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Error("add help output missing Usage:")
	}
}

func TestApparmorRootRemoveHelpOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "remove", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("apparmor root remove --help exited %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Error("remove help output missing Usage:")
	}
}

func TestApparmorHelpSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"help", "apparmor"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help apparmor exited %d", code)
	}
	if !strings.Contains(stdout.String(), "AppArmor") {
		t.Error("help apparmor missing description")
	}
}

func TestApparmorHelpNestedSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"help", "apparmor", "root", "add"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help apparmor root add exited %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Error("help apparmor root add missing Usage:")
	}
}

// --- Rejection when effective UID is not 0 ---

func TestApparmorRootListRequiresRoot(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = saved }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "list"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "root") {
		t.Errorf("expected root error, got: %s", stderr.String())
	}
}

func TestApparmorRootAddRequiresRoot(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = saved }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "add", "/tmp"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "root") {
		t.Errorf("expected root error, got: %s", stderr.String())
	}
}

func TestApparmorRootRemoveRequiresRoot(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = saved }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "remove", "/tmp"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "root") {
		t.Errorf("expected root error, got: %s", stderr.String())
	}
}

func TestApparmorCheckRequiresRoot(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = saved }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "check"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "root") {
		t.Errorf("expected root error, got: %s", stderr.String())
	}
}

// --- Absolute/existing-directory validation ---

func TestApparmorRootAddRelativePath(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = saved }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "add", "relative/path"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 for relative path, got %d", code)
	}
	if !strings.Contains(stderr.String(), "absolute") {
		t.Errorf("expected absolute path error, got: %s", stderr.String())
	}
}

func TestApparmorRootAddNonExistentPath(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = saved }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "add", "/nonexistent/path/xyz"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 for non-existent path, got %d", code)
	}
	if !strings.Contains(stderr.String(), "does not exist") {
		t.Errorf("expected not exist error, got: %s", stderr.String())
	}
}

func TestApparmorRootAddFileNotDirectory(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = saved }()

	tmpfile := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(tmpfile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "add", tmpfile}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 for file path, got %d", code)
	}
	if !strings.Contains(stderr.String(), "not a directory") {
		t.Errorf("expected not a directory error, got: %s", stderr.String())
	}
}

// --- Canonicalization of a symlinked input path ---

func TestApparmorRootAddSymlinkedPath(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = saved }()

	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	linkDir := filepath.Join(dir, "link")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	result, err := mgr.addRoot(linkDir)
	if err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}
	if result != "added" {
		t.Errorf("expected added, got %s", result)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 1 || roots[0] != realDir {
		t.Errorf("expected canonical root %s, got %v", realDir, roots)
	}
}

// --- Rejection of / and AppArmor-pattern input ---

func TestApparmorRootAddRootDirectory(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = saved }()

	_, mgr, _ := setupApparmorTest(t)

	_, err := mgr.addRoot("/")
	if err == nil {
		t.Fatal("expected error for /")
	}
	if !strings.Contains(err.Error(), "root directory") {
		t.Errorf("expected root directory error, got: %v", err)
	}
}

func TestApparmorRootAddGlobAsterisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test*")
	if err := os.MkdirAll(path, 0755); err == nil {
		defer os.RemoveAll(path)

		_, mgr, _ := setupApparmorTest(t)
		_, err := mgr.addRoot(path)
		if err == nil {
			t.Fatal("expected error for path with *")
		}
		if !strings.Contains(err.Error(), "*") {
			t.Errorf("expected * error, got: %v", err)
		}
	}
}

func TestApparmorRootAddGlobQuestionMark(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test?")
	if err := os.MkdirAll(path, 0755); err == nil {
		defer os.RemoveAll(path)

		_, mgr, _ := setupApparmorTest(t)
		_, err := mgr.addRoot(path)
		if err == nil {
			t.Fatal("expected error for path with ?")
		}
	}
}

func TestApparmorRootAddGlobBracket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test[")
	if err := os.MkdirAll(path, 0755); err == nil {
		defer os.RemoveAll(path)

		_, mgr, _ := setupApparmorTest(t)
		_, err := mgr.addRoot(path)
		if err == nil {
			t.Fatal("expected error for path with [")
		}
	}
}

func TestApparmorRootAddGlobBrace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test{")
	if err := os.MkdirAll(path, 0755); err == nil {
		defer os.RemoveAll(path)

		_, mgr, _ := setupApparmorTest(t)
		_, err := mgr.addRoot(path)
		if err == nil {
			t.Fatal("expected error for path with {")
		}
	}
}

func TestApparmorRootAddCLIRejectsGlob(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = saved }()

	dir := t.TempDir()
	path := filepath.Join(dir, "test*")
	if err := os.MkdirAll(path, 0755); err == nil {
		defer os.RemoveAll(path)

		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"apparmor", "root", "add", path}, &stdout, &stderr)
		if code != 2 {
			t.Errorf("expected exit 2 for glob path, got %d", code)
		}
	}
}

// --- Deterministic sorted rendering ---

func TestRenderFragmentSorted(t *testing.T) {
	roots := []string{"/z/workspace", "/a/workspace", "/m/workspace"}
	data := renderFragment(roots)

	content := string(data)
	aIdx := strings.Index(content, "# root: /a/workspace")
	mIdx := strings.Index(content, "# root: /m/workspace")
	zIdx := strings.Index(content, "# root: /z/workspace")

	if aIdx >= mIdx || mIdx >= zIdx {
		t.Errorf("roots not sorted: a=%d m=%d z=%d", aIdx, mIdx, zIdx)
	}
}

func TestRenderFragmentDeterministic(t *testing.T) {
	roots := []string{"/b", "/a", "/c"}
	data1 := renderFragment(roots)
	data2 := renderFragment([]string{"/c", "/a", "/b"})

	if !bytes.Equal(data1, data2) {
		t.Error("renderFragment not deterministic for same roots in different order")
	}
}

func TestRenderFragmentEmpty(t *testing.T) {
	data := renderFragment(nil)
	content := string(data)
	if !strings.HasPrefix(content, fragmentHeader1) {
		t.Error("empty fragment should start with header")
	}
	if strings.Contains(content, "# root:") {
		t.Error("empty fragment should not contain root entries")
	}
}

// --- Literal-path escaping ---

func TestEscapeAppArmorPath(t *testing.T) {
	tests := []struct {
		input  string
		output string
	}{
		{"/normal/path", "/normal/path"},
		{"/path/with\\backslash", "/path/with\\\\backslash"},
		{"/path/with\\\\double", "/path/with\\\\\\\\double"},
	}

	for _, tc := range tests {
		if got := escapeAppArmorPath(tc.input); got != tc.output {
			t.Errorf("escapeAppArmorPath(%q) = %q, want %q", tc.input, got, tc.output)
		}
	}
}

func TestRenderFragmentEscapesBackslash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "back\\slash")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}

	roots := []string{path}
	data := renderFragment(roots)
	content := string(data)

	escapedPath := escapeAppArmorPath(path)
	if !strings.Contains(content, escapedPath) {
		t.Errorf("fragment should contain escaped path %q, got:\n%s", escapedPath, content)
	}
}

// --- Duplicate add ---

func TestApparmorDuplicateAdd(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	result1, err := mgr.addRoot(testDir)
	if err != nil {
		t.Fatalf("first addRoot failed: %v", err)
	}
	if result1 != "added" {
		t.Errorf("first add expected added, got %s", result1)
	}

	result2, err := mgr.addRoot(testDir)
	if err != nil {
		t.Fatalf("second addRoot failed: %v", err)
	}
	if result2 != "already present" {
		t.Errorf("second add expected already present, got %s", result2)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 1 {
		t.Errorf("expected 1 root, got %d", len(roots))
	}
}

// --- Absent remove ---

func TestApparmorAbsentRemove(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	result, err := mgr.removeRoot(testDir)
	if err != nil {
		t.Fatalf("removeRoot failed: %v", err)
	}
	if result != "was not present" {
		t.Errorf("expected was not present, got %s", result)
	}
}

// --- List of an absent fragment ---

func TestApparmorListAbsentFragment(t *testing.T) {
	_, mgr, _ := setupApparmorTest(t)

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 0 {
		t.Errorf("expected empty list, got %v", roots)
	}
}

// --- Malformed managed fragment ---

func TestApparmorMalformedFragment(t *testing.T) {
	_, mgr, _ := setupApparmorTest(t)

	fragmentDir := filepath.Dir(mgr.managedFragmentPath)
	if err := os.MkdirAll(fragmentDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mgr.managedFragmentPath, []byte("garbage content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := mgr.listRoots()
	if err == nil {
		t.Fatal("expected error for malformed fragment")
	}
}

func TestApparmorFragmentMissingTrailingNewline(t *testing.T) {
	_, mgr, _ := setupApparmorTest(t)

	fragmentDir := filepath.Dir(mgr.managedFragmentPath)
	if err := os.MkdirAll(fragmentDir, 0755); err != nil {
		t.Fatal(err)
	}
	data := renderFragment([]string{"/test"})
	if err := os.WriteFile(mgr.managedFragmentPath, data[:len(data)-1], 0644); err != nil {
		t.Fatal(err)
	}

	_, err := mgr.listRoots()
	if err == nil {
		t.Fatal("expected error for fragment missing trailing newline")
	}
}

func TestApparmorFragmentWrongHeader(t *testing.T) {
	_, mgr, _ := setupApparmorTest(t)

	fragmentDir := filepath.Dir(mgr.managedFragmentPath)
	if err := os.MkdirAll(fragmentDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mgr.managedFragmentPath, []byte("# Wrong header\n# Another line\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := mgr.listRoots()
	if err == nil {
		t.Fatal("expected error for wrong header")
	}
}

func TestApparmorFragmentExtraRules(t *testing.T) {
	_, mgr, _ := setupApparmorTest(t)

	fragmentDir := filepath.Dir(mgr.managedFragmentPath)
	if err := os.MkdirAll(fragmentDir, 0755); err != nil {
		t.Fatal(err)
	}
	extra := renderFragment([]string{"/test"})
	extra = append(extra, []byte("\n/extra/rule/ r,\n")...)
	if err := os.WriteFile(mgr.managedFragmentPath, extra, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := mgr.listRoots()
	if err == nil {
		t.Fatal("expected error for fragment with extra rules")
	}
}

// --- Exact parser arguments without a shell ---

func TestApparmorReloadParserArgs(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "fragment")
	lockPath := filepath.Join(dir, "lock")

	var captured []string
	fakeRunner := func(args []string) error {
		captured = args
		return nil
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath, fakeRunner, func() error { return nil })

	testDir := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, err := mgr.addRoot(testDir)
	if err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}

	if len(captured) != 2 || captured[0] != "-r" || captured[1] != mainProfile {
		t.Errorf("expected parser args [-r %s], got %v", mainProfile, captured)
	}
}

func TestApparmorValidateParserArgs(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "fragment")
	lockPath := filepath.Join(dir, "lock")

	var captured []string
	fakeRunner := func(args []string) error {
		captured = args
		return nil
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath, fakeRunner, func() error { return nil })

	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := mgr.check(); err != nil {
		t.Fatalf("check failed: %v", err)
	}

	if len(captured) != 2 || captured[0] != "--validate" || captured[1] != mainProfile {
		t.Errorf("expected parser args [--validate %s], got %v", mainProfile, captured)
	}
}

func TestApparmorNoShellInvocation(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "fragment")
	lockPath := filepath.Join(dir, "lock")

	shellUsed := false
	fakeRunner := func(args []string) error {
		for _, arg := range args {
			if arg == "-c" || arg == "-sh" || arg == "/bin/sh" || arg == "/bin/bash" {
				shellUsed = true
			}
		}
		return nil
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath, fakeRunner, func() error { return nil })

	testDir := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, err := mgr.addRoot(testDir)
	if err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}

	if shellUsed {
		t.Error("parser should not be invoked through a shell")
	}
}

// --- check does not reload or modify files ---

func TestApparmorCheckDoesNotReload(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
	lockPath := filepath.Join(dir, "lock")

	reloadCalled := false
	validateCalled := false
	fakeRunner := func(args []string) error {
		if len(args) >= 1 && args[0] == "-r" {
			reloadCalled = true
		}
		if len(args) >= 1 && args[0] == "--validate" {
			validateCalled = true
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(fragment), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fragment, renderFragment(nil), 0644); err != nil {
		t.Fatal(err)
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath, fakeRunner, func() error { return nil })

	if err := mgr.check(); err != nil {
		t.Fatalf("check failed: %v", err)
	}

	if reloadCalled {
		t.Error("check should not reload the profile")
	}
	if !validateCalled {
		t.Error("check should validate the profile")
	}
}

func TestApparmorCheckDoesNotModifyFiles(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
	lockPath := filepath.Join(dir, "lock")

	if err := os.MkdirAll(filepath.Dir(fragment), 0755); err != nil {
		t.Fatal(err)
	}
	mainData := []byte("profile test { }\n")
	fragData := renderFragment([]string{"/test"})
	if err := os.WriteFile(mainProfile, mainData, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fragment, fragData, 0644); err != nil {
		t.Fatal(err)
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath, func(args []string) error { return nil }, func() error { return nil })

	if err := mgr.check(); err != nil {
		t.Fatalf("check failed: %v", err)
	}

	afterMain, err := os.ReadFile(mainProfile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterMain, mainData) {
		t.Error("check modified the main profile")
	}

	afterFrag, err := os.ReadFile(fragment)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterFrag, fragData) {
		t.Error("check modified the managed fragment")
	}
}

// --- Successful atomic add/remove ---

func TestApparmorSuccessfulAdd(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, captured := setupApparmorTest(t)

	result, err := mgr.addRoot(testDir)
	if err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}
	if result != "added" {
		t.Errorf("expected added, got %s", result)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 1 || roots[0] != testDir {
		t.Errorf("expected root %s, got %v", testDir, roots)
	}

	if len(*captured) != 2 || (*captured)[0] != "-r" {
		t.Errorf("expected reload call, got args %v", *captured)
	}
}

func TestApparmorSuccessfulRemove(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, captured := setupApparmorTest(t)

	if _, err := mgr.addRoot(testDir); err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}
	*captured = nil

	result, err := mgr.removeRoot(testDir)
	if err != nil {
		t.Fatalf("removeRoot failed: %v", err)
	}
	if result != "removed" {
		t.Errorf("expected removed, got %s", result)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 0 {
		t.Errorf("expected empty list after remove, got %v", roots)
	}

	if len(*captured) != 2 || (*captured)[0] != "-r" {
		t.Errorf("expected reload call after remove, got args %v", *captured)
	}
}

func TestApparmorAddMultipleRoots(t *testing.T) {
	dir := t.TempDir()
	dirA := filepath.Join(dir, "a")
	dirB := filepath.Join(dir, "b")
	dirC := filepath.Join(dir, "c")
	for _, d := range []string{dirA, dirB, dirC} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	_, mgr, _ := setupApparmorTest(t)

	if _, err := mgr.addRoot(dirC); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.addRoot(dirA); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.addRoot(dirB); err != nil {
		t.Fatal(err)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	expected := []string{dirA, dirB, dirC}
	if !reflectSliceEqual(roots, expected) {
		t.Errorf("expected %v, got %v", expected, roots)
	}
}

func reflectSliceEqual(a, b []string) bool {
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

// --- Fragment permissions ---

func TestApparmorFragmentPermissions(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	if _, err := mgr.addRoot(testDir); err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}

	info, err := os.Stat(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("stat fragment failed: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0644 {
		t.Errorf("expected fragment mode 0644, got %o", perm)
	}

	fragDir := filepath.Dir(mgr.managedFragmentPath)
	dirInfo, err := os.Stat(fragDir)
	if err != nil {
		t.Fatalf("stat fragment dir failed: %v", err)
	}
	dirPerm := dirInfo.Mode().Perm()
	if dirPerm != 0755 {
		t.Errorf("expected fragment dir mode 0755, got %o", dirPerm)
	}
}

// --- Parser failure restores the exact previous bytes ---

func TestApparmorParserFailureRestoresPrevious(t *testing.T) {
	dir := t.TempDir()
	testDirA := filepath.Join(dir, "a")
	testDirB := filepath.Join(dir, "b")
	for _, d := range []string{testDirA, testDirB} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	callCount := 0
	fakeRunner := func(args []string) error {
		callCount++
		if callCount == 1 {
			return nil
		}
		return errors.New("parser failed")
	}

	_, mgr := setupApparmorTestWithRunner(t, fakeRunner)

	if _, err := mgr.addRoot(testDirA); err != nil {
		t.Fatalf("first addRoot failed: %v", err)
	}

	prevData, err := os.ReadFile(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("cannot read fragment: %v", err)
	}

	_, err = mgr.addRoot(testDirB)
	if err == nil {
		t.Fatal("expected error for second addRoot")
	}

	afterData, err := os.ReadFile(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("cannot read fragment after rollback: %v", err)
	}

	if !bytes.Equal(prevData, afterData) {
		t.Error("fragment was not restored to previous bytes after parser failure")
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed after rollback: %v", err)
	}
	if len(roots) != 1 || roots[0] != testDirA {
		t.Errorf("expected only %s after rollback, got %v", testDirA, roots)
	}
}

func TestApparmorParserFailureRemoveRestores(t *testing.T) {
	dir := t.TempDir()
	testDirA := filepath.Join(dir, "a")
	testDirB := filepath.Join(dir, "b")
	for _, d := range []string{testDirA, testDirB} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	callCount := 0
	fakeRunner := func(args []string) error {
		callCount++
		return nil
	}

	_, mgr := setupApparmorTestWithRunner(t, fakeRunner)

	if _, err := mgr.addRoot(testDirA); err != nil {
		t.Fatalf("first addRoot failed: %v", err)
	}
	if _, err := mgr.addRoot(testDirB); err != nil {
		t.Fatalf("second addRoot failed: %v", err)
	}

	fakeRunner = func(args []string) error {
		return errors.New("parser failed on remove")
	}
	mgr.runParser = fakeRunner

	prevData, err := os.ReadFile(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("cannot read fragment: %v", err)
	}

	_, err = mgr.removeRoot(testDirA)
	if err == nil {
		t.Fatal("expected error for removeRoot")
	}

	afterData, err := os.ReadFile(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("cannot read fragment after rollback: %v", err)
	}

	if !bytes.Equal(prevData, afterData) {
		t.Error("fragment was not restored to previous bytes after parser failure on remove")
	}
}

// --- Rollback reload failure is reported ---

func TestApparmorRollbackReloadFailure(t *testing.T) {
	dir := t.TempDir()
	testDirA := filepath.Join(dir, "a")
	testDirB := filepath.Join(dir, "b")
	for _, d := range []string{testDirA, testDirB} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	fakeRunner := func(args []string) error {
		return nil
	}

	_, mgr := setupApparmorTestWithRunner(t, fakeRunner)

	if _, err := mgr.addRoot(testDirA); err != nil {
		t.Fatalf("first addRoot failed: %v", err)
	}

	callCount := 0
	mgr.runParser = func(args []string) error {
		callCount++
		return fmt.Errorf("parser error %d", callCount)
	}

	_, err := mgr.addRoot(testDirB)
	if err == nil {
		t.Fatal("expected error for second addRoot")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "reload failed") {
		t.Errorf("expected reload failed in error, got: %v", err)
	}
	if !strings.Contains(errMsg, "rollback also failed") {
		t.Errorf("expected rollback also failed in error, got: %v", err)
	}
}

// --- Concurrent writers are serialized by the lock ---

func TestApparmorConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	testDirA := filepath.Join(dir, "a")
	testDirB := filepath.Join(dir, "b")
	for _, d := range []string{testDirA, testDirB} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	_ = dir

	fakeRunner := func(args []string) error {
		time.Sleep(50 * time.Millisecond)
		return nil
	}

	_, mgr := setupApparmorTestWithRunner(t, fakeRunner)

	var wg sync.WaitGroup
	var errs [2]error
	var results [2]string

	doneFirst := make(chan struct{})

	wg.Add(2)
	go func() {
		defer wg.Done()
		results[0], errs[0] = mgr.addRoot(testDirA)
		close(doneFirst)
	}()

	go func() {
		defer wg.Done()
		<-doneFirst
		results[1], errs[1] = mgr.addRoot(testDirB)
	}()

	wg.Wait()

	for i, e := range errs {
		if e != nil {
			t.Fatalf("goroutine %d error: %v", i, e)
		}
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	sort.Strings(roots)
	expected := []string{testDirA, testDirB}
	if !reflectSliceEqual(roots, expected) {
		t.Errorf("expected %v, got %v", expected, roots)
	}
}

func TestApparmorLockSerialization(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "lock")

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "fragment")

	mgr := newApparmorManager(mainProfile, fragment, lockPath,
		func(args []string) error { return nil },
		func() error { return nil },
	)

	_, err = mgr.acquireApparmorLock()
	if err == nil {
		f.Close()
		t.Fatal("expected lock error when another process holds the lock")
	}
	if !strings.Contains(err.Error(), "in progress") {
		t.Errorf("expected in progress error, got: %v", err)
	}

	f.Close()
}

// --- validateRootPath edge cases ---

func TestValidateRootPathAbsolute(t *testing.T) {
	_, err := validateRootPath("relative")
	if err == nil {
		t.Fatal("expected error for relative path")
	}
	if !isInputError(err) {
		t.Error("expected inputError for relative path")
	}
}

func TestValidateRootPathNotDirectory(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(tmpfile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := validateRootPath(tmpfile)
	if err == nil {
		t.Fatal("expected error for file path")
	}
	if !isInputError(err) {
		t.Error("expected inputError for file path")
	}
}

func TestValidateRootPathNotExists(t *testing.T) {
	_, err := validateRootPath("/nonexistent/path/xyz")
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
	if !isInputError(err) {
		t.Error("expected inputError for non-existent path")
	}
}

// --- Symlink at managed fragment path ---

func TestApparmorSymlinkFragmentRejected(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	realFragment := filepath.Join(dir, "real-fragment")
	linkFragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
	lockPath := filepath.Join(dir, "lock")

	if err := os.MkdirAll(filepath.Dir(linkFragment), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realFragment, renderFragment(nil), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realFragment, linkFragment); err != nil {
		t.Fatal(err)
	}

	mgr := newApparmorManager(mainProfile, linkFragment, lockPath,
		func(args []string) error { return nil },
		func() error { return nil },
	)

	_, err := mgr.listRoots()
	if err == nil {
		t.Fatal("expected error for symlink fragment")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
}

// --- Check command behavior ---

func TestApparmorCheckParserNotAvailable(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "fragment")
	lockPath := filepath.Join(dir, "lock")

	mgr := newApparmorManager(mainProfile, fragment, lockPath,
		func(args []string) error { return nil },
		func() error { return errors.New("apparmor_parser not found in PATH") },
	)

	err := mgr.check()
	if err == nil {
		t.Fatal("expected error when parser not available")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got: %v", err)
	}
}

func TestApparmorCheckMainProfileNotFound(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "nonexistent")
	fragment := filepath.Join(dir, "fragment")
	lockPath := filepath.Join(dir, "lock")

	mgr := newApparmorManager(mainProfile, fragment, lockPath,
		func(args []string) error { return nil },
		func() error { return nil },
	)

	err := mgr.check()
	if err == nil {
		t.Fatal("expected error when main profile not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got: %v", err)
	}
}

func TestApparmorCheckValidationFailure(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
	lockPath := filepath.Join(dir, "lock")

	if err := os.MkdirAll(filepath.Dir(fragment), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fragment, renderFragment(nil), 0644); err != nil {
		t.Fatal(err)
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath,
		func(args []string) error { return errors.New("validation failed") },
		func() error { return nil },
	)

	err := mgr.check()
	if err == nil {
		t.Fatal("expected error when validation fails")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("expected validation failed error, got: %v", err)
	}
}

func TestApparmorCheckSuccess(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
	lockPath := filepath.Join(dir, "lock")

	if err := os.MkdirAll(filepath.Dir(fragment), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fragment, renderFragment(nil), 0644); err != nil {
		t.Fatal(err)
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath,
		func(args []string) error { return nil },
		func() error { return nil },
	)

	if err := mgr.check(); err != nil {
		t.Fatalf("check failed: %v", err)
	}
}

// --- Remove does not infer parent/child ---

func TestApparmorRemoveNoInference(t *testing.T) {
	dir := t.TempDir()
	parentDir := filepath.Join(dir, "parent")
	childDir := filepath.Join(parentDir, "child")
	for _, d := range []string{parentDir, childDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	_, mgr, _ := setupApparmorTest(t)

	if _, err := mgr.addRoot(parentDir); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.addRoot(childDir); err != nil {
		t.Fatal(err)
	}

	if _, err := mgr.removeRoot(childDir); err != nil {
		t.Fatalf("removeRoot failed: %v", err)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 1 || roots[0] != parentDir {
		t.Errorf("expected only parent %s, got %v", parentDir, roots)
	}
}

// --- Fragment parse round-trip ---

func TestFragmentRoundTrip(t *testing.T) {
	roots := []string{"/a", "/b", "/c"}
	data := renderFragment(roots)

	parsed, err := parseFragment(data)
	if err != nil {
		t.Fatalf("parseFragment failed: %v", err)
	}
	if !reflectSliceEqual(parsed, roots) {
		t.Errorf("expected %v, got %v", roots, parsed)
	}
}

func TestFragmentEmptyRoundTrip(t *testing.T) {
	data := renderFragment(nil)
	parsed, err := parseFragment(data)
	if err != nil {
		t.Fatalf("parseFragment failed: %v", err)
	}
	if len(parsed) != 0 {
		t.Errorf("expected empty, got %v", parsed)
	}
}

// --- CLI exit codes ---

func TestApparmorRootAddInputErrorExitCode(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = saved }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "add", "not-absolute"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 for input error, got %d", code)
	}
}

func TestApparmorRootRemoveInputErrorExitCode(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = saved }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "remove", "not-absolute"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 for input error, got %d", code)
	}
}

func TestApparmorRootAddMissingArg(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "add"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 for missing arg, got %d", code)
	}
}

func TestApparmorRootRemoveMissingArg(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "remove"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 for missing arg, got %d", code)
	}
}

func TestApparmorRootMissingSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 for missing subcommand, got %d", code)
	}
}

func TestApparmorMissingSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 for missing subcommand, got %d", code)
	}
}

// --- renderFragment format ---

func TestRenderFragmentFormat(t *testing.T) {
	roots := []string{"/workspace"}
	data := renderFragment(roots)
	content := string(data)

	lines := strings.Split(content, "\n")
	if lines[0] != fragmentHeader1 {
		t.Errorf("expected header line 1, got: %s", lines[0])
	}
	if lines[1] != fragmentHeader2 {
		t.Errorf("expected header line 2, got: %s", lines[1])
	}
	if lines[2] != "" {
		t.Errorf("expected blank line after header, got: %s", lines[2])
	}
	if lines[3] != "# root: /workspace" {
		t.Errorf("expected root metadata, got: %s", lines[3])
	}
	if lines[4] != "/workspace/ r," {
		t.Errorf("expected dir rule, got: %s", lines[4])
	}
	if lines[5] != "/workspace/** r," {
		t.Errorf("expected glob rule, got: %s", lines[5])
	}
}

func TestRenderFragmentMultipleRoots(t *testing.T) {
	roots := []string{"/a", "/b"}
	data := renderFragment(roots)
	content := string(data)

	if !strings.Contains(content, "# root: /a") {
		t.Error("missing root /a")
	}
	if !strings.Contains(content, "# root: /b") {
		t.Error("missing root /b")
	}
	if !strings.Contains(content, "/a/ r,") {
		t.Error("missing rule for /a")
	}
	if !strings.Contains(content, "/b/ r,") {
		t.Error("missing rule for /b")
	}
}
