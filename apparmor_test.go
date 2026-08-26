package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// capturedParserCall records the most recent apparmor_parser invocation.
type capturedParserCall struct {
	exe  string
	args []string
}

// setupAppArmorTestWithRunner builds a manager over a fresh temp dir with a
// fake executable parser and the given runner.
func setupAppArmorTestWithRunner(t *testing.T, runner func(exe string, args []string) error) (dir string, mgr *appArmorProfileManager) {
	t.Helper()
	dir = t.TempDir()

	mainProfile := filepath.Join(dir, "docker-helper-system")
	managedFragment := filepath.Join(dir, "docker-helper.d", "managed-boundaries")
	lockPath := filepath.Join(dir, "apparmor.lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mgr = newAppArmorProfileManager(
		mainProfile,
		managedFragment,
		lockPath,
		parserPath,
		runner,
	)

	return dir, mgr
}

// setupAppArmorTest is like setupAppArmorTestWithRunner but captures each
// parser invocation for assertions.
func setupAppArmorTest(t *testing.T) (dir string, mgr *appArmorProfileManager, captured *capturedParserCall) {
	t.Helper()
	captured = &capturedParserCall{}
	dir, mgr = setupAppArmorTestWithRunner(t, func(exe string, args []string) error {
		captured.exe = exe
		captured.args = args
		return nil
	})
	return dir, mgr, captured
}

// mockAppArmorActive sets appArmorLSMActive to return (active, nil) and
// returns a cleanup function to restore the original.
func mockAppArmorActive(t *testing.T, active bool) {
	t.Helper()
	saved := appArmorLSMActive
	appArmorLSMActive = func() (bool, error) { return active, nil }
	t.Cleanup(func() { appArmorLSMActive = saved })
}

// mockSELinuxInactive disables SELinux detection for tests that target
// AppArmor-only scenarios, preventing host SELinux state from leaking in.
func mockSELinuxInactive(t *testing.T) {
	t.Helper()
	saved := selinuxEnabled
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	t.Cleanup(func() { selinuxEnabled = saved })
}

// --- Command registration and help ---

// TestAppArmorHelpOutput verifies help dispatch for every apparmor command
// level, including the "help <command>" form. Running "apparmor --help"
// through the real dispatcher also proves the command is registered.
func TestAppArmorHelpOutput(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{name: "apparmor", args: []string{"apparmor", "--help"}, want: []string{"Usage:", "root", "check"}},
		{name: "apparmor root", args: []string{"apparmor", "root", "--help"}, want: []string{"Usage:", "list", "add", "remove"}},
		{name: "apparmor check", args: []string{"apparmor", "check", "--help"}, want: []string{"Usage:"}},
		{name: "apparmor root list", args: []string{"apparmor", "root", "list", "--help"}, want: []string{"Usage:"}},
		{name: "apparmor root add", args: []string{"apparmor", "root", "add", "--help"}, want: []string{"Usage:"}},
		{name: "apparmor root remove", args: []string{"apparmor", "root", "remove", "--help"}, want: []string{"Usage:"}},
		{name: "help apparmor", args: []string{"help", "apparmor"}, want: []string{"AppArmor"}},
		{name: "help apparmor root add", args: []string{"help", "apparmor", "root", "add"}, want: []string{"Usage:"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tc.args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exited %d, stderr: %s", code, stderr.String())
			}
			for _, s := range tc.want {
				if !strings.Contains(stdout.String(), s) {
					t.Errorf("help output missing %q", s)
				}
			}
		})
	}
}

// --- Rejection when effective UID is not 0 ---

func TestAppArmorRequiresRoot(t *testing.T) {
	saved := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = saved }()

	tests := []struct {
		name string
		args []string
	}{
		{name: "root list", args: []string{"apparmor", "root", "list"}},
		{name: "root add", args: []string{"apparmor", "root", "add", "/tmp"}},
		{name: "root remove", args: []string{"apparmor", "root", "remove", "/tmp"}},
		{name: "check", args: []string{"apparmor", "check"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tc.args, &stdout, &stderr)
			if code != 1 {
				t.Errorf("expected exit 1, got %d", code)
			}
			if !strings.Contains(stderr.String(), "root") {
				t.Errorf("expected root error, got: %s", stderr.String())
			}
		})
	}
}

// --- Absolute/existing-directory validation ---

func TestAppArmorBoundaryAddRelativePath(t *testing.T) {
	mockAppArmorActive(t, true)
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

func TestAppArmorBoundaryAddNonExistentPath(t *testing.T) {
	mockAppArmorActive(t, true)
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

func TestAppArmorBoundaryAddFileNotDirectory(t *testing.T) {
	mockAppArmorActive(t, true)
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

func TestAppArmorBoundaryAddSymlinkedPath(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	realDir := filepath.Join(rootDir, "real")
	linkDir := filepath.Join(rootDir, "link")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupAppArmorTest(t)

	result, err := mgr.addManagedBoundary(linkDir)
	if err != nil {
		t.Fatalf("addBoundary failed: %v", err)
	}
	if result.Path != realDir {
		t.Errorf("expected canonical result %s, got %s", realDir, result.Path)
	}
	if !result.Changed {
		t.Error("expected Changed=true")
	}

	boundaries, err := mgr.listManagedBoundaries()
	if err != nil {
		t.Fatalf("listBoundaries failed: %v", err)
	}
	if len(boundaries) != 1 || boundaries[0] != realDir {
		t.Errorf("expected canonical boundary %s, got %v", realDir, boundaries)
	}
}

// --- Rejection of / and AppArmor-pattern input ---

func TestAppArmorBoundaryAddRootDirectory(t *testing.T) {
	_, mgr, _ := setupAppArmorTest(t)

	_, err := mgr.addManagedBoundary("/")
	if err == nil {
		t.Fatal("expected error for /")
	}
	if !strings.Contains(err.Error(), "filesystem root") {
		t.Errorf("expected filesystem root error, got: %v", err)
	}
}

func TestAppArmorBoundaryAddGlobRejected(t *testing.T) {
	// The base must be policy-legal (t.TempDir() is under the forbidden /tmp
	// tree and would be rejected by the workspace-path policy before lexical
	// validation runs), so the rejection comes from the lexical check.
	rootDir := testAllowedRootDir(t)

	for _, ch := range []string{"*", "?", "[", "{"} {
		t.Run(ch, func(t *testing.T) {
			path := filepath.Join(rootDir, "test"+ch)
			if err := os.MkdirAll(path, 0755); err != nil {
				t.Skipf("cannot create path with %q: %v", ch, err)
			}

			_, mgr, _ := setupAppArmorTest(t)
			_, err := mgr.addManagedBoundary(path)
			if err == nil {
				t.Fatalf("expected error for path with %q", ch)
			}
			if !strings.Contains(err.Error(), ch) {
				t.Errorf("expected %q in error, got: %v", ch, err)
			}
		})
	}
}

func TestAppArmorRootAddCLIRejectsGlob(t *testing.T) {
	mockAppArmorActive(t, true)
	saved := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = saved }()

	// Policy-legal base, as in TestAppArmorBoundaryAddGlobRejected.
	rootDir := testAllowedRootDir(t)
	path := filepath.Join(rootDir, "test*")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Skipf("cannot create path with glob: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "add", path}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 for glob path, got %d", code)
	}
}

// --- Deterministic sorted rendering ---

func TestRenderFragmentSorted(t *testing.T) {
	boundaries := []string{"/z/workspace", "/a/workspace", "/m/workspace"}
	data := renderFragment(boundaries)

	content := string(data)
	aIdx := strings.Index(content, `# root-json: "/a/workspace"`)
	mIdx := strings.Index(content, `# root-json: "/m/workspace"`)
	zIdx := strings.Index(content, `# root-json: "/z/workspace"`)

	if aIdx >= mIdx || mIdx >= zIdx {
		t.Errorf("boundaries not sorted: a=%d m=%d z=%d", aIdx, mIdx, zIdx)
	}
}

func TestRenderFragmentDeterministic(t *testing.T) {
	boundaries := []string{"/b", "/a", "/c"}
	data1 := renderFragment(boundaries)
	data2 := renderFragment([]string{"/c", "/a", "/b"})

	if !bytes.Equal(data1, data2) {
		t.Error("renderFragment not deterministic for same boundaries in different order")
	}
}

func TestRenderFragmentEmpty(t *testing.T) {
	data := renderFragment(nil)
	content := string(data)
	if !strings.HasPrefix(content, fragmentHeader1) {
		t.Error("empty fragment should start with header")
	}
	if strings.Contains(content, "# root-json:") {
		t.Error("empty fragment should not contain boundary entries")
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
		{"/path/with\"quote", "/path/with\\\"quote"},
		{"/path/with\\\\double", "/path/with\\\\\\\\double"},
	}

	for _, tc := range tests {
		if got := escapeAppArmorPath(tc.input); got != tc.output {
			t.Errorf("escapeAppArmorPath(%q) = %q, want %q", tc.input, got, tc.output)
		}
	}
}

// --- Special characters in paths ---

func TestBoundaryWithSpecialCharacters(t *testing.T) {
	for _, name := range []string{"with space", `with"quote`, "with#hash", "with,comma", "with\\backslash"} {
		t.Run(name, func(t *testing.T) {
			rootDir := testAllowedRootDir(t)
			path := filepath.Join(rootDir, name)
			if err := os.MkdirAll(path, 0755); err != nil {
				t.Fatal(err)
			}

			_, mgr, _ := setupAppArmorTest(t)

			result, err := mgr.addManagedBoundary(path)
			if err != nil {
				t.Fatalf("addBoundary failed: %v", err)
			}
			if result.Path != path {
				t.Errorf("expected %s, got %s", path, result.Path)
			}

			boundaries, err := mgr.listManagedBoundaries()
			if err != nil {
				t.Fatalf("listBoundaries failed: %v", err)
			}
			if len(boundaries) != 1 || boundaries[0] != path {
				t.Errorf("expected boundary %s, got %v", path, boundaries)
			}
		})
	}
}

func TestBoundaryWithControlCharacter(t *testing.T) {
	// Policy-legal base so the rejection comes from lexical validation, not
	// the workspace-path policy (t.TempDir() is under the forbidden /tmp).
	rootDir := testAllowedRootDir(t)
	path := filepath.Join(rootDir, "with\x01control")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupAppArmorTest(t)
	_, err := mgr.addManagedBoundary(path)
	if err == nil {
		t.Fatal("expected error for control character")
	}
}

// --- Metadata round trip ---

func TestMetadataRoundTrip(t *testing.T) {
	paths := []string{
		"/normal",
		"/with space",
		`/with"quote`,
		"/with\\backslash",
		"/with#hash",
		"/with,comma",
	}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			quoted := jsonQuote(p)
			line := "# root-json: " + quoted
			unquoted, err := jsonUnquote(quoted)
			if err != nil {
				t.Fatalf("jsonUnquote failed: %v", err)
			}
			if unquoted != p {
				t.Errorf("round trip failed: %q -> %q -> %q", p, quoted, unquoted)
			}
			if !strings.HasPrefix(line, "# root-json: ") {
				t.Error("metadata line should start with # root-json: ")
			}
		})
	}
}

// --- Exact AppArmor rule text ---

func TestRenderFragmentRuleEscaping(t *testing.T) {
	boundaries := []string{`/path\with"special`}
	data := renderFragment(boundaries)
	content := string(data)

	if !strings.Contains(content, `"/path\\with\"special/" r,`) {
		t.Errorf("expected escaped rule, got:\n%s", content)
	}
}

// --- Duplicate add ---

func TestAppArmorDuplicateAdd(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	testDir := filepath.Join(rootDir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupAppArmorTest(t)

	result1, err := mgr.addManagedBoundary(testDir)
	if err != nil {
		t.Fatalf("first addBoundary failed: %v", err)
	}
	if !result1.Changed {
		t.Error("first add expected Changed=true")
	}
	if result1.Path != testDir {
		t.Errorf("first add expected path %s, got %s", testDir, result1.Path)
	}

	result2, err := mgr.addManagedBoundary(testDir)
	if err != nil {
		t.Fatalf("second addBoundary failed: %v", err)
	}
	if result2.Changed {
		t.Error("second add expected Changed=false")
	}
	if result2.Path != testDir {
		t.Errorf("second add expected path %s, got %s", testDir, result2.Path)
	}

	boundaries, err := mgr.listManagedBoundaries()
	if err != nil {
		t.Fatalf("listBoundaries failed: %v", err)
	}
	if len(boundaries) != 1 {
		t.Errorf("expected 1 boundary, got %d", len(boundaries))
	}
}

// --- Absent remove ---

func TestAppArmorAbsentRemove(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupAppArmorTest(t)

	result, err := mgr.removeManagedBoundary(testDir)
	if err != nil {
		t.Fatalf("removeBoundary failed: %v", err)
	}
	if result.Changed {
		t.Error("expected Changed=false for absent root")
	}
	if result.Path != testDir {
		t.Errorf("expected path %s, got %s", testDir, result.Path)
	}
}

// --- Remove after directory deletion ---

func TestAppArmorRemoveAfterDeletion(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	testDir := filepath.Join(rootDir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupAppArmorTest(t)

	if _, err := mgr.addManagedBoundary(testDir); err != nil {
		t.Fatalf("addBoundary failed: %v", err)
	}

	if err := os.RemoveAll(testDir); err != nil {
		t.Fatalf("RemoveAll failed: %v", err)
	}

	result, err := mgr.removeManagedBoundary(testDir)
	if err != nil {
		t.Fatalf("removeBoundary failed after deletion: %v", err)
	}
	if !result.Changed {
		t.Error("expected Changed=true")
	}
	if result.Path != testDir {
		t.Errorf("expected %s, got %s", testDir, result.Path)
	}

	boundaries, err := mgr.listManagedBoundaries()
	if err != nil {
		t.Fatalf("listBoundaries failed: %v", err)
	}
	if len(boundaries) != 0 {
		t.Errorf("expected empty list after remove, got %v", boundaries)
	}
}

// --- List of an absent fragment ---

func TestAppArmorListAbsentFragment(t *testing.T) {
	_, mgr, _ := setupAppArmorTest(t)

	boundaries, err := mgr.listManagedBoundaries()
	if err != nil {
		t.Fatalf("listBoundaries failed: %v", err)
	}
	if len(boundaries) != 0 {
		t.Errorf("expected empty list, got %v", boundaries)
	}
}

// --- Malformed managed fragment ---

func TestAppArmorListMalformedFragment(t *testing.T) {
	_, mgr, _ := setupAppArmorTest(t)

	fragmentDir := filepath.Dir(mgr.managedFragmentPath)
	if err := os.MkdirAll(fragmentDir, 0755); err != nil {
		t.Fatal(err)
	}
	valid := renderFragment([]string{"/test"})

	tests := []struct {
		name string
		data []byte
	}{
		{"garbage content", []byte("garbage content\n")},
		{"missing trailing newline", valid[:len(valid)-1]},
		{"wrong header", []byte("# Wrong header\n# Another line\n")},
		{"extra rules", append(append([]byte{}, valid...), []byte("\n/extra/rule/ r,\n")...)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(mgr.managedFragmentPath, tc.data, 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := mgr.listManagedBoundaries(); err == nil {
				t.Fatal("expected error for malformed fragment")
			}
		})
	}
}

// --- Exact parser executable and arguments ---

func TestAppArmorParserInvocation(t *testing.T) {
	tests := []struct {
		name     string
		op       func(mgr *appArmorProfileManager, testDir string) error
		wantArgs []string // plus the main profile path as the final argument
	}{
		{
			name: "reload on add",
			op: func(mgr *appArmorProfileManager, testDir string) error {
				_, err := mgr.addManagedBoundary(testDir)
				return err
			},
			wantArgs: []string{"--replace", "--skip-read-cache"},
		},
		{
			name: "validate on check",
			op: func(mgr *appArmorProfileManager, testDir string) error {
				return mgr.check()
			},
			wantArgs: []string{"--skip-kernel-load", "--skip-read-cache"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			rootDir := testAllowedRootDir(t)
			testDir := filepath.Join(rootDir, "workspace")
			mainProfile := filepath.Join(dir, "main")
			fragment := filepath.Join(dir, "fragment")
			lockPath := filepath.Join(dir, "lock")
			parserPath := filepath.Join(dir, "sbin", "apparmor_parser")

			if err := os.MkdirAll(filepath.Dir(parserPath), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(testDir, 0755); err != nil {
				t.Fatal(err)
			}

			captured := &capturedParserCall{}
			mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath,
				func(exe string, args []string) error {
					captured.exe = exe
					captured.args = args
					return nil
				},
			)

			if err := tc.op(mgr, testDir); err != nil {
				t.Fatalf("operation failed: %v", err)
			}

			if captured.exe != parserPath {
				t.Errorf("expected parser exe %s, got %s", parserPath, captured.exe)
			}
			wantArgs := append(append([]string{}, tc.wantArgs...), mainProfile)
			if len(captured.args) != len(wantArgs) {
				t.Fatalf("expected parser args %v, got %v", wantArgs, captured.args)
			}
			for i := range wantArgs {
				if captured.args[i] != wantArgs[i] {
					t.Errorf("parser arg[%d] = %q, want %q", i, captured.args[i], wantArgs[i])
				}
			}
		})
	}
}

func TestAppArmorNoShellInvocation(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "fragment")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	shellUsed := false
	fakeRunner := func(exe string, args []string) error {
		base := filepath.Base(exe)
		if base == "sh" || base == "bash" || exe == "/bin/sh" || exe == "/bin/bash" {
			shellUsed = true
		}
		for _, arg := range args {
			if arg == "-c" || arg == "-sh" {
				shellUsed = true
			}
		}
		return nil
	}

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath, fakeRunner)

	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, err := mgr.addManagedBoundary(testDir)
	if err != nil {
		t.Fatalf("addBoundary failed: %v", err)
	}

	if shellUsed {
		t.Error("parser should not be invoked through a shell")
	}
}

// --- check does not reload or modify files ---

func TestAppArmorCheckDoesNotReload(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-boundaries")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.MkdirAll(filepath.Dir(fragment), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fragment, renderFragment(nil), 0644); err != nil {
		t.Fatal(err)
	}

	reloadCalled := false
	validateCalled := false
	fakeRunner := func(exe string, args []string) error {
		if len(args) >= 1 && args[0] == "--replace" {
			reloadCalled = true
		}
		if len(args) >= 1 && args[0] == "--skip-kernel-load" {
			validateCalled = true
		}
		return nil
	}

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath, fakeRunner)

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

func TestAppArmorCheckDoesNotModifyFiles(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-boundaries")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.MkdirAll(filepath.Dir(fragment), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
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

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath, func(exe string, args []string) error { return nil })

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

func TestAppArmorSuccessfulAdd(t *testing.T) {
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, captured := setupAppArmorTest(t)

	result, err := mgr.addManagedBoundary(testDir)
	if err != nil {
		t.Fatalf("addBoundary failed: %v", err)
	}
	if !result.Changed {
		t.Error("expected Changed=true")
	}
	if result.Path != testDir {
		t.Errorf("expected %s, got %s", testDir, result.Path)
	}

	boundaries, err := mgr.listManagedBoundaries()
	if err != nil {
		t.Fatalf("listBoundaries failed: %v", err)
	}
	if len(boundaries) != 1 || boundaries[0] != testDir {
		t.Errorf("expected boundary %s, got %v", testDir, boundaries)
	}

	if len(captured.args) != 3 || captured.args[0] != "--replace" {
		t.Errorf("expected reload call, got args %v", captured.args)
	}
}

func TestAppArmorSuccessfulRemove(t *testing.T) {
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, captured := setupAppArmorTest(t)

	if _, err := mgr.addManagedBoundary(testDir); err != nil {
		t.Fatalf("addBoundary failed: %v", err)
	}
	captured.args = nil

	result, err := mgr.removeManagedBoundary(testDir)
	if err != nil {
		t.Fatalf("removeBoundary failed: %v", err)
	}
	if !result.Changed {
		t.Error("expected Changed=true")
	}
	if result.Path != testDir {
		t.Errorf("expected %s, got %s", testDir, result.Path)
	}

	boundaries, err := mgr.listManagedBoundaries()
	if err != nil {
		t.Fatalf("listBoundaries failed: %v", err)
	}
	if len(boundaries) != 0 {
		t.Errorf("expected empty list after remove, got %v", boundaries)
	}

	if len(captured.args) != 3 || captured.args[0] != "--replace" {
		t.Errorf("expected reload call after remove, got args %v", captured.args)
	}
}

func TestAppArmorAddMultipleBoundaries(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	dirA := filepath.Join(rootDir, "a")
	dirB := filepath.Join(rootDir, "b")
	dirC := filepath.Join(rootDir, "c")
	for _, d := range []string{dirA, dirB, dirC} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	_, mgr, _ := setupAppArmorTest(t)

	if _, err := mgr.addManagedBoundary(dirC); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.addManagedBoundary(dirA); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.addManagedBoundary(dirB); err != nil {
		t.Fatal(err)
	}

	boundaries, err := mgr.listManagedBoundaries()
	if err != nil {
		t.Fatalf("listBoundaries failed: %v", err)
	}
	expected := []string{dirA, dirB, dirC}
	if !reflectSliceEqual(boundaries, expected) {
		t.Errorf("expected %v, got %v", expected, boundaries)
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

func TestAppArmorFragmentPermissions(t *testing.T) {
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupAppArmorTest(t)

	if _, err := mgr.addManagedBoundary(testDir); err != nil {
		t.Fatalf("addBoundary failed: %v", err)
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

func TestAppArmorParserFailureRestoresPrevious(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	testDirA := filepath.Join(rootDir, "a")
	testDirB := filepath.Join(rootDir, "b")
	for _, d := range []string{testDirA, testDirB} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	callCount := 0
	fakeRunner := func(exe string, args []string) error {
		callCount++
		if callCount == 1 {
			return nil
		}
		return errors.New("parser failed")
	}

	_, mgr := setupAppArmorTestWithRunner(t, fakeRunner)

	if _, err := mgr.addManagedBoundary(testDirA); err != nil {
		t.Fatalf("first addBoundary failed: %v", err)
	}

	prevData, err := os.ReadFile(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("cannot read fragment: %v", err)
	}

	_, err = mgr.addManagedBoundary(testDirB)
	if err == nil {
		t.Fatal("expected error for second addBoundary")
	}

	afterData, err := os.ReadFile(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("cannot read fragment after rollback: %v", err)
	}

	if !bytes.Equal(prevData, afterData) {
		t.Error("fragment was not restored to previous bytes after parser failure")
	}

	boundaries, err := mgr.listManagedBoundaries()
	if err != nil {
		t.Fatalf("listBoundaries failed after rollback: %v", err)
	}
	if len(boundaries) != 1 || boundaries[0] != testDirA {
		t.Errorf("expected only %s after rollback, got %v", testDirA, boundaries)
	}
}

func TestAppArmorParserFailureRemoveRestores(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	testDirA := filepath.Join(rootDir, "a")
	testDirB := filepath.Join(rootDir, "b")
	for _, d := range []string{testDirA, testDirB} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	fakeRunner := func(exe string, args []string) error {
		return nil
	}

	_, mgr := setupAppArmorTestWithRunner(t, fakeRunner)

	if _, err := mgr.addManagedBoundary(testDirA); err != nil {
		t.Fatalf("first addBoundary failed: %v", err)
	}
	if _, err := mgr.addManagedBoundary(testDirB); err != nil {
		t.Fatalf("second addBoundary failed: %v", err)
	}

	mgr.runParser = func(exe string, args []string) error {
		return errors.New("parser failed on remove")
	}

	prevData, err := os.ReadFile(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("cannot read fragment: %v", err)
	}

	_, err = mgr.removeManagedBoundary(testDirA)
	if err == nil {
		t.Fatal("expected error for removeBoundary")
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

func TestAppArmorRollbackReloadFailure(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	testDirA := filepath.Join(rootDir, "a")
	testDirB := filepath.Join(rootDir, "b")
	for _, d := range []string{testDirA, testDirB} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	fakeRunner := func(exe string, args []string) error {
		return nil
	}

	_, mgr := setupAppArmorTestWithRunner(t, fakeRunner)

	if _, err := mgr.addManagedBoundary(testDirA); err != nil {
		t.Fatalf("first addBoundary failed: %v", err)
	}

	callCount := 0
	mgr.runParser = func(exe string, args []string) error {
		callCount++
		return fmt.Errorf("parser error %d", callCount)
	}

	_, err := mgr.addManagedBoundary(testDirB)
	if err == nil {
		t.Fatal("expected error for second addBoundary")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "reload failed") {
		t.Errorf("expected reload failed in error, got: %v", err)
	}
	if !strings.Contains(errMsg, "rollback also failed") {
		t.Errorf("expected rollback also failed in error, got: %v", err)
	}
}

// --- Lock serialization ---

func TestAppArmorLockSerialization(t *testing.T) {
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
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return nil },
	)

	_, err = mgr.acquireAppArmorLock()
	if err == nil {
		f.Close()
		t.Fatal("expected lock error when another process holds the lock")
	}
	if !strings.Contains(err.Error(), "in progress") {
		t.Errorf("expected in progress error, got: %v", err)
	}

	f.Close()
}

// --- Real concurrency test ---

func TestAppArmorConcurrentLockBusy(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	testDirA := filepath.Join(rootDir, "a")
	testDirB := filepath.Join(rootDir, "b")
	for _, d := range []string{testDirA, testDirB} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	firstInRunner := make(chan struct{})
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})

	fakeRunner := func(exe string, args []string) error {
		close(firstInRunner)
		<-firstDone
		return nil
	}

	_, mgr := setupAppArmorTestWithRunner(t, fakeRunner)

	var wg sync.WaitGroup
	var errA, errB error
	var resultA boundaryResult

	wg.Add(2)

	// First goroutine: enters runner, holds lock
	go func() {
		defer wg.Done()
		resultA, errA = mgr.addManagedBoundary(testDirA)
	}()

	// Wait for first goroutine to be in the runner (lock held)
	<-firstInRunner

	// Second goroutine: tries to acquire lock while first holds it
	go func() {
		defer wg.Done()
		_, errB = mgr.addManagedBoundary(testDirB)
		close(secondDone)
	}()

	// Wait for second goroutine to complete (should get lock-busy error)
	<-secondDone

	// Release first goroutine
	close(firstDone)

	wg.Wait()

	// First should succeed
	if errA != nil {
		t.Fatalf("first goroutine error: %v", errA)
	}
	if !resultA.Changed {
		t.Error("first goroutine expected Changed=true")
	}

	// Second should get lock-busy error
	if errB == nil {
		t.Error("second goroutine expected lock-busy error, got nil")
	} else if !strings.Contains(errB.Error(), "in progress") {
		t.Errorf("second goroutine expected lock-busy error, got: %v", errB)
	}
}

// --- Parser not executable preflight ---

func TestAppArmorParserNotExecutable(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-boundaries")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	// Parser with mode 0644 (not executable)
	if err := os.WriteFile(parserPath, []byte("fake"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a valid fragment before the operation
	validFragment := renderFragment([]string{"/existing"})
	if err := os.MkdirAll(filepath.Dir(fragment), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fragment, validFragment, 0644); err != nil {
		t.Fatal(err)
	}

	// Save original fragment state
	origData, err := os.ReadFile(fragment)
	if err != nil {
		t.Fatal(err)
	}
	origInfo, err := os.Stat(fragment)
	if err != nil {
		t.Fatal(err)
	}
	origMode := origInfo.Mode().Perm()

	runnerCalled := false
	fakeRunner := func(exe string, args []string) error {
		runnerCalled = true
		return nil
	}

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath, fakeRunner)

	_, err = mgr.addManagedBoundary(testDir)
	if err == nil {
		t.Fatal("expected error for non-executable parser")
	}
	if !strings.Contains(err.Error(), "not executable") {
		t.Errorf("expected not executable error, got: %v", err)
	}
	if runnerCalled {
		t.Error("runner should not be called when parser is not executable")
	}

	// Fragment should be unchanged
	afterData, err := os.ReadFile(fragment)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterData, origData) {
		t.Error("fragment bytes should not be modified")
	}

	afterInfo, err := os.Stat(fragment)
	if err != nil {
		t.Fatal(err)
	}
	if afterInfo.Mode().Perm() != origMode {
		t.Errorf("fragment mode should not be modified: expected %o, got %o", origMode, afterInfo.Mode().Perm())
	}
}

// --- Symlink fragment rejected in add and remove ---

func TestAppArmorSymlinkFragmentRejected(t *testing.T) {
	tests := []struct {
		name string
		op   func(mgr *appArmorProfileManager, testDir string) error
	}{
		{"add", func(mgr *appArmorProfileManager, testDir string) error {
			_, err := mgr.addManagedBoundary(testDir)
			return err
		}},
		{"remove", func(mgr *appArmorProfileManager, testDir string) error {
			_, err := mgr.removeManagedBoundary(testDir)
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			testDir := filepath.Join(testAllowedRootDir(t), "workspace")
			if err := os.MkdirAll(testDir, 0755); err != nil {
				t.Fatal(err)
			}

			mainProfile := filepath.Join(dir, "main")
			realFragment := filepath.Join(dir, "real-fragment")
			linkFragment := filepath.Join(dir, "docker-helper.d", "managed-boundaries")
			lockPath := filepath.Join(dir, "lock")
			parserPath := filepath.Join(dir, "apparmor_parser")

			if err := os.MkdirAll(filepath.Dir(linkFragment), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
				t.Fatal(err)
			}
			targetData := renderFragment(nil)
			if err := os.WriteFile(realFragment, targetData, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(realFragment, linkFragment); err != nil {
				t.Fatal(err)
			}

			runnerCalled := false
			mgr := newAppArmorProfileManager(mainProfile, linkFragment, lockPath, parserPath,
				func(exe string, args []string) error {
					runnerCalled = true
					return nil
				},
			)

			err := tc.op(mgr, testDir)
			if err == nil {
				t.Fatal("expected error for symlink fragment")
			}
			if !strings.Contains(err.Error(), "symlink") {
				t.Errorf("expected symlink error, got: %v", err)
			}
			if runnerCalled {
				t.Error("runner should not be called when fragment is a symlink")
			}

			// Symlink should still be a symlink
			info, err := os.Lstat(linkFragment)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&os.ModeSymlink == 0 {
				t.Error("symlink should still be a symlink")
			}

			// Target should be unchanged
			afterData, err := os.ReadFile(realFragment)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(afterData, targetData) {
				t.Error("target bytes should not be modified")
			}
		})
	}
}

// --- Non-regular fragment rejected (directory) ---

func TestAppArmorNonRegularFragmentDirectory(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-boundaries")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.MkdirAll(filepath.Dir(fragment), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Create fragment as a directory instead of a file
	if err := os.MkdirAll(fragment, 0755); err != nil {
		t.Fatal(err)
	}

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return nil },
	)

	_, err := mgr.addManagedBoundary(testDir)
	if err == nil {
		t.Fatal("expected error for directory fragment")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("expected not a regular file error, got: %v", err)
	}
}

// --- Parser unavailable preflight ---

func TestAppArmorParserUnavailableNoChanges(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-boundaries")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "nonexistent_parser")

	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return nil },
	)

	_, err := mgr.addManagedBoundary(testDir)
	if err == nil {
		t.Fatal("expected error for missing parser")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got: %v", err)
	}

	if _, err := os.Stat(fragment); !os.IsNotExist(err) {
		t.Error("fragment should not be created when parser is unavailable")
	}
}

// --- Main profile missing preflight ---

func TestAppArmorMainProfileMissingNoChanges(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "nonexistent_profile")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-boundaries")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return nil },
	)

	_, err := mgr.addManagedBoundary(testDir)
	if err == nil {
		t.Fatal("expected error for missing main profile")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got: %v", err)
	}

	if _, err := os.Stat(fragment); !os.IsNotExist(err) {
		t.Error("fragment should not be created when main profile is missing")
	}
}

// --- Check command behavior ---

func TestAppArmorCheckParserNotAvailable(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "fragment")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "nonexistent")

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return nil },
	)

	err := mgr.check()
	if err == nil {
		t.Fatal("expected error when parser not available")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got: %v", err)
	}
}

func TestAppArmorCheckMainProfileNotFound(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "nonexistent")
	fragment := filepath.Join(dir, "fragment")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return nil },
	)

	err := mgr.check()
	if err == nil {
		t.Fatal("expected error when main profile not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got: %v", err)
	}
}

func TestAppArmorCheckValidationFailure(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-boundaries")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.MkdirAll(filepath.Dir(fragment), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fragment, renderFragment(nil), 0644); err != nil {
		t.Fatal(err)
	}

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return errors.New("validation failed") },
	)

	err := mgr.check()
	if err == nil {
		t.Fatal("expected error when validation fails")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("expected validation failed error, got: %v", err)
	}
}

func TestAppArmorCheckSuccess(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-boundaries")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.MkdirAll(filepath.Dir(fragment), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fragment, renderFragment(nil), 0644); err != nil {
		t.Fatal(err)
	}

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return nil },
	)

	if err := mgr.check(); err != nil {
		t.Fatalf("check failed: %v", err)
	}
}

// --- Remove does not infer parent/child ---

func TestAppArmorRemoveNoInference(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	parentDir := filepath.Join(rootDir, "parent")
	childDir := filepath.Join(parentDir, "child")
	for _, d := range []string{parentDir, childDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	_, mgr, _ := setupAppArmorTest(t)

	if _, err := mgr.addManagedBoundary(parentDir); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.addManagedBoundary(childDir); err != nil {
		t.Fatal(err)
	}

	if _, err := mgr.removeManagedBoundary(childDir); err != nil {
		t.Fatalf("removeBoundary failed: %v", err)
	}

	boundaries, err := mgr.listManagedBoundaries()
	if err != nil {
		t.Fatalf("listBoundaries failed: %v", err)
	}
	if len(boundaries) != 1 || boundaries[0] != parentDir {
		t.Errorf("expected only parent %s, got %v", parentDir, boundaries)
	}
}

// --- Fragment parse round-trip ---

func TestFragmentRoundTrip(t *testing.T) {
	boundaries := []string{"/a", "/b", "/c"}
	data := renderFragment(boundaries)

	parsed, err := parseFragment(data)
	if err != nil {
		t.Fatalf("parseFragment failed: %v", err)
	}
	if !reflectSliceEqual(parsed, boundaries) {
		t.Errorf("expected %v, got %v", boundaries, parsed)
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

func TestFragmentRoundTripSpecialChars(t *testing.T) {
	boundaries := []string{"/with space", `/with"quote`, "/with\\backslash", "/with#hash", "/with,comma"}
	data := renderFragment(boundaries)

	parsed, err := parseFragment(data)
	if err != nil {
		t.Fatalf("parseFragment failed: %v", err)
	}

	expected := []string{"/with space", `/with"quote`, "/with#hash", "/with,comma", "/with\\backslash"}
	if !reflectSliceEqual(parsed, expected) {
		t.Errorf("expected %v, got %v", expected, parsed)
	}
}

// --- CLI exit codes ---

func TestAppArmorCLIExitCodes(t *testing.T) {
	mockAppArmorActive(t, true)
	saved := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = saved }()

	tests := []struct {
		name string
		args []string
	}{
		{name: "root add relative path", args: []string{"apparmor", "root", "add", "not-absolute"}},
		{name: "root remove relative path", args: []string{"apparmor", "root", "remove", "not-absolute"}},
		{name: "root add missing arg", args: []string{"apparmor", "root", "add"}},
		{name: "root remove missing arg", args: []string{"apparmor", "root", "remove"}},
		{name: "root missing subcommand", args: []string{"apparmor", "root"}},
		{name: "missing subcommand", args: []string{"apparmor"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tc.args, &stdout, &stderr)
			if code != 2 {
				t.Errorf("expected exit 2, got %d (stderr: %s)", code, stderr.String())
			}
		})
	}
}

// --- renderFragment format ---

func TestRenderFragmentFormat(t *testing.T) {
	boundaries := []string{"/workspace"}
	data := renderFragment(boundaries)
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
	if lines[3] != `# root-json: "/workspace"` {
		t.Errorf("expected boundary metadata, got: %s", lines[3])
	}
	if lines[4] != `"/workspace/" r,` {
		t.Errorf("expected dir rule, got: %s", lines[4])
	}
	if lines[5] != `"/workspace/**" r,` {
		t.Errorf("expected glob rule, got: %s", lines[5])
	}
}

func TestRenderFragmentMultipleBoundaries(t *testing.T) {
	boundaries := []string{"/a", "/b"}
	data := renderFragment(boundaries)
	content := string(data)

	if !strings.Contains(content, `# root-json: "/a"`) {
		t.Error("missing boundary /a")
	}
	if !strings.Contains(content, `# root-json: "/b"`) {
		t.Error("missing boundary /b")
	}
	if !strings.Contains(content, `"/a/" r,`) {
		t.Error("missing rule for /a")
	}
	if !strings.Contains(content, `"/b/" r,`) {
		t.Error("missing rule for /b")
	}
}

// --- validateBoundaryPathForRemove ---

func TestValidateBoundaryPathForRemoveNonExistent(t *testing.T) {
	canonical, err := validateBoundaryPathForRemove("/nonexistent/path")
	if err != nil {
		t.Fatalf("expected success for non-existent path in remove, got: %v", err)
	}
	if canonical != "/nonexistent/path" {
		t.Errorf("expected /nonexistent/path, got %s", canonical)
	}
}

func TestValidateBoundaryPathForRemoveFilesystemRoot(t *testing.T) {
	_, err := validateBoundaryPathForRemove("/")
	if err == nil {
		t.Fatal("expected error for /")
	}
}

// --- Rollback restores exact mode ---

func TestAppArmorRollbackRestoresMode(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	testDirA := filepath.Join(rootDir, "a")
	testDirB := filepath.Join(rootDir, "b")
	for _, d := range []string{testDirA, testDirB} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	callCount := 0
	fakeRunner := func(exe string, args []string) error {
		callCount++
		if callCount == 1 {
			return nil
		}
		return errors.New("parser failed")
	}

	_, mgr := setupAppArmorTestWithRunner(t, fakeRunner)

	if _, err := mgr.addManagedBoundary(testDirA); err != nil {
		t.Fatalf("first addBoundary failed: %v", err)
	}

	prevInfo, err := os.Stat(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("cannot stat fragment: %v", err)
	}
	prevMode := prevInfo.Mode().Perm()

	_, err = mgr.addManagedBoundary(testDirB)
	if err == nil {
		t.Fatal("expected error for second addBoundary")
	}

	afterInfo, err := os.Stat(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("cannot stat fragment after rollback: %v", err)
	}
	afterMode := afterInfo.Mode().Perm()

	if prevMode != afterMode {
		t.Errorf("expected mode %o after rollback, got %o", prevMode, afterMode)
	}
}

// --- Rollback when fragment previously absent ---

func TestAppArmorRollbackRestoresNoFragment(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-boundaries")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	callCount := 0
	fakeRunner := func(exe string, args []string) error {
		callCount++
		return errors.New("parser always fails")
	}

	mgr := newAppArmorProfileManager(mainProfile, fragment, lockPath, parserPath, fakeRunner)

	_, err := mgr.addManagedBoundary(testDir)
	if err == nil {
		t.Fatal("expected error for addBoundary")
	}

	if _, err := os.Stat(fragment); !os.IsNotExist(err) {
		t.Error("fragment should not exist after rollback to absent state")
	}
}

// --- Lexical validation table-driven tests ---

func TestValidateBoundaryLexical(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid normal", "/workspace", false},
		{"valid with space", "/with space", false},
		{"valid with quote", `/with"quote`, false},
		{"valid with backslash", "/with\\backslash", false},
		{"valid with hash", "/with#hash", false},
		{"valid with comma", "/with,comma", false},
		{"relative", "workspace", true},
		{"root", "/", true},
		{"non-clean", "/a//b", true},
		{"trailing slash", "/workspace/", true},
		{"glob asterisk", "/workspace*", true},
		{"glob question", "/workspace?", true},
		{"glob bracket", "/workspace[1]", true},
		{"glob brace", "/workspace{1}", true},
		{"tab", "/with\ttab", true},
		{"newline", "/with\nnewline", true},
		{"CR", "/with\rCR", true},
		{"DEL", "/with\x7fDEL", true},
		{"control", "/with\x01control", true},
		{"unicode control NEL", "/with\u0085control", true},
		{"unicode control", "/with\u009fcontrol", true},
		{"invalid UTF-8", string([]byte{0xff, 0xfe}), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBoundaryLexical(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.path)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %q: %v", tc.path, err)
				}
			}
		})
	}
}

// --- Fragment with invalid boundaries rejected by parseFragment ---

func TestParseFragmentRejectsInvalidBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		boundary string
	}{
		{"relative", "relative"},
		{"root dir", "/"},
		{"non-clean", "/a//b"},
		{"glob", "/workspace*"},
		{"tab", "/with\ttab"},
		{"DEL", "/with\x7fDEL"},
		{"unicode control", "/with\u0085control"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Use renderFragment to create a properly formatted fragment
			data := renderFragment([]string{tc.boundary})
			_, err := parseFragment(data)
			if err == nil {
				t.Fatalf("expected error for invalid boundary %q, got nil", tc.boundary)
			}
		})
	}
}

// --- Stat error in remove ---

func TestValidateBoundaryPathForRemoveStatError(t *testing.T) {
	// Test with a symlink loop to get ELOOP error
	dir := t.TempDir()
	linkPath := filepath.Join(dir, "loop")
	if err := os.Symlink(linkPath, linkPath); err != nil {
		t.Fatal(err)
	}

	_, err := validateBoundaryPathForRemove(linkPath)
	if err == nil {
		t.Fatal("expected error for symlink loop")
	}

	// Check that it's not an inputError (it's a stat error)
	var ie *inputError
	if errors.As(err, &ie) {
		t.Error("symlink loop error should not be an inputError")
	}

	// Check that it wraps or contains ELOOP
	if !strings.Contains(err.Error(), "too many levels of symbolic links") {
		t.Errorf("expected ELOOP error, got: %v", err)
	}
}

// --- Existing non-directory path as lexical stale boundary ---

func TestValidateBoundaryPathForRemoveNonDirectory(t *testing.T) {
	dir := t.TempDir()
	tmpfile := filepath.Join(dir, "notadir")
	if err := os.WriteFile(tmpfile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	canonical, err := validateBoundaryPathForRemove(tmpfile)
	if err != nil {
		t.Fatalf("expected success for existing non-directory, got: %v", err)
	}
	if canonical != tmpfile {
		t.Errorf("expected %s, got %s", tmpfile, canonical)
	}
}

// --- Stale unsafe boundaries: parser tolerance and REMOVE semantics ---

// TestAppArmorStaleUnsafeBoundaryPreservedSemantics verifies that a managed
// fragment containing a managed boundary that violates the current workspace-path
// policy (e.g., a pre-policy /var/... boundary) is still parsed, can still be
// removed (stale REMOVE semantics), and is diagnosed by check.
func TestAppArmorStaleUnsafeBoundaryPreservedSemantics(t *testing.T) {
	_, mgr, _ := setupAppArmorTest(t)

	staleUnsafe := "/var/lib/legacy-workspaces"
	fragmentPath := mgr.managedFragmentPath
	if err := os.MkdirAll(filepath.Dir(fragmentPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fragmentPath, renderFragment([]string{staleUnsafe}), 0644); err != nil {
		t.Fatal(err)
	}

	// 1) Parser must tolerate the stale unsafe boundary.
	boundaries, err := mgr.listManagedBoundaries()
	if err != nil {
		t.Fatalf("listBoundaries() error: %v", err)
	}
	if len(boundaries) != 1 || boundaries[0] != staleUnsafe {
		t.Fatalf("listBoundaries() = %v, want [%s]", boundaries, staleUnsafe)
	}

	// 2) Stale REMOVE semantics: the unsafe boundary must still be removable.
	res, err := mgr.removeManagedBoundary(staleUnsafe)
	if err != nil {
		t.Fatalf("removeBoundary() error: %v", err)
	}
	if !res.Changed {
		t.Error("removeBoundary should report Changed=true")
	}
	boundaries, err = mgr.listManagedBoundaries()
	if err != nil {
		t.Fatalf("listBoundaries() after remove: %v", err)
	}
	if len(boundaries) != 0 {
		t.Errorf("listBoundaries() after remove = %v, want empty", boundaries)
	}

	// 3) check() must diagnose the policy violation (not crash or reject parse).
	if err := os.WriteFile(fragmentPath, renderFragment([]string{staleUnsafe}), 0644); err != nil {
		t.Fatal(err)
	}
	err = mgr.check()
	if err == nil {
		t.Error("check() should diagnose policy-violating managed boundary")
	} else if !strings.Contains(err.Error(), "workspace root policy") {
		t.Errorf("check() error = %q, want workspace-path policy diagnostic", err.Error())
	}
}

// --- Shipped profile regression tests ---

func TestSystemProfileContainsDockerBuildx(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Skipf("system profile not found: %v", err)
	}
	content := string(data)

	// Binary rules must use rix (read + inherit + execute) for plugin discovery.
	buildxBinaries := []string{
		"/usr/local/lib/docker/cli-plugins/docker-buildx rix,",
		"/usr/local/libexec/docker/cli-plugins/docker-buildx rix,",
		"/usr/lib/docker/cli-plugins/docker-buildx rix,",
		"/usr/libexec/docker/cli-plugins/docker-buildx rix,",
	}
	for _, p := range buildxBinaries {
		if !strings.Contains(content, p) {
			t.Errorf("system profile missing buildx binary rule: %s", p)
		}
	}

	// Directory read rules are required for Docker CLI plugin discovery.
	buildxDirs := []string{
		"/usr/local/lib/docker/cli-plugins/ r,",
		"/usr/local/libexec/docker/cli-plugins/ r,",
		"/usr/lib/docker/cli-plugins/ r,",
		"/usr/libexec/docker/cli-plugins/ r,",
	}
	for _, p := range buildxDirs {
		if !strings.Contains(content, p) {
			t.Errorf("system profile missing buildx directory rule: %s", p)
		}
	}

	// Must NOT contain broad cli-plugins wildcard.
	if strings.Contains(content, "cli-plugins/**") {
		t.Error("system profile must not grant broad cli-plugins/** execute")
	}
}

func TestSystemProfileDockerInheritedConfinement(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Skipf("system profile not found: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "/usr/bin/docker rix,") {
		t.Error("system profile must permit /usr/bin/docker with inherited confinement")
	}
}

func TestSystemProfileSocketLockFileLocking(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Skipf("system profile not found: %v", err)
	}
	content := string(data)

	// The socket lock file must have the k (file locking) permission.
	if !strings.Contains(content, "/run/docker-helper/docker-helper.sock.lock rwk,") {
		t.Error("system profile must grant rwk on /run/docker-helper/docker-helper.sock.lock for flock-based single-instance locking")
	}

	// The broad /run/docker-helper/** rule must NOT include k (file locking).
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "/run/docker-helper/**") {
			// Check the permission flags (last token before comma) for 'k'.
			perm := trimmed[strings.LastIndex(trimmed, " ")+1:]
			if strings.Contains(perm, "k") {
				t.Errorf("system profile must not grant k on /run/docker-helper/** (found: %s)", trimmed)
			}
		}
	}
}

func TestSystemProfileAppArmorLifecycleLockFileLocking(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Skipf("system profile not found: %v", err)
	}
	content := string(data)

	// The AppArmor lifecycle lock file must grant rwk: read is required by
	// os.OpenFile(..., O_RDWR, ...) and k (file locking) by syscall.Flock.
	if !strings.Contains(content, "/run/lock/docker-helper-apparmor.lock rwk,") {
		t.Error("system profile must grant rwk on /run/lock/docker-helper-apparmor.lock for the AppArmor lifecycle lock")
	}

	// It must not regress to a permission lacking read (O_RDWR) or lock (flock).
	for _, bad := range []string{
		"/run/lock/docker-helper-apparmor.lock w,",
		"/run/lock/docker-helper-apparmor.lock rw,",
	} {
		if strings.Contains(content, bad) {
			t.Errorf("system profile must not use %q for the AppArmor lifecycle lock", bad)
		}
	}
}

func TestSystemProfileIncludesManagedBoundaries(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Skipf("system profile not found: %v", err)
	}
	content := string(data)

	// Must include the dynamic managed boundaries state via if-exists.
	if !strings.Contains(content, `#include if exists "/var/lib/docker-helper/apparmor/managed-boundaries"`) {
		t.Error("system profile must include managed boundaries state via if-exists")
	}

	// Must NOT include the legacy managed-roots fragment path.
	if strings.Contains(content, "docker-helper.d/managed-roots") {
		t.Error("system profile must not reference legacy managed-roots fragment")
	}
}

func TestSystemProfileAppArmorStateSubtreePermissions(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Skipf("system profile not found: %v", err)
	}
	content := string(data)

	// Must grant rw on the dedicated AppArmor state subtree.
	if !strings.Contains(content, "/var/lib/docker-helper/apparmor/ rw,") {
		t.Error("system profile must grant rw on /var/lib/docker-helper/apparmor/ directory")
	}
	if !strings.Contains(content, "/var/lib/docker-helper/apparmor/* rw,") {
		t.Error("system profile must grant rw on /var/lib/docker-helper/apparmor/* files")
	}

	// Must NOT grant generic write access to /etc/apparmor.d/**.
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "/etc/apparmor.d/**") {
			perm := trimmed[strings.LastIndex(trimmed, " ")+1:]
			if strings.Contains(perm, "w") {
				t.Errorf("system profile must not grant write on /etc/apparmor.d/** (found: %s)", trimmed)
			}
		}
	}
}

func TestProductionAppArmorStatePath(t *testing.T) {
	if appArmorManagedBoundariesPath != "/var/lib/docker-helper/apparmor/managed-boundaries" {
		t.Errorf("appArmorManagedBoundariesPath = %q, want /var/lib/docker-helper/apparmor/managed-boundaries", appArmorManagedBoundariesPath)
	}

	mgr := newProductionAppArmorProfileManager()
	if mgr.managedFragmentPath != "/var/lib/docker-helper/apparmor/managed-boundaries" {
		t.Errorf("production manager path = %q, want /var/lib/docker-helper/apparmor/managed-boundaries", mgr.managedFragmentPath)
	}
}

func TestParseFragmentLegacyHeader(t *testing.T) {
	legacy := renderFragment([]string{"/a", "/b"})
	legacy = bytes.Replace(legacy, []byte(fragmentHeader2+"\n"), []byte(legacyFragmentHeader2+"\n"), 1)

	parsed, err := parseFragment(legacy)
	if err != nil {
		t.Fatalf("parseFragment legacy header failed: %v", err)
	}
	if !reflectSliceEqual(parsed, []string{"/a", "/b"}) {
		t.Errorf("parsed = %v, want [/a /b]", parsed)
	}
}

func TestRewriteNormalizesLegacyHeader(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	testDir := filepath.Join(rootDir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupAppArmorTest(t)

	// Write legacy header content
	legacy := renderFragment([]string{})
	legacy = bytes.Replace(legacy, []byte(fragmentHeader2+"\n"), []byte(legacyFragmentHeader2+"\n"), 1)
	if err := os.MkdirAll(filepath.Dir(mgr.managedFragmentPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mgr.managedFragmentPath, legacy, 0644); err != nil {
		t.Fatal(err)
	}

	// Add a boundary — this rewrites the file with the new header.
	_, err := mgr.addManagedBoundary(testDir)
	if err != nil {
		t.Fatalf("addManagedBoundary failed: %v", err)
	}

	data, err := os.ReadFile(mgr.managedFragmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(fragmentHeader2)) {
		t.Error("rewrite should normalize to boundary header")
	}
	if bytes.Contains(data, []byte(legacyFragmentHeader2)) {
		t.Error("rewrite should not retain legacy header")
	}
}

func TestRenderFragmentBoundaryTerminology(t *testing.T) {
	data := renderFragment([]string{"/workspace"})
	content := string(data)
	if !strings.Contains(content, "workspace boundaries") {
		t.Error("renderFragment should use 'workspace boundaries' terminology")
	}
	if strings.Contains(content, "workspace roots") {
		t.Error("renderFragment should not use 'workspace roots' terminology")
	}
}

func TestUserProfileContainsDockerBuildx(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper")
	if err != nil {
		t.Skipf("user profile not found: %v", err)
	}
	content := string(data)

	// Binary rules must use rix (read + inherit + execute) for plugin discovery.
	buildxBinaries := []string{
		"/usr/local/lib/docker/cli-plugins/docker-buildx rix,",
		"/usr/local/libexec/docker/cli-plugins/docker-buildx rix,",
		"/usr/lib/docker/cli-plugins/docker-buildx rix,",
		"/usr/libexec/docker/cli-plugins/docker-buildx rix,",
	}
	for _, p := range buildxBinaries {
		if !strings.Contains(content, p) {
			t.Errorf("user profile missing buildx binary rule: %s", p)
		}
	}

	// Directory read rules are required for Docker CLI plugin discovery.
	buildxDirs := []string{
		"/usr/local/lib/docker/cli-plugins/ r,",
		"/usr/local/libexec/docker/cli-plugins/ r,",
		"/usr/lib/docker/cli-plugins/ r,",
		"/usr/libexec/docker/cli-plugins/ r,",
	}
	for _, p := range buildxDirs {
		if !strings.Contains(content, p) {
			t.Errorf("user profile missing buildx directory rule: %s", p)
		}
	}

	// Must NOT contain broad cli-plugins wildcard.
	if strings.Contains(content, "cli-plugins/**") {
		t.Error("user profile must not grant broad cli-plugins/** execute")
	}
}

func TestAppArmorUserProfileParserValidation(t *testing.T) {
	if _, err := exec.LookPath("apparmor_parser"); err != nil {
		t.Skip("apparmor_parser not available")
	}

	data, err := os.ReadFile("packaging/apparmor/docker-helper")
	if err != nil {
		t.Fatalf("cannot read user profile template: %v", err)
	}

	// Render the template: replace placeholders with valid values.
	content := strings.ReplaceAll(string(data), "@@BINARY_PATH@@", "/usr/bin/docker-helper-test")
	content = strings.ReplaceAll(content, "# @@WORKSPACE_RULE@@", "")

	if strings.Contains(content, "@@BINARY_PATH@@") {
		t.Fatal("rendered profile still contains @@BINARY_PATH@@")
	}
	if strings.Contains(content, "# @@WORKSPACE_RULE@@") {
		t.Fatal("rendered profile still contains # @@WORKSPACE_RULE@@")
	}

	dir := t.TempDir()
	profilePath := filepath.Join(dir, "docker-helper")
	if err := os.WriteFile(profilePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("apparmor_parser", "--skip-kernel-load", "--skip-read-cache", profilePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("user profile parser validation failed: %v\n%s", err, out)
	}
}

func TestBuildxDirectoryRulesHaveRead(t *testing.T) {
	profiles := map[string]string{
		"system": "packaging/apparmor/docker-helper-system",
		"user":   "packaging/apparmor/docker-helper",
	}

	for name, path := range profiles {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("profile not found: %v", err)
			}
			content := string(data)

			dirs := []string{
				"/usr/local/lib/docker/cli-plugins/",
				"/usr/local/libexec/docker/cli-plugins/",
				"/usr/lib/docker/cli-plugins/",
				"/usr/libexec/docker/cli-plugins/",
			}
			for _, dir := range dirs {
				rule := dir + " r,"
				if !strings.Contains(content, rule) {
					t.Errorf("profile missing directory read rule: %s", rule)
				}
			}
		})
	}
}

func TestBuildxBinaryRulesHaveRix(t *testing.T) {
	profiles := map[string]string{
		"system": "packaging/apparmor/docker-helper-system",
		"user":   "packaging/apparmor/docker-helper",
	}

	for name, path := range profiles {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("profile not found: %v", err)
			}
			content := string(data)

			binaries := []string{
				"/usr/local/lib/docker/cli-plugins/docker-buildx",
				"/usr/local/libexec/docker/cli-plugins/docker-buildx",
				"/usr/lib/docker/cli-plugins/docker-buildx",
				"/usr/libexec/docker/cli-plugins/docker-buildx",
			}
			for _, bin := range binaries {
				rule := bin + " rix,"
				if !strings.Contains(content, rule) {
					t.Errorf("profile missing binary rix rule: %s", rule)
				}

				// Must not have bare ix (missing read permission needed for discovery).
				badRule := bin + " ix,"
				if strings.Contains(content, badRule) {
					t.Errorf("profile has bare ix instead of rix: %s", badRule)
				}
			}
		})
	}
}

func TestBuildxNoBroadWildcard(t *testing.T) {
	profiles := map[string]string{
		"system": "packaging/apparmor/docker-helper-system",
		"user":   "packaging/apparmor/docker-helper",
	}

	for name, path := range profiles {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("profile not found: %v", err)
			}
			content := string(data)

			// Must not grant broad cli-plugins wildcard execute.
			if strings.Contains(content, "cli-plugins/**") {
				t.Error("profile must not grant broad cli-plugins/** execute")
			}

			// Must not grant broad /usr/libexec wildcard execute.
			for _, bad := range []string{
				"/usr/libexec/** ix",
				"/usr/libexec/**rix",
				"/usr/libexec/** rix",
			} {
				if strings.Contains(content, bad) {
					t.Errorf("profile must not grant broad libexec wildcard: %s", bad)
				}
			}

			// Must not grant arbitrary plugin execute (only docker-buildx).
			for _, bad := range []string{
				"cli-plugins/* ix",
				"cli-plugins/* rix",
			} {
				if strings.Contains(content, bad) {
					t.Errorf("profile must not grant arbitrary plugin execute: %s", bad)
				}
			}
		})
	}
}
