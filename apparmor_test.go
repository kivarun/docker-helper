package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func setupApparmorTest(t *testing.T) (dir string, mgr *apparmorManager, captured *struct {
	exe  string
	args []string
}) {
	t.Helper()
	dir = t.TempDir()

	mainProfile := filepath.Join(dir, "docker-helper-system")
	managedFragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
	lockPath := filepath.Join(dir, "apparmor.lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	captured = &struct {
		exe  string
		args []string
	}{}
	fakeRunner := func(exe string, args []string) error {
		captured.exe = exe
		captured.args = args
		return nil
	}

	mgr = newApparmorManager(
		mainProfile,
		managedFragment,
		lockPath,
		parserPath,
		fakeRunner,
	)

	return dir, mgr, captured
}

func setupApparmorTestWithRunner(t *testing.T, runner func(exe string, args []string) error) (dir string, mgr *apparmorManager) {
	t.Helper()
	dir = t.TempDir()

	mainProfile := filepath.Join(dir, "docker-helper-system")
	managedFragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
	lockPath := filepath.Join(dir, "apparmor.lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mgr = newApparmorManager(
		mainProfile,
		managedFragment,
		lockPath,
		parserPath,
		runner,
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
	rootDir := testAllowedRootDir(t)
	realDir := filepath.Join(rootDir, "real")
	linkDir := filepath.Join(rootDir, "link")
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
	if result.Path != realDir {
		t.Errorf("expected canonical result %s, got %s", realDir, result.Path)
	}
	if !result.Changed {
		t.Error("expected Changed=true")
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
	_, mgr, _ := setupApparmorTest(t)

	_, err := mgr.addRoot("/")
	if err == nil {
		t.Fatal("expected error for /")
	}
	if !strings.Contains(err.Error(), "filesystem root") {
		t.Errorf("expected filesystem root error, got: %v", err)
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
	aIdx := strings.Index(content, `# root-json: "/a/workspace"`)
	mIdx := strings.Index(content, `# root-json: "/m/workspace"`)
	zIdx := strings.Index(content, `# root-json: "/z/workspace"`)

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
	if strings.Contains(content, "# root-json:") {
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
		{"/path/with\"quote", "/path/with\\\"quote"},
		{"/path/with\\\\double", "/path/with\\\\\\\\double"},
	}

	for _, tc := range tests {
		if got := escapeAppArmorPath(tc.input); got != tc.output {
			t.Errorf("escapeAppArmorPath(%q) = %q, want %q", tc.input, got, tc.output)
		}
	}
}

// --- JSON quoting ---

func TestJSONQuoteRoundTrip(t *testing.T) {
	tests := []string{
		"/normal",
		"/with space",
		`/with"quote`,
		"/with\\backslash",
		"/with#hash",
		"/with,comma",
	}
	for _, s := range tests {
		quoted := jsonQuote(s)
		unquoted, err := jsonUnquote(quoted)
		if err != nil {
			t.Fatalf("jsonUnquote(%q) failed: %v", quoted, err)
		}
		if unquoted != s {
			t.Errorf("round trip: %q -> %q -> %q", s, quoted, unquoted)
		}
	}
}

// --- Special characters in paths ---

func TestRootWithPathWithSpace(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	path := filepath.Join(rootDir, "with space")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	result, err := mgr.addRoot(path)
	if err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}
	if result.Path != path {
		t.Errorf("expected %s, got %s", path, result.Path)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 1 || roots[0] != path {
		t.Errorf("expected root %s, got %v", path, roots)
	}
}

func TestRootWithPathWithQuote(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	path := filepath.Join(rootDir, `with"quote`)
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	result, err := mgr.addRoot(path)
	if err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}
	if result.Path != path {
		t.Errorf("expected %s, got %s", path, result.Path)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 1 || roots[0] != path {
		t.Errorf("expected root %s, got %v", path, roots)
	}
}

func TestRootWithPathWithHash(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	path := filepath.Join(rootDir, "with#hash")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	result, err := mgr.addRoot(path)
	if err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}
	if result.Path != path {
		t.Errorf("expected %s, got %s", path, result.Path)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 1 || roots[0] != path {
		t.Errorf("expected root %s, got %v", path, roots)
	}
}

func TestRootWithPathWithComma(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	path := filepath.Join(rootDir, "with,comma")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	result, err := mgr.addRoot(path)
	if err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}
	if result.Path != path {
		t.Errorf("expected %s, got %s", path, result.Path)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 1 || roots[0] != path {
		t.Errorf("expected root %s, got %v", path, roots)
	}
}

func TestRootWithPathWithBackslash(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	path := filepath.Join(rootDir, "with\\backslash")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	result, err := mgr.addRoot(path)
	if err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}
	if result.Path != path {
		t.Errorf("expected %s, got %s", path, result.Path)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 1 || roots[0] != path {
		t.Errorf("expected root %s, got %v", path, roots)
	}
}

func TestRootWithControlCharacter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "with\x01control")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)
	_, err := mgr.addRoot(path)
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

func TestRenderFragmentRuleText(t *testing.T) {
	roots := []string{"/workspace"}
	data := renderFragment(roots)
	content := string(data)

	if !strings.Contains(content, `"/workspace/" r,`) {
		t.Errorf("expected quoted dir rule, got:\n%s", content)
	}
	if !strings.Contains(content, `"/workspace/**" r,`) {
		t.Errorf("expected quoted glob rule, got:\n%s", content)
	}
}

func TestRenderFragmentRuleEscaping(t *testing.T) {
	roots := []string{`/path\with"special`}
	data := renderFragment(roots)
	content := string(data)

	if !strings.Contains(content, `"/path\\with\"special/" r,`) {
		t.Errorf("expected escaped rule, got:\n%s", content)
	}
}

// --- Duplicate add ---

func TestApparmorDuplicateAdd(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	testDir := filepath.Join(rootDir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	result1, err := mgr.addRoot(testDir)
	if err != nil {
		t.Fatalf("first addRoot failed: %v", err)
	}
	if !result1.Changed {
		t.Error("first add expected Changed=true")
	}
	if result1.Path != testDir {
		t.Errorf("first add expected path %s, got %s", testDir, result1.Path)
	}

	result2, err := mgr.addRoot(testDir)
	if err != nil {
		t.Fatalf("second addRoot failed: %v", err)
	}
	if result2.Changed {
		t.Error("second add expected Changed=false")
	}
	if result2.Path != testDir {
		t.Errorf("second add expected path %s, got %s", testDir, result2.Path)
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
	if result.Changed {
		t.Error("expected Changed=false for absent root")
	}
	if result.Path != testDir {
		t.Errorf("expected path %s, got %s", testDir, result.Path)
	}
}

// --- Remove after directory deletion ---

func TestApparmorRemoveAfterDeletion(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	testDir := filepath.Join(rootDir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	if _, err := mgr.addRoot(testDir); err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}

	if err := os.RemoveAll(testDir); err != nil {
		t.Fatalf("RemoveAll failed: %v", err)
	}

	result, err := mgr.removeRoot(testDir)
	if err != nil {
		t.Fatalf("removeRoot failed after deletion: %v", err)
	}
	if !result.Changed {
		t.Error("expected Changed=true")
	}
	if result.Path != testDir {
		t.Errorf("expected %s, got %s", testDir, result.Path)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 0 {
		t.Errorf("expected empty list after remove, got %v", roots)
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

// --- Exact parser executable and arguments ---

func TestApparmorReloadParserExecutable(t *testing.T) {
	dir := t.TempDir()
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

	captured := &struct {
		exe  string
		args []string
	}{}
	fakeRunner := func(exe string, args []string) error {
		captured.exe = exe
		captured.args = args
		return nil
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath, fakeRunner)

	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, err := mgr.addRoot(testDir)
	if err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}

	if captured.exe != parserPath {
		t.Errorf("expected parser exe %s, got %s", parserPath, captured.exe)
	}
	if len(captured.args) != 3 || captured.args[0] != "--replace" || captured.args[1] != "--skip-read-cache" || captured.args[2] != mainProfile {
		t.Errorf("expected parser args [--replace --skip-read-cache %s], got %v", mainProfile, captured.args)
	}
}

func TestApparmorValidateParserExecutable(t *testing.T) {
	dir := t.TempDir()
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

	captured := &struct {
		exe  string
		args []string
	}{}
	fakeRunner := func(exe string, args []string) error {
		captured.exe = exe
		captured.args = args
		return nil
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath, fakeRunner)

	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := mgr.check(); err != nil {
		t.Fatalf("check failed: %v", err)
	}

	if captured.exe != parserPath {
		t.Errorf("expected parser exe %s, got %s", parserPath, captured.exe)
	}
	if len(captured.args) != 3 || captured.args[0] != "--skip-kernel-load" || captured.args[1] != "--skip-read-cache" || captured.args[2] != mainProfile {
		t.Errorf("expected parser args [--skip-kernel-load --skip-read-cache %s], got %v", mainProfile, captured.args)
	}
}

func TestApparmorNoShellInvocation(t *testing.T) {
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

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath, fakeRunner)

	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
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

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath, fakeRunner)

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

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath, func(exe string, args []string) error { return nil })

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
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, captured := setupApparmorTest(t)

	result, err := mgr.addRoot(testDir)
	if err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}
	if !result.Changed {
		t.Error("expected Changed=true")
	}
	if result.Path != testDir {
		t.Errorf("expected %s, got %s", testDir, result.Path)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 1 || roots[0] != testDir {
		t.Errorf("expected root %s, got %v", testDir, roots)
	}

	if len(captured.args) != 3 || captured.args[0] != "--replace" {
		t.Errorf("expected reload call, got args %v", captured.args)
	}
}

func TestApparmorSuccessfulRemove(t *testing.T) {
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, captured := setupApparmorTest(t)

	if _, err := mgr.addRoot(testDir); err != nil {
		t.Fatalf("addRoot failed: %v", err)
	}
	captured.args = nil

	result, err := mgr.removeRoot(testDir)
	if err != nil {
		t.Fatalf("removeRoot failed: %v", err)
	}
	if !result.Changed {
		t.Error("expected Changed=true")
	}
	if result.Path != testDir {
		t.Errorf("expected %s, got %s", testDir, result.Path)
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed: %v", err)
	}
	if len(roots) != 0 {
		t.Errorf("expected empty list after remove, got %v", roots)
	}

	if len(captured.args) != 3 || captured.args[0] != "--replace" {
		t.Errorf("expected reload call after remove, got args %v", captured.args)
	}
}

func TestApparmorAddMultipleRoots(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	dirA := filepath.Join(rootDir, "a")
	dirB := filepath.Join(rootDir, "b")
	dirC := filepath.Join(rootDir, "c")
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
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
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

	_, mgr := setupApparmorTestWithRunner(t, fakeRunner)

	if _, err := mgr.addRoot(testDirA); err != nil {
		t.Fatalf("first addRoot failed: %v", err)
	}
	if _, err := mgr.addRoot(testDirB); err != nil {
		t.Fatalf("second addRoot failed: %v", err)
	}

	mgr.runParser = func(exe string, args []string) error {
		return errors.New("parser failed on remove")
	}

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

	_, mgr := setupApparmorTestWithRunner(t, fakeRunner)

	if _, err := mgr.addRoot(testDirA); err != nil {
		t.Fatalf("first addRoot failed: %v", err)
	}

	callCount := 0
	mgr.runParser = func(exe string, args []string) error {
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

// --- Rollback restores absence of fragment ---

func TestApparmorRollbackRestoresAbsence(t *testing.T) {
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

	_, mgr := setupApparmorTestWithRunner(t, fakeRunner)

	if _, err := mgr.addRoot(testDirA); err != nil {
		t.Fatalf("first addRoot failed: %v", err)
	}

	_, err := mgr.addRoot(testDirB)
	if err == nil {
		t.Fatal("expected error for second addRoot")
	}

	roots, err := mgr.listRoots()
	if err != nil {
		t.Fatalf("listRoots failed after rollback: %v", err)
	}
	if len(roots) != 1 || roots[0] != testDirA {
		t.Errorf("expected only %s after rollback, got %v", testDirA, roots)
	}
}

// --- Lock serialization ---

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
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return nil },
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

// --- Real concurrency test ---

func TestApparmorConcurrentLockBusy(t *testing.T) {
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

	_, mgr := setupApparmorTestWithRunner(t, fakeRunner)

	var wg sync.WaitGroup
	var errA, errB error
	var resultA rootResult

	wg.Add(2)

	// First goroutine: enters runner, holds lock
	go func() {
		defer wg.Done()
		resultA, errA = mgr.addRoot(testDirA)
	}()

	// Wait for first goroutine to be in the runner (lock held)
	<-firstInRunner

	// Second goroutine: tries to acquire lock while first holds it
	go func() {
		defer wg.Done()
		_, errB = mgr.addRoot(testDirB)
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

func TestApparmorParserNotExecutable(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
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

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath, fakeRunner)

	_, err = mgr.addRoot(testDir)
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

// --- Symlink fragment rejected in add ---

func TestApparmorSymlinkFragmentAddRejected(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "main")
	realFragment := filepath.Join(dir, "real-fragment")
	linkFragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
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
	fakeRunner := func(exe string, args []string) error {
		runnerCalled = true
		return nil
	}

	mgr := newApparmorManager(mainProfile, linkFragment, lockPath, parserPath, fakeRunner)

	_, err := mgr.addRoot(testDir)
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
}

// --- Symlink fragment rejected in remove ---

func TestApparmorSymlinkFragmentRemoveRejected(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "main")
	realFragment := filepath.Join(dir, "real-fragment")
	linkFragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
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
	fakeRunner := func(exe string, args []string) error {
		runnerCalled = true
		return nil
	}

	mgr := newApparmorManager(mainProfile, linkFragment, lockPath, parserPath, fakeRunner)

	_, err := mgr.removeRoot(testDir)
	if err == nil {
		t.Fatal("expected error for symlink fragment")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
	if runnerCalled {
		t.Error("runner should not be called when fragment is a symlink")
	}

	info, err := os.Lstat(linkFragment)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink should still be a symlink")
	}

	afterData, err := os.ReadFile(realFragment)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterData, targetData) {
		t.Error("target bytes should not be modified")
	}
}

// --- Non-regular fragment rejected (directory) ---

func TestApparmorNonRegularFragmentDirectory(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
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

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return nil },
	)

	_, err := mgr.addRoot(testDir)
	if err == nil {
		t.Fatal("expected error for directory fragment")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("expected not a regular file error, got: %v", err)
	}
}

// --- Parser unavailable preflight ---

func TestApparmorParserUnavailableNoChanges(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "nonexistent_parser")

	if err := os.WriteFile(mainProfile, []byte("profile test { }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return nil },
	)

	_, err := mgr.addRoot(testDir)
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

func TestApparmorMainProfileMissingNoChanges(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "nonexistent_profile")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return nil },
	)

	_, err := mgr.addRoot(testDir)
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

func TestApparmorCheckParserNotAvailable(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "fragment")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "nonexistent")

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath,
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

func TestApparmorCheckMainProfileNotFound(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "nonexistent")
	fragment := filepath.Join(dir, "fragment")
	lockPath := filepath.Join(dir, "lock")
	parserPath := filepath.Join(dir, "apparmor_parser")

	if err := os.WriteFile(parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath,
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

func TestApparmorCheckValidationFailure(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
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

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath,
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

func TestApparmorCheckSuccess(t *testing.T) {
	dir := t.TempDir()
	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
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

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath,
		func(exe string, args []string) error { return nil },
	)

	if err := mgr.check(); err != nil {
		t.Fatalf("check failed: %v", err)
	}
}

// --- Remove does not infer parent/child ---

func TestApparmorRemoveNoInference(t *testing.T) {
	rootDir := testAllowedRootDir(t)
	parentDir := filepath.Join(rootDir, "parent")
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

func TestFragmentRoundTripSpecialChars(t *testing.T) {
	roots := []string{"/with space", `/with"quote`, "/with\\backslash", "/with#hash", "/with,comma"}
	data := renderFragment(roots)

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
	if lines[3] != `# root-json: "/workspace"` {
		t.Errorf("expected root metadata, got: %s", lines[3])
	}
	if lines[4] != `"/workspace/" r,` {
		t.Errorf("expected dir rule, got: %s", lines[4])
	}
	if lines[5] != `"/workspace/**" r,` {
		t.Errorf("expected glob rule, got: %s", lines[5])
	}
}

func TestRenderFragmentMultipleRoots(t *testing.T) {
	roots := []string{"/a", "/b"}
	data := renderFragment(roots)
	content := string(data)

	if !strings.Contains(content, `# root-json: "/a"`) {
		t.Error("missing root /a")
	}
	if !strings.Contains(content, `# root-json: "/b"`) {
		t.Error("missing root /b")
	}
	if !strings.Contains(content, `"/a/" r,`) {
		t.Error("missing rule for /a")
	}
	if !strings.Contains(content, `"/b/" r,`) {
		t.Error("missing rule for /b")
	}
}

// --- validateRootPathForRemove ---

func TestValidateRootPathForRemoveNonExistent(t *testing.T) {
	canonical, err := validateRootPathForRemove("/nonexistent/path")
	if err != nil {
		t.Fatalf("expected success for non-existent path in remove, got: %v", err)
	}
	if canonical != "/nonexistent/path" {
		t.Errorf("expected /nonexistent/path, got %s", canonical)
	}
}

func TestValidateRootPathForRemoveRelative(t *testing.T) {
	_, err := validateRootPathForRemove("relative")
	if err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestValidateRootPathForRemoveRoot(t *testing.T) {
	_, err := validateRootPathForRemove("/")
	if err == nil {
		t.Fatal("expected error for /")
	}
}

// --- validateRootPathForAdd ---

func TestValidateRootPathForAddAbsolute(t *testing.T) {
	_, err := validateRootPathForAdd("relative")
	if err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestValidateRootPathForAddNotDirectory(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(tmpfile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := validateRootPathForAdd(tmpfile)
	if err == nil {
		t.Fatal("expected error for file path")
	}
}

func TestValidateRootPathForAddNotExists(t *testing.T) {
	_, err := validateRootPathForAdd("/nonexistent/path/xyz")
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

// --- Rollback restores exact mode ---

func TestApparmorRollbackRestoresMode(t *testing.T) {
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

	_, mgr := setupApparmorTestWithRunner(t, fakeRunner)

	if _, err := mgr.addRoot(testDirA); err != nil {
		t.Fatalf("first addRoot failed: %v", err)
	}

	prevInfo, err := os.Stat(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("cannot stat fragment: %v", err)
	}
	prevMode := prevInfo.Mode().Perm()

	_, err = mgr.addRoot(testDirB)
	if err == nil {
		t.Fatal("expected error for second addRoot")
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

func TestApparmorRollbackRestoresNoFragment(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainProfile := filepath.Join(dir, "main")
	fragment := filepath.Join(dir, "docker-helper.d", "managed-roots")
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

	mgr := newApparmorManager(mainProfile, fragment, lockPath, parserPath, fakeRunner)

	_, err := mgr.addRoot(testDir)
	if err == nil {
		t.Fatal("expected error for addRoot")
	}

	if _, err := os.Stat(fragment); !os.IsNotExist(err) {
		t.Error("fragment should not exist after rollback to absent state")
	}
}

// --- Lexical validation table-driven tests ---

func TestValidateRootLexical(t *testing.T) {
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
			err := validateRootLexical(tc.path)
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

// --- Fragment with invalid roots rejected by parseFragment ---

func TestParseFragmentRejectsInvalidRoots(t *testing.T) {
	tests := []struct {
		name string
		root string
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
			data := renderFragment([]string{tc.root})
			_, err := parseFragment(data)
			if err == nil {
				t.Fatalf("expected error for invalid root %q, got nil", tc.root)
			}
		})
	}
}

// --- Idempotent operation result ---

func TestApparmorIdempotentAddResult(t *testing.T) {
	testDir := filepath.Join(testAllowedRootDir(t), "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	result1, err := mgr.addRoot(testDir)
	if err != nil {
		t.Fatal(err)
	}
	if !result1.Changed {
		t.Error("first add should report Changed=true")
	}

	result2, err := mgr.addRoot(testDir)
	if err != nil {
		t.Fatal(err)
	}
	if result2.Changed {
		t.Error("duplicate add should report Changed=false")
	}
}

func TestApparmorIdempotentRemoveResult(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	_, mgr, _ := setupApparmorTest(t)

	result, err := mgr.removeRoot(testDir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Error("remove absent root should report Changed=false")
	}
}

// --- Stat error in remove ---

func TestValidateRootPathForRemoveStatError(t *testing.T) {
	// Test with a symlink loop to get ELOOP error
	dir := t.TempDir()
	linkPath := filepath.Join(dir, "loop")
	if err := os.Symlink(linkPath, linkPath); err != nil {
		t.Fatal(err)
	}

	_, err := validateRootPathForRemove(linkPath)
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

// --- Existing non-directory path as lexical stale root ---

func TestValidateRootPathForRemoveNonDirectory(t *testing.T) {
	dir := t.TempDir()
	tmpfile := filepath.Join(dir, "notadir")
	if err := os.WriteFile(tmpfile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	canonical, err := validateRootPathForRemove(tmpfile)
	if err != nil {
		t.Fatalf("expected success for existing non-directory, got: %v", err)
	}
	if canonical != tmpfile {
		t.Errorf("expected %s, got %s", tmpfile, canonical)
	}
}
