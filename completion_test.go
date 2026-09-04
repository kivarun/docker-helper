package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// completionFixture holds the package-lifetime cached completion binary
// and script. Built once, reused by all completion tests.
var (
	completionFixtureOnce sync.Once
	completionFixture     completionFixtureResult
	completionFixtureErr  error
)

type completionFixtureResult struct {
	binPath string
	script  string
	tmpDir  string
}

// initCompletionFixture builds the docker-helper binary and generates the
// bash completion script once for the lifetime of the test process.
func initCompletionFixture() {
	res := completionFixtureResult{}

	res.tmpDir, completionFixtureErr = os.MkdirTemp("", "completion-test-*")
	if completionFixtureErr != nil {
		return
	}

	// Clean up tempdir if any subsequent step fails.
	defer func() {
		if completionFixtureErr != nil {
			os.RemoveAll(res.tmpDir)
		}
	}()

	res.binPath = filepath.Join(res.tmpDir, "docker-helper")
	cmd := exec.Command("go", "build", "-o", res.binPath, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		completionFixtureErr = fmt.Errorf("failed to build docker-helper: %w: %s", err, out)
		return
	}

	cmd = exec.Command(res.binPath, "completion", "bash")
	out, err := cmd.CombinedOutput()
	if err != nil {
		completionFixtureErr = fmt.Errorf("docker-helper completion bash failed: %w: %s", err, out)
		return
	}
	res.script = string(out)

	completionFixture = res
}

// cleanupCompletionFixture removes the package-lifetime temporary directory.
func cleanupCompletionFixture() {
	if completionFixture.tmpDir != "" {
		os.RemoveAll(completionFixture.tmpDir)
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	cleanupCompletionFixture()
	os.Exit(code)
}

// getCompletionBinary returns the path to the cached docker-helper binary.
func getCompletionBinary(t *testing.T) string {
	t.Helper()
	completionFixtureOnce.Do(initCompletionFixture)
	if completionFixtureErr != nil {
		t.Fatalf("completion fixture init failed: %v", completionFixtureErr)
	}
	return completionFixture.binPath
}

// completionScript returns the cached bash completion script.
func completionScript(t *testing.T) string {
	t.Helper()
	completionFixtureOnce.Do(initCompletionFixture)
	if completionFixtureErr != nil {
		t.Fatalf("completion fixture init failed: %v", completionFixtureErr)
	}
	return completionFixture.script
}

func runCompletion(t *testing.T, script string, compWords []string) []string {
	t.Helper()
	cword := len(compWords) - 1

	// Build the test script
	var sb strings.Builder
	sb.WriteString(script)
	sb.WriteString("\n\n")
	sb.WriteString("# Test setup\n")
	sb.WriteString("COMP_WORDS=(")
	for _, w := range compWords {
		sb.WriteString(" '" + w + "'")
	}
	sb.WriteString(")\n")
	sb.WriteString("COMP_CWORD=" + strconv.Itoa(cword) + "\n")
	sb.WriteString("COMPREPLY=()\n")
	sb.WriteString("_docker_helper_completion\n")
	sb.WriteString("echo \"${COMPREPLY[@]}\"\n")

	cmd := exec.Command("bash", "-c", sb.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash completion failed: %v\n%s", err, out)
	}

	output := strings.TrimSpace(string(out))
	if output == "" {
		return nil
	}
	return strings.Fields(output)
}

func TestCompletionScriptExitCode(t *testing.T) {
	binPath := getCompletionBinary(t)
	cmd := exec.Command(binPath, "completion", "bash")
	if err := cmd.Run(); err != nil {
		t.Errorf("docker-helper completion bash exit code: %v", err)
	}
}

func TestCompletionScriptNonEmpty(t *testing.T) {
	script := completionScript(t)
	if len(script) == 0 {
		t.Error("completion script is empty")
	}
	if !strings.Contains(script, "_docker_helper_completion") {
		t.Error("completion script missing _docker_helper_completion function")
	}
	if !strings.Contains(script, "complete -F") {
		t.Error("completion script missing complete registration")
	}
}

func TestCompletionScriptNoInitCompletion(t *testing.T) {
	script := completionScript(t)
	if strings.Contains(script, "_init_completion") {
		t.Error("completion script must not use _init_completion")
	}
}

func TestCompletionDeterministic(t *testing.T) {
	binPath := getCompletionBinary(t)

	out1, err := exec.Command(binPath, "completion", "bash").CombinedOutput()
	if err != nil {
		t.Fatalf("first completion bash failed: %v\n%s", err, out1)
	}
	out2, err := exec.Command(binPath, "completion", "bash").CombinedOutput()
	if err != nil {
		t.Fatalf("second completion bash failed: %v\n%s", err, out2)
	}
	if string(out1) != string(out2) {
		t.Error("completion script is not deterministic")
	}
}

func TestCompletionRootCommands(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", ""})
	if len(results) == 0 {
		t.Error("expected root command completions")
		return
	}
	// Check that expected commands are present
	expected := []string{"serve", "init", "version", "help", "principal", "session", "config"}
	resultsMap := make(map[string]bool)
	for _, r := range results {
		resultsMap[r] = true
	}
	for _, exp := range expected {
		if !resultsMap[exp] {
			t.Errorf("expected root command %q not found in completions: %v", exp, results)
		}
	}
}

func TestCompletionPartialRootCommand(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "pri"})
	if len(results) == 0 {
		t.Error("expected partial command completions for 'pri'")
		return
	}
	found := false
	for _, r := range results {
		if r == "principal" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'principal' in completions for 'pri': %v", results)
	}
}

func TestCompletionNestedSubcommands(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "principal", ""})
	if len(results) == 0 {
		t.Error("expected principal subcommand completions")
		return
	}
	expected := []string{"create", "list", "show", "set", "delete", "allowed-root"}
	resultsMap := make(map[string]bool)
	for _, r := range results {
		resultsMap[r] = true
	}
	for _, exp := range expected {
		if !resultsMap[exp] {
			t.Errorf("expected principal subcommand %q not found: %v", exp, results)
		}
	}
}

func TestCompletionDeepNestedSubcommands(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "principal", "allowed-root", ""})
	if len(results) == 0 {
		t.Error("expected deep nested subcommand completions")
		return
	}
	expected := []string{"add", "remove"}
	resultsMap := make(map[string]bool)
	for _, r := range results {
		resultsMap[r] = true
	}
	for _, exp := range expected {
		if !resultsMap[exp] {
			t.Errorf("expected deep nested subcommand %q not found: %v", exp, results)
		}
	}
}

func TestCompletionAdminTokenSubcommands(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "admin-token", ""})
	if len(results) == 0 {
		t.Error("expected admin-token subcommand completions")
		return
	}
	found := false
	for _, r := range results {
		if r == "rotate" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'rotate' in admin-token completions: %v", results)
	}
	// Only rotate may be offered under admin-token.
	if len(results) != 1 || results[0] != "rotate" {
		t.Errorf("admin-token must complete only rotate, got: %v", results)
	}
}

// TestCompletionSELinux verifies `selinux` is a root command completion and
// `check` is a selinux subcommand completion.
func TestCompletionSELinux(t *testing.T) {
	script := completionScript(t)

	results := runCompletion(t, script, []string{"docker-helper", ""})
	if !slices.Contains(results, "selinux") {
		t.Errorf("root completion must offer selinux, got: %v", results)
	}

	results = runCompletion(t, script, []string{"docker-helper", "selinux", ""})
	if len(results) == 0 {
		t.Fatal("expected selinux subcommand completions")
	}
	if !slices.Contains(results, "check") {
		t.Errorf("selinux completion must offer check, got: %v", results)
	}
	if len(results) != 1 || results[0] != "check" {
		t.Errorf("selinux must complete only check, got: %v", results)
	}
}

// TestCompletionNoLegacyAdminHierarchy verifies root completion offers
// admin-token and never the legacy admin/token hierarchy.
func TestCompletionNoLegacyAdminHierarchy(t *testing.T) {
	script := completionScript(t)

	// Root completion must offer admin-token and not admin.
	results := runCompletion(t, script, []string{"docker-helper", ""})
	if !slices.Contains(results, "admin-token") {
		t.Error("root completion must offer admin-token")
	}
	if slices.Contains(results, "admin") {
		t.Error("root completion must NOT offer admin")
	}

	// Prefix "a" must yield admin-token, not admin.
	results = runCompletion(t, script, []string{"docker-helper", "a"})
	for _, r := range results {
		if r == "admin" {
			t.Error("prefix 'a' must NOT complete the legacy admin command")
		}
	}
	if !slices.Contains(results, "admin-token") {
		t.Error("prefix 'a' must complete admin-token")
	}

	// The legacy hierarchy must not resolve: completing under 'admin' yields
	// nothing (admin is not a command, so no token subcommand).
	results = runCompletion(t, script, []string{"docker-helper", "admin", "token", ""})
	if slices.Contains(results, "rotate") {
		t.Error("legacy 'admin token' hierarchy must not offer rotate")
	}
	if slices.Contains(results, "token") {
		t.Error("legacy 'admin' must not offer token")
	}
}

func TestCompletionBoolFlagDoesNotSwallow(t *testing.T) {
	// After a boolean flag like --system, the next word should still complete
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "principal", "create", "--system", "-"})
	if len(results) == 0 {
		t.Error("expected flag completions after boolean flag --system")
		return
	}
	// Should still offer flags
	found := false
	for _, r := range results {
		if strings.HasPrefix(r, "--") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected flags after --system: %v", results)
	}
}

func TestCompletionOptionWithValue(t *testing.T) {
	// After --endpoint value, the next word should still complete
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "principal", "create", "--endpoint", "unix:///tmp/test", "-"})
	if len(results) == 0 {
		t.Error("expected flag completions after --endpoint value")
		return
	}
	// Should still offer flags
	found := false
	for _, r := range results {
		if strings.HasPrefix(r, "--") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected flags after --endpoint value: %v", results)
	}
}

func TestCompletionConfigShowFields(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "config", "show", ""})
	if len(results) == 0 {
		t.Error("expected config show field completions")
		return
	}
	expected := []string{"allowed_roots", "session_ttl", "log_level", "audit_enabled"}
	resultsMap := make(map[string]bool)
	for _, r := range results {
		resultsMap[r] = true
	}
	for _, exp := range expected {
		if !resultsMap[exp] {
			t.Errorf("expected config show field %q not found: %v", exp, results)
		}
	}
	// Must not contain legacy allowed_root.
	if resultsMap["allowed_root"] {
		t.Error("config show must not contain legacy allowed_root")
	}
}

func TestCompletionConfigSetFields(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "config", "set", ""})
	if len(results) == 0 {
		t.Error("expected config set field completions")
		return
	}
	expected := []string{"session_ttl", "log_level", "audit_enabled"}
	resultsMap := make(map[string]bool)
	for _, r := range results {
		resultsMap[r] = true
	}
	for _, exp := range expected {
		if !resultsMap[exp] {
			t.Errorf("expected config set field %q not found: %v", exp, results)
		}
	}
	// Must not contain allowed_root or allowed_roots.
	if resultsMap["allowed_root"] {
		t.Error("config set must not contain legacy allowed_root")
	}
	if resultsMap["allowed_roots"] {
		t.Error("config set must not contain allowed_roots")
	}
}

func TestCompletionConfigUnsetFields(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "config", "unset", ""})
	if len(results) == 0 {
		t.Error("expected config unset field completions")
		return
	}
	expected := []string{"log_level", "audit_enabled", "shutdown_timeout"}
	resultsMap := make(map[string]bool)
	for _, r := range results {
		resultsMap[r] = true
	}
	for _, exp := range expected {
		if !resultsMap[exp] {
			t.Errorf("expected config unset field %q not found: %v", exp, results)
		}
	}
}

func TestCompletionConfigSetValue(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "config", "set", "log_level", ""})
	if len(results) == 0 {
		t.Error("expected config set log_level value completions")
		return
	}
	expected := []string{"debug", "info", "warn", "error"}
	resultsMap := make(map[string]bool)
	for _, r := range results {
		resultsMap[r] = true
	}
	for _, exp := range expected {
		if !resultsMap[exp] {
			t.Errorf("expected config set log_level value %q not found: %v", exp, results)
		}
	}
}

// TestCompletionConfigSetTrustedCAPathFilesystem verifies that the
// trusted_ca_path value (a filesystem path) is completed with filesystem
// entries, matching the other path-valued config value.
func TestCompletionConfigSetTrustedCAPathFilesystem(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "config", "set", "trusted_ca_path", "/usr"})
	if len(results) == 0 {
		t.Error("expected trusted_ca_path value completions")
		return
	}
	found := false
	for _, r := range results {
		if strings.HasPrefix(r, "/usr") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected /usr* path completions, got %v", results)
	}
}

func TestCompletionIntermediateCommandHelp(t *testing.T) {
	// -h/--help must complete on intermediate commands whose NewInvocation is nil
	script := completionScript(t)
	for _, cmd := range []string{"principal", "session", "config"} {
		results := runCompletion(t, script, []string{"docker-helper", cmd, "-"})
		if len(results) == 0 {
			t.Errorf("expected flag completions for %s", cmd)
			continue
		}
		foundH := false
		foundHelp := false
		for _, r := range results {
			if r == "-h" {
				foundH = true
			}
			if r == "--help" {
				foundHelp = true
			}
		}
		if !foundH {
			t.Errorf("expected -h in %s flag completions: %v", cmd, results)
		}
		if !foundHelp {
			t.Errorf("expected --help in %s flag completions: %v", cmd, results)
		}
	}
}

func TestCompletionRootHelpFlags(t *testing.T) {
	// docker-helper -<TAB> must complete -h and --help
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "-"})
	if len(results) == 0 {
		t.Error("expected flag completions for root command")
		return
	}
	foundH := false
	foundHelp := false
	for _, r := range results {
		if r == "-h" {
			foundH = true
		}
		if r == "--help" {
			foundHelp = true
		}
	}
	if !foundH {
		t.Errorf("expected -h in root flag completions: %v", results)
	}
	if !foundHelp {
		t.Errorf("expected --help in root flag completions: %v", results)
	}
}

func TestCompletionRootVersionFlags(t *testing.T) {
	// docker-helper -<TAB> must also suggest the -v/--version aliases.
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "-"})
	if len(results) == 0 {
		t.Error("expected flag completions for root command")
		return
	}
	foundV := false
	foundVersion := false
	for _, r := range results {
		if r == "-v" {
			foundV = true
		}
		if r == "--version" {
			foundVersion = true
		}
	}
	if !foundV {
		t.Errorf("expected -v in root flag completions: %v", results)
	}
	if !foundVersion {
		t.Errorf("expected --version in root flag completions: %v", results)
	}
}

func TestCompletionPasswordStdinIsBool(t *testing.T) {
	// --password-stdin is a real bool flag; it must not swallow the next word
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "registry", "login", "--password-stdin", "-"})
	if len(results) == 0 {
		t.Error("expected flag completions after --password-stdin")
		return
	}
	found := false
	for _, r := range results {
		if strings.HasPrefix(r, "--") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected flags after --password-stdin: %v", results)
	}
}

func TestCompletionWorksInPlainBash(t *testing.T) {
	// Verify the script works without bash-completion loaded
	script := completionScript(t)
	// Run with a minimal bash environment
	cmd := exec.Command("bash", "--norc", "--noprofile", "-c", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("completion script failed in plain bash: %v\n%s", err, out)
	}
}

func TestConfigShowFieldsVocabulary(t *testing.T) {
	fields := configShowFields()

	// Must contain allowed_roots.
	if !slices.Contains(fields, "allowed_roots") {
		t.Error("config show must contain allowed_roots")
	}

	// Must NOT contain legacy allowed_root.
	if slices.Contains(fields, "allowed_root") {
		t.Error("config show must not contain legacy allowed_root")
	}

	// Must contain representative computed fields.
	for _, f := range []string{"mode", "config_path"} {
		if !slices.Contains(fields, f) {
			t.Errorf("config show must contain %s", f)
		}
	}

	// Every returned field must be accepted by configShowField's contract.
	for _, f := range fields {
		if _, ok := lookupConfigField(f); !ok {
			t.Errorf("config show field %q is not in configFields", f)
		}
	}
}

func TestConfigSetFieldsVocabulary(t *testing.T) {
	fields := configSetFields()

	// Must NOT contain allowed_root or allowed_roots.
	if slices.Contains(fields, "allowed_root") {
		t.Error("config set must not contain legacy allowed_root")
	}
	if slices.Contains(fields, "allowed_roots") {
		t.Error("config set must not contain allowed_roots")
	}

	// Must contain writable scalar fields.
	for _, f := range []string{"session_ttl", "log_level", "trusted_ca_path", "http_address"} {
		if !slices.Contains(fields, f) {
			t.Errorf("config set must contain %s", f)
		}
	}

	// Must not contain read-only fields.
	for _, f := range []string{"mode", "config_path", "audit_enabled_source"} {
		if slices.Contains(fields, f) {
			t.Errorf("config set must not contain read-only field %s", f)
		}
	}
}

func TestConfigUnsetFieldsVocabulary(t *testing.T) {
	fields := configUnsetFields()

	// Must NOT contain allowed_root or allowed_roots.
	if slices.Contains(fields, "allowed_root") {
		t.Error("config unset must not contain legacy allowed_root")
	}
	if slices.Contains(fields, "allowed_roots") {
		t.Error("config unset must not contain allowed_roots")
	}

	// Must NOT contain required fields.
	if slices.Contains(fields, "session_ttl") {
		t.Error("config unset must not contain required session_ttl")
	}

	// Must contain optional writable fields.
	for _, f := range []string{"log_level", "http_address"} {
		if !slices.Contains(fields, f) {
			t.Errorf("config unset must contain %s", f)
		}
	}
}

func TestCompletionConfigShowNoStaleAllowedRoot(t *testing.T) {
	script := completionScript(t)

	// config show must contain allowed_roots.
	results := runCompletion(t, script, []string{"docker-helper", "config", "show", ""})
	if !slices.Contains(results, "allowed_roots") {
		t.Error("config show completion must contain allowed_roots")
	}

	// config show must NOT contain stale allowed_root.
	if slices.Contains(results, "allowed_root") {
		t.Error("config show completion must not contain stale allowed_root")
	}
}

func TestCompletionConfigSetNoStaleAllowedRoot(t *testing.T) {
	script := completionScript(t)

	// config set FIELD must NOT contain stale allowed_root.
	results := runCompletion(t, script, []string{"docker-helper", "config", "set", ""})
	if slices.Contains(results, "allowed_root") {
		t.Error("config set completion must not contain stale allowed_root")
	}
	if slices.Contains(results, "allowed_roots") {
		t.Error("config set completion must not contain allowed_roots")
	}
}

func TestCompletionConfigUnsetNoStaleAllowedRoot(t *testing.T) {
	script := completionScript(t)

	// config unset must NOT contain stale allowed_root.
	results := runCompletion(t, script, []string{"docker-helper", "config", "unset", ""})
	if slices.Contains(results, "allowed_root") {
		t.Error("config unset completion must not contain stale allowed_root")
	}
	if slices.Contains(results, "allowed_roots") {
		t.Error("config unset completion must not contain allowed_roots")
	}
}

func TestCompletionAllowedRootSubcommands(t *testing.T) {
	script := completionScript(t)

	// config allowed-root must complete list, add, remove.
	results := runCompletion(t, script, []string{"docker-helper", "config", "allowed-root", ""})
	expected := []string{"list", "add", "remove"}
	if len(results) != len(expected) {
		t.Fatalf("expected %d subcommands, got %d: %v", len(expected), len(results), results)
	}
	for _, sub := range expected {
		if !slices.Contains(results, sub) {
			t.Errorf("config allowed-root completion must contain %s", sub)
		}
	}

	// Prefix completion: "a" should yield only "add".
	results = runCompletion(t, script, []string{"docker-helper", "config", "allowed-root", "a"})
	if len(results) != 1 || results[0] != "add" {
		t.Errorf("expected [add], got %v", results)
	}

	// Prefix completion: "l" should yield only "list".
	results = runCompletion(t, script, []string{"docker-helper", "config", "allowed-root", "l"})
	if len(results) != 1 || results[0] != "list" {
		t.Errorf("expected [list], got %v", results)
	}

	// After "list", must NOT repeat action words.
	results = runCompletion(t, script, []string{"docker-helper", "config", "allowed-root", "list", ""})
	for _, sub := range expected {
		if slices.Contains(results, sub) {
			t.Errorf("after 'config allowed-root list', must not repeat action words, got: %v", results)
		}
	}
}

func TestCompletionAllowedRootListNoPathCompletion(t *testing.T) {
	script := completionScript(t)

	// "config allowed-root list" must not produce action/path suggestions.
	results := runCompletion(t, script, []string{"docker-helper", "config", "allowed-root", "list", ""})
	// Should be empty or contain only filesystem entries (not action words).
	for _, sub := range []string{"list", "add", "remove"} {
		if slices.Contains(results, sub) {
			t.Errorf("after 'config allowed-root list', must not suggest action %q, got: %v", sub, results)
		}
	}
}

// TestCompletionApparmorRootAddDirectoryOnly verifies that "apparmor root add"
// completes directories (a managed workspace root must be a directory).
func TestCompletionApparmorRootAddDirectoryOnly(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "apparmor", "root", "add", "/us"})
	if len(results) == 0 {
		t.Error("expected apparmor root add directory completions")
		return
	}
	found := false
	for _, r := range results {
		if strings.HasPrefix(r, "/usr") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected /usr* directory completions, got %v", results)
	}
	if !strings.Contains(script, "\"apparmor root add\"") {
		t.Error("completion script must include an apparmor root add case")
	}
}

// TestCompletionApparmorRootRemoveFilesystem verifies that "apparmor root
// remove" completes filesystem entries.
func TestCompletionApparmorRootRemoveFilesystem(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "apparmor", "root", "remove", "/us"})
	if len(results) == 0 {
		t.Error("expected apparmor root remove filesystem completions")
		return
	}
	found := false
	for _, r := range results {
		if strings.HasPrefix(r, "/usr") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected /usr* filesystem completions, got %v", results)
	}
	if !strings.Contains(script, "\"apparmor root remove\"") {
		t.Error("completion script must include an apparmor root remove case")
	}
}

func TestCompletionAllowedRootAddDirectoryOnly(t *testing.T) {
	script := completionScript(t)

	// "config allowed-root add" should complete directories.
	// We verify the generated script contains compgen -d for the add case.
	if !strings.Contains(script, "compgen -d") {
		t.Error("completion script must use 'compgen -d' for directory completion in 'add' case")
	}
}

func TestCompletionAllowedRootRemoveFilesystemCompletion(t *testing.T) {
	script := completionScript(t)

	// "config allowed-root remove" should complete filesystem entries.
	// We verify the generated script contains compgen -f for the remove case.
	if !strings.Contains(script, "compgen -f") {
		t.Error("completion script must use 'compgen -f' for filesystem completion in 'remove' case")
	}
}

// TestCompletionPathValuedFlagsFilesystemCompletion verifies the generated
// script completes filesystem paths for the path-valued flags surfaced in UAT.
func TestCompletionPathValuedFlagsFilesystemCompletion(t *testing.T) {
	script := completionScript(t)
	for _, flag := range pathValuedFlags {
		if !strings.Contains(script, "\""+flag+"\"") {
			t.Errorf("completion script must include a completion case for --%s", flag)
		}
	}
	if !strings.Contains(script, "compgen -f -- \"$cur\"") {
		t.Error("completion script must use 'compgen -f' for path-valued flags")
	}
}

func TestCompletionAllowedRootPartialActionNoPathCompletion(t *testing.T) {
	script := completionScript(t)

	// "config allowed-root li" should complete to "list" via generic subcommand completion.
	results := runCompletion(t, script, []string{"docker-helper", "config", "allowed-root", "li"})
	if len(results) != 1 || results[0] != "list" {
		t.Errorf("expected [list], got %v", results)
	}
}

func TestCompletionNoWorkspaceRoot(t *testing.T) {
	script := completionScript(t)

	// Root commands must NOT include workspace-root.
	results := runCompletion(t, script, []string{"docker-helper", ""})
	if slices.Contains(results, "workspace-root") {
		t.Error("root completion must NOT include workspace-root")
	}

	// Prefix completion: "wo" should NOT yield workspace-root.
	results = runCompletion(t, script, []string{"docker-helper", "wo"})
	if slices.Contains(results, "workspace-root") {
		t.Error("prefix 'wo' must NOT yield workspace-root")
	}

	// completion must complete "bash".
	results = runCompletion(t, script, []string{"docker-helper", "completion", ""})
	if len(results) != 1 || results[0] != "bash" {
		t.Errorf("expected [bash], got %v", results)
	}
}

// TestCompletionAllowedRootAddDirectoryOnlyBehavioral verifies that
// "config allowed-root add" completes only directories, not files.
func TestCompletionAllowedRootAddDirectoryOnlyBehavioral(t *testing.T) {
	script := completionScript(t)

	// Create a temp structure with a directory and a regular file.
	tmpDir := t.TempDir()
	dirName := "workspaces"
	fileName := "config.json"
	if err := os.MkdirAll(filepath.Join(tmpDir, dirName), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, fileName), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	sb.WriteString(script)
	sb.WriteString("\n\n")
	sb.WriteString("COMP_WORDS=(")
	sb.WriteString(" 'docker-helper' 'config' 'allowed-root' 'add' ''")
	sb.WriteString(")\n")
	sb.WriteString("COMP_CWORD=4\n")
	sb.WriteString("COMPREPLY=()\n")
	sb.WriteString("cd " + tmpDir + "\n")
	sb.WriteString("_docker_helper_completion\n")
	sb.WriteString("echo \"${COMPREPLY[@]}\"\n")

	cmd := exec.Command("bash", "-c", sb.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash completion failed: %v\n%s", err, out)
	}

	output := strings.TrimSpace(string(out))

	// Must contain the directory name.
	if !strings.Contains(output, dirName) {
		t.Errorf("expected directory %q in completions, got: %s", dirName, output)
	}

	// Must NOT contain the regular file name.
	if strings.Contains(output, fileName) {
		t.Errorf("regular file %q must NOT appear in 'add' completions, got: %s", fileName, output)
	}
}

// TestCompletionAllowedRootAddAbsolutePrefixBehavioral verifies that
// "config allowed-root add" with an absolute prefix completes directories
// and excludes regular files, matching the directory-only policy.
func TestCompletionAllowedRootAddAbsolutePrefixBehavioral(t *testing.T) {
	script := completionScript(t)

	tmpDir := t.TempDir()
	dirName := "prefix-dir"
	fileName := "prefix-file"
	if err := os.MkdirAll(filepath.Join(tmpDir, dirName), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, fileName), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	absPrefix := tmpDir + "/prefix"

	var sb strings.Builder
	sb.WriteString(script)
	sb.WriteString("\n\n")
	sb.WriteString("COMP_WORDS=(")
	sb.WriteString(" 'docker-helper' 'config' 'allowed-root' 'add' '" + absPrefix + "'")
	sb.WriteString(")\n")
	sb.WriteString("COMP_CWORD=4\n")
	sb.WriteString("COMPREPLY=()\n")
	sb.WriteString("_docker_helper_completion\n")
	sb.WriteString("echo \"${COMPREPLY[@]}\"\n")

	cmd := exec.Command("bash", "-c", sb.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash completion failed: %v\n%s", err, out)
	}

	output := string(out)

	// Must contain the directory (with trailing /).
	if !strings.Contains(output, dirName) {
		t.Errorf("expected directory %q in completions, got: %s", dirName, output)
	}

	// Must NOT contain the regular file.
	if strings.Contains(output, fileName) {
		t.Errorf("regular file %q must NOT appear in 'add' completions, got: %s", fileName, output)
	}
}

// TestCompletionAllowedRootRemoveAbsolutePrefixBehavioral verifies that
// "config allowed-root remove" with an absolute prefix completes both
// directories and files.
func TestCompletionAllowedRootRemoveAbsolutePrefixBehavioral(t *testing.T) {
	script := completionScript(t)

	tmpDir := t.TempDir()
	dirName := "prefix-dir"
	fileName := "prefix-file"
	if err := os.MkdirAll(filepath.Join(tmpDir, dirName), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, fileName), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	absPrefix := tmpDir + "/prefix"

	var sb strings.Builder
	sb.WriteString(script)
	sb.WriteString("\n\n")
	sb.WriteString("COMP_WORDS=(")
	sb.WriteString(" 'docker-helper' 'config' 'allowed-root' 'remove' '" + absPrefix + "'")
	sb.WriteString(")\n")
	sb.WriteString("COMP_CWORD=4\n")
	sb.WriteString("COMPREPLY=()\n")
	sb.WriteString("_docker_helper_completion\n")
	sb.WriteString("echo \"${COMPREPLY[@]}\"\n")

	cmd := exec.Command("bash", "-c", sb.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash completion failed: %v\n%s", err, out)
	}

	output := string(out)

	// Must contain both directory and file.
	if !strings.Contains(output, dirName) {
		t.Errorf("expected directory %q in 'remove' completions, got: %s", dirName, output)
	}
	if !strings.Contains(output, fileName) {
		t.Errorf("expected file %q in 'remove' completions, got: %s", fileName, output)
	}
}

// TestCompletionAllowedRootRemoveFilesystemBehavioral verifies that
// "config allowed-root remove" completes filesystem entries.
func TestCompletionAllowedRootRemoveFilesystemBehavioral(t *testing.T) {
	script := completionScript(t)

	tmpDir := t.TempDir()
	dirName := "workspaces"
	fileName := "config.json"
	if err := os.MkdirAll(filepath.Join(tmpDir, dirName), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, fileName), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	sb.WriteString(script)
	sb.WriteString("\n\n")
	sb.WriteString("COMP_WORDS=(")
	sb.WriteString(" 'docker-helper' 'config' 'allowed-root' 'remove' ''")
	sb.WriteString(")\n")
	sb.WriteString("COMP_CWORD=4\n")
	sb.WriteString("COMPREPLY=()\n")
	sb.WriteString("cd " + tmpDir + "\n")
	sb.WriteString("_docker_helper_completion\n")
	sb.WriteString("echo \"${COMPREPLY[@]}\"\n")

	cmd := exec.Command("bash", "-c", sb.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash completion failed: %v\n%s", err, out)
	}

	output := strings.TrimSpace(string(out))

	// Must contain both directory and file.
	if !strings.Contains(output, dirName) {
		t.Errorf("expected directory %q in 'remove' completions, got: %s", dirName, output)
	}
	if !strings.Contains(output, fileName) {
		t.Errorf("expected file %q in 'remove' completions, got: %s", fileName, output)
	}
}

// TestCompletionAllowedRootListNoSuggestionsBehavioral verifies that
// "config allowed-root list" produces no action or path suggestions.
func TestCompletionAllowedRootListFlagsOnlyBehavioral(t *testing.T) {
	script := completionScript(t)

	tmpDir := t.TempDir()
	// Create sentinel entries to prove no filesystem completion occurs.
	if err := os.MkdirAll(filepath.Join(tmpDir, "sentinel-dir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-file"), []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	sb.WriteString(script)
	sb.WriteString("\n\n")
	sb.WriteString("COMP_WORDS=(")
	sb.WriteString(" 'docker-helper' 'config' 'allowed-root' 'list' ''")
	sb.WriteString(")\n")
	sb.WriteString("COMP_CWORD=4\n")
	sb.WriteString("COMPREPLY=()\n")
	sb.WriteString("cd " + tmpDir + "\n")
	sb.WriteString("_docker_helper_completion\n")
	sb.WriteString("echo \"${COMPREPLY[@]}\"\n")

	cmd := exec.Command("bash", "-c", sb.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash completion failed: %v\n%s", err, out)
	}

	output := strings.TrimSpace(string(out))

	// "config allowed-root list" is a flag-only leaf: the generic tree model
	// offers the command's own flags. No action words and no filesystem
	// entries may appear.
	results := strings.Fields(output)
	if len(results) == 0 {
		t.Fatal("flag-only leaf must offer its flags, got none")
	}
	for _, r := range results {
		if !strings.HasPrefix(r, "-") {
			t.Errorf("'list' completion must offer flag words only, got %q", r)
		}
	}
	if !slices.Contains(results, "--help") {
		t.Errorf("'list' completion must offer --help, got: %v", results)
	}
}

// TestCompletionAllowedRootAfterPathNoSuggestionsBehavioral verifies that
// after the PATH argument, no further positional suggestions are produced.
func TestCompletionAllowedRootAfterPathNoSuggestionsBehavioral(t *testing.T) {
	script := completionScript(t)

	tmpDir := t.TempDir()
	// Create sentinel entries to prove no filesystem completion occurs.
	if err := os.MkdirAll(filepath.Join(tmpDir, "sentinel-dir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-file"), []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	sb.WriteString(script)
	sb.WriteString("\n\n")
	sb.WriteString("COMP_WORDS=(")
	sb.WriteString(" 'docker-helper' 'config' 'allowed-root' 'add' '/some/path' ''")
	sb.WriteString(")\n")
	sb.WriteString("COMP_CWORD=5\n")
	sb.WriteString("COMPREPLY=()\n")
	sb.WriteString("cd " + tmpDir + "\n")
	sb.WriteString("_docker_helper_completion\n")
	sb.WriteString("echo \"${COMPREPLY[@]}\"\n")

	cmd := exec.Command("bash", "-c", sb.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash completion failed: %v\n%s", err, out)
	}

	output := strings.TrimSpace(string(out))

	// COMPREPLY must be actually empty.
	if output != "" {
		t.Errorf("after PATH, must produce empty COMPREPLY, got: %s", output)
	}
}

func TestCompletionDoubleDashStopsFlagCompletion(t *testing.T) {
	// After literal --, COMPREPLY must be empty.
	// Container command arguments after -- are not docker-helper options.
	// No docker-helper completions may leak through: flags, subcommands, -h, --help, etc.
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "run", "--image", "alpine", "--", "sh", "-"})
	if len(results) != 0 {
		t.Errorf("after --, COMPREPLY must be empty, got: %v", results)
	}
}

func TestCompletionNoFlagsAfterPositional(t *testing.T) {
	// Go flag.FlagSet stops flag parsing at the first positional argument.
	// Completion must not suggest helper flags after a positional argument.
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "principal", "create", "alice", "--s"})
	for _, r := range results {
		if r == "--system" {
			t.Error("--system must NOT be suggested after positional argument")
			break
		}
	}
}

func TestCompletionFlagsBeforePositional(t *testing.T) {
	// Flags before positional arguments must still work.
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "principal", "create", "--s"})
	found := false
	for _, r := range results {
		if r == "--system" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("--system must be suggested before positional argument, got: %v", results)
	}
}

func TestCompletionFlagEqualsValueDoesNotConsumeNext(t *testing.T) {
	// --flag=value is self-contained; the following word must not be consumed
	// as the flag value. If the completion walk consumed the positional that
	// follows --endpoint=VALUE, flag completion would resume after it
	// instead of stopping at the positional argument.
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "session", "create", "--endpoint=http://localhost:9999", "work", "--s"})
	if len(results) != 0 {
		t.Errorf("--flag=value consumed the following word; positional did not stop flag completion, got: %v", results)
	}
}

// ---- completion for the `help` navigation branch ----

// TestCompletionAfterHelpRoot proves `docker-helper help <TAB>` offers the
// top-level commands, walking the same canonical command tree (not a
// separate hard-coded list).
func TestCompletionAfterHelpRoot(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "help", ""})
	for _, want := range []string{"principal", "launcher", "credential", "session", "config"} {
		found := false
		for _, r := range results {
			if r == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("help <TAB> missing %q, got: %v", want, results)
		}
	}
}

// TestCompletionAfterHelpPrincipal proves second-level help navigation.
func TestCompletionAfterHelpPrincipal(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "help", "principal", ""})
	for _, want := range []string{"create", "list", "show", "set", "delete", "allowed-root", "credential"} {
		found := false
		for _, r := range results {
			if r == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("help principal <TAB> missing %q, got: %v", want, results)
		}
	}
}

// TestCompletionAfterHelpPrincipalCredential proves third-level help
// navigation into the canonical principal credential tree.
func TestCompletionAfterHelpPrincipalCredential(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "help", "principal", "credential", ""})
	for _, want := range []string{"create", "list", "revoke", "rotate"} {
		found := false
		for _, r := range results {
			if r == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("help principal credential <TAB> missing %q, got: %v", want, results)
		}
	}
}

// TestCompletionAfterHelpLauncherCredential proves help navigation reaches
// the launcher credential subtree.
func TestCompletionAfterHelpLauncherCredential(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "help", "launcher", "credential", ""})
	for _, want := range []string{"create", "show", "rotate", "delete"} {
		found := false
		for _, r := range results {
			if r == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("help launcher credential <TAB> missing %q, got: %v", want, results)
		}
	}
}

// TestCompletionAfterHelpFlags proves flags complete under help navigation.
func TestCompletionAfterHelpFlags(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "help", "-"})
	if !slices.Contains(results, "-h") || !slices.Contains(results, "--help") {
		t.Errorf("help - <TAB> must offer -h --help, got: %v", results)
	}
}

// ---- generic command-tree completion invariants ----
//
// The following tests walk the real declarative Command tree instead of
// naming individual commands, so a newly added command automatically falls
// under the same parser-tree == help-tree == completion-tree invariants.

// completionTreeClasses walks the real Command tree and classifies every
// non-root node by dispatch shape. A node must be exactly one of:
// branch (subcommands, no NewInvocation) or leaf (NewInvocation, no
// subcommands). A hybrid node would be unreachable by dispatch and invisible
// to the generated completion model.
func completionTreeClasses(t *testing.T) (leaves, branches [][]string) {
	t.Helper()
	var walk func(cmd *Command, path []string)
	walk = func(cmd *Command, path []string) {
		for _, sub := range cmd.Subcommands {
			subPath := append(append([]string{}, path...), sub.Name)
			isLeaf := sub.NewInvocation != nil
			hasSubs := len(sub.Subcommands) > 0
			label := strings.Join(subPath, " ")
			switch {
			case isLeaf && hasSubs:
				t.Fatalf("command %q is both leaf and branch; dispatch and completion assume a clean tree", label)
			case isLeaf:
				leaves = append(leaves, subPath)
			case hasSubs:
				branches = append(branches, subPath)
			default:
				t.Fatalf("command %q has neither subcommands nor NewInvocation", label)
			}
			walk(sub, subPath)
		}
	}
	walk(rootCommand, nil)
	return leaves, branches
}

// treeCommandLongFlags derives the long flags a command accepts from its
// real FlagSet, plus --help which every leaf registers at dispatch time.
func treeCommandLongFlags(cmd *Command) []string {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	cmd.NewInvocation(fs)
	var flags []string
	fs.VisitAll(func(f *flag.Flag) {
		flags = append(flags, "--"+f.Name)
	})
	flags = append(flags, "--help")
	slices.Sort(flags)
	return flags
}

// treeCommandFlagWords derives the full flag word list a command's
// completion table emits: long flags, single-character short forms, and the
// always-present -h/--help pair.
func treeCommandFlagWords(cmd *Command) []string {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	cmd.NewInvocation(fs)
	var words []string
	fs.VisitAll(func(f *flag.Flag) {
		words = append(words, "--"+f.Name)
		if len(f.Name) == 1 {
			words = append(words, "-"+f.Name)
		}
	})
	words = append(words, "-h", "--help")
	slices.Sort(words)
	return words
}

// treeProviderLeafPaths lists leaf commands whose positional completion is
// semantic: config FIELD/VALUE and filesystem PATH providers, and the help
// navigation command whose unlimited positionals walk the command tree
// itself. Their empty-word behavior is provider-owned, not the generic flag
// fallback.
var treeProviderLeafPaths = []string{
	"config show",
	"config set",
	"config unset",
	"config allowed-root add",
	"config allowed-root remove",
	"apparmor root add",
	"apparmor root remove",
	"help",
}

func treeProbeWords(path []string, cur ...string) []string {
	words := make([]string, 0, len(path)+len(cur)+1)
	words = append(words, "docker-helper")
	words = append(words, path...)
	words = append(words, cur...)
	return words
}

// TestCompletionTreeBranchSubcommands proves that every branch command
// completes exactly its real subcommands on an empty current word.
func TestCompletionTreeBranchSubcommands(t *testing.T) {
	script := completionScript(t)
	_, branches := completionTreeClasses(t)
	if len(branches) == 0 {
		t.Fatal("no branch commands found in the tree")
	}
	for _, path := range branches {
		cmd := completionCommandPath(path)
		if cmd == nil {
			t.Fatalf("branch path %q not resolvable", strings.Join(path, " "))
		}
		want := make([]string, 0, len(cmd.Subcommands))
		for _, sub := range cmd.Subcommands {
			want = append(want, sub.Name)
		}
		slices.Sort(want)
		results := runCompletion(t, script, treeProbeWords(path, ""))
		slices.Sort(results)
		if !slices.Equal(results, want) {
			t.Errorf("%s <TAB>: got %v, want subcommands %v", strings.Join(path, " "), results, want)
		}
	}
}

// TestCompletionTreeLeafLongFlags proves that every leaf command completes
// exactly the long flags registered by its real FlagSet (plus --help) on an
// unfinished -- current word, with no per-command special casing.
func TestCompletionTreeLeafLongFlags(t *testing.T) {
	script := completionScript(t)
	leaves, _ := completionTreeClasses(t)
	if len(leaves) == 0 {
		t.Fatal("no leaf commands found in the tree")
	}
	for _, path := range leaves {
		cmd := completionCommandPath(path)
		if cmd == nil {
			t.Fatalf("leaf path %q not resolvable", strings.Join(path, " "))
		}
		want := treeCommandLongFlags(cmd)
		results := runCompletion(t, script, treeProbeWords(path, "--"))
		slices.Sort(results)
		if !slices.Equal(results, want) {
			t.Errorf("%s --<TAB>: got %v, want %v", strings.Join(path, " "), results, want)
		}
	}
}

// TestCompletionTreeFlagOnlyLeafEmptyWord proves that every leaf command
// with MaxPosArgs == 0 offers its own flags on an empty current word — the
// generic fallback for commands with no applicable positional or subcommand
// completion.
func TestCompletionTreeFlagOnlyLeafEmptyWord(t *testing.T) {
	script := completionScript(t)
	leaves, _ := completionTreeClasses(t)
	checked := 0
	for _, path := range leaves {
		cmd := completionCommandPath(path)
		if cmd == nil || cmd.MaxPosArgs != 0 {
			continue
		}
		want := treeCommandFlagWords(cmd)
		results := runCompletion(t, script, treeProbeWords(path, ""))
		slices.Sort(results)
		if !slices.Equal(results, want) {
			t.Errorf("%s <TAB>: got %v, want flags %v", strings.Join(path, " "), results, want)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no flag-only leaf commands found; tree shape changed")
	}
}

// TestCompletionTreePositionalLeafEmptyWordNoFlagFallback proves that leaf
// commands that accept positional arguments do not fall back to flag
// completion on an empty word: their positional completion is either
// semantic (providers) or intentionally empty.
func TestCompletionTreePositionalLeafEmptyWordNoFlagFallback(t *testing.T) {
	script := completionScript(t)
	leaves, _ := completionTreeClasses(t)
	for _, path := range leaves {
		cmd := completionCommandPath(path)
		if cmd == nil || cmd.MaxPosArgs == 0 {
			continue
		}
		label := strings.Join(path, " ")
		if slices.Contains(treeProviderLeafPaths, label) {
			continue
		}
		results := runCompletion(t, script, treeProbeWords(path, ""))
		if len(results) != 0 {
			t.Errorf("%s <TAB>: positional leaf must not fall back to flags, got %v", label, results)
		}
	}
}

// TestCompletionTreeOptionTerminatorNoFlags proves that after an explicit
// option terminator (--), no leaf command offers flags: the completed --
// ends the options section.
func TestCompletionTreeOptionTerminatorNoFlags(t *testing.T) {
	script := completionScript(t)
	leaves, _ := completionTreeClasses(t)
	for _, path := range leaves {
		results := runCompletion(t, script, treeProbeWords(path, "--", ""))
		if len(results) != 0 {
			t.Errorf("%s -- <TAB>: terminator must suppress flags, got %v", strings.Join(path, " "), results)
		}
	}
}

// TestCompletionTreeFlagPrefixFilter proves that a dash-prefixed current
// word prefix-filters the command's real flags on every leaf command.
func TestCompletionTreeFlagPrefixFilter(t *testing.T) {
	script := completionScript(t)
	leaves, _ := completionTreeClasses(t)
	for _, path := range leaves {
		cmd := completionCommandPath(path)
		if cmd == nil {
			continue
		}
		long := treeCommandLongFlags(cmd)
		// Anchor on the first long flag; --help is always present.
		anchor := long[0]
		prefix := anchor[:len("--")+1]
		results := runCompletion(t, script, treeProbeWords(path, prefix))
		if len(results) == 0 {
			t.Errorf("%s %s<TAB>: prefix filter returned nothing", strings.Join(path, " "), prefix)
			continue
		}
		for _, r := range results {
			if !strings.HasPrefix(r, prefix) {
				t.Errorf("%s %s<TAB>: %q does not match prefix", strings.Join(path, " "), prefix, r)
			}
		}
		if !slices.Contains(results, anchor) {
			t.Errorf("%s %s<TAB>: anchor flag %q missing, got %v", strings.Join(path, " "), prefix, anchor, results)
		}
	}
}

// TestCompletionTreeHelpNavigationLeafNoFlagFallback proves the flag-only
// fallback stays off under help navigation: help walks the command tree,
// and a leaf path under help offers no flags on an empty word.
func TestCompletionTreeHelpNavigationLeafNoFlagFallback(t *testing.T) {
	script := completionScript(t)
	leaves, _ := completionTreeClasses(t)
	for _, path := range leaves {
		results := runCompletion(t, script, treeProbeWords(append([]string{"help"}, path...), ""))
		if len(results) != 0 {
			t.Errorf("help %s <TAB>: navigation must not fall back to flags, got %v", strings.Join(path, " "), results)
		}
	}
}

// TestCompletionTreeLeafDashWordFlags proves that on a bare dash current
// word every leaf command offers its complete flag word list: long flags,
// single-character short forms, and the always-present -h/--help pair.
func TestCompletionTreeLeafDashWordFlags(t *testing.T) {
	script := completionScript(t)
	leaves, _ := completionTreeClasses(t)
	for _, path := range leaves {
		cmd := completionCommandPath(path)
		if cmd == nil {
			continue
		}
		want := treeCommandFlagWords(cmd)
		results := runCompletion(t, script, treeProbeWords(path, "-"))
		slices.Sort(results)
		if !slices.Equal(results, want) {
			t.Errorf("%s -<TAB>: got %v, want %v", strings.Join(path, " "), results, want)
		}
	}
}
