package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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

	// completion must complete "bash" and the roots query namespace.
	results = runCompletion(t, script, []string{"docker-helper", "completion", ""})
	if !slices.Equal(results, []string{"bash", "roots"}) {
		t.Errorf("expected [bash roots], got %v", results)
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

// ---- daemon-backed policy-aware completion harness ----

// runCompletionWithPreamble sources the completion script after the given
// bash preamble (PATH setup, working directory), then invokes the completion
// function with the given words. Returns the suggested words and the
// separate stderr text, so tests can prove completion never pollutes the
// user's terminal.
func runCompletionWithPreamble(t *testing.T, script, preamble string, compWords []string) ([]string, string) {
	t.Helper()
	cword := len(compWords) - 1

	var sb strings.Builder
	sb.WriteString(preamble)
	sb.WriteString("\n")
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
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("bash completion failed: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	output := strings.TrimSpace(stdout.String())
	if output == "" {
		return nil, stderr.String()
	}
	return strings.Fields(output), stderr.String()
}

// completionPATHPreamble puts the built binary on the harness PATH so the
// generated script re-invokes the same docker-helper the user is completing.
func completionPATHPreamble(t *testing.T) string {
	t.Helper()
	return "PATH=" + filepath.Dir(getCompletionBinary(t)) + ":$PATH; export PATH"
}

// runCompletionWithDeadline runs the completion harness exactly like
// runCompletionWithPreamble, but bounds the bash process with an explicit
// deadline so a completion that never terminates fails the test instead of
// hanging it. Output is captured through temp files rather than pipes: a
// hung completion child would otherwise keep the inherited pipe write ends
// open forever and block Wait even after the deadline kill. Returns the
// suggestions, the separate stderr text, and the harness error (deadline
// expiry included).
func runCompletionWithDeadline(t *testing.T, script, preamble string, compWords []string, limit time.Duration) ([]string, string, error) {
	t.Helper()
	cword := len(compWords) - 1

	var sb strings.Builder
	sb.WriteString(preamble)
	sb.WriteString("\n")
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

	dir := t.TempDir()
	writeHarnessOutput := func(name string) (*os.File, string) {
		t.Helper()
		f, err := os.CreateTemp(dir, name)
		if err != nil {
			t.Fatalf("create harness %s file: %v", name, err)
		}
		return f, f.Name()
	}
	stdoutFile, stdoutPath := writeHarnessOutput("stdout")
	stderrFile, stderrPath := writeHarnessOutput("stderr")

	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", sb.String())
	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile
	err := cmd.Run()
	stdoutFile.Close()
	stderrFile.Close()
	if err != nil {
		return nil, strings.TrimSpace(readHarnessFile(t, stderrPath)), err
	}
	output := strings.TrimSpace(readHarnessFile(t, stdoutPath))
	if output == "" {
		return nil, strings.TrimSpace(readHarnessFile(t, stderrPath)), nil
	}
	return strings.Fields(output), strings.TrimSpace(readHarnessFile(t, stderrPath)), nil
}

func readHarnessFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read harness output %s: %v", path, err)
	}
	return string(data)
}

// trimTrailingSlash normalizes one trailing slash for bash-version-robust
// assertions on directory completions.
func trimTrailingSlash(s string) string {
	return strings.TrimSuffix(s, "/")
}

// sortedTrimmed sorts and normalizes completion results.
func sortedTrimmed(results []string) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = trimTrailingSlash(r)
	}
	slices.Sort(out)
	return out
}

// TestCompletionPolicyValueTableConsistency proves every registered policy
// completion target is a real command path whose FlagSet registers the flag
// and whose value is a path: the semantic table can never drift from the
// parser tree.
func TestCompletionPolicyValueTableConsistency(t *testing.T) {
	for _, p := range policyValueCompletions {
		words := strings.Split(p.commandPath, " ")
		cmd := completionCommandPath(words)
		if cmd == nil {
			t.Errorf("policy completion path %q is not a command path", p.commandPath)
			continue
		}
		fs := flag.NewFlagSet("", flag.ContinueOnError)
		cmd.NewInvocation(fs)
		if f := fs.Lookup(p.flag); f == nil {
			t.Errorf("policy completion flag --%s is not registered by %q", p.flag, p.commandPath)
		}
		if !slices.Contains(pathValuedFlags, p.flag) {
			t.Errorf("policy completion flag --%s of %q is not path-valued", p.flag, p.commandPath)
		}
		switch p.query {
		case "principal", "session":
		default:
			t.Errorf("policy completion query %q is unknown", p.query)
		}
	}
}

// TestCompletionPolicyLauncherAllowedRootAnchors proves the first TAB on
// launcher create --allowed-root offers the daemon's effective Principal
// roots as the policy anchors, queried through docker-helper itself with the
// forwarded operator flags and the typed --principal target.
func TestCompletionPolicyLauncherAllowedRootAnchors(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "root-a")
	rootB := filepath.Join(base, "root-b")
	for _, d := range []string{rootA, rootB} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	endpoint, tokenPath, requests := startCompletionPolicyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/principals/alice/effective-allowed-roots" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, effectiveRootsResponse{
				OK: true, Principal: "alice", AllowedRoots: []string{rootA, rootB},
			})
			return
		}
		http.NotFound(w, r)
	})

	script := completionScript(t)
	results, stderr := runCompletionWithPreamble(t, script, completionPATHPreamble(t), []string{
		"docker-helper", "launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath,
		"--principal", "alice", "--allowed-root", "",
	})
	if stderr != "" {
		t.Fatalf("policy completion must not write to stderr: %q", stderr)
	}
	if want := []string{rootA, rootB}; !slices.Equal(sortedTrimmed(results), want) {
		t.Errorf("anchors = %v, want %v", results, want)
	}
	requests.waitFor(t, 1)
	if got := requests.snapshot(); len(got) != 1 || got[0].path != "/principals/alice/effective-allowed-roots" {
		t.Fatalf("requests = %+v, want exactly one principal roots query", got)
	}
}

// TestCompletionPolicyLauncherAllowedRootConfinement proves that after a
// successful policy query, directory completion inside an allowed root stays
// inside it: subdirectories are offered, a sibling root directory and a
// regular file are not.
func TestCompletionPolicyLauncherAllowedRootConfinement(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "root-a")
	rootB := filepath.Join(base, "root-b")
	if err := os.MkdirAll(filepath.Join(rootA, "sub1"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(rootA, "zzdir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootA, "afile"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(rootB, "xdir"), 0755); err != nil {
		t.Fatal(err)
	}
	endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/principals/alice/effective-allowed-roots" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, effectiveRootsResponse{
				OK: true, Principal: "alice", AllowedRoots: []string{rootA},
			})
			return
		}
		http.NotFound(w, r)
	})

	script := completionScript(t)
	baseWords := []string{"docker-helper", "launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath, "--principal", "alice"}

	// Inside the root: only its own subdirectories.
	insideWords := append(append([]string{}, baseWords...), "--allowed-root", rootA+"/")
	results, stderr := runCompletionWithPreamble(t, script, completionPATHPreamble(t), insideWords)
	if stderr != "" {
		t.Fatalf("policy completion must not write to stderr: %q", stderr)
	}
	if want := []string{filepath.Join(rootA, "sub1"), filepath.Join(rootA, "zzdir")}; !slices.Equal(sortedTrimmed(results), want) {
		t.Errorf("inside-root = %v, want %v", results, want)
	}

	// The sibling root directory is not offered even though it exists.
	results, _ = runCompletionWithPreamble(t, script, completionPATHPreamble(t), []string{
		"docker-helper", "launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath,
		"--principal", "alice", "--allowed-root", rootB + "/",
	})
	if len(results) != 0 {
		t.Errorf("sibling root must not be offered, got %v", results)
	}

	// A prefix of nothing outside the roots offers nothing.
	results, _ = runCompletionWithPreamble(t, script, completionPATHPreamble(t), []string{
		"docker-helper", "launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath,
		"--principal", "alice", "--allowed-root", "/nonexistent-policy-prefix",
	})
	if len(results) != 0 {
		t.Errorf("outside-roots prefix must not be offered, got %v", results)
	}
}

// TestCompletionPolicySymlinkOutsideNotSuggested proves the confinement of
// filesystem candidates is canonical, not lexical: a symlink under the
// allowed root pointing outside the root is never suggested, and its
// target's children are not reachable through the link. A real directory
// inside the root is still offered, proving the harness reached the
// candidate stage rather than failing earlier.
func TestCompletionPolicySymlinkOutsideNotSuggested(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{root, filepath.Join(root, "realdir"), outside, filepath.Join(outside, "escapee")} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	endpoint, tokenPath, _ := startCompletionPolicyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/principals/alice/effective-allowed-roots" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, effectiveRootsResponse{
				OK: true, Principal: "alice", AllowedRoots: []string{root},
			})
			return
		}
		http.NotFound(w, r)
	})

	script := completionScript(t)
	baseWords := []string{"docker-helper", "launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath, "--principal", "alice"}

	// One level down: the real directory is offered, the escaping link is not.
	results, stderr := runCompletionWithPreamble(t, script, completionPATHPreamble(t),
		append(append([]string{}, baseWords...), "--allowed-root", root+"/"))
	if stderr != "" {
		t.Fatalf("policy completion must not write to stderr: %q", stderr)
	}
	if want := []string{filepath.Join(root, "realdir")}; !slices.Equal(sortedTrimmed(results), want) {
		t.Errorf("inside root = %v, want %v (link escaping the root must not be suggested)", results, want)
	}

	// Through the link: the outside children are not reachable.
	results, _ = runCompletionWithPreamble(t, script, completionPATHPreamble(t),
		append(append([]string{}, baseWords...), "--allowed-root", root+"/link/"))
	if len(results) != 0 {
		t.Errorf("children behind a link leaving the root must not be suggested, got %v", results)
	}
}

// TestCompletionPolicySymlinkInsideSuggested proves the canonical
// confinement check admits legitimate traversal: a symlink under the allowed
// root pointing to a directory inside the same root is suggested, and its
// target's children are reachable through the link. Regular files inside the
// root are still never suggested.
func TestCompletionPolicySymlinkInsideSuggested(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	internal := filepath.Join(root, "internal")
	for _, d := range []string{root, internal, filepath.Join(internal, "sub1"), filepath.Join(internal, "sub2")} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "afile"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(internal, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	endpoint, tokenPath, _ := startCompletionPolicyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/principals/alice/effective-allowed-roots" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, effectiveRootsResponse{
				OK: true, Principal: "alice", AllowedRoots: []string{root},
			})
			return
		}
		http.NotFound(w, r)
	})

	script := completionScript(t)
	baseWords := []string{"docker-helper", "launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath, "--principal", "alice"}

	// One level down: the link pointing inside and the real directory are
	// offered; the regular file is not.
	results, stderr := runCompletionWithPreamble(t, script, completionPATHPreamble(t),
		append(append([]string{}, baseWords...), "--allowed-root", root+"/"))
	if stderr != "" {
		t.Fatalf("policy completion must not write to stderr: %q", stderr)
	}
	if want := []string{internal, filepath.Join(root, "link")}; !slices.Equal(sortedTrimmed(results), want) {
		t.Errorf("inside root = %v, want %v", results, want)
	}

	// Through the link: internal's children are suggested via the link path.
	results, _ = runCompletionWithPreamble(t, script, completionPATHPreamble(t),
		append(append([]string{}, baseWords...), "--allowed-root", root+"/link/"))
	if want := []string{filepath.Join(root, "link", "sub1"), filepath.Join(root, "link", "sub2")}; !slices.Equal(sortedTrimmed(results), want) {
		t.Errorf("through inside link = %v, want %v", results, want)
	}
}

// TestCompletionPolicyScopeSetAllowedRoot proves launcher scope set shares
// the same principal roots provider.
func TestCompletionPolicyScopeSetAllowedRoot(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "root-a")
	if err := os.MkdirAll(rootA, 0755); err != nil {
		t.Fatal(err)
	}
	endpoint, tokenPath, requests := startCompletionPolicyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/principals/alice/effective-allowed-roots" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, effectiveRootsResponse{
				OK: true, Principal: "alice", AllowedRoots: []string{rootA},
			})
			return
		}
		http.NotFound(w, r)
	})

	script := completionScript(t)
	results, stderr := runCompletionWithPreamble(t, script, completionPATHPreamble(t), []string{
		"docker-helper", "launcher", "scope", "set", "--endpoint", endpoint, "--token-file", tokenPath,
		"--principal", "alice", "--allowed-root", "",
	})
	if stderr != "" {
		t.Fatalf("policy completion must not write to stderr: %q", stderr)
	}
	if want := []string{rootA}; !slices.Equal(sortedTrimmed(results), want) {
		t.Errorf("anchors = %v, want %v", results, want)
	}
	requests.waitFor(t, 1)
	if got := requests.snapshot(); len(got) != 1 || got[0].path != "/principals/alice/effective-allowed-roots" {
		t.Fatalf("requests = %+v", got)
	}
}

// TestCompletionPolicySessionWorkspaceAnchors proves session create
// --workspace offers the Session-create policy roots as traversal anchors
// and that the query is the session policy query — the restricted
// Launcher's narrowed roots, not a Principal's wider scope. The anchor is
// the bare root: Bash's filename semantics append the directory separator
// on insertion, and a pre-slash-terminated candidate would risk a doubled
// separator on Bash versions that mark directories again.
func TestCompletionPolicySessionWorkspaceAnchors(t *testing.T) {
	base := t.TempDir()
	restricted := filepath.Join(base, "project-a")
	if err := os.MkdirAll(filepath.Join(restricted, "src"), 0755); err != nil {
		t.Fatal(err)
	}
	endpoint, tokenPath, requests := startCompletionPolicyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions/create-policy" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, sessionCreatePolicyResponse{
				OK: true, Principal: "alice", LauncherID: "dhl_x", Launcher: "agent",
				AllowedRoots: []string{restricted},
			})
			return
		}
		http.NotFound(w, r)
	})

	script := completionScript(t)
	results, stderr := runCompletionWithPreamble(t, script, completionPATHPreamble(t), []string{
		"docker-helper", "session", "create", "--endpoint", endpoint, "--token-file", tokenPath, "--workspace", "",
	})
	if stderr != "" {
		t.Fatalf("policy completion must not write to stderr: %q", stderr)
	}
	if len(results) != 1 || results[0] != restricted || strings.HasSuffix(results[0], "/") {
		t.Fatalf("workspace anchors = %v, want the restricted root bare (no trailing separator)", results)
	}
	requests.waitFor(t, 1)
	if got := requests.snapshot(); len(got) != 1 || got[0].path != "/sessions/create-policy" {
		t.Fatalf("requests = %+v, want exactly one session policy query", got)
	}

	// Inside the restricted root: its subdirectories are offered, and
	// everything offered stays inside the restricted root (the anchor
	// itself may re-appear as the traversal prefix).
	results, _ = runCompletionWithPreamble(t, script, completionPATHPreamble(t), []string{
		"docker-helper", "session", "create", "--endpoint", endpoint, "--token-file", tokenPath,
		"--workspace", restricted + "/",
	})
	trimmed := sortedTrimmed(results)
	if !slices.Contains(trimmed, filepath.Join(restricted, "src")) {
		t.Errorf("inside restricted root must offer its subdirectories, got %v", results)
	}
	for _, r := range trimmed {
		// The root itself may re-appear as the traversal anchor; everything
		// else must stay inside the restricted root.
		if r != restricted && !strings.HasPrefix(r, restricted+"/") {
			t.Errorf("inside restricted root must stay confined, got %q", r)
		}
	}
}

// TestCompletionPolicyOperatorFlagForwarding proves the generated forwarding
// helper collects every operator override form already typed on the command
// line as separate Bash array elements plus the typed --principal value, so
// the completion query targets the same daemon and token as the command
// being completed. The args travel end to end as arrays: no string
// round-trip, so values with spaces survive verbatim.
func TestCompletionPolicyOperatorFlagForwarding(t *testing.T) {
	script := completionScript(t)
	endpoint := "http://127.0.0.1:59999"
	spacey := "/tmp/path with spaces/token"

	var sb strings.Builder
	sb.WriteString(script)
	sb.WriteString("\n\n")
	sb.WriteString("COMP_WORDS=(docker-helper launcher create --system --endpoint " + endpoint +
		" --endpoint=" + endpoint + " --token-file '" + spacey + "' --token-file=/tmp/t2 --principal alice --principal bob)\n")
	sb.WriteString("COMP_CWORD=${#COMP_WORDS[@]}\n")
	sb.WriteString("mapfile -d '' -t opargs < <(_docker_helper_operator_args 'launcher create')\n")
	sb.WriteString("if [ ${#opargs[@]} -gt 0 ]; then printf 'ARG:%s\\n' \"${opargs[@]}\"; fi\n")
	sb.WriteString("echo \"principal=$(_docker_helper_typed_flag_value principal)\"\n")

	out, err := exec.Command("bash", "-c", sb.String()).CombinedOutput()
	if err != nil {
		t.Fatalf("harness failed: %v\n%s", err, out)
	}
	var got []string
	principalSeen := false
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch {
		case strings.HasPrefix(line, "ARG:"):
			got = append(got, strings.TrimPrefix(line, "ARG:"))
		case strings.HasPrefix(line, "principal="):
			principalSeen = true
			if line != "principal=bob" {
				t.Errorf("typed --principal must mirror flag parsing (last wins), got %q", line)
			}
		default:
			t.Errorf("unexpected harness line %q", line)
		}
	}
	if !principalSeen {
		t.Error("typed --principal line missing from harness output")
	}
	want := []string{
		"--system",
		"--endpoint", endpoint,
		"--endpoint=" + endpoint,
		"--token-file", spacey,
		"--token-file=/tmp/t2",
	}
	if !slices.Equal(got, want) {
		t.Errorf("forwarded operator args = %q, want %q", got, want)
	}
}

// TestCompletionPolicyForwardedEndpointForm proves the --endpoint=VALUE form
// reaches the same daemon: the inner query is issued through the forwarded
// endpoint and the token file forwarded from the typed line.
func TestCompletionPolicyForwardedEndpointForm(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "root-a")
	if err := os.MkdirAll(rootA, 0755); err != nil {
		t.Fatal(err)
	}
	endpoint, tokenPath, requests := startCompletionPolicyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want the forwarded token", got)
		}
		if r.URL.Path == "/principals/alice/effective-allowed-roots" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, effectiveRootsResponse{
				OK: true, Principal: "alice", AllowedRoots: []string{rootA},
			})
			return
		}
		http.NotFound(w, r)
	})

	script := completionScript(t)
	results, stderr := runCompletionWithPreamble(t, script, completionPATHPreamble(t), []string{
		"docker-helper", "launcher", "create", "--endpoint=" + endpoint, "--token-file=" + tokenPath,
		"--principal=alice", "--allowed-root", "",
	})
	if stderr != "" {
		t.Fatalf("policy completion must not write to stderr: %q", stderr)
	}
	if want := []string{rootA}; !slices.Equal(sortedTrimmed(results), want) {
		t.Errorf("anchors = %v, want %v", results, want)
	}
	requests.waitFor(t, 1)
	if got := requests.snapshot(); len(got) != 1 {
		t.Fatalf("requests = %+v, want exactly one query", got)
	}
}

// TestCompletionPolicyForwardedValueWithSpaces proves the removed string
// round-trip end to end: operator values containing spaces typed on the
// command line — a --token-file path with spaces, and a Unix endpoint socket
// path with a space — reach the daemon as single arguments (the query
// authenticates and answers), and the returned roots are suggested.
func TestCompletionPolicyForwardedValueWithSpaces(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "root-a")
	if err := os.MkdirAll(rootA, 0755); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(base, "tok en file")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}

	respond := func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want the forwarded token", got)
		}
		if r.URL.Path == "/principals/alice/effective-allowed-roots" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, effectiveRootsResponse{
				OK: true, Principal: "alice", AllowedRoots: []string{rootA},
			})
			return
		}
		http.NotFound(w, r)
	}
	script := completionScript(t)

	t.Run("token file path with spaces", func(t *testing.T) {
		endpoint, _, _ := startCompletionPolicyServer(t, respond)
		words := []string{"docker-helper", "launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath, "--principal", "alice", "--allowed-root", ""}
		results, stderr := runCompletionWithPreamble(t, script, completionPATHPreamble(t), words)
		if stderr != "" {
			t.Fatalf("policy completion must not write to stderr: %q", stderr)
		}
		if want := []string{rootA}; !slices.Equal(sortedTrimmed(results), want) {
			t.Errorf("anchors = %v, want %v", results, want)
		}
	})

	t.Run("unix socket path with spaces", func(t *testing.T) {
		sockPath := filepath.Join(base, "dh sp ace.sock")
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(respond)}
		go srv.Serve(ln)
		t.Cleanup(func() {
			srv.Close()
			ln.Close()
		})

		words := []string{"docker-helper", "launcher", "create", "--endpoint", sockPath, "--token-file", tokenPath, "--principal", "alice", "--allowed-root", ""}
		results, stderr := runCompletionWithPreamble(t, script, completionPATHPreamble(t), words)
		if stderr != "" {
			t.Fatalf("policy completion must not write to stderr: %q", stderr)
		}
		if want := []string{rootA}; !slices.Equal(sortedTrimmed(results), want) {
			t.Errorf("anchors = %v, want %v", results, want)
		}
	})
}

// TestCompletionPolicyGracefulDegradation proves the failure contract: when
// the daemon query fails (unreachable daemon or rejected bearer), completion
// degrades silently to the generic filesystem completion — no stderr
// pollution, sentinels offered again.
func TestCompletionPolicyGracefulDegradation(t *testing.T) {
	base := t.TempDir()
	sentinel := filepath.Join(base, "sentinel-file")
	if err := os.WriteFile(sentinel, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	preamble := completionPATHPreamble(t) + "; cd " + base

	script := completionScript(t)
	for _, tc := range []struct {
		name     string
		endpoint string
		token    string
	}{
		{"unreachable daemon", "http://127.0.0.1:1", "unused"},
		{"rejected bearer", "rejected", "unused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var endpoint, tokenPath string
			if tc.endpoint == "rejected" {
				endpoint, tokenPath, _ = startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
					writeJSONResponse(w, http.StatusUnauthorized, map[string]any{
						"ok": false, "code": "unauthorized", "message": "no",
					})
				})
			} else {
				endpoint, tokenPath = tc.endpoint, t.TempDir()+"/tok"
				if err := os.WriteFile(tokenPath, []byte("tok"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			results, stderr := runCompletionWithPreamble(t, script, preamble, []string{
				"docker-helper", "launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath,
				"--principal", "alice", "--allowed-root", "sent",
			})
			if stderr != "" {
				t.Fatalf("degraded completion must not write to stderr: %q", stderr)
			}
			if want := []string{"sentinel-file"}; !slices.Equal(results, want) {
				t.Errorf("filesystem fallback = %v, want %v", results, want)
			}
		})
	}
}

// TestCompletionPolicyHangingDaemonBoundedFallback proves the machine-facing
// completion query cannot stall the shell: a daemon that accepts the
// connection but never answers makes the helper exit non-zero within the
// bounded completion query timeout, the generated Bash degrades silently to
// the generic filesystem completion, and nothing reaches stderr.
func TestCompletionPolicyHangingDaemonBoundedFallback(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "sentinel-dir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "sentinel-file"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(base, "tok")
	if err := os.WriteFile(tokenPath, []byte("tok"), 0600); err != nil {
		t.Fatal(err)
	}

	// HTTP server that accepts requests but never answers: the exact
	// accept-but-hang failure mode the completion query timeout exists for.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan struct{}, 8)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- struct{}{}
		<-r.Context().Done()
	})}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		ln.Close()
	})
	endpoint := "http://" + ln.Addr().String()

	script := completionScript(t)
	preamble := completionPATHPreamble(t) + "; cd " + base

	start := time.Now()
	results, stderr, harnessErr := runCompletionWithDeadline(t, script, preamble, []string{
		"docker-helper", "launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath,
		"--principal", "alice", "--allowed-root", "",
	}, 15*time.Second)
	elapsed := time.Since(start)

	if harnessErr != nil {
		t.Fatalf("completion did not terminate on its own (elapsed %s): %v", elapsed, harnessErr)
	}
	if elapsed > 10*completionQueryTimeout {
		t.Errorf("completion took %s, want bounded by the query timeout (<= %s)", elapsed, 10*completionQueryTimeout)
	}
	// The query reached the hanging daemon, so the bound was genuinely
	// exercised: dial and request succeeded, only the answer was withheld.
	select {
	case <-requests:
	case <-time.After(5 * time.Second):
		t.Error("the hanging daemon never received the query; the bound was not exercised")
	}
	if stderr != "" {
		t.Errorf("degraded completion must not write to stderr: %q", stderr)
	}
	if !slices.Contains(results, "sentinel-file") {
		t.Errorf("fallback to generic filesystem completion missing sentinel-file, got %v", results)
	}
}

// TestCompletionPolicyOwnPrincipalInference proves the bash-side path where
// no --principal is typed: the generated script re-invokes docker-helper,
// which infers the caller's own Principal via GET /auth (the same rule the
// launcher command family uses) and queries the effective roots.
func TestCompletionPolicyOwnPrincipalInference(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "root-a")
	if err := os.MkdirAll(rootA, 0755); err != nil {
		t.Fatal(err)
	}
	endpoint, tokenPath, requests := startCompletionPolicyServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
		case r.URL.Path == "/principals/alice/effective-allowed-roots" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, effectiveRootsResponse{
				OK: true, Principal: "alice", AllowedRoots: []string{rootA},
			})
		default:
			http.NotFound(w, r)
		}
	})

	script := completionScript(t)
	results, stderr := runCompletionWithPreamble(t, script, completionPATHPreamble(t), []string{
		"docker-helper", "launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath,
		"--allowed-root", "",
	})
	if stderr != "" {
		t.Fatalf("policy completion must not write to stderr: %q", stderr)
	}
	if want := []string{rootA}; !slices.Equal(sortedTrimmed(results), want) {
		t.Errorf("anchors = %v, want %v", results, want)
	}
	requests.waitFor(t, 2)
	if got := requests.snapshot(); len(got) != 2 || got[0].path != "/auth" || got[1].path != "/principals/alice/effective-allowed-roots" {
		t.Fatalf("requests = %+v, want /auth then effective-roots", got)
	}
}

// policyQueryRecorder records the requests the bash-driven CLI queries make
// against the harness mock daemon. The completion harness runs the CLI as a
// child process, so request arrival is observable only through the server:
// the seen channel gives tests a deterministic arrival signal and the mutex
// keeps the recorder's slice race-free across process boundaries.
type policyQueryRecorder struct {
	mu       sync.Mutex
	requests []recordedRequest
	seen     chan recordedRequest
}

func (r *policyQueryRecorder) record(req recordedRequest) {
	r.mu.Lock()
	r.requests = append(r.requests, req)
	r.mu.Unlock()
	r.seen <- req
}

func (r *policyQueryRecorder) snapshot() []recordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedRequest{}, r.requests...)
}

// waitFor blocks until n requests have arrived, with an explicit deadline so
// a query that never happens fails the test instead of hanging it.
func (r *policyQueryRecorder) waitFor(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-r.seen:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d expected requests arrived", i, n)
		}
	}
}

// startCompletionPolicyServer is the harness mock daemon for bash-driven
// completion queries: it records every request through policyQueryRecorder
// and answers via the given responder.
func startCompletionPolicyServer(t *testing.T, respond func(w http.ResponseWriter, r *http.Request)) (string, string, *policyQueryRecorder) {
	t.Helper()
	rec := &policyQueryRecorder{seen: make(chan recordedRequest, 32)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(recordedRequest{r.Method, r.URL.Path, "", r.URL.RawQuery})
		respond(w, r)
	}))
	t.Cleanup(server.Close)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return server.URL, tokenPath, rec
}
