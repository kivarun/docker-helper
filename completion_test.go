package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// getCompletionBinary returns the path to a docker-helper binary for testing.
func getCompletionBinary(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "docker-helper")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build docker-helper: %v\n%s", err, out)
	}
	return binPath
}

func completionScript(t *testing.T) string {
	t.Helper()
	binPath := getCompletionBinary(t)
	cmd := exec.Command(binPath, "completion", "bash")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker-helper completion bash failed: %v\n%s", err, out)
	}
	return string(out)
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
	sb.WriteString("COMP_CWORD=" + string(rune('0'+cword)) + "\n")
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
	script1 := completionScript(t)
	script2 := completionScript(t)
	if script1 != script2 {
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
	results := runCompletion(t, script, []string{"docker-helper", "admin", "token", ""})
	if len(results) == 0 {
		t.Error("expected admin token subcommand completions")
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
		t.Errorf("expected 'rotate' in admin token completions: %v", results)
	}
}

func TestCompletionLeafFlags(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "principal", "create", "-"})
	if len(results) == 0 {
		t.Error("expected flag completions for principal create")
		return
	}
	expected := []string{"--system", "--endpoint", "--token-file", "-h", "--help"}
	resultsMap := make(map[string]bool)
	for _, r := range results {
		resultsMap[r] = true
	}
	for _, exp := range expected {
		if !resultsMap[exp] {
			t.Errorf("expected flag %q not found in completions: %v", exp, results)
		}
	}
}

func TestCompletionHelpFlags(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "principal", "create", "-"})
	if len(results) == 0 {
		t.Error("expected flag completions for -")
		return
	}
	foundHelp := false
	foundH := false
	for _, r := range results {
		if r == "--help" {
			foundHelp = true
		}
		if r == "-h" {
			foundH = true
		}
	}
	if !foundHelp {
		t.Error("expected --help in flag completions")
	}
	if !foundH {
		t.Error("expected -h in flag completions")
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
	expected := []string{"allowed_root", "session_ttl", "log_level", "audit_enabled"}
	resultsMap := make(map[string]bool)
	for _, r := range results {
		resultsMap[r] = true
	}
	for _, exp := range expected {
		if !resultsMap[exp] {
			t.Errorf("expected config show field %q not found: %v", exp, results)
		}
	}
}

func TestCompletionConfigSetFields(t *testing.T) {
	script := completionScript(t)
	results := runCompletion(t, script, []string{"docker-helper", "config", "set", ""})
	if len(results) == 0 {
		t.Error("expected config set field completions")
		return
	}
	expected := []string{"allowed_root", "session_ttl", "log_level", "audit_enabled"}
	resultsMap := make(map[string]bool)
	for _, r := range results {
		resultsMap[r] = true
	}
	for _, exp := range expected {
		if !resultsMap[exp] {
			t.Errorf("expected config set field %q not found: %v", exp, results)
		}
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
