package main

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// runCompletionEntrypoint invokes the actually registered completion entrypoint
// with a shell-function compopt seam. This observes whether the compspec enables
// Readline filename semantics; COMPREPLY alone cannot expose Bash's automatic
// trailing-space decision.
func runCompletionEntrypoint(t *testing.T, script string, compWords []string) (reply []string, filenameMode bool) {
	t.Helper()
	cword := len(compWords) - 1
	var sb strings.Builder
	sb.WriteString(script)
	sb.WriteString("\ncompopt() { if [ \"$1\" = -o ] && [ \"$2\" = filenames ]; then DH_FILENAME_MODE=1; fi; }\n")
	sb.WriteString("DH_FILENAME_MODE=0\n")
	sb.WriteString("COMP_WORDS=(")
	for _, w := range compWords {
		sb.WriteString(" '")
		sb.WriteString(strings.ReplaceAll(w, "'", "'\\''"))
		sb.WriteString("'")
	}
	sb.WriteString(")\n")
	sb.WriteString("COMP_CWORD=" + strconv.Itoa(cword) + "\n")
	sb.WriteString("COMPREPLY=()\n")
	sb.WriteString("_docker_helper_completion_entrypoint\n")
	sb.WriteString("printf 'MODE=%s\\n' \"$DH_FILENAME_MODE\"\n")
	sb.WriteString("printf 'REPLY=%s\\n' \"${COMPREPLY[*]}\"\n")

	out, err := exec.Command("bash", "-c", sb.String()).CombinedOutput()
	if err != nil {
		t.Fatalf("completion entrypoint failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch {
		case line == "MODE=1":
			filenameMode = true
		case strings.HasPrefix(line, "REPLY="):
			value := strings.TrimPrefix(line, "REPLY=")
			if value != "" {
				reply = strings.Fields(value)
			}
		}
	}
	return reply, filenameMode
}

func TestCompletionPathFlagsEnableFilenameSemantics(t *testing.T) {
	script := completionScript(t)
	for _, words := range [][]string{
		{"docker-helper", "session", "create", "--workspace", "/home/michael/"},
		{"docker-helper", "launcher", "create", "--allowed-root", "/home/michael/"},
		{"docker-helper", "launcher", "scope", "set", "--allowed-root", "/home/michael/"},
		{"docker-helper", "config", "set", "trusted_ca_path", "/etc/ssl/"},
		{"docker-helper", "session", "create", "--workspace=/home/michael/"},
	} {
		t.Run(strings.Join(words[1:], " "), func(t *testing.T) {
			_, filenameMode := runCompletionEntrypoint(t, script, words)
			if !filenameMode {
				t.Fatalf("path-valued completion did not enable filename semantics: %v", words)
			}
		})
	}
}

func TestCompletionNonPathFlagDoesNotForceFilenameSemantics(t *testing.T) {
	script := completionScript(t)
	_, filenameMode := runCompletionEntrypoint(t, script,
		[]string{"docker-helper", "launcher", "list", "--principal", "michael"})
	if filenameMode {
		t.Fatal("non-path flag unexpectedly enabled filename semantics")
	}
}

func TestCompletionAuthorityHelperHiddenFromSuggestions(t *testing.T) {
	if !completionAvailabilityByCommand[completionAuthorityCommand].Hidden {
		t.Fatal("completion authority must be hidden UI metadata")
	}
	results := runCompletion(t, completionScript(t), []string{"docker-helper", "completion", ""})
	if strings.Contains(" "+strings.Join(results, " ")+" ", " authority ") {
		t.Fatalf("machine-facing authority helper leaked into completion: %v", results)
	}
	for _, want := range []string{"bash", "roots"} {
		found := false
		for _, got := range results {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("completion suggestions %v missing %q", results, want)
		}
	}
}
