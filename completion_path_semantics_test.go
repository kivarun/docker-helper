package main

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// TestCompletionAuthorityQueryReusesExistingTree protects the structural
// invariant that parser tree == help tree == completion tree. Authority
// introspection reuses the existing machine-facing `completion roots
// principal` surface with --authority-only; a hidden `completion authority`
// node would violate the invariant and must never exist.
func TestCompletionAuthorityQueryReusesExistingTree(t *testing.T) {
	completion := completionCommandPath([]string{"completion"})
	if completion == nil {
		t.Fatal("completion command missing from parser tree")
	}
	for _, sub := range completion.Subcommands {
		if sub.Name == "authority" {
			t.Fatal("hidden completion authority node must not exist in the parser tree")
		}
	}
	flags := collectFlagsForCommand(completionRootsPrincipalCommand)
	if !slices.Contains(flags, "--authority-only") {
		t.Fatalf("completion roots principal flags %v missing --authority-only", flags)
	}
	results := runCompletion(t, completionScript(t), []string{"docker-helper", "completion", ""})
	if strings.Contains(" "+strings.Join(results, " ")+" ", " authority ") {
		t.Fatalf("machine-facing authority helper leaked into completion: %v", results)
	}
	for _, want := range []string{"bash", "roots"} {
		if !slices.Contains(results, want) {
			t.Fatalf("completion suggestions %v missing %q", results, want)
		}
	}
}

// startPolicyRootsServer starts a stub daemon serving the Session-create
// policy query with the given allowed root, and returns the endpoint and
// token path for the completion harness.
func startPolicyRootsServer(t *testing.T, root string) (endpoint, tokenPath string) {
	t.Helper()
	endpoint, tokenPath, _ = startCompletionPolicyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions/create-policy" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, sessionCreatePolicyResponse{
				OK: true, Principal: "alice", LauncherID: "dhl_x", Launcher: "agent",
				AllowedRoots: []string{root},
			})
			return
		}
		http.NotFound(w, r)
	})
	return endpoint, tokenPath
}

// TestCompletionPolicyWorkspaceDoubledSeparatorNotPropagated protects the
// reported completion defect: completing a workspace word that already
// carries a doubled separator (typed, or produced by an earlier completion)
// must not hand Bash a candidate that carries it into the completed word.
// Bash joins a directory prefix ending in a separator with directory
// entries verbatim, so an unnormalized candidate would surface as for
// example /home/michael/work//git/. The regression is driven through the
// actually registered completion entrypoint with the filename-semantics
// seam, so it proves the path-value stage was reached rather than failing
// earlier with no candidates.
func TestCompletionPolicyWorkspaceDoubledSeparatorNotPropagated(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "work")
	if err := os.MkdirAll(filepath.Join(root, "git"), 0755); err != nil {
		t.Fatal(err)
	}
	endpoint, tokenPath := startPolicyRootsServer(t, root)

	script := completionPATHPreamble(t) + "\n" + completionScript(t)
	reply, filenameMode := runCompletionEntrypoint(t, script, []string{
		"docker-helper", "session", "create", "--endpoint", endpoint, "--token-file", tokenPath,
		"--workspace", root + "//",
	})
	if !filenameMode {
		t.Fatal("path-valued completion did not enable filename semantics")
	}
	if len(reply) == 0 {
		t.Fatal("no candidates produced; the doubled-separator stage was not reached")
	}
	for _, r := range reply {
		if strings.Contains(r, "//") {
			t.Errorf("candidate %q carries a doubled separator into the completed word", r)
		}
	}
	if want := filepath.Join(root, "git"); !slices.Contains(reply, want) {
		t.Errorf("candidates = %v, want the in-root child %q", reply, want)
	}
}

// TestCompletionPolicyAnchorsNotPreSlashTerminated protects the other half
// of the doubled-separator defect: the completion script never emits a
// directory candidate that already ends in a separator. Bash's filename
// semantics append the separator for a directory itself, so a
// pre-terminated candidate could receive a second separator on Bash
// versions that mark directories again, leaving the word with a doubled
// separator that later completion steps then propagate.
func TestCompletionPolicyAnchorsNotPreSlashTerminated(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "work")
	if err := os.MkdirAll(filepath.Join(root, "git"), 0755); err != nil {
		t.Fatal(err)
	}
	endpoint, tokenPath := startPolicyRootsServer(t, root)

	script := completionPATHPreamble(t) + "\n" + completionScript(t)
	reply, _ := runCompletionEntrypoint(t, script, []string{
		"docker-helper", "session", "create", "--endpoint", endpoint, "--token-file", tokenPath,
		"--workspace", root,
	})
	if len(reply) == 0 {
		t.Fatal("no candidates produced; the anchor stage was not reached")
	}
	if !slices.Contains(reply, root) {
		t.Errorf("candidates = %v, want the policy root %q as an anchor", reply, root)
	}
	for _, r := range reply {
		if strings.HasSuffix(r, "/") {
			t.Errorf("candidate %q is pre-slash-terminated; Bash must add the directory separator itself", r)
		}
	}
}
