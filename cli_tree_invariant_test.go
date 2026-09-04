package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// walkCommandPaths returns every registered command path (including each
// top-level command and every nested subcommand) from the parser tree.
func walkCommandPaths(cmd *Command, prefix []string) [][]string {
	var paths [][]string
	for _, sub := range cmd.Subcommands {
		path := append(append([]string{}, prefix...), sub.Name)
		paths = append(paths, path)
		paths = append(paths, walkCommandPaths(sub, path)...)
	}
	return paths
}

// TestCompletionTreeMatchesParser proves parser tree == completion tree:
//
//   - every registered command path appears verbatim in the generated
//     completion script's _docker_helper_is_command case list;
//   - every branch path's _docker_helper_subcommands entry lists exactly the
//     registered subcommand names.
//
// A completion-only drift (hard-coded stale tree) or a registered command
// missing from completion fails this test.
func TestCompletionTreeMatchesParser(t *testing.T) {
	script := completionScript(t)
	paths := walkCommandPaths(rootCommand, nil)
	if len(paths) == 0 {
		t.Fatal("parser tree has no commands")
	}

	for _, path := range paths {
		joined := strings.Join(path, " ")
		if !strings.Contains(script, "\""+joined+"\") return 0 ;;") {
			t.Errorf("registered command %q missing from completion _docker_helper_is_command", joined)
		}
	}

	// Branch paths must list exactly the registered subcommands.
	for _, path := range paths {
		cmd := completionCommandPath(path)
		if cmd == nil || len(cmd.Subcommands) == 0 {
			continue
		}
		joined := strings.Join(path, " ")
		var want []string
		for _, sub := range cmd.Subcommands {
			want = append(want, sub.Name)
		}
		line := "\"" + joined + "\") echo \"" + strings.Join(want, " ") + "\" ;;"
		if !strings.Contains(script, line) {
			t.Errorf("completion subcommand drift for %q: expected line %q in script", joined, line)
		}
	}

	// Reverse direction: every subcommands case label must resolve in the
	// parser tree (no hard-coded completion-only commands).
	subsection := script[strings.Index(script, "_docker_helper_subcommands() {"):]
	subsection = subsection[:strings.Index(subsection, "\n}")]
	re := regexp.MustCompile(`"([^"]*)"\) echo "`)
	for _, m := range re.FindAllStringSubmatch(subsection, -1) {
		label := m[1]
		if label == "" {
			continue
		}
		if completionCommandPath(strings.Split(label, " ")) == nil {
			t.Errorf("completion lists unknown command path %q", label)
		}
	}
}

// TestHelpTreeMatchesParser proves parser tree == help tree: for every
// registered command path, `docker-helper help <path...>` output equals
// `docker-helper <path...> --help` output and exits 0. A help-only or
// parser-only drift anywhere in the tree fails this test.
func TestHelpTreeMatchesParser(t *testing.T) {
	paths := walkCommandPaths(rootCommand, nil)
	for _, path := range paths {
		helpArgs := append([]string{"help"}, path...)
		flagArgs := append(append([]string{}, path...), "--help")

		var helpOut, helpErr, flagOut, flagErr bytes.Buffer
		helpCode := runCommandWithWriters(helpArgs, &helpOut, &helpErr)
		flagCode := runCommandWithWriters(flagArgs, &flagOut, &flagErr)

		joined := strings.Join(path, " ")
		if helpCode != 0 {
			t.Errorf("help %s: exit %d, stderr=%s", joined, helpCode, helpErr.String())
			continue
		}
		if flagCode != 0 {
			t.Errorf("%s --help: exit %d, stderr=%s", joined, flagCode, flagErr.String())
			continue
		}
		if helpOut.String() != flagOut.String() {
			t.Errorf("help vs --help mismatch for %q\nhelp: %q\nflag: %q", joined, helpOut.String(), flagOut.String())
		}
	}
}

// TestCompletionRootSubcommandsExactOrder pins the canonical top-level
// completion list: adding or removing a top-level command changes this list
// and must be an explicit, reviewed decision.
func TestCompletionRootSubcommandsExactOrder(t *testing.T) {
	script := completionScript(t)
	var want []string
	for _, sub := range rootCommand.Subcommands {
		want = append(want, sub.Name)
	}
	if !strings.Contains(script, "\"\") echo \""+strings.Join(want, " ")+"\" ;;") {
		t.Errorf("root completion list drifted: want %v", want)
	}
}

// TestWalkCommandPathsUnique guards the walker itself: paths are unique and
// sufficiently numerous so the tree assertions above cannot silently pass on
// a partially walked tree.
func TestWalkCommandPathsUnique(t *testing.T) {
	paths := walkCommandPaths(rootCommand, nil)
	seen := make(map[string]bool)
	for _, p := range paths {
		s := strings.Join(p, " ")
		if seen[s] {
			t.Fatalf("duplicate path %q", s)
		}
		seen[s] = true
	}
	if len(seen) < 20 {
		t.Fatalf("only %d paths walked; tree walk is incomplete", len(seen))
	}
}
