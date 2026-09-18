package main

import (
	"flag"
	"strings"
	"testing"
)

// TestCommandTreePresentationContract is the project-wide regression gate for
// the canonical CLI presentation architecture. Every leaf declares its
// presentation contract on Command itself: finite results declare the
// human-default + explicit --json mode; true non-result surfaces declare an
// exception with the reason colocated with the command. An unspecified leaf
// is always an error, so new Release 3 commands cannot silently inherit a
// presentation convention.
func TestCommandTreePresentationContract(t *testing.T) {
	for _, path := range walkCommandPaths(rootCommand, nil) {
		cmd, _ := rootCommand.resolveCommandPath(path)
		if cmd == nil {
			continue
		}
		joined := strings.Join(path, " ")

		if cmd.NewInvocation == nil {
			if cmd.Presentation.Mode != presentationUnspecified || cmd.Presentation.Reason != "" {
				t.Errorf("branch command %q must not declare leaf presentation metadata", joined)
			}
			continue
		}

		fs := flag.NewFlagSet("presentation-contract", flag.ContinueOnError)
		cmd.NewInvocation(fs)
		hasJSON := fs.Lookup("json") != nil
		usageHasJSON := strings.Contains(cmd.Usage, "--json")

		switch cmd.Presentation.Mode {
		case presentationHumanDefaultJSON:
			if cmd.Presentation.Reason != "" {
				t.Errorf("finite-result command %q declares an exception reason in human+json mode: %q", joined, cmd.Presentation.Reason)
			}
			if !hasJSON {
				t.Errorf("finite-result command %q declares human-default + --json but registers no --json flag", joined)
			}
			if !usageHasJSON {
				t.Errorf("finite-result command %q declares human-default + --json but Usage omits --json: %s", joined, cmd.Usage)
			}
		case presentationException:
			if strings.TrimSpace(cmd.Presentation.Reason) == "" {
				t.Errorf("presentation exception %q must declare its semantic reason next to the command", joined)
			}
			if hasJSON {
				t.Errorf("presentation exception %q (%s) registers --json; make it a finite-result command or remove the flag", joined, cmd.Presentation.Reason)
			}
			if usageHasJSON {
				t.Errorf("presentation exception %q (%s) advertises --json in Usage without registering it", joined, cmd.Presentation.Reason)
			}
		case presentationUnspecified:
			t.Errorf("leaf command %q has no declarative presentation contract", joined)
		default:
			t.Errorf("leaf command %q has unknown presentation mode %d", joined, cmd.Presentation.Mode)
		}
	}
}
