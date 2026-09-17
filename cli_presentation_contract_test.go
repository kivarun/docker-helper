package main

import (
	"flag"
	"strings"
	"testing"
)

// jsonPresentationExceptions is the complete, explicitly reviewed registry of
// leaf commands outside the canonical two-mode presentation contract
// (default human-readable result, --json structured result). Every other
// finite-result leaf command must register --json. The registry is
// intentionally small; a new command without --json fails the contract test
// unless it is added here with its reason.
var jsonPresentationExceptions = map[string]string{
	// Streams: stdout/stderr carry execution/progress/workload data, not one
	// result renderer; the final status is the exit code.
	"pull":  "stream: pull progress data, not one result renderer",
	"build": "stream: build log stream, not one result renderer",
	"run":   "stream: workload output stream, not one result renderer",

	// Protocol/generator output: stdout itself is the generated artifact or
	// the machine-line protocol.
	"completion bash":                "generator: stdout is the generated completion script",
	"completion roots principal":     "machine-line protocol: one path per line for shell completion",
	"completion roots session":       "machine-line protocol: one path per line for shell completion",
	"completion roots launcher":      "machine-line protocol: one path per line for shell completion",
	"completion selectors principal": "machine-line protocol: one selector per line for shell completion",
	"completion selectors launcher":  "machine-line protocol: one selector per line for shell completion",

	// Navigation/documentation.
	"help": "navigation: prints help text, not a command result",

	// Process command: a long-running daemon, not a finite result.
	"serve": "process: the daemon itself, not a finite result",

	// Interactive workflow: an interactive setup wizard whose one-shot
	// disclosure contract (admin token) predates the presentation contract.
	"init": "interactive setup workflow with one-time admin-token disclosure",
}

// TestCommandTreeJSONPresentationContract is the project-wide regression gate
// for the canonical CLI presentation contract: every finite-result leaf
// command registers --json, and the only exceptions are the explicitly
// reviewed registry above. A future command that silently omits --json (or
// an accidental removal from an existing command) fails here.
func TestCommandTreeJSONPresentationContract(t *testing.T) {
	for _, path := range walkCommandPaths(rootCommand, nil) {
		cmd, _ := rootCommand.resolveCommandPath(path)
		if cmd == nil || cmd.NewInvocation == nil {
			// Branch commands produce no output themselves.
			continue
		}
		joined := strings.Join(path, " ")
		reason, exempt := jsonPresentationExceptions[joined]
		fs := flag.NewFlagSet("presentation-contract", flag.ContinueOnError)
		cmd.NewInvocation(fs)
		hasJSON := fs.Lookup("json") != nil
		if exempt {
			if hasJSON {
				t.Errorf("command %q is a registered exception (%s) but registers --json; remove it from the registry or drop the flag", joined, reason)
			}
			continue
		}
		if !hasJSON {
			t.Errorf("leaf command %q registers no --json flag: every finite-result command must offer the two-mode presentation contract (human default, explicit --json) or be added to the exception registry with a reason", joined)
		}
	}
}

// TestJSONPresentationExceptionRegistryIsExact guards the registry against
// silent rot: every registered exception must still be a leaf command of the
// tree, so a removed command cannot linger in the registry unnoticed.
func TestJSONPresentationExceptionRegistryIsExact(t *testing.T) {
	leaves := map[string]bool{}
	for _, path := range walkCommandPaths(rootCommand, nil) {
		cmd, _ := rootCommand.resolveCommandPath(path)
		if cmd == nil || cmd.NewInvocation == nil {
			continue
		}
		leaves[strings.Join(path, " ")] = true
	}
	for joined := range jsonPresentationExceptions {
		if !leaves[joined] {
			t.Errorf("exception registry entry %q is not a leaf command of the tree", joined)
		}
	}
}
