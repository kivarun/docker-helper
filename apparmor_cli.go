package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

var appArmorCommand = &Command{
	Name:    "apparmor",
	Summary: "Inspect managed AppArmor MAC boundaries (system mode)",
	Subcommands: []*Command{
		appArmorRootCommand,
		appArmorCheckCommand,
	},
}

var appArmorRootCommand = &Command{
	Name:    "root",
	Summary: "Inspect managed AppArmor MAC boundaries",
	Subcommands: []*Command{
		appArmorRootListCommand,
	},
}

var appArmorRootListCommand = &Command{
	Name:    "list",
	Summary: "List managed AppArmor MAC boundaries",
	Usage:   "docker-helper apparmor root list [--json]",

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runAppArmorRootList(stdout, stderr, *jsonOut)
			},
		}
	},
}

var appArmorCheckCommand = &Command{
	Name:    "check",
	Summary: "Validate the AppArmor profile",
	Usage:   "docker-helper apparmor check [--json]",

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runAppArmorCheck(stdout, stderr, *jsonOut)
			},
		}
	},
}

func requireRoot() error {
	if EffectiveUID() != 0 {
		return errors.New("this command requires root (effective UID 0)")
	}
	return nil
}

func runAppArmorRootList(stdout, stderr io.Writer, jsonOut bool) int {
	if err := requireRoot(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	mgr := newProductionAppArmorProfileManager()
	boundaries, err := mgr.listManagedBoundaries()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	if jsonOut {
		if err := encodeJSONOut(stdout, boundaries); err != nil {
			fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
			return 1
		}
		return 0
	}

	for _, boundary := range boundaries {
		fmt.Fprintln(stdout, boundary)
	}

	return 0
}

func runAppArmorCheck(stdout, stderr io.Writer, jsonOut bool) int {
	if err := requireRoot(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := requireAppArmorActive(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	mgr := newProductionAppArmorProfileManager()
	checkCtx, cancel := newMACTransitionContext()
	defer cancel()
	if err := mgr.check(checkCtx); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	if jsonOut {
		if err := encodeJSONOut(stdout, policyCheckResult{Valid: true}); err != nil {
			fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintln(stdout, "AppArmor profile valid")
	return 0
}

// policyCheckResult is the CLI-owned --json shape of the MAC policy check
// diagnostics: the valid fact the human status line reports. The exit code
// carries failure; a failed check prints no result.
type policyCheckResult struct {
	Valid bool `json:"valid"`
}
