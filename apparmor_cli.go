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
	Usage:   "docker-helper apparmor root list",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runAppArmorRootList(stdout, stderr)
			},
		}
	},
}

var appArmorCheckCommand = &Command{
	Name:    "check",
	Summary: "Validate the AppArmor profile",
	Usage:   "docker-helper apparmor check",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runAppArmorCheck(stdout, stderr)
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

func runAppArmorRootList(stdout, stderr io.Writer) int {
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

	for _, boundary := range boundaries {
		fmt.Fprintln(stdout, boundary)
	}

	return 0
}

func runAppArmorCheck(stdout, stderr io.Writer) int {
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

	fmt.Fprintln(stdout, "AppArmor profile valid")
	return 0
}
