package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

var apparmorCommand = &Command{
	Name:    "apparmor",
	Summary: "Manage AppArmor workspace roots (system mode)",
	Subcommands: []*Command{
		apparmorRootCommand,
		apparmorCheckCommand,
	},
}

var apparmorRootCommand = &Command{
	Name:    "root",
	Summary: "Manage workspace roots in the AppArmor profile",
	Subcommands: []*Command{
		apparmorRootListCommand,
		apparmorRootAddCommand,
		apparmorRootRemoveCommand,
	},
}

var apparmorRootListCommand = &Command{
	Name:    "list",
	Summary: "List managed workspace roots",
	Usage:   "docker-helper apparmor root list",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runApparmorRootList(stdout, stderr)
			},
		}
	},
}

var apparmorRootAddCommand = &Command{
	Name:       "add",
	Summary:    "Add a workspace root to the AppArmor profile",
	Usage:      "docker-helper apparmor root add PATH",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runApparmorRootAdd(fs.Args()[0], stdout, stderr)
			},
		}
	},
}

var apparmorRootRemoveCommand = &Command{
	Name:       "remove",
	Summary:    "Remove a workspace root from the AppArmor profile",
	Usage:      "docker-helper apparmor root remove PATH",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runApparmorRootRemove(fs.Args()[0], stdout, stderr)
			},
		}
	},
}

var apparmorCheckCommand = &Command{
	Name:    "check",
	Summary: "Validate the AppArmor profile",
	Usage:   "docker-helper apparmor check",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runApparmorCheck(stdout, stderr)
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

func newProductionApparmorManager() *apparmorManager {
	return newApparmorManager(
		apparmorMainProfile,
		apparmorManagedFragment,
		apparmorLockPath,
		apparmorParserPath,
		newProductionParserRunner(),
	)
}

func runApparmorRootList(stdout, stderr io.Writer) int {
	if err := requireRoot(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := requireAppArmorActive(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	mgr := newProductionApparmorManager()
	roots, err := mgr.listRoots()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	for _, root := range roots {
		fmt.Fprintln(stdout, root)
	}

	return 0
}

func runApparmorRootAdd(path string, stdout, stderr io.Writer) int {
	if err := requireRoot(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := requireAppArmorActive(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	mgr := newProductionApparmorManager()
	result, err := mgr.addRoot(path)
	if err != nil {
		var ie *inputError
		if errors.As(err, &ie) {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	if result.Changed {
		fmt.Fprintf(stdout, "added %s\n", result.Path)
	} else {
		fmt.Fprintf(stdout, "already present %s\n", result.Path)
	}
	return 0
}

func runApparmorRootRemove(path string, stdout, stderr io.Writer) int {
	if err := requireRoot(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := requireAppArmorActive(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	mgr := newProductionApparmorManager()
	result, err := mgr.removeRoot(path)
	if err != nil {
		var ie *inputError
		if errors.As(err, &ie) {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	if result.Changed {
		fmt.Fprintf(stdout, "removed %s\n", result.Path)
	} else {
		fmt.Fprintf(stdout, "not present %s\n", result.Path)
	}
	return 0
}

func runApparmorCheck(stdout, stderr io.Writer) int {
	if err := requireRoot(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := requireAppArmorActive(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	mgr := newProductionApparmorManager()
	if err := mgr.check(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "AppArmor profile valid")
	return 0
}
