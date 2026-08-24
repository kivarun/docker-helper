package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

var appArmorCommand = &Command{
	Name:    "apparmor",
	Summary: "Manage AppArmor workspace roots (system mode)",
	Subcommands: []*Command{
		appArmorRootCommand,
		appArmorCheckCommand,
	},
}

var appArmorRootCommand = &Command{
	Name:    "root",
	Summary: "Manage workspace roots in the AppArmor profile",
	Subcommands: []*Command{
		appArmorRootListCommand,
		appArmorRootAddCommand,
		appArmorRootRemoveCommand,
	},
}

var appArmorRootListCommand = &Command{
	Name:    "list",
	Summary: "List managed workspace roots",
	Usage:   "docker-helper apparmor root list",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runAppArmorRootList(stdout, stderr)
			},
		}
	},
}

var appArmorRootAddCommand = &Command{
	Name:       "add",
	Summary:    "Add a workspace root to the AppArmor profile",
	Usage:      "docker-helper apparmor root add PATH",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runAppArmorRootAdd(fs.Args()[0], stdout, stderr)
			},
		}
	},
}

var appArmorRootRemoveCommand = &Command{
	Name:       "remove",
	Summary:    "Remove a workspace root from the AppArmor profile",
	Usage:      "docker-helper apparmor root remove PATH",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runAppArmorRootRemove(fs.Args()[0], stdout, stderr)
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
	roots, err := mgr.listManagedRoots()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	for _, root := range roots {
		fmt.Fprintln(stdout, root)
	}

	return 0
}

func runAppArmorRootAdd(path string, stdout, stderr io.Writer) int {
	if err := requireRoot(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := requireAppArmorActive(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	mgr := newProductionAppArmorProfileManager()
	result, err := mgr.addManagedRoot(path)
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

func runAppArmorRootRemove(path string, stdout, stderr io.Writer) int {
	if err := requireRoot(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := requireAppArmorActive(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	mgr := newProductionAppArmorProfileManager()
	result, err := mgr.removeManagedRoot(path)
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
	if err := mgr.check(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "AppArmor profile valid")
	return 0
}
