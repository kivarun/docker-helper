package main

// builder_launcher.go owns the categorized launch child (G32 r3 §5): the
// hidden internal `docker-helper builder launch-exec` leaf. The SELinux
// manager re-execs the shared binary with this subcommand; the exec
// transitions into docker_helper_builder_launcher_t, the child validates
// the canonical category token and the exact canonical production
// rootlesskit argv, writes its OWN /proc/self/attr/exec with the FIXED
// target context, and execs the fixed rootlesskit entry file as an execve
// REPLACEMENT — the pid the manager spawned becomes the rootlesskit
// session leader (the pid all lifecycle anchors use). The launcher is not
// a runcon clone and not a general-purpose exec: one executable target,
// one category grammar, one argv grammar.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// builderManagerSelfBinary is the fixed packaged binary the SELinux
// manager re-execs for the launcher chain. The policy transition is bound
// to docker_helper_exec_t on the canonical packaged binary: no PATH
// lookup, no os.Executable() derivation.
const builderManagerSelfBinary = "/usr/bin/docker-helper"

// builderProcessTargetContext builds the FIXED launcher target context:
// the user/role/type are constants; the only variable part is the
// canonical category from the record. It never accepts a context string,
// a type, a role, a user, or a range.
func builderProcessTargetContext(category builderCategory) string {
	return "system_u:system_r:docker_helper_rootlesskit_t:s0:" + category.String()
}

// builderRootlessKitArgv is the single canonical production argv grammar
// (G32 r3 §5): the exact rootlesskit flags of one operation in the fixed
// order, derived only from the canonical op id and its per-op dirs. The
// manager's command construction and the launcher's validation share this
// owner — there is no second, independently evolving argv spelling.
func builderRootlessKitArgv(opID, rtDir, stDir string) []string {
	return []string{
		"--net=slirp4netns",
		"--copy-up=/etc",
		"--disable-host-loopback",
		"--state-dir=" + filepath.Join(stDir, "rootlesskit-state"),
		builderManagerBuildkitd,
		"--rootless",
		"--root=" + filepath.Join(stDir, "root"),
		"--addr=unix://" + opSocketPath(opID),
	}
}

// builderValidateLaunchArgv validates the received rootlesskit argv as the
// exact production grammar: the op id is derived from the --state-dir
// argument's canonical state-op path, the op id grammar is enforced, and
// the full argv must rebuild EXACTLY from the canonical owner — no extra
// flags, no altered values, no cross-op path correlation.
func builderValidateLaunchArgv(argv []string) ([]string, error) {
	if len(argv) == 0 {
		return nil, errors.New("launch-exec requires the rootlesskit argument vector")
	}
	stateDirArg := ""
	for _, a := range argv {
		if strings.HasPrefix(a, "--state-dir=") {
			if stateDirArg != "" {
				return nil, errors.New("duplicate --state-dir argument in the launch argv")
			}
			stateDirArg = strings.TrimPrefix(a, "--state-dir=")
		}
	}
	if stateDirArg == "" {
		return nil, errors.New("no --state-dir argument in the launch argv")
	}
	prefix := filepath.Join(builderStateRoot, "ops") + "/"
	const suffix = "/rootlesskit-state"
	if !strings.HasPrefix(stateDirArg, prefix) || !strings.HasSuffix(stateDirArg, suffix) {
		return nil, fmt.Errorf("--state-dir is not a canonical operation state path: %q", stateDirArg)
	}
	opID := strings.TrimSuffix(strings.TrimPrefix(stateDirArg, prefix), suffix)
	if !isOperationID(opID) {
		return nil, fmt.Errorf("--state-dir op id is not canonical: %q", opID)
	}
	canonical := builderRootlessKitArgv(opID, opRuntimeDir(opID), opStateDir(opID))
	if !slices.Equal(argv, canonical) {
		return nil, errors.New("launch argv does not match the canonical production grammar")
	}
	return argv, nil
}

// builderWriteProcattrExec writes the forced exec context to the
// launcher's OWN /proc/self/attr/exec — the fixed procattr pathname, no
// pid parameter, no libselinux, no security_check_context round-trip: the
// kernel write is the authoritative validation. Injectable for tests.
var builderWriteProcattrExec = func(context string) error {
	return os.WriteFile("/proc/self/attr/exec", []byte(context+"\n"), 0)
}

// builderExecve replaces the launcher process with the fixed executable
// (production: unix.Exec). The execve REPLACEMENT form is mandatory: a
// spawned child with its own pid would break the manager's pid anchors
// (instance.pid, the process-group lifecycle, STOP, stale-identity
// proofing). Injectable for tests.
var builderExecve = func(path string, argv []string, env []string) error {
	return unix.Exec(path, argv, env)
}

// runBuilderLaunchExec is the launcher child's entry: validate the
// canonical category token and the exact canonical rootlesskit argv, write
// the fixed target context to the launcher's own procattr, then exec the
// fixed rootlesskit entry file. Any validation refusal exits 2; any
// procattr or exec failure exits 1; neither ever falls back to a direct
// launch. The successful Exec replaces this process and never returns.
func runBuilderLaunchExec(args []string, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "error: launch-exec requires the operation category token")
		return 2
	}
	category, ok := parseBuilderCategory(args[0])
	if !ok {
		fmt.Fprintf(stderr, "error: invalid operation category %q\n", args[0])
		return 2
	}
	argv, err := builderValidateLaunchArgv(args[1:])
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if err := builderWriteProcattrExec(builderProcessTargetContext(category)); err != nil {
		fmt.Fprintf(stderr, "error: cannot set the forced exec context: %v\n", err)
		return 1
	}
	if err := builderExecve(builderManagerRootlessKit, append([]string{builderManagerRootlessKit}, argv...), os.Environ()); err != nil {
		fmt.Fprintf(stderr, "error: rootlesskit exec failed: %v\n", err)
		return 1
	}
	return 0
}
