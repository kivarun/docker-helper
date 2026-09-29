package main

// builder_launcher.go owns the categorized launch child (G32 r3 §5): the
// hidden internal `docker-helper builder launch-exec` leaf. The SELinux
// manager re-execs the shared binary with this subcommand; the exec
// transitions into docker_helper_builder_launcher_t, the child validates
// the canonical category token and the exact canonical production
// rootlesskit argv, pins its OS thread, writes its OWN
// /proc/thread-self/attr/exec with the FIXED target context, and execs
// the fixed rootlesskit entry file as an execve REPLACEMENT — the pid the
// manager spawned becomes the rootlesskit session leader (the pid all
// lifecycle anchors use). The launcher is not a runcon clone and not a
// general-purpose exec: one executable target, one category grammar, one
// argv grammar.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
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

// builderProcattrExecPath is the FIXED thread-local exec procattr
// pathname: /proc/thread-self/attr/exec, the current-thread form upstream
// libselinux setexeccon writes through (older kernels:
// /proc/self/task/<tid>/attr/exec). The exec context is per-thread kernel
// state read at the execve of the writing thread, so the write and the
// exec must run on the same OS thread — see runBuilderLaunchExec.
const builderProcattrExecPath = "/proc/thread-self/attr/exec"

// builderProcattrOpen, builderProcattrWrite and builderProcattrClose are
// the launcher procattr syscall seams (production: the unix syscalls on
// the fixed procattr pathname). Package-global; tests restore them.
var (
	builderProcattrOpen = func(path string, flags int, perm uint32) (int, error) {
		return unix.Open(path, flags, perm)
	}
	builderProcattrWrite = func(fd int, payload []byte) (int, error) {
		return unix.Write(fd, payload)
	}
	builderProcattrClose = func(fd int) error {
		return unix.Close(fd)
	}
)

// builderWriteProcattrExec writes the forced exec context to the pinned
// calling thread's /proc/thread-self/attr/exec in the upstream
// setexeccon_raw wire form: the exact context text plus one terminal NUL
// (no trailing newline — that is the legacy alternative form whose
// setprocattr handler strips the newline and reports a short count),
// opened O_RDWR|O_CLOEXEC, written in one logical write retried only on
// EINTR, and requiring the full payload length: a short write, a write
// error, an open failure, or a close failure after a committed write all
// fail the launch closed (the write error is authoritative; the close
// path never turns a failed write into success). The fixed procattr
// pathname, no pid parameter, no libselinux, no security_check_context
// round-trip: the kernel write is the authoritative validation.
// Injectable for tests through the syscall seams above.
var builderWriteProcattrExec = func(context string) error {
	payload := append([]byte(context), 0)
	fd, err := builderProcattrOpen(builderProcattrExecPath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cannot open the forced exec procattr %s: %w", builderProcattrExecPath, err)
	}
	n, err := builderProcattrWrite(fd, payload)
	for err == unix.EINTR {
		n, err = builderProcattrWrite(fd, payload)
	}
	if err != nil {
		_ = builderProcattrClose(fd)
		return fmt.Errorf("cannot write the forced exec context %q (tid %d, requested %d bytes, wrote %d): %w", context, unix.Gettid(), len(payload), n, err)
	}
	if n != len(payload) {
		_ = builderProcattrClose(fd)
		return fmt.Errorf("short write of the forced exec context %q (tid %d, requested %d bytes, wrote %d)", context, unix.Gettid(), len(payload), n)
	}
	if err := builderProcattrClose(fd); err != nil {
		return fmt.Errorf("cannot close the forced exec procattr after writing %q (tid %d): %w", context, unix.Gettid(), err)
	}
	return nil
}

// builderReadProcattrExec reads back the pinned calling thread's
// /proc/thread-self/attr/exec raw bytes (the same fixed procattr pathname,
// no pid parameter). The kernel returns the stored context text verbatim
// when a forced exec context is set and an empty read when it is not, so
// the read-back raw bytes carry exactly the canonical-context encodings
// decodeSELinuxXattrContext accepts. Injectable for tests.
var builderReadProcattrExec = func() ([]byte, error) {
	return os.ReadFile(builderProcattrExecPath)
}

// builderVerifyProcattrExec is the mandatory read-back verification of the
// forced exec context, run on the same pinned OS thread as the write and
// the exec (the exec context is per-thread kernel state): the raw
// read-back is decoded by the shared canonical-context decoder and must
// equal the requested target context exactly. Any read failure, malformed
// encoding, or mismatch fails closed — the launch dies before the execve
// instead of entering the flow domain with a wrong or missing context
// (the Phase 4B-R3 live evidence: a silent forced-context loss produced an
// uncategorized flow entry). The failure messages carry the boundary
// telemetry (thread id, raw length, escaped raw bytes) for the proof
// evidence; the success path prints nothing.
func builderVerifyProcattrExec(target string) error {
	raw, err := builderReadProcattrExec()
	if err != nil {
		return fmt.Errorf("cannot read back the forced exec context (tid %d): %w", unix.Gettid(), err)
	}
	got, err := decodeSELinuxXattrContext(raw)
	if err != nil {
		return fmt.Errorf("the forced exec context read back malformed (tid %d, %d raw bytes %q): %w", unix.Gettid(), len(raw), raw, err)
	}
	if got != target {
		return fmt.Errorf("the forced exec context did not stick (tid %d): want %q, got %q (%d raw bytes %q)", unix.Gettid(), target, got, len(raw), raw)
	}
	return nil
}

// builderExecve replaces the launcher process with the fixed executable
// (production: unix.Exec). It runs on the same pinned OS thread the
// procattr write used (see runBuilderLaunchExec). The execve REPLACEMENT
// form is mandatory: a spawned child with its own pid would break the
// manager's pid anchors (instance.pid, the process-group lifecycle, STOP,
// stale-identity proofing). Injectable for tests.
var builderExecve = func(path string, argv []string, env []string) error {
	return unix.Exec(path, argv, env)
}

// runBuilderLaunchExec is the launcher child's entry: validate the
// canonical category token and the exact canonical rootlesskit argv, pin
// the calling OS thread, write the fixed target context to that thread's
// procattr, read the procattr back and verify it carries the exact target
// context, then exec the fixed rootlesskit entry file on the same thread.
// The pin is mandatory: the Go runtime is already multi-threaded
// when the launcher runs, and the exec context is per-thread state read
// at the execve of the writing thread (the same contract upstream
// setexeccon keeps) — an OS-thread migration between the procattr write
// and the exec would leave the exec reading a different thread's exec
// context. The read-back verification is mandatory for the same reason:
// a write that does not stick must fail the launch closed, not enter the
// flow domain with the inherited uncategorized range (the R3 live
// blocker). Any validation refusal exits 2; any procattr write, read-back
// verification, or exec failure unlocks the thread and exits 1; neither
// ever falls back to a direct launch. The successful Exec replaces the
// pinned calling thread's process image and never returns, so the unlock
// defer fires only on the failure returns; the manager's pid anchors are
// unaffected (the spawned pid becomes the rootlesskit process).
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	target := builderProcessTargetContext(category)
	if err := builderWriteProcattrExec(target); err != nil {
		fmt.Fprintf(stderr, "error: cannot set the forced exec context: %v\n", err)
		return 1
	}
	if err := builderVerifyProcattrExec(target); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := builderExecve(builderManagerRootlessKit, append([]string{builderManagerRootlessKit}, argv...), os.Environ()); err != nil {
		fmt.Fprintf(stderr, "error: rootlesskit exec failed: %v\n", err)
		return 1
	}
	return 0
}
