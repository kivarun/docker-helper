package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// selinuxCommand inspects SELinux system-policy state for a SELinux system
// deployment. It is diagnostics only and never mutates SELinux state.
var selinuxCommand = &Command{
	Name:    "selinux",
	Summary: "Inspect SELinux system policy state (system mode)",
	Subcommands: []*Command{
		selinuxCheckCommand,
	},
}

var selinuxCheckCommand = &Command{
	Name:    "check",
	Summary: "Validate the installed SELinux policy module and file contexts",
	Usage:   "docker-helper selinux check",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runSELinuxCheck(stdout, stderr)
			},
		}
	},
}

const (
	// selinuxPolicyModule is the installed docker-helper SELinux policy
	// module name (packaging/selinux/docker-helper.te).
	selinuxPolicyModule = "docker_helper"
	// selinuxCheckExecutable is the installed docker-helper binary. It is part
	// of the installed system contract and required by the check.
	selinuxCheckExecutable = "/usr/bin/docker-helper"
)

// selinuxCheckPaths are docker-helper-owned paths whose file contexts, when
// the path is present, must be consistent with the docker-helper.fc policy
// defaults. The executable is required; these are optional (absent is not a
// failure).
var selinuxCheckPaths = []string{
	"/etc/docker-helper",
	"/var/lib/docker-helper",
	"/run/docker-helper",
	"/run/docker-helper/trusted-ca",
}

// selinuxCheckVerifier runs the read-only `docker-helper selinux check`
// diagnostics. It owns no MAC lifecycle state and never mutates SELinux.
//
// Seams are injectable for tests: runCommand executes the read-only external
// commands, detectLSM is the single host MAC authority, and statPath reports
// whether a host path is present, distinguishing a genuine absence from a
// stat error so presence that cannot be determined never looks absent.
type selinuxCheckVerifier struct {
	runCommand func(string, ...string) ([]byte, error)
	detectLSM  func() (LSMBackend, error)
	statPath   func(string) (present bool, err error)
}

func newProductionSELinuxCheckVerifier() *selinuxCheckVerifier {
	return &selinuxCheckVerifier{
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			c := exec.Command(cmd, args...)
			return c.CombinedOutput()
		},
		detectLSM: detectLSM,
		statPath: func(p string) (bool, error) {
			_, err := os.Stat(p)
			if err == nil {
				return true, nil
			}
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return false, fmt.Errorf("cannot determine presence of %s: %w", p, err)
		},
	}
}

// runSELinuxCheck is the CLI entry point for `docker-helper selinux check`.
func runSELinuxCheck(stdout, stderr io.Writer) int {
	return runSELinuxCheckWithVerifier(newProductionSELinuxCheckVerifier(), stdout, stderr)
}

// runSELinuxCheckWithVerifier is runSELinuxCheck with an injectable verifier.
func runSELinuxCheckWithVerifier(v *selinuxCheckVerifier, stdout, stderr io.Writer) int {
	if err := requireRoot(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := v.check(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "SELinux policy valid")
	return 0
}

// check validates the installed SELinux system-policy foundation. It uses
// detectLSM as the single authority for host MAC state, then verifies the
// docker-helper policy module is loaded and docker-helper-owned file contexts
// are consistent with the active policy. It never mutates SELinux state and
// never inspects dynamic Session MAC resources.
func (v *selinuxCheckVerifier) check() error {
	backend, err := v.detectLSM()
	if err != nil {
		return err
	}
	switch backend {
	case LSMSELinux:
		// Supported enforcing SELinux host: continue.
	case LSMAppArmor:
		return fmt.Errorf("AppArmor is the active MAC backend; SELinux system mode is not active")
	case LSMNone:
		return fmt.Errorf("no supported MAC backend active (system mode requires enforcing SELinux)")
	default:
		return fmt.Errorf("unknown MAC backend: %s", backend)
	}

	if err := v.checkPolicyModule(); err != nil {
		return err
	}
	if err := v.checkFileContexts(); err != nil {
		return err
	}
	return nil
}

// checkPolicyModule verifies the docker_helper policy module is loaded via the
// read-only `semodule -l` listing. The match is an exact module-name match.
func (v *selinuxCheckVerifier) checkPolicyModule() error {
	out, err := v.runCommand("semodule", "-l")
	if err != nil {
		return fmt.Errorf("cannot list installed SELinux policy modules (semodule -l): %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == selinuxPolicyModule {
			return nil
		}
	}
	return fmt.Errorf("SELinux policy module %q is not loaded", selinuxPolicyModule)
}

// checkFileContexts verifies docker-helper-owned file contexts against the
// active policy defaults using the read-only `matchpathcon -V`. The installed
// executable is required; the remaining paths are optional (genuinely absent
// is not a failure, a present path whose context mismatches is, and presence
// that cannot be determined fails diagnostically rather than being skipped).
func (v *selinuxCheckVerifier) checkFileContexts() error {
	present, err := v.statPath(selinuxCheckExecutable)
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("installed executable %s not found", selinuxCheckExecutable)
	}
	if err := v.verifyFileContext(selinuxCheckExecutable); err != nil {
		return err
	}
	for _, p := range selinuxCheckPaths {
		present, err := v.statPath(p)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		if err := v.verifyFileContext(p); err != nil {
			return err
		}
	}
	return nil
}

// verifyFileContext verifies that path's current label matches the active
// policy default via `matchpathcon -V`.
func (v *selinuxCheckVerifier) verifyFileContext(path string) error {
	out, err := v.runCommand("matchpathcon", "-V", path)
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return fmt.Errorf("file context mismatch for %s: %s", path, msg)
		}
		return fmt.Errorf("file context check failed for %s (matchpathcon -V): %w", path, err)
	}
	return nil
}
