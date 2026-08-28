package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// helperOwnedDeploymentPaths returns the helper-owned config/state trees that
// system init must relabel under enforcing SELinux. These are exactly the
// allowed relabel scope for deployment state. The runtime tree
// (/run/docker-helper) is deliberately excluded: it is created and labeled by
// systemd (RuntimeDirectory) and its mounts subtree aliases real workspace
// inodes that must never be relabeled here.
func helperOwnedDeploymentPaths() []string {
	return []string{
		"/etc/docker-helper",
		"/var/lib/docker-helper",
	}
}

// deploymentRestorecon runs restorecon over helper-owned deployment paths. It
// is a package-level variable so tests can capture the exact invocation
// without executing a real SELinux policy binary.
var deploymentRestorecon = func(args ...string) ([]byte, error) {
	cmd := exec.Command("/usr/sbin/restorecon", args...)
	return cmd.CombinedOutput()
}

// relabelDeploymentConfigState applies the installed SELinux fcontext rules to
// the helper-owned config/state trees (recursive restorecon). It is the single
// owner of deployment relabel behavior for docker-helper's own state.
//
// -R relabels recursively (both trees are helper-owned); -m skips the
// /proc/mounts scan, matching the trusted CA restorecon owner.
func relabelDeploymentConfigState() error {
	paths := helperOwnedDeploymentPaths()
	args := []string{"-R", "-m"}
	args = append(args, paths...)
	out, err := deploymentRestorecon(args...)
	if err != nil {
		return fmt.Errorf("deployment relabel failed (restorecon -R -m %s): %w: %s",
			strings.Join(paths, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// applyDeploymentSELinuxRelabel is invoked by system init immediately after
// the helper-owned config/state directories are created and before the config
// / admin token are written, so the created files inherit the correct labels
// and the first daemon start succeeds.
//
// Under system mode with enforcing SELinux an inability to perform the relabel
// is fatal: init must not complete with badly labeled deployment state. For
// AppArmor system mode and user mode there is no SELinux dependency and no
// relabel behavior.
func applyDeploymentSELinuxRelabel(mode DeploymentMode) error {
	if mode != ModeSystem {
		return nil
	}
	backend, err := detectLSM()
	if err != nil {
		return fmt.Errorf("cannot determine MAC backend for deployment relabel: %w", err)
	}
	if backend != LSMSELinux {
		return nil
	}
	return relabelDeploymentConfigState()
}
