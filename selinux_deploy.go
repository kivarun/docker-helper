package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// dockerCLISearchPath is the PATH the daemon resolves "docker" against
// (systemd service default). Under enforcing SELinux init must relabel the
// exact executable docker-helper will exec, so it searches the same
// directories in the same order.
var dockerCLISearchPath = []string{
	"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
}

// dockerCLIExecutable returns the exact Docker CLI executable that docker-helper
// uses to drive the Docker daemon, resolving "docker" the way the daemon does at
// runtime. It is a package-level variable so tests can inject a stable path
// without a docker install.
var dockerCLIExecutable = func() (string, error) {
	for _, dir := range dockerCLISearchPath {
		p := filepath.Join(dir, "docker")
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New("docker CLI not found in the daemon search path")
}

// relabelDockerCLI applies the installed fcontext rules to the exact Docker CLI
// executable so the confined docker_helper_t domain can execute it
// (execute_no_trans on container_runtime_exec_t). It is the narrow complement
// to relabelDeploymentConfigState: exact-path restorecon only, never recursive,
// never a directory, never a broad /usr/bin relabel, and it adds no execute
// permission to bin_t.
func relabelDockerCLI() error {
	path, err := dockerCLIExecutable()
	if err != nil {
		return fmt.Errorf("cannot locate docker CLI for SELinux relabel: %w", err)
	}
	out, err := deploymentRestorecon("-m", path)
	if err != nil {
		return fmt.Errorf("docker CLI relabel failed (restorecon -m %s): %w: %s",
			path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// applyDeploymentSELinuxRelabel is invoked by system init immediately after
// the helper-owned config/state directories are created and before the config
// / admin token are written, so the created files inherit the correct labels
// and the first daemon start succeeds.
//
// Under system mode with enforcing SELinux an inability to perform the relabel
// is fatal: init must not complete with badly labeled deployment state. This
// covers both the helper-owned config/state trees and the exact Docker CLI
// executable docker-helper will exec (whose type must already be defined by the
// distro/container-selinux fcontext rules). For AppArmor system mode and user
// mode there is no SELinux dependency and no relabel behavior.
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
	if err := relabelDeploymentConfigState(); err != nil {
		return err
	}
	return relabelDockerCLI()
}
