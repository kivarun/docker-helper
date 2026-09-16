//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

// setMACCommandPdeathsig guarantees that an external MAC command never
// outlives the daemon process on any exit path: the kernel delivers SIGKILL
// to the child when its creating daemon dies (crash, signal, normal exit).
// The daemon-owned MAC transition budget kills the command during normal
// operation; this guarantee covers the exit itself.
func setMACCommandPdeathsig(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	return nil
}
