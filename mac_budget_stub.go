//go:build !linux

package main

import (
	"os/exec"
)

// setMACCommandPdeathsig is a no-op on non-Linux platforms; bounded MAC
// command execution is a Linux capability (the daemon is Linux-only).
func setMACCommandPdeathsig(cmd *exec.Cmd) error {
	return nil
}
