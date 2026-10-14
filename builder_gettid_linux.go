//go:build linux

package main

// builderGetTid is the Linux OS-thread id used by the launcher's procattr
// diagnostics: the forced exec context is per-thread kernel state, so the
// write and the exec must run on the same pinned OS thread and the tid
// names that thread in the operational diagnostics.

import "golang.org/x/sys/unix"

func builderGetTid() int {
	return unix.Gettid()
}
