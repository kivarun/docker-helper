//go:build !linux

package main

// builderGetTid is unsupported outside Linux: the launcher procattr
// mechanics are a Linux runtime surface; the non-Linux compile stays
// closed with a constant placeholder (never executed).

func builderGetTid() int {
	return 0
}
