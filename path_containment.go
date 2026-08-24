package main

import (
	"path/filepath"
	"strings"
)

// pathWithin returns true if path is within root (equality allowed).
// Both root and path must be canonical (absolute, cleaned).
func pathWithin(root, path string) bool {
	if root == path {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// pathStrictlyWithin returns true if path is a proper descendant of root.
// Both root and path must be canonical (absolute, cleaned).
func pathStrictlyWithin(root, path string) bool {
	if root == path {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
