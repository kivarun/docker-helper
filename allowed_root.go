package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

// AllowedRootAccess is the canonical allowed-root access-mode vocabulary. The
// only valid values are the two constants below; no boolean or shorthand
// spelling (rw, ro, readonly, writable) exists in the policy model.
//
//   - read_write: reads are allowed and a workload may be granted a writable
//     host-path exposure when the complete effective policy permits it;
//   - read_only: reads are allowed and a workload may never obtain a writable
//     host-path exposure through this policy.
type AllowedRootAccess string

const (
	AllowedRootAccessReadWrite AllowedRootAccess = "read_write"
	AllowedRootAccessReadOnly  AllowedRootAccess = "read_only"
)

// isValid reports whether a is exactly one of the two canonical access values.
func (a AllowedRootAccess) isValid() bool {
	return a == AllowedRootAccessReadWrite || a == AllowedRootAccessReadOnly
}

// allowedRootAccessVocabulary is the static vocabulary of the canonical
// access modes, in canonical order. It is the single source for completion
// and help surfaces that enumerate the access values.
func allowedRootAccessVocabulary() []string {
	return []string{string(AllowedRootAccessReadWrite), string(AllowedRootAccessReadOnly)}
}

// AllowedRootEntry is the single canonical allowed-root policy value: one
// canonical absolute host path and its access mode. Every path-only
// (pre-2.2) representation normalizes to this entry with access read_write.
type AllowedRootEntry struct {
	Path   string
	Access AllowedRootAccess
}

// allowedRootEntry constructs the canonical entry for a path-only policy
// input. Path-only state is always read_write.
func allowedRootEntry(path string) AllowedRootEntry {
	return AllowedRootEntry{Path: path, Access: AllowedRootAccessReadWrite}
}

// UnmarshalJSON decodes either the legacy path-only string form (normalized
// immediately to read_write) or the canonical {"path","access"} object form.
// Unsupported shapes and unknown access values fail closed; the strict
// config validation in validateRawConfig remains the authoritative input
// validator and runs before any file decode.
func (e *AllowedRootEntry) UnmarshalJSON(data []byte) error {
	var path string
	if err := json.Unmarshal(data, &path); err == nil {
		*e = allowedRootEntry(path)
		return nil
	}
	var raw struct {
		Path   string            `json:"path"`
		Access AllowedRootAccess `json:"access"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf(`allowed_roots entry must be a path string or a {"path","access"} object`)
	}
	if !raw.Access.isValid() {
		return fmt.Errorf("unknown allowed_roots access %q: must be read_write or read_only", string(raw.Access))
	}
	e.Path = raw.Path
	e.Access = raw.Access
	return nil
}

// MarshalJSON always emits the canonical {"path","access"} object form, the
// only representation a 2.2 config write produces.
func (e AllowedRootEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Path   string            `json:"path"`
		Access AllowedRootAccess `json:"access"`
	}{
		Path:   e.Path,
		Access: e.Access,
	})
}

// allowedRootPaths projects canonical entries to their path strings. This is
// the derived path-only projection for consumers whose 2.1 semantics are
// path containment only; the entries remain the authoritative policy value.
func allowedRootPaths(entries []AllowedRootEntry) []string {
	if entries == nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Path)
	}
	return out
}

// allowedRootEntriesForPaths lifts a path-only policy scope into canonical
// entries: every path-only root is read_write. It is the inverse projection
// of allowedRootPaths for 2.1-shaped callers and never invents an
// authoritative policy value of its own.
func allowedRootEntriesForPaths(paths []string) []AllowedRootEntry {
	if paths == nil {
		return nil
	}
	out := make([]AllowedRootEntry, 0, len(paths))
	for _, p := range paths {
		out = append(out, allowedRootEntry(p))
	}
	return out
}

// parseAllowedRootAccess parses a request-supplied access vocabulary value
// into the canonical access mode. It is the single vocabulary parser for
// control-plane inputs (HTTP request fields, CLI flags and positional
// arguments): any value other than the two canonical spellings fails closed
// with ErrInvalidAllowedRootAccess, never a silent default.
func parseAllowedRootAccess(access string) (AllowedRootAccess, error) {
	parsed := AllowedRootAccess(access)
	if !parsed.isValid() {
		return "", fmt.Errorf("access must be read_write or read_only, got %q: %w", access, ErrInvalidAllowedRootAccess)
	}
	return parsed, nil
}

// resolveAllowedRootIdentity resolves the canonical stored-root identity a
// control-plane mutation targets (set-access and the exact-match remove
// semantics): the absolute path, symlink-resolved when the target still
// exists on the filesystem, the cleaned absolute form otherwise. A stored
// root is always matched by this identity, so a symlink alias names the same
// stored entry as its target and a deleted directory keeps its stored
// identity. It is the shared owner of that resolution for every allowed-root
// family (global config, Principal, Launcher).
func resolveAllowedRootIdentity(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path: %w: %w", err, ErrInvalidAllowedRoot)
	}
	if canonical, err := filepath.EvalSymlinks(abs); err == nil {
		return canonical, nil
	}
	return filepath.Clean(abs), nil
}
