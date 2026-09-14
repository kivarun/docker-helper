package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
)

// dockerBindMount is the structured fact set of one Docker bind mount: the
// canonical bind source (a helper-owned pinned or projection path in system
// mode, the canonical resolved host path in user mode, or a daemon-owned
// runtime path for server-owned injections), the container target, and the
// requested consumption mode.
type dockerBindMount struct {
	Source   string
	Target   string
	ReadOnly bool
}

// dockerMountFieldRepresentable is the serializer owner's representability
// proof for one --mount field value. The authoritative Docker CLI grammar
// (opts/mount.go, MountOpt.Set) parses a --mount value as ONE Go CSV record
// read once, whose fields are key=value pairs (first '=' splits) or boolean
// flags; encoding/csv quoting represents every other byte sequence — commas,
// quotes, newlines, lone carriage returns, '=' signs, backslashes, spaces —
// faithfully, but the CSV reader normalizes the literal CRLF pair to LF
// inside quoted fields. A value that cannot be represented faithfully is
// refused here: this is the one representability boundary of the Docker
// bind-mount serialization, never a per-caller scattered prohibition and
// never an approximate encoding.
func dockerMountFieldRepresentable(field string) error {
	if field == "" {
		return fmt.Errorf("docker mount field is empty")
	}
	if strings.Contains(field, "\r\n") {
		return fmt.Errorf("docker mount field contains a CRLF sequence that the Docker mount grammar cannot represent faithfully")
	}
	return nil
}

// dockerBindMountSpec serializes exactly one Docker --mount argument for a
// bind mount. The grammar is the authoritative Docker CLI grammar
// (opts/mount.go, MountOpt.Set): ONE Go CSV record whose fields are
// key=value pairs or boolean flags — encoding/csv quoting is the
// Docker-sanctioned encoding, so a crafted source or target stays exactly
// ONE field and cannot add a mount option, change the target, flip the
// consumption mode, or create a second logical field through a comma,
// newline, quote, equal sign, or backslash. The serializer is the one
// production owner of that encoding: every Docker bind-mount form (user
// mounts, trusted CA injection, helper-socket runtime projection) builds
// its argv value here, and the shell/exec argv layer stays structured (no
// shell escaping is involved). Fail closed: an empty source/target or a
// value the grammar cannot represent faithfully returns an error instead
// of an approximately encoded argv value.
func dockerBindMountSpec(m dockerBindMount) (string, error) {
	if err := dockerMountFieldRepresentable(m.Source); err != nil {
		return "", fmt.Errorf("bind mount source: %w", err)
	}
	if err := dockerMountFieldRepresentable(m.Target); err != nil {
		return "", fmt.Errorf("bind mount target: %w", err)
	}
	fields := []string{"type=bind", "source=" + m.Source, "target=" + m.Target}
	if m.ReadOnly {
		fields = append(fields, "readonly")
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(fields); err != nil {
		return "", fmt.Errorf("cannot serialize docker bind mount: %w", err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", fmt.Errorf("cannot serialize docker bind mount: %w", err)
	}
	// csv.Writer terminates the record with a newline; the Docker CLI
	// receives the record without that terminator.
	return strings.TrimSuffix(buf.String(), "\n"), nil
}
