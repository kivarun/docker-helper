package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
)

// dockerBindMount is the structured fact set of one Docker bind mount: the
// canonical bind source (a helper-owned pinned or projection path, or a
// daemon-owned runtime path for server-owned injections), the container
// target, and the requested consumption mode.
type dockerBindMount struct {
	Source   string
	Target   string
	ReadOnly bool
}

// dockerMountFieldRepresentable is the serializer owner's representability
// proof for one --mount field value. A field value is representable only if
// all three authoritative boundaries carry it unchanged:
//
//   - the encoding survives: the Docker CLI grammar (opts/mount.go,
//     MountOpt.Set) parses a --mount value as ONE Go CSV record read once,
//     whose fields are key=value pairs (first '=' splits) or boolean flags;
//     encoding/csv quoting represents every other byte sequence — commas,
//     quotes, newlines, lone carriage returns, '=' signs, backslashes,
//     internal whitespace — faithfully, but the CSV reader normalizes the
//     literal CRLF pair to LF inside quoted fields;
//   - the value survives Docker's MountOpt.Set validation: an empty value
//     and a value with leading or trailing whitespace are rejected, so the
//     accepted value must be unchanged under strings.TrimSpace and non-empty
//     after that trim;
//   - the value survives exec argv: a Unix exec argument cannot carry an
//     embedded NUL byte.
//
// A value that fails any boundary is refused here. This is the one
// representability boundary of the Docker bind-mount serialization — never a
// per-caller scattered prohibition and never an approximate encoding.
func dockerMountFieldRepresentable(field string) error {
	if field == "" {
		return fmt.Errorf("docker mount field is empty")
	}
	if strings.Contains(field, "\x00") {
		return fmt.Errorf("docker mount field contains a NUL byte that exec argv cannot carry")
	}
	if strings.Contains(field, "\r\n") {
		return fmt.Errorf("docker mount field contains a CRLF sequence that the encoding/csv record cannot represent faithfully")
	}
	if v := strings.TrimSpace(field); v != field || v == "" {
		return fmt.Errorf("docker mount field is empty after trim or carries leading/trailing whitespace that the Docker mount grammar rejects")
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
// newline, quote, equal sign, or backslash. A source or target must also
// survive the Docker MountOpt.Set value validation unchanged (non-empty, no
// leading/trailing whitespace) and exec argv (no NUL). The serializer is
// the one production owner of that encoding: every Docker bind-mount form
// (user mounts, trusted CA injection, helper-socket runtime projection)
// builds its argv value here, and the shell/exec argv layer stays
// structured (no shell escaping is involved). Fail closed: a source/target
// that cannot be represented faithfully returns an error instead of an
// approximately encoded argv value.
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
