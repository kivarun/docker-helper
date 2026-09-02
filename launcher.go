package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// LauncherScopeMode is the scope policy of a Launcher beneath its Principal.
type LauncherScopeMode string

const (
	// LauncherScopeInherit adds no narrowing: the Launcher's effective
	// Session-creation roots equal the current effective Principal roots.
	LauncherScopeInherit LauncherScopeMode = "inherit"

	// LauncherScopeRestricted intersects the current effective Principal roots
	// with the Launcher's canonical stored roots.
	LauncherScopeRestricted LauncherScopeMode = "restricted"
)

// Launcher is the stable Session owner beneath one Principal. This is the
// persistence-level domain record introduced by Stage 1.1; Launcher CRUD and
// Session ownership cutover are owned by later stages. Launcher roots do not
// own MAC state, and a Launcher is not a credential.
type Launcher struct {
	ID          string
	PrincipalID int64
	Name        string
	Enabled     bool
	ScopeMode   LauncherScopeMode
	CreatedAt   time.Time
}

// launcherIDPrefix and launcherIDEntropyBytes define the single stable Launcher
// ID format: a random 16-byte (128-bit) value, lowercase-hex encoded and
// prefixed with "dhl_". The format is analogous to the existing stable
// resource-ID formats and is not generalized into a shared ID framework.
const (
	launcherIDPrefix       = "dhl_"
	launcherIDEntropyBytes = 16
)

// generateLauncherID returns a random 16-byte hex ID prefixed with "dhl_".
func generateLauncherID() (string, error) {
	b := make([]byte, launcherIDEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot generate random bytes: %w", err)
	}
	return launcherIDPrefix + hex.EncodeToString(b), nil
}
