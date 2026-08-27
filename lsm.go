package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// LSMBackend identifies the active mandatory access control backend.
type LSMBackend string

const (
	LSMNone     LSMBackend = ""
	LSMAppArmor LSMBackend = "apparmor"
	LSMSELinux  LSMBackend = "selinux"
)

const (
	selinuxEnforcePath = "/sys/fs/selinux/enforce"
	selinuxAttrPath    = "/proc/self/attr/current"
	dockerHelperType   = "docker_helper_t"
)

// parseSELinuxEnforceValue parses the content of /sys/fs/selinux/enforce.
// Returns (true, nil) for "1", (false, nil) for "0", error otherwise.
func parseSELinuxEnforceValue(data []byte) (enforcing bool, err error) {
	mode := strings.TrimSpace(string(data))
	switch mode {
	case "1":
		return true, nil
	case "0":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected SELinux enforce value %q (expected 0 or 1)", mode)
	}
}

// selinuxEnabled checks whether the SELinux filesystem is mounted and
// reads the current mode. Returns (true, enforcing) when the file exists
// and contains "1". Returns (true, false) when the file exists and
// contains "0". Returns (false, false, nil) when the file is missing.
// Returns an error on malformed content or unexpected I/O failures.
// The function is a test seam.
var selinuxEnabled = func() (bool, bool, error) {
	data, err := os.ReadFile(selinuxEnforcePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("cannot read %s: %w", selinuxEnforcePath, err)
	}
	enforcing, err := parseSELinuxEnforceValue(data)
	if err != nil {
		return false, false, err
	}
	return true, enforcing, nil
}

// selinuxProcessContext reads the current SELinux security context of this process.
// Returns the context string (e.g., "system_u:system_r:docker_helper_t:s0").
// The function is a test seam.
var selinuxProcessContext = func() (string, error) {
	data, err := os.ReadFile(selinuxAttrPath)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", selinuxAttrPath, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// parseSELinuxType extracts the TYPE component from a SELinux security context.
// Context format: USER:ROLE:TYPE:RANGE
// Returns an error if the context is malformed (fewer than 3 colon-separated fields).
func parseSELinuxType(ctx string) (string, error) {
	parts := strings.SplitN(ctx, ":", 4)
	if len(parts) < 3 {
		return "", fmt.Errorf("malformed SELinux context %q (expected USER:ROLE:TYPE[:RANGE])", ctx)
	}
	return parts[2], nil
}

// detectLSM determines which MAC backend is active on the host.
//
// Returns:
//   - (LSMAppArmor, nil) when only AppArmor is active
//   - (LSMSELinux, nil) when only enforcing SELinux is active
//   - (LSMNone, nil) when no supported backend is active
//   - (LSMNone, error) when both backends are active (unsupported),
//     SELinux is permissive, SELinux enforce value is malformed,
//     or a real I/O error occurs during detection
//
// ENOENT for an individual backend marker means that backend is not active.
// Detection errors must not silently downgrade security.
//
// This is a test seam: tests may replace detectLSM to simulate a specific
// backend without requiring the host to have that backend active.
var detectLSM = func() (LSMBackend, error) {
	appArmorActive, err := appArmorLSMActive()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			appArmorActive = false
		} else {
			return LSMNone, fmt.Errorf("cannot determine AppArmor LSM status: %w", err)
		}
	}

	selinuxActive, selinuxEnforcing, err := selinuxEnabled()
	if err != nil {
		return LSMNone, fmt.Errorf("cannot determine SELinux status: %w", err)
	}

	if appArmorActive && selinuxActive {
		return LSMNone, fmt.Errorf("both AppArmor and SELinux are active (unsupported configuration)")
	}

	if appArmorActive {
		return LSMAppArmor, nil
	}

	if selinuxActive && selinuxEnforcing {
		return LSMSELinux, nil
	}

	if selinuxActive && !selinuxEnforcing {
		return LSMNone, fmt.Errorf("SELinux is active but in permissive mode (system mode requires enforcing SELinux)")
	}

	return LSMNone, nil
}

// requireMACBackend checks that exactly one supported MAC backend is active.
// Returns nil if a backend is available, or a descriptive error if none is
// active, both are active, or detection failed.
func requireMACBackend() error {
	backend, err := detectLSM()
	if err != nil {
		return err
	}
	if backend == LSMNone {
		return fmt.Errorf("no MAC backend active (system mode requires AppArmor or enforcing SELinux)")
	}
	return nil
}

// requireMACConfinement checks that the process is confined under the
// active MAC backend. Returns nil if properly confined, or a descriptive
// error otherwise.
func requireMACConfinement() error {
	backend, err := detectLSM()
	if err != nil {
		return err
	}
	if backend == LSMNone {
		return fmt.Errorf("no MAC backend active (system mode requires AppArmor or enforcing SELinux)")
	}

	switch backend {
	case LSMAppArmor:
		return requireAppArmorConfinement()
	case LSMSELinux:
		return requireSELinuxConfinement()
	default:
		return fmt.Errorf("unknown MAC backend: %s", backend)
	}
}

// requireSELinuxConfinement checks that the process is confined in the
// expected SELinux type. Requires:
//   - SELinux enabled
//   - Enforcing mode
//   - Current process type == docker_helper_t
//
// Returns nil if properly confined, or a descriptive error otherwise.
func requireSELinuxConfinement() error {
	selinuxActive, selinuxEnforcing, err := selinuxEnabled()
	if err != nil {
		return fmt.Errorf("cannot determine SELinux status: %w", err)
	}
	if !selinuxActive {
		return fmt.Errorf("SELinux is not enabled")
	}
	if !selinuxEnforcing {
		return fmt.Errorf("SELinux is not in enforcing mode (system mode requires enforcing SELinux)")
	}

	ctx, err := selinuxProcessContext()
	if err != nil {
		return fmt.Errorf("cannot determine SELinux process context: %w", err)
	}

	typ, err := parseSELinuxType(ctx)
	if err != nil {
		return fmt.Errorf("cannot parse SELinux process context: %w", err)
	}

	if typ != dockerHelperType {
		return fmt.Errorf("process not confined in expected SELinux type: want %q, got %q (full context: %s)", dockerHelperType, typ, ctx)
	}
	return nil
}
