package main

import (
	"fmt"
	"os"
	"strings"
)

// LSMBackend identifies the active mandatory access control backend.
type LSMBackend string

const (
	LSMNone     LSMBackend = ""
	LSMAppArmor LSMBackend = "apparmor"
	LSMSelinux  LSMBackend = "selinux"
)

const (
	selinuxEnforcePath = "/sys/fs/selinux/enforce"
	selinuxAttrPath    = "/proc/self/attr/current"
	dockerHelperType   = "system_u:system_r:docker_helper_t:s0"
)

// selinuxEnabled checks whether the SELinux filesystem is mounted and
// reads the current mode. Returns (true, enforcing) when the file exists
// and is readable. Returns (false, false) when the file is missing.
// Returns an error only on unexpected I/O failures.
// The function is a test seam.
var selinuxEnabled = func() (bool, bool, error) {
	data, err := os.ReadFile(selinuxEnforcePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("cannot read %s: %w", selinuxEnforcePath, err)
	}
	mode := strings.TrimSpace(string(data))
	enforcing := mode == "1"
	return true, enforcing, nil
}

// selinuxProcessType reads the current SELinux security context of this process.
// Returns the context string (e.g., "system_u:system_r:docker_helper_t:s0").
// The function is a test seam.
var selinuxProcessType = func() (string, error) {
	data, err := os.ReadFile(selinuxAttrPath)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", selinuxAttrPath, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// detectLSM determines which MAC backend is active on the host.
//
// Returns:
//   - (LSMAppArmor, nil) when only AppArmor is active
//   - (LSMSelinux, nil) when only enforcing SELinux is active
//   - (LSMNone, nil) when no supported backend is active
//   - (LSMNone, error) when both backends are active (unsupported) or
//     SELinux is permissive (not equivalent to enforce mode)
//   - (LSMNone, error) when detection itself fails (read error)
//
// Detection errors must not silently downgrade security.
func detectLSM() (LSMBackend, error) {
	appArmorActive, err := apparmorLSMActive()
	if err != nil {
		return LSMNone, fmt.Errorf("cannot determine AppArmor LSM status: %w", err)
	}

	selinuxActive, selinuxEnforcing, err := selinuxEnabled()
	if err != nil {
		return LSMNone, fmt.Errorf("cannot determine SELinux status: %w", err)
	}

	if appArmorActive && selinuxActive && selinuxEnforcing {
		return LSMNone, fmt.Errorf("both AppArmor and enforcing SELinux are active (unsupported configuration)")
	}

	if appArmorActive {
		return LSMAppArmor, nil
	}

	if selinuxActive && selinuxEnforcing {
		return LSMSelinux, nil
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
	case LSMSelinux:
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

	ctx, err := selinuxProcessType()
	if err != nil {
		return fmt.Errorf("cannot determine SELinux process context: %w", err)
	}

	if ctx != dockerHelperType {
		return fmt.Errorf("process not confined in expected SELinux type: want %q, got %q", dockerHelperType, ctx)
	}
	return nil
}

// currentBackend returns the active MAC backend without failing.
// Returns LSMNone when no backend is active or detection failed.
func currentBackend() LSMBackend {
	backend, _ := detectLSM()
	return backend
}
