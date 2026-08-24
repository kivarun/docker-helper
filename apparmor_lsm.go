package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	appArmorEnabledPath = "/sys/module/apparmor/parameters/enabled"
	appArmorAttrPath    = "/proc/self/attr/current"
	systemProfileName   = "docker-helper-system"
)

// appArmorLSMActive checks whether the AppArmor LSM is active on the kernel.
// Returns true only when the file contains "Y".
// Returns false for "N", missing file, or read errors.
// The reader function is a test seam.
var appArmorLSMActive = func() (bool, error) {
	data, err := os.ReadFile(appArmorEnabledPath)
	if err != nil {
		return false, fmt.Errorf("cannot read %s: %w", appArmorEnabledPath, err)
	}
	return strings.TrimSpace(string(data)) == "Y", nil
}

// appArmorProcessConfinement reads the current AppArmor profile of this process.
// Returns the profile string (e.g., "docker-helper-system (enforce)").
// The reader function is a test seam.
var appArmorProcessConfinement = func() (string, error) {
	data, err := os.ReadFile(appArmorAttrPath)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", appArmorAttrPath, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// requireAppArmorActive checks that the AppArmor LSM is active.
// Returns nil if active, or a descriptive error if inactive or unreadable.
func requireAppArmorActive() error {
	active, err := appArmorLSMActive()
	if err != nil {
		return fmt.Errorf("cannot determine AppArmor LSM status: %w", err)
	}
	if !active {
		return fmt.Errorf("AppArmor LSM is not active on this kernel (system mode requires AppArmor)")
	}
	return nil
}

// requireAppArmorConfinement checks that the process is confined in the
// expected system profile in enforce mode.
// Returns nil if properly confined, or a descriptive error otherwise.
func requireAppArmorConfinement() error {
	if err := requireAppArmorActive(); err != nil {
		return err
	}

	confinement, err := appArmorProcessConfinement()
	if err != nil {
		return fmt.Errorf("cannot determine AppArmor confinement: %w", err)
	}

	expected := systemProfileName + " (enforce)"
	if confinement != expected {
		return fmt.Errorf("process not confined in expected AppArmor profile: want %q, got %q", expected, confinement)
	}
	return nil
}
