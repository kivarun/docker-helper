package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	apparmorEnabledPath = "/sys/module/apparmor/parameters/enabled"
	apparmorAttrPath    = "/proc/self/attr/current"
	systemProfileName   = "docker-helper-system"
)

// apparmorLSMActive checks whether the AppArmor LSM is active on the kernel.
// Returns true only when the file contains "Y".
// Returns false for "N", missing file, or read errors.
// The reader function is a test seam.
var apparmorLSMActive = func() (bool, error) {
	data, err := os.ReadFile(apparmorEnabledPath)
	if err != nil {
		return false, fmt.Errorf("cannot read %s: %w", apparmorEnabledPath, err)
	}
	return strings.TrimSpace(string(data)) == "Y", nil
}

// apparmorProcessConfinement reads the current AppArmor profile of this process.
// Returns the profile string (e.g., "docker-helper-system (enforce)").
// The reader function is a test seam.
var apparmorProcessConfinement = func() (string, error) {
	data, err := os.ReadFile(apparmorAttrPath)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", apparmorAttrPath, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// requireAppArmorActive checks that the AppArmor LSM is active.
// Returns nil if active, or a descriptive error if inactive or unreadable.
func requireAppArmorActive() error {
	active, err := apparmorLSMActive()
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

	confinement, err := apparmorProcessConfinement()
	if err != nil {
		return fmt.Errorf("cannot determine AppArmor confinement: %w", err)
	}

	expected := systemProfileName + " (enforce)"
	if confinement != expected {
		return fmt.Errorf("process not confined in expected AppArmor profile: want %q, got %q", expected, confinement)
	}
	return nil
}
