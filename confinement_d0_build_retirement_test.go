package main

import (
	"os"
	"strings"
	"testing"
)

// activePolicyLines returns non-empty, non-comment policy source lines. The
// D0.2 confinement regression is deliberately semantic: retired rule text may
// remain in comments as migration evidence, but it must never be an active MAC
// grant again.
func activePolicyLines(data []byte) []string {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}

func TestD0BuildRetirementRemovesActiveBuildxAppArmorGrants(t *testing.T) {
	profiles := []string{
		"packaging/apparmor/docker-helper-system",
		"packaging/apparmor/docker-helper",
	}
	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			data, err := os.ReadFile(profile)
			if err != nil {
				t.Fatalf("read %s: %v", profile, err)
			}
			for _, line := range activePolicyLines(data) {
				for _, retired := range []string{
					"docker-buildx",
					"/docker/cli-plugins/",
					"/docker/buildx/.lock",
					"/docker/.token_seed.lock",
				} {
					if strings.Contains(line, retired) {
						t.Errorf("retired D0 build grant remains active in %s: %s", profile, line)
					}
				}
			}
		})
	}
}

func TestD0BuildRetirementKeepsLegacyRunDockerCLIGrant(t *testing.T) {
	// D0.3b is intentionally outside this correction PR. The remaining run
	// path still executes /usr/bin/docker, so D0.2 must not accidentally retire
	// that grant while removing Buildx-only access.
	for _, profile := range []string{
		"packaging/apparmor/docker-helper-system",
		"packaging/apparmor/docker-helper",
	} {
		data, err := os.ReadFile(profile)
		if err != nil {
			t.Fatalf("read %s: %v", profile, err)
		}
		found := false
		for _, line := range activePolicyLines(data) {
			if line == "/usr/bin/docker rix," {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s must retain /usr/bin/docker rix until D0.3b", profile)
		}
	}
}
