package main

import (
	"strings"
	"testing"
)

// assertOpaqueTokenFormat verifies the shared bearer-token encoding contract:
// "dht_" followed by 64 lowercase hex characters.
func assertOpaqueTokenFormat(t *testing.T, token string) {
	t.Helper()
	if !strings.HasPrefix(token, "dht_") {
		t.Errorf("token should have prefix dht_, got %q", token)
	}

	payload := strings.TrimPrefix(token, "dht_")
	if len(payload) != 64 {
		t.Errorf("hex payload length = %d, want 64", len(payload))
	}

	// Verify all characters are lowercase hex.
	for _, c := range payload {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("payload contains non-hex character %q", c)
			break
		}
	}
}

func TestGenerateOpaqueTokenFormat(t *testing.T) {
	token, err := generateOpaqueToken()
	if err != nil {
		t.Fatalf("generateOpaqueToken() error: %v", err)
	}
	assertOpaqueTokenFormat(t, token)
}

// TestTokenGenerationByDomain verifies each domain wrapper preserves the
// shared dht_ encoding contract without collapsing the two domain concepts
// at their call sites.
func TestTokenGenerationByDomain(t *testing.T) {
	for _, tc := range []struct {
		name string
		gen  func() (string, error)
	}{
		{name: "admin token", gen: generateAdminToken},
		{name: "session token", gen: generateSessionToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := tc.gen()
			if err != nil {
				t.Fatalf("generate %s error: %v", tc.name, err)
			}
			assertOpaqueTokenFormat(t, token)
		})
	}
}
