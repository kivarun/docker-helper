package main

import (
	"strings"
	"testing"
)

func TestGenerateTokenFormat(t *testing.T) {
	token, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken() error: %v", err)
	}

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
