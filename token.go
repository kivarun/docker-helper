package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// generateToken returns a random bearer token: "dht_" followed by 64 lowercase
// hex characters (32 random bytes). Callers wrap the returned error with
// context-specific messages and sentinel errors.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot generate random bytes: %w", err)
	}
	return "dht_" + hex.EncodeToString(b), nil
}
