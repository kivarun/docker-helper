package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// generateOpaqueToken returns a random bearer token: "dht_" followed by 64
// lowercase hex characters (32 random bytes). It is the shared low-level
// encoding mechanic for domain token wrappers. Callers wrap the returned
// error with context-specific messages and sentinel errors.
func generateOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot generate random bytes: %w", err)
	}
	return "dht_" + hex.EncodeToString(b), nil
}

// generateAdminToken returns a new admin-token domain bearer token.
func generateAdminToken() (string, error) {
	return generateOpaqueToken()
}

// generateSessionToken returns a new Session bearer token.
func generateSessionToken() (string, error) {
	return generateOpaqueToken()
}
