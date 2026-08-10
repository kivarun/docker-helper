package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRegistryLoginCLIInteractive(t *testing.T) {
	// This test verifies the CLI help and flag parsing
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"registry", "login", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "registry") {
		t.Errorf("expected help text: %s", stdout.String())
	}
}

func TestRegistryLoginCLIMissingFlags(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommandWithWriters([]string{"registry", "login"}, &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestRegistryLoginCLIMissingSessionToken(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "")

	var stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"registry", "login",
		"--registry", "registry.example.com",
		"--username", "user",
	}, &bytes.Buffer{}, &stderr)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "DOCKER_HELPER_SESSION_TOKEN") {
		t.Errorf("expected error about DOCKER_HELPER_SESSION_TOKEN, got: %s", stderr.String())
	}
}
