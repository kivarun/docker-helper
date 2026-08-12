package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestCAInjectionAddsMountAndEnv(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	fakeBinDir := filepath.Join(dir, "fake_bin")
	hash := computeTestOpenSSLHash(t, caPath)
	createFakeOpenSSL(t, fakeBinDir, hash)

	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	os.MkdirAll(runtimeSubDir, 0700)

	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	preparedDir, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}

	expectedMount := fmt.Sprintf("type=bind,source=%s,target=%s,readonly", preparedDir, trustedCAContainerDir)
	if !strings.Contains(expectedMount, "readonly") {
		t.Error("mount should be readonly")
	}
	if !strings.Contains(expectedMount, trustedCAContainerDir) {
		t.Error("mount should target trusted CA container dir")
	}
}

func TestCAExplicitEnvPreserved(t *testing.T) {
	req := runRequest{
		Image: "alpine:3.24",
		Environment: map[string]string{
			"SSL_CERT_DIR":        "/custom/certs",
			"NODE_EXTRA_CA_CERTS": "/custom/ca.pem",
		},
	}

	allEnv := make(map[string]string)
	for k, v := range req.Environment {
		allEnv[k] = v
	}

	if _, exists := allEnv[trustedCAEnvSSLDir]; !exists {
		allEnv[trustedCAEnvSSLDir] = trustedCAEnvSSLDirValue
	}
	if _, exists := allEnv[trustedCAEnvNodeExtra]; !exists {
		allEnv[trustedCAEnvNodeExtra] = trustedCAEnvNodeExtraValue
	}

	if allEnv["SSL_CERT_DIR"] != "/custom/certs" {
		t.Errorf("SSL_CERT_DIR should be preserved, got %s", allEnv["SSL_CERT_DIR"])
	}
	if allEnv["NODE_EXTRA_CA_CERTS"] != "/custom/ca.pem" {
		t.Errorf("NODE_EXTRA_CA_CERTS should be preserved, got %s", allEnv["NODE_EXTRA_CA_CERTS"])
	}
}

func TestCADeterministicEnvOrder(t *testing.T) {
	req := runRequest{
		Image: "alpine:3.24",
		Environment: map[string]string{
			"ZEBRA":  "1",
			"ALPHA":  "2",
			"MIDDLE": "3",
		},
	}

	allEnv := make(map[string]string)
	for k, v := range req.Environment {
		allEnv[k] = v
	}
	if _, exists := allEnv[trustedCAEnvSSLDir]; !exists {
		allEnv[trustedCAEnvSSLDir] = trustedCAEnvSSLDirValue
	}
	if _, exists := allEnv[trustedCAEnvNodeExtra]; !exists {
		allEnv[trustedCAEnvNodeExtra] = trustedCAEnvNodeExtraValue
	}

	names := make([]string, 0, len(allEnv))
	for name := range allEnv {
		names = append(names, name)
	}
	sort.Strings(names)

	expected := []string{
		"ALPHA", "MIDDLE", "NODE_EXTRA_CA_CERTS", "SSL_CERT_DIR", "ZEBRA",
	}
	if !stringSliceEqual(names, expected) {
		t.Errorf("env order = %v, want %v", names, expected)
	}
}

func TestCAMountOverlapRejected(t *testing.T) {
	tests := []struct {
		target  string
		overlap bool
	}{
		{"/run/docker-helper/trusted-ca", true},
		{"/run/docker-helper/trusted-ca/ca.pem", true},
		{"/run/docker-helper/trusted-ca/subdir", true},
		{"/run/docker-helper", true},
		{"/run", true},
		{"/workspace", false},
		{"/etc/ssl/certs", false},
		{"/run/docker-helper/other", false},
	}

	for _, tc := range tests {
		got := isTrustedCAMountOverlap(tc.target)
		if got != tc.overlap {
			t.Errorf("isTrustedCAMountOverlap(%q) = %v, want %v", tc.target, got, tc.overlap)
		}
	}
}

func TestCADisabledNoChange(t *testing.T) {
	cfg := Config{
		TrustedCAInjection:   "disabled",
		TrustedCAPreparedDir: "",
	}

	injected := cfg.TrustedCAInjection == "auto" && cfg.TrustedCAPreparedDir != ""
	if injected {
		t.Error("expected no injection when disabled")
	}
}

func TestIsTrustedCAEnvVar(t *testing.T) {
	if !isTrustedCAEnvVar("SSL_CERT_DIR") {
		t.Error("SSL_CERT_DIR should be a trusted CA env var")
	}
	if !isTrustedCAEnvVar("NODE_EXTRA_CA_CERTS") {
		t.Error("NODE_EXTRA_CA_CERTS should be a trusted CA env var")
	}
	if isTrustedCAEnvVar("SSL_CERT_FILE") {
		t.Error("SSL_CERT_FILE should NOT be a trusted CA env var")
	}
	if isTrustedCAEnvVar("CUSTOM_VAR") {
		t.Error("CUSTOM_VAR should NOT be a trusted CA env var")
	}
}

func TestRunHandlerWithCAInjection(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	fakeBinDir := filepath.Join(dir, "fake_bin")
	hash := computeTestOpenSSLHash(t, caPath)
	createFakeOpenSSL(t, fakeBinDir, hash)

	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	os.MkdirAll(runtimeSubDir, 0700)

	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	preparedDir, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}

	expectedMount := fmt.Sprintf("type=bind,source=%s,target=%s,readonly", preparedDir, trustedCAContainerDir)

	if !strings.HasPrefix(expectedMount, "type=bind,source=") {
		t.Error("mount spec should start with type=bind,source=")
	}
	if !strings.HasSuffix(expectedMount, ",readonly") {
		t.Error("mount spec should end with ,readonly")
	}
}

func TestCAEnvInjectionDisabledMode(t *testing.T) {
	req := runRequest{
		Image: "alpine:3.24",
		Environment: map[string]string{
			"APP_MODE": "test",
		},
	}

	allEnv := make(map[string]string)
	for k, v := range req.Environment {
		allEnv[k] = v
	}

	trustedCAInjected := false
	if trustedCAInjected {
		if _, exists := allEnv[trustedCAEnvSSLDir]; !exists {
			allEnv[trustedCAEnvSSLDir] = trustedCAEnvSSLDirValue
		}
		if _, exists := allEnv[trustedCAEnvNodeExtra]; !exists {
			allEnv[trustedCAEnvNodeExtra] = trustedCAEnvNodeExtraValue
		}
	}

	if _, exists := allEnv[trustedCAEnvSSLDir]; exists {
		t.Error("SSL_CERT_DIR should not be injected when disabled")
	}
	if _, exists := allEnv[trustedCAEnvNodeExtra]; exists {
		t.Error("NODE_EXTRA_CA_CERTS should not be injected when disabled")
	}
	if len(allEnv) != 1 {
		t.Errorf("expected 1 env var, got %d", len(allEnv))
	}
}

func TestRunHandlerCAInjectionFull(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	fakeBinDir := filepath.Join(dir, "fake_bin")
	hash := computeTestOpenSSLHash(t, caPath)
	createFakeOpenSSL(t, fakeBinDir, hash)

	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	os.MkdirAll(runtimeSubDir, 0700)

	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	preparedDir, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}

	caFile := filepath.Join(preparedDir, "ca.pem")
	if _, err := os.Stat(caFile); os.IsNotExist(err) {
		t.Fatal("ca.pem should exist in prepared dir")
	}

	entries, err := os.ReadDir(preparedDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".0") {
			info, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&os.ModeSymlink == 0 {
				t.Error("hash file should be a symlink")
			}
		}
	}
}

func TestCAInjectionConstants(t *testing.T) {
	if trustedCAContainerDir != "/run/docker-helper/trusted-ca" {
		t.Errorf("trustedCAContainerDir = %s", trustedCAContainerDir)
	}
	if trustedCAEnvSSLDir != "SSL_CERT_DIR" {
		t.Errorf("trustedCAEnvSSLDir = %s", trustedCAEnvSSLDir)
	}
	if trustedCAEnvNodeExtra != "NODE_EXTRA_CA_CERTS" {
		t.Errorf("trustedCAEnvNodeExtra = %s", trustedCAEnvNodeExtra)
	}
	if !strings.Contains(trustedCAEnvSSLDirValue, "/run/docker-helper/trusted-ca") {
		t.Error("SSL_CERT_DIR value should contain trusted CA dir")
	}
	if !strings.Contains(trustedCAEnvSSLDirValue, "/etc/ssl/certs") {
		t.Error("SSL_CERT_DIR value should contain /etc/ssl/certs")
	}
	if !strings.Contains(trustedCAEnvSSLDirValue, "/etc/pki/tls/certs") {
		t.Error("SSL_CERT_DIR value should contain /etc/pki/tls/certs")
	}
	if trustedCAEnvNodeExtraValue != "/run/docker-helper/trusted-ca/ca.pem" {
		t.Errorf("NODE_EXTRA_CA_CERTS value = %s", trustedCAEnvNodeExtraValue)
	}
}

func TestCAInjectionNoSSL_CERT_FILE(t *testing.T) {
	if isTrustedCAEnvVar("SSL_CERT_FILE") {
		t.Error("SSL_CERT_FILE should NOT be a trusted CA env var")
	}
}
