package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// --- M4 RED: the raw-validation key grammar and the fileConfig struct decode
// do NOT share one key grammar. validateRawConfig recognizes canonical exact
// snake_case spellings, while encoding/json struct matching also accepts
// case-insensitive matches against the json tag, so a later case-variant
// member can silently overwrite a validated canonical value — including
// security-relevant values — without any revalidation.

// m4MixedPayload returns the RED payload: a canonical-valid value followed by
// a case-variant value that violates the canonical validator.
func m4MixedPayload() string {
	return `{
  "allowed_roots": ["/opt/project"],
  "session_ttl": "12h",
  "operation_max_completed": 200,
  "Operation_Max_Completed": -1
}`
}

// TestValidateRawConfigRejectsCaseVariantKeys proves the strict member-name
// contract through the raw-validation owner: every member of a config
// document must be a canonical exact config-file key, and a case variant
// (which encoding/json struct decoding would silently fold onto the
// canonical field) is refused instead of being treated as an alias.
func TestValidateRawConfigRejectsCaseVariantKeys(t *testing.T) {
	cases := []struct {
		name    string
		raw     map[string]json.RawMessage
		keyName string
	}{
		{
			name:    "Operation_Max_Completed",
			raw:     map[string]json.RawMessage{"allowed_roots": json.RawMessage(`["/opt/p"]`), "session_ttl": json.RawMessage(`"12h"`), "Operation_Max_Completed": json.RawMessage(`-1`)},
			keyName: "Operation_Max_Completed",
		},
		{
			name:    "Session_TTL",
			raw:     map[string]json.RawMessage{"allowed_roots": json.RawMessage(`["/opt/p"]`), "session_ttl": json.RawMessage(`"12h"`), "Session_TTL": json.RawMessage(`"1s"`)},
			keyName: "Session_TTL",
		},
		{
			name:    "SESSION_TTL",
			raw:     map[string]json.RawMessage{"allowed_roots": json.RawMessage(`["/opt/p"]`), "session_ttl": json.RawMessage(`"12h"`), "SESSION_TTL": json.RawMessage(`"1s"`)},
			keyName: "SESSION_TTL",
		},
		{
			name:    "Audit_Enabled",
			raw:     map[string]json.RawMessage{"allowed_roots": json.RawMessage(`["/opt/p"]`), "session_ttl": json.RawMessage(`"12h"`), "Audit_Enabled": json.RawMessage(`false`)},
			keyName: "Audit_Enabled",
		},
		{
			name:    "Allowed_Roots",
			raw:     map[string]json.RawMessage{"allowed_roots": json.RawMessage(`["/opt/p"]`), "session_ttl": json.RawMessage(`"12h"`), "Allowed_Roots": json.RawMessage(`[]`)},
			keyName: "Allowed_Roots",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRawConfig(tc.raw)
			if err == nil {
				t.Fatalf("validateRawConfig accepted the case-variant member %q (pre-fix behavior: silently ignored, later folded by struct decoding)", tc.keyName)
			}
			if !strings.Contains(err.Error(), tc.keyName) {
				t.Errorf("error %q does not name the offending member %q", err, tc.keyName)
			}
		})
	}
}

// TestValidateRawConfigRejectsUnknownKey proves an unknown top-level member is
// refused, not silently ignored.
func TestValidateRawConfigRejectsUnknownKey(t *testing.T) {
	raw := map[string]json.RawMessage{
		"allowed_roots":        json.RawMessage(`["/opt/p"]`),
		"session_ttl":          json.RawMessage(`"12h"`),
		"unknown_future_field": json.RawMessage(`1`),
	}
	err := validateRawConfig(raw)
	if err == nil {
		t.Fatal("validateRawConfig accepted an unknown top-level member (pre-fix behavior: silently ignored)")
	}
	if !strings.Contains(err.Error(), "unknown_future_field") {
		t.Errorf("error %q does not name the unknown member", err)
	}
}

// TestConfigProjectionNeverFoldsCaseVariant proves the security invariant at
// the REAL production ingest (loadAndPrepareRuntimeConfig, the startup and
// reload owner): a document whose canonical operation_max_completed is 200
// must never produce an effective OperationMaxCompleted of -1 through a
// case-variant member, whatever the member order. Either the document is
// refused or the effective value is the canonical one — a silent fold is
// never acceptable.
func TestConfigProjectionNeverFoldsCaseVariant(t *testing.T) {
	root := testAllowedRootDir(t)
	userModeLoad := func(t *testing.T, payload string) (*Config, error) {
		t.Helper()
		dir := t.TempDir()
		configPath := filepath.Join(dir, "config.json")
		if err := os.WriteFile(configPath, []byte(payload), 0600); err != nil {
			t.Fatal(err)
		}
		origUID := EffectiveUID
		EffectiveUID = func() int { return 1000 }
		defer func() { EffectiveUID = origUID }()
		origGetConfig := getConfigPathFunc
		getConfigPathFunc = func() string { return configPath }
		defer func() { getConfigPathFunc = origGetConfig }()
		t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
		t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		return loadAndPrepareRuntimeConfig()
	}

	cases := []struct {
		name    string
		payload string
	}{
		{"canonical first, case variant later", fmt.Sprintf(`{
  "allowed_roots": [%q],
  "session_ttl": "12h",
  "operation_max_completed": 200,
  "Operation_Max_Completed": -1
}`, root)},
		{"case variant first, canonical later", fmt.Sprintf(`{
  "Operation_Max_Completed": -1,
  "allowed_roots": [%q],
  "session_ttl": "12h",
  "operation_max_completed": 200
}`, root)},
		{"case variant only", fmt.Sprintf(`{
  "allowed_roots": [%q],
  "session_ttl": "12h",
  "Operation_Max_Completed": -1
}`, root)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := userModeLoad(t, tc.payload)
			if err != nil {
				// A refusal is equally acceptable: the invariant is that the
				// case-variant value never reaches the effective config.
				return
			}
			if cfg.OperationMaxCompleted != 200 {
				t.Fatalf("effective OperationMaxCompleted = %d, want the canonical 200 (a case-variant member folded onto the field)", cfg.OperationMaxCompleted)
			}
		})
	}
}

// TestLoadRawConfigFileRejectsDuplicateMembers proves the strict document
// contract at the config-file load boundary: duplicate top-level members must
// fail closed (one JSON member maps to one config identity), never "last
// wins".
func TestLoadRawConfigFileRejectsDuplicateMembers(t *testing.T) {
	cases := []struct {
		name   string
		config string
	}{
		{"duplicate session_ttl different values", `{"allowed_roots":["/opt/p"],"session_ttl":"12h","session_ttl":"1h"}`},
		{"duplicate operation_max_completed last invalid", `{"allowed_roots":["/opt/p"],"session_ttl":"12h","operation_max_completed":200,"operation_max_completed":-1}`},
		{"duplicate operation_max_completed last valid", `{"allowed_roots":["/opt/p"],"session_ttl":"12h","operation_max_completed":-1,"operation_max_completed":200}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := setupConfigTestWithData(t, []byte(tc.config))
			if _, err := loadRawConfigFile(path); err == nil {
				t.Fatalf("loadRawConfigFile accepted duplicate top-level members (pre-fix behavior: map decode collapses duplicates, last wins)")
			}
		})
	}
}

// TestPruneCompletedNegativeCapPanics documents why the strict config ingest
// is security-critical: the operation supervisor's completed-cap consumer
// cannot defend a negative cap (a case-variant config member could deliver
// one pre-fix), and a negative cap deterministically panics at the slice
// boundary. The panic is recovered in this contained test; the security
// invariant is that the negative value can never exist in effective Config.
func TestPruneCompletedNegativeCapPanics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("slice-boundary panic wording is runtime-specific; this suite is linux-only anyway")
	}
	supervisor := newOperationSupervisor()
	now := time.Now()
	op := newTestOperation(t, operationSucceeded, now.Add(-1*time.Minute))
	supervisor.admit(op)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("pruneCompleted with a negative cap did not panic; the consumer hazard is not demonstrable")
		}
	}()
	supervisor.pruneCompleted(10*time.Minute, -1)
	t.Fatal("pruneCompleted with a negative cap returned normally; expected the contained panic")
}
