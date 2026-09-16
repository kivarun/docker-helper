package main

import (
	"bytes"
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
	admitForTest(supervisor, op)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("pruneCompleted with a negative cap did not panic; the consumer hazard is not demonstrable")
		}
	}()
	supervisor.pruneCompleted(10*time.Minute, -1)
	t.Fatal("pruneCompleted with a negative cap returned normally; expected the contained panic")
}

// --- GREEN: the strict config document ingest contract ---

// strictKeyTable is the full config-file key table: every canonical key with
// one valid value, plus its exact legacy/deprecated/retired/computed
// special-case spellings.
func strictKeyTable() []struct {
	name    string
	key     string
	value   string
	diagSub string // for case variants: the offending spelling is named
} {
	return []struct {
		name    string
		key     string
		value   string
		diagSub string
	}{
		{name: "allowed_roots", key: "allowed_roots", value: `["/opt/project"]`},
		{name: "session_ttl", key: "session_ttl", value: `"12h"`},
		{name: "log_level", key: "log_level", value: `"info"`},
		{name: "audit_enabled", key: "audit_enabled", value: `true`},
		{name: "shutdown_timeout", key: "shutdown_timeout", value: `"30s"`},
		{name: "operation_retention_ttl", key: "operation_retention_ttl", value: `"10m"`},
		{name: "operation_max_completed", key: "operation_max_completed", value: `200`},
		{name: "operation_log_max_bytes", key: "operation_log_max_bytes", value: `4194304`},
		{name: "trusted_ca_path", key: "trusted_ca_path", value: `"/etc/ssl/ca.pem"`},
		{name: "trusted_ca_injection", key: "trusted_ca_injection", value: `"disabled"`},
		{name: "http_address", key: "http_address", value: `"127.0.0.1:54321"`},
		{name: "allowed_root legacy", key: "allowed_root", value: `"/opt/project"`},
	}
}

// strictDocument builds a minimal valid document carrying exactly the
// required members plus one extra member with the given name/value; for the
// required members themselves the document carries the tested value in place
// of the default, and the legacy allowed_root scalar replaces allowed_roots
// (the exact legacy migration input shape).
func strictDocument(name, value string) string {
	switch name {
	case "allowed_roots":
		return fmt.Sprintf(`{"allowed_roots": %s, "session_ttl": "12h"}`, value)
	case "session_ttl":
		return fmt.Sprintf(`{"allowed_roots": ["/opt/project"], "session_ttl": %s}`, value)
	case "allowed_root":
		return fmt.Sprintf(`{"allowed_root": %s, "session_ttl": "12h"}`, value)
	default:
		return fmt.Sprintf(`{"allowed_roots": ["/opt/project"], "session_ttl": "12h", %q: %s}`, name, value)
	}
}

// strictVariantDocument builds a minimal valid document plus one case-variant
// member spelling of a canonical key.
func strictVariantDocument(variant, value string) string {
	return fmt.Sprintf(`{"allowed_roots": ["/opt/project"], "session_ttl": "12h", %q: %s}`, variant, value)
}

// TestStrictDocumentExactKeyGrammar covers the exact key contract end to end
// through the strict ingest owner: every canonical config-file key is
// accepted with its exact spelling when the value is valid, and a case
// variant of the same key is refused as an unknown member (never an alias).
// The exact legacy allowed_root migration input stays accepted.
func TestStrictDocumentExactKeyGrammar(t *testing.T) {
	for _, tc := range strictKeyTable() {
		t.Run(tc.name+" exact", func(t *testing.T) {
			raw, err := decodeStrictConfigDocument([]byte(strictDocument(tc.key, tc.value)))
			if err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			if err := validateRawConfig(raw); err != nil {
				t.Fatalf("validateRawConfig accepted-value case: %v", err)
			}
		})
		t.Run(tc.name+" case variant", func(t *testing.T) {
			variant := caseVariantOf(tc.key)
			raw, err := decodeStrictConfigDocument([]byte(strictVariantDocument(variant, tc.value)))
			if err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			err = validateRawConfig(raw)
			if err == nil {
				t.Fatalf("case variant %q accepted (must fail closed as unknown, never an alias)", variant)
			}
			if !strings.Contains(err.Error(), variant) {
				t.Errorf("error %q does not name the case variant %q", err, variant)
			}
		})
	}
}

// caseVariantOf returns a deterministic case-variant spelling of a
// snake_case config key (title-case every word).
func caseVariantOf(key string) string {
	parts := strings.Split(key, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "_")
}

// TestStrictDocumentSpecialDiagnostics preserves the existing exact-spelling
// diagnostics: deprecated fields keep their rename diagnostic, retired fields
// keep the retired diagnostic, computed fields keep the computed diagnostic —
// while case variants of those same spellings are refused as unknown (exact
// spelling only).
func TestStrictDocumentSpecialDiagnostics(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want string
	}{
		{"deprecated exact keeps rename diagnostic", "build_log_max_bytes", "was renamed to"},
		{"retired exact keeps retired diagnostic", "allowed_root_entries", "retired field"},
		{"retired exact 2 keeps retired diagnostic", "effective_allowed_root_entries", "retired field"},
		{"computed exact keeps computed diagnostic", "config_path", "computed and cannot be configured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := decodeStrictConfigDocument([]byte(strictDocument(tc.key, `"x"`)))
			if err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			err = validateRawConfig(raw)
			if err == nil {
				t.Fatalf("%s accepted without its diagnostic", tc.key)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q, want diagnostic containing %q", err, tc.want)
			}
		})
		t.Run(tc.name+" case variant is unknown", func(t *testing.T) {
			variant := caseVariantOf(tc.key)
			raw, err := decodeStrictConfigDocument([]byte(strictDocument(variant, `"x"`)))
			if err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			err = validateRawConfig(raw)
			if err == nil {
				t.Fatalf("case variant %q accepted", variant)
			}
			if !strings.Contains(err.Error(), "unknown configuration field") {
				t.Errorf("case variant %q error %q, want the unknown-field diagnostic (exact spelling only for special diagnostics)", variant, err)
			}
		})
	}
}

// TestStrictDocumentStructural covers the JSON object grammar: exactly one
// top-level object, no trailing tokens, duplicates refused, malformed input
// refused.
func TestStrictDocumentStructural(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		wantSub string
	}{
		{"top-level null", `null`, "not a JSON object"},
		{"top-level array", `[]`, "not a JSON object"},
		{"top-level string", `"config"`, "not a JSON object"},
		{"top-level number", `42`, "not a JSON object"},
		{"malformed JSON", `{"allowed_roots": [`, "cannot parse config"},
		{"trailing second document", `{"allowed_roots": ["/opt/project"]} {"session_ttl": "12h"}`, "trailing data"},
		{"trailing garbage", `{"allowed_roots": ["/opt/project"]} garbage`, "trailing data"},
		{"duplicate member", `{"allowed_roots": ["/opt/project"],"allowed_roots": ["/opt/p2"]}`, "duplicate"},
		{"duplicate member other key", `{"session_ttl": "12h","session_ttl": "1h","allowed_roots": ["/opt/project"]}`, "duplicate"},
		{"empty object (member grammar reports requirements)", `{}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := decodeStrictConfigDocument([]byte(tc.doc))
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("decodeStrictConfigDocument(%s): %v", tc.doc, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("decodeStrictConfigDocument(%s) = %+v, want refusal containing %q", tc.doc, raw, tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q, want containing %q", err, tc.wantSub)
			}
		})
	}

	// Through the file-load boundary the same grammar holds.
	t.Run("file load trailing", func(t *testing.T) {
		path := setupConfigTestWithData(t, []byte(`{"allowed_roots": ["/opt/project"],"session_ttl": "12h"} `))
		// Trailing whitespace is not a trailing token.
		if _, err := loadRawConfigFile(path); err != nil {
			t.Fatalf("trailing whitespace rejected: %v", err)
		}
	})
	t.Run("file load trailing second value", func(t *testing.T) {
		path := setupConfigTestWithData(t, []byte(`{"allowed_roots": ["/opt/project"],"session_ttl": "12h"} {"x":1}`))
		if _, err := loadRawConfigFile(path); err == nil {
			t.Fatal("trailing second JSON value accepted")
		}
	})
}

// TestStrictIngestOrderIndependence proves the acceptance outcome does not
// depend on JSON member order: a case variant is refused whether it appears
// before or after its canonical spelling.
func TestStrictIngestOrderIndependence(t *testing.T) {
	before := `{
  "Operation_Max_Completed": -1,
  "allowed_roots": ["/opt/project"],
  "session_ttl": "12h",
  "operation_max_completed": 200
}`
	after := `{
  "allowed_roots": ["/opt/project"],
  "session_ttl": "12h",
  "operation_max_completed": 200,
  "Operation_Max_Completed": -1
}`
	for _, doc := range []string{before, after} {
		raw, err := decodeStrictConfigDocument([]byte(doc))
		if err != nil {
			t.Fatalf("strict decode: %v", err)
		}
		if err := validateRawConfig(raw); err == nil {
			t.Fatalf("case-variant document accepted (order-dependent acceptance): %s", doc)
		}
	}
}

// TestStrictIngestRefusalBeforeRuntimeSideEffects proves the strict decode
// and validation happen before effective config and before runtime side
// effects: a document carrying a case-variant member is refused with the
// runtime directory never created (the runtime-dir resolution is the first
// side effect after validation, and the trusted-CA preparation runs after
// it), so no MAC/CA/runtime state can derive from a malformed value.
func TestStrictIngestRefusalBeforeRuntimeSideEffects(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	payload := fmt.Sprintf(`{
  "allowed_roots": [%q],
  "session_ttl": "12h",
  "operation_max_completed": 200,
  "Operation_Max_Completed": -1
}`, testAllowedRootDir(t))
	if err := os.WriteFile(configPath, []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}

	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	runtimeDirCalls := 0
	origRuntimeDir := getRuntimeDirFunc
	getRuntimeDirFunc = func() (string, error) {
		runtimeDirCalls++
		return filepath.Join(dir, "runtime"), nil
	}
	defer func() { getRuntimeDirFunc = origRuntimeDir }()

	if _, err := loadAndPrepareRuntimeConfig(); err == nil {
		t.Fatal("case-variant document loaded (must be refused)")
	}
	if runtimeDirCalls != 0 {
		t.Fatalf("runtime-dir resolution ran %d time(s) before the refusal; malformed input must fail before any runtime side effect", runtimeDirCalls)
	}
}

// --- Config CLI: show and mutations refuse malformed documents ---

// TestConfigShowRefusesMalformedDocuments proves `config show` and
// `config show FIELD` refuse every malformed strict-grammar class: duplicate
// member, unknown member, case variant, and trailing content.
func TestConfigShowRefusesMalformedDocuments(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		wantSub string
	}{
		{"duplicate member", `{"allowed_roots": ["/home/user/work"],"session_ttl": "12h","session_ttl": "1h"}`, "duplicate"},
		{"unknown member", `{"allowed_roots": ["/home/user/work"],"session_ttl": "12h","custom_field": "v"}`, `unknown configuration field "custom_field"`},
		{"case variant", `{"allowed_roots": ["/home/user/work"],"session_ttl": "12h","Operation_Max_Completed": 200}`, `unknown configuration field "Operation_Max_Completed"`},
		{"trailing second value", `{"allowed_roots": ["/home/user/work"],"session_ttl": "12h"} {"x":1}`, "trailing data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupConfigTestWithData(t, []byte(tc.doc))
			for _, args := range [][]string{{"config", "show"}, {"config", "show", "log_level"}} {
				_, stderr := runConfigCLI(t, 1, args...)
				if !strings.Contains(stderr, tc.wantSub) {
					t.Errorf("config show %v: stderr = %q, want refusal containing %q", args, stderr, tc.wantSub)
				}
			}
		})
	}
}

// TestConfigAllowedRootMutationRefusesMalformedDocument proves the allowed-root
// transaction family refuses a malformed existing document under the same
// strict grammar, leaving the file bytes unchanged. (The add path
// canonicalizes its operator-supplied path before the transaction, so the
// added root must be a real directory to reach the document grammar check.)
func TestConfigAllowedRootMutationRefusesMalformedDocument(t *testing.T) {
	root := testAllowedRootDir(t)
	extra := filepath.Join(filepath.Dir(root), filepath.Base(root)+"-m4-extra")
	if err := os.MkdirAll(extra, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(extra) })

	doc := fmt.Sprintf(`{
  "allowed_roots": [%q],
  "session_ttl": "12h",
  "Allowed_Roots": [%q]
}`, root, extra)
	configPath := setupConfigTestWithData(t, []byte(doc))
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	_, stderr := runConfigCLI(t, 1, "config", "allowed-root", "add", extra)
	if !strings.Contains(stderr, `unknown configuration field "Allowed_Roots"`) {
		t.Errorf("stderr = %q, want the case-variant refusal", stderr)
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the refused mutation rewrote config.json:\nbefore: %s\nafter:  %s", before, after)
	}
}
