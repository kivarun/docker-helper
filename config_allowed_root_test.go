package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// configRawWithAllowedRoots builds a raw config map carrying allowed_roots
// as raw JSON plus the required session_ttl.
func configRawWithAllowedRoots(t *testing.T, allowedRoots string) map[string]json.RawMessage {
	t.Helper()
	return map[string]json.RawMessage{
		"allowed_roots": json.RawMessage(allowedRoots),
		"session_ttl":   json.RawMessage(`"12h"`),
	}
}

// TestValidateRawConfigAllowedRootEntryShapes proves the strict per-entry
// input contract: legacy path strings and canonical {"path","access"} objects
// are accepted; unknown access values, unsupported shapes, unknown object
// fields, empty/relative/policy-forbidden paths fail closed.
func TestValidateRawConfigAllowedRootEntryShapes(t *testing.T) {
	root := testAllowedRootDir(t)
	other := testAllowedRootDir(t)

	tests := []struct {
		name    string
		roots   string // raw JSON array body
		wantErr string
	}{
		{name: "legacy strings", roots: `["` + root + `", "` + other + `"]`},
		{name: "rich read_write", roots: `[{"path":"` + root + `","access":"read_write"}]`},
		{name: "rich read_only", roots: `[{"path":"` + root + `","access":"read_only"}]`},
		{name: "mixed legacy and rich entries", roots: `["` + root + `", {"path":"` + other + `","access":"read_only"}]`},
		{
			name:    "unknown access",
			roots:   `[{"path":"` + root + `","access":"ro"}]`,
			wantErr: `allowed_roots entry access must be "read_write" or "read_only"`,
		},
		{
			name:    "readonly alias rejected",
			roots:   `[{"path":"` + root + `","access":"readonly"}]`,
			wantErr: `allowed_roots entry access must be "read_write" or "read_only"`,
		},
		{
			name:    "writable synonym rejected",
			roots:   `[{"path":"` + root + `","access":"writable"}]`,
			wantErr: `allowed_roots entry access must be "read_write" or "read_only"`,
		},
		{
			name:    "missing access",
			roots:   `[{"path":"` + root + `"}]`,
			wantErr: `allowed_roots entry must contain exactly "path" and "access"`,
		},
		{
			name:    "missing path",
			roots:   `[{"access":"read_write"}]`,
			wantErr: `allowed_roots entry must contain exactly "path" and "access"`,
		},
		{
			name:    "unknown object field",
			roots:   `[{"path":"` + root + `","access":"read_write","mode":"777"}]`,
			wantErr: `allowed_roots entry must contain exactly "path" and "access"`,
		},
		{
			name:    "empty path",
			roots:   `[{"path":"","access":"read_write"}]`,
			wantErr: "allowed_root must be a non-empty absolute path",
		},
		{
			name:    "relative path",
			roots:   `[{"path":"rel/dir","access":"read_write"}]`,
			wantErr: "allowed_root must be a non-empty absolute path",
		},
		{
			name:    "policy-forbidden path",
			roots:   `[{"path":"/dev","access":"read_write"}]`,
			wantErr: "forbidden system directory",
		},
		{
			name:    "empty entry",
			roots:   `[""]`,
			wantErr: "allowed_root must be a non-empty absolute path",
		},
		{
			name:    "numeric entry",
			roots:   `[5]`,
			wantErr: `allowed_roots entry must be a path string or a {"path","access"} object`,
		},
		{
			name:    "null entry",
			roots:   `[null]`,
			wantErr: "allowed_root must be a non-empty absolute path",
		},
		{
			name:    "array entry",
			roots:   `[["` + root + `"]]`,
			wantErr: `allowed_roots entry must be a path string or a {"path","access"} object`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRawConfig(configRawWithAllowedRoots(t, tt.roots))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateRawConfig() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateRawConfig() = nil, want error %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestValidateRawConfigAllowedRootAmbiguityPreserved proves the legacy
// simultaneous allowed_root/allowed_roots refusal is unchanged, and the
// required/absent rules keep their current messages.
func TestValidateRawConfigAllowedRootAmbiguityPreserved(t *testing.T) {
	root := testAllowedRootDir(t)

	err := validateRawConfig(map[string]json.RawMessage{
		"allowed_root":  json.RawMessage(`"` + root + `"`),
		"allowed_roots": json.RawMessage(`["` + root + `"]`),
		"session_ttl":   json.RawMessage(`"12h"`),
	})
	if err == nil || !strings.Contains(err.Error(), "ambiguous configuration: both allowed_root and allowed_roots are present") {
		t.Errorf("ambiguous config error = %v, want the unchanged refusal", err)
	}

	if err := validateRawConfig(map[string]json.RawMessage{"session_ttl": json.RawMessage(`"12h"`)}); err == nil ||
		!strings.Contains(err.Error(), "allowed_roots is required") {
		t.Errorf("missing allowed_roots error = %v, want unchanged requirement", err)
	}

	// The legacy singular alone still validates (read_write normalization is
	// the load resolver's rule).
	if err := validateRawConfig(map[string]json.RawMessage{
		"allowed_root": json.RawMessage(`"` + root + `"`),
		"session_ttl":  json.RawMessage(`"12h"`),
	}); err != nil {
		t.Errorf("legacy allowed_root must keep validating, got %v", err)
	}
}

// TestResolveAllowedRootsNormalizesToRichEntries proves the load resolver
// normalizes every accepted input form into canonical rich entries with
// deterministic first-occurrence ordering and the current duplicate semantics.
func TestResolveAllowedRootsNormalizesToRichEntries(t *testing.T) {
	root := testAllowedRootDir(t)
	other := testAllowedRootDir(t)

	tests := []struct {
		name   string
		roots  string
		legacy string // non-empty means allowed_root singular instead
		want   []AllowedRootEntry
	}{
		{
			name:  "legacy strings become read_write",
			roots: `["` + root + `", "` + other + `"]`,
			want:  []AllowedRootEntry{allowedRootEntry(root), allowedRootEntry(other)},
		},
		{
			name:  "rich entries keep their access",
			roots: `[{"path":"` + root + `","access":"read_only"}, {"path":"` + other + `","access":"read_write"}]`,
			want:  []AllowedRootEntry{{Path: root, Access: AllowedRootAccessReadOnly}, {Path: other, Access: AllowedRootAccessReadWrite}},
		},
		{
			name:  "mixed array normalizes per entry",
			roots: `["` + root + `", {"path":"` + other + `","access":"read_only"}]`,
			want:  []AllowedRootEntry{allowedRootEntry(root), {Path: other, Access: AllowedRootAccessReadOnly}},
		},
		{
			name:  "duplicate same canonical path same access keeps first",
			roots: `["` + root + `", "` + root + `"]`,
			want:  []AllowedRootEntry{allowedRootEntry(root)},
		},
		{
			name:   "legacy singular becomes one read_write entry",
			legacy: root,
			want:   []AllowedRootEntry{allowedRootEntry(root)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := map[string]json.RawMessage{"session_ttl": json.RawMessage(`"12h"`)}
			if tt.legacy != "" {
				raw["allowed_root"] = json.RawMessage(`"` + tt.legacy + `"`)
			} else {
				raw["allowed_roots"] = json.RawMessage(tt.roots)
			}
			fc, err := decodeFileConfig(raw)
			if err != nil {
				t.Fatalf("decodeFileConfig() error: %v", err)
			}
			got, err := resolveAllowedRoots(raw, fc)
			if err != nil {
				t.Fatalf("resolveAllowedRoots() error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("resolveAllowedRoots() = %+v, want %+v", got, tt.want)
			}
			for i, e := range got {
				if e != tt.want[i] {
					t.Errorf("entry %d = %+v, want %+v", i, e, tt.want[i])
				}
			}
			// The path-only projection is derived from the canonical entries.
			if paths := allowedRootPaths(got); len(paths) != len(got) {
				t.Fatalf("projection length %d != entries %d", len(paths), len(got))
			}
		})
	}
}

// TestResolveAllowedRootsConflictingCanonicalPathFailsClosed proves the same
// canonical path with conflicting access is a fail-closed error, never a
// silent last-write-wins choice.
func TestResolveAllowedRootsConflictingCanonicalPathFailsClosed(t *testing.T) {
	root := testAllowedRootDir(t)

	tests := []struct {
		name  string
		roots string
	}{
		{
			name:  "object then object conflict",
			roots: `[{"path":"` + root + `","access":"read_write"}, {"path":"` + root + `","access":"read_only"}]`,
		},
		{
			name:  "legacy string then object conflict",
			roots: `["` + root + `", {"path":"` + root + `","access":"read_only"}]`,
		},
		{
			name:  "object then legacy string conflict",
			roots: `[{"path":"` + root + `","access":"read_only"}, "` + root + `"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := configRawWithAllowedRoots(t, tt.roots)
			if err := validateRawConfig(raw); err != nil {
				t.Fatalf("validateRawConfig() rejected a shape-valid config: %v", err)
			}
			fc, err := decodeFileConfig(raw)
			if err != nil {
				t.Fatalf("decodeFileConfig() error: %v", err)
			}
			_, err = resolveAllowedRoots(raw, fc)
			if err == nil {
				t.Fatal("resolveAllowedRoots() = nil, want conflicting-canonical-path failure")
			}
			if !strings.Contains(err.Error(), "conflicting allowed_roots entries") {
				t.Errorf("error = %v, want the conflicting-entries refusal", err)
			}
		})
	}
}

// TestResolveAllowedRootsInvalidPathsFailClosed proves existing path policy
// failures keep failing the rich schema exactly as they did for legacy strings.
func TestResolveAllowedRootsInvalidPathsFailClosed(t *testing.T) {
	tests := []struct {
		name  string
		roots string
	}{
		{name: "legacy relative", roots: `["rel/dir"]`},
		{name: "rich relative", roots: `[{"path":"rel/dir","access":"read_write"}]`},
		{name: "rich nonexistent", roots: `[{"path":"/definitely/not/a/dir/2.2.1","access":"read_write"}]`},
		{name: "rich policy-forbidden", roots: `[{"path":"/dev","access":"read_only"}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := configRawWithAllowedRoots(t, tt.roots)
			fc, err := decodeFileConfig(raw)
			if err != nil {
				t.Fatalf("decodeFileConfig() error: %v", err)
			}
			_, err = resolveAllowedRoots(raw, fc)
			if err == nil {
				t.Fatal("resolveAllowedRoots() = nil, want path-policy failure")
			}
		})
	}
}

// TestLoadAndPrepareRuntimeConfigRichObjectForm proves the full load boundary
// accepts the canonical object form and that the canonical in-memory state is
// the rich entries with no second path-only store: every consumer projects
// paths from the entries.
func TestLoadAndPrepareRuntimeConfigRichObjectForm(t *testing.T) {
	dir := t.TempDir()
	root := testAllowedRootDir(t)
	other := testAllowedRootDir(t)

	configPath := filepath.Join(dir, "config.json")
	cfg := map[string]any{
		"allowed_roots": []any{
			other,
			map[string]any{"path": root, "access": "read_only"},
		},
		"session_ttl": "12h",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	loaded, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatalf("loadAndPrepareRuntimeConfig() error: %v", err)
	}
	want := []AllowedRootEntry{
		allowedRootEntry(other),
		{Path: root, Access: AllowedRootAccessReadOnly},
	}
	if len(loaded.AllowedRoots) != len(want) {
		t.Fatalf("loaded roots = %+v, want %+v", loaded.AllowedRoots, want)
	}
	for i, e := range loaded.AllowedRoots {
		if e != want[i] {
			t.Errorf("loaded entry %d = %+v, want %+v", i, e, want[i])
		}
	}

	// The legacy projection surfaces exactly the stored paths, in order.
	raw, _, err := loadRawConfig()
	if err != nil {
		t.Fatal(err)
	}
	fc, err := decodeFileConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := resolveAllowedRootsForShow(raw, fc)
	if err != nil {
		t.Fatal(err)
	}
	wantShow := []AllowedRootEntry{
		allowedRootEntry(other),
		{Path: root, Access: AllowedRootAccessReadOnly},
	}
	if !slices.Equal(entries, wantShow) {
		t.Errorf("show projection = %v, want %v", entries, wantShow)
	}
}

// TestConfigAllowedRootAddWritesObjectForm proves a successful 2.2 config
// mutation persists the canonical {"path","access"} object representation, and
// the reloaded runtime config matches byte-for-byte the read_write authority
// the legacy string spelling would have had.
func TestConfigAllowedRootAddWritesObjectForm(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	newRoot := testAllowedRootDir(t)
	stdout, _ := runConfigCLI(t, 0, "config", "allowed-root", "add", newRoot)
	if !strings.Contains(stdout, "added "+newRoot) {
		t.Fatalf("expected 'added %s', got: %s", newRoot, stdout)
	}

	raw := readConfigJSON(t, configPath)
	var entries []AllowedRootEntry
	if err := json.Unmarshal(raw["allowed_roots"], &entries); err != nil {
		t.Fatalf("written allowed_roots are not canonical object entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("written roots = %+v, want 2 entries", entries)
	}
	// Every persisted entry carries the canonical access value.
	for _, e := range entries {
		if !e.Access.isValid() {
			t.Errorf("written entry %q has invalid access %q", e.Path, e.Access)
		}
	}
	if entries[0].Path != allowedRoot || entries[0].Access != AllowedRootAccessReadWrite {
		t.Errorf("written legacy entry = %+v, want read_write at %s", entries[0], allowedRoot)
	}
	if entries[1].Path != newRoot || entries[1].Access != AllowedRootAccessReadWrite {
		t.Errorf("written added entry = %+v, want read_write at %s", entries[1], newRoot)
	}
}

// TestLegacyAllowedRootSingularLoadReadWriteAuthority proves the compatibility
// gate: a pure legacy config (singular allowed_root) loads as canonical
// read_write authority — the same path authority the pre-2.2 build granted.
func TestLegacyAllowedRootSingularLoadReadWriteAuthority(t *testing.T) {
	dir := t.TempDir()
	root := testAllowedRootDir(t)

	configPath := filepath.Join(dir, "config.json")
	cfg := map[string]any{
		"allowed_root": root,
		"session_ttl":  "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	loaded, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatalf("loadAndPrepareRuntimeConfig() error: %v", err)
	}
	want := []AllowedRootEntry{allowedRootEntry(root)}
	if len(loaded.AllowedRoots) != 1 || loaded.AllowedRoots[0] != want[0] {
		t.Fatalf("legacy singular loaded as %+v, want %+v", loaded.AllowedRoots, want)
	}
}

// TestAllowedRootEntryJSONContract proves the entry's JSON contract directly:
// string decodes normalize to read_write, object decodes preserve the access,
// unknown access fails, and marshaling always emits the canonical object form.
func TestAllowedRootEntryJSONContract(t *testing.T) {
	var legacy AllowedRootEntry
	if err := json.Unmarshal([]byte(`"/opt/work"`), &legacy); err != nil {
		t.Fatalf("legacy string decode: %v", err)
	}
	if legacy != allowedRootEntry("/opt/work") {
		t.Errorf("legacy decode = %+v, want read_write entry", legacy)
	}

	var rich AllowedRootEntry
	if err := json.Unmarshal([]byte(`{"path":"/opt/work/inputs","access":"read_only"}`), &rich); err != nil {
		t.Fatalf("rich decode: %v", err)
	}
	if rich != (AllowedRootEntry{Path: "/opt/work/inputs", Access: AllowedRootAccessReadOnly}) {
		t.Errorf("rich decode = %+v", rich)
	}

	var bad AllowedRootEntry
	if err := json.Unmarshal([]byte(`{"path":"/opt/work","access":"ro"}`), &bad); err == nil {
		t.Error("unknown access accepted, want failure")
	}
	if err := json.Unmarshal([]byte(`{"path":"/opt/work","mode":"777"}`), &bad); err == nil {
		t.Error("object without access accepted, want failure")
	}

	out, err := json.Marshal(allowedRootEntry("/opt/work"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != `{"path":"/opt/work","access":"read_write"}` {
		t.Errorf("marshal = %s, want the canonical object form", out)
	}
	out, err = json.Marshal(AllowedRootEntry{Path: "/opt/ro", Access: AllowedRootAccessReadOnly})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != `{"path":"/opt/ro","access":"read_only"}` {
		t.Errorf("marshal = %s, want the canonical object form", out)
	}
}

// TestAllowedRootEntryProjectionIsDerived proves allowedRootPaths is a pure
// derived projection: it reflects the entries and owns no state of its own
// (no second path-only store exists after load).
func TestAllowedRootEntryProjectionIsDerived(t *testing.T) {
	entries := []AllowedRootEntry{
		{Path: "/a", Access: AllowedRootAccessReadWrite},
		{Path: "/b", Access: AllowedRootAccessReadOnly},
	}
	paths := allowedRootPaths(entries)
	if len(paths) != 2 || paths[0] != "/a" || paths[1] != "/b" {
		t.Fatalf("projection = %v, want [/a /b]", paths)
	}
	// Mutating the projection must not touch the canonical entries.
	paths[0] = "/changed"
	if entries[0].Path != "/a" {
		t.Errorf("projection mutation leaked into canonical entries: %+v", entries[0])
	}
	var nilEntries []AllowedRootEntry
	if got := allowedRootPaths(nilEntries); got != nil {
		t.Errorf("nil projection = %v, want nil", got)
	}
}

// TestAllowedRootPersistenceCarriesReadWrite proves the canonical access value
// round-trips through every Principal and Launcher persistence path: the
// default Principal root, a Principal root add, a restricted Launcher create,
// a restricted scope replacement, and a Launcher root add all persist
// read_write, and the rich reads surface it (the 2.1 path-only contract is
// the derived path projection of these entries).
func TestAllowedRootPersistenceCarriesReadWrite(t *testing.T) {
	db := openFreshTestDB(t)
	defer db.Close()
	globalRoot := testAllowedRootDir(t)
	pid, home := setupPrincipalForLauncherTest(t, db, []string{globalRoot}, "rwuser")

	// The default Principal root persisted as read_write.
	p, err := findPrincipalByUsername(db, "rwuser")
	if err != nil {
		t.Fatalf("findPrincipalByUsername: %v", err)
	}
	wantHome := AllowedRootEntry{Path: home, Access: AllowedRootAccessReadWrite}
	if len(p.AllowedRoots) != 1 || p.AllowedRoots[0] != wantHome {
		t.Fatalf("default principal root = %+v, want %+v", p.AllowedRoots, wantHome)
	}

	// A Principal root add persists read_write.
	extra := filepath.Join(globalRoot, "extra")
	if err := os.MkdirAll(extra, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := addPrincipalAllowedRoot(db, "rwuser", extra, AllowedRootAccessReadWrite, []string{globalRoot}); err != nil {
		t.Fatalf("addPrincipalAllowedRoot: %v", err)
	}
	entries, err := readPrincipalAllowedRoots(db, pid)
	if err != nil {
		t.Fatalf("readPrincipalAllowedRoots: %v", err)
	}
	wantExtra := AllowedRootEntry{Path: extra, Access: AllowedRootAccessReadWrite}
	if len(entries) != 2 || !((entries[0] == wantHome && entries[1] == wantExtra) || (entries[0] == wantExtra && entries[1] == wantHome)) {
		t.Fatalf("added principal root = %+v, want [%+v %+v] in lexical order", entries, wantExtra, wantHome)
	}

	// A restricted Launcher create persists read_write entries.
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}
	l, _, _, err := createLauncher(db, pid, "rw", LauncherScopeRestricted, []string{proj}, []string{home}, false)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	lEntries, err := readLauncherAllowedRoots(db, l.ID)
	if err != nil {
		t.Fatalf("readLauncherAllowedRoots: %v", err)
	}
	wantProj := AllowedRootEntry{Path: proj, Access: AllowedRootAccessReadWrite}
	if len(lEntries) != 1 || lEntries[0] != wantProj {
		t.Fatalf("created launcher roots = %+v, want %+v", lEntries, wantProj)
	}

	// A restricted scope replacement persists read_write entries and keeps
	// the replacement atomic (the whole set is one canonical state).
	repl := filepath.Join(home, "repl")
	if err := os.MkdirAll(repl, 0755); err != nil {
		t.Fatal(err)
	}
	updated, err := replaceLauncherScope(db, l, LauncherScopeRestricted, []AllowedRootEntry{allowedRootEntry(repl)}, []string{home})
	if err != nil {
		t.Fatalf("replaceLauncherScope: %v", err)
	}
	wantRepl := AllowedRootEntry{Path: repl, Access: AllowedRootAccessReadWrite}
	if updated.ScopeMode != LauncherScopeRestricted || updated.AllowedRoots[0] != wantRepl {
		t.Fatalf("replaced projection = %+v, want [%+v]", updated.AllowedRoots, wantRepl)
	}
	rEntries, err := readLauncherAllowedRoots(db, l.ID)
	if err != nil {
		t.Fatalf("readLauncherAllowedRoots: %v", err)
	}
	if len(rEntries) != 1 || rEntries[0] != wantRepl {
		t.Fatalf("persisted replacement roots = %+v", rEntries)
	}
}
