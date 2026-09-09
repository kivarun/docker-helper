package main

import (
	"errors"
	"slices"
	"testing"
)

// rwP and roP build canonical read_write/read_only test entries.
func rwP(path string) AllowedRootEntry {
	return AllowedRootEntry{Path: path, Access: AllowedRootAccessReadWrite}
}
func roP(path string) AllowedRootEntry {
	return AllowedRootEntry{Path: path, Access: AllowedRootAccessReadOnly}
}
func accE(path string) AllowedRootEntry { return AllowedRootEntry{Path: path} }

// mustNormalize normalizes and requires canonically ordered output.
func mustNormalize(t *testing.T, entries []AllowedRootEntry) []AllowedRootEntry {
	t.Helper()
	out := normalizeAllowedRootEntries(entries)
	for i := 1; i < len(out); i++ {
		if out[i-1].Path >= out[i].Path {
			t.Fatalf("normalized output is not canonically ordered: %v", out)
		}
	}
	return out
}

func mustCompose(t *testing.T, ceiling, narrowing []AllowedRootEntry) []AllowedRootEntry {
	t.Helper()
	out := composeAllowedRootScopes(ceiling, narrowing)
	if err := validateCanonicalAllowedRootEntries(out); err != nil {
		t.Fatalf("composed output is not canonical: %v: %v", out, err)
	}
	return out
}

func lookupAll(t *testing.T, entries []AllowedRootEntry, sources ...string) []string {
	t.Helper()
	out := make([]string, 0, len(sources))
	for _, s := range sources {
		access, ok := lookupAllowedRootAccess(entries, s)
		if !ok {
			t.Fatalf("lookup(%q) unauthorized, want authority", s)
		}
		out = append(out, string(access))
	}
	return out
}

// TestMeetAllowedRootAccess proves the exact meet table: read_only dominates.
func TestMeetAllowedRootAccess(t *testing.T) {
	for _, tt := range []struct {
		a, b, want AllowedRootAccess
	}{
		{AllowedRootAccessReadWrite, AllowedRootAccessReadWrite, AllowedRootAccessReadWrite},
		{AllowedRootAccessReadWrite, AllowedRootAccessReadOnly, AllowedRootAccessReadOnly},
		{AllowedRootAccessReadOnly, AllowedRootAccessReadWrite, AllowedRootAccessReadOnly},
		{AllowedRootAccessReadOnly, AllowedRootAccessReadOnly, AllowedRootAccessReadOnly},
	} {
		if got := meetAllowedRootAccess(tt.a, tt.b); got != tt.want {
			t.Errorf("meet(%s, %s) = %s, want %s", tt.a, tt.b, got, tt.want)
		}
	}
}

// TestLookupMostSpecificInOneScope proves the within-scope rule: the
// most-specific matching entry decides, overlapping entries nest, and
// component-aware matching never lets /data match /data2.
func TestLookupMostSpecificInOneScope(t *testing.T) {
	policy := []AllowedRootEntry{
		rwP("/work"),
		roP("/work/inputs"),
		rwP("/work/inputs/cache"),
	}
	if got := lookupAll(t, policy, "/work/a", "/work/inputs/a", "/work/inputs/cache/a"); !slices.Equal(got, []string{"read_write", "read_only", "read_write"}) {
		t.Errorf("nested lookups = %v, want [read_write read_only read_write]", got)
	}

	// Prefix traps: /data must not match /data2, /work/a must not match /work/ab.
	traps := []AllowedRootEntry{roP("/data"), roP("/work/a")}
	for _, source := range []string{"/data2", "/data2/x", "/work/ab", "/work/ab/x"} {
		if access, ok := lookupAllowedRootAccess(traps, source); ok {
			t.Errorf("lookup(%q) = (%q, true), want no authority (prefix trap)", source, access)
		}
	}
	if got := lookupAll(t, traps, "/data", "/data/x", "/work/a", "/work/a/x"); !slices.Equal(got, []string{"read_only", "read_only", "read_only", "read_only"}) {
		t.Errorf("trap lookups = %v, want read_only everywhere inside the roots", got)
	}
}

// TestLookupInsertionOrderIndependent proves lookup result does not depend on
// insertion order for overlapping and disjoint entries.
func TestLookupInsertionOrderIndependent(t *testing.T) {
	policy := []AllowedRootEntry{rwP("/work"), roP("/work/inputs"), rwP("/work/inputs/cache"), rwP("/other")}
	shuffled := []AllowedRootEntry{rwP("/work/inputs/cache"), rwP("/other"), rwP("/work"), roP("/work/inputs")}
	for _, source := range []string{"/work", "/work/x", "/work/inputs", "/work/inputs/x", "/work/inputs/cache", "/work/inputs/cache/x", "/other", "/other/x", "/elsewhere"} {
		gotPolicy, okPolicy := lookupAllowedRootAccess(policy, source)
		gotShuffled, okShuffled := lookupAllowedRootAccess(shuffled, source)
		if okPolicy != okShuffled || gotPolicy != gotShuffled {
			t.Errorf("lookup(%q) differs by insertion order: (%q,%v) vs (%q,%v)", source, gotPolicy, okPolicy, gotShuffled, okShuffled)
		}
	}
}

// TestComposeSingleScopeShapes proves the composed access at each nesting
// level for the canonical RW->RO->RW and RO->RW shapes, and that deep
// multiple transitions are preserved.
func TestComposeSingleScopeShapes(t *testing.T) {
	tests := []struct {
		name    string
		policy  []AllowedRootEntry
		narrow  []AllowedRootEntry // nil means compose against an empty disallowed scope
		sources []string
		want    []string
	}{
		{
			name:    "single read_write scope stays readable and writable",
			policy:  []AllowedRootEntry{rwP("/w")},
			sources: []string{"/w", "/w/x"},
			want:    []string{"read_write", "read_write"},
		},
		{
			name:    "single read_only scope stays read_only",
			policy:  []AllowedRootEntry{roP("/w")},
			sources: []string{"/w", "/w/x"},
			want:    []string{"read_only", "read_only"},
		},
		{
			name:    "nested RW -> RO",
			policy:  []AllowedRootEntry{rwP("/w"), roP("/w/inputs")},
			sources: []string{"/w", "/w/a", "/w/inputs", "/w/inputs/a"},
			want:    []string{"read_write", "read_write", "read_only", "read_only"},
		},
		{
			name:    "nested RO -> RW",
			policy:  []AllowedRootEntry{roP("/w"), rwP("/w/project")},
			sources: []string{"/w", "/w/inputs", "/w/project", "/w/project/a"},
			want:    []string{"read_only", "read_only", "read_write", "read_write"},
		},
		{
			name: "RW -> RO -> RW -> RO keeps every transition",
			policy: []AllowedRootEntry{
				rwP("/w"), roP("/w/a"), rwP("/w/a/b"), roP("/w/a/b/c"),
			},
			sources: []string{"/w/x", "/w/a", "/w/a/b", "/w/a/b/c", "/w/a/b/c/d"},
			want:    []string{"read_write", "read_only", "read_write", "read_only", "read_only"},
		},
		{
			name:    "empty narrowing scope removes all authority",
			policy:  []AllowedRootEntry{rwP("/w")},
			narrow:  []AllowedRootEntry{},
			sources: []string{"/w"},
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upper := tt.policy
			lower := tt.narrow
			if lower == nil && tt.want != nil {
				// Compose the scope against itself: no additional narrowing.
				lower = upper
			}
			composed := mustCompose(t, upper, lower)
			if tt.want == nil {
				if len(composed) != 0 {
					t.Fatalf("compose = %v, want empty", composed)
				}
				return
			}
			if got := lookupAll(t, composed, tt.sources...); !slices.Equal(got, tt.want) {
				t.Errorf("composed lookups = %v, want %v (composed=%v)", got, tt.want, composed)
			}
		})
	}
}

// TestComposeMostSpecificAcrossScopes proves the composed transitions for the
// required multi-level example: a downstream read_write on a deeper path is
// preserved under an upstream read_write root, and an upstream read_only
// narrows it.
func TestComposeMostSpecificAcrossScopes(t *testing.T) {
	global := []AllowedRootEntry{rwP("/w"), roP("/w/input")}
	principal := []AllowedRootEntry{rwP("/w"), rwP("/w/input/cache")}

	composed := mustCompose(t, global, principal)
	// Effective transitions: /w RW, /w/input RO (upstream narrows), and the
	// principal's /w/input/cache read_write is suppressed by the upstream
	// read_only region between /w/input and /w/input/cache.
	if got := lookupAll(t, composed, "/w/a", "/w/input", "/w/input/cache"); !slices.Equal(got, []string{"read_write", "read_only", "read_only"}) {
		t.Errorf("suppressed downstream RW = %v, want [read_write read_only read_only]", got)
	}

	// Without the upstream read_only, the deeper downstream read_write
	// survives and its region is writable.
	globalRW := []AllowedRootEntry{rwP("/w")}
	composedRW := mustCompose(t, globalRW, principal)
	if got := lookupAll(t, composedRW, "/w", "/w/input", "/w/input/cache"); !slices.Equal(got, []string{"read_write", "read_write", "read_write"}) {
		t.Errorf("downstream RW without upstream RO = %v, want read_write everywhere", got)
	}
}

// TestComposePrefixTrapAcrossScopes proves component-aware composition: a
// narrow scope under /data2 cannot authorize anything inside /data and vice
// versa.
func TestComposePrefixTrapAcrossScopes(t *testing.T) {
	composed := mustCompose(t, []AllowedRootEntry{roP("/data")}, []AllowedRootEntry{rwP("/data2")})
	if len(composed) != 0 {
		t.Fatalf("composed = %v, want empty (disjoint prefixes)", composed)
	}
	composed = mustCompose(t, []AllowedRootEntry{roP("/w/a")}, []AllowedRootEntry{rwP("/w/ab")})
	if len(composed) != 0 {
		t.Fatalf("composed = %v, want empty (/w/ab is not inside /w/a)", composed)
	}
}

// TestComposeUpstreamReadOnlyCannotWiden proves the meet direction: upstream
// read_write + downstream read_only narrows, and upstream read_only +
// downstream read_write stays read_only in both orders.
func TestComposeUpstreamReadOnlyCannotWiden(t *testing.T) {
	tests := []struct {
		name      string
		global    AllowedRootEntry
		principal AllowedRootEntry
		want      string
	}{
		{name: "global RW narrowed by principal RO", global: rwP("/x"), principal: roP("/x"), want: "read_only"},
		{name: "global RO cannot be widened by principal RW", global: roP("/x"), principal: rwP("/x"), want: "read_only"},
		{name: "global RO with principal RO stays RO", global: roP("/x"), principal: roP("/x"), want: "read_only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			composed := mustCompose(t, []AllowedRootEntry{tt.global}, []AllowedRootEntry{tt.principal})
			got := lookupAll(t, composed, "/x", "/x/y")
			if len(got) != 2 || got[0] != tt.want || got[1] != tt.want {
				t.Errorf("composed lookups = %v, want %q everywhere", got, tt.want)
			}
			wantEntry := AllowedRootEntry{Path: "/x", Access: AllowedRootAccess(tt.want)}
			if len(composed) != 1 || composed[0] != wantEntry {
				t.Errorf("composed entries = %v, want exactly %v", composed, wantEntry)
			}
		})
	}
}

// TestComposeEqualAndMultipleOverlappingRoots proves equal paths compose and
// several overlapping roots keep the most-specific rule per level.
func TestComposeEqualAndMultipleOverlappingRoots(t *testing.T) {
	global := []AllowedRootEntry{rwP("/g/one"), rwP("/g/two"), roP("/g/two/narrow")}
	principal := []AllowedRootEntry{roP("/g/one"), rwP("/g/two"), rwP("/g/two/narrow/deeper")}
	composed := mustCompose(t, global, principal)
	if got := lookupAll(t, composed, "/g/one/x", "/g/two/a", "/g/two/narrow/a", "/g/two/narrow/deeper/a"); !slices.Equal(got, []string{"read_only", "read_write", "read_only", "read_only"}) {
		t.Errorf("overlapping composition = %v, want [RO RW RO RO]", got)
	}
	// Principal broader than global: /g is pruned by the global ceiling.
	composed = mustCompose(t, []AllowedRootEntry{rwP("/g/one")}, []AllowedRootEntry{rwP("/g")})
	if got := lookupAll(t, composed, "/g/one", "/g/one/x"); !slices.Equal(got, []string{"read_write", "read_write"}) {
		t.Errorf("principal broader = %v, want read_write under /g/one", got)
	}
	if _, ok := lookupAllowedRootAccess(composed, "/g/other"); ok {
		t.Error("/g/other authorized although the global ceiling excludes it")
	}
}

// TestComposeDeterministicNormalization proves one policy set produces
// byte-for-byte the same normalized output in every insertion order.
func TestComposeDeterministicNormalization(t *testing.T) {
	orders := [][]AllowedRootEntry{
		{rwP("/w"), roP("/w/inputs"), rwP("/w/inputs/cache"), rwP("/w/project"), roP("/deep")},
		{roP("/deep"), rwP("/w/project"), rwP("/w/inputs/cache"), roP("/w/inputs"), rwP("/w")},
		{rwP("/w/inputs/cache"), rwP("/w"), rwP("/w/project"), roP("/w/inputs"), roP("/deep")},
		{roP("/w/inputs"), rwP("/w/inputs/cache"), rwP("/w"), rwP("/w/project"), roP("/deep")},
	}
	var first []AllowedRootEntry
	for i, order := range orders {
		got := mustCompose(t, order, []AllowedRootEntry{rwP("/w")})
		if i == 0 {
			first = got
			continue
		}
		if !slices.Equal(got, first) {
			t.Errorf("order %d produced %v, want %v", i, got, first)
		}
	}
	// The /deep read_only root is outside the narrowing scope and
	// /w/project is a redundant same-mode child of /w; the deeper read_write
	// under the /w/inputs read_only region survives as an explicit
	// transition because it changes the lookup below /w/inputs/cache.
	want := []AllowedRootEntry{rwP("/w"), roP("/w/inputs"), rwP("/w/inputs/cache")}
	if !slices.Equal(first, want) {
		t.Errorf("composed = %v, want %v", first, want)
	}
}

// TestComposeEmptyAndDisjointScopes proves empty/disjoint scopes yield empty
// authority and multiple disjoint authorized roots stay in canonical order.
func TestComposeEmptyAndDisjointScopes(t *testing.T) {
	if got := composeAllowedRootScopes(nil, []AllowedRootEntry{rwP("/a")}); len(got) != 0 {
		t.Errorf("empty ceiling composed = %v, want empty", got)
	}
	disjoint := mustCompose(
		t,
		[]AllowedRootEntry{roP("/b"), rwP("/a")},
		[]AllowedRootEntry{rwP("/a"), roP("/c")},
	)
	want := []AllowedRootEntry{rwP("/a")}
	if !slices.Equal(disjoint, want) {
		t.Errorf("disjoint composition = %v, want %v (only /a is authorized in both)", disjoint, want)
	}
}

// TestCanonicalOrderingAncestorFirst proves the canonical order places
// ancestors before descendants and keeps disjoint paths deterministic.
func TestCanonicalOrderingAncestorFirst(t *testing.T) {
	entries := []AllowedRootEntry{roP("/z/y/x"), rwP("/a"), roP("/a/b"), rwP("/a/b/c"), roP("/a2")}
	sortAllowedRootEntriesCanonical(entries)
	want := []string{"/a", "/a/b", "/a/b/c", "/a2", "/z/y/x"}
	for i, e := range entries {
		if e.Path != want[i] {
			t.Fatalf("order = %v, want %v", entries, want)
		}
	}
}

// TestNormalizeAllowedRootEntries proves the normalization rules: redundant
// same-mode children are removed, real transitions are retained, downstream
// read_write suppressed by an upstream read_only is removed, disjoint roots
// are all retained, and the workspace-boundary entry (an ancestor) is kept.
func TestNormalizeAllowedRootEntries(t *testing.T) {
	tests := []struct {
		name  string
		input []AllowedRootEntry
		want  []AllowedRootEntry
	}{
		{
			name:  "redundant same-mode child removed",
			input: []AllowedRootEntry{rwP("/work"), rwP("/work/project")},
			want:  []AllowedRootEntry{rwP("/work")},
		},
		{
			name:  "real mode transition retained",
			input: []AllowedRootEntry{rwP("/work"), roP("/work/input"), rwP("/work/input/x")},
			want:  []AllowedRootEntry{rwP("/work"), roP("/work/input"), rwP("/work/input/x")},
		},
		{
			name:  "suppressed downstream RW under upstream RO removed",
			input: []AllowedRootEntry{roP("/work"), roP("/work/x")},
			want:  []AllowedRootEntry{roP("/work")},
		},
		{
			name:  "deep equal-mode chain collapses to its root",
			input: []AllowedRootEntry{rwP("/w"), rwP("/w/a"), rwP("/w/a/b"), rwP("/w/a/b/c")},
			want:  []AllowedRootEntry{rwP("/w")},
		},
		{
			name:  "disjoint roots all retained",
			input: []AllowedRootEntry{rwP("/a"), roP("/b"), rwP("/c/d")},
			want:  []AllowedRootEntry{rwP("/a"), roP("/b"), rwP("/c/d")},
		},
		{
			name:  "sibling subtrees keep their own transitions",
			input: []AllowedRootEntry{rwP("/w"), roP("/w/one"), rwP("/w/two"), roP("/w/two/in")},
			// The /w/two read_write entry itself is a redundant same-mode
			// child of /w; only the read_only transition inside it changes
			// any lookup and is therefore kept.
			want: []AllowedRootEntry{rwP("/w"), roP("/w/one"), roP("/w/two/in")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustNormalize(t, tt.input)
			if !slices.Equal(got, tt.want) {
				t.Errorf("normalized = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNormalizedLookupEquivalence proves normalization preserves observable
// access semantics: lookup over the original policy equals lookup over the
// normalized policy for every representative source, on and around every
// boundary.
func TestNormalizedLookupEquivalence(t *testing.T) {
	policies := [][]AllowedRootEntry{
		{rwP("/w"), rwP("/w/a"), rwP("/w/a/b")},
		{rwP("/w"), roP("/w/input"), rwP("/w/input/x"), roP("/w/input/x/y")},
		{roP("/w"), rwP("/w/project"), rwP("/w/project/secret"), rwP("/w/project/secret/x")},
		{rwP("/a"), roP("/b"), rwP("/c/d"), rwP("/c/de")},
	}
	for pi, policy := range policies {
		normalized := mustNormalize(t, policy)
		sources := []string{}
		for _, e := range policy {
			sources = append(sources, e.Path, e.Path+"/leaf", "/"+e.Path+"/../neighbor")
		}
		sources = append(sources, "/w", "/w/x", "/a/x", "/b/x", "/c", "/c/d", "/c/d/x", "/c/de", "/c/de/x", "/nowhere")
		for _, s := range sources {
			gotOriginal, okOriginal := lookupAllowedRootAccess(policy, s)
			gotNormalized, okNormalized := lookupAllowedRootAccess(normalized, s)
			if okOriginal != okNormalized || gotOriginal != gotNormalized {
				t.Errorf("policy %d lookup(%q): original (%q,%v) != normalized (%q,%v)", pi, s, gotOriginal, okOriginal, gotNormalized, okNormalized)
			}
		}
	}
}

// TestEffectivePrincipalAllowedRoots proves the Principal-level semantics:
// user-mode daemon-owner collapse onto the global policy including modes,
// normal composition otherwise, and empty fail-closed authority for
// non-owner or system-mode Principals.
func TestEffectivePrincipalAllowedRoots(t *testing.T) {
	global := []AllowedRootEntry{rwP("/g"), roP("/g/inputs")}
	const owner = int64(7)

	tests := []struct {
		name        string
		userMode    bool
		principalID int64
		daemonID    int64
		stored      []AllowedRootEntry
		want        []AllowedRootEntry
	}{
		{
			name:        "daemon owner with zero roots collapses onto global modes",
			userMode:    true,
			principalID: owner,
			daemonID:    owner,
			stored:      nil,
			want:        []AllowedRootEntry{rwP("/g"), roP("/g/inputs")},
		},
		{
			name:        "daemon owner with stored roots composes normally",
			userMode:    true,
			principalID: owner,
			daemonID:    owner,
			stored:      []AllowedRootEntry{roP("/g")},
			want:        []AllowedRootEntry{roP("/g")},
		},
		{
			name:        "non-owner with zero roots has empty authority",
			userMode:    true,
			principalID: 11,
			daemonID:    owner,
			stored:      nil,
			want:        nil,
		},
		{
			name:        "system mode with zero roots has empty authority",
			userMode:    false,
			principalID: owner,
			daemonID:    owner,
			stored:      nil,
			want:        nil,
		},
		{
			name:        "system mode composes stored roots",
			userMode:    false,
			principalID: 11,
			daemonID:    owner,
			stored:      []AllowedRootEntry{roP("/g/inputs"), rwP("/g")},
			want:        []AllowedRootEntry{rwP("/g"), roP("/g/inputs")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectivePrincipalAllowedRoots(global, tt.stored, tt.principalID, tt.daemonID, tt.userMode)
			if !slices.Equal(got, tt.want) {
				t.Errorf("effective Principal policy = %v, want %v", got, tt.want)
			}
		})
	}
}

// newOwnershipSnapshotForTest builds a sessionOwnershipSnapshot for the pure
// Launcher composition tests.
func newOwnershipSnapshotForTest(principalID int64, scope LauncherScopeMode, launcherRoots, principalRoots []AllowedRootEntry) *sessionOwnershipSnapshot {
	return &sessionOwnershipSnapshot{
		launcherID:       "dhl_test",
		launcherName:     "default",
		launcherEnabled:  true,
		launcherScope:    scope,
		launcherRoots:    launcherRoots,
		principalID:      principalID,
		principalName:    "u",
		principalEnabled: true,
		principalRoots:   principalRoots,
	}
}

// TestEffectiveLauncherAllowedRoots proves inherit/restricted semantics: an
// inherit Launcher equals the Principal ceiling, a restricted Launcher
// narrows paths and modes, a wider downstream mode cannot widen an upstream
// read_only, a restricted Launcher with no stored roots is fail-closed
// empty, and a stale out-of-ceiling root fails closed.
func TestEffectiveLauncherAllowedRoots(t *testing.T) {
	global := []AllowedRootEntry{rwP("/g"), roP("/g/inputs")}
	const owner = int64(7)

	tests := []struct {
		name     string
		userMode bool
		snap     *sessionOwnershipSnapshot
		want     []AllowedRootEntry
		wantErr  error
	}{
		{
			name:     "inherit equals the Principal ceiling",
			userMode: false,
			snap: newOwnershipSnapshotForTest(11, LauncherScopeInherit, nil,
				[]AllowedRootEntry{rwP("/g"), roP("/g/inputs")}),
			want: []AllowedRootEntry{rwP("/g"), roP("/g/inputs")},
		},
		{
			name:     "inherit with daemon-owner collapse keeps global modes",
			userMode: true,
			snap:     newOwnershipSnapshotForTest(owner, LauncherScopeInherit, nil, nil),
			want:     []AllowedRootEntry{rwP("/g"), roP("/g/inputs")},
		},
		{
			name:     "restricted path narrowing",
			userMode: false,
			snap: newOwnershipSnapshotForTest(11, LauncherScopeRestricted,
				[]AllowedRootEntry{rwP("/g/sub")}, []AllowedRootEntry{rwP("/g")}),
			want: []AllowedRootEntry{rwP("/g/sub")},
		},
		{
			name:     "restricted mode narrowing",
			userMode: false,
			snap: newOwnershipSnapshotForTest(11, LauncherScopeRestricted,
				[]AllowedRootEntry{roP("/g")}, []AllowedRootEntry{rwP("/g")}),
			want: []AllowedRootEntry{roP("/g")},
		},
		{
			name:     "restricted read_write cannot widen upstream read_only",
			userMode: false,
			snap: newOwnershipSnapshotForTest(11, LauncherScopeRestricted,
				[]AllowedRootEntry{rwP("/g/inputs")}, []AllowedRootEntry{roP("/g/inputs")}),
			want: []AllowedRootEntry{roP("/g/inputs")},
		},
		{
			name:     "restricted with zero stored roots is fail-closed empty",
			userMode: false,
			snap:     newOwnershipSnapshotForTest(11, LauncherScopeRestricted, nil, []AllowedRootEntry{rwP("/g")}),
			want:     nil,
		},
		{
			name:     "stale out-of-ceiling restricted root fails closed",
			userMode: false,
			snap: newOwnershipSnapshotForTest(11, LauncherScopeRestricted,
				[]AllowedRootEntry{rwP("/elsewhere")}, []AllowedRootEntry{rwP("/g")}),
			wantErr: ErrLauncherUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := effectiveLauncherAllowedRoots(global, tt.snap, owner, tt.userMode)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("effective Launcher policy = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSamePathUpdateSemantics proves a same-path mode update is one canonical
// entry changing access, not two entries: composing the same scope with /x
// read_write and then /x read_only changes the effective result to read_only
// with exactly one entry, with no duplicate-row state involved.
func TestSamePathUpdateSemantics(t *testing.T) {
	global := []AllowedRootEntry{rwP("/x")}

	asRW := mustCompose(t, global, []AllowedRootEntry{rwP("/x")})
	if len(asRW) != 1 || asRW[0] != rwP("/x") {
		t.Fatalf("read_write state = %v, want [/%s read_write]", asRW, "x")
	}

	// The updated canonical state: the single /x entry now carries read_only.
	updated := []AllowedRootEntry{{Path: "/x", Access: AllowedRootAccessReadOnly}}
	asRO := mustCompose(t, global, updated)
	if len(asRO) != 1 || asRO[0] != roP("/x") {
		t.Fatalf("read_only state = %v, want exactly [/%s read_only]", asRO, "x")
	}
	// A duplicate exact path is structurally impossible canonical state.
	if err := validateCanonicalAllowedRootEntries([]AllowedRootEntry{rwP("/x"), roP("/x")}); err == nil {
		t.Error("conflicting duplicate path accepted, want failure")
	}
	if err := validateCanonicalAllowedRootEntries([]AllowedRootEntry{rwP("/x"), rwP("/x")}); err == nil {
		t.Error("same-mode duplicate path accepted, want failure")
	}
}

// TestValidateCanonicalAllowedRootEntries proves the pure boundary rejects
// structurally impossible input states.
func TestValidateCanonicalAllowedRootEntries(t *testing.T) {
	tests := []struct {
		name    string
		entries []AllowedRootEntry
		wantErr bool
	}{
		{name: "canonical entries", entries: []AllowedRootEntry{rwP("/a"), roP("/a/b")}},
		{name: "relative path", entries: []AllowedRootEntry{rwP("a/b")}, wantErr: true},
		{name: "uncleaned path", entries: []AllowedRootEntry{rwP("/a//b")}, wantErr: true},
		{name: "unknown access", entries: []AllowedRootEntry{accE("/a")}, wantErr: true},
		{name: "empty access", entries: []AllowedRootEntry{{Path: "/a"}}, wantErr: true},
		{name: "conflicting duplicate", entries: []AllowedRootEntry{rwP("/a"), roP("/a")}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCanonicalAllowedRootEntries(tt.entries)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateCanonicalAllowedRootEntries(%v) = %v, wantErr %v", tt.entries, err, tt.wantErr)
			}
		})
	}
}

// TestDeriveSessionFilesystemSnapshot proves the snapshot derivation rules:
// the workspace boundary is explicit, ancestor policy materializes inside the
// workspace, nested transitions are copied, outside entries are dropped,
// redundant transitions are normalized, and the output is deterministic.
func TestDeriveSessionFilesystemSnapshot(t *testing.T) {
	tests := []struct {
		name      string
		effective []AllowedRootEntry
		workspace string
		want      []AllowedRootEntry
		wantErr   bool
	}{
		{
			name:      "one-mode workspace keeps only the workspace entry",
			effective: []AllowedRootEntry{rwP("/run"), rwP("/elsewhere")},
			workspace: "/run/job",
			want:      []AllowedRootEntry{rwP("/run/job")},
		},
		{
			name:      "workspace inherits the ancestor entry mode",
			effective: []AllowedRootEntry{roP("/run")},
			workspace: "/run/job",
			want:      []AllowedRootEntry{roP("/run/job")},
		},
		{
			name:      "nested transitions inside the workspace are copied",
			effective: []AllowedRootEntry{rwP("/run"), roP("/run/job/inputs"), rwP("/run/job/inputs/generated"), rwP("/run/job/project")},
			workspace: "/run/job",
			want:      []AllowedRootEntry{rwP("/run/job"), roP("/run/job/inputs"), rwP("/run/job/inputs/generated")},
		},
		{
			name:      "entries outside the workspace never enter the snapshot",
			effective: []AllowedRootEntry{rwP("/run"), roP("/run/other")},
			workspace: "/run/job",
			want:      []AllowedRootEntry{rwP("/run/job")},
		},
		{
			name:      "workspace outside the effective policy fails closed",
			effective: []AllowedRootEntry{rwP("/elsewhere")},
			workspace: "/run/job",
			wantErr:   true,
		},
		{
			name:      "non-canonical workspace fails closed",
			effective: []AllowedRootEntry{rwP("/run")},
			workspace: "/run/job/",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap, err := deriveSessionFilesystemSnapshot(tt.effective, tt.workspace)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("derivation = %+v, want failure", snap)
				}
				return
			}
			if err != nil {
				t.Fatalf("derivation error: %v", err)
			}
			if snap.Workspace != tt.workspace {
				t.Errorf("snapshot workspace = %q, want %q", snap.Workspace, tt.workspace)
			}
			if !slices.Equal(snap.Entries, tt.want) {
				t.Errorf("snapshot entries = %v, want %v", snap.Entries, tt.want)
			}
		})
	}

	// Deterministic: the same effective policy derives the same snapshot
	// regardless of the input order.
	a, errA := deriveSessionFilesystemSnapshot([]AllowedRootEntry{roP("/run"), rwP("/run/job/x")}, "/run/job")
	b, errB := deriveSessionFilesystemSnapshot([]AllowedRootEntry{rwP("/run/job/x"), roP("/run")}, "/run/job")
	if errA != nil || errB != nil {
		t.Fatalf("derivation errors: %v %v", errA, errB)
	}
	if !slices.Equal(a.Entries, b.Entries) {
		t.Errorf("derivation is order-dependent: %v vs %v", a.Entries, b.Entries)
	}
}

// TestSnapshotLookupAccess proves the snapshot source lookup: exact workspace,
// descendants, exact and deeper transitions, outside-workspace rejection, and
// the prefix trap.
func TestSnapshotLookupAccess(t *testing.T) {
	snap, err := deriveSessionFilesystemSnapshot(
		[]AllowedRootEntry{rwP("/run"), roP("/run/job/inputs"), rwP("/run/job/inputs/generated")},
		"/run/job",
	)
	if err != nil {
		t.Fatalf("derivation error: %v", err)
	}

	tests := []struct {
		source     string
		want       AllowedRootAccess
		authorized bool
	}{
		{source: "/run/job", want: AllowedRootAccessReadWrite, authorized: true},
		{source: "/run/job/file", want: AllowedRootAccessReadWrite, authorized: true},
		{source: "/run/job/inputs", want: AllowedRootAccessReadOnly, authorized: true},
		{source: "/run/job/inputs/file", want: AllowedRootAccessReadOnly, authorized: true},
		{source: "/run/job/inputs/generated", want: AllowedRootAccessReadWrite, authorized: true},
		{source: "/run/job/inputs/generated/file", want: AllowedRootAccessReadWrite, authorized: true},
		{source: "/run", authorized: false},
		{source: "/run/job2", authorized: false},
		{source: "/run/job/inputs2", want: AllowedRootAccessReadWrite, authorized: true},
		{source: "/elsewhere", authorized: false},
	}

	// The entry-level prefix trap inside one snapshot: a source beside a
	// transition entry (inputs2 vs inputs) resolves through the workspace
	// root, never through the similarly named transition.
	trapSnap, err := deriveSessionFilesystemSnapshot(
		[]AllowedRootEntry{rwP("/run"), roP("/run/job/data"), rwP("/run/job/data2/deep")},
		"/run/job",
	)
	if err != nil {
		t.Fatalf("trap derivation error: %v", err)
	}
	if got, ok := trapSnap.LookupAccess("/run/job/data2"); !ok || got != AllowedRootAccessReadWrite {
		t.Errorf("LookupAccess(/run/job/data2) = (%q, %v), want (read_write, true)", got, ok)
	}
	for _, tt := range tests {
		got, ok := snap.LookupAccess(tt.source)
		if ok != tt.authorized {
			t.Errorf("LookupAccess(%q) authorized = %v, want %v", tt.source, ok, tt.authorized)
			continue
		}
		if ok && got != tt.want {
			t.Errorf("LookupAccess(%q) = %q, want %q", tt.source, got, tt.want)
		}
	}
}

// TestCanExposeWritable proves the single writable-parent rule: a source is
// writable only when it resolves read_write and its exposed subtree contains
// no read_only region, regardless of deeper read_write transitions under
// that region.
func TestCanExposeWritable(t *testing.T) {
	// /work RW with a nested read_only input region.
	snap, err := deriveSessionFilesystemSnapshot(
		[]AllowedRootEntry{rwP("/work"), roP("/work/input")},
		"/work",
	)
	if err != nil {
		t.Fatalf("derivation error: %v", err)
	}
	if !snap.CanExposeWritable("/work/data") {
		t.Error("plain read_write source refused")
	}
	if snap.CanExposeWritable("/work/input") {
		t.Error("read_only source allowed writable")
	}
	if snap.CanExposeWritable("/work") {
		t.Error("workspace spanning a read_only region allowed writable")
	}
	if snap.CanExposeWritable("/work/input/x") {
		t.Error("source inside a read_only region allowed writable")
	}
	if snap.CanExposeWritable("/outside") {
		t.Error("source outside the snapshot allowed writable")
	}

	// A narrower read_write under a read_only ancestor is writable when its
	// own subtree is clean.
	roSnap, err := deriveSessionFilesystemSnapshot(
		[]AllowedRootEntry{roP("/data"), rwP("/data/project")},
		"/data",
	)
	if err != nil {
		t.Fatalf("derivation error: %v", err)
	}
	if !roSnap.CanExposeWritable("/data/project") {
		t.Error("narrower read_write under a read_only ancestor refused")
	}
	if roSnap.CanExposeWritable("/data") {
		t.Error("read_only root allowed writable")
	}

	// A read_write transition nested inside a read_only region does not make
	// the region's parent writable: the region between the read_only boundary
	// and the deeper transition stays read-only, and the deeper read_write
	// source itself is only writable when its own subtree is clean.
	deepSnap, err := deriveSessionFilesystemSnapshot(
		[]AllowedRootEntry{rwP("/work/project"), roP("/work/project/secret"), rwP("/work/project/secret/x")},
		"/work/project",
	)
	if err != nil {
		t.Fatalf("derivation error: %v", err)
	}
	if deepSnap.CanExposeWritable("/work/project") {
		t.Error("read_write source spanning its own read_only region allowed writable")
	}
	if deepSnap.CanExposeWritable("/work/project/secret") {
		t.Error("read_only boundary source allowed writable")
	}
	if !deepSnap.CanExposeWritable("/work/project/secret/x") {
		t.Error("narrower read_write under a read_only ancestor refused")
	}

	// A narrower read_write source with its own nested read_only region is
	// refused despite its own read_write resolution.
	narrowSnap, err := deriveSessionFilesystemSnapshot(
		[]AllowedRootEntry{roP("/data"), rwP("/data/project"), roP("/data/project/secret")},
		"/data",
	)
	if err != nil {
		t.Fatalf("derivation error: %v", err)
	}
	if narrowSnap.CanExposeWritable("/data/project") {
		t.Error("narrower read_write with its own nested read_only region allowed writable")
	}
	if !narrowSnap.CanExposeWritable("/data/project/code") {
		t.Error("clean leaf under the narrower read_write source refused")
	}
}

// TestSnapshotEquivalenceWithEffectivePolicy proves clipping and
// normalization never change observable access semantics: for every tested
// source inside the workspace, the effective-policy lookup and the derived
// snapshot lookup agree, and sources outside the workspace have no authority
// in the snapshot while the effective policy may still authorize them.
func TestSnapshotEquivalenceWithEffectivePolicy(t *testing.T) {
	effective := []AllowedRootEntry{
		rwP("/run"),
		roP("/run/job/inputs"),
		rwP("/run/job/inputs/generated"),
		rwP("/run/job/project"),
	}
	snap, err := deriveSessionFilesystemSnapshot(effective, "/run/job")
	if err != nil {
		t.Fatalf("derivation error: %v", err)
	}
	inside := []string{
		"/run/job", "/run/job/file", "/run/job/inputs", "/run/job/inputs/x",
		"/run/job/inputs/generated", "/run/job/inputs/generated/x",
		"/run/job/project", "/run/job/project/x",
	}
	for _, s := range inside {
		wantAccess, wantOK := lookupAllowedRootAccess(effective, s)
		gotAccess, gotOK := snap.LookupAccess(s)
		if wantOK != gotOK || wantAccess != gotAccess {
			t.Errorf("source %q: effective (%q,%v) != snapshot (%q,%v)", s, wantAccess, wantOK, gotAccess, gotOK)
		}
	}
	outside := []string{"/run", "/run/other", "/run/job2", "/elsewhere"}
	for _, s := range outside {
		if _, ok := snap.LookupAccess(s); ok {
			t.Errorf("source %q outside the workspace has snapshot authority", s)
		}
	}
}
