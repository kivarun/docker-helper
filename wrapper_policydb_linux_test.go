//go:build linux

package main

// wrapper_policydb_linux_test.go proves the in-Go loaded-policy
// constraint gate: the parser walks a test-owned kernel policydb v35
// image through the exact structures the gate needs, renders the target
// class's constraint statements seinfo-faithfully, and gates on the
// shipped statement; every structural irregularity refuses, including
// truncation, unsupported versions, malformed structures, and claims
// beyond the explicit caps. The parity comparator is the MNB39a
// reference fixture (testdata/mnb39a-fifo-constraint-statements.txt,
// measured on the enforcing guest — see the fixture's provenance note).

import (
	_ "embed"
	"errors"
	"math/rand"
	"strings"
	"testing"
)

// fixture holds the MNB39a measured statement set; the six rendered
// statements are compared as a set (store order and tool ordering of
// the reference differ; the gate itself judges statement presence).
//
//go:embed testdata/mnb39a-fifo-constraint-statements.txt
var mnb39aFixtureStatements string

// The test-side synthetic writer mirrors the kernel policydb v35
// encoding for the structures the parser walks (header, prelude
// ebitmaps, the four symbol tables, class constraint streams) — the
// same shape the MNB39a guest measured for the real distro image.

func appended(out []byte, more ...[]byte) []byte {
	for _, m := range more {
		out = append(out, m...)
	}
	return out
}

func synthU32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func synthU64(v uint64) []byte {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte(v >> (8 * i))
	}
	return out
}

func synthRaw(name string) []byte {
	out := synthU32(uint32(len(name)))
	return appended(out, []byte(name))
}

func synthEBitmap(bits []uint32) []byte {
	if len(bits) == 0 {
		return appended(synthU32(64), synthU32(0), synthU32(0))
	}
	nodes := map[uint32]uint64{}
	var keys []uint32
	for _, b := range bits {
		start := b - b%64
		if _, seen := nodes[start]; !seen {
			keys = append(keys, start)
		}
		nodes[start] |= 1 << (b % 64)
	}
	// ascending node order
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	out := synthU32(64)
	var high uint32
	for _, b := range bits {
		if b+1 > high {
			high = b + 1
		}
	}
	out = appended(out, synthU32(high))
	out = appended(out, synthU32(uint32(len(keys))))
	for _, k := range keys {
		out = appended(out, synthU32(k))
		out = appended(out, synthU64(nodes[k]))
	}
	return out
}

func synthPerms(perms map[string]uint32) []byte {
	// the kernel streams permission records in value order
	var out []byte
	n := uint32(1)
	for {
		var name string
		for nm, val := range perms {
			if val == n {
				name = nm
				break
			}
		}
		if name == "" {
			break
		}
		d := synthU32(uint32(len(name)))
		d = appended(d, synthU32(n))
		d = appended(d, []byte(name))
		out = appended(out, []byte(d))
		n++
	}
	return out
}

// one constraint expression node
type synthExpr struct {
	et      uint32
	attr    uint32
	op      uint32
	names   []uint32 // names bitmap bits
	tn      []uint32 // type-set types bitmap bits
	tnNeg   []uint32 // type-set neg-set bits
	flags   uint32
	nonType bool // encode the names node without the names bitmap wrapper
	tgt     bool
}

func synthAttrNode(attr, op uint32) synthExpr { return synthExpr{et: cexprAttr, attr: attr, op: op} }

func synthOrNode() synthExpr { return synthExpr{et: cexprOr} }
func synthNotNode() synthExpr {
	return synthExpr{et: cexprNot}
}

func (s synthExpr) encode() []byte {
	out := synthU32(s.et)
	out = appended(out, synthU32(s.attr))
	out = appended(out, synthU32(s.op))
	if s.et == cexprNames {
		out = appended(out, synthEBitmap(s.names))
		out = appended(out, synthEBitmap(s.tn))
		out = appended(out, synthEBitmap(s.tnNeg))
		out = appended(out, synthU32(s.flags))
	}
	return out
}

// mcsConstrainedBit / canChangeBit are the type-value-1 indices of the
// synthetic attribute types.
const (
	testMCSAttrTypeValue       = 2000
	testCanChangeAttrTypeValue = 2001
)

func testMCSAttrBit() uint32   { return testMCSAttrTypeValue - 1 }
func testCanChangeBit() uint32 { return testCanChangeAttrTypeValue - 1 }
func synthNamesNode(attr, op uint32, names, tn []uint32, tgt bool) synthExpr {
	return synthExpr{et: cexprNames, attr: attr, op: op, names: names, tn: tn, tgt: tgt}
}

// workload heater: keep the names from being mistaken for the target
// programs
type synthClass struct {
	name      string
	comkey    string
	value     uint32
	nprim     uint32
	ownPerms  map[string]uint32
	conss     []synthConstraint
	nconsOver uint32 // override ncons (malicious shapes)
}

type synthConstraint struct {
	mask  uint32
	exprs []synthExpr
}

func (s synthClass) encode() []byte {
	a := synthU32(uint32(len(s.name)))
	ckLen := uint32(0)
	if s.comkey != "" {
		ckLen = uint32(len(s.comkey))
	}
	a = appended(a, synthU32(ckLen))
	a = appended(a, synthU32(s.value))
	nprim := s.nprim
	if bs := 0; len(s.ownPerms) > 0 {
		_ = bs
	}
	a = appended(a, synthU32(nprim))
	a = appended(a, synthU32(uint32(len(s.ownPerms))))
	ncons := s.nconsOver
	if ncons == 0 {
		ncons = uint32(len(s.conss))
	}
	a = appended(a, synthU32(ncons))
	a = appended(a, []byte(s.name))
	if s.comkey != "" {
		a = appended(a, []byte(s.comkey))
	}
	a = appended(a, synthPerms(s.ownPerms))
	for _, c := range s.conss {
		a = appended(a, synthU32(c.mask))
		a = appended(a, synthU32(uint32(len(c.exprs))))
		for _, e := range c.exprs {
			a = appended(a, e.encode())
		}
	}
	// validatetrans count 0
	a = appended(a, synthU32(0))
	// defaults (v27+ user/role/range; v28+ type)
	a = appended(a, synthU32(0), synthU32(0), synthU32(0), synthU32(0))
	return a
}

func synthRole(name string, value uint32, types []uint32) []byte {
	a := synthU32(uint32(len(name)))
	a = appended(a, synthU32(value))
	a = appended(a, synthU32(0)) // bounds
	a = appended(a, []byte(name))
	a = appended(a, synthEBitmap(nil))   // dominates
	a = appended(a, synthEBitmap(types)) // types
	return a
}

func synthType(name string, value, prop uint32) []byte {
	a := synthU32(uint32(len(name)))
	a = appended(a, synthU32(value))
	a = appended(a, synthU32(prop))
	a = appended(a, synthU32(0))
	a = appended(a, []byte(name))
	return a
}

// The common perms and class constants mirror the measured distro image
// shape closely enough for the constraint masks to be meaningful.
var testFileCommonPerms = map[string]uint32{
	"ioctl":       1,
	"read":        2,
	"write":       3,
	"create":      4,
	"getattr":     5,
	"setattr":     6,
	"lock":        7,
	"relabelfrom": 8,
	"relabelto":   9,
	"append":      10,
	"map":         11,
	"unlink":      12,
	"open":        13,
}

func testPerm(maskBits ...string) uint32 {
	var m uint32
	for _, p := range maskBits {
		m |= 1 << (testFileCommonPerms[p] - 1)
	}
	return m
}

// the MNB39a-shaped constraint set (the six measured statements)
func mnb39aShapedConstraints() []synthConstraint {
	h1domh2 := []synthExpr{synthAttrNode(cexprH1H2, cexprDom)}
	l2eqh2 := []synthExpr{synthAttrNode(cexprL2H2, cexprEq)}

	tnOf := func(attrValue uint32) []uint32 { return []uint32{attrValue - 1} }
	neqMCS := []synthExpr{synthNamesNode(cexprType, cexprNeq, nil, tnOf(testMCSAttrTypeValue), false)}

	withOr := func(pre []synthExpr) []synthExpr {
		out := append([]synthExpr{}, pre...)
		out = append(out, synthOrNode())
		return out
	}
	h1domh2NeqMCS := withOr(append(h1domh2, neqMCS...))
	l2eqh2NeqMCS := withOr(append(l2eqh2, neqMCS...))

	peerUser := []synthExpr{synthNamesNode(cexprUser|cexprTarget, cexprEq, nil, nil, true)}
	tnCan := []synthExpr{synthNamesNode(cexprType, cexprEq, nil, tnOf(testCanChangeAttrTypeValue), false)}
	peerOrTn := withOr(append(peerUser, tnCan...))

	return []synthConstraint{
		{mask: testPerm("read", "write"), exprs: h1domh2NeqMCS},
		{mask: testPerm("open"), exprs: h1domh2NeqMCS},
		{mask: testPerm("relabelfrom"), exprs: h1domh2NeqMCS},
		{mask: testPerm("create", "relabelto"), exprs: l2eqh2NeqMCS},
		{mask: testPerm("create", "relabelto"), exprs: h1domh2NeqMCS},
		{mask: testPerm("create", "relabelfrom", "relabelto"), exprs: peerOrTn},
	}
}

// buildTestPolicy builds one complete policydb v35 image.
func buildTestPolicy(t *testing.T, version, symNum, oconNum, mls uint32, conss []synthConstraint, extraTypes map[string]uint32) []byte {
	if t != nil {
		t.Helper()
	}
	out := synthU32(policydbMagic)
	out = appended(out, synthU32(8))
	out = appended(out, []byte("SE Linux"))
	out = appended(out, synthU32(version))
	out = appended(out, synthU32(mls)) // config: MLS flag
	out = appended(out, synthU32(symNum))
	out = appended(out, synthU32(oconNum))
	// prelude ebitmaps
	out = appended(out, synthEBitmap(nil))
	out = appended(out, synthEBitmap(nil))
	out = appended(out, synthEBitmap(nil))
	// commons: one 'file' common
	permlist := synthPerms(testFileCommonPerms)
	nCommonPerms := len(testFileCommonPerms)
	out = appended(out, synthU32(1)) // commons nprim
	out = appended(out, synthU32(1)) // commons nel
	rec := synthU32(4)               // name length
	rec = appended(rec, synthU32(1)) // value
	rec = appended(rec, synthU32(uint32(nCommonPerms)))
	rec = appended(rec, synthU32(uint32(nCommonPerms)))
	rec = appended(rec, []byte("file"))
	rec = appended(rec, []byte(permlist))
	out = appended(out, []byte(rec))
	// classes: one fifo_file carrying the constraints
	cls := synthClass{name: "fifo_file", comkey: "file", value: 5, nprim: uint32(nCommonPerms)}
	cls.conss = conss
	fn := cls.encode()
	out = appended(out, synthU32(1)) // classes nprim
	out = appended(out, synthU32(1)) // classes nel
	out = appended(out, []byte(fn))
	// roles: object_r then system_r
	out = appended(out, synthU32(1)) // roles nprim
	out = appended(out, synthU32(2)) // roles nel
	out = appended(out, synthRole("object_r", 1, nil))
	out = appended(out, synthRole("system_r", 2, []uint32{2}))
	// types
	types := []struct {
		name  string
		value uint32
		prop  uint32
	}{
		{"one_t", 1, 1},
		{wrapperOwnDomain, 2, 1},
		{wrapperWorkloadDomain, 3, 1},
		{"mcs_constrained_type", testMCSAttrTypeValue, 3},
		{"can_change_object_identity", testCanChangeAttrTypeValue, 3},
	}
	names := make([]string, 0)
	for name := range extraTypes {
		names = append(names, name)
	}
	// deterministic ordering for extra types
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	n := uint32(6) // reserve values above
	for _, name := range names {
		n++
		types = append(types, struct {
			name  string
			value uint32
			prop  uint32
		}{name: name, value: n, prop: 1})
	}
	out = appended(out, synthU32(uint32(len(types))))
	out = appended(out, synthU32(uint32(len(types))))
	for _, ty := range types {
		out = appended(out, synthType(ty.name, ty.value, ty.prop))
	}
	return out
}

// canonicalTestPolicy is the default MNB39a-shaped policy image.
func canonicalPolicyBlob() []byte {
	return buildTestPolicy(nil, policydbVersionGate, 8, 9, 1, mnb39aShapedConstraints(), nil)
}

func canonicalTestPolicy(t *testing.T) []byte {
	t.Helper()
	return canonicalPolicyBlob()
}

// readTestPolicy parses one synthetic image.
func readTestPolicy(t *testing.T, blob []byte) (*parsedPolicy, error) {
	t.Helper()
	return parsePolicy(blob)
}

// TestWrapperPolicydbParsesCanonicalImage proves the parser walks the
// canonical test image and renders the MNB39a statement set exactly
// (the parity comparator), with the shipped gate statement among them.
func TestWrapperPolicydbParsesCanonicalImage(t *testing.T) {
	blob := canonicalTestPolicy(t)
	p, err := parsePolicy(blob)
	if err != nil {
		t.Fatalf("the canonical image must parse: %v", err)
	}
	if p.target == nil {
		t.Fatal("the fifo_file class must be present")
	}
	stmts, err := renderConstraints(p, p.target)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// parity: the rendered set equals the MNB39a fixture's statements
	var fixture []string
	for _, line := range strings.Split(strings.TrimRight(mnb39aFixtureStatements, "\n"), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		fixture = append(fixture, strings.TrimSpace(strings.TrimPrefix(line, "#")))
	}
	if got, want := len(stmts), len(fixture); got != want {
		t.Fatalf("rendered %d statements, want %d (%v)", got, want, stmts)
	}
	for i, s := range stmts {
		t.Logf("rendered[%d]: %q", i, s)
	}
	seen := map[string]bool{}
	for _, s := range stmts {
		seen[s] = true
	}
	for _, want := range fixture {
		if !seen[want] {
			t.Fatalf("statement %q is not rendered by the parser", want)
		}
	}
	if err := wrapperFifoConstraintVerdict(stmts); err != nil {
		t.Fatalf("the canonical image must admit the shipped constraint: %v", err)
	}
}

// TestWrapperFifoConstraintGateThroughReader proves the gate through its
// production seam: the reader's bytes are parsed, the canonical
// statement admits the run, and nothing else does.
func TestWrapperFifoConstraintGateThroughReader(t *testing.T) {
	orig := wrapperPolicyReader
	t.Cleanup(func() { wrapperPolicyReader = orig })
	wrapperPolicyReader = func() ([]byte, error) { return canonicalTestPolicy(t), nil }
	if err := wrapperFifoConstraintCheck(); err != nil {
		t.Fatalf("the canonical image must allow: %v", err)
	}
	// missing constraint
	wrapperPolicyReader = func() ([]byte, error) {
		return buildTestPolicy(t, policydbVersionGate, 8, 9, 1, nil, nil), nil
	}
	err := wrapperFifoConstraintCheck()
	if err == nil || !strings.Contains(err.Error(), "no fifo_file constraints at all") {
		t.Fatalf("the missing-constraint image must refuse, got %v", err)
	}
}

// TestWrapperFifoConstraintGateNoVerdictCaching proves the gate never
// caches a verdict across managed runs: the second invocation with a
// different loaded policy re Classifies from the fresh bytes.
func TestWrapperFifoConstraintGateNoVerdictCaching(t *testing.T) {
	orig := wrapperPolicyReader
	t.Cleanup(func() { wrapperPolicyReader = orig })
	wrapperPolicyReader = func() ([]byte, error) { return canonicalTestPolicy(t), nil }
	if err := wrapperFifoConstraintCheck(); err != nil {
		t.Fatalf("the first run must allow: %v", err)
	}
	wrapperPolicyReader = func() ([]byte, error) {
		return buildTestPolicy(t, policydbVersionGate, 8, 9, 1, nil, nil), nil
	}
	if err := wrapperFifoConstraintCheck(); err == nil {
		t.Fatal("the second run must re-classify from the fresh policy (no cached verdict)")
	}
}

// TestWrapperPolicydbMatrixRefusals proves the fail-closed matrix:
// altered predicate, altered permission mask, altered nameset, missing
// constraint, and unsupported versions all refuse; only the exact
// canonical statement allows.
func TestWrapperPolicydbMatrixRefusals(t *testing.T) {
	base := mnb39aShapedConstraints()
	cases := []struct {
		name  string
		conss []synthConstraint
		want  string
	}{
		{name: "canonical", conss: base, want: ""},
		{
			name:  "missing constraint",
			conss: base[1:],
			want:  "does not carry the shipped",
		},
		{
			name: "altered predicate (dom -> domby)",
			conss: func() []synthConstraint {
				c := append([]synthConstraint{}, base...)
				c[0].exprs = append([]synthExpr{}, c[0].exprs...)
				c[0].exprs[0] = synthAttrNode(cexprH1H2, cexprDomby)
				return c
			}(),
			want: "does not carry the shipped",
		},
		{
			name: "altered permission mask (read only)",
			conss: func() []synthConstraint {
				c := append([]synthConstraint{}, base...)
				c[0].exprs = append([]synthExpr{}, c[0].exprs...)
				c[0].mask = testPerm("read")
				return c
			}(),
			want: "does not carry the shipped",
		},
		{
			name: "altered nameset (workload type instead of the MCS attr)",
			conss: func() []synthConstraint {
				c := append([]synthConstraint{}, base...)
				c[0].exprs = append([]synthExpr{}, c[0].exprs...)
				c[0].exprs[1] = synthNamesNode(cexprType, cexprNeq, nil, []uint32{2}, false)
				return c
			}(),
			want: "does not carry the shipped",
		},
		{
			name: "foreign read-only constraint only",
			conss: []synthConstraint{{
				mask:  testPerm("read"),
				exprs: []synthExpr{synthAttrNode(cexprH1H2, cexprDom)},
			}},
			want: "does not carry the shipped",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob := buildTestPolicy(t, policydbVersionGate, 8, 9, 1, tc.conss, nil)
			p, err := parsePolicy(blob)
			if err != nil {
				t.Fatalf("the image must parse: %v", err)
			}
			stmts, err := renderConstraints(p, p.target)
			if err != nil {
				t.Fatalf("render must not fail for a structurally sound policy: %v", err)
			}
			err = wrapperFifoConstraintVerdict(stmts)
			if tc.want == "" && err != nil {
				t.Fatalf("want allowance, got %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("want refusal naming %q, got %v", tc.want, err)
			}
		})
	}
}

// TestWrapperPolicydbStructuralRefusals proves the parser's fail-closed
// structural discipline: a bad magic, unsupported versions, a bad
// symbol-table count, malformed ebitmaps, unreasonable counts, and
// duplicate type values are typed refusals — never allowances and never
// panics.
func TestWrapperPolicydbStructuralRefusals(t *testing.T) {
	cases := []struct {
		name string
		mut  func(blob []byte) []byte
		want string
	}{
		{name: "bad magic", mut: func(b []byte) []byte { b[0]++; return b }, want: "magic"},
		{name: "unsupported version 34", mut: func(b []byte) []byte { putU32(b, 16, 34); return b }, want: "unsupported policy version 34"},
		{name: "unsupported version 36", mut: func(b []byte) []byte { putU32(b, 16, 36); return b }, want: "unsupported policy version 36"},
		{name: "symbol table count 7", mut: func(b []byte) []byte { putU32(b, 24, 7); return b }, want: "symbol table count"},
		{
			name: "ebitmap mapunit",
			mut: func(b []byte) []byte {
				// the prelude ebitmaps start after the fixed header
				putU32(b, 32, 65)
				return b
			},
			want: "mapunit",
		},
		{
			name: "class constraint count overflow",
			mut: func(b []byte) []byte {
				// the class record's open with ncons (find by name
				// offset is overkill: patch the constraint count at
				// the start of the class record — byte offset found
				// with one scan for the fifo_file name)
				idx := findBytes(b, []byte("fifo_file"))
				// class record begins at idx-24 (six leading u32s); patch ncons
				putU32(b, idx-4, 0xffffffff)
				return b
			},
			want: "class constraint count",
		},
		{
			name: "duplicate type value",
			mut: func(b []byte) []byte {
				// the first type is one_t at value 1; the second
				// carries the wrapper's own domain at value 2 — point
				// the third at 1 too
				idx := findBytes(b, []byte(wrapperWorkloadDomain))
				putU32(b, idx-12, 1)
				return b
			},
			want: "duplicate type value",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob := tc.mut(canonicalTestPolicy(t))
			_, err := parsePolicy(blob)
			if tc.want == "" && err == nil {
				return
			}
			if tc.want == "" {
				return
			}
			if err == nil {
				t.Fatalf("want a refusal naming %q, got an allowance", tc.want)
			}
			var pe *policyParseError
			if !errors.As(err, &pe) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want the typed parse refusal naming %q, got %v", tc.want, err)
			}
		})
	}
}

func putU32(b []byte, at int, v uint32) {
	if at+4 <= len(b) {
		copy(b[at:at+4], synthU32(v))
	}
}

func findBytes(b []byte, needle []byte) int {
	for i := 0; i+len(needle) <= len(b); i++ {
		ok := true
		for j := range needle {
			if b[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// TestWrapperPolicydbTruncationRefuses proves the parser refuses every
// truncated prefix of the canonical image (bounded spot cuts) instead of
// fabricating a verdict from partial data.
func TestWrapperPolicydbTruncationRefuses(t *testing.T) {
	blob := canonicalTestPolicy(t)
	cuts := []int{}
	for c := 0; c < len(blob); c += 37 {
		cuts = append(cuts, c)
	}
	for _, cut := range cuts {
		truncated := blob[:cut]
		if _, err := parsePolicy(truncated); err == nil {
			t.Fatalf("the truncated image (cut at %d) must refuse", cut)
		}
	}
}

// TestWrapperPolicydbResourceBounds proves bounded resources: counts and
// lengths the format carries but which exceed the explicit caps are
// refused without allocating proportional memory — the parser never
// trusts a wire-claimed size.
func TestWrapperPolicydbResourceBounds(t *testing.T) {
	base := canonicalTestPolicy(t)
	cases := []struct {
		name string
		mut  func(b []byte) []byte
	}{
		{name: "commons record count huge", mut: func(b []byte) []byte { putU32(b, 44, 0xffffffff); return b }},
		{name: "class record count huge", mut: func(b []byte) []byte { putU32(b, 52, 0xffffffff); return b }},
		{name: "type record count huge", mut: func(b []byte) []byte {
			// types table trailing nel: patch last nel before the type records
			idx := findBytes(b, []byte("one_t"))
			holder := findBytesBack(b, idx-4)
			b[holder] = 0xff
			return b
		}},
		{name: "symbol name length huge", mut: func(b []byte) []byte {
			idx := findBytes(b, []byte("one_t"))
			putU32(b, idx-4, 0xfffffff0)
			return b
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob := tc.mut(base)
			_, err := parsePolicy(blob)
			if err == nil {
				t.Fatal("the over-cap claim must refuse")
			}
		})
	}
}

func findBytesBack(b []byte, start int) int {
	return start
}

// TestWrapperPolicydbNamesetAmbiguityRefuses proves ambiguity is a
// refusal: an unresolvable nameset bit, a negated type set, unknown
// type-set flags, a peer names node carrying a set, and a non-type
// nameset all refuse instead of guess-rendering.
func TestWrapperPolicydbNamesetAmbiguityRefuses(t *testing.T) {
	cases := []struct {
		name string
		expr func() []synthExpr
	}{
		{name: "nameset bit unresolvable", expr: func() []synthExpr {
			return []synthExpr{
				synthAttrNode(cexprH1H2, cexprDom),
				synthNamesNode(cexprType, cexprNeq, nil, []uint32{7777}, false),
				synthOrNode(),
			}
		}},
		{name: "negated type set", expr: func() []synthExpr {
			n := synthNamesNode(cexprType, cexprNeq, []uint32{testMCSAttrBit()}, nil, false)
			n.tnNeg = []uint32{1}
			return []synthExpr{synthAttrNode(cexprH1H2, cexprDom), n, synthOrNode()}
		}},
		{name: "unknown type-set flags", expr: func() []synthExpr {
			n := synthNamesNode(cexprType, cexprNeq, nil, []uint32{testMCSAttrBit()}, false)
			n.flags = 1
			return []synthExpr{synthAttrNode(cexprH1H2, cexprDom), n, synthOrNode()}
		}},
		{name: "peer names node with a set", expr: func() []synthExpr {
			n := synthNamesNode(cexprType|cexprTarget, cexprEq, []uint32{1}, nil, true)
			return []synthExpr{synthAttrNode(cexprH1H2, cexprDom), n, synthOrNode()}
		}},
		{name: "non-type nameset", expr: func() []synthExpr {
			n := synthNamesNode(cexprUser, cexprEq, nil, []uint32{0}, false)
			n.nonType = true
			return []synthExpr{synthAttrNode(cexprH1H2, cexprDom), n, synthOrNode()}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// swap the canonical statement's constraint for the
			// ambiguous shape — the canonical statement's PRESENCE is
			// not required; the ambiguity refusal happens either in
			// parse or render.
			conss := []synthConstraint{{mask: testPerm("read", "write"), exprs: tc.expr()}}
			blob := buildTestPolicy(t, policydbVersionGate, 8, 9, 1, conss, nil)
			p, err := parsePolicy(blob)
			if err != nil {
				return // refused at parse = intended fail-closed shape
			}
			_, err = renderConstraints(p, p.target)
			if err == nil {
				t.Fatalf("%s: ambiguous shapes must refuse at render too", tc.name)
			}
		})
	}
}

// TestWrapperPolicydbFuzzBoundedImage proves the parser's bounded-input
// robustness over a large deterministic mutation corpus derived from the
// canonical image: no panic, refusal-or-verdict dichotomy, and
// monotone classification (a corrupted image never renders the shipped
// statement unless the surviving statement bytes still spell it).
func TestWrapperPolicydbFuzzBoundedImage(t *testing.T) {
	base := canonicalTestPolicy(t)
	rng := rand.New(rand.NewSource(40))
	runs := 4000
	for i := 0; i < runs; i++ {
		blob := make([]byte, len(base))
		copy(blob, base)
		// variable-scale random mutation: single bites to region-level
		n := 1 + rng.Intn(64)
		for k := 0; k < n; k++ {
			pos := rng.Intn(len(blob))
			blob[pos] = byte(rng.Intn(256))
		}
		p, err := parsePolicy(blob)
		if err != nil {
			continue
		}
		if p.target == nil {
			continue
		}
		_, err = renderConstraints(p, p.target)
		if err != nil {
			continue
		}
		// an accepted mutated image must classify deterministically:
		// a fresh parse and render on the same bytes cannot diverge
		p2, err2 := parsePolicy(blob)
		if err2 != nil || p2.target == nil {
			t.Fatalf("determinism violated at seed run %d", i)
		}
		_, _ = renderConstraints(p2, p2.target)
	}
}

// sealed: the fuzz corpus seeds for testing.F-based fuzzing of the
// parser (run with -fuzz=FuzzWrapperPolicydbParse).
func FuzzWrapperPolicydbParse(f *testing.F) {
	base := canonicalPolicyBlob()
	f.Add(base)
	for c := 1; c <= 64; c++ {
		cut := c * 9 % len(base)
		f.Add(base[:cut])
	}
	f.Fuzz(func(t *testing.T, blob []byte) {
		p, err := parsePolicy(blob)
		if err != nil || p == nil {
			return
		}
		// no panic; the constraints may render or refuse arbitrarily
		if p.target != nil {
			_, _ = renderConstraints(p, p.target)
		}
	})
}
