//go:build linux

package main

// wrapper_policydb_linux.go owns the in-Go extraction of the loaded
// policy's fifo_file MLS constraint (MNB40): the wrapper no longer forks
// seinfo --constrain; it reads the LOADED binary policy
// (/sys/fs/selinux/policy — the authority that actually decides the
// workload FIFO accesses) and parses the kernel policydb format's
// constraint tree directly.
//
// The reader order follows the kernel's
// security/selinux/ss/policydb.c (policydb_read) and the statement
// rendering follows setools' seinfo --constrain output for the
// statements the gate judges. Both were established against the
// enforcing guest in the MNB39/MNB39a rounds; the MNB39a reference
// fixtures remain the parity comparators for the test suite (the
// fixture's provenance lives in the test file) — they are historical
// references, never runtime dependencies.
//
// Bounds discipline (fail-closed): every read is offset-checked against
// the policy buffer; every count, length, value, and name the format
// carries is bounded by an explicit cap before it can shape an
// allocation, a slice, or a loop; every structural anomaly (a bad
// magic, an unsupported version, a malformed structure, an invalid
// reference, an ambiguous or unresolvable constraint) is a typed parse
// refusal. A refused parse is a query failure the caller classifies;
// it is never an authoritative absence and never an allowance. Only
// version 35 is accepted; every other loaded-policy version fails
// closed.
//
// The gate never caches: every managed run re-reads and re-parses the
// loaded policy, so a policy reload re-arms the verdict immediately.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// The policydb and constraint wire constants (kernel policydb.h /
// constraint.h).
const (
	policydbMagic = 0xf97cff8c

	// policydbVersionGate is the ONE version this parser accepts. The
	// measured distro loaded policy carries exactly this version; an
	// older or newer loaded policy is a refusal, never a best-effort
	// parse.
	policydbVersionGate = 35

	// The stream-layout switch names come from the kernel versions
	// that introduce each element, so the layout stays auditable.
	policyVersionValidatetrans   = 19 // validatetrans streams on classes
	policyVersionPolcap          = 22 // policycaps ebitmap in the prelude
	policyVersionPermissive      = 23 // permissive ebitmap in the prelude
	policyVersionConstraintNames = 29 // constraint type-set ebitmaps
	policyVersionNeveraudit      = 35 // neveraudit ebitmap in the prelude

	cexprNot   = 1
	cexprAnd   = 2
	cexprOr    = 3
	cexprAttr  = 4
	cexprNames = 5

	cexprUser    = 1
	cexprRole    = 2
	cexprType    = 4
	cexprTarget  = 8
	cexprXTarget = 16
	cexprL1L2    = 32
	cexprL1H2    = 64
	cexprH1L2    = 128
	cexprH1H2    = 256
	cexprL1H1    = 512
	cexprL2H2    = 1024

	cexprEq     = 1
	cexprNeq    = 2
	cexprDom    = 3
	cexprDomby  = 4
	cexprIncomp = 5

	cexprMaxDepth = 5

	// The constraint class the gate extracts. Type names resolve at
	// render time from the types table parsed after the classes
	// symtab, so the target class's constraint byte range is captured
	// during the class walk and rendered afterwards.
	wrapperFifoConstraintClass = "fifo_file"
)

// Explicit parser caps: every count the loaded policy carries is
// bounded before it can shape an allocation or a loop. The caps exceed
// the measured distro loaded policy by a wide margin while keeping
// malformed input from driving allocation or work by its own claims.
const (
	// policyReadCeiling bounds the policy file read (the measured
	// distro loaded policy is ~3.9 MB). A larger or empty read is a
	// refusal, never a partial parse.
	policyReadCeiling = 64 << 20
	// maxPolicyName bounds one symbol name; SELinux symbol names are
	// far shorter.
	maxPolicyName = 256
	// maxPolicyCommons, maxPolicyClasses, maxPolicyRoles and
	// maxPolicyTypes bound the symbol tables' record claims.
	maxPolicyCommons = 64
	maxPolicyClasses = 1024
	maxPolicyRoles   = 1 << 17
	maxPolicyTypes   = 1 << 17
	// maxPolicyEBitmapNodes bounds one ebitmap's node count.
	maxPolicyEBitmapNodes = 8192
	// maxPolicyExprNodes bounds one constraint expression's node
	// count.
	maxPolicyExprNodes = 64
	// maxPolicyConstraintCount bounds one class's constraint and
	// validatetrans lists.
	maxPolicyConstraintCount = 1024
	// maxPermsPerSymbol caps the per-class/common permission capacity.
	maxPermsPerSymbol = 32
	// maxRenderedStatement bounds one rendered statement so a
	// pathological nameset cannot drive rendering work on its own
	// claim.
	maxRenderedStatement = 4096
)

// wrapperLoadedPolicyPath is the kernel-deciding loaded binary policy —
// the top of the check's authority chain. The gate never consults a
// configured policy file, a module store listing, or an installed CIL
// artifact.
const wrapperLoadedPolicyPath = "/sys/fs/selinux/policy"

// policyParseError is the typed parse refusal: it reports where in the
// loaded policy the structure broke. The offset makes the failure
// auditable.
type policyParseError struct {
	off  int
	what string
}

func (e *policyParseError) Error() string {
	return fmt.Sprintf("the loaded policy is malformed at offset %d: %s", e.off, e.what)
}

// policyReader walks one policy image with strict offsets. Every raw
// accessor verifies the claim against the remaining bytes and the caps
// before it advances or allocates.
type policyReader struct {
	b []byte
	o int
}

func (r *policyReader) fail(what string) error {
	return &policyParseError{off: r.o, what: what}
}

func (r *policyReader) u32() (uint32, error) {
	if len(r.b)-r.o < 4 {
		return 0, r.fail("truncated u32")
	}
	v := uint32(r.b[r.o]) | uint32(r.b[r.o+1])<<8 |
		uint32(r.b[r.o+2])<<16 | uint32(r.b[r.o+3])<<24
	r.o += 4
	return v, nil
}

func (r *policyReader) u64() (uint64, error) {
	if len(r.b)-r.o < 8 {
		return 0, r.fail("truncated u64")
	}
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(r.b[r.o+i])
	}
	r.o += 8
	return v, nil
}

// rawName reads the length-prefixed symbol name of a datum whose
// length word was already consumed by the caller.
func (r *policyReader) rawName(n uint32, what string) (string, error) {
	if n == 0 || n > maxPolicyName {
		return "", r.fail(what)
	}
	if len(r.b)-r.o < int(n) {
		return "", r.fail("truncated " + what)
	}
	s := string(r.b[r.o : r.o+int(n)])
	r.o += int(n)
	return s, nil
}

// name reads one self-length-prefixed name (header string, perm
// names).
func (r *policyReader) name() (string, error) {
	n, err := r.u32()
	if err != nil {
		return "", err
	}
	return r.rawName(n, "symbol name")
}

// ebitmap reads one kernel ebitmap (mapunit 64; highbit; node count;
// then each node as start bit + 64-bit map) and returns its set bit
// indices in ascending bit order.
func (r *policyReader) ebitmap() ([]uint32, error) {
	mapUnit, err := r.u32()
	if err != nil {
		return nil, err
	}
	if mapUnit != 64 {
		return nil, r.fail("ebitmap mapunit")
	}
	if _, err := r.u32(); err != nil { // highbit
		return nil, err
	}
	count, err := r.u32()
	if err != nil {
		return nil, err
	}
	if count > maxPolicyEBitmapNodes {
		return nil, r.fail("ebitmap node count")
	}
	bits := make([]uint32, 0)
	for i := uint32(0); i < count; i++ {
		start, err := r.u32()
		if err != nil {
			return nil, err
		}
		m, err := r.u64()
		if err != nil {
			return nil, err
		}
		for b := 0; b < 64; b++ {
			if m>>uint(b)&1 != 0 {
				bits = append(bits, start+uint32(b))
			}
		}
	}
	return bits, nil
}

// policyCommon is one parsed common record.
type policyCommon struct {
	name   string
	nprim  uint32
	values map[uint32]string
}

// policyClass is one parsed class record. The constraint byte range
// (consOff/consEnd within the policy image) is exactly the captured
// region the rendering walks; the non-constraint suffix
// (validatetrans, class defaults) is validated with its own stream
// discipline but is not retained.
type policyClass struct {
	name    string
	nprim   uint32
	comkey  string
	values  map[uint32]string
	consOff int
	consEnd int
	ncons   int
}

// parsedPolicy is one completed in-memory parse of one policy image.
type parsedPolicy struct {
	blob    []byte
	version uint32
	mls     bool
	commons []policyCommon
	classes []policyClass
	types   []string // types[value-1] = name ("" while reserved)
	// target is the gate's class record (nil when the loaded policy
	// carries no such class — itself a fail-closed verdict).
	target *policyClass
}

// wrapperPolicyReader is the policy-file seam: production reads the
// fixed selinuxfs loaded-policy path and nothing else. A configured
// policy file or a module-store listing is never consulted. The read is
// sized first and bounded by policyReadCeiling; a torn or short read is
// a refusal, never a partial parse. Package-global; tests restore it.
var wrapperPolicyReader = func() ([]byte, error) {
	f, err := os.Open(wrapperLoadedPolicyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", wrapperLoadedPolicyPath, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot size %s: %w", wrapperLoadedPolicyPath, err)
	}
	size := st.Size()
	if size <= 0 || size > policyReadCeiling {
		return nil, fmt.Errorf(
			"the loaded policy size %d is outside the %d-byte read ceiling",
			size, policyReadCeiling)
	}
	blob := make([]byte, size)
	if _, err := io.ReadFull(f, blob); err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", wrapperLoadedPolicyPath, err)
	}
	// A policy reload that swaps the image between the sizing and the
	// read yields either the full older image byte-exactly or a
	// structurally broken stream; the parse below refuses a broken
	// stream, so the verdict is always made on one self-consistent
	// policy image.
	return blob, nil
}

// parsePolicy walks one policy image through exactly the structures the
// constraint extraction needs: the prelude, the four symbol tables
// (commons, classes, roles, types — the roles table is walked in full
// order but retained in nothing; constraint byte ranges are captured
// during the class walk), then the target class is resolved.
func parsePolicy(blob []byte) (*parsedPolicy, error) {
	p := &parsedPolicy{blob: blob}
	r := &policyReader{b: blob}
	if err := parsePolicyPrelude(p, r); err != nil {
		return nil, err
	}
	if err := parsePolicySymbolTables(p, r); err != nil {
		return nil, err
	}
	// Exactly one class record may carry the gate's class name; a
	// duplicate is a malformed store and refuses.
	for i := range p.classes {
		if p.classes[i].name == wrapperFifoConstraintClass {
			if p.target != nil {
				return nil, &policyParseError{
					off:  len(blob),
					what: "duplicate " + wrapperFifoConstraintClass + " class record",
				}
			}
			p.target = &p.classes[i]
		}
	}
	return p, nil
}

// parsePolicyPrelude reads header and prelude ebitmaps (policycaps
// v22+, permissive v23+, neveraudit v35+ — all present at the gate
// version). The version is validated before anything else is walked.
func parsePolicyPrelude(p *parsedPolicy, r *policyReader) error {
	magic, err := r.u32()
	if err != nil {
		return err
	}
	if magic != policydbMagic {
		return r.fail("not a policydb (magic)")
	}
	str, err := r.name()
	if err != nil {
		return err
	}
	if str != "SE Linux" {
		return r.fail("policy string")
	}
	ver, err := r.u32()
	if err != nil {
		return err
	}
	if ver != policydbVersionGate {
		return r.fail(fmt.Sprintf("unsupported policy version %d (this gate parses version %d only)",
			ver, policydbVersionGate))
	}
	p.version = ver
	config, err := r.u32()
	if err != nil {
		return err
	}
	p.mls = config&1 != 0
	symNum, err := r.u32()
	if err != nil {
		return err
	}
	if symNum != 8 {
		return r.fail("unexpected symbol table count")
	}
	oconNum, err := r.u32()
	if err != nil {
		return err
	}
	if oconNum > 1024 {
		return r.fail("ocontext count")
	}
	if _, err := r.ebitmap(); err != nil { // policycaps (v22+)
		return err
	}
	if _, err := r.ebitmap(); err != nil { // permissive (v23+)
		return err
	}
	if _, err := r.ebitmap(); err != nil { // neveraudit (v35+)
		return err
	}
	return nil
}

// parsePolicySymbolTables walks the four symbol tables in store order:
// commons, classes, roles, types. The role record's ebitmaps are
// consumed to keep the stream aligned and droppable; type names slot by
// value-1 so constraint namesets resolve through the types table.
func parsePolicySymbolTables(p *parsedPolicy, r *policyReader) error {
	if _, err := r.u32(); err != nil { // commons nprim
		return err
	}
	nel, err := r.u32()
	if err != nil {
		return err
	}
	if nel > maxPolicyCommons {
		return r.fail("commons record count")
	}
	for i := uint32(0); i < nel; i++ {
		cm, err := parsePolicyCommonRecord(r)
		if err != nil {
			return err
		}
		p.commons = append(p.commons, cm)
	}
	if _, err := r.u32(); err != nil { // classes nprim
		return err
	}
	nel, err = r.u32()
	if err != nil {
		return err
	}
	if nel > maxPolicyClasses {
		return r.fail("class record count")
	}
	for i := uint32(0); i < nel; i++ {
		c, err := parsePolicyClassRecord(r)
		if err != nil {
			return err
		}
		p.classes = append(p.classes, c)
	}
	if _, err := r.u32(); err != nil { // roles nprim
		return err
	}
	nel, err = r.u32()
	if err != nil {
		return err
	}
	if nel > maxPolicyRoles {
		return r.fail("role record count")
	}
	for i := uint32(0); i < nel; i++ {
		if err := parsePolicyRoleRecord(r, i+1); err != nil {
			return err
		}
	}
	if _, err := r.u32(); err != nil { // types nprim
		return err
	}
	nel, err = r.u32()
	if err != nil {
		return err
	}
	if nel > maxPolicyTypes {
		return r.fail("type record count")
	}
	for i := uint32(0); i < nel; i++ {
		name, value, err := parsePolicyTypeRecord(r)
		if err != nil {
			return err
		}
		if value == 0 || value > maxPolicyTypes {
			return r.fail("type value out of range")
		}
		// The type's bitmap index is value-1; sparse values are legal
		// and reserve-fill the table.
		for len(p.types) < int(value) {
			p.types = append(p.types, "")
		}
		if p.types[value-1] != "" {
			return r.fail("duplicate type value")
		}
		p.types[value-1] = name
	}
	return nil
}

// parsePolicyCommonRecord reads one common datum: name length, value,
// perms nprim, perm record count, name, then the perm records
// {name length, value, name}.
func parsePolicyCommonRecord(r *policyReader) (policyCommon, error) {
	var cm policyCommon
	hlen, err := r.u32()
	if err != nil {
		return cm, err
	}
	value, err := r.u32()
	if err != nil {
		return cm, err
	}
	nprim, err := r.u32()
	if err != nil {
		return cm, err
	}
	nel, err := r.u32()
	if err != nil {
		return cm, err
	}
	if hlen == 0 || hlen > maxPolicyName {
		return cm, r.fail("common name length")
	}
	if cm.name, err = r.rawName(hlen, "common name"); err != nil {
		return cm, err
	}
	if value == 0 {
		return cm, r.fail("common value out of range")
	}
	if nprim > maxPermsPerSymbol {
		return cm, r.fail("common perm capacity")
	}
	if nel > maxPermsPerSymbol {
		return cm, r.fail("common perm record count")
	}
	cm.nprim = nprim
	cm.values = make(map[uint32]string, nel)
	for i := uint32(0); i < nel; i++ {
		plen, err := r.u32()
		if err != nil {
			return cm, err
		}
		pval, err := r.u32()
		if err != nil {
			return cm, err
		}
		if plen == 0 || plen > maxPolicyName || pval == 0 || pval > nprim {
			return cm, r.fail("common perm record")
		}
		pname, err := r.rawName(plen, "common perm name")
		if err != nil {
			return cm, err
		}
		cm.values[pval] = pname
	}
	return cm, nil
}

// parsePolicyClassRecord reads one class datum: name length, common key
// length, value, perms nprim, own perm record count, constraint count,
// name, [common key], own perm records {length, value, name}, the
// constraint stream (whose byte range is captured), the validatetrans
// stream (v19+), and the class defaults (v27+ user/role/range, v28+
// type).
func parsePolicyClassRecord(r *policyReader) (policyClass, error) {
	var c policyClass
	hlen, err := r.u32()
	if err != nil {
		return c, err
	}
	comkeyLen, err := r.u32()
	if err != nil {
		return c, err
	}
	if _, err := r.u32(); err != nil { // value
		return c, err
	}
	nprim, err := r.u32()
	if err != nil {
		return c, err
	}
	ownPermCount, err := r.u32()
	if err != nil {
		return c, err
	}
	ncons, err := r.u32()
	if err != nil {
		return c, err
	}
	if hlen == 0 || hlen > maxPolicyName {
		return c, r.fail("class name length")
	}
	if c.name, err = r.rawName(hlen, "class name"); err != nil {
		return c, err
	}
	if comkeyLen > maxPolicyName {
		return c, r.fail("class common key length")
	}
	if comkeyLen != 0 {
		if c.comkey, err = r.rawName(comkeyLen, "class common key"); err != nil {
			return c, err
		}
	}
	if nprim > maxPermsPerSymbol {
		return c, r.fail("class perm capacity")
	}
	if ownPermCount > maxPermsPerSymbol {
		return c, r.fail("class own perm record count")
	}
	if ncons > maxPolicyConstraintCount {
		return c, r.fail("class constraint count")
	}
	c.nprim = nprim
	c.ncons = int(ncons)
	c.values = make(map[uint32]string, ownPermCount)
	for i := uint32(0); i < ownPermCount; i++ {
		plen, err := r.u32()
		if err != nil {
			return c, err
		}
		pval, err := r.u32()
		if err != nil {
			return c, err
		}
		if plen == 0 || plen > maxPolicyName || pval == 0 || pval > nprim {
			return c, r.fail("class own perm record")
		}
		pname, err := r.rawName(plen, "class own perm name")
		if err != nil {
			return c, err
		}
		c.values[pval] = pname
	}
	// The target class's consumed constraint span, exactly.
	c.consOff = r.o
	if err := walkConstraintList(r, ncons, false); err != nil {
		return c, err
	}
	c.consEnd = r.o
	nvt, err := r.u32()
	if err != nil {
		return c, err
	}
	if nvt > maxPolicyConstraintCount {
		return c, r.fail("class validatetrans count")
	}
	if err := walkConstraintList(r, nvt, true); err != nil {
		return c, err
	}
	// class defaults: default_user, default_role, default_range
	// (v27+), default_type (v28+)
	if _, err := r.u32(); err != nil {
		return c, err
	}
	if _, err := r.u32(); err != nil {
		return c, err
	}
	if _, err := r.u32(); err != nil {
		return c, err
	}
	if _, err := r.u32(); err != nil {
		return c, err
	}
	return c, nil
}

// parsePolicyRoleRecord reads one role datum: name length, value,
// bounds, name, the role-dominates ebitmap, and the role-types ebitmap.
// object_r is the kernel's first pre-inserted record and consumes its
// streamed datum too; both ebitmaps are read purely to keep the record
// boundary exact. The streamed value is bounds-checked only (the distro
// policy's role values are not stream positions).
func parsePolicyRoleRecord(r *policyReader, idx uint32) error {
	hlen, err := r.u32()
	if err != nil {
		return err
	}
	value, err := r.u32()
	if err != nil {
		return err
	}
	if _, err := r.u32(); err != nil { // bounds
		return err
	}
	if _, err := r.rawName(hlen, "role name"); err != nil {
		return err
	}
	// the streamed role VALUE is the kernel's own identifier; the distro
	// policy carries values that do not equal the stream position (the
	// measured enforcing guest rejects the stream-index identity), so the
	// value is only bounds-checked, never equality-checked
	if value == 0 || value > maxPolicyRoles {
		return r.fail(fmt.Sprintf("role value %d at streamed record %d", value, idx))
	}
	if _, err := r.ebitmap(); err != nil { // role-dominates
		return err
	}
	if _, err := r.ebitmap(); err != nil { // role-types
		return err
	}
	return nil
}

// parsePolicyTypeRecord reads one type datum: name length, value,
// primary/attribute property bits, bounds, name.
func parsePolicyTypeRecord(r *policyReader) (string, uint32, error) {
	hlen, err := r.u32()
	if err != nil {
		return "", 0, err
	}
	value, err := r.u32()
	if err != nil {
		return "", 0, err
	}
	if _, err := r.u32(); err != nil { // primary/attr property bits
		return "", 0, err
	}
	if _, err := r.u32(); err != nil { // bounds
		return "", 0, err
	}
	name, err := r.rawName(hlen, "type name")
	if err != nil {
		return "", 0, err
	}
	return name, value, nil
}

// walkConstraintList validates a class's constraint (or validatetrans)
// list entry by entry.
func walkConstraintList(r *policyReader, count uint32, allowXTarget bool) error {
	for i := uint32(0); i < count; i++ {
		if _, err := r.u32(); err != nil { // permissions mask
			return err
		}
		nn, err := r.u32()
		if err != nil {
			return err
		}
		if nn > maxPolicyExprNodes {
			return r.fail("constraint expression node count")
		}
		if err := walkExprStream(r, nn, allowXTarget); err != nil {
			return err
		}
	}
	return nil
}

// walkExprStream validates one constraint expression in kernel wire
// order (RPN): node depths are well-formed exactly as the kernel's own
// consistency checks require, and NAMES nodes carry their ebitmaps —
// plain names, then the type-set trios at the gate version (v29+).
func walkExprStream(r *policyReader, nexpr uint32, allowXTarget bool) error {
	depth := 0
	for j := uint32(0); j < nexpr; j++ {
		et, err := r.u32()
		if err != nil {
			return err
		}
		attr, err := r.u32()
		if err != nil {
			return err
		}
		op, err := r.u32()
		if err != nil {
			return err
		}
		switch et {
		case cexprNot:
			if depth < 1 {
				return r.fail("expression NOT stack")
			}
		case cexprAnd, cexprOr:
			if depth < 2 {
				return r.fail("expression AND/OR stack")
			}
			depth--
		case cexprAttr:
			if depth >= cexprMaxDepth {
				return r.fail("expression ATTR depth")
			}
			depth++
			switch attr {
			case cexprUser, cexprType:
				if op != cexprEq && op != cexprNeq {
					return r.fail("expression USER/TYPE op")
				}
			case cexprRole, cexprL1L2, cexprL1H2, cexprH1L2, cexprH1H2, cexprL1H1, cexprL2H2:
				if op < cexprEq || op > cexprIncomp {
					return r.fail("expression op range")
				}
			default:
				return r.fail("expression attr kind")
			}
		case cexprNames:
			if !allowXTarget && attr&cexprXTarget != 0 {
				return r.fail("expression xtarget in constraint")
			}
			if depth >= cexprMaxDepth {
				return r.fail("expression NAMES depth")
			}
			depth++
			switch attr &^ (cexprTarget | cexprXTarget) {
			case cexprUser, cexprRole, cexprType:
			default:
				return r.fail("expression names attr kind")
			}
			if attr&(cexprTarget|cexprXTarget) == cexprTarget|cexprXTarget {
				return r.fail("expression names xtarget")
			}
			if op != cexprEq && op != cexprNeq {
				return r.fail("expression names op")
			}
			if _, err := r.ebitmap(); err != nil { // names
				return err
			}
			if _, err := r.ebitmap(); err != nil { // type-set types (v29+)
				return err
			}
			if _, err := r.ebitmap(); err != nil { // type-set neg set
				return err
			}
			if _, err := r.u32(); err != nil { // type-set flags
				return err
			}
		default:
			return r.fail("expression node kind")
		}
	}
	if depth != 1 {
		return r.fail("expression stack shape")
	}
	return nil
}

// renderConstraints renders one class's captured constraint byte range
// into the statement list the gate judges, in store order, exactly
// seinfo-faithful.
func renderConstraints(p *parsedPolicy, c *policyClass) ([]string, error) {
	if c.consEnd < c.consOff || c.consEnd > len(p.blob) {
		return nil, fmt.Errorf("the loaded policy carries an unrenderable %s constraint range", c.name)
	}
	r := &policyReader{b: p.blob[c.consOff:c.consEnd]}
	stmts := make([]string, 0, c.ncons)
	for i := 0; i < c.ncons; i++ {
		perms, err := r.u32()
		if err != nil {
			return nil, err
		}
		nn, err := r.u32()
		if err != nil {
			return nil, err
		}
		if nn > maxPolicyExprNodes {
			return nil, r.fail("constraint expression node count")
		}
		expr, mls, err := renderExprStream(p, r, nn)
		if err != nil {
			return nil, err
		}
		permNames, err := renderPermNames(p, c, perms)
		if err != nil {
			return nil, err
		}
		kind := "constraint"
		if mls {
			kind = "mlsconstrain"
		}
		var sb strings.Builder
		sb.WriteString(kind)
		sb.WriteByte(' ')
		sb.WriteString(c.name)
		sb.WriteByte(' ')
		sb.WriteString(permNames)
		sb.WriteByte(' ')
		if !strings.HasPrefix(expr, "(") {
			sb.WriteByte('(')
			sb.WriteString(expr)
			sb.WriteString(");")
		} else {
			sb.WriteString(expr)
			sb.WriteString(";")
		}
		if sb.Len() > maxRenderedStatement {
			return nil, r.fail("rendered statement length")
		}
		stmts = append(stmts, sb.String())
	}
	return stmts, nil
}

// renderPermNames resolves one constraint's permission mask against the
// class's common perms and own perms, in bit order, with setools'
// bracing for multi-perm masks.
func renderPermNames(p *parsedPolicy, c *policyClass, mask uint32) (string, error) {
	var common *policyCommon
	if c.comkey != "" {
		for i := range p.commons {
			if p.commons[i].name == c.comkey {
				common = &p.commons[i]
				break
			}
		}
	}
	var names []string
	for bit := 0; bit < maxPermsPerSymbol; bit++ {
		if mask>>uint(bit)&1 == 0 {
			continue
		}
		pval := uint32(bit + 1)
		var nm string
		if common != nil {
			nm = common.values[pval]
		}
		if nm == "" {
			nm = c.values[pval]
		}
		if nm == "" {
			return "", fmt.Errorf("the loaded policy's %s constraint carries permission bit %d that does not resolve", c.name, bit)
		}
		names = append(names, nm)
	}
	switch len(names) {
	case 0:
		return "", fmt.Errorf("the loaded policy's %s constraint carries an empty permission mask", c.name)
	case 1:
		return names[0], nil
	default:
		return "{ " + strings.Join(names, " ") + " }", nil
	}
}

// typeSetNames resolves a NAMES node's rendered names through the
// type-set trio the gate version stores: the type-set types when
// present, otherwise the plain names bitmap, with every bit resolved
// against the types table. Anything unresolvable or adorned (a neg set,
// unknown flags) is ambiguous and refuses.
func typeSetNames(p *parsedPolicy, namesBits, tnBits, tnNegBits []uint32) ([]string, error) {
	if len(tnNegBits) != 0 {
		return nil, errors.New("constraint nameset carries a negated type set")
	}
	use := namesBits
	if len(tnBits) != 0 {
		use = tnBits
	}
	if len(use) == 0 {
		return nil, errors.New("constraint nameset is empty")
	}
	names := make([]string, 0, len(use))
	for _, bit := range use {
		if bit >= uint32(len(p.types)) {
			return nil, fmt.Errorf("constraint nameset bit %d does not resolve to a type", bit)
		}
		name := p.types[bit]
		if name == "" {
			return nil, fmt.Errorf("constraint nameset bit %d does not resolve to a type", bit)
		}
		names = append(names, name)
	}
	return names, nil
}

// renderExprStream renders one expression in kernel RPN order onto a
// bounded string stack, faithfully to the measured seinfo rendering:
// infix "==" / "!=" for the equality family (pairwise, simple, and
// named alike), plain "dom"/"domby"/"incomp" for the ordering family;
// namesets rendered from their bit-resolved type names, braced only
// when they hold more than one name; peer references (CEXPR_TARGET
// names nodes with an empty set) rendered as the u2/r2/t2 peer ident.
// Any structural irregularity is a typed refusal, never a partially
// rendered statement.
func renderExprStream(p *parsedPolicy, r *policyReader, nexpr uint32) (string, bool, error) {
	var stack [cexprMaxDepth]string
	sp := 0
	mls := false
	for j := uint32(0); j < nexpr; j++ {
		et, err := r.u32()
		if err != nil {
			return "", false, err
		}
		attr, err := r.u32()
		if err != nil {
			return "", false, err
		}
		op, err := r.u32()
		if err != nil {
			return "", false, err
		}
		switch et {
		case cexprAttr:
			if attr >= cexprL1L2 && attr <= cexprL2H2 {
				// pairwise (two-level) comparison: the kernel packs
				// both level fields into one attributes word; setools
				// renders it as an infix triple.
				mls = true
				left, right, ok := pairwiseSides(attr)
				if !ok {
					return "", false, r.fail("expr attr kind")
				}
				o, errt := constraintOpText(op)
				if errt != nil {
					return "", false, r.fail("expr op kind")
				}
				if err := pushRender(&stack, &sp, left+" "+o+" "+right); err != nil {
					return "", false, err
				}
				break
			}
			var lead string
			switch attr {
			case cexprUser:
				lead = "u1"
			case cexprRole:
				lead = "r1"
			case cexprType:
				lead = "t1"
			default:
				return "", false, r.fail("expr attr kind")
			}
			o, errt := constraintOpText(op)
			if errt != nil {
				return "", false, r.fail("expr op kind")
			}
			if err := pushRender(&stack, &sp, lead+" "+o); err != nil {
				return "", false, err
			}
		case cexprNames:
			namesBits, err := r.ebitmap()
			if err != nil {
				return "", false, err
			}
			tnBits, err := r.ebitmap()
			if err != nil {
				return "", false, err
			}
			tnNegBits, err := r.ebitmap()
			if err != nil {
				return "", false, err
			}
			flags, err := r.u32()
			if err != nil {
				return "", false, err
			}
			if flags != 0 {
				return "", false, r.fail("constraint nameset carries unknown type-set flags")
			}
			o, errt := constraintOpText(op)
			if errt != nil {
				return "", false, r.fail("expr op kind")
			}
			lead, peer, ok := namesLead(attr)
			if !ok {
				return "", false, r.fail("expr names attr kind")
			}
			if peer != "" {
				// CEXPR_TARGET: the kernel encodes a peer comparison
				// (u1 == u2) as a names node whose set is empty; a
				// set of names in that shape is ambiguous.
				if len(namesBits) != 0 || len(tnBits) != 0 || len(tnNegBits) != 0 {
					return "", false, r.fail("peer names node carries a set")
				}
				if err := pushRender(&stack, &sp, lead+" "+o+" "+peer); err != nil {
					return "", false, err
				}
				break
			}
			base := attr &^ (cexprTarget | cexprXTarget)
			if base != cexprType {
				return "", false, r.fail("non-type nameset is unresolvable")
			}
			names, err := typeSetNames(p, namesBits, tnBits, tnNegBits)
			if err != nil {
				return "", false, err
			}
			rendered := names[0]
			if len(names) > 1 {
				rendered = "{ " + strings.Join(names, " ") + " }"
			}
			if err := pushRender(&stack, &sp, lead+" "+o+" "+rendered); err != nil {
				return "", false, err
			}
		case cexprNot:
			sp--
			stack[sp] = "(not " + stack[sp] + ")"
			sp++
		case cexprAnd, cexprOr:
			o := "and"
			if et == cexprOr {
				o = "or"
			}
			sp -= 2
			left, right := stack[sp], stack[sp+1]
			if err := pushRender(&stack, &sp, "("+left+" "+o+" "+right+")"); err != nil {
				return "", false, err
			}
		default:
			return "", false, r.fail("expr node kind")
		}
	}
	if sp != 1 {
		return "", false, r.fail("rendered expression stack shape")
	}
	return stack[0], mls, nil
}

// pushRender pushes one rendered node onto the bounded expression
// stack, refusing overflow and oversized renderings explicitly.
func pushRender(stack *[cexprMaxDepth]string, sp *int, s string) error {
	if *sp < 0 || *sp >= cexprMaxDepth {
		return fmt.Errorf("the loaded policy constraint expression exceeds the %d-node render depth", cexprMaxDepth)
	}
	if len(s) > maxRenderedStatement {
		return fmt.Errorf("the loaded policy constraint rendering exceeds %d bytes", maxRenderedStatement)
	}
	stack[*sp] = s
	*sp++
	return nil
}

// constraintOpText renders one constraint operator in setools' spelling
// ("==" / "!=" for the equality family, plain words for the ordering
// family); anything else is a typed refusal.
func constraintOpText(op uint32) (string, error) {
	switch op {
	case cexprEq:
		return "==", nil
	case cexprNeq:
		return "!=", nil
	case cexprDom:
		return "dom", nil
	case cexprDomby:
		return "domby", nil
	case cexprIncomp:
		return "incomp", nil
	}
	return "", fmt.Errorf("the loaded policy constraint carries operator %d, which has no rendering", op)
}

// pairwiseSides maps a pairwise (two-level) constraint attribute to the
// setools side pair.
func pairwiseSides(attr uint32) (string, string, bool) {
	switch attr {
	case cexprL1L2:
		return "l1", "l2", true
	case cexprL1H2:
		return "l1", "h2", true
	case cexprH1L2:
		return "h1", "l2", true
	case cexprH1H2:
		return "h1", "h2", true
	case cexprL1H1:
		return "l1", "h1", true
	case cexprL2H2:
		return "l2", "h2", true
	}
	return "", "", false
}

// namesLead maps a NAMES attributes word to the leading token and,
// when CEXPR_TARGET is set, the peer ident (u2/r2/t2); an empty peer
// string marks the ordinary names-bearing node.
func namesLead(attr uint32) (string, string, bool) {
	base := attr &^ (cexprTarget | cexprXTarget)
	var peer string
	if attr&cexprTarget != 0 {
		peer = "2"
	}
	switch base {
	case cexprUser:
		if peer != "" {
			return "u1", "u2", true
		}
		return "u1", "", true
	case cexprRole:
		if peer != "" {
			return "r1", "r2", true
		}
		return "r1", "", true
	case cexprType:
		if peer != "" {
			return "t1", "t2", true
		}
		return "t1", "", true
	}
	return "", "", false
}

// wrapperFifoConstraintCheck is the injectable constraint admission
// gate (the same package seam the runtime pipeline consumes): the gate
// reads the LOADED kernel policy, parses it, renders the gate class's
// constraint statements, and requires the exact shipped statement. No
// tooling is spawned; no verdict is cached; the store listing and the
// installed artifact are never consulted. Package-global; tests restore
// it.
var wrapperFifoConstraintCheck = func() error {
	blob, err := wrapperPolicyReader()
	if err != nil {
		return err
	}
	p, err := parsePolicy(blob)
	if err != nil {
		return err
	}
	var stmts []string
	if p.target != nil {
		stmts, err = renderConstraints(p, p.target)
		if err != nil {
			return err
		}
	}
	return wrapperFifoConstraintVerdict(stmts)
}

// wrapperFifoConstraintVerdict is the exact-statement classifier over
// the parsed-and-rendered constraint statement list: the canonical
// shipped statement must be present word-exactly (a parsed rendering is
// already canonical, so no whitespace normalization exists); no target
// class, no statements, or no match is a refusal naming the operator
// remediation.
func wrapperFifoConstraintVerdict(stmts []string) error {
	for _, stmt := range stmts {
		if stmt == wrapperFifoConstraintStatement {
			return nil
		}
	}
	if len(stmts) == 0 {
		return fmt.Errorf(
			"the loaded policy carries no %s constraints at all; refusing the run (repair: %s)",
			wrapperFifoConstraintClass, wrapperFifoConstraintRemediation)
	}
	return fmt.Errorf(
		"the loaded policy does not carry the shipped fifo_file read/write isolation constraint; refusing the run (repair: %s)",
		wrapperFifoConstraintRemediation)
}
