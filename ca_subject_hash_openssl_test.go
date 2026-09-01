package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// opensslDifferentialEnv is the test-only required-mode environment variable
// that enables the live OpenSSL differential test. It is never consulted by
// production code.
const opensslDifferentialEnv = "DOCKER_HELPER_OPENSSL_DIFFERENTIAL"

// corpusBytes decodes a hex DER literal into bytes. It is used to keep the
// checked-in corpus readable as hex strings rather than long byte slices.
func corpusBytes(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return b
}

// opensslSubjectHashCase is one entry in the OpenSSL subject-hash differential
// corpus: a raw subject DER Name plus the subject hash produced by OpenSSL.
//
// The expected hash is an INDEPENDENT OpenSSL oracle value. It was produced
// (never by computeOpenSSLSubjectHash) by building a self-signed certificate
// whose RawSubject is exactly rawSubject, writing it as PEM, and running:
//
//	openssl x509 -in cert.pem -hash -noout
//
// against OpenSSL 3.5.8 (OpenSSL 3.5.8 25 Aug 2026, Debian). The same corpus
// is re-verified against the OpenSSL 3.0.x shipped on the CI Ubuntu 24.04
// runner by the live differential test in CI.
//
// VisibleString is intentionally absent: OpenSSL 3.5.8's `openssl x509`
// command refuses to load a certificate whose SUBJECT contains an
// ISO646String/VisibleString value (reported as a STORE "unsupported" error),
// so no independent oracle value exists. VisibleString canonicalization is
// still covered by TestOpenSSLSubjectHashIA5AndVisible at the unit level.
type opensslSubjectHashCase struct {
	name       string
	rawSubject []byte
	expected   string
}

// opensslSubjectHashCorpus is the shared semantic corpus used by:
//
//   - TestOpenSSLSubjectHashCorpus (static, checks the implementation against
//     the checked-in OpenSSL oracle without invoking openssl);
//   - TestOpenSSLSubjectHashDifferential (live three-way proof against a real
//     openssl executable, required-mode only);
//   - FuzzComputeOpenSSLSubjectHashRawSubject (valid seeds).
var opensslSubjectHashCorpus = []opensslSubjectHashCase{
	// simple CN utf8
	// CN=UTF8String("Test CA")
	{name: "simple CN utf8", rawSubject: corpusBytes("30123110300e06035504030c0754657374204341"), expected: "3387b84d"},
	// uppercase CN
	// CN=UTF8String("TEST CA") — ASCII case folding
	{name: "uppercase CN", rawSubject: corpusBytes("30123110300e06035504030c0754455354204341"), expected: "3387b84d"},
	// leading whitespace
	// CN=UTF8String("  Test CA")
	{name: "leading whitespace", rawSubject: corpusBytes("30143112301006035504030c09202054657374204341"), expected: "3387b84d"},
	// trailing whitespace
	// CN=UTF8String("Test CA  ")
	{name: "trailing whitespace", rawSubject: corpusBytes("30143112301006035504030c09546573742043412020"), expected: "3387b84d"},
	// internal repeated whitespace
	// CN=UTF8String("Test   CA")
	{name: "internal repeated whitespace", rawSubject: corpusBytes("30143112301006035504030c09546573742020204341"), expected: "3387b84d"},
	// space separator
	// CN=UTF8String("Test CA") — SPACE internal
	{name: "space separator", rawSubject: corpusBytes("30123110300e06035504030c0754657374204341"), expected: "3387b84d"},
	// tab separator
	// CN=UTF8String("Test\tCA")
	{name: "tab separator", rawSubject: corpusBytes("30123110300e06035504030c0754657374094341"), expected: "3387b84d"},
	// lf separator
	// CN=UTF8String("Test\nCA")
	{name: "lf separator", rawSubject: corpusBytes("30123110300e06035504030c07546573740a4341"), expected: "3387b84d"},
	// vt separator
	// CN=UTF8String("Test\vCA")
	{name: "vt separator", rawSubject: corpusBytes("30123110300e06035504030c07546573740b4341"), expected: "3387b84d"},
	// ff separator
	// CN=UTF8String("Test\fCA")
	{name: "ff separator", rawSubject: corpusBytes("30123110300e06035504030c07546573740c4341"), expected: "3387b84d"},
	// cr separator
	// CN=UTF8String("Test\rCA")
	{name: "cr separator", rawSubject: corpusBytes("30123110300e06035504030c07546573740d4341"), expected: "3387b84d"},
	// all whitespace classes
	// leading+internal+trailing mix of TAB/LF/VT/FF/CR/SPACE
	{name: "all whitespace classes", rawSubject: corpusBytes("301f311d301b06035504030c14090a0b0c0d20205465737420202043412020090a"), expected: "3387b84d"},
	// multi RDN C/O/CN
	// C=US, O=Example Inc, CN=Root CA (3 RDNs)
	{name: "multi RDN C/O/CN", rawSubject: corpusBytes("3035310b300906035504060c02555331143012060355040a0c0b4578616d706c6520496e633110300e06035504030c07526f6f74204341"), expected: "54c6f1c9"},
	// PrintableString
	// CN=PrintableString("Test CA")
	{name: "PrintableString", rawSubject: corpusBytes("30123110300e0603550403130754657374204341"), expected: "3387b84d"},
	// IA5String
	// CN=IA5String("Test CA")
	{name: "IA5String", rawSubject: corpusBytes("30123110300e0603550403160754657374204341"), expected: "3387b84d"},
	// T61String non-ASCII
	// CN=T61String(0xe9) — Latin-1 é
	{name: "T61String non-ASCII", rawSubject: corpusBytes("300c310a300806035504031401e9"), expected: "7799dc1a"},
	// BMPString non-ASCII
	// CN=BMPString("Te" + U+20AC €)
	{name: "BMPString non-ASCII", rawSubject: corpusBytes("3011310f300d06035504031e060054006520ac"), expected: "61f5c7a4"},
	// UniversalString non-BMP
	// CN=UniversalString('T' + U+1F600) — UTF-32BE 00 01 F6 00 (real non-BMP)
	{name: "UniversalString non-BMP", rawSubject: corpusBytes("30133111300f06035504031c08000000540001f600"), expected: "3c9f142c"},
	// non-ASCII UTF-8 text
	// CN=UTF8String("日本語テスト")
	{name: "non-ASCII UTF-8 text", rawSubject: corpusBytes("301d311b301906035504030c12e697a5e69cace8aa9ee38386e382b9e38388"), expected: "6ca7f5bd"},
	// non-ASCII next to ASCII upper
	// CN=UTF8String("Tëst CÄ") — ASCII fold only
	{name: "non-ASCII next to ASCII upper", rawSubject: corpusBytes("30143112301006035504030c0954c3a973742043c384"), expected: "57f623bf"},
	// NBSP is not ASCII whitespace
	// CN=UTF8String(U+00A0) — NBSP must not be stripped
	{name: "NBSP is not ASCII whitespace", rawSubject: corpusBytes("300d310b300906035504030c02c2a0"), expected: "61ad6a42"},
	// multi-valued RDN order A
	// SET{CN="BBB", CN="AAA"} input order
	{name: "multi-valued RDN order A", rawSubject: corpusBytes("301a3118300a06035504030c03424242300a06035504030c03414141"), expected: "1cd247fd"},
	// multi-valued RDN order B reversed
	// SET{CN="AAA", CN="BBB"} reversed input order
	{name: "multi-valued RDN order B reversed", rawSubject: corpusBytes("301a3118300a06035504030c03414141300a06035504030c03424242"), expected: "1cd247fd"},
	// multi-valued RDN mixed OIDs
	// SET{O="Org", CN="CN"}
	{name: "multi-valued RDN mixed OIDs", rawSubject: corpusBytes("30193117300a060355040a0c034f7267300906035504030c02434e"), expected: "ec5aaaac"},
	// multi-valued RDN mixed OIDs reversed
	// SET{CN="CN", O="Org"}
	{name: "multi-valued RDN mixed OIDs reversed", rawSubject: corpusBytes("30193117300906035504030c02434e300a060355040a0c034f7267"), expected: "ec5aaaac"},
	// NumericString no canon
	// CN=NumericString("12345") — not in ASN1_MASK_CANON
	{name: "NumericString no canon", rawSubject: corpusBytes("3010310e300c060355040312053132333435"), expected: "8046ad34"},
	// NumericString spaces preserved
	// CN=NumericString(" 12 3 ") — whitespace NOT stripped
	{name: "NumericString spaces preserved", rawSubject: corpusBytes("3011310f300d06035504031206203132203320"), expected: "975421e7"},
	// length 127 boundary
	// CN=UTF8String(127 'x') — short-form boundary
	{name: "length 127 boundary", rawSubject: corpusBytes("30818c31818930818606035504030c7f78787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"), expected: "016df46f"},
	// length 128 boundary
	// CN=UTF8String(128 'x') — long-form boundary
	{name: "length 128 boundary", rawSubject: corpusBytes("30818e31818b30818806035504030c81807878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"), expected: "6468be98"},
	// length 130 long form
	// CN=UTF8String(130 'A') — long-form length + case fold
	{name: "length 130 long form", rawSubject: corpusBytes("30819031818d30818a06035504030c818241414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141"), expected: "6352320c"},
	// empty CN value
	// CN=UTF8String("")
	{name: "empty CN value", rawSubject: corpusBytes("300b3109300706035504030c00"), expected: "5da78770"},
	// empty name
	// Name=SEQUENCE{} (empty)
	{name: "empty name", rawSubject: corpusBytes("3000"), expected: "eea339da"},
}

// TestOpenSSLSubjectHashCorpus is the static, deterministic part of the
// differential proof. It compares computeOpenSSLSubjectHash against the
// checked-in OpenSSL oracle for every corpus case and MUST NOT invoke the
// openssl executable, so the ordinary Go test suite stays independent of
// external OpenSSL.
func TestOpenSSLSubjectHashCorpus(t *testing.T) {
	for _, tc := range opensslSubjectHashCorpus {
		t.Run(tc.name, func(t *testing.T) {
			got, err := computeOpenSSLSubjectHash(&x509.Certificate{RawSubject: tc.rawSubject})
			if err != nil {
				t.Fatalf("computeOpenSSLSubjectHash: %v", err)
			}
			if got != tc.expected {
				t.Errorf("hash = %s, want OpenSSL oracle %s", got, tc.expected)
			}
		})
	}
}

// TestOpenSSLSubjectHashDifferential is the live part of the differential
// proof. It is gated behind the test-only required-mode environment variable
// DOCKER_HELPER_OPENSSL_DIFFERENTIAL=1:
//
//   - when disabled, the test skips (the static corpus test still runs);
//   - when enabled, a missing openssl executable is a FAILURE, never a skip.
//
// For every corpus case it builds a self-signed certificate whose RawSubject
// is exactly the corpus DER, verifies the subject bytes round-trip, and runs
//
//	openssl x509 -in cert.pem -hash -noout
//
// producing a three-way proof:
//
//	checked-in oracle  ==  live OpenSSL  ==  docker-helper implementation
func TestOpenSSLSubjectHashDifferential(t *testing.T) {
	if os.Getenv(opensslDifferentialEnv) != "1" {
		t.Skipf("live OpenSSL differential disabled (set %s=1)", opensslDifferentialEnv)
	}

	opensslBin, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatalf("openssl executable required in differential mode: %v", err)
	}

	// Provenance: record which OpenSSL produced the live values.
	verOut, err := exec.Command(opensslBin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl version: %v", err)
	}
	t.Logf("openssl version: %s", strings.TrimSpace(string(verOut)))

	for _, tc := range opensslSubjectHashCorpus {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Build a valid self-signed cert whose RawSubject is exactly
			// the corpus bytes (Go's x509.CreateCertificate honors RawSubject).
			certDER := makeCertWithExactRawSubject(t, tc.rawSubject)

			// 2. Read the subject back out of the produced DER and assert it
			// exactly equals the input bytes.
			gotSubject := certSubjectFromDER(t, certDER)
			if !bytes.Equal(gotSubject, tc.rawSubject) {
				t.Fatalf("cert subject = %x, want %x", gotSubject, tc.rawSubject)
			}

			// 3. Write PEM.
			pemPath := filepath.Join(t.TempDir(), "cert.pem")
			writePEMCert(t, pemPath, certDER)

			// 4. Run the independent oracle.
			out, err := exec.Command(opensslBin, "x509", "-in", pemPath, "-hash", "-noout").CombinedOutput()
			if err != nil {
				t.Fatalf("openssl x509 -hash: %v\n%s", err, out)
			}
			live := strings.TrimSpace(string(out))
			if len(live) != 8 {
				t.Fatalf("unexpected openssl output %q", live)
			}

			// 5. Three-way comparison.
			if live != tc.expected {
				t.Errorf("live OpenSSL %s != checked-in oracle %s", live, tc.expected)
			}
			ours, err := computeOpenSSLSubjectHash(&x509.Certificate{RawSubject: tc.rawSubject})
			if err != nil {
				t.Fatalf("computeOpenSSLSubjectHash: %v", err)
			}
			if ours != live {
				t.Errorf("docker-helper %s != live OpenSSL %s", ours, live)
			}
		})
	}
}

// makeCertWithExactRawSubject builds a valid self-signed certificate whose
// RawSubject is exactly rawSubject, using x509.CreateCertificate with the
// template.RawSubject field (honored verbatim by the Go x509 package).
func makeCertWithExactRawSubject(t *testing.T, rawSubject []byte) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		RawSubject:            rawSubject,
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// writePEMCert writes der as a PEM certificate at path.
func writePEMCert(t *testing.T, path string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

// certSubjectFromDER walks a certificate DER and returns the subject TLV
// (tag + length + value) bytes, so RawSubject preservation can be asserted
// even for subjects Go's own parser rejects (for example UniversalString).
func certSubjectFromDER(t *testing.T, der []byte) []byte {
	t.Helper()
	// Certificate ::= SEQUENCE { tbs, sigalg, sig } — the outer value is the
	// TBSCertificate element (tag + length + content).
	outer, _, err := derTLVAt(der, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Unwrap the TBSCertificate SEQUENCE to its content.
	tbs, _, err := derTLVAt(outer, 0)
	if err != nil {
		t.Fatal(err)
	}
	// TBS fields: version, serial, sigalg, issuer, validity, subject, spki...
	off := 0
	for i := 0; i < 5; i++ {
		_, next, err := derTLVAt(tbs, off)
		if err != nil {
			t.Fatal(err)
		}
		off = next
	}
	// The 6th field (index 5) is the subject; return its full TLV.
	_, end, err := derTLVAt(tbs, off)
	if err != nil {
		t.Fatal(err)
	}
	return tbs[off:end]
}

// derTLVAt returns (value, offset-after-value, err) for the DER TLV at off.
// It is a small test-only walker used to locate the subject inside a
// certificate DER.
func derTLVAt(b []byte, off int) (value []byte, nextOff int, err error) {
	if off >= len(b) {
		return nil, 0, fmt.Errorf("offset out of bounds")
	}
	// b[off] = tag, b[off+1] = length marker.
	lb := off + 1
	if lb >= len(b) {
		return nil, 0, fmt.Errorf("no length")
	}
	m := int(b[lb])
	var vlen, hdr int
	if m&0x80 == 0 {
		vlen = m
		hdr = lb + 1
	} else {
		n := m & 0x7f
		if n == 0 || lb+1+n > len(b) {
			return nil, 0, fmt.Errorf("invalid length encoding")
		}
		l := 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[lb+1+i])
		}
		vlen = l
		hdr = lb + 1 + n
	}
	if vlen < 0 || hdr > len(b) || vlen > len(b)-hdr {
		return nil, 0, fmt.Errorf("value length out of bounds")
	}
	return b[hdr : hdr+vlen], hdr + vlen, nil
}

// FuzzComputeOpenSSLSubjectHashRawSubject fuzzes the raw-subject
// parser/canonicalizer boundary. For arbitrary RawSubject bytes the required
// robustness property is that computeOpenSSLSubjectHash NEVER panics; errors
// are acceptable for malformed input. For successful results it additionally
// asserts the 8-character lowercase-hex form and determinism. The fuzz loop
// never invokes openssl.
func FuzzComputeOpenSSLSubjectHashRawSubject(f *testing.F) {
	// Valid corpus subjects (successful-result assertions apply).
	for _, tc := range opensslSubjectHashCorpus {
		f.Add(tc.rawSubject)
	}

	// Short/truncated DER.
	f.Add([]byte{})
	f.Add([]byte{0x30})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x01})
	f.Add([]byte{0x30, 0x05, 0x31})
	f.Add([]byte{0x30, 0x05, 0x31, 0x03})

	// Regression seeds from the fuzz session: hostile declared lengths that
	// previously panicked with a slice-bounds error before the bounds checks
	// in parseX509RawSubject were added.
	f.Add([]byte("0010")) // outer SEQUENCE declares 48 bytes, only 2 remain

	// Malformed/long-form length encodings.
	f.Add([]byte{0x30, 0x80})                                                                                           // indefinite-length marker
	f.Add([]byte{0x30, 0x81})                                                                                           // long-form with no length byte
	f.Add([]byte{0x30, 0x81, 0x00})                                                                                     // long-form zero-length content
	f.Add([]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff})                                                                   // long-form huge length
	f.Add([]byte{0x30, 0x82, 0x00, 0x05})                                                                               // declared length exceeds buffer
	f.Add([]byte{0x30, 0x8f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // long-form overflow

	// Malformed SET / attribute SEQUENCE boundaries.
	f.Add([]byte{0x30, 0x06, 0x31, 0x04, 0x30, 0x02, 0x06})
	f.Add([]byte{0x30, 0x08, 0x31, 0x06, 0x30, 0x04, 0x06, 0x02, 0x01, 0x01})
	f.Add([]byte{0x30, 0x05, 0x31, 0x03, 0x30, 0x01})
	f.Add([]byte{0x30, 0x08, 0x31, 0x06, 0x30, 0x04, 0x06, 0x01, 0x00, 0x0c}) // OID length past buffer

	// BMPString odd length / surrogate (reuse existing malformed cases).
	f.Add(derSeq(derSet(derAttr(oidCommonName, derTagLength(0x1e, []byte{0x00, 0x54, 0x65}))))) // odd length
	f.Add(derSeq(derSet(derAttr(oidCommonName, derTagLength(0x1e, []byte{0xd8, 0x00})))))       // low surrogate
	f.Add(derSeq(derSet(derAttr(oidCommonName, derTagLength(0x1e, []byte{0xdf, 0xff})))))       // high surrogate

	// UniversalString invalid length / surrogate / > U+10FFFF.
	f.Add(derSeq(derSet(derAttr(oidCommonName, derTagLength(0x1c, []byte{0x00, 0x00, 0x00, 0x54, 0x65}))))) // not multiple of 4
	f.Add(derSeq(derSet(derAttr(oidCommonName, derTagLength(0x1c, []byte{0x00, 0x00, 0xd8, 0x00})))))       // surrogate
	f.Add(derSeq(derSet(derAttr(oidCommonName, derTagLength(0x1c, []byte{0x01, 0x10, 0x00, 0x00})))))       // > U+10FFFF

	f.Fuzz(func(t *testing.T, raw []byte) {
		hash, err := computeOpenSSLSubjectHash(&x509.Certificate{RawSubject: raw})
		if err != nil {
			return
		}
		if len(hash) != 8 {
			t.Errorf("hash %q: must be exactly 8 characters", hash)
		}
		for _, c := range hash {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				t.Errorf("hash %q: must contain only lowercase hex", hash)
			}
		}
		again, err := computeOpenSSLSubjectHash(&x509.Certificate{RawSubject: raw})
		if err != nil {
			t.Errorf("determinism: second call returned error %v", err)
		}
		if again != hash {
			t.Errorf("determinism: %q vs %q for identical input", hash, again)
		}
	})
}

// TestOpenSSLDifferentialCIContract verifies the live OpenSSL differential
// proof layer: a dedicated x509-openssl-differential CI job enables the
// required-mode env var and runs only the focused live differential test,
// while the ordinary checks job stays free of the OpenSSL differential /
// tool-install path (consistent with the Stage 0.2 decision to keep checks
// lightweight).
func TestOpenSSLDifferentialCIContract(t *testing.T) {
	ci, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	ciContent := string(ci)

	diffJob := findJobSection(ciContent, "x509-openssl-differential")
	if diffJob == "" {
		t.Fatal("ci.yml must contain a separate x509-openssl-differential job")
	}
	if !strings.Contains(diffJob, "DOCKER_HELPER_OPENSSL_DIFFERENTIAL=1") {
		t.Error("x509-openssl-differential job must enable DOCKER_HELPER_OPENSSL_DIFFERENTIAL=1")
	}
	if !strings.Contains(diffJob, "-run") || !strings.Contains(diffJob, "TestOpenSSLSubjectHashDifferential") {
		t.Error("x509-openssl-differential job must run only the focused TestOpenSSLSubjectHashDifferential test")
	}
	if strings.Contains(diffJob, "go test ./...") {
		t.Error("x509-openssl-differential job must not run the full Go suite")
	}

	// The ordinary checks job must not acquire an OpenSSL differential or
	// tool-install path: that belongs to the dedicated job.
	checksJob := findJobSection(ciContent, "checks")
	if checksJob == "" {
		t.Fatal("ci.yml must contain a checks job")
	}
	for _, banned := range []string{
		"DOCKER_HELPER_OPENSSL_DIFFERENTIAL",
		"TestOpenSSLSubjectHashDifferential",
		"apt-get install -y openssl",
	} {
		if strings.Contains(checksJob, banned) {
			t.Errorf("checks job must not gain an OpenSSL differential/tool-install path (%q)", banned)
		}
	}
}

// TestNoProductionOpenSSLExec verifies the no-runtime-OpenSSL-dependency
// invariant: no production .go file may exec the openssl executable. The
// external oracle is permitted only in *_test.go and in test CI jobs.
func TestNoProductionOpenSSLExec(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, pattern := range []string{
			`exec.Command("openssl"`,
			"exec.Command(`openssl`",
			`exec.CommandContext("openssl"`,
		} {
			if bytes.Contains(data, []byte(pattern)) {
				t.Errorf("%s: production code must not exec the openssl executable", file)
			}
		}
	}
}
