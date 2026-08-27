package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCAPrepareSuccess(t *testing.T) {
	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	cfgObj, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatalf("loadAndPrepareRuntimeConfig failed: %v", err)
	}

	if cfgObj.TrustedCAInjection != "auto" {
		t.Errorf("expected auto, got %s", cfgObj.TrustedCAInjection)
	}
	if cfgObj.TrustedCAPreparedDir == "" {
		t.Fatal("expected non-empty prepared dir")
	}

	preparedDir := cfgObj.TrustedCAPreparedDir
	if _, err := os.Stat(preparedDir); os.IsNotExist(err) {
		t.Fatal("prepared dir does not exist")
	}

	dirInfo, err := os.Stat(preparedDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0755 {
		t.Errorf("dir mode = %o, want 0755", dirInfo.Mode().Perm())
	}

	caFile := filepath.Join(preparedDir, "ca.pem")
	caInfo, err := os.Stat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if caInfo.Mode().Perm() != 0644 {
		t.Errorf("ca.pem mode = %o, want 0644", caInfo.Mode().Perm())
	}

	entries, err := os.ReadDir(preparedDir)
	if err != nil {
		t.Fatal(err)
	}
	foundSymlink := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".0") {
			foundSymlink = true
			link, err := os.Readlink(filepath.Join(preparedDir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if link != "ca.pem" {
				t.Errorf("symlink target = %s, want ca.pem", link)
			}
		}
	}
	if !foundSymlink {
		t.Fatal("no hash symlink found")
	}
}

func TestCAPrepareIdempotent(t *testing.T) {
	configPath, caPath, runtimeDir := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	cfgObj1, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	firstDir := cfgObj1.TrustedCAPreparedDir

	cfgObj2, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfgObj2.TrustedCAPreparedDir != firstDir {
		t.Error("expected same prepared dir for same CA")
	}

	trustedCADir := filepath.Join(runtimeDir, "docker-helper", "trusted-ca")
	entries, err := os.ReadDir(trustedCADir)
	if err != nil {
		t.Fatal(err)
	}
	dirCount := 0
	for _, e := range entries {
		if e.IsDir() {
			dirCount++
		}
	}
	if dirCount != 1 {
		t.Errorf("expected 1 snapshot dir, got %d", dirCount)
	}
}

func TestCAPrepareUmaskResilient(t *testing.T) {
	oldUmask := syscall.Umask(0077)
	defer syscall.Umask(oldUmask)

	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	cfgObj, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	snapshotDir := cfgObj.TrustedCAPreparedDir

	dirInfo, err := os.Stat(snapshotDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0755 {
		t.Errorf("snapshot dir mode = %o, want 0755", dirInfo.Mode().Perm())
	}

	caFile := filepath.Join(snapshotDir, "ca.pem")
	caInfo, err := os.Stat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if caInfo.Mode().Perm() != 0644 {
		t.Errorf("ca.pem mode = %o, want 0644", caInfo.Mode().Perm())
	}

	if err := os.Chmod(snapshotDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfgObj2, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfgObj2.TrustedCAPreparedDir != snapshotDir {
		t.Error("expected same prepared dir for same CA")
	}

	dirInfo2, err := os.Stat(snapshotDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo2.Mode().Perm() != 0755 {
		t.Errorf("snapshot dir mode after idempotent reload = %o, want 0755", dirInfo2.Mode().Perm())
	}
}

func TestCAPrepareNewSnapshotOnCAChange(t *testing.T) {
	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	cfgObj1, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	firstDir := cfgObj1.TrustedCAPreparedDir

	newCAPath := filepath.Join(filepath.Dir(configPath), "new-ca.crt")
	generateTestCAPEM(t, newCAPath)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      newCAPath,
		"trusted_ca_injection": "auto",
	})

	cfgObj2, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfgObj2.TrustedCAPreparedDir == firstDir {
		t.Error("expected different prepared dir for different CA")
	}

	if _, err := os.Stat(firstDir); os.IsNotExist(err) {
		t.Error("old snapshot dir should still exist")
	}
}

func TestCAReloadChangesCA(t *testing.T) {
	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	cfgObj1, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	firstDir := cfgObj1.TrustedCAPreparedDir

	newCAPath := filepath.Join(filepath.Dir(configPath), "new-ca.crt")
	generateTestCAPEM(t, newCAPath)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      newCAPath,
		"trusted_ca_injection": "auto",
	})

	cfgObj2, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfgObj2.TrustedCAPreparedDir == firstDir {
		t.Error("expected different prepared dir after CA change")
	}
	if cfgObj2.TrustedCAPreparedDir == "" {
		t.Error("expected non-empty prepared dir after reload")
	}
}

func setupPreparedCA(t *testing.T) (runtimeSubDir, caPath, preparedDir string) {
	t.Helper()
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir = filepath.Join(runtimeDir, "docker-helper")
	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}

	caPath = filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	var err error
	preparedDir, err = prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestCAPrepareFixesWrongSymlink(t *testing.T) {
	runtimeSubDir, caPath, preparedDir := setupPreparedCA(t)

	// Find the hash symlink.
	entries, err := os.ReadDir(preparedDir)
	if err != nil {
		t.Fatal(err)
	}
	var symlinkPath string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".0") {
			symlinkPath = filepath.Join(preparedDir, e.Name())
			break
		}
	}
	if symlinkPath == "" {
		t.Fatal("no hash symlink found")
	}

	// Corrupt: replace symlink with one pointing to wrong.pem.
	if err := os.Remove(symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("wrong.pem", symlinkPath); err != nil {
		t.Fatal(err)
	}

	// Re-prepare should fix the symlink.
	preparedDir2, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if preparedDir2 != preparedDir {
		t.Error("expected same prepared dir")
	}

	target, err := os.Readlink(symlinkPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != "ca.pem" {
		t.Errorf("symlink target = %q, want ca.pem", target)
	}
}

func TestCAPrepareFixesRegularFileHashEntry(t *testing.T) {
	runtimeSubDir, caPath, preparedDir := setupPreparedCA(t)

	// Find the hash symlink.
	entries, err := os.ReadDir(preparedDir)
	if err != nil {
		t.Fatal(err)
	}
	var symlinkPath string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".0") {
			symlinkPath = filepath.Join(preparedDir, e.Name())
			break
		}
	}
	if symlinkPath == "" {
		t.Fatal("no hash symlink found")
	}

	// Corrupt: replace symlink with a regular file.
	if err := os.Remove(symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(symlinkPath, []byte("not-a-symlink"), 0644); err != nil {
		t.Fatal(err)
	}

	// Re-prepare should restore the symlink.
	preparedDir2, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if preparedDir2 != preparedDir {
		t.Error("expected same prepared dir")
	}

	target, err := os.Readlink(symlinkPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != "ca.pem" {
		t.Errorf("symlink target = %q, want ca.pem", target)
	}
}

func TestCAPrepareRestoresPemMode(t *testing.T) {
	runtimeSubDir, caPath, preparedDir := setupPreparedCA(t)

	caFile := filepath.Join(preparedDir, "ca.pem")

	// Corrupt: change mode to 0600.
	if err := os.Chmod(caFile, 0600); err != nil {
		t.Fatal(err)
	}

	// Re-prepare should restore mode 0644.
	preparedDir2, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if preparedDir2 != preparedDir {
		t.Error("expected same prepared dir")
	}

	info, err := os.Stat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("ca.pem mode = %o, want 0644", info.Mode().Perm())
	}
}

func TestCAPrepareFixesPemSymlink(t *testing.T) {
	runtimeSubDir, caPath, preparedDir := setupPreparedCA(t)

	caFile := filepath.Join(preparedDir, "ca.pem")
	caData, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt: replace ca.pem with a symlink to another file with the same content.
	targetFile := filepath.Join(preparedDir, "target-ca.pem")
	if err := os.WriteFile(targetFile, caData, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(caFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target-ca.pem", caFile); err != nil {
		t.Fatal(err)
	}

	// Re-prepare should restore ca.pem as a regular file with mode 0644.
	preparedDir2, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if preparedDir2 != preparedDir {
		t.Error("expected same prepared dir")
	}

	info, err := os.Lstat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("ca.pem should be a regular file, got mode %v", info.Mode())
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("ca.pem mode = %o, want 0644", info.Mode().Perm())
	}
}

func TestCAPrepareSnapshotConsistency(t *testing.T) {
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}

	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)
	originalData, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the source file to prove that prepareCAFromData uses only the
	// captured bytes and never re-reads the filesystem.
	if err := os.WriteFile(caPath, []byte("corrupted"), 0644); err != nil {
		t.Fatalf("corruption write failed: %v", err)
	}

	// prepareCAFromData uses only the captured snapshot, not the file.
	preparedDir, err := prepareCAFromData(runtimeSubDir, originalData)
	if err != nil {
		t.Fatalf("prepareCAFromData failed: %v", err)
	}

	// Verify prepared ca.pem matches the original snapshot, not the corrupted file.
	preparedCAFile := filepath.Join(preparedDir, "ca.pem")
	preparedData, err := os.ReadFile(preparedCAFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preparedData, originalData) {
		t.Error("prepared ca.pem does not match original CA bytes")
	}

	// Verify the hash symlink exists and points to ca.pem.
	entries, err := os.ReadDir(preparedDir)
	if err != nil {
		t.Fatal(err)
	}
	foundSymlink := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".0") {
			foundSymlink = true
			target, err := os.Readlink(filepath.Join(preparedDir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if target != "ca.pem" {
				t.Errorf("symlink target = %s, want ca.pem", target)
			}
		}
	}
	if !foundSymlink {
		t.Fatal("no hash symlink found")
	}
}

func TestOpenSSLSubjectHashGolden(t *testing.T) {
	tests := []struct {
		name     string
		subject  pkix.Name
		expected string
	}{
		{
			name:     "simple CN",
			subject:  pkix.Name{CommonName: "Test CA"},
			expected: "3387b84d",
		},
		{
			name:     "organization",
			subject:  pkix.Name{Organization: []string{"My Company"}},
			expected: "82b2249e",
		},
		{
			name: "full DN",
			subject: pkix.Name{
				Country:            []string{"US"},
				Organization:       []string{"Example Inc"},
				OrganizationalUnit: []string{"Engineering"},
				CommonName:         "Root CA",
			},
			expected: "41c6e02d",
		},
		{
			name:     "non-ascii subject",
			subject:  pkix.Name{CommonName: "日本語テスト"},
			expected: "6ca7f5bd",
		},
		{
			name:     "case normalization",
			subject:  pkix.Name{CommonName: "TEST CA"},
			expected: "3387b84d",
		},
		{
			name:     "whitespace normalization",
			subject:  pkix.Name{CommonName: "  Test   CA  "},
			expected: "3387b84d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCertWithSubject(t, tt.subject)
			hash, err := computeOpenSSLSubjectHash(cert)
			if err != nil {
				t.Fatalf("computeOpenSSLSubjectHash failed: %v", err)
			}
			if hash != tt.expected {
				t.Errorf("hash = %s, want %s", hash, tt.expected)
			}
		})
	}
}

// TestOpenSSLSubjectHashNotMD5RawSubject verifies that the implementation does NOT
// degenerate to MD5(RawSubject) or SHA1(RawSubject), which were incorrect
// algorithms that produced wrong hashes.
func TestOpenSSLSubjectHashNotMD5RawSubject(t *testing.T) {
	cert := createTestCertWithSubject(t, pkix.Name{CommonName: "Test CA"})
	hash, err := computeOpenSSLSubjectHash(cert)
	if err != nil {
		t.Fatalf("computeOpenSSLSubjectHash failed: %v", err)
	}

	// These are the hashes that would be produced by the wrong algorithms.
	// If any of these match, the implementation has regressed.
	wrongHashes := map[string]string{
		"d2b0b910": "MD5(RawSubject) big-endian",
		"02ff75da": "SHA1(RawSubject) big-endian",
		"9536e9fc": "SHA256(RawSubject) big-endian",
	}
	for wrong, label := range wrongHashes {
		if hash == wrong {
			t.Errorf("hash %s matches wrong algorithm: %s", hash, label)
		}
	}
}

func createTestCertWithSubject(t *testing.T, subject pkix.Name) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// --- raw ASN.1 subject compatibility tests ---

var oidCommonName = []byte{0x55, 0x04, 0x03} // 2.5.4.3

// makeCertWithRawSubject creates a certificate whose RawSubject is set to
// the provided DER bytes. computeOpenSSLSubjectHash only reads RawSubject, so the
// rest of the certificate is irrelevant.
func makeCertWithRawSubject(t *testing.T, rawSubject []byte) *x509.Certificate {
	t.Helper()
	cert := createTestCertWithSubject(t, pkix.Name{CommonName: "placeholder"})
	cert.RawSubject = rawSubject
	return cert
}

// expectedHashFromCanonDER computes the OpenSSL subject hash from canonical
// DER bytes (without outer SEQUENCE). This serves as an independent reference
// for test expectations.
func expectedHashFromCanonDER(t *testing.T, canonDER []byte) string {
	t.Helper()
	h := sha1.Sum(canonDER)
	return fmt.Sprintf("%08x", uint32(h[3])<<24|uint32(h[2])<<16|uint32(h[1])<<8|uint32(h[0]))
}

// derSeq builds a DER SEQUENCE wrapper around the given inner bytes.
func derSeq(inner []byte) []byte {
	return append(append([]byte{0x30}, encodeDERLength(len(inner))...), inner...)
}

// derSet builds a DER SET wrapper around the given inner bytes.
func derSet(inner []byte) []byte {
	return append(append([]byte{0x31}, encodeDERLength(len(inner))...), inner...)
}

// derOID builds a DER OID wrapper around the given OID bytes.
func derOID(oid []byte) []byte {
	return append(append([]byte{0x06}, encodeDERLength(len(oid))...), oid...)
}

// derUTF8String builds a DER UTF8String wrapper.
func derUTF8String(b []byte) []byte {
	return append(append([]byte{0x0c}, encodeDERLength(len(b))...), b...)
}

// derT61String builds a DER T61String wrapper.
func derT61String(b []byte) []byte {
	return append(append([]byte{0x14}, encodeDERLength(len(b))...), b...)
}

// derBMPString builds a DER BMPString (UTF-16 BE) wrapper from runes.
func derBMPString(runes []rune) []byte {
	b := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		b = append(b, byte(r>>8), byte(r))
	}
	return append(append([]byte{0x1e}, encodeDERLength(len(b))...), b...)
}

// derUniversalString builds a DER UniversalString (UTF-32 BE) wrapper from runes.
func derUniversalString(runes []rune) []byte {
	b := make([]byte, 0, len(runes)*4)
	for _, r := range runes {
		b = append(b, 0, 0, byte(r>>8), byte(r))
	}
	return append(append([]byte{0x1c}, encodeDERLength(len(b))...), b...)
}

// derAttr builds a DER AttributeTypeAndValue SEQUENCE.
func derAttr(oid, value []byte) []byte {
	return derSeq(append(derOID(oid), value...))
}

// canonAttr builds a canonical attribute DER (OID + UTF8String value).
func canonAttr(oid, canonValue []byte) []byte {
	return derSeq(append(derOID(oid), derUTF8String(canonValue)...))
}

// canonRDN builds a canonical RDN SET from canonical attribute DERs.
func canonRDN(attrs ...[]byte) []byte {
	return derSet(bytes.Join(attrs, nil))
}

func TestOpenSSLSubjectHashRawSubject(t *testing.T) {
	// Pre-compute values that can't be expressed inline in a composite literal.
	longVal := make([]byte, 130)
	for i := range longVal {
		longVal[i] = 'A'
	}
	longCanon := make([]byte, 130)
	for i := range longCanon {
		longCanon[i] = 'a'
	}
	attrBBB := derAttr(oidCommonName, derUTF8String([]byte("BBB")))
	attrAAA := derAttr(oidCommonName, derUTF8String([]byte("AAA")))

	tests := []struct {
		name       string
		rawSubject []byte
		canonDER   []byte
	}{
		{
			name: "T61String non-ASCII e9",
			// CN = T61String(0xe9) — ISO-8859-1 é
			rawSubject: derSeq(derSet(derAttr(oidCommonName, derT61String([]byte{0xe9})))),
			// Canonical: UTF8String(c3 a9) — UTF-8 é
			canonDER: canonRDN(canonAttr(oidCommonName, []byte{0xc3, 0xa9})),
		},
		{
			name: "BMPString Test",
			// CN = BMPString("Test")
			rawSubject: derSeq(derSet(derAttr(oidCommonName, derBMPString([]rune("Test"))))),
			// Canonical: UTF8String("test")
			canonDER: canonRDN(canonAttr(oidCommonName, []byte("test"))),
		},
		{
			name: "UniversalString Test",
			// CN = UniversalString("Test")
			rawSubject: derSeq(derSet(derAttr(oidCommonName, derUniversalString([]rune("Test"))))),
			// Canonical: UTF8String("test")
			canonDER: canonRDN(canonAttr(oidCommonName, []byte("test"))),
		},
		{
			name: "VT and FF whitespace",
			// CN = UTF8String("Test\x0b\x0cCA") — VT and FF between words
			rawSubject: derSeq(derSet(derAttr(oidCommonName, derUTF8String([]byte("Test\x0b\x0cCA"))))),
			// Canonical: UTF8String("test ca") — VT/FF collapsed to single space, lowercased
			canonDER: canonRDN(canonAttr(oidCommonName, []byte("test ca"))),
		},
		{
			name: "long-form DER length",
			// CN = UTF8String(130 'A' bytes) — triggers long-form DER length encoding
			rawSubject: derSeq(derSet(derAttr(oidCommonName, derUTF8String(longVal)))),
			// Canonical: UTF8String(130 'a' bytes)
			canonDER: canonRDN(canonAttr(oidCommonName, longCanon)),
		},
		{
			name: "multi-valued RDN SET OF ordering",
			// SET { CN="BBB", CN="AAA" } — raw order is reversed
			rawSubject: derSeq(derSet(append(attrBBB, attrAAA...))),
			// Canonical: sorted SET { CN="aaa", CN="bbb" }
			canonDER: canonRDN(
				canonAttr(oidCommonName, []byte("aaa")),
				canonAttr(oidCommonName, []byte("bbb")),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := makeCertWithRawSubject(t, tt.rawSubject)
			hash, err := computeOpenSSLSubjectHash(cert)
			if err != nil {
				t.Fatalf("computeOpenSSLSubjectHash failed: %v", err)
			}
			want := expectedHashFromCanonDER(t, tt.canonDER)
			if hash != want {
				t.Errorf("hash = %s, want %s", hash, want)
			}
		})
	}
}

func TestOpenSSLSubjectHashSameValueDifferentEncodings(t *testing.T) {
	// Same logical value "Test" encoded with different ASN.1 string types
	// must produce identical hashes after canonicalization.
	encodings := [][]byte{
		derSeq(derSet(derAttr(oidCommonName, derUTF8String([]byte("Test"))))),
		derSeq(derSet(derAttr(oidCommonName, derBMPString([]rune("Test"))))),
		derSeq(derSet(derAttr(oidCommonName, derUniversalString([]rune("Test"))))),
		derSeq(derSet(derAttr(oidCommonName, derT61String([]byte("Test"))))),
	}

	var firstHash string
	for i, raw := range encodings {
		cert := makeCertWithRawSubject(t, raw)
		hash, err := computeOpenSSLSubjectHash(cert)
		if err != nil {
			t.Fatalf("encoding %d: computeOpenSSLSubjectHash failed: %v", i, err)
		}
		if firstHash == "" {
			firstHash = hash
		}
		if hash != firstHash {
			t.Errorf("encoding %d hash %s != first hash %s", i, hash, firstHash)
		}
	}
}

// TestOpenSSLSubjectHashSurrogateRejection verifies that BMPString and UniversalString
// with surrogate code points are rejected, matching OpenSSL behavior.
func TestOpenSSLSubjectHashSurrogateRejection(t *testing.T) {
	tests := []struct {
		name       string
		rawSubject []byte
	}{
		{
			name: "BMPString surrogate low",
			// CN = BMPString(U+D800) — low surrogate
			rawSubject: derSeq(derSet(derAttr(oidCommonName,
				derTagLength(0x1e, []byte{0xd8, 0x00})))),
		},
		{
			name: "BMPString surrogate high",
			// CN = BMPString(U+DFFF) — high surrogate
			rawSubject: derSeq(derSet(derAttr(oidCommonName,
				derTagLength(0x1e, []byte{0xdf, 0xff})))),
		},
		{
			name: "UniversalString surrogate",
			// CN = UniversalString(U+D800) — surrogate
			rawSubject: derSeq(derSet(derAttr(oidCommonName,
				derTagLength(0x1c, []byte{0x00, 0x00, 0xd8, 0x00})))),
		},
		{
			name: "UniversalString above 10FFFF",
			// CN = UniversalString(U+110000) — above valid Unicode range
			rawSubject: derSeq(derSet(derAttr(oidCommonName,
				derTagLength(0x1c, []byte{0x01, 0x10, 0x00, 0x00})))),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := makeCertWithRawSubject(t, tt.rawSubject)
			_, err := computeOpenSSLSubjectHash(cert)
			if err == nil {
				t.Fatal("expected error for invalid code point, got nil")
			}
		})
	}
}

// TestOpenSSLSubjectHashMalformedLength verifies that malformed BMPString and
// UniversalString lengths are rejected.
func TestOpenSSLSubjectHashMalformedLength(t *testing.T) {
	tests := []struct {
		name       string
		rawSubject []byte
	}{
		{
			name: "BMPString odd length",
			// CN = BMPString with 3 bytes (not multiple of 2)
			rawSubject: derSeq(derSet(derAttr(oidCommonName,
				derTagLength(0x1e, []byte{0x00, 0x54, 0x65})))),
		},
		{
			name: "UniversalString length not multiple of 4",
			// CN = UniversalString with 5 bytes (not multiple of 4)
			rawSubject: derSeq(derSet(derAttr(oidCommonName,
				derTagLength(0x1c, []byte{0x00, 0x00, 0x00, 0x54, 0x65})))),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := makeCertWithRawSubject(t, tt.rawSubject)
			_, err := computeOpenSSLSubjectHash(cert)
			if err == nil {
				t.Fatal("expected error for malformed length, got nil")
			}
		})
	}
}

// derTagLength builds a DER tag+length+value for the given tag and data.
func derTagLength(tag byte, data []byte) []byte {
	return append(append([]byte{tag}, encodeDERLength(len(data))...), data...)
}

// TestOpenSSLSubjectHashNumericStringNotCanonicalized verifies that NumericString
// is NOT canonicalized (not in ASN1_MASK_CANON) and retains its original tag.
func TestOpenSSLSubjectHashNumericStringNotCanonicalized(t *testing.T) {
	// CN = NumericString("12345")
	rawSubject := derSeq(derSet(derAttr(oidCommonName,
		derTagLength(0x12, []byte("12345")))))
	canonDER := canonRDN(derSeq(append(derOID(oidCommonName),
		derTagLength(0x12, []byte("12345"))...)))

	cert := makeCertWithRawSubject(t, rawSubject)
	hash, err := computeOpenSSLSubjectHash(cert)
	if err != nil {
		t.Fatalf("computeOpenSSLSubjectHash failed: %v", err)
	}
	want := expectedHashFromCanonDER(t, canonDER)
	if hash != want {
		t.Errorf("hash = %s, want %s", hash, want)
	}
}

// TestOpenSSLSubjectHashNonASCIIUntouched verifies that non-ASCII UTF-8 bytes
// are not modified by the ASCII-only lowercase/whitespace logic.
func TestOpenSSLSubjectHashNonASCIIUntouched(t *testing.T) {
	// CN = UTF8String("Tëst CÄ") — non-ASCII bytes should pass through unchanged
	rawSubject := derSeq(derSet(derAttr(oidCommonName,
		derUTF8String([]byte("T\xc3\xa9st C\xc3\x84")))))
	// Canonical: lowercase ASCII only, non-ASCII unchanged
	// "T" -> "t", "ë" (c3 a9) unchanged, "st" -> "st", " " unchanged,
	// "C" -> "c", "Ä" (c3 84) unchanged
	canonDER := canonRDN(canonAttr(oidCommonName, []byte("t\xc3\xa9st c\xc3\x84")))

	cert := makeCertWithRawSubject(t, rawSubject)
	hash, err := computeOpenSSLSubjectHash(cert)
	if err != nil {
		t.Fatalf("computeOpenSSLSubjectHash failed: %v", err)
	}
	want := expectedHashFromCanonDER(t, canonDER)
	if hash != want {
		t.Errorf("hash = %s, want %s", hash, want)
	}
}

// TestOpenSSLSubjectHashWhitespaceFull verifies all 6 whitespace characters
// (TAB, LF, VT, FF, CR, SPACE) are normalized.
func TestOpenSSLSubjectHashWhitespaceFull(t *testing.T) {
	// CN = UTF8String("\t\x0a\x0b\x0c\x0d  Test   CA  \t\x0a")
	// All whitespace types at leading, internal, and trailing positions
	rawSubject := derSeq(derSet(derAttr(oidCommonName,
		derUTF8String([]byte("\t\x0a\x0b\x0c\x0d  Test   CA  \t\x0a")))))
	// Canonical: "test ca" (all whitespace trimmed/collapsed, lowercased)
	canonDER := canonRDN(canonAttr(oidCommonName, []byte("test ca")))

	cert := makeCertWithRawSubject(t, rawSubject)
	hash, err := computeOpenSSLSubjectHash(cert)
	if err != nil {
		t.Fatalf("computeOpenSSLSubjectHash failed: %v", err)
	}
	want := expectedHashFromCanonDER(t, canonDER)
	if hash != want {
		t.Errorf("hash = %s, want %s", hash, want)
	}
}

// TestOpenSSLSubjectHashIA5AndVisible verifies IA5String and VisibleString
// are canonicalized (in ASN1_MASK_CANON).
func TestOpenSSLSubjectHashIA5AndVisible(t *testing.T) {
	tests := []struct {
		name string
		tag  byte
		data []byte
	}{
		{"IA5String", 0x16, []byte("Test CA")},
		{"VisibleString", 0x1a, []byte("Test CA")},
	}

	// All should produce the same canonical form: UTF8String("test ca")
	expectedCanon := canonRDN(canonAttr(oidCommonName, []byte("test ca")))
	want := expectedHashFromCanonDER(t, expectedCanon)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawSubject := derSeq(derSet(derAttr(oidCommonName,
				derTagLength(tt.tag, tt.data))))
			cert := makeCertWithRawSubject(t, rawSubject)
			hash, err := computeOpenSSLSubjectHash(cert)
			if err != nil {
				t.Fatalf("computeOpenSSLSubjectHash failed: %v", err)
			}
			if hash != want {
				t.Errorf("hash = %s, want %s", hash, want)
			}
		})
	}
}

// TestOpenSSLSubjectHashPrintableString verifies PrintableString is canonicalized.
func TestOpenSSLSubjectHashPrintableString(t *testing.T) {
	// CN = PrintableString("Test CA")
	rawSubject := derSeq(derSet(derAttr(oidCommonName,
		derTagLength(0x13, []byte("Test CA")))))
	canonDER := canonRDN(canonAttr(oidCommonName, []byte("test ca")))

	cert := makeCertWithRawSubject(t, rawSubject)
	hash, err := computeOpenSSLSubjectHash(cert)
	if err != nil {
		t.Fatalf("computeOpenSSLSubjectHash failed: %v", err)
	}
	want := expectedHashFromCanonDER(t, canonDER)
	if hash != want {
		t.Errorf("hash = %s, want %s", hash, want)
	}
}

// TestOpenSSLSubjectHashMultiAttributeRDN verifies multi-attribute RDNs.
func TestOpenSSLSubjectHashMultiAttributeRDN(t *testing.T) {
	oidOrg := []byte{0x55, 0x04, 0x0a} // 2.5.4.10 (organization)

	// SET { O="Org", CN="CN" }
	attrOrg := derAttr(oidOrg, derUTF8String([]byte("Org")))
	attrCN := derAttr(oidCommonName, derUTF8String([]byte("CN")))
	rawSubject := derSeq(derSet(append(attrOrg, attrCN...)))

	// Canonical: both become UTF8String, sorted by DER
	canonOrg := canonAttr(oidOrg, []byte("org"))
	canonCN := canonAttr(oidCommonName, []byte("cn"))
	// Sort: compare full DER of each attribute
	var canonAttrs [][]byte
	if bytes.Compare(canonCN, canonOrg) < 0 {
		canonAttrs = [][]byte{canonCN, canonOrg}
	} else {
		canonAttrs = [][]byte{canonOrg, canonCN}
	}
	canonDER := canonRDN(canonAttrs...)

	cert := makeCertWithRawSubject(t, rawSubject)
	hash, err := computeOpenSSLSubjectHash(cert)
	if err != nil {
		t.Fatalf("computeOpenSSLSubjectHash failed: %v", err)
	}
	want := expectedHashFromCanonDER(t, canonDER)
	if hash != want {
		t.Errorf("hash = %s, want %s", hash, want)
	}
}

func TestTrustedCARestoreconInvokesWithMountScanDisabled(t *testing.T) {
	origSEL := selinuxEnabled
	origCmd := trustedCArestorecon
	defer func() {
		selinuxEnabled = origSEL
		trustedCArestorecon = origCmd
	}()
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }

	var args []string
	trustedCArestorecon = func(a ...string) ([]byte, error) {
		args = a
		return []byte{}, nil
	}

	base := "/run/docker-helper/trusted-ca"
	if err := restoreconTrustedCATree(base); err != nil {
		t.Fatalf("restoreconTrustedCATree failed: %v", err)
	}

	want := []string{"-R", "-m", base}
	if len(args) != len(want) {
		t.Fatalf("restorecon args = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("restorecon arg[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

func TestTrustedCARestoreconSkipsWhenSELinuxInactive(t *testing.T) {
	origSEL := selinuxEnabled
	origCmd := trustedCArestorecon
	defer func() {
		selinuxEnabled = origSEL
		trustedCArestorecon = origCmd
	}()
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }

	called := false
	trustedCArestorecon = func(a ...string) ([]byte, error) {
		called = true
		return []byte{}, nil
	}

	if err := restoreconTrustedCATree("/run/docker-helper/trusted-ca"); err != nil {
		t.Fatalf("restoreconTrustedCATree failed: %v", err)
	}
	if called {
		t.Error("restorecon must NOT be invoked when SELinux is inactive")
	}
}

func TestTrustedCARestoreconErrorPropagates(t *testing.T) {
	origSEL := selinuxEnabled
	origCmd := trustedCArestorecon
	defer func() {
		selinuxEnabled = origSEL
		trustedCArestorecon = origCmd
	}()
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	trustedCArestorecon = func(a ...string) ([]byte, error) {
		return []byte("policy error"), fmt.Errorf("restorecon: denied")
	}

	err := restoreconTrustedCATree("/run/docker-helper/trusted-ca")
	if err == nil {
		t.Fatal("expected error when restorecon fails")
	}
	if !strings.Contains(err.Error(), "policy error") {
		t.Errorf("error should include restorecon output, got: %v", err)
	}
}
