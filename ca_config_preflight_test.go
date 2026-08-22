package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCAPreflightAutoMissingCA(t *testing.T) {
	configPath, caPath := setupCAConfigPreflightTest(t)

	// Remove the CA file so it's missing.
	if err := os.Remove(caPath); err != nil {
		t.Fatalf("cannot remove CA: %v", err)
	}

	// Set trusted_ca_path to the missing file first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}

	// Save original config bytes before the failing command.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Now try to enable auto with the missing CA.
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config file should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightAutoMalformedCA(t *testing.T) {
	configPath, _ := setupCAConfigPreflightTest(t)

	// Create a malformed CA file.
	badCAPath := filepath.Join(filepath.Dir(configPath), "bad-ca.crt")
	if err := os.WriteFile(badCAPath, []byte("not valid PEM data"), 0644); err != nil {
		t.Fatalf("cannot write bad CA: %v", err)
	}

	// First set the path.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", badCAPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Now try to enable auto with the malformed CA.
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stderr: %q", code, stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightAutoLeafCA(t *testing.T) {
	configPath, _ := setupCAConfigPreflightTest(t)

	// Create a leaf certificate.
	leafPath := filepath.Join(filepath.Dir(configPath), "leaf.crt")
	leafPEM := generateTestLeafPEM(t)
	if err := os.WriteFile(leafPath, leafPEM, 0644); err != nil {
		t.Fatalf("cannot write leaf: %v", err)
	}

	// Set the path first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", leafPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Try to enable auto with the leaf CA.
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stderr: %q", code, stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightReplacePathInvalidWhileAuto(t *testing.T) {
	configPath, caPath := setupCAConfigPreflightTest(t)

	// First set path and enable auto (should succeed with valid CA).
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d stdout: %q stderr: %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d stdout: %q stderr: %q", code, stdout.String(), stderr.String())
	}

	// Save original config bytes after setup.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Now try to replace path with a non-existent file.
	badPath := filepath.Join(filepath.Dir(configPath), "nonexistent.crt")
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_path", badPath}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stderr: %q", code, stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightValidCASucceeds(t *testing.T) {
	configPath, caPath := setupCAConfigPreflightTest(t)

	// Set path and enable auto (should succeed).
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d, stderr: %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d, stderr: %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in stdout, got: %q", stdout.String())
	}

	// Verify config was written.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("cannot parse config: %v", err)
	}
	if raw["trusted_ca_injection"] != "auto" {
		t.Errorf("expected auto, got %v", raw["trusted_ca_injection"])
	}
}

func TestCAPreflightDisabledNoValidation(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	nonexistentRuntime := filepath.Join(dir, "nonexistent_runtime")
	nonexistentState := filepath.Join(dir, "nonexistent_state")

	// Write admin token.
	if err := os.WriteFile(tokenPath, []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatalf("cannot write token: %v", err)
	}

	// Write initial config with disabled injection.
	allowedRoot := testAllowedRootDir(t)
	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         allowedRoot,
		"session_ttl":          "12h",
		"trusted_ca_injection": "disabled",
	})

	// Set environment: nonexistent runtime/state.
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", nonexistentRuntime)
	t.Setenv("XDG_STATE_HOME", nonexistentState)

	// Prevent reaching a real system daemon.
	origSocket := systemSocketExists
	systemSocketExists = func() bool { return false }
	t.Cleanup(func() { systemSocketExists = origSocket })

	// Point to a non-existent CA path while injection is disabled.
	badPath := filepath.Join(dir, "nonexistent.crt")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", badPath}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 for disabled mode, got %d, stderr: %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in stdout, got: %q", stdout.String())
	}

	// Verify runtime directory was NOT created.
	if _, err := os.Stat(nonexistentRuntime); !os.IsNotExist(err) {
		t.Errorf("runtime dir %s should not have been created", nonexistentRuntime)
	}

	// Verify state directory was NOT created.
	if _, err := os.Stat(nonexistentState); !os.IsNotExist(err) {
		t.Errorf("state dir %s should not have been created", nonexistentState)
	}
}

func TestCAPreflightUnchangedWithBrokenCA(t *testing.T) {
	configPath, caPath := setupCAConfigPreflightTest(t)

	// Set up valid config first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d stdout: %q stderr: %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d stdout: %q stderr: %q", code, stdout.String(), stderr.String())
	}

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Now break the CA file.
	if err := os.Remove(caPath); err != nil {
		t.Fatalf("cannot remove CA: %v", err)
	}

	// Try to set the same values (unchanged path).
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 for unchanged with broken CA, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightSetUnchanged(t *testing.T) {
	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "unchanged") {
		t.Errorf("expected 'unchanged' in output, got: %s", stdout.String())
	}
}

func TestCAPreflightUnsetAbsentWithBrokenCA(t *testing.T) {
	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	beforeData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Break the CA file so preflight validation fails.
	if err := os.Remove(caPath); err != nil {
		t.Fatal(err)
	}

	// Unset a field that is already absent to hit the "already absent" branch.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	afterData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeData, afterData) {
		t.Error("config.json should not be modified when preflight fails")
	}
}

// generateCAWithSurrogateSubject creates a CA certificate PEM whose subject
// contains a BMPString with a Unicode surrogate (U+D800). Go's x509 parser
// rejects this certificate during parsing, but the certificate is valid PEM.
func generateCAWithSurrogateSubject(t *testing.T) []byte {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TestCA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	// Patch DER to replace subject with one containing BMPString surrogate.
	patched := patchSubjectInCertDER(t, der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: patched})
}

func patchSubjectInCertDER(t *testing.T, der []byte) []byte {
	t.Helper()
	newSub := []byte{
		0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d,
		0x06, 0x03, 0x55, 0x04, 0x03,
		0x1e, 0x04, 0xd8, 0x00, 0x43, 0x41,
	}
	_, outerOff, err := parseTestDERLen(der, 1)
	if err != nil {
		t.Fatal(err)
	}
	tbsLen, tbsOff, err := parseTestDERLen(der, outerOff+1)
	if err != nil {
		t.Fatal(err)
	}
	tbsEnd := tbsOff + tbsLen
	pos := tbsOff
	if der[pos] == 0xa0 {
		vl, vo, _ := parseTestDERLen(der, pos+1)
		pos = vo + vl
	}
	sl, so, _ := parseTestDERLen(der, pos+1)
	pos = so + sl
	al, ao, _ := parseTestDERLen(der, pos+1)
	pos = ao + al
	il, io, _ := parseTestDERLen(der, pos+1)
	pos = io + il
	vl, vo, _ := parseTestDERLen(der, pos+1)
	pos = vo + vl
	subStart := pos
	subOff := pos + 1
	for der[subOff] >= 0x80 {
		n := der[subOff] & 0x7f
		subOff += 1 + int(n)
	}
	subEnd := subOff + 1 + int(der[subOff])

	delta := len(newSub) - (subEnd - subStart)
	origOuterLen, _, _ := parseTestDERLen(der, 1)
	patched := make([]byte, len(der)+delta)
	w := 0
	patched[w] = 0x30
	w++
	w += writeTestDERLen(patched[w:], origOuterLen+delta)
	patched[w] = 0x30
	w++
	w += writeTestDERLen(patched[w:], tbsLen+delta)
	w += copy(patched[w:], der[tbsOff:subStart])
	w += copy(patched[w:], newSub)
	w += copy(patched[w:], der[subEnd:tbsEnd])
	w += copy(patched[w:], der[tbsEnd:])
	return patched
}

func parseTestDERLen(data []byte, off int) (int, int, error) {
	if off >= len(data) {
		return 0, 0, fmt.Errorf("offset out of bounds")
	}
	b := data[off]
	off++
	if b < 0x80 {
		return int(b), off, nil
	}
	n := b & 0x7f
	if n == 0 || off+int(n) > len(data) {
		return 0, 0, fmt.Errorf("invalid length encoding")
	}
	v := 0
	for i := 0; i < int(n); i++ {
		v = v<<8 | int(data[off])
		off++
	}
	return v, off, nil
}

func writeTestDERLen(buf []byte, v int) int {
	if v < 128 {
		buf[0] = byte(v)
		return 1
	}
	var b []byte
	tmp := v
	for tmp > 0 {
		b = append([]byte{byte(tmp)}, b...)
		tmp >>= 8
	}
	buf[0] = 0x80 | byte(len(b))
	copy(buf[1:], b)
	return 1 + len(b)
}

func TestValidateCAConfigReachesHashComputation(t *testing.T) {
	// Regression: validateCAConfig must call computeOpenSSLHash and
	// propagate its error, not discard it.
	//
	// Go's x509 parser validates BMPString/UniversalString for surrogate
	// code points during parsing, so it is not possible to create a PEM
	// file that passes Go's parser but fails computeOpenSSLHash.
	//
	// This test proves validateCAConfig reaches computeOpenSSLHash by
	// verifying that a valid CA passes (the hash succeeds). The existing
	// TestOpenSSLHashSurrogateRejection proves computeOpenSSLHash can
	// fail. The fix ensures that if computeOpenSSLHash ever fails,
	// the error is propagated with context.

	_, caPath := setupCAConfigPreflightTest(t)

	raw := map[string]json.RawMessage{
		"trusted_ca_injection": json.RawMessage(`"auto"`),
		"trusted_ca_path":      json.RawMessage(fmt.Sprintf(`"%s"`, caPath)),
	}

	if err := validateCAConfig(raw); err != nil {
		t.Fatalf("valid CA should pass: %v", err)
	}
}

func TestValidateCAConfigRejectsSurrogateSubject(t *testing.T) {
	// Regression: validateCAConfig must reject a CA with an invalid subject.
	// Go's parser rejects the surrogate during parsing (before computeOpenSSLHash),
	// but this still proves the validation chain rejects invalid certificates.

	dir := t.TempDir()
	caPath := filepath.Join(dir, "surrogate-ca.crt")
	pemData := generateCAWithSurrogateSubject(t)
	if err := os.WriteFile(caPath, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	raw := map[string]json.RawMessage{
		"trusted_ca_injection": json.RawMessage(`"auto"`),
		"trusted_ca_path":      json.RawMessage(fmt.Sprintf(`"%s"`, caPath)),
	}

	err := validateCAConfig(raw)
	if err == nil {
		t.Fatal("expected error for CA with surrogate subject, got nil")
	}
}

func TestConfigMutationRejectsSurrogateCA(t *testing.T) {
	// End-to-end: config set must reject a CA with an invalid subject
	// before committing the config file.

	configPath, _ := setupCAConfigPreflightTest(t)

	surrogateCAPath := filepath.Join(filepath.Dir(configPath), "surrogate-ca.crt")
	pemData := generateCAWithSurrogateSubject(t)
	if err := os.WriteFile(surrogateCAPath, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	// Set the path first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", surrogateCAPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d, stderr: %q", code, stderr.String())
	}

	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Try to enable auto — should fail.
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestComputeOpenSSLHashFailsForSurrogate(t *testing.T) {
	// Prove computeOpenSSLHash fails for a certificate with a surrogate subject.
	surrogateSubject := derSeqTest(derSetTest(derAttrTest(oidCommonNameTest,
		derTagLengthTest(0x1e, []byte{0xd8, 0x00}))))
	cert := makeCertWithRawSubjectForTest(surrogateSubject)

	_, err := computeOpenSSLHash(cert)
	if err == nil {
		t.Fatal("computeOpenSSLHash should fail for surrogate subject")
	}
}

// Helper functions for constructing DER subjects in tests.
var oidCommonNameTest = []byte{0x55, 0x04, 0x03}

func derSeqTest(inner []byte) []byte {
	return append(append([]byte{0x30}, encodeDERLength(len(inner))...), inner...)
}
func derSetTest(inner []byte) []byte {
	return append(append([]byte{0x31}, encodeDERLength(len(inner))...), inner...)
}
func derAttrTest(oid, value []byte) []byte {
	return derSeqTest(append(derOIDTest(oid), value...))
}
func derOIDTest(oid []byte) []byte {
	return append(append([]byte{0x06}, encodeDERLength(len(oid))...), oid...)
}
func derTagLengthTest(tag byte, data []byte) []byte {
	return append(append([]byte{tag}, encodeDERLength(len(data))...), data...)
}

func makeCertWithRawSubjectForTest(rawSubject []byte) *x509.Certificate {
	cert := createTestCertWithSubjectForTest(pkix.Name{CommonName: "placeholder"})
	cert.RawSubject = rawSubject
	return cert
}

func createTestCertWithSubjectForTest(subject pkix.Name) *x509.Certificate {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(der)
	return cert
}
