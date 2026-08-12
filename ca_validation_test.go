package main

import (
	"encoding/pem"
	"path/filepath"
	"testing"
)

func TestReadValidatedCAFileSuccess(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	data, cert, err := readValidatedCAFile(caPath)
	if err != nil {
		t.Fatalf("readValidatedCAFile failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty bytes")
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if !cert.IsCA {
		t.Error("expected CA certificate")
	}
}

func TestReadValidatedCAFileMissing(t *testing.T) {
	_, _, err := readValidatedCAFile("/nonexistent/ca.crt")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadValidatedCAFileNotRegular(t *testing.T) {
	dir := t.TempDir()
	_, _, err := readValidatedCAFile(dir)
	if err == nil {
		t.Fatal("expected error for directory")
	}
}

func TestValidateCAPEMValidCA(t *testing.T) {
	data := generateTestCAPEMData(t)
	cert, err := validateCAPEM(data)
	if err != nil {
		t.Fatalf("expected valid CA, got error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if !cert.IsCA {
		t.Error("expected IsCA=true")
	}
}

func TestValidateCAPEMWhitespaceAround(t *testing.T) {
	pemData := generateTestCAPEMData(t)
	data := append([]byte("\n\n\n"), append(pemData, '\n', '\n')...)
	cert, err := validateCAPEM(data)
	if err != nil {
		t.Fatalf("expected valid CA with whitespace, got error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

func TestValidateCAPEMLeadingGarbageRejected(t *testing.T) {
	pemData := generateTestCAPEMData(t)
	data := append([]byte("garbage before cert\n"), pemData...)
	_, err := validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for leading garbage before certificate")
	}
}

func TestValidateCAPEMLeafRejected(t *testing.T) {
	data := generateTestLeafPEM(t)
	_, err := validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for leaf certificate")
	}
}

func TestValidateCAPEMCAPlusPrivateKeyRejected(t *testing.T) {
	data := generateTestCAPrivateKeyPEM(t)
	_, err := validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for CA + private key")
	}
}

func TestValidateCAPEMCAPlusSecondPEMBlockRejected(t *testing.T) {
	data := generateTestCASecondPEMBlock(t)
	_, err := validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for CA + second PEM block")
	}
}

func TestValidateCAPEMCAPlusTrailingGarbageRejected(t *testing.T) {
	pemData := generateTestCAPEMData(t)
	data := append(pemData, []byte(" trailing garbage")...)
	_, err := validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for CA + trailing garbage")
	}
}

func TestValidateCAPEMInvalidBase64Rejected(t *testing.T) {
	data := []byte("-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----\n")
	_, err := validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for invalid base64 in PEM")
	}
}

func TestValidateCAPEMEmptyDataRejected(t *testing.T) {
	_, err := validateCAPEM([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestValidateCAPEMNoPEMRejected(t *testing.T) {
	_, err := validateCAPEM([]byte("not PEM data at all"))
	if err == nil {
		t.Fatal("expected error for non-PEM data")
	}
}

func TestValidateCAPEMNonCertificateBlockRejected(t *testing.T) {
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")})
	_, err := validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for non-CERTIFICATE block")
	}
}

// --- fingerprintDir tests ---

func TestFingerprintDirDeterministic(t *testing.T) {
	runtimeDir := "/tmp/runtime"
	data := []byte("test CA data")

	dir1 := fingerprintDir(runtimeDir, data)
	dir2 := fingerprintDir(runtimeDir, data)

	if dir1 != dir2 {
		t.Error("fingerprintDir should be deterministic")
	}

	dir3 := fingerprintDir(runtimeDir, []byte("different data"))
	if dir1 == dir3 {
		t.Error("different data should produce different fingerprint")
	}
}
