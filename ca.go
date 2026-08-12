package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// trustedCAContainerDir is the container mount target for the trusted CA directory.
const trustedCAContainerDir = "/run/docker-helper/trusted-ca"

// trustedCAEnvSSLDir and trustedCAEnvNodeExtra are the injected environment
// variable names for CA injection.
const (
	trustedCAEnvSSLDir    = "SSL_CERT_DIR"
	trustedCAEnvNodeExtra = "NODE_EXTRA_CA_CERTS"
)

// trustedCAEnvSSLDirValue is the injected SSL_CERT_DIR value.
const trustedCAEnvSSLDirValue = "/run/docker-helper/trusted-ca:/etc/ssl/certs:/etc/pki/tls/certs"

// trustedCAEnvNodeExtraValue is the injected NODE_EXTRA_CA_CERTS value.
const trustedCAEnvNodeExtraValue = "/run/docker-helper/trusted-ca/ca.pem"

// opensslHashPattern validates the output of `openssl x509 -hash -noout`.
var opensslHashPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}$`)

// validateCAFile reads the file at caPath and verifies it is a readable
// regular file containing exactly one valid PEM-encoded X.509 CA certificate.
// The file must contain exactly one PEM block of type CERTIFICATE, with only
// whitespace before and after the block. The certificate must have
// BasicConstraintsValid=true and IsCA=true.
// Returns the parsed certificate, or an error if validation fails.
func validateCAFile(caPath string) (*x509.Certificate, error) {
	info, err := os.Stat(caPath)
	if err != nil {
		return nil, fmt.Errorf("cannot access trusted_ca_path: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("trusted_ca_path must be a regular file: %s", caPath)
	}

	data, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read trusted_ca_path: %w", err)
	}

	return validateCAPEM(data)
}

// validateCAPEM validates that data contains exactly one PEM-encoded X.509
// CA certificate. Returns the parsed certificate, or an error.
func validateCAPEM(data []byte) (*x509.Certificate, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("trusted_ca_path contains no PEM data")
	}

	// Reject any non-whitespace prefix before the PEM block.
	// pem.Decode silently skips leading bytes, so we enforce that
	// the trimmed content starts exactly with the PEM header.
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, fmt.Errorf("trusted_ca_path does not contain valid PEM data")
	}

	block, rest := pem.Decode(trimmed)
	if block == nil {
		return nil, fmt.Errorf("trusted_ca_path does not contain valid PEM data")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("trusted_ca_path contains invalid PEM block type, expected CERTIFICATE")
	}

	// After the PEM block only whitespace is allowed (trimmed has none,
	// so rest must be empty).
	if len(rest) > 0 {
		return nil, fmt.Errorf("trusted_ca_path contains extra content after certificate")
	}

	// Parse the DER bytes as an X.509 certificate.
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("trusted_ca_path contains invalid X.509 certificate")
	}

	// Verify it's a CA certificate.
	if !cert.BasicConstraintsValid {
		return nil, fmt.Errorf("trusted_ca_path certificate is not a CA (missing basic constraints)")
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("trusted_ca_path certificate is not a CA")
	}

	return cert, nil
}

// computeOpenSSLHash runs `openssl x509 -hash -noout -in CA_FILE` and returns
// the 8-character hex hash. It uses exec.Command (no shell).
// Returns an error if openssl is missing, the command fails, or the output
// does not match the expected format.
func computeOpenSSLHash(caPath string) (string, error) {
	cmd := exec.Command("openssl", "x509", "-hash", "-noout", "-in", caPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("openssl x509 -hash failed")
	}

	hash := strings.TrimSpace(string(out))
	if !opensslHashPattern.MatchString(hash) {
		return "", fmt.Errorf("openssl x509 -hash output is invalid")
	}
	return hash, nil
}

// fingerprintDir returns the path to the fingerprint directory for a given
// CA source file: $runtime_dir/trusted-ca/<sha256-of-source-bytes>/
func fingerprintDir(runtimeDir string, caData []byte) string {
	h := sha256.Sum256(caData)
	hexHash := hex.EncodeToString(h[:])
	return filepath.Join(runtimeDir, "trusted-ca", hexHash)
}

// prepareCAInjection validates the CA file, computes the openssl hash, and
// materializes the CA in the helper-owned runtime directory:
//
//	$RUNTIME_DIR/trusted-ca/<sha256-of-source-bytes>/
//	    ├── ca.pem
//	    └── <openssl-hash>.0 -> ca.pem
//
// Returns the prepared directory path, or an error if preparation fails.
// Idempotent: re-preparing the same CA is a no-op.
func prepareCAInjection(runtimeDir, caPath string) (preparedDir string, err error) {
	// Validate the source CA file.
	if _, err := validateCAFile(caPath); err != nil {
		return "", err
	}

	// Read source data for fingerprinting.
	caData, err := os.ReadFile(caPath)
	if err != nil {
		return "", fmt.Errorf("cannot read trusted_ca_path: %w", err)
	}

	// Compute openssl hash (requires openssl binary).
	hash, err := computeOpenSSLHash(caPath)
	if err != nil {
		return "", err
	}

	// Determine fingerprint directory.
	fpDir := fingerprintDir(runtimeDir, caData)
	caFile := filepath.Join(fpDir, "ca.pem")
	symlinkPath := filepath.Join(fpDir, hash+".0")

	// If the directory already exists with the correct content, skip.
	if info, err := os.Stat(fpDir); err == nil && info.IsDir() {
		if existing, err := os.ReadFile(caFile); err == nil && bytes.Equal(existing, caData) {
			if target, err := os.Readlink(symlinkPath); err == nil && target == "ca.pem" {
				// Ensure the fingerprint directory mode is 0755 regardless of umask.
				if err := os.Chmod(fpDir, 0755); err != nil {
					return "", fmt.Errorf("cannot set trusted CA directory permissions: %w", err)
				}
				return fpDir, nil
			}
		}
	}

	// Create the fingerprint directory with mode 0755.
	if err := os.MkdirAll(fpDir, 0755); err != nil {
		return "", fmt.Errorf("cannot create trusted CA directory: %w", err)
	}
	// Explicitly set mode to guarantee 0755 regardless of process umask.
	if err := os.Chmod(fpDir, 0755); err != nil {
		return "", fmt.Errorf("cannot set trusted CA directory permissions: %w", err)
	}

	// Write ca.pem atomically with mode 0644.
	tmp, err := os.CreateTemp(fpDir, "ca-*.pem.tmp")
	if err != nil {
		return "", fmt.Errorf("cannot create temp CA file: %w", err)
	}
	tmpName := tmp.Name()

	cleanupTemp := func(werr error) (string, error) {
		tmp.Close()
		os.Remove(tmpName)
		return "", werr
	}

	if _, err := tmp.Write(caData); err != nil {
		return cleanupTemp(fmt.Errorf("cannot write CA file: %w", err))
	}
	if err := tmp.Chmod(0644); err != nil {
		return cleanupTemp(fmt.Errorf("cannot set CA file permissions: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return cleanupTemp(fmt.Errorf("cannot close CA file: %w", err))
	}
	if err := os.Rename(tmpName, caFile); err != nil {
		return cleanupTemp(fmt.Errorf("cannot install CA file: %w", err))
	}

	// Create the openssl hash symlink.
	// Remove existing entry if present (different hash or stale).
	if err := os.Remove(symlinkPath); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot remove existing CA hash entry: %w", err)
	}
	if err := os.Symlink("ca.pem", symlinkPath); err != nil {
		return "", fmt.Errorf("cannot create CA hash symlink: %w", err)
	}

	return fpDir, nil
}

// isTrustedCAEnvVar returns true if envKey is one of the helper-injected
// CA environment variable names.
func isTrustedCAEnvVar(envKey string) bool {
	return envKey == trustedCAEnvSSLDir || envKey == trustedCAEnvNodeExtra
}

// isTrustedCAMountOverlap returns true if the agent mount target overlaps
// with the trusted CA injection target. This includes exact match, ancestor,
// and descendant relationships.
func isTrustedCAMountOverlap(target string) bool {
	cleaned := filepath.Clean(target)
	if cleaned == trustedCAContainerDir {
		return true
	}
	rel, err := filepath.Rel(trustedCAContainerDir, cleaned)
	if err != nil {
		return false
	}
	// cleaned is inside trustedCAContainerDir
	if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	// cleaned is an ancestor of trustedCAContainerDir
	rel2, err := filepath.Rel(cleaned, trustedCAContainerDir)
	if err != nil {
		return false
	}
	if rel2 != ".." && !strings.HasPrefix(rel2, ".."+string(filepath.Separator)) {
		return true
	}
	return false
}
