package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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
// regular file containing exactly one valid PEM-encoded X.509 certificate.
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

	certs, err := parseCAPEM(data)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("trusted_ca_path contains no X.509 certificates")
	}
	if len(certs) > 1 {
		return nil, fmt.Errorf("trusted_ca_path must contain exactly one certificate, found %d", len(certs))
	}
	return certs[0], nil
}

// pemBlock represents a decoded PEM block.
type pemBlock struct {
	Type  string
	Bytes []byte
}

// parseCAPEM parses PEM-encoded X.509 certificates from data.
// Returns the parsed certificates, or an error if the data is not valid PEM.
func parseCAPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	remaining := data

	for len(remaining) > 0 {
		block, rest := pemDecode(remaining)
		if block == nil {
			break
		}
		remaining = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trusted_ca_path contains invalid X.509 certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 && len(data) > 0 {
		return nil, fmt.Errorf("trusted_ca_path does not contain valid PEM data")
	}

	return certs, nil
}

// pemDecode extracts the next PEM block from data.
// Returns the block (with Type and Bytes) and the remaining data,
// or (nil, data) if no block is found.
func pemDecode(data []byte) (block *pemBlock, rest []byte) {
	start := bytesIndex(data, []byte("-----BEGIN "))
	if start < 0 {
		return nil, data
	}
	// Find the closing dashes after the type: "-----BEGIN TYPE-----\n"
	dashEnd := bytesIndex(data[start+11:], []byte("-----\n"))
	if dashEnd < 0 {
		// Try CRLF
		dashEnd = bytesIndex(data[start+11:], []byte("-----\r\n"))
		if dashEnd < 0 {
			return nil, data
		}
	}
	blockType := string(data[start+11 : start+11+dashEnd])

	end := bytesIndex(data[start:], []byte("-----END "))
	if end < 0 {
		return nil, data
	}
	end += start
	// Find the closing dashes and newline: "-----END TYPE-----\n"
	var blockEnd int
	for i := end + 9; i < len(data); i++ {
		if data[i] == '-' && i+1 < len(data) && data[i+1] == '\n' {
			blockEnd = i + 2
			break
		}
		if data[i] == '-' && i+1 < len(data) && data[i+1] == '\r' && i+2 < len(data) && data[i+2] == '\n' {
			blockEnd = i + 3
			break
		}
	}
	if blockEnd == 0 {
		return nil, data
	}

	// Extract the base64 content between BEGIN and END lines.
	contentStart := start + 11 + dashEnd
	// Skip the newline after "-----BEGIN TYPE-----"
	if contentStart < len(data) && data[contentStart] == '\n' {
		contentStart++
	} else if contentStart < len(data) && data[contentStart] == '\r' && contentStart+1 < len(data) && data[contentStart+1] == '\n' {
		contentStart += 2
	}
	contentEnd := end // up to "-----END "
	rawContent := bytes.TrimSpace(data[contentStart:contentEnd])

	// Decode base64.
	decoded, err := base64Decode(rawContent)
	if err != nil {
		return nil, data[blockEnd:]
	}

	return &pemBlock{Type: blockType, Bytes: decoded}, data[blockEnd:]
}

// base64Decode decodes standard base64 data.
func base64Decode(data []byte) ([]byte, error) {
	dec := make([]byte, 0, len(data))
	var val uint32
	var bits int
	for _, c := range data {
		if c == '=' {
			break
		}
		v := base64Value(c)
		if v < 0 {
			continue // skip whitespace
		}
		val = (val << 6) | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			dec = append(dec, byte(val>>(bits)))
		}
	}
	return dec, nil
}

func base64Value(c byte) int {
	if c >= 'A' && c <= 'Z' {
		return int(c - 'A')
	}
	if c >= 'a' && c <= 'z' {
		return int(c - 'a' + 26)
	}
	if c >= '0' && c <= '9' {
		return int(c - '0' + 52)
	}
	if c == '+' {
		return 62
	}
	if c == '/' {
		return 63
	}
	return -1
}

func bytesIndex(data, sub []byte) int {
	for i := 0; i <= len(data)-len(sub); i++ {
		if data[i] == sub[0] {
			match := true
			for j := 1; j < len(sub); j++ {
				if data[i+j] != sub[j] {
					match = false
					break
				}
			}
			if match {
				return i
			}
		}
	}
	return -1
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
			if _, err := os.Lstat(symlinkPath); err == nil {
				return fpDir, nil
			}
		}
	}

	// Create the fingerprint directory with mode 0755.
	if err := os.MkdirAll(fpDir, 0755); err != nil {
		return "", fmt.Errorf("cannot create trusted CA directory: %w", err)
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
	// Remove existing symlink if present (different hash or stale).
	os.Remove(symlinkPath)
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
