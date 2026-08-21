package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
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

// readValidatedCAFile opens the file at caPath, verifies it is a regular file,
// reads its contents, and validates them as a single PEM-encoded X.509 CA
// certificate. Returns the file bytes.
// The file is opened once; the fd is used for Stat to avoid TOCTOU.
func readValidatedCAFile(caPath string) ([]byte, error) {
	f, err := os.Open(caPath)
	if err != nil {
		return nil, fmt.Errorf("cannot access trusted_ca_path: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot access trusted_ca_path: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("trusted_ca_path must be a regular file: %s", caPath)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("cannot read trusted_ca_path: %w", err)
	}

	if _, err := validateCAPEM(data); err != nil {
		return nil, err
	}

	return data, nil
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

// x509NameAttr represents one attribute in an X.509 name.
type x509NameAttr struct {
	oid  []byte
	tag  byte
	data []byte
}

// x509NameRDN represents one RDN (SET of attributes).
type x509NameRDN struct {
	attrs []x509NameAttr
}

// parseX509RawSubject parses the DER-encoded RawSubject into RDNs and attributes.
func parseX509RawSubject(raw []byte) ([]x509NameRDN, error) {
	if len(raw) < 2 || raw[0] != 0x30 {
		return nil, fmt.Errorf("x509 name: not a SEQUENCE")
	}
	_, off := parseDERLength(raw, 1)
	content := raw[off:]

	var rdns []x509NameRDN
	pos := 0
	for pos < len(content) {
		if content[pos] != 0x31 {
			return nil, fmt.Errorf("x509 name: expected SET at offset %d", pos)
		}
		setLen, setOff := parseDERLength(content, pos+1)
		setContent := content[setOff : setOff+setLen]
		pos = setOff + setLen

		var attrs []x509NameAttr
		spos := 0
		for spos < len(setContent) {
			if setContent[spos] != 0x30 {
				return nil, fmt.Errorf("x509 name: expected attribute SEQUENCE")
			}
			attrLen, attrOff := parseDERLength(setContent, spos+1)
			attrContent := setContent[attrOff : attrOff+attrLen]
			spos = attrOff + attrLen

			if len(attrContent) < 2 || attrContent[0] != 0x06 {
				return nil, fmt.Errorf("x509 name: expected OID")
			}
			oidLen, oidOff := parseDERLength(attrContent, 1)
			oidBytes := attrContent[oidOff : oidOff+oidLen]
			attrContent = attrContent[oidOff+oidLen:]

			if len(attrContent) < 2 {
				return nil, fmt.Errorf("x509 name: no attribute value")
			}
			valTag := attrContent[0]
			valLen, valOff := parseDERLength(attrContent, 1)
			valBytes := attrContent[valOff : valOff+valLen]

			attrs = append(attrs, x509NameAttr{
				oid:  oidBytes,
				tag:  valTag,
				data: valBytes,
			})
		}
		rdns = append(rdns, x509NameRDN{attrs: attrs})
	}
	return rdns, nil
}

// parseDERLength parses a DER length field and returns (length, offset-after-length).
func parseDERLength(data []byte, offset int) (length int, valueOffset int) {
	b := int(data[offset])
	offset++
	if b&0x80 == 0 {
		return b, offset
	}
	n := b & 0x7f
	length = 0
	for i := 0; i < n; i++ {
		length = length<<8 | int(data[offset])
		offset++
	}
	return length, offset
}

// asn1StringNeedsCanon returns true if the given ASN.1 tag is a string type
// that should be canonicalized (converted to UTF-8, lowercased, whitespace
// normalized) per OpenSSL's x509_name_canon.
func asn1StringNeedsCanon(tag byte) bool {
	switch tag {
	case 0x0c, // UTF8String
		0x13, // PrintableString
		0x16, // IA5String
		0x14, // T61String
		0x1e, // BMPString
		0x1c, // UniversalString
		0x1a, // VisibleString
		0x12: // NumericString
		return true
	}
	return false
}

// canonicalizeASN1Value canonicalizes a string value per OpenSSL's
// asn1_string_canon: convert to UTF-8, strip leading/trailing whitespace,
// collapse internal whitespace runs, and lowercase ASCII letters.
func canonicalizeASN1Value(data []byte, tag byte) []byte {
	s := string(data)

	// Strip leading whitespace
	i := 0
	for i < len(s) && unicode.IsSpace(rune(s[i])) {
		i++
	}
	s = s[i:]

	// Strip trailing whitespace
	j := len(s)
	for j > 0 && unicode.IsSpace(rune(s[j-1])) {
		j--
	}
	s = s[:j]

	// Collapse whitespace runs and lowercase
	var out []rune
	lastSpace := false
	for _, c := range s {
		if unicode.IsSpace(c) {
			if !lastSpace {
				out = append(out, ' ')
				lastSpace = true
			}
		} else {
			out = append(out, unicode.ToLower(c))
			lastSpace = false
		}
	}
	return []byte(string(out))
}

// buildCanonicalX509NameDER builds the canonical DER encoding of an X.509 name
// matching OpenSSL's x509_name_canon / i2d_name_canon. The outer SEQUENCE
// wrapper is omitted (OpenSSL's canon_enc excludes it for dirName comparison).
func buildCanonicalX509NameDER(rdns []x509NameRDN) []byte {
	var buf []byte

	for _, rdn := range rdns {
		var setInner []byte
		for _, attr := range rdn.attrs {
			var attrInner []byte
			attrInner = append(attrInner, 0x06, byte(len(attr.oid)))
			attrInner = append(attrInner, attr.oid...)

			if asn1StringNeedsCanon(attr.tag) {
				canon := canonicalizeASN1Value(attr.data, attr.tag)
				attrInner = append(attrInner, 0x0c, byte(len(canon)))
				attrInner = append(attrInner, canon...)
			} else {
				attrInner = append(attrInner, attr.tag, byte(len(attr.data)))
				attrInner = append(attrInner, attr.data...)
			}

			setInner = append(setInner, 0x30, byte(len(attrInner)))
			setInner = append(setInner, attrInner...)
		}
		buf = append(buf, 0x31, byte(len(setInner)))
		buf = append(buf, setInner...)
	}
	return buf
}

// computeOpenSSLHash computes the OpenSSL-compatible subject-name hash for
// the given certificate. The algorithm matches `openssl x509 -hash -noout`
// (OpenSSL 3.x subject_hash):
//
// 1. Canonicalize the X.509 subject name:
//   - Convert all string types to UTF-8
//   - Strip leading/trailing whitespace
//   - Collapse internal whitespace runs to a single space
//   - Lowercase ASCII letters
//
// 2. DER-encode the canonical name (without outer SEQUENCE wrapper)
// 3. SHA-1 hash of the canonical DER
// 4. First 4 bytes as little-endian 8-character lowercase hex
func computeOpenSSLHash(cert *x509.Certificate) string {
	rdns, err := parseX509RawSubject(cert.RawSubject)
	if err != nil {
		// Fallback: should not happen for valid certificates
		return "00000000"
	}

	canon := buildCanonicalX509NameDER(rdns)
	h := sha1.Sum(canon)
	return fmt.Sprintf("%08x", uint32(h[3])<<24|uint32(h[2])<<16|uint32(h[1])<<8|uint32(h[0]))
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
	// Read and validate the source CA file once.
	caData, err := readValidatedCAFile(caPath)
	if err != nil {
		return "", err
	}

	// Parse certificate to compute the openssl-compatible hash.
	cert, err := validateCAPEM(caData)
	if err != nil {
		return "", err
	}

	// Compute openssl hash from the parsed certificate.
	hash := computeOpenSSLHash(cert)

	// Determine fingerprint directory.
	fpDir := fingerprintDir(runtimeDir, caData)
	caFile := filepath.Join(fpDir, "ca.pem")
	symlinkPath := filepath.Join(fpDir, hash+".0")

	// If the directory already exists with the correct content, skip.
	if info, err := os.Stat(fpDir); err == nil && info.IsDir() {
		caInfo, statErr := os.Lstat(caFile)
		if statErr == nil && caInfo.Mode().IsRegular() {
			if existing, err := os.ReadFile(caFile); err == nil && bytes.Equal(existing, caData) {
				if target, err := os.Readlink(symlinkPath); err == nil && target == "ca.pem" {
					// Ensure modes are correct regardless of umask or external chmod.
					if err := os.Chmod(fpDir, 0755); err != nil {
						return "", fmt.Errorf("cannot set trusted CA directory permissions: %w", err)
					}
					if err := os.Chmod(caFile, 0644); err != nil {
						return "", fmt.Errorf("cannot set trusted CA file permissions: %w", err)
					}
					return fpDir, nil
				}
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
