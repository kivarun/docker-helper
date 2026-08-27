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
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// trustedCAContainerDir is the container mount target for the trusted CA directory.
const trustedCAContainerDir = "/run/docker-helper/trusted-ca"

// trustedCAPreparationError identifies any failure originating from trusted CA
// preflight or preparation. It wraps the inner error and can be identified
// with errors.As regardless of the inner error text.
type trustedCAPreparationError struct {
	Err error
}

func (e *trustedCAPreparationError) Error() string {
	return fmt.Sprintf("trusted CA preparation failed: %v", e.Err)
}

func (e *trustedCAPreparationError) Unwrap() error {
	return e.Err
}

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
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("trusted_ca_path contains no PEM data")
	}

	// Reject any non-whitespace prefix before the PEM block.
	// pem.Decode silently skips leading bytes, so we enforce that
	// the trimmed content starts exactly with the PEM header.
	if !strings.HasPrefix(trimmed, "-----BEGIN CERTIFICATE-----") {
		return nil, fmt.Errorf("trusted_ca_path does not contain valid PEM data")
	}

	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("trusted_ca_path does not contain valid PEM data")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("trusted_ca_path contains invalid PEM block type, expected CERTIFICATE")
	}

	// After the PEM block only whitespace is allowed.
	if len(rest) > 0 {
		restTrimmed := strings.TrimSpace(string(rest))
		if len(restTrimmed) > 0 {
			return nil, fmt.Errorf("trusted_ca_path contains extra content after certificate")
		}
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
	_, off, err := parseDERLength(raw, 1)
	if err != nil {
		return nil, err
	}
	content := raw[off:]

	var rdns []x509NameRDN
	pos := 0
	for pos < len(content) {
		if content[pos] != 0x31 {
			return nil, fmt.Errorf("x509 name: expected SET at offset %d", pos)
		}
		setLen, setOff, err := parseDERLength(content, pos+1)
		if err != nil {
			return nil, err
		}
		setContent := content[setOff : setOff+setLen]
		pos = setOff + setLen

		var attrs []x509NameAttr
		spos := 0
		for spos < len(setContent) {
			if setContent[spos] != 0x30 {
				return nil, fmt.Errorf("x509 name: expected attribute SEQUENCE")
			}
			attrLen, attrOff, err := parseDERLength(setContent, spos+1)
			if err != nil {
				return nil, err
			}
			attrContent := setContent[attrOff : attrOff+attrLen]
			spos = attrOff + attrLen

			if len(attrContent) < 2 || attrContent[0] != 0x06 {
				return nil, fmt.Errorf("x509 name: expected OID")
			}
			oidLen, oidOff, err := parseDERLength(attrContent, 1)
			if err != nil {
				return nil, err
			}
			oidBytes := attrContent[oidOff : oidOff+oidLen]
			attrContent = attrContent[oidOff+oidLen:]

			if len(attrContent) < 2 {
				return nil, fmt.Errorf("x509 name: no attribute value")
			}
			valTag := attrContent[0]
			valLen, valOff, err := parseDERLength(attrContent, 1)
			if err != nil {
				return nil, err
			}
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
func parseDERLength(data []byte, offset int) (length int, valueOffset int, err error) {
	if offset >= len(data) {
		return 0, 0, fmt.Errorf("x509 name: offset out of bounds")
	}
	b := int(data[offset])
	offset++
	if b&0x80 == 0 {
		return b, offset, nil
	}
	n := b & 0x7f
	if n == 0 || offset+n > len(data) {
		return 0, 0, fmt.Errorf("x509 name: invalid length encoding")
	}
	length = 0
	for i := 0; i < n; i++ {
		length = length<<8 | int(data[offset])
		offset++
	}
	return length, offset, nil
}

// asn1StringNeedsCanon returns true if the given ASN.1 tag is a string type
// that should be canonicalized per OpenSSL's ASN1_MASK_CANON.
// Note: NumericString (0x12) is NOT in the mask.
func asn1StringNeedsCanon(tag byte) bool {
	switch tag {
	case 0x0c, // UTF8String
		0x13, // PrintableString
		0x16, // IA5String
		0x14, // T61String
		0x1e, // BMPString
		0x1c, // UniversalString
		0x1a: // VisibleString
		return true
	}
	return false
}

// isASCIISpace returns true for ASCII whitespace characters that OpenSSL
// considers for stripping/collapsing (per ossl_isspace):
// TAB (0x09), LF (0x0a), VT (0x0b), FF (0x0c), CR (0x0d), SPACE (0x20).
func isASCIISpace(b byte) bool {
	return b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r' || b == ' '
}

// isASCIILetter returns true for ASCII uppercase letters A-Z.
func isASCIILetter(b byte) bool {
	return b >= 'A' && b <= 'Z'
}

// toASCIILower converts an ASCII uppercase letter to lowercase.
func toASCIILower(b byte) byte {
	if isASCIILetter(b) {
		return b + 32
	}
	return b
}

// convertASN1StringToUTF8 converts an ASN.1 string value to UTF-8 based on its tag.
// This implements the equivalent of ASN1_STRING_to_UTF8 for each supported type.
func convertASN1StringToUTF8(data []byte, tag byte) ([]byte, error) {
	switch tag {
	case 0x0c: // UTF8String
		return data, nil
	case 0x13: // PrintableString (ASCII printable: 0x20-0x7e)
		return data, nil
	case 0x16: // IA5String (ASCII)
		return data, nil
	case 0x1a: // VisibleString (ASCII visible characters)
		return data, nil
	case 0x14: // T61String (ISO 8859-1 / Latin-1)
		// ISO-8859-1 bytes 0x00-0x7F map directly to UTF-8
		// ISO-8859-1 bytes 0x80-0xFF need two-byte UTF-8 encoding
		result := make([]byte, 0, len(data))
		for _, b := range data {
			if b < 0x80 {
				result = append(result, b)
			} else {
				result = append(result, 0xc0|b>>6, 0x80|b&0x3f)
			}
		}
		return result, nil
	case 0x1e: // BMPString (UTF-16 BE)
		if len(data)%2 != 0 {
			return nil, fmt.Errorf("x509 name: BMPString has odd length")
		}
		result := make([]byte, 0, len(data))
		for i := 0; i < len(data); i += 2 {
			ch := uint16(data[i])<<8 | uint16(data[i+1])
			if ch >= 0xd800 && ch <= 0xdfff {
				return nil, fmt.Errorf("x509 name: BMPString contains surrogate code point U+%04X", ch)
			}
			if ch < 0x80 {
				result = append(result, byte(ch))
			} else if ch < 0x800 {
				result = append(result, 0xc0|byte(ch>>6), 0x80|byte(ch&0x3f))
			} else {
				result = append(result, 0xe0|byte(ch>>12), 0x80|byte(ch>>6&0x3f), 0x80|byte(ch&0x3f))
			}
		}
		return result, nil
	case 0x1c: // UniversalString (UTF-32 BE)
		if len(data)%4 != 0 {
			return nil, fmt.Errorf("x509 name: UniversalString has invalid length")
		}
		result := make([]byte, 0, len(data))
		for i := 0; i < len(data); i += 4 {
			ch := uint32(data[i])<<24 | uint32(data[i+1])<<16 | uint32(data[i+2])<<8 | uint32(data[i+3])
			if ch > 0x10ffff {
				return nil, fmt.Errorf("x509 name: UniversalString code point U+%04X exceeds U+10FFFF", ch)
			}
			if ch >= 0xd800 && ch <= 0xdfff {
				return nil, fmt.Errorf("x509 name: UniversalString contains surrogate code point U+%04X", ch)
			}
			if ch < 0x80 {
				result = append(result, byte(ch))
			} else if ch < 0x800 {
				result = append(result, 0xc0|byte(ch>>6), 0x80|byte(ch&0x3f))
			} else if ch < 0x10000 {
				result = append(result, 0xe0|byte(ch>>12), 0x80|byte(ch>>6&0x3f), 0x80|byte(ch&0x3f))
			} else {
				result = append(result, 0xf0|byte(ch>>18), 0x80|byte(ch>>12&0x3f), 0x80|byte(ch>>6&0x3f), 0x80|byte(ch&0x3f))
			}
		}
		return result, nil
	default:
		// For unknown types, return as-is
		return data, nil
	}
}

// canonicalizeASN1Value canonicalizes a string value per OpenSSL's
// asn1_string_canon: convert to UTF-8, strip leading/trailing ASCII whitespace,
// collapse internal ASCII whitespace runs, and lowercase ASCII letters only.
func canonicalizeASN1Value(data []byte, tag byte) ([]byte, error) {
	// Convert to UTF-8 first
	utf8Data, err := convertASN1StringToUTF8(data, tag)
	if err != nil {
		return nil, err
	}

	// Strip leading ASCII whitespace
	i := 0
	for i < len(utf8Data) && isASCIISpace(utf8Data[i]) {
		i++
	}
	utf8Data = utf8Data[i:]

	// Strip trailing ASCII whitespace
	j := len(utf8Data)
	for j > 0 && isASCIISpace(utf8Data[j-1]) {
		j--
	}
	utf8Data = utf8Data[:j]

	// Collapse internal ASCII whitespace runs and lowercase ASCII letters
	// Only ASCII whitespace (space, tab, LF, CR) is collapsed
	// Only ASCII letters (A-Z) are lowercased; non-ASCII bytes pass through unchanged
	var out []byte
	lastSpace := false
	for _, b := range utf8Data {
		if isASCIISpace(b) {
			if !lastSpace {
				out = append(out, ' ')
				lastSpace = true
			}
		} else {
			out = append(out, toASCIILower(b))
			lastSpace = false
		}
	}
	return out, nil
}

// encodeDERLength encodes a length in DER short or long form.
func encodeDERLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	// Long form: first byte indicates number of length bytes
	var lenBytes []byte
	tmp := length
	for tmp > 0 {
		lenBytes = append([]byte{byte(tmp)}, lenBytes...)
		tmp >>= 8
	}
	result := append([]byte{0x80 | byte(len(lenBytes))}, lenBytes...)
	return result
}

// buildCanonicalX509NameDER builds the canonical DER encoding of an X.509 name
// matching OpenSSL's x509_name_canon / i2d_name_canon. The outer SEQUENCE
// wrapper is omitted (OpenSSL's canon_enc excludes it for dirName comparison).
//
// For multi-valued RDNs (multiple attributes in a single SET), the attributes
// are sorted by their canonical DER encoding to match OpenSSL's SET OF semantics.
func buildCanonicalX509NameDER(rdns []x509NameRDN) ([]byte, error) {
	var buf []byte

	for _, rdn := range rdns {
		// Build canonical DER for each attribute first
		type attrDER struct {
			der []byte
		}
		var attrs []attrDER

		for _, attr := range rdn.attrs {
			var attrInner []byte
			// OID with proper DER length encoding
			attrInner = append(attrInner, 0x06)
			attrInner = append(attrInner, encodeDERLength(len(attr.oid))...)
			attrInner = append(attrInner, attr.oid...)

			if asn1StringNeedsCanon(attr.tag) {
				canon, err := canonicalizeASN1Value(attr.data, attr.tag)
				if err != nil {
					return nil, err
				}
				// UTF8String (0x0c) with proper DER length encoding
				attrInner = append(attrInner, 0x0c)
				attrInner = append(attrInner, encodeDERLength(len(canon))...)
				attrInner = append(attrInner, canon...)
			} else {
				// Keep original tag and value with proper DER length encoding
				attrInner = append(attrInner, attr.tag)
				attrInner = append(attrInner, encodeDERLength(len(attr.data))...)
				attrInner = append(attrInner, attr.data...)
			}

			// Attribute SEQUENCE with proper DER length encoding
			var seq []byte
			seq = append(seq, 0x30)
			seq = append(seq, encodeDERLength(len(attrInner))...)
			seq = append(seq, attrInner...)

			attrs = append(attrs, attrDER{der: seq})
		}

		// Sort attributes by their DER encoding for SET OF semantics
		// This matches OpenSSL's canonical ordering for multi-valued RDNs
		sort.Slice(attrs, func(i, j int) bool {
			return bytes.Compare(attrs[i].der, attrs[j].der) < 0
		})

		// Build the SET from sorted attributes
		var setInner []byte
		for _, a := range attrs {
			setInner = append(setInner, a.der...)
		}

		// RDN SET with proper DER length encoding
		buf = append(buf, 0x31)
		buf = append(buf, encodeDERLength(len(setInner))...)
		buf = append(buf, setInner...)
	}
	return buf, nil
}

// computeOpenSSLSubjectHash computes the OpenSSL-compatible subject-name hash for
// the given certificate. The algorithm matches `openssl x509 -hash -noout`
// (OpenSSL 3.x subject_hash):
//
// 1. Canonicalize the X.509 subject name:
//   - Convert all string types to UTF-8
//   - Strip leading/trailing ASCII whitespace
//   - Collapse internal ASCII whitespace runs to single space
//   - Lowercase ASCII letters only (A-Z), non-ASCII bytes pass through
//
// 2. DER-encode the canonical name WITHOUT outer SEQUENCE wrapper
// 3. SHA-1 hash of the canonical DER
// 4. First 4 bytes as little-endian 8-character lowercase hex
//
// Returns an error on parse/canonicalization failure.
func computeOpenSSLSubjectHash(cert *x509.Certificate) (string, error) {
	rdns, err := parseX509RawSubject(cert.RawSubject)
	if err != nil {
		return "", err
	}

	canon, err := buildCanonicalX509NameDER(rdns)
	if err != nil {
		return "", err
	}

	h := sha1.Sum(canon)
	return fmt.Sprintf("%08x", uint32(h[3])<<24|uint32(h[2])<<16|uint32(h[1])<<8|uint32(h[0])), nil
}

// trustedCASnapshotDir returns the path to the trusted CA snapshot directory
// for a given CA source file: $runtime_dir/trusted-ca/<sha256-of-source-bytes>/
func trustedCASnapshotDir(runtimeDir string, caData []byte) string {
	h := sha256.Sum256(caData)
	hexHash := hex.EncodeToString(h[:])
	return filepath.Join(runtimeDir, "trusted-ca", hexHash)
}

// prepareCAInjection validates the CA file, computes the OpenSSL subject hash,
// and materializes the CA in the helper-owned runtime directory:
//
//	$RUNTIME_DIR/trusted-ca/<sha256-of-source-bytes>/
//	    ├── ca.pem
//	    └── <subject-hash>.0 -> ca.pem
//
// Returns the prepared directory path, or an error if preparation fails.
// Idempotent: re-preparing the same CA is a no-op.
func prepareCAInjection(runtimeDir, caPath string) (preparedDir string, err error) {
	// Read and validate the source CA file once.
	caData, err := readValidatedCAFile(caPath)
	if err != nil {
		return "", err
	}

	return prepareCAFromData(runtimeDir, caData)
}

// prepareCAFromData computes the OpenSSL subject hash and materializes the CA in
// the helper-owned runtime directory using pre-read CA bytes. This function is
// the authoritative path for CA preparation and is also exposed for tests that
// need to verify snapshot consistency without filesystem races.
func prepareCAFromData(runtimeDir string, caData []byte) (preparedDir string, err error) {
	cert, err := validateCAPEM(caData)
	if err != nil {
		return "", err
	}

	// Compute the OpenSSL subject hash from the parsed certificate.
	subjectHash, err := computeOpenSSLSubjectHash(cert)
	if err != nil {
		return "", fmt.Errorf("cannot compute CA hash: %w", err)
	}

	// Determine the trusted CA snapshot directory.
	snapshotDir := trustedCASnapshotDir(runtimeDir, caData)
	caFile := filepath.Join(snapshotDir, "ca.pem")
	symlinkPath := filepath.Join(snapshotDir, subjectHash+".0")

	// If the directory already exists with the correct content, skip.
	if info, err := os.Stat(snapshotDir); err == nil && info.IsDir() {
		caInfo, statErr := os.Lstat(caFile)
		if statErr == nil && caInfo.Mode().IsRegular() {
			if existing, err := os.ReadFile(caFile); err == nil && bytes.Equal(existing, caData) {
				if target, err := os.Readlink(symlinkPath); err == nil && target == "ca.pem" {
					// Ensure modes are correct regardless of umask or external chmod.
					if err := os.Chmod(snapshotDir, 0755); err != nil {
						return "", fmt.Errorf("cannot set trusted CA directory permissions: %w", err)
					}
					if err := os.Chmod(caFile, 0644); err != nil {
						return "", fmt.Errorf("cannot set CA file permissions: %w", err)
					}
					// Relabel the trusted CA tree (handles upgrade/restart where
					// existing material may be mislabeled).
					trustedCABase := filepath.Join(runtimeDir, "trusted-ca")
					if err := restoreconTrustedCATree(trustedCABase); err != nil {
						return "", fmt.Errorf("trusted CA labeling failed: %w", err)
					}
					return snapshotDir, nil
				}
			}
		}
	}

	// Create the snapshot directory with mode 0755.
	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		return "", fmt.Errorf("cannot create trusted CA directory: %w", err)
	}
	// Explicitly set mode to guarantee 0755 regardless of process umask.
	if err := os.Chmod(snapshotDir, 0755); err != nil {
		return "", fmt.Errorf("cannot set trusted CA directory permissions: %w", err)
	}

	// Write ca.pem atomically with mode 0644.
	tmp, err := os.CreateTemp(snapshotDir, "ca-*.pem.tmp")
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

	// Create the OpenSSL subject hash symlink.
	// Remove existing entry if present (different subject hash or stale).
	if err := os.Remove(symlinkPath); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot remove existing CA hash entry: %w", err)
	}
	if err := os.Symlink("ca.pem", symlinkPath); err != nil {
		return "", fmt.Errorf("cannot create CA hash symlink: %w", err)
	}

	// Relabel the trusted CA tree to the dedicated type (required for the
	// container to read the CA material). The type_transition rules handle
	// future dynamic files within the labeled tree.
	trustedCABase := filepath.Join(runtimeDir, "trusted-ca")
	if err := restoreconTrustedCATree(trustedCABase); err != nil {
		return "", fmt.Errorf("trusted CA labeling failed: %w", err)
	}

	return snapshotDir, nil
}

// trustedCArestorecon runs restorecon over the trusted CA tree. It is a
// package-level variable so tests can capture the exact invocation without
// executing a real SELinux policy binary.
var trustedCArestorecon = func(args ...string) ([]byte, error) {
	cmd := exec.Command("/usr/sbin/restorecon", args...)
	return cmd.CombinedOutput()
}

// restoreconTrustedCATree relabels the trusted CA base directory tree to the
// dedicated docker_helper_trusted_ca_t type (from the file-context rule).
// Dynamically created runtime files do not inherit the CA type from the
// docker_helper_runtime_t parent, so an explicit restorecon is required after
// materialization. It is a no-op when SELinux is not active.
//
// -m disables restorecon's mount-table scan, so it only relabels the named
// base tree and does not descend into unrelated mounted filesystems.
func restoreconTrustedCATree(baseDir string) error {
	active, _, err := selinuxEnabled()
	if err != nil {
		return fmt.Errorf("cannot determine SELinux state for trusted CA restorecon: %w", err)
	}
	if !active {
		return nil
	}
	out, err := trustedCArestorecon("-R", "-m", baseDir)
	if err != nil {
		return fmt.Errorf("trusted CA restorecon failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
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
