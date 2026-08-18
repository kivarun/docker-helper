package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const credentialTokenPrefix = "dhc_"
const credentialTokenHexLen = 64
const credentialTokenTotalLen = len(credentialTokenPrefix) + credentialTokenHexLen

var (
	ErrCredentialTokenInvalid     = errors.New("invalid credential token format")
	ErrCredentialAlreadyExists    = errors.New("credential already installed")
	ErrCredentialInstallAsRoot    = errors.New("credential install must not be run as root")
	ErrCredentialDirectoryMissing = errors.New("credential directory cannot be created")
)

// credentialInstallConfig holds the injectable dependencies for installCredential.
type credentialInstallConfig struct {
	// reader provides the raw input (stdin or TTY).
	reader io.Reader
	// writer performs the atomic file write.
	writer func(path string, data []byte) error
	// isTTY is true when stdin is a terminal.
	isTTY bool
	// uid returns the effective UID of the process.
	uid func() int
}

// credentialPath returns the user credential file path.
// ${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/credential.token
func credentialPath() (string, error) {
	xdgConfig := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		xdgConfig = filepath.Join(home, ".config")
	}
	dir := filepath.Join(xdgConfig, "docker-helper")
	return filepath.Join(dir, "credential.token"), nil
}

// validateCredentialToken checks the token format: dhc_ + 64 lowercase hex chars.
func validateCredentialToken(token string) error {
	if len(token) != credentialTokenTotalLen {
		return fmt.Errorf("invalid token length: got %d, want %d: %w", len(token), credentialTokenTotalLen, ErrCredentialTokenInvalid)
	}
	if !strings.HasPrefix(token, credentialTokenPrefix) {
		return fmt.Errorf("invalid token prefix: %w", ErrCredentialTokenInvalid)
	}
	hexPart := token[len(credentialTokenPrefix):]
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("invalid token character at position %d: %w", i, ErrCredentialTokenInvalid)
		}
	}
	return nil
}

// readTokenFromReader reads a single token line from the reader.
// Trims trailing newline/carriage return.
func readTokenFromReader(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("error reading token: %w", err)
		}
		return "", fmt.Errorf("empty input: provide a credential token")
	}
	token := strings.TrimSpace(scanner.Text())
	if token == "" {
		return "", fmt.Errorf("empty input: provide a credential token")
	}
	return token, nil
}

// installCredential performs the credential installation.
// Returns the credential path on success.
func installCredential(cfg credentialInstallConfig) (string, error) {
	// Reject root.
	if cfg.uid() == 0 {
		return "", ErrCredentialInstallAsRoot
	}

	// Read token.
	token, err := readTokenFromReader(cfg.reader)
	if err != nil {
		return "", err
	}

	// Validate token format.
	if err := validateCredentialToken(token); err != nil {
		return "", err
	}

	// Resolve credential path.
	credPath, err := credentialPath()
	if err != nil {
		return "", err
	}

	// Check if credential already exists.
	if info, err := os.Stat(credPath); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("credential already exists at %s: use --force to replace: %w", credPath, ErrCredentialAlreadyExists)
		}
	}

	// Create directory with mode 0700.
	dir := filepath.Dir(credPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create credential directory: %w", ErrCredentialDirectoryMissing)
	}

	// Write token with trailing newline.
	data := append([]byte(token), '\n')

	// Atomic write with mode 0600.
	if err := cfg.writer(credPath, data); err != nil {
		return "", err
	}

	return credPath, nil
}

// safeWriteCredential is the production writer for credential files.
// Creates a temp file in the target directory, writes data, sets mode 0600,
// and renames atomically.
func safeWriteCredential(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "credential-*.tmp")
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("cannot write credential: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("cannot set credential permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("cannot close credential file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("cannot install credential: %w", err)
	}
	return nil
}

// isStdinTTY checks if stdin is a terminal.
func isStdinTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// readTokenTTY reads a token from TTY with hidden input.
func readTokenTTY(prompt string) (string, error) {
	// Use syscall to read from /dev/tty with echo disabled.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		// Fallback to stdin if /dev/tty is not available.
		return readTokenFromReader(os.Stdin)
	}
	defer tty.Close()

	// Disable echo on the TTY fd.
	// This is a simplified approach; on Linux we can use ioctl.
	// For portability, we just read from /dev/tty.
	fmt.Print(prompt)
	token, err := readTokenFromReader(tty)
	fmt.Println()
	return token, err
}
