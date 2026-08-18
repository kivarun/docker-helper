package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
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
	// reader provides the raw input (stdin for non-TTY).
	reader io.Reader
	// writer performs the atomic file write.
	writer func(path string, data []byte) error
	// uid returns the effective UID of the process.
	uid func() int
	// isTerminal checks if stdin is a terminal.
	isTerminal func() bool
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

// readTokenHidden reads a token from the terminal with hidden input.
// Uses golang.org/x/term to disable echo.
func readTokenHidden(prompt string, stderr io.Writer) (string, error) {
	fmt.Fprint(stderr, prompt)
	byteToken, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("error reading token: %w", err)
	}
	token := strings.TrimSpace(string(byteToken))
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
	var token string
	if cfg.isTerminal() {
		// TTY: use hidden input.
		return "", fmt.Errorf("TTY input requires stderr writer: use installCredentialWithIO")
	}
	// Non-TTY: read from stdin.
	var err error
	token, err = readTokenFromReader(cfg.reader)
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

// installCredentialWithIO is the full install flow with TTY support.
// It handles root check, token input (hidden for TTY), validation,
// --force check, and atomic write.
func installCredentialWithIO(force bool, stderr io.Writer) (string, error) {
	// Reject root.
	if EffectiveUID() == 0 {
		return "", ErrCredentialInstallAsRoot
	}

	// Read token.
	var token string
	if isStdinTTY() {
		// TTY: use hidden input.
		var err error
		token, err = readTokenHidden("Credential token: ", stderr)
		if err != nil {
			return "", err
		}
	} else {
		// Non-TTY: read from stdin.
		var err error
		token, err = readTokenFromReader(os.Stdin)
		if err != nil {
			return "", err
		}
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
		if !info.IsDir() && !force {
			return "", fmt.Errorf("credential already exists: use --force to replace: %w", ErrCredentialAlreadyExists)
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
	if err := safeWriteCredential(credPath, data); err != nil {
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
