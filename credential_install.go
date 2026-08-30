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

var (
	ErrCredentialTokenInvalid     = errors.New("invalid credential token format")
	ErrCredentialAlreadyExists    = errors.New("credential already installed")
	ErrCredentialInstallAsRoot    = errors.New("credential install must not be run as root")
	ErrCredentialDirectoryMissing = errors.New("credential directory cannot be created")
)

// credentialInstallConfig holds the injectable dependencies for installCredential.
type credentialInstallConfig struct {
	// reader provides the raw input for non-TTY token reading.
	reader io.Reader
	// writer performs the atomic file write.
	writer func(path string, data []byte) error
	// uid returns the effective UID of the process.
	uid func() int
	// isTerminal checks if stdin is a terminal.
	isTerminal func() bool
	// readPassword reads a hidden password from stdin (for TTY).
	readPassword func() (string, error)
	// force replaces an existing credential without error.
	force bool
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

// validateCredentialToken checks the Principal-credential token format defined
// by the canonical credential.go constants: dhc_ + 64 lowercase hex chars.
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

// credentialState represents the result of checking an existing credential file.
type credentialState int

const (
	// credentialAbsent means no credential file exists.
	credentialAbsent credentialState = iota
	// credentialMatch means the existing credential matches the given token.
	credentialMatch
	// credentialConflict means a different credential is already installed.
	credentialConflict
)

// checkCredentialState checks the credential file against the given token.
// Returns (credentialAbsent, nil) when the file does not exist (ENOENT).
// Returns (credentialMatch, nil) when the file exists and contains the same token.
// Returns (credentialConflict, nil) when the file exists with a different token.
// Returns (0, error) for credentialPath resolution failures or I/O errors
// other than ENOENT (fail closed).
func checkCredentialState(token string) (credentialState, error) {
	credPath, err := credentialPath()
	if err != nil {
		return 0, fmt.Errorf("cannot determine credential path: %w", err)
	}
	existing, err := os.ReadFile(credPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return credentialAbsent, nil
		}
		return 0, fmt.Errorf("cannot read credential file: %w", err)
	}
	if strings.TrimSpace(string(existing)) == token {
		return credentialMatch, nil
	}
	return credentialConflict, nil
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

// installCredential performs the full credential installation flow.
// Rejects root, checks --force for an existing credential, reads token
// (hidden on TTY, stdin otherwise), validates, and writes atomically.
// Returns the credential path on success.
//
// The existing-credential conflict is detected and rejected BEFORE any token
// input is read, so stdin/token-file input remains untouched when the
// operation is going to be rejected anyway.
func installCredential(cfg credentialInstallConfig) (string, error) {
	if cfg.uid() == 0 {
		return "", ErrCredentialInstallAsRoot
	}

	credPath, err := credentialPath()
	if err != nil {
		return "", err
	}

	if !cfg.force {
		if info, err := os.Stat(credPath); err == nil && !info.IsDir() {
			return "", fmt.Errorf("credential already exists: use --force to replace: %w", ErrCredentialAlreadyExists)
		}
	}

	var token string
	if cfg.isTerminal() {
		var err error
		token, err = cfg.readPassword()
		if err != nil {
			return "", err
		}
	} else {
		var err error
		token, err = readTokenFromReader(cfg.reader)
		if err != nil {
			return "", err
		}
	}

	if err := validateCredentialToken(token); err != nil {
		return "", err
	}

	dir := filepath.Dir(credPath)
	if err := ensureCredentialDir(dir); err != nil {
		return "", err
	}

	data := append([]byte(token), '\n')
	if err := cfg.writer(credPath, data); err != nil {
		return "", err
	}

	return credPath, nil
}

// ensureCredentialDir creates the credential directory with mode 0700.
// If the directory already exists, it verifies and fixes the mode to 0700.
func ensureCredentialDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create credential directory: %w", ErrCredentialDirectoryMissing)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0700 {
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("cannot set credential directory permissions: %w", err)
		}
	}
	return nil
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
