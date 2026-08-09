package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var configCommand = &Command{
	Name:    "config",
	Summary: "Inspect and modify configuration",
	Subcommands: []*Command{
		configShowCommand,
		configSetCommand,
		configUnsetCommand,
	},
}

var (
	writableFields = []string{"allowed_root", "session_ttl", "log_level", "audit_enabled"}
	requiredFields = map[string]bool{"allowed_root": true, "session_ttl": true}
	allFields      = []string{
		"allowed_root",
		"session_ttl",
		"log_level",
		"audit_enabled",
		"audit_enabled_source",
		"config_path",
		"config_dir",
		"runtime_dir",
		"socket_path",
		"lock_path",
		"state_dir",
		"database_path",
		"admin_token_path",
		"admin_token",
	}
)

func isKnownField(name string) bool {
	for _, f := range allFields {
		if f == name {
			return true
		}
	}
	return false
}

func isRuntimeDependent(name string) bool {
	switch name {
	case "runtime_dir", "socket_path", "lock_path":
		return true
	default:
		return false
	}
}

// isPureComputed returns true for fields that can be resolved without
// reading config.json (config_path, config_dir, admin_token_path).
func isPureComputed(name string) bool {
	switch name {
	case "config_path", "config_dir", "admin_token_path":
		return true
	default:
		return false
	}
}

var configShowCommand = &Command{
	Name:       "show",
	Summary:    "Show configuration values",
	Usage:      "docker-helper config show [FIELD]",
	MinPosArgs: 0,
	MaxPosArgs: 1,
	Help: `Without FIELD, prints the complete effective configuration as JSON.
With FIELD, prints only that field's scalar value followed by a newline.

The general JSON output redacts admin_token.
"config show admin_token" intentionally prints the complete real token.

Fields:
  allowed_root
  session_ttl
  log_level
  audit_enabled
  audit_enabled_source
  config_path
  config_dir
  runtime_dir
  socket_path
  lock_path
  state_dir
  database_path
  admin_token_path
  admin_token`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				if len(args) == 0 {
					return configShowAll(stdout, stderr)
				}
				return configShowField(args[0], stdout, stderr)
			},
		}
	},
}

var configSetCommand = &Command{
	Name:       "set",
	Summary:    "Set a configuration value",
	Usage:      "docker-helper config set FIELD VALUE",
	MinPosArgs: 2,
	MaxPosArgs: 2,
	Help: `Writable fields:
  allowed_root    non-empty absolute path (required)
  session_ttl     positive Go duration, for example 30m or 12h (required)
  log_level       debug, info, warn, or error
  audit_enabled   true or false

A successful command reports either "updated" or "unchanged".
If the daemon is running, the change is applied immediately.
If the daemon is not running, the change is written to disk and
will apply on the next start.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				return configSet(args[0], args[1], stdout, stderr)
			},
		}
	},
}

var configUnsetCommand = &Command{
	Name:       "unset",
	Summary:    "Unset a configuration value",
	Usage:      "docker-helper config unset FIELD",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	Help: `Unsettable fields:
  log_level       removing it restores the effective default info
  audit_enabled   removing it restores behavior derived from log_level

A successful command reports either "unset" or "unchanged".
If the daemon is running, the change is applied immediately.
If the daemon is not running, the change is written to disk and
will apply on the next start.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				return configUnset(args[0], stdout, stderr)
			},
		}
	},
}

// loadRawConfig reads config.json from disk as a raw JSON map.
// It requires a top-level JSON object and rejects reserved/read-only fields.
// Returns the raw map, the config file path, and any error.
func loadRawConfig() (map[string]json.RawMessage, string, error) {
	configPath := getConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, "", err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, "", err
	}
	if raw == nil {
		return nil, "", fmt.Errorf("configuration is not a JSON object")
	}

	// Reject reserved fields that must not appear in config.json.
	for field := range raw {
		if reservedConfigFields[field] {
			return nil, "", fmt.Errorf("%s is computed and cannot be configured", field)
		}
	}

	return raw, configPath, nil
}

// decodeFileConfig decodes a raw config map into a fileConfig struct.
// It does not perform disk I/O.
func decodeFileConfig(raw map[string]json.RawMessage) (*fileConfig, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var fc fileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, err
	}
	return &fc, nil
}

// validateRawConfig validates the known fields in a raw config map.
// It does not require XDG_RUNTIME_DIR and does not create directories.
// Returns an error if the document is malformed or known fields are invalid.
func validateRawConfig(raw map[string]json.RawMessage) error {
	if raw == nil {
		return fmt.Errorf("configuration is not a JSON object")
	}

	// Validate allowed_root: must exist as a non-empty absolute string.
	if v, ok := raw["allowed_root"]; ok {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return fmt.Errorf("allowed_root must be a JSON string")
		}
		if err := validateAllowedRootValue(s); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("allowed_root is required")
	}

	// Validate session_ttl: must exist as a valid positive duration string.
	if v, ok := raw["session_ttl"]; ok {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return fmt.Errorf("session_ttl must be a JSON string")
		}
		if _, err := parseSessionTTL(s); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("session_ttl is required")
	}

	// Validate log_level if present: must be a valid level string.
	if v, ok := raw["log_level"]; ok {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return fmt.Errorf("log_level must be a JSON string")
		}
		if _, err := parseLogLevel(s); err != nil {
			return fmt.Errorf("invalid log_level %q: must be one of debug, info, warn, error", s)
		}
	}

	// Validate audit_enabled if present: must be a JSON boolean.
	if v, ok := raw["audit_enabled"]; ok {
		var b bool
		if err := json.Unmarshal(v, &b); err != nil {
			return fmt.Errorf("audit_enabled must be a JSON boolean")
		}
		_ = b
	}

	return nil
}

func safeWriteConfig(configPath string, data []byte) error {
	dir := filepath.Dir(configPath)
	tmp, err := os.CreateTemp(dir, "config-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, configPath); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

func getRuntimeDirSafe() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "docker-helper")
}

func configShowAll(stdout, stderr io.Writer) int {
	raw, configPath, err := loadRawConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := validateRawConfig(raw); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fc, err := decodeFileConfig(raw)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	configDir := filepath.Dir(configPath)
	runtimeDir := getRuntimeDirSafe()
	stateDir := getStateDir()
	socketPath := ""
	lockPath := ""
	if runtimeDir != "" {
		socketPath = filepath.Join(runtimeDir, "docker-helper.sock")
		lockPath = socketPath + ".lock"
	}
	databasePath := filepath.Join(stateDir, "docker-helper.db")
	adminTokenPath := filepath.Join(configDir, "admin.token")

	levelStr := fc.Level
	if levelStr == "" {
		levelStr = "info"
	}

	slogLevel, _ := parseLogLevel(levelStr)
	auditEnabled := resolveAuditEnabled(fc.AuditEnabled, slogLevel)
	auditSource := "log_level"
	if fc.AuditEnabled != nil {
		auditSource = "explicit"
	}

	result := map[string]any{
		"allowed_root":         fc.AllowedRoot,
		"session_ttl":          fc.SessionTTL,
		"log_level":            levelStr,
		"audit_enabled":        auditEnabled,
		"audit_enabled_source": auditSource,
		"config_path":          configPath,
		"config_dir":           configDir,
		"runtime_dir":          runtimeDir,
		"socket_path":          socketPath,
		"lock_path":            lockPath,
		"state_dir":            stateDir,
		"database_path":        databasePath,
		"admin_token_path":     adminTokenPath,
		"admin_token":          "<redacted>",
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(stderr, "error: cannot encode JSON: %v\n", err)
		return 1
	}
	return 0
}

func configShowField(field string, stdout, stderr io.Writer) int {
	if !isKnownField(field) {
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}

	// Bootstrap fields: never parse config.json.
	// admin_token reads only the token file.
	if field == "admin_token" {
		configPath := getConfigPath()
		configDir := filepath.Dir(configPath)
		adminTokenPath := filepath.Join(configDir, "admin.token")
		data, err := os.ReadFile(adminTokenPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			fmt.Fprintf(stderr, "error: admin token file is empty\n")
			return 1
		}
		fmt.Fprintln(stdout, token)
		return 0
	}

	// Pure computed fields: resolve from paths without reading config.json.
	if isPureComputed(field) {
		configPath := getConfigPath()
		configDir := filepath.Dir(configPath)
		switch field {
		case "config_path":
			fmt.Fprintln(stdout, configPath)
		case "config_dir":
			fmt.Fprintln(stdout, configDir)
		case "admin_token_path":
			fmt.Fprintln(stdout, filepath.Join(configDir, "admin.token"))
		}
		return 0
	}

	// All other fields: single read of config.json.
	raw, _, err := loadRawConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := validateRawConfig(raw); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Runtime-dependent fields: validate config first, then check XDG_RUNTIME_DIR.
	if isRuntimeDependent(field) {
		runtimeDir := getRuntimeDirSafe()
		if runtimeDir == "" {
			fmt.Fprintf(stderr, "error: XDG_RUNTIME_DIR is not set, cannot determine %s\n", field)
			return 1
		}
		switch field {
		case "runtime_dir":
			fmt.Fprintln(stdout, runtimeDir)
		case "socket_path":
			fmt.Fprintln(stdout, filepath.Join(runtimeDir, "docker-helper.sock"))
		case "lock_path":
			fmt.Fprintln(stdout, filepath.Join(runtimeDir, "docker-helper.sock.lock"))
		}
		return 0
	}

	// Config-backed fields: decode from raw (already validated above).
	fc, err := decodeFileConfig(raw)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	stateDir := getStateDir()

	switch field {
	case "allowed_root":
		fmt.Fprintln(stdout, fc.AllowedRoot)
	case "session_ttl":
		fmt.Fprintln(stdout, fc.SessionTTL)
	case "log_level":
		level := fc.Level
		if level == "" {
			level = "info"
		}
		fmt.Fprintln(stdout, level)
	case "audit_enabled":
		levelStr := fc.Level
		if levelStr == "" {
			levelStr = "info"
		}
		slogLevel, _ := parseLogLevel(levelStr)
		auditEnabled := resolveAuditEnabled(fc.AuditEnabled, slogLevel)
		fmt.Fprintln(stdout, auditEnabled)
	case "audit_enabled_source":
		if fc.AuditEnabled != nil {
			fmt.Fprintln(stdout, "explicit")
		} else {
			fmt.Fprintln(stdout, "log_level")
		}
	case "state_dir":
		fmt.Fprintln(stdout, stateDir)
	case "database_path":
		fmt.Fprintln(stdout, filepath.Join(stateDir, "docker-helper.db"))
	default:
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}
	return 0
}

func configSet(field, value string, stdout, stderr io.Writer) int {
	if !isKnownField(field) {
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}
	if reservedConfigFields[field] {
		fmt.Fprintf(stderr, "error: field %q is read-only\n", field)
		return 2
	}

	switch field {
	case "allowed_root":
		if value == "" || !filepath.IsAbs(value) {
			fmt.Fprintf(stderr, "error: allowed_root must be a non-empty absolute path\n")
			return 2
		}
	case "session_ttl":
		if _, err := time.ParseDuration(value); err != nil {
			fmt.Fprintf(stderr, "error: invalid duration %q: %v\n", value, err)
			return 2
		}
		if d, _ := time.ParseDuration(value); d <= 0 {
			fmt.Fprintf(stderr, "error: session_ttl must be a positive duration\n")
			return 2
		}
	case "log_level":
		if _, err := parseLogLevel(value); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	case "audit_enabled":
		if value != "true" && value != "false" {
			fmt.Fprintf(stderr, "error: audit_enabled must be true or false\n")
			return 2
		}
	}

	raw, configPath, err := loadRawConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Compute the JSON-encoded value for the field.
	var newValue json.RawMessage
	switch field {
	case "allowed_root":
		newValue, _ = json.Marshal(value)
	case "session_ttl":
		newValue, _ = json.Marshal(value)
	case "log_level":
		newValue, _ = json.Marshal(value)
	case "audit_enabled":
		newValue, _ = json.Marshal(value == "true")
	}

	// Compare with the existing explicit JSON member.
	if existing, ok := raw[field]; ok && bytes.Equal(existing, newValue) {
		// Validate the existing configuration before returning unchanged.
		if err := validateRawConfig(raw); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "unchanged %s=%s\n", field, value)
		return 0
	}

	raw[field] = newValue

	// Validate the complete resulting configuration before writing.
	if err := validateRawConfig(raw); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot encode JSON: %v\n", err)
		return 1
	}
	data = append(data, '\n')

	if err := safeWriteConfig(configPath, data); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "updated %s=%s\n", field, value)
	tryReloadConfig(stdout, stderr)
	return 0
}

func configUnset(field string, stdout, stderr io.Writer) int {
	if !isKnownField(field) {
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}
	if reservedConfigFields[field] {
		fmt.Fprintf(stderr, "error: field %q is read-only\n", field)
		return 2
	}
	if requiredFields[field] {
		fmt.Fprintf(stderr, "error: field %q is required and cannot be unset\n", field)
		return 2
	}

	raw, configPath, err := loadRawConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Check if the member is already absent.
	if _, ok := raw[field]; !ok {
		// Validate the existing configuration before returning unchanged.
		if err := validateRawConfig(raw); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "unchanged %s is already unset\n", field)
		return 0
	}

	delete(raw, field)

	// Validate the complete resulting configuration before writing.
	if err := validateRawConfig(raw); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot encode JSON: %v\n", err)
		return 1
	}
	data = append(data, '\n')

	if err := safeWriteConfig(configPath, data); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "unset", field)
	tryReloadConfig(stdout, stderr)
	return 0
}

// tryReloadConfig attempts to reload the running daemon's configuration.
// It is called after a successful config set/unset.
// If the daemon is not running, the operation is still considered successful.
// If the daemon is running but reload fails (e.g., invalid config), the error
// is printed but the config change is not rolled back.
func tryReloadConfig(stdout, stderr io.Writer) {
	// Use safe path resolution without creating directories.
	configPath := getConfigPath()
	configDir := filepath.Dir(configPath)
	adminTokenPath := filepath.Join(configDir, "admin.token")

	tokenData, err := os.ReadFile(adminTokenPath)
	if err != nil {
		// Cannot read token - assume daemon not running
		fmt.Fprintln(stdout, "daemon not running; change will apply on next start")
		return
	}
	token := strings.TrimSpace(string(tokenData))
	if token == "" {
		// Empty token - assume daemon not running
		fmt.Fprintln(stdout, "daemon not running; change will apply on next start")
		return
	}

	runtimeDir := getRuntimeDirSafe()
	if runtimeDir == "" {
		// No runtime dir - assume daemon not running
		fmt.Fprintln(stdout, "daemon not running; change will apply on next start")
		return
	}
	socketPath := filepath.Join(runtimeDir, "docker-helper.sock")

	client := newReloadClient(socketPath, func() (string, error) {
		return token, nil
	})
	if err := client.reload(); err != nil {
		// Check if the error is due to the daemon not running.
		if isDaemonNotRunning(err) {
			fmt.Fprintln(stdout, "daemon not running; change will apply on next start")
		} else {
			// Real reload error - print warning
			fmt.Fprintf(stderr, "warning: reload failed: %v\n", err)
		}
	}
}

// isDaemonNotRunning returns true if the error indicates the daemon
// is not listening on the socket.
func isDaemonNotRunning(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "no such file or directory")
}
