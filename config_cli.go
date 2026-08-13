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
	writableFields = []string{
		"allowed_root",
		"session_ttl",
		"log_level",
		"audit_enabled",
		"shutdown_timeout",
		"operation_retention_ttl",
		"operation_max_completed",
		"operation_log_max_bytes",
		"trusted_ca_path",
		"trusted_ca_injection",
	}
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
		"shutdown_timeout",
		"operation_retention_ttl",
		"operation_max_completed",
		"operation_log_max_bytes",
		"trusted_ca_path",
		"trusted_ca_injection",
		"mode",
		"http_address",
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

// deprecatedFieldMessage returns the rename diagnostic for a deprecated field.
func deprecatedFieldMessage(name string) string {
	if newField, ok := deprecatedConfigFields[name]; ok {
		return fmt.Sprintf("error: %s was renamed to %s\n", name, newField)
	}
	return ""
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
// reading config.json (config_path, config_dir, admin_token_path, mode).
func isPureComputed(name string) bool {
	switch name {
	case "config_path", "config_dir", "admin_token_path", "mode":
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
  admin_token
  shutdown_timeout
  operation_retention_ttl
  operation_max_completed
  operation_log_max_bytes
  trusted_ca_path
  trusted_ca_injection
  mode
  http_address`,
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
  allowed_root            non-empty absolute path (required)
  session_ttl             positive Go duration, for example 30m or 12h (required)
  log_level               debug, info, warn, or error
  audit_enabled           true or false
  shutdown_timeout        positive Go duration, for example 30s (default 30s)
  operation_retention_ttl positive Go duration, for example 10m (default 10m)
  operation_max_completed positive integer (default 200)
  operation_log_max_bytes positive integer, bytes (default 4194304 = 4 MiB)
  trusted_ca_path         absolute path to a single PEM X.509 CA file (optional)
  trusted_ca_injection    "disabled" or "auto" (default "disabled")

Trusted CA injection:
  To enable, set trusted_ca_path first, then set trusted_ca_injection to auto.
  The host "openssl" binary must be available in PATH.
  CA injection only affects containers started via POST /run.

To disable, set trusted_ca_injection to disabled first, then optionally
unset trusted_ca_path.

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
  log_level               removing it restores the effective default info
  audit_enabled           removing it restores behavior derived from log_level
  shutdown_timeout        removing it restores the default 30s
  operation_retention_ttl removing it restores the default 10m
  operation_max_completed removing it restores the default 200
  operation_log_max_bytes removing it restores the default 4 MiB
  trusted_ca_path         removing it clears the CA file path
  trusted_ca_injection    removing it restores the default "disabled"

trusted_ca_path cannot be unset while trusted_ca_injection is "auto".
Set trusted_ca_injection to "disabled" first.

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
// It parses the top-level JSON object and returns the raw map and config path.
// Semantic validation (reserved fields, deprecated fields, value constraints)
// is performed by validateRawConfig, not by this function.
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

// persistRawConfig validates, encodes, and atomically writes the raw config.
func persistRawConfig(configPath string, raw map[string]json.RawMessage) error {
	if err := validateRawConfig(raw); err != nil {
		return err
	}
	if err := validateCAConfig(raw); err != nil {
		return err
	}
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode JSON: %w", err)
	}
	data = append(data, '\n')
	return safeWriteConfig(configPath, data)
}

func getRuntimeDirSafe() string {
	if resolveDeploymentMode() == ModeSystem {
		return "/run/docker-helper"
	}
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "docker-helper")
}

// adminAPIPaths returns the socket and admin token paths without reading
// config.json or creating directories. Used by CLI commands that only need
// to talk to the daemon or read the admin token.
func adminAPIPaths() (socketPath, adminTokenPath string, err error) {
	runtimeDir, err := getRuntimeDir()
	if err != nil {
		return "", "", err
	}
	socketPath = filepath.Join(runtimeDir, "docker-helper.sock")
	adminTokenPath = filepath.Join(getConfigDir(), "admin.token")
	return
}

// adminAPITokenSource returns a token source function that reads the admin
// token from the given path.
func adminAPITokenSource(tokenPath string) (func() (string, error), error) {
	token, err := readAdminTokenPlain(tokenPath)
	if err != nil {
		return nil, err
	}
	return func() (string, error) { return token, nil }, nil
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
		"allowed_root":            fc.AllowedRoot,
		"session_ttl":             fc.SessionTTL,
		"log_level":               levelStr,
		"audit_enabled":           auditEnabled,
		"audit_enabled_source":    auditSource,
		"config_path":             configPath,
		"config_dir":              configDir,
		"runtime_dir":             runtimeDir,
		"socket_path":             socketPath,
		"lock_path":               lockPath,
		"state_dir":               stateDir,
		"database_path":           databasePath,
		"admin_token_path":        adminTokenPath,
		"admin_token":             "<redacted>",
		"shutdown_timeout":        fc.ShutdownTimeout,
		"operation_retention_ttl": fc.OperationRetentionTTL,
		"operation_max_completed": fc.OperationMaxCompleted,
		"operation_log_max_bytes": fc.OperationLogMaxBytes,
		"trusted_ca_path":         fc.TrustedCAPath,
		"trusted_ca_injection":    resolveTrustedCAInjection(fc.TrustedCAInjection),
		"mode":                    resolveDeploymentMode(),
		"http_address":            resolveHTTPAddress(fc.HTTPAddress),
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

// resolveHTTPAddress returns the effective HTTP address.
// If the configured value is empty, returns the default for system mode or empty for user mode.
func resolveHTTPAddress(configured string) string {
	if configured != "" {
		return configured
	}
	if resolveDeploymentMode() == ModeSystem {
		return DefaultHTTPAddress
	}
	return ""
}

func configShowField(field string, stdout, stderr io.Writer) int {
	if msg := deprecatedFieldMessage(field); msg != "" {
		fmt.Fprint(stderr, msg)
		return 2
	}
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
		case "mode":
			fmt.Fprintln(stdout, resolveDeploymentMode())
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

	// http_address: resolve from config, with default.
	if field == "http_address" {
		fc, err := decodeFileConfig(raw)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, resolveHTTPAddress(fc.HTTPAddress))
		return 0
	}

	// Runtime-dependent fields: validate config first, then check XDG_RUNTIME_DIR.
	// In system mode, runtime dir is always available (/run/docker-helper).
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
	case "shutdown_timeout":
		st := fc.ShutdownTimeout
		if st == "" {
			st = "30s"
		}
		fmt.Fprintln(stdout, st)
	case "operation_retention_ttl":
		ort := fc.OperationRetentionTTL
		if ort == "" {
			ort = "10m"
		}
		fmt.Fprintln(stdout, ort)
	case "operation_max_completed":
		omc := fc.OperationMaxCompleted
		if omc == nil {
			omc = ptrOf(200)
		}
		fmt.Fprintln(stdout, *omc)
	case "operation_log_max_bytes":
		olmb := fc.OperationLogMaxBytes
		if olmb == nil {
			olmb = ptrOf(int64(4 * 1024 * 1024))
		}
		fmt.Fprintln(stdout, *olmb)
	case "trusted_ca_path":
		fmt.Fprintln(stdout, fc.TrustedCAPath)
	case "trusted_ca_injection":
		fmt.Fprintln(stdout, resolveTrustedCAInjection(fc.TrustedCAInjection))
	default:
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}
	return 0
}

func configSet(field, value string, stdout, stderr io.Writer) int {
	if msg := deprecatedFieldMessage(field); msg != "" {
		fmt.Fprint(stderr, msg)
		return 2
	}
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
	case "shutdown_timeout":
		if _, err := parseDurationPositive(value, "shutdown_timeout"); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	case "operation_retention_ttl":
		if _, err := parseDurationPositive(value, "operation_retention_ttl"); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	case "operation_max_completed":
		var n int
		if _, err := fmt.Sscanf(value, "%d", &n); err != nil || n <= 0 {
			fmt.Fprintf(stderr, "error: operation_max_completed must be a positive integer\n")
			return 2
		}
	case "operation_log_max_bytes":
		var n int64
		if _, err := fmt.Sscanf(value, "%d", &n); err != nil || n <= 0 {
			fmt.Fprintf(stderr, "error: operation_log_max_bytes must be a positive integer\n")
			return 2
		}
	case "trusted_ca_path":
		if value != "" && !filepath.IsAbs(value) {
			fmt.Fprintf(stderr, "error: trusted_ca_path must be an absolute path\n")
			return 2
		}
	case "trusted_ca_injection":
		if value != "disabled" && value != "auto" {
			fmt.Fprintf(stderr, "error: trusted_ca_injection must be \"disabled\" or \"auto\"\n")
			return 2
		}
	case "http_address":
		if resolveDeploymentMode() != ModeSystem {
			fmt.Fprintln(stderr, "error: http_address is only used in system mode")
			return 2
		}
		if err := validateHTTPAddress(value); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
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
	case "shutdown_timeout":
		newValue, _ = json.Marshal(value)
	case "operation_retention_ttl":
		newValue, _ = json.Marshal(value)
	case "operation_max_completed":
		var n int
		fmt.Sscanf(value, "%d", &n)
		newValue, _ = json.Marshal(n)
	case "operation_log_max_bytes":
		var n int64
		fmt.Sscanf(value, "%d", &n)
		newValue, _ = json.Marshal(n)
	case "trusted_ca_path":
		newValue, _ = json.Marshal(value)
	case "trusted_ca_injection":
		newValue, _ = json.Marshal(value)
	case "http_address":
		newValue, _ = json.Marshal(value)
	}

	// Compare with the existing explicit JSON member.
	if existing, ok := raw[field]; ok && bytes.Equal(existing, newValue) {
		// Validate the existing configuration before returning unchanged.
		if err := validateRawConfig(raw); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		if err := validateCAConfig(raw); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "unchanged %s=%s\n", field, value)
		return 0
	}

	raw[field] = newValue

	if err := persistRawConfig(configPath, raw); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "updated %s=%s\n", field, value)
	tryReloadConfig(stdout, stderr)
	return 0
}

func configUnset(field string, stdout, stderr io.Writer) int {
	if msg := deprecatedFieldMessage(field); msg != "" {
		fmt.Fprint(stderr, msg)
		return 2
	}
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
		if err := validateCAConfig(raw); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "unchanged %s is already unset\n", field)
		return 0
	}

	delete(raw, field)

	if err := persistRawConfig(configPath, raw); err != nil {
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
