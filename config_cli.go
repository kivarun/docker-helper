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
	"syscall"
	"time"
)

// configOp identifies the type of config mutation.
type configOp int

const (
	configOpSet   configOp = iota // config set FIELD VALUE
	configOpUnset                 // config unset FIELD
)

// configMutationResult is returned by a mutation callback to control
// the shared transaction's write/reload behavior.
type configMutationResult struct {
	SkipWrite   bool   // true: skip write/reload, print message and return
	Message     string // success message to print (may be empty if SkipWrite)
	StartupOnly bool   // true: skip reload, print "restart required" after message
}

// configMutation is a callback that modifies the raw config under the lock.
// The raw map has already been validated and legacy-migrated by the shared layer.
// migrated is true if the shared layer performed a legacy allowed_root migration.
//
// Return values:
//   - configMutationResult: controls write/skip and success message
//   - error: non-nil aborts the transaction (printed to stderr, exit 1)
//     use configUserError to return a user-facing error with exit code 2.
type configMutation func(raw map[string]json.RawMessage, migrated bool) (configMutationResult, error)

// configUserError wraps a user-facing error that should produce exit code 2
// rather than the default exit code 1 for internal/transaction errors.
type configUserError struct {
	msg string
}

func (e configUserError) Error() string { return e.msg }

// isConfigUserError returns true if err is a configUserError.
func isConfigUserError(err error) bool {
	_, ok := err.(configUserError)
	return ok
}

// configWriter abstracts the atomic file write so tests can inject
// failure scenarios (e.g., rollback write failure).
type configWriter func(path string, data []byte) error

var configCommand = &Command{
	Name:    "config",
	Summary: "Inspect and modify configuration",
	Subcommands: []*Command{
		configShowCommand,
		configSetCommand,
		configUnsetCommand,
		configAllowedRootCommand,
	},
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

// isPureComputed returns true for fields that can be requested without
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
  allowed_roots
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
  session_ttl             positive Go duration, for example 30m or 12h (required)
  log_level               debug, info, warn, or error
  audit_enabled           true or false
  shutdown_timeout        positive Go duration, for example 30s (default 30s)
  operation_retention_ttl positive Go duration, for example 10m (default 10m)
  operation_max_completed positive integer (default 200)
  operation_log_max_bytes positive integer, bytes (default 4194304 = 4 MiB)
  trusted_ca_path         absolute path to a single PEM X.509 CA file (optional)
  trusted_ca_injection    "disabled" or "auto" (default "disabled")
  http_address            127.0.0.1:PORT, system mode only, restart required

Allowed roots:
  Use "docker-helper config allowed-root add/remove/list" to manage global roots.
  "config set allowed_root" is no longer supported; use the structured commands.

Trusted CA injection:
  To enable, set trusted_ca_path first, then set trusted_ca_injection to auto.
  CA injection only affects containers started via POST /run.

To disable, set trusted_ca_injection to disabled first, then optionally
unset trusted_ca_path.

http_address is startup-only: the change is written to disk and
requires a daemon restart to take effect.

A successful command reports either "updated" or "unchanged".
If the daemon is running, the change is applied immediately,
except for startup-only fields such as http_address.
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
  http_address            removing it restores the default 127.0.0.1:52375

trusted_ca_path cannot be unset while trusted_ca_injection is "auto".
Set trusted_ca_injection to "disabled" first.

http_address is startup-only: unsetting it requires a daemon restart
to take effect. The default 127.0.0.1:52375 is restored after restart.

A successful command reports either "unset" or "unchanged".
If the daemon is running, the change is applied immediately,
except for startup-only fields such as http_address.
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

// configAllowedRootCommand manages the global allowed_roots array.
var configAllowedRootCommand = &Command{
	Name:    "allowed-root",
	Summary: "Manage global allowed roots",
	Help: `Manage the global allowed_roots array.

The global allowed_roots is the coarse authorization ceiling for new
sessions. Every new session workspace must be under at least one allowed
root. Principal allowed roots further narrow the ceiling per principal.

Changing allowed_roots never prepares MAC state.
In system mode, MAC coverage for a concrete workspace is handled by the
session lifecycle at session creation. In user mode, no MAC preparation
is required.

remove does not invalidate already-issued sessions.`,
	Subcommands: []*Command{
		configAllowedRootListCommand,
		configAllowedRootAddCommand,
		configAllowedRootRemoveCommand,
	},
}

var configAllowedRootListCommand = &Command{
	Name:       "list",
	Summary:    "List all allowed roots",
	Usage:      "docker-helper config allowed-root list",
	MinPosArgs: 0,
	MaxPosArgs: 0,
	Help:       `List all allowed roots, one canonical root per line.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return configAllowedRootList(stdout, stderr)
			},
		}
	},
}

var configAllowedRootAddCommand = &Command{
	Name:       "add",
	Summary:    "Add an allowed root",
	Usage:      "docker-helper config allowed-root add PATH",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	Help: `Add an allowed root.

Canonicalizes and validates the path. Idempotent (prints "already present"
if the root exists). Preserves existing roots.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				return configAllowedRootAdd(args[0], stdout, stderr)
			},
		}
	},
}

var configAllowedRootRemoveCommand = &Command{
	Name:       "remove",
	Summary:    "Remove an allowed root",
	Usage:      "docker-helper config allowed-root remove PATH",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	Help: `Remove an allowed root.

Resolves/matches the stored canonical form. Idempotent (prints "not found"
if the root does not exist). Rejects removal of the final global root.
Does not invalidate already-issued sessions.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				return configAllowedRootRemove(args[0], stdout, stderr)
			},
		}
	},
}

// configAllowedRootList prints all allowed roots, one per line.
func configAllowedRootList(stdout, stderr io.Writer) int {
	raw, _, err := loadRawConfig()
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
	// Use canonical resolved roots (same as loadConfig).
	requestedRoots, err := resolveAllowedRoots(raw, fc)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	for _, r := range requestedRoots {
		fmt.Fprintln(stdout, r)
	}
	return 0
}

// configAllowedRootAdd adds a root to allowed_roots.
// MAC preparation is now handled at session creation time, not at config time.
func configAllowedRootAdd(path string, stdout, stderr io.Writer) int {
	if path == "" {
		fmt.Fprintln(stderr, "error: path is required")
		return 2
	}
	if !filepath.IsAbs(path) {
		fmt.Fprintln(stderr, "error: path must be absolute")
		return 2
	}

	canonical, err := canonicalizePathForAdd(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	return addAllowedRootToConfig(canonical, stdout, stderr)
}

// configAllowedRootRemove removes a root from allowed_roots.
func configAllowedRootRemove(path string, stdout, stderr io.Writer) int {
	if path == "" {
		fmt.Fprintln(stderr, "error: path is required")
		return 2
	}
	if !filepath.IsAbs(path) {
		fmt.Fprintln(stderr, "error: path must be absolute")
		return 2
	}

	// Resolve the requested removal path identity.
	requestedAbs, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot resolve path: %v\n", err)
		return 2
	}
	requestedIdentity, err := filepath.EvalSymlinks(requestedAbs)
	if err != nil {
		if os.IsNotExist(err) {
			requestedIdentity = filepath.Clean(requestedAbs)
		} else {
			fmt.Fprintf(stderr, "error: cannot resolve path: %v\n", err)
			return 2
		}
	}

	return executeConfigTransaction(stdout, stderr, safeWriteConfig, func(raw map[string]json.RawMessage, migrated bool) (configMutationResult, error) {
		fc, err := decodeFileConfig(raw)
		if err != nil {
			return configMutationResult{}, err
		}
		storedRoots := fc.AllowedRoots
		if len(storedRoots) == 0 {
			return configMutationResult{}, fmt.Errorf("allowed_roots must contain at least one entry")
		}

		// Build removable roots with identity resolution.
		roots := make([]removableRoot, 0, len(storedRoots))
		for _, r := range storedRoots {
			if r == "" || !filepath.IsAbs(r) {
				return configMutationResult{}, fmt.Errorf("invalid stored root %q", r)
			}
			abs, err := filepath.Abs(r)
			if err != nil {
				return configMutationResult{}, fmt.Errorf("cannot resolve stored root %q: %w", r, err)
			}
			identity, err := filepath.EvalSymlinks(abs)
			if err != nil {
				if os.IsNotExist(err) {
					identity = filepath.Clean(abs)
				} else {
					return configMutationResult{}, fmt.Errorf("cannot resolve stored root %q: %w", r, err)
				}
			}
			roots = append(roots, removableRoot{Stored: r, Identity: identity})
		}

		// Find and remove the root (match by identity).
		found := false
		newStored := make([]string, 0, len(roots))
		for _, rr := range roots {
			if rr.Identity == requestedIdentity {
				found = true
				continue
			}
			newStored = append(newStored, rr.Stored)
		}

		if !found {
			if migrated {
				// Write the migration, report not found.
				return configMutationResult{Message: fmt.Sprintf("not found %s\n", requestedIdentity)}, nil
			}
			return configMutationResult{SkipWrite: true, Message: fmt.Sprintf("not found %s\n", requestedIdentity)}, nil
		}

		// Reject removal of the final global root.
		if len(newStored) == 0 {
			return configMutationResult{}, configUserError{"cannot remove the last allowed root"}
		}

		rawBytes, _ := json.Marshal(newStored)
		raw["allowed_roots"] = rawBytes
		return configMutationResult{Message: fmt.Sprintf("removed %s\n", requestedIdentity)}, nil
	})
}

// loadRawConfig reads config.json from disk as a raw JSON map.
// It parses the top-level JSON object and returns the raw map and config path.
// Semantic validation (reserved fields, deprecated fields, value constraints)
// is performed by validateRawConfig, not by this function.
// Returns the raw map, the config file path, and any error.
func loadRawConfig() (map[string]json.RawMessage, string, error) {
	configPath := getConfigPath()
	raw, err := loadRawConfigFile(configPath)
	if err != nil {
		return nil, "", err
	}
	return raw, configPath, nil
}

// loadRawConfigFile reads config.json from the given path as a raw JSON map.
func loadRawConfigFile(configPath string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("configuration is not a JSON object")
	}

	return raw, nil
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

	// Resolve effective allowed_roots (handles legacy migration).
	requestedRoots, err := resolveAllowedRootsForShow(raw, fc)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	ec := resolveEffectiveConfig(*fc)

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

	result := map[string]any{
		"allowed_roots":           requestedRoots,
		"session_ttl":             fc.SessionTTL,
		"log_level":               ec.LogLevel,
		"audit_enabled":           ec.AuditEnabled,
		"audit_enabled_source":    ec.AuditEnabledSource,
		"config_path":             configPath,
		"config_dir":              configDir,
		"runtime_dir":             runtimeDir,
		"socket_path":             socketPath,
		"lock_path":               lockPath,
		"state_dir":               stateDir,
		"database_path":           databasePath,
		"admin_token_path":        adminTokenPath,
		"admin_token":             "<redacted>",
		"shutdown_timeout":        ec.ShutdownTimeout,
		"operation_retention_ttl": ec.OperationRetentionTTL,
		"operation_max_completed": ec.OperationMaxCompleted,
		"operation_log_max_bytes": ec.OperationLogMaxBytes,
		"trusted_ca_path":         fc.TrustedCAPath,
		"trusted_ca_injection":    ec.TrustedCAInjection,
		"mode":                    resolveDeploymentMode(),
		"http_address":            ec.HTTPAddress,
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

	// Resolve effective allowed_roots (handles legacy migration).
	requestedRoots, err := resolveAllowedRootsForShow(raw, fc)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	ec := resolveEffectiveConfig(*fc)

	stateDir := getStateDir()

	switch field {
	case "allowed_roots":
		data, _ := json.MarshalIndent(requestedRoots, "", "  ")
		fmt.Fprintln(stdout, string(data))
	case "session_ttl":
		fmt.Fprintln(stdout, fc.SessionTTL)
	case "log_level":
		fmt.Fprintln(stdout, ec.LogLevel)
	case "audit_enabled":
		fmt.Fprintln(stdout, ec.AuditEnabled)
	case "audit_enabled_source":
		fmt.Fprintln(stdout, ec.AuditEnabledSource)
	case "state_dir":
		fmt.Fprintln(stdout, stateDir)
	case "database_path":
		fmt.Fprintln(stdout, filepath.Join(stateDir, "docker-helper.db"))
	case "shutdown_timeout":
		fmt.Fprintln(stdout, ec.ShutdownTimeout)
	case "operation_retention_ttl":
		fmt.Fprintln(stdout, ec.OperationRetentionTTL)
	case "operation_max_completed":
		fmt.Fprintln(stdout, ec.OperationMaxCompleted)
	case "operation_log_max_bytes":
		fmt.Fprintln(stdout, ec.OperationLogMaxBytes)
	case "trusted_ca_path":
		fmt.Fprintln(stdout, fc.TrustedCAPath)
	case "trusted_ca_injection":
		fmt.Fprintln(stdout, ec.TrustedCAInjection)
	default:
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}
	return 0
}

// addAllowedRootToConfig adds a root to allowed_roots using the shared
// config transaction owner.
func addAllowedRootToConfig(canonical string, stdout, stderr io.Writer) int {
	return executeConfigTransaction(stdout, stderr, safeWriteConfig, func(raw map[string]json.RawMessage, migrated bool) (configMutationResult, error) {
		fc, err := decodeFileConfig(raw)
		if err != nil {
			return configMutationResult{}, err
		}

		// Validate existing roots with full canonicalization (strict resolver).
		existingRoots, err := resolveAllowedRoots(raw, fc)
		if err != nil {
			return configMutationResult{}, err
		}

		// Check if already present.
		present := false
		for _, r := range existingRoots {
			if r == canonical {
				present = true
				break
			}
		}

		if present {
			if !migrated {
				return configMutationResult{
					SkipWrite: true,
					Message:   fmt.Sprintf("already present %s\n", canonical),
				}, nil
			}
			// Legacy migration needed: write migrated config.
			return configMutationResult{
				Message: fmt.Sprintf("already present %s (legacy schema migrated)\n", canonical),
			}, nil
		}

		// Add new root to canonical roots list.
		rawBytes, _ := json.Marshal(append(existingRoots, canonical))
		raw["allowed_roots"] = rawBytes

		return configMutationResult{
			Message: fmt.Sprintf("added %s\n", canonical),
		}, nil
	})
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

	switch field {
	case "allowed_root":
		fmt.Fprintln(stderr, "error: allowed_root is no longer settable as a scalar")
		fmt.Fprintln(stderr, "use: docker-helper config allowed-root add PATH")
		return 2
	case "allowed_roots":
		fmt.Fprintln(stderr, "error: allowed_roots is managed via structured commands")
		fmt.Fprintln(stderr, "use: docker-helper config allowed-root add/remove/list")
		return 2
	}

	if isReadOnlyField(field) {
		fmt.Fprintf(stderr, "error: field %q is read-only\n", field)
		return 2
	}

	switch field {
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

	// Compute the JSON-encoded value for the field.
	var newValue json.RawMessage
	switch field {
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

	return applyConfigChangeTransactionally(
		configOpSet,
		field,
		value,
		newValue,
		func(raw map[string]json.RawMessage) {
			raw[field] = newValue
		},
		safeWriteConfig,
		stdout,
		stderr,
	)
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
	if field == "allowed_root" {
		fmt.Fprintln(stderr, "error: allowed_root is legacy and cannot be unset directly")
		fmt.Fprintln(stderr, "use: docker-helper config allowed-root remove PATH")
		return 2
	}
	if isReadOnlyField(field) {
		fmt.Fprintf(stderr, "error: field %q is read-only\n", field)
		return 2
	}
	if isRequiredField(field) {
		fmt.Fprintf(stderr, "error: field %q is required and cannot be unset\n", field)
		return 2
	}

	return applyConfigChangeTransactionally(
		configOpUnset,
		field,
		"",
		nil,
		func(raw map[string]json.RawMessage) {
			delete(raw, field)
		},
		safeWriteConfig,
		stdout,
		stderr,
	)
}

// configChangeLockPath returns the lock file path for serializing config
// mutations across processes. It sits beside the config file.
func configChangeLockPath(configPath string) string {
	return configPath + ".lock"
}

// acquireConfigChangeLock opens the lock file and acquires an exclusive
// blocking flock. Returns the open file that must stay open for the lock
// to remain held, or an error if the lock file cannot be opened.
//
// Uses blocking flock so concurrent operations serialize automatically
// instead of failing with EWOULDBLOCK.
func acquireConfigChangeLock(configPath string) (*os.File, error) {
	f, err := os.OpenFile(configChangeLockPath(configPath), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open config lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot acquire config lock: %w", err)
	}
	return f, nil
}

// reloadResult captures the outcome of a transactional reload attempt.
type reloadResult int

const (
	reloadSuccess          reloadResult = iota // daemon accepted the new config
	reloadDaemonNotRunning                     // daemon is not running
	reloadRejected                             // daemon rejected (HTTP 4xx/5xx)
	reloadTransportError                       // transport error (not daemon-not-running)
)

// reloadOutcome captures the outcome of a reload attempt.
type reloadOutcome struct {
	result reloadResult
	err    error // nil for success/daemonNotRunning
}

// formatReloadError returns a human-readable description of a reload failure.
// For daemon-not-running, err is nil so it is not formatted.
func formatReloadError(r reloadOutcome) string {
	switch r.result {
	case reloadRejected:
		return fmt.Sprintf("reload rejected: %v", r.err)
	case reloadTransportError:
		return fmt.Sprintf("reload transport error: %v", r.err)
	case reloadDaemonNotRunning:
		return "daemon not running"
	default:
		return "reload failed"
	}
}

// formatReReloadError returns a human-readable description of a re-reload
// failure. Unlike formatReloadError, it does not include the "reload" prefix
// to avoid "re-reload reload rejected" redundancy.
func formatReReloadError(r reloadOutcome) string {
	switch r.result {
	case reloadRejected:
		return fmt.Sprintf("rejected: %v", r.err)
	case reloadTransportError:
		return fmt.Sprintf("transport error: %v", r.err)
	case reloadDaemonNotRunning:
		return "daemon not running"
	default:
		return "failed"
	}
}

// removableRoot separates stored representation from comparison identity.
type removableRoot struct {
	Stored   string // original absolute stored spelling
	Identity string // EvalSymlinks result or cleaned abs on ENOENT
}

// executeConfigTransaction is the shared config mutation transaction executor.
// It owns the entire read-modify-write-reload-rollback lifecycle under a
// single process-level lock.
//
// The mutation callback receives the raw config map after legacy migration
// (if any). It modifies the map in place and returns a result controlling
// whether the write/reload should proceed.
//
// The caller provides only operation-specific logic:
// - path validation/canonicalization (before calling this function);
// - collection mutation and idempotency checks;
// - operation-specific success output.
//
// writeFn is the atomic write function (safeWriteConfig in production,
// injectable for tests).
//
// It returns exit code 0 on success, 1 on transaction/internal error,
// 2 on user-facing error (wrapped in configUserError).
func executeConfigTransaction(stdout, stderr io.Writer, writeFn configWriter, mutate configMutation) int {
	configPath := getConfigPathFunc()

	// Acquire process-level lock BEFORE reading config.
	lockFile, err := acquireConfigChangeLock(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer lockFile.Close()

	// Read current config under lock.
	raw, err := loadRawConfigFile(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Check for ambiguous schema before migration (fail closed).
	hasLegacy := raw["allowed_root"] != nil
	hasNew := raw["allowed_roots"] != nil
	if hasLegacy && hasNew {
		fmt.Fprintln(stderr, "error: ambiguous configuration: both allowed_root and allowed_roots are present; migrate to allowed_roots and remove allowed_root")
		return 1
	}

	// Migrate legacy allowed_root to allowed_roots if present.
	// This must happen BEFORE the mutation so that a successful
	// mutation always produces canonical config.
	migrated := false
	if hasLegacy && !hasNew {
		var legacyVal string
		if err := json.Unmarshal(raw["allowed_root"], &legacyVal); err != nil {
			fmt.Fprintf(stderr, "error: cannot parse allowed_root: %v\n", err)
			return 1
		}
		canon, canonErr := canonicalizePathForAdd(legacyVal)
		if canonErr != nil {
			fmt.Fprintf(stderr, "error: cannot canonicalize allowed_root %q: %v\n", legacyVal, canonErr)
			return 1
		}
		newRoots, _ := json.Marshal([]string{canon})
		raw["allowed_roots"] = newRoots
		delete(raw, "allowed_root")
		migrated = true
	}

	// Execute mutation.
	result, err := mutate(raw, migrated)
	if err != nil {
		if isConfigUserError(err) {
			fmt.Fprintf(stderr, "error: %s\n", err.Error())
			return 2
		}
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Validate before allowing SkipWrite or proceeding to write.
	// This prevents no-op callbacks (allowed-root "already present"/"not found")
	// from reporting success on an otherwise invalid configuration.
	if err := validateRawConfig(raw); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := validateCAConfig(raw); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Skip write: print message and return.
	if result.SkipWrite {
		if result.Message != "" {
			fmt.Fprint(stdout, result.Message)
		}
		return 0
	}

	// Save original bytes for rollback.
	original, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot read current config: %v\n", err)
		return 1
	}

	// Encode new config.
	newData, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	newData = append(newData, '\n')

	// Atomically write new config.
	if err := writeFn(configPath, newData); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Startup-only fields: no reload, print message immediately.
	if result.StartupOnly {
		if result.Message != "" {
			fmt.Fprint(stdout, result.Message)
		}
		fmt.Fprintln(stdout, "restart required")
		return 0
	}

	// Attempt reload.
	outcome := attemptReload()
	switch outcome.result {
	case reloadSuccess:
		if result.Message != "" {
			fmt.Fprint(stdout, result.Message)
		}
		return 0
	case reloadDaemonNotRunning:
		if result.Message != "" {
			fmt.Fprint(stdout, result.Message)
		}
		fmt.Fprintln(stdout, "daemon not running; change will apply on next start")
		return 0
	case reloadRejected, reloadTransportError:
		// Print the initial reload failure reason first.
		reloadErrStr := formatReloadError(outcome)

		// Rollback: restore original bytes.
		if rollErr := writeFn(configPath, original); rollErr != nil {
			fmt.Fprintf(stderr, "error: %s\n", reloadErrStr)
			fmt.Fprintf(stderr, "error: rollback write failed: %v\n", rollErr)
			return 1
		}

		// Re-reload to synchronize runtime with restored file.
		reOutcome := attemptReload()
		if reOutcome.result != reloadSuccess {
			fmt.Fprintf(stderr, "error: %s\n", reloadErrStr)
			fmt.Fprintf(stderr, "error: config rolled back; re-reload %s\n", formatReReloadError(reOutcome))
			return 1
		}

		fmt.Fprintf(stderr, "error: %s\n", reloadErrStr)
		fmt.Fprintln(stderr, "error: config rolled back")
		return 1
	}

	return 0
}

// applyConfigChangeTransactionally performs the atomic write + reload + rollback
// transaction for a config set/unset operation.
//
// The entire read-modify-write-reload-rollback cycle runs under a single
// process-level lock to serialize concurrent config mutations.
//
// It returns exit code 0 on success, 1 on failure.
func applyConfigChangeTransactionally(
	op configOp,
	field string,
	value string,
	newValue json.RawMessage,
	modify func(map[string]json.RawMessage),
	writeFn configWriter,
	stdout, stderr io.Writer,
) int {
	startupOnly := field == "http_address"

	return executeConfigTransaction(stdout, stderr, writeFn, func(raw map[string]json.RawMessage, migrated bool) (configMutationResult, error) {
		// Apply modification tentatively to check if it repairs the config.
		tempRaw := make(map[string]json.RawMessage)
		for k, v := range raw {
			tempRaw[k] = v
		}
		modify(tempRaw)

		// Validate after mutation. If the mutation repairs the config, this passes.
		if err := validateRawConfig(tempRaw); err != nil {
			return configMutationResult{}, err
		}

		// Check unchanged AFTER migration.
		// Distinguish fieldChanged vs schemaChanged.
		// Only return without writing when BOTH are false.
		fieldChanged := false
		if op == configOpSet && newValue != nil {
			if existing, ok := raw[field]; !ok || !bytes.Equal(existing, newValue) {
				fieldChanged = true
			}
		} else if op == configOpUnset {
			if _, ok := raw[field]; ok {
				fieldChanged = true
			}
		}

		if !fieldChanged && !migrated {
			// Truly unchanged: no field change and no schema migration needed.
			if err := validateCAConfig(raw); err != nil {
				return configMutationResult{}, err
			}
			if op == configOpUnset {
				return configMutationResult{SkipWrite: true, Message: fmt.Sprintf("unchanged %s is already unset\n", field)}, nil
			}
			return configMutationResult{SkipWrite: true, Message: fmt.Sprintf("unchanged %s=%s\n", field, value)}, nil
		}

		// Apply modification.
		modify(raw)

		// Validate CA config (for repair mutations).
		if err := validateCAConfig(raw); err != nil {
			return configMutationResult{}, err
		}

		// Determine success message.
		var msg string
		if op == configOpSet {
			if fieldChanged {
				msg = fmt.Sprintf("updated %s=%s\n", field, value)
			} else {
				msg = fmt.Sprintf("unchanged %s=%s; configuration schema migrated\n", field, value)
			}
		} else {
			if fieldChanged {
				msg = fmt.Sprintf("unset %s\n", field)
			} else {
				msg = fmt.Sprintf("unchanged %s is already unset; configuration schema migrated\n", field)
			}
		}

		return configMutationResult{
			Message:     msg,
			StartupOnly: startupOnly,
		}, nil
	})
}

// attemptReload calls POST /reload and returns a structured result with error.
// Can be replaced in tests to avoid requiring a running daemon.
var attemptReload = func() reloadOutcome {
	client, resolveErr := resolveOperatorClient(operatorClientOptions{})
	if resolveErr != nil {
		return reloadOutcome{reloadTransportError, resolveErr}
	}

	resp, reqErr := client.doAuthenticatedRequest("POST", "/reload", nil)
	if reqErr != nil {
		if isDaemonNotRunning(reqErr) {
			return reloadOutcome{reloadDaemonNotRunning, nil}
		}
		return reloadOutcome{reloadTransportError, reqErr}
	}
	defer resp.Body.Close()

	_, bodyErr := client.readResponseBody(resp)
	if bodyErr != nil {
		return reloadOutcome{reloadRejected, bodyErr}
	}

	return reloadOutcome{reloadSuccess, nil}
}

// isDaemonNotRunning returns true if the error indicates the daemon
// is not listening on the socket. Only transport-level errors are
// checked; local errors (missing token, bad config) never qualify.
func isDaemonNotRunning(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "no such file or directory") {
		return true
	}
	// "invalid argument" can be caused by missing socket file OR too-long path.
	// Distinguish: if the path in the error message is suspiciously long (>108 chars),
	// it's likely a path-too-long error, not a missing-socket error.
	if strings.Contains(msg, "invalid argument") {
		// Check if this is a dial unix error with a reasonable path length.
		// Unix socket paths are limited to ~108 bytes on Linux.
		// If the path in the error is shorter than that, it's likely a missing socket.
		// Allow some margin for test temp directories.
		const maxUnixPathLen = 140
		if idx := strings.Index(msg, "dial unix "); idx >= 0 {
			rest := msg[idx+len("dial unix "):]
			if spaceIdx := strings.Index(rest, ":"); spaceIdx > 0 && spaceIdx < maxUnixPathLen {
				return true
			}
		}
	}
	return false
}
