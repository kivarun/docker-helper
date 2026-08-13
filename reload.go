package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// runReload is the CLI entry point for the reload command.
func runReload(stdout, stderr io.Writer, flags *flag.FlagSet) int {
	system := flags.Bool("system", false, "Connect to system daemon")
	endpoint := flags.String("endpoint", "", "Explicit endpoint (unix:///path or http://127.0.0.1:port)")
	tokenFile := flags.String("token-file", "", "Token file path")

	client, err := resolveOperatorClient(operatorClientOptions{
		System:    *system,
		Endpoint:  *endpoint,
		TokenFile: *tokenFile,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	resp, err := client.doAuthenticatedRequest("POST", "/reload", nil)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	_, err = client.readResponseBody(resp)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "reloaded")
	return 0
}

// handleReload reloads the configuration from disk and updates the daemon's
// runtime configuration. Configurable fields updated: allowed_root,
// session_ttl, log_level, audit_enabled, shutdown_timeout,
// operation_retention_ttl, operation_max_completed, operation_log_max_bytes,
// trusted_ca_path, trusted_ca_injection.
// Computed paths (socket, database, etc.) and startup-only fields (http_address)
// remain unchanged.
//
// If the new configuration is invalid, the daemon keeps its current
// configuration and returns an error.
func (a *App) handleReload(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}

	newCfg, err := loadConfig()
	if err != nil {
		opLog(r.Context()).Error("reload config error",
			slog.String("operation", "reload"),
			slog.String("error", err.Error()),
		)
		writeError(r.Context(), w, http.StatusBadRequest,
			"invalid_config",
			"invalid configuration",
		)
		return
	}

	// Preserve startup-only fields that cannot be changed at runtime.
	oldCfg := a.getConfig()
	newCfg.HTTPAddress = oldCfg.HTTPAddress

	a.setConfig(newCfg)

	// Snapshot writers under read lock, then re-initialize loggers
	// with the new log level and audit setting under write lock.
	opW, audW := logging.snapshotWriters()

	logging.configure(opW, audW, newCfg.LogLevel, newCfg.AuditEnabled)

	opLog(r.Context()).Info("configuration reloaded",
		slog.String("allowed_root", newCfg.AllowedRoot),
		slog.String("session_ttl", newCfg.SessionTTL.String()),
		slog.String("log_level", newCfg.LogLevel.String()),
		slog.Bool("audit_enabled", newCfg.AuditEnabled),
		slog.String("shutdown_timeout", newCfg.ShutdownTimeout.String()),
		slog.String("operation_retention_ttl", newCfg.OperationRetentionTTL.String()),
		slog.Int("operation_max_completed", newCfg.OperationMaxCompleted),
		slog.Int64("operation_log_max_bytes", newCfg.OperationLogMaxBytes),
		slog.String("trusted_ca_injection", newCfg.TrustedCAInjection),
		slog.String("trusted_ca_path", newCfg.TrustedCAPath),
	)

	writeJSON(r.Context(), w, http.StatusOK, response{
		OK:      true,
		Message: "configuration reloaded",
	})
}
