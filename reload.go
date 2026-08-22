package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// runReload is the CLI entry point for the reload command.
func runReload(stdout, stderr io.Writer, opts operatorClientOptions) int {
	client, err := resolveOperatorClient(opts)
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

	started := time.Now()
	ctx := r.Context()

	newCfg, err := loadConfig()
	if err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		diagnostic := "invalid configuration"
		var caErr *trustedCAPreparationError
		if errors.As(err, &caErr) {
			diagnostic = caErr.Error()
		}
		opLog(ctx).Error("reload config error",
			slog.String("operation", "reload"),
			slog.String("error", err.Error()),
			slog.String("diagnostic", diagnostic),
		)
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "config.reload",
			Result:   "invalid_config",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest,
			"invalid_config",
			diagnostic,
		)
		return
	}

	// System mode with SELinux: verify non-home allowed_root workspace label.
	// This is a read-only check — no semanage/restorecon mutation on reload.
	if resolveDeploymentMode() == ModeSystem {
		backend, _ := detectLSM()
		if backend == LSMSelinux && !isHomeRoot(newCfg.AllowedRoot) {
			selMgr := newSELinuxWorkspaceManager()
			if err := selMgr.verifyWorkspaceLabel(newCfg.AllowedRoot); err != nil {
				duration := time.Since(started).Round(time.Millisecond).String()
				opLog(ctx).Error("reload SELinux workspace verification failed",
					slog.String("operation", "reload"),
					slog.String("error", err.Error()),
				)
				writeAuditWithRequestID(ctx, auditRecord{
					Event:    "config.reload",
					Result:   "selinux_workspace_verification_failed",
					Duration: duration,
				})
				writeError(ctx, w, http.StatusBadRequest,
					"selinux_workspace_verification_failed",
					err.Error(),
				)
				return
			}
		}
	}

	// Preserve startup-only fields that cannot be changed at runtime.
	oldCfg := a.getConfig()
	newCfg.HTTPAddress = oldCfg.HTTPAddress

	a.setConfig(newCfg)

	// Snapshot writers under read lock, then re-initialize loggers
	// with the new log level and audit setting under write lock.
	opW, audW := logging.snapshotWriters()

	// Capture old audit_enabled state before reconfiguring.
	oldAuditEnabled, _, _ := logging.snapshotAudit()

	// When audit is being disabled (true->false), write the success event
	// before reconfiguring so the record is actually emitted.
	if oldAuditEnabled && !newCfg.AuditEnabled {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "config.reload",
			Result:   "success",
			Duration: duration,
		})
		logging.configure(opW, audW, newCfg.LogLevel, newCfg.AuditEnabled)
	} else {
		logging.configure(opW, audW, newCfg.LogLevel, newCfg.AuditEnabled)
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "config.reload",
			Result:   "success",
			Duration: duration,
		})
	}

	opLog(ctx).Info("configuration reloaded",
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
