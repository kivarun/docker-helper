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
func runReload(stdout, stderr io.Writer, opts operatorClientOptions, jsonOut bool) int {
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

	if jsonOut {
		if err := encodeJSONOut(stdout, reloadedResult{Reloaded: true}); err != nil {
			fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintln(stdout, "reloaded")
	return 0
}

// reloadedResult is the CLI-owned --json shape of the reload
// acknowledgement: the daemon's POST /reload returns no document, so the
// CLI presentation layer owns the smallest stable result.
type reloadedResult struct {
	Reloaded bool `json:"reloaded"`
}

// reloadDeps are the production dependencies for handleReload.
// Tests may inject runtime-config preparation for deterministic testing.
type reloadDeps struct {
	loadAndPrepareRuntimeConfig func() (*Config, error)
}

// handleReload reloads the configuration from disk and updates the daemon's
// runtime configuration. Configurable fields updated: allowed_roots,
// session_ttl, log_level, audit_enabled, shutdown_timeout,
// operation_retention_ttl, operation_max_completed, operation_log_max_bytes,
// trusted_ca_path, trusted_ca_injection.
// Computed paths (socket, database, etc.) and startup-only fields (http_address)
// remain unchanged.
//
// Global allowed_roots remain authorization policy; reload does not prepare
// or verify MAC coverage for them. MAC state follows concrete session
// workspace lifecycle.
//
// If the new configuration is invalid, the daemon keeps its current
// configuration and returns an error.
func (a *App) handleReload(w http.ResponseWriter, r *http.Request) {
	a.handleReloadWithDeps(w, r, reloadDeps{
		loadAndPrepareRuntimeConfig: loadAndPrepareRuntimeConfig,
	})
}

// handleReloadWithDeps is the implementation of handleReload with
// injectable dependencies for testing.
func (a *App) handleReloadWithDeps(w http.ResponseWriter, r *http.Request, deps reloadDeps) {
	if !a.requireAdmin(w, r) {
		return
	}

	started := time.Now()
	ctx := r.Context()

	// The authoritative global-allowed-root transition shares the lifecycle
	// serialization with Session creation: resolution and the setConfig commit
	// are one critical section, so a concurrent Session create either observes
	// the old global roots or the new ones, never a mix, and a narrowing that
	// linearizes before the create commits prevents that Session. The runtime
	// config load (filesystem, trusted CA preparation) runs inside the
	// boundary so a config resolved for the transition cannot be interleaved
	// with another transition. Lock ordering: lifecycleMu -> a.mu (setConfig).
	a.lifecycleMu.Lock()
	newCfg, err := deps.loadAndPrepareRuntimeConfig()
	if err != nil {
		a.lifecycleMu.Unlock()
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
		writeRequestContextAudit(ctx, auditRecord{
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

	// Preserve startup-only fields that cannot be changed at runtime.
	newCfg.HTTPAddress = a.getConfig().HTTPAddress

	// The authoritative global-ceiling transition: the new global
	// allowed-root policy becomes durable policy state only together with its
	// cascaded stored descendants. The reconciliation owner commits the
	// stored-root prune in one transaction before the new runtime policy is
	// published; a reconciliation failure publishes nothing, so a concurrent
	// Session create observes either the old complete hierarchy or the new
	// complete cascaded hierarchy, never a new parent ceiling with stale
	// child rows.
	reconcileResult, err := reconcileStoredAllowedRootsToGlobalCeiling(a.DB, newCfg.AllowedRoots)
	if err != nil {
		a.lifecycleMu.Unlock()
		duration := time.Since(started).Round(time.Millisecond).String()
		opLog(ctx).Error("reload allowed-root reconciliation failed",
			slog.String("operation", "reload"),
			slog.String("error", err.Error()),
		)
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "config.reload",
			Result:   "reconciliation_failed",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusInternalServerError,
			"database_error",
			"stored allowed-root reconciliation failed; configuration not reloaded",
		)
		return
	}
	logStoredRootReconciliation(ctx, "reload", reconcileResult)

	a.setConfig(newCfg)
	a.lifecycleMu.Unlock()

	// Snapshot writers under read lock, then re-initialize loggers
	// with the new log level and audit setting under write lock.
	opW, audW := logging.snapshotWriters()

	// Capture old audit_enabled state before reconfiguring.
	oldAuditEnabled, _, _ := logging.snapshotAudit()

	// When audit is being disabled (true->false), write the success event
	// before reconfiguring so the record is actually emitted.
	if oldAuditEnabled && !newCfg.AuditEnabled {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "config.reload",
			Result:   "success",
			Duration: duration,
		})
		logging.configure(opW, audW, newCfg.LogLevel, newCfg.AuditEnabled)
	} else {
		logging.configure(opW, audW, newCfg.LogLevel, newCfg.AuditEnabled)
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "config.reload",
			Result:   "success",
			Duration: duration,
		})
	}

	opLog(ctx).Info("configuration reloaded",
		slog.Any("allowed_roots", newCfg.AllowedRoots),
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
