package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// Context keys for request-scoped values.
type contextKey int

const (
	requestIDKey contextKey = iota
	sessionIDKey
)

// requestIDFromContext returns the request ID stored in the context,
// or an empty string if none is set.
func requestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// sessionIDFromContext returns the session ID stored in the context,
// or an empty string if none is set.
func sessionIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(sessionIDKey).(string); ok {
		return v
	}
	return ""
}

// generateRequestID returns a random 16-byte hex string prefixed with "req_".
func generateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}

// loggingState owns the operational logger, audit writer, and audit flag.
// All mutation is atomic under mu.
type loggingState struct {
	mu           sync.RWMutex
	opLogger     *slog.Logger
	opWriter     io.Writer
	auditWriter  io.Writer
	auditEnabled bool
	auditMu      sync.Mutex
}

// logging is the package-level logging state.
var logging = new(loggingState)

// operationalHandler wraps a slog.Handler to inject "stream": "operational"
// into every record.
type operationalHandler struct {
	slog.Handler
}

func (h *operationalHandler) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(slog.String("stream", "operational"))
	return h.Handler.Handle(ctx, r)
}

func (h *operationalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &operationalHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *operationalHandler) WithGroup(name string) slog.Handler {
	return &operationalHandler{Handler: h.Handler.WithGroup(name)}
}

// configure replaces the logging configuration atomically.
// The operational logger writes JSON to opW at the given level with
// "stream": "operational" on every record. Timestamps use UTC RFC3339Nano.
// The audit writer receives JSON Lines audit records when enabled is true.
func (ls *loggingState) configure(opW, audW io.Writer, level slog.Level, enabled bool) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.opWriter = opW
	ls.auditWriter = audW
	ls.auditEnabled = enabled
	ls.opLogger = slog.New(&operationalHandler{
		Handler: slog.NewJSONHandler(opW, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey && len(groups) == 0 {
					return slog.Attr{
						Key:   slog.TimeKey,
						Value: slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339Nano)),
					}
				}
				return a
			},
		}),
	})
}

// snapshotLogger returns the current operational logger under read lock.
func (ls *loggingState) snapshotLogger() *slog.Logger {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	return ls.opLogger
}

// snapshotWriters returns the current writers under read lock.
func (ls *loggingState) snapshotWriters() (opW, audW io.Writer) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	return ls.opWriter, ls.auditWriter
}

// snapshotAudit returns (auditEnabled, auditWriter, opLogger) under a single
// read lock so the caller sees a consistent configuration.
func (ls *loggingState) snapshotAudit() (bool, io.Writer, *slog.Logger) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	return ls.auditEnabled, ls.auditWriter, ls.opLogger
}

// initLoggers creates the operational logger and audit writer.
// The operational logger writes JSON to the given writer at the given level,
// with "stream": "operational" on every record. Timestamps use UTC RFC3339Nano.
// The audit writer receives JSON Lines audit records.
// When auditEnabled is true, audit records are written to audWriter.
func initLoggers(opW io.Writer, audW io.Writer, level slog.Level, enabled bool) {
	logging.configure(opW, audW, level, enabled)
}

// writeAudit marshals the audit record to JSON and writes it to the audit writer.
// It centrally enforces stream="audit" and populates the timestamp.
// If audit is disabled, the record is silently dropped.
// If the audit writer is nil (e.g. during tests that don't set it up), the record
// is silently dropped. If writing or encoding fails, a structured operational error
// is emitted to stderr with correlation fields copied from the record.
func writeAudit(record auditRecord) {
	enabled, aw, logger := logging.snapshotAudit()
	if !enabled || aw == nil {
		return
	}

	// Central enforcement: always set stream and time.
	record.Stream = "audit"
	if record.Time == "" {
		record.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}

	data, err := json.Marshal(record)
	if err != nil {
		if logger != nil {
			l := logger.With(
				slog.String("operation", "audit_encode"),
				slog.String("error", err.Error()),
				slog.String("audit_event", record.Event),
			)
			if record.RequestID != "" {
				l = l.With(slog.String("request_id", record.RequestID))
			}
			if record.SessionID != "" {
				l = l.With(slog.String("session_id", record.SessionID))
			}
			if record.OperationID != "" {
				l = l.With(slog.String("operation_id", record.OperationID))
			}
			l.Error("audit: cannot marshal record")
		}
		return
	}

	data = append(data, '\n')
	logging.auditMu.Lock()
	if _, err := aw.Write(data); err != nil {
		logging.auditMu.Unlock()
		if logger != nil {
			l := logger.With(
				slog.String("operation", "audit_write"),
				slog.String("error", err.Error()),
				slog.String("audit_event", record.Event),
			)
			if record.RequestID != "" {
				l = l.With(slog.String("request_id", record.RequestID))
			}
			if record.SessionID != "" {
				l = l.With(slog.String("session_id", record.SessionID))
			}
			if record.OperationID != "" {
				l = l.With(slog.String("operation_id", record.OperationID))
			}
			l.Error("audit: cannot write record")
		}
	} else {
		logging.auditMu.Unlock()
	}
}

// writeAuditWithRequestID is like writeAudit but includes the request_id and
// session_id from the context.
func writeAuditWithRequestID(ctx context.Context, record auditRecord) {
	record.RequestID = requestIDFromContext(ctx)
	if record.SessionID == "" {
		record.SessionID = sessionIDFromContext(ctx)
	}
	writeAudit(record)
}

// writeDockerActionRejected emits a <kind>.rejected audit event and writes the
// corresponding HTTP error response. It is used for Docker-action requests
// (pull, build, run) that are rejected after successful session authentication
// but before the corresponding *.start event.
//
// The rejected event contains only: event, result, principal_name, session_id,
// request_id. No request payload metadata (image, mounts, env, etc.) is included.
func writeDockerActionRejected(
	ctx context.Context,
	w http.ResponseWriter,
	status int,
	kind string, // "pull", "build", or "run"
	resultCode string,
	message string,
	principalName string,
) {
	writeAuditWithRequestID(ctx, auditRecord{
		Event:         kind + ".rejected",
		Result:        resultCode,
		PrincipalName: principalName,
	})
	writeError(ctx, w, status, resultCode, message)
}

// opLog returns the operational logger with request-scoped attributes.
// It adds request_id and session_id when available in the context.
func opLog(ctx context.Context) *slog.Logger {
	l := logging.snapshotLogger()
	if l == nil {
		return discardLogger
	}
	if rid := requestIDFromContext(ctx); rid != "" {
		l = l.With(slog.String("request_id", rid))
	}
	if sid := sessionIDFromContext(ctx); sid != "" {
		l = l.With(slog.String("session_id", sid))
	}
	return l
}

// writeJSONError logs a response encoding failure using the request context.
// It includes request_id and session_id when available.
func writeJSONError(ctx context.Context, err error) {
	opLog(ctx).Error(
		"failed to encode response",
		slog.String("operation", "response_encode"),
		slog.String("error", err.Error()),
	)
}

// osStderr is the original os.Stderr, captured at package init.
var osStderr io.Writer = os.Stderr

// discardLogger is a no-op logger used when the operational logger
// has not been configured. It silently drops all records.
var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// formatStartupFallbackTime formats a time for the serveStartupError JSON fallback.
func formatStartupFallbackTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// serveStartupError logs a daemon startup failure as structured JSON to stderr.
// It is safe to call before initLoggers.
func serveStartupError(err error, hint string) {
	logger := logging.snapshotLogger()
	if logger != nil {
		l := logger.With(
			slog.String("operation", "serve_startup"),
			slog.String("error", err.Error()),
		)
		if hint != "" {
			l = l.With(slog.String("hint", hint))
		}
		l.Error("daemon startup failed")
		return
	}
	// Fallback before logging is initialized: emit structured JSON to stderr.
	record := map[string]any{
		"stream":    "operational",
		"time":      formatStartupFallbackTime(time.Now()),
		"level":     "ERROR",
		"msg":       "daemon startup failed",
		"operation": "serve_startup",
		"error":     err.Error(),
	}
	if hint != "" {
		record["hint"] = hint
	}
	data, _ := json.Marshal(record)
	fmt.Fprintln(osStderr, string(data))
}
