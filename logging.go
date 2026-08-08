package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
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

// opLogger is the package-level operational logger.
// It is initialized by initLoggers and can be replaced in tests.
// All operational logging goes through this logger.
var opLogger *slog.Logger

// auditWriter is the package-level writer for audit records.
// It is initialized by initLoggers and can be replaced in tests.
var auditWriter io.Writer

// initLoggers creates the operational logger and audit writer.
// The operational logger writes JSON to the given writer at the given level.
// The audit writer receives JSON Lines audit records.
func initLoggers(opWriter io.Writer, audWriter io.Writer, level slog.Level) {
	opLogger = slog.New(slog.NewJSONHandler(opWriter, &slog.HandlerOptions{
		Level: level,
	}))
	auditWriter = audWriter
}

// writeAudit marshals the audit record to JSON and writes it to the audit writer.
// If the audit writer is nil (e.g. during tests that don't set it up), the record
// is silently dropped. If writing or encoding fails, a structured operational error
// is emitted to stderr.
func writeAudit(record auditRecord) {
	if auditWriter == nil {
		return
	}

	data, err := json.Marshal(record)
	if err != nil {
		if opLogger != nil {
			opLogger.Error("audit: cannot marshal record", slog.String("error", err.Error()))
		}
		return
	}

	data = append(data, '\n')
	if _, err := auditWriter.Write(data); err != nil {
		if opLogger != nil {
			opLogger.Error("audit: cannot write record", slog.String("error", err.Error()))
		}
	}
}

// writeAuditWithRequestID is like writeAudit but includes the request_id from the context.
func writeAuditWithRequestID(ctx context.Context, record auditRecord) {
	record.RequestID = requestIDFromContext(ctx)
	writeAudit(record)
}

// opLog returns the operational logger with request-scoped attributes.
// It adds request_id and session_id when available in the context.
func opLog(ctx context.Context) *slog.Logger {
	if opLogger == nil {
		return slog.Default()
	}
	l := opLogger
	if rid := requestIDFromContext(ctx); rid != "" {
		l = l.With(slog.String("request_id", rid))
	}
	if sid := sessionIDFromContext(ctx); sid != "" {
		l = l.With(slog.String("session_id", sid))
	}
	return l
}
