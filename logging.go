package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
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

// opLogger is the package-level operational logger.
// It is initialized by initLoggers and can be replaced in tests.
// All operational logging goes through this logger.
var opLogger *slog.Logger

// opWriter is the operational log output writer.
// It is initialized by initLoggers and can be replaced in tests.
var opWriter io.Writer

// auditWriter is the package-level writer for audit records.
// It is initialized by initLoggers and can be replaced in tests.
var auditWriter io.Writer

// auditEnabled controls whether audit records are written.
// When false, writeAudit is a no-op.
var auditEnabled bool

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

// initLoggers creates the operational logger and audit writer.
// The operational logger writes JSON to the given writer at the given level,
// with "stream": "operational" on every record. Timestamps use UTC RFC3339Nano.
// The audit writer receives JSON Lines audit records.
// When auditEnabled is true, audit records are written to audWriter.
func initLoggers(opW io.Writer, audW io.Writer, level slog.Level, enabled bool) {
	opWriter = opW
	auditWriter = audW
	auditEnabled = enabled
	opLogger = slog.New(&operationalHandler{
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

// writeAudit marshals the audit record to JSON and writes it to the audit writer.
// It centrally enforces stream="audit" and populates the timestamp.
// If audit is disabled, the record is silently dropped.
// If the audit writer is nil (e.g. during tests that don't set it up), the record
// is silently dropped. If writing or encoding fails, a structured operational error
// is emitted to stderr with correlation fields copied from the record.
func writeAudit(record auditRecord) {
	if !auditEnabled {
		return
	}
	if auditWriter == nil {
		return
	}

	// Central enforcement: always set stream and time.
	record.Stream = "audit"
	if record.Time == "" {
		record.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}

	data, err := json.Marshal(record)
	if err != nil {
		if opLogger != nil {
			l := opLogger.With(
				slog.String("operation", "audit_encode"),
				slog.String("error", err.Error()),
			)
			if record.RequestID != "" {
				l = l.With(slog.String("request_id", record.RequestID))
			}
			if record.SessionID != "" {
				l = l.With(slog.String("session_id", record.SessionID))
			}
			l.Error("audit: cannot marshal record")
		}
		return
	}

	data = append(data, '\n')
	if _, err := auditWriter.Write(data); err != nil {
		if opLogger != nil {
			l := opLogger.With(
				slog.String("operation", "audit_write"),
				slog.String("error", err.Error()),
			)
			if record.RequestID != "" {
				l = l.With(slog.String("request_id", record.RequestID))
			}
			if record.SessionID != "" {
				l = l.With(slog.String("session_id", record.SessionID))
			}
			l.Error("audit: cannot write record")
		}
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

// writeJSONError logs a response encoding failure using the request context.
// It includes request_id and session_id when available.
func writeJSONError(ctx context.Context, err error) {
	if opLogger == nil {
		return
	}
	l := opLogger.With(slog.String("operation", "response_encode"), slog.String("error", err.Error()))
	if rid := requestIDFromContext(ctx); rid != "" {
		l = l.With(slog.String("request_id", rid))
	}
	if sid := sessionIDFromContext(ctx); sid != "" {
		l = l.With(slog.String("session_id", sid))
	}
	l.Error("failed to encode response")
}

// osStderr is the original os.Stderr, captured at package init.
var osStderr io.Writer = os.Stderr

// serveStartupError logs a daemon startup failure as structured JSON to stderr.
// It is safe to call before initLoggers.
func serveStartupError(err error, hint string) {
	if opLogger != nil {
		l := opLogger.With(
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
		"time":      time.Now().UTC().Format(time.RFC3339),
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
