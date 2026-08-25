package main

import (
	"bytes"
	"io"
	"log/slog"
	"testing"
)

// setupTestLogging initializes the logging infrastructure with test buffers.
// Returns the audit buffer and operational buffer.
func setupTestLogging(t *testing.T) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	t.Cleanup(logging.reset)
	return auditBuf, opBuf
}

// setupTestLoggingDiscard initializes the logging infrastructure with
// discard writers for tests that don't need to capture logs.
func setupTestLoggingDiscard(t *testing.T) {
	t.Helper()
	initLoggers(io.Discard, io.Discard, slog.LevelError, true)
	t.Cleanup(logging.reset)
}
