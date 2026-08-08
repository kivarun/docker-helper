package main

import (
	"context"
	"net/http"
	"time"
)

// withRequestID wraps an HTTP handler to generate a server-side request ID,
// store it in the request context, and return it in the X-Request-ID header.
// It does not trust or reuse any client-supplied request ID.
func withRequestID(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rid := generateRequestID()
		ctx := context.WithValue(r.Context(), requestIDKey, rid)

		// Set session_id in context after authentication establishes it.
		// Handlers that call requireSession or requireAdmin will set this.

		w.Header().Set("X-Request-ID", rid)
		next(w, r.WithContext(ctx))
	}
}

// withSessionID wraps an HTTP handler to add the session ID to the context
// after the handler has established the session through authentication.
// This is used internally by handlers after requireSession returns.
func withSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionIDKey, sessionID)
}

// withLogging wraps an HTTP handler to log request completion at DEBUG level.
// It records the request ID, method, route pattern, status code, and duration.
// It never logs query parameters, request bodies, headers, or session IDs.
// Must be called inside withRequestID so request_id is available in context.
func withLogging(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()

		lw := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next(lw, r)

		duration := time.Since(started).Milliseconds()
		route := getRoutePattern(r)
		rid := requestIDFromContext(r.Context())

		loggerMu.RLock()
		logger := opLogger
		loggerMu.RUnlock()
		if logger != nil {
			logger.Debug("request completed",
				"request_id", rid,
				"method", r.Method,
				"route", route,
				"status", lw.status,
				"duration_ms", duration,
			)
		}
	}
}

// statusResponseWriter wraps http.ResponseWriter to capture the status code.
type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// getRoutePattern returns the registered route pattern for the request.
// For parameterized routes, it returns the pattern with {param} placeholders.
// For static routes, it returns the path as-is.
func getRoutePattern(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return r.URL.Path
}
