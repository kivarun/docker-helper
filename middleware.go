package main

import (
	"context"
	"net/http"
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
