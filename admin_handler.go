package main

import (
	"errors"
	"log/slog"
	"net/http"
	"time"
)

func (a *App) handleRotateAdminToken(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	tokenHash, ok := a.requireAdminWithHash(w, r)
	if !ok {
		return
	}

	ctx := r.Context()

	newToken, err := a.rotateAdminToken(tokenHash)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		if errors.Is(err, ErrStaleRotation) {
			// The authorizing token was invalidated by a concurrent
			// rotation before this one committed. The capability is no
			// longer valid; respond with 401.
			writeAuditWithRequestID(ctx, auditRecord{
				Event:    "admin_token.rotate",
				Result:   "stale_token",
				Duration: duration,
			})
			writeUnauthorizedAdmin(ctx, w)
			return
		}

		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "admin_token.rotate",
			Result:   "error",
			Duration: duration,
		})
		opLog(ctx).Error("admin token rotate failed",
			slog.String("operation", "admin_token_rotate"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:    "admin_token.rotate",
		Result:   "success",
		Duration: duration,
	})

	writeJSONRaw(ctx, w, http.StatusOK, rotateAdminTokenResponse{
		OK:    true,
		Token: newToken,
	})
}
