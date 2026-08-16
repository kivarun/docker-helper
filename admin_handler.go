package main

import (
	"net/http"
	"time"
)

type rotateAdminTokenResponse struct {
	OK    bool   `json:"ok"`
	Token string `json:"token"`
}

func (a *App) handleRotateAdminToken(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	newToken, err := a.rotateAdminToken()
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "admin_token.rotate",
			Result:   "error",
			Duration: duration,
		})
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
