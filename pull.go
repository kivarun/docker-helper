package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"
)

type pullRequest struct {
	Image string `json:"image"`
}

func defaultPullCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

func (a *App) handlePull(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	var req pullRequest

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Image == "" {
		writeError(w, http.StatusBadRequest, "image is required")
		return
	}

	if !imagePattern.MatchString(req.Image) {
		writeError(w, http.StatusBadRequest, "invalid image name or tag")
		return
	}

	writeAudit(auditRecord{
		Event:     "pull.start",
		SessionID: session.ID,
		Image:     req.Image,
	})

	started := time.Now()

	args := []string{"pull", req.Image}

	pullCmd := a.PullCommand
	if pullCmd == nil {
		pullCmd = defaultPullCommand
	}

	output, err := pullCmd("docker", args...)
	duration := time.Since(started).Round(time.Millisecond).String()

	var result string
	var exitCode *int

	if err != nil {
		exitCode = extractExitCode(err)
		result = "pull_error"

		writeJSON(w, http.StatusInternalServerError, response{
			OK:       false,
			Message:  fmt.Sprintf("docker pull failed: %v", err),
			Output:   string(output),
			Duration: duration,
		})
	} else {
		result = "success"

		writeJSON(w, http.StatusOK, response{
			OK:       true,
			Message:  "image pulled successfully",
			Output:   string(output),
			Duration: duration,
		})
	}

	writeAudit(auditRecord{
		Event:     "pull.finish",
		SessionID: session.ID,
		Image:     req.Image,
		Result:    result,
		ExitCode:  exitCode,
		Duration:  duration,
	})
}
