package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type auditRecord struct {
	Time        string       `json:"time"`
	Event       string       `json:"event"`
	Method      string       `json:"method,omitempty"`
	Path        string       `json:"path,omitempty"`
	SessionID   string       `json:"session_id,omitempty"`
	Image       string       `json:"image,omitempty"`
	Command     []string     `json:"command,omitempty"`
	Mounts      []auditMount `json:"mounts,omitempty"`
	EnvKeys     []string     `json:"env_keys,omitempty"`
	Context     string       `json:"context,omitempty"`
	Dockerfile  string       `json:"dockerfile,omitempty"`
	Workspace   string       `json:"workspace,omitempty"`
	Result      string       `json:"result,omitempty"`
	ExitCode    *int         `json:"exit_code,omitempty"`
	Duration    string       `json:"duration,omitempty"`
}

type auditMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

func writeAudit(record auditRecord) {
	record.Time = time.Now().UTC().Format(time.RFC3339)

	data, err := json.Marshal(record)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: cannot marshal: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "%s\n", data)
}