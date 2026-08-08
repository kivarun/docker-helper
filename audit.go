package main

import (
	"time"
)

type auditRecord struct {
	Time            string       `json:"time"`
	Stream          string       `json:"stream"`
	Event           string       `json:"event"`
	Method          string       `json:"method,omitempty"`
	Path            string       `json:"path,omitempty"`
	SessionID       string       `json:"session_id,omitempty"`
	RequestID       string       `json:"request_id,omitempty"`
	Image           string       `json:"image,omitempty"`
	CommandArgCount *int         `json:"command_arg_count,omitempty"`
	Mounts          []auditMount `json:"mounts,omitempty"`
	EnvKeys         []string     `json:"env_keys,omitempty"`
	Context         string       `json:"context,omitempty"`
	Dockerfile      string       `json:"dockerfile,omitempty"`
	Workspace       string       `json:"workspace,omitempty"`
	Result          string       `json:"result,omitempty"`
	ExitCode        *int         `json:"exit_code,omitempty"`
	Duration        string       `json:"duration,omitempty"`
}

type auditMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

// makeAuditRecord sets the time and stream fields on an audit record.
func makeAuditRecord(event string) auditRecord {
	return auditRecord{
		Time:   time.Now().UTC().Format(time.RFC3339),
		Stream: "audit",
		Event:  event,
	}
}
