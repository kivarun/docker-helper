package main

import "time"

// Shared API request/response types for the docker-helper HTTP contract.
// Both server handlers and client methods use these types.

// pullRequest is the request body for POST /pull.
type pullRequest struct {
	Image string `json:"image"`
}

// buildRequest is the request body for POST /build.
type buildRequest struct {
	Context    string            `json:"context"`
	Dockerfile string            `json:"dockerfile"`
	Image      string            `json:"image"`
	BuildArgs  map[string]string `json:"build_args,omitempty"`
}

// runRequest is the request body for POST /run.
type runRequest struct {
	Image       string            `json:"image"`
	Entrypoint  string            `json:"entrypoint,omitempty"`
	Workdir     string            `json:"workdir,omitempty"`
	Command     []string          `json:"command,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Mounts      []mountRequest    `json:"mounts,omitempty"`
	ShmSize     string            `json:"shm_size,omitempty"`
}

// mountRequest is a mount specification for POST /run.
type mountRequest struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// pullResponse is the response from POST /pull.
type pullResponse struct {
	OK       bool   `json:"ok"`
	Code     string `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
	Output   string `json:"output,omitempty"`
	Duration string `json:"duration,omitempty"`
}

// operationCreatedResponse is the response from POST /build and POST /run.
type operationCreatedResponse struct {
	OK          bool           `json:"ok"`
	OperationID string         `json:"operation_id"`
	Status      operationState `json:"status"`
}

// operationStatusResponse is the response from GET /operations/{id}.
type operationStatusResponse struct {
	OK          bool           `json:"ok"`
	OperationID string         `json:"operation_id"`
	Status      operationState `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	Duration    *string        `json:"duration,omitempty"`
	ExitCode    *int           `json:"exit_code,omitempty"`
	ResultCode  *string        `json:"result_code,omitempty"`
}

// operationLogsResponse is the response from GET /operations/{id}/logs.
type operationLogsResponse struct {
	OK          bool   `json:"ok"`
	OperationID string `json:"operation_id"`
	Offset      int64  `json:"offset"`
	NextOffset  int64  `json:"next_offset"`
	Truncated   bool   `json:"truncated"`
	Logs        string `json:"logs"`
}
