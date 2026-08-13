package main

type auditRecord struct {
	Time              string       `json:"time"`
	Stream            string       `json:"stream"`
	Event             string       `json:"event"`
	Method            string       `json:"method,omitempty"`
	Path              string       `json:"path,omitempty"`
	SessionID         string       `json:"session_id,omitempty"`
	RequestID         string       `json:"request_id,omitempty"`
	OperationID       string       `json:"operation_id,omitempty"`
	Image             string       `json:"image,omitempty"`
	CommandArgCount   *int         `json:"command_arg_count,omitempty"`
	Mounts            []auditMount `json:"mounts,omitempty"`
	EnvKeys           []string     `json:"env_keys,omitempty"`
	BuildArgKeys      []string     `json:"build_arg_keys,omitempty"`
	ShmSize           string       `json:"shm_size,omitempty"`
	TrustedCAInjected bool         `json:"trusted_ca_injected,omitempty"`
	Registry          string       `json:"registry,omitempty"`
	Context           string       `json:"context,omitempty"`
	Dockerfile        string       `json:"dockerfile,omitempty"`
	Workspace         string       `json:"workspace,omitempty"`
	PrincipalName     string       `json:"principal_name,omitempty"`
	PrincipalEnabled  *bool        `json:"principal_enabled,omitempty"`
	PrincipalPath     string       `json:"principal_path,omitempty"`
	CredentialID      string       `json:"credential_id,omitempty"`
	CredentialName    string       `json:"credential_name,omitempty"`
	CredentialChanged *bool        `json:"credential_changed,omitempty"`
	Result            string       `json:"result,omitempty"`
	ExitCode          *int         `json:"exit_code,omitempty"`
	Duration          string       `json:"duration,omitempty"`
}

type auditMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}
