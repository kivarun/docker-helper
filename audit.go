package main

type auditRecord struct {
	Time   string `json:"time"`
	Stream string `json:"stream"`
	Event  string `json:"event"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	// SelfType is the authenticated credential class of a successful GET
	// /self introspection (principal, launcher, or session). It names the
	// caller's own authority class only and carries no credential material.
	SelfType          string       `json:"self_type,omitempty"`
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
	HelperSocket      bool         `json:"helper_socket,omitempty"`
	// WorkloadMACBackend is the one bounded workload MAC fact of a run: the
	// backend that materialized the accepted exposure plan. Generated
	// internal profile/projection paths are deliberately not audited.
	WorkloadMACBackend string `json:"workload_mac_backend,omitempty"`
	Registry           string `json:"registry,omitempty"`
	Context            string `json:"context,omitempty"`
	Dockerfile         string `json:"dockerfile,omitempty"`
	// BuildContextResolved/BuildDockerfileResolved carry the canonical policy
	// identity and effective snapshot access of the build host inputs.
	// Build consumption is read-only by definition: the helper reads the
	// context and Dockerfile from either snapshot access mode and never
	// writes into them.
	BuildContextResolved    string `json:"build_context_resolved,omitempty"`
	BuildContextAccess      string `json:"build_context_access,omitempty"`
	BuildDockerfileResolved string `json:"build_dockerfile_resolved,omitempty"`
	BuildDockerfileAccess   string `json:"build_dockerfile_access,omitempty"`
	Workspace               string `json:"workspace,omitempty"`
	PrincipalName           string `json:"principal_name,omitempty"`
	PrincipalEnabled        *bool  `json:"principal_enabled,omitempty"`
	PrincipalAllowedRoot    string `json:"principal_path,omitempty"`
	CredentialID            string `json:"credential_id,omitempty"`
	CredentialName          string `json:"credential_name,omitempty"`
	InitiatorCredentialID   string `json:"initiator_credential_id,omitempty"`
	CredentialChanged       *bool  `json:"credential_changed,omitempty"`
	LauncherID              string `json:"launcher_id,omitempty"`
	LauncherName            string `json:"launcher_name,omitempty"`
	LauncherScope           string `json:"launcher_scope,omitempty"`
	LauncherEnabled         *bool  `json:"launcher_enabled,omitempty"`
	LauncherAllowedRoot     string `json:"launcher_path,omitempty"`
	// RequestedAccess and StoredAccess carry the allowed-root access-mode
	// facts of the 2.2 control-plane mutations: the access value the caller
	// requested and the access actually stored after the mutation. They are
	// distinguished so an idempotent no-op that observed a different stored
	// value (for example re-adding a read_only root) can never be audited as
	// if the requested access had been stored.
	RequestedAccess string `json:"requested_access,omitempty"`
	StoredAccess    string `json:"stored_access,omitempty"`
	Result          string `json:"result,omitempty"`
	ExitCode        *int   `json:"exit_code,omitempty"`
	Duration        string `json:"duration,omitempty"`
}

type auditMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
	// ResolvedSource is the canonical policy identity of the source, the
	// identity the filesystem policy owner decided on. The caller spelling in
	// Source is kept for provenance; policy is never decided on it.
	ResolvedSource string `json:"resolved_source,omitempty"`
	// Access is the effective read_write/read_only mode the issued Session
	// filesystem snapshot grants to the resolved canonical source.
	Access string `json:"access,omitempty"`
	// WritableAllowed records whether the snapshot owner permits writable
	// exposure of the resolved source. It is a pointer so an explicit false
	// (for example a read_write source spanning a nested read_only region)
	// is never lost to omitempty.
	WritableAllowed *bool `json:"writable_allowed,omitempty"`
}
