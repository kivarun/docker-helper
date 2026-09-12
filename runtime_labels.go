package main

// Reserved helper-owned Docker container labels.
//
// These labels are set by docker-helper on every container it starts and are
// reserved: they are one code owner (runtime_labels.go) with one schema value
// (runtimeLabelSchemaValue), and their values always come from the already
// resolved Session ownership chain, never from caller input. They are evidence
// for checked cleanup/attribution of helper runtime, not an authorization
// mechanism.
//
// The exact key strings and the schema value are public anti-tamper
// identifiers shared with the Docker daemon; do not rename them.
const (
	// runtimeLabelSchema is the invariant schema marker value for every
	// helper-owned label set. A container without this value set to
	// runtimeLabelSchemaValue is not recognized as a current-owner helper
	// runtime.
	runtimeLabelSchema = "com.dockerhelper.schema"
	// runtimeLabelSchemaValue is the single canonical schema value.
	runtimeLabelSchemaValue = "1"
	// runtimeLabelSessionID carries the owning Session ID.
	runtimeLabelSessionID = "com.dockerhelper.session.id"
	// runtimeLabelLauncherID carries the owning Launcher ID.
	runtimeLabelLauncherID = "com.dockerhelper.launcher.id"
	// runtimeLabelPrincipalName carries the owning Principal name.
	runtimeLabelPrincipalName = "com.dockerhelper.principal.name"
)

// runtimeLabelsFor returns the reserved label set for the given Session
// ownership chain. Values are derived from the already-resolved Session, never
// from caller input.
func runtimeLabelsFor(s *Session) []string {
	return []string{
		runtimeLabelSchema + "=" + runtimeLabelSchemaValue,
		runtimeLabelSessionID + "=" + s.ID,
		runtimeLabelLauncherID + "=" + s.LauncherID,
		runtimeLabelPrincipalName + "=" + s.PrincipalName,
	}
}
