package main

import "strings"

// dockerErrorKind is a coarse classification of a docker CLI failure derived
// from the docker CLI's stderr output.
type dockerErrorKind int

const (
	// dockerErrorUnknown means the failure does not match a recognized,
	// stable docker error line.
	dockerErrorUnknown dockerErrorKind = iota
	// dockerErrorImageNotFound means the image/repository was not found.
	dockerErrorImageNotFound
	// dockerErrorAuthDenied means the registry rejected authentication or
	// authorization for the requested operation.
	dockerErrorAuthDenied
	// dockerErrorNetwork means the registry/backend was unreachable or failed.
	dockerErrorNetwork
)

// classifyDockerError inspects docker CLI stderr output and returns a coarse
// domain classification. The docker CLI exposes no structured error to its
// caller, so classification matches the stable error lines emitted by the
// docker daemon/registry path. Only categories the evidence supports are
// distinguished; anything unrecognized remains dockerErrorUnknown.
func classifyDockerError(output string) dockerErrorKind {
	lower := strings.ToLower(output)

	if strings.Contains(lower, "dial tcp") ||
		strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "no such host") ||
		strings.Contains(lower, "i/o timeout") ||
		strings.Contains(lower, "tls handshake timeout") ||
		strings.Contains(lower, "connection reset") ||
		strings.Contains(lower, "proxyconnect") ||
		strings.Contains(lower, "net/http: request canceled") {
		return dockerErrorNetwork
	}

	if strings.Contains(lower, "unauthorized") ||
		strings.Contains(lower, "authentication required") ||
		strings.Contains(lower, "401 unauthorized") ||
		strings.Contains(lower, "failed with status: 401") ||
		strings.Contains(lower, "pull access denied") ||
		strings.Contains(lower, "denied: requested access") ||
		strings.Contains(lower, "authorization failed") ||
		strings.Contains(lower, "no basic auth credentials") {
		return dockerErrorAuthDenied
	}

	if strings.Contains(lower, "manifest unknown") ||
		strings.Contains(lower, "no such manifest") ||
		strings.Contains(lower, "repository does not exist") ||
		strings.Contains(lower, "name does not exist") ||
		strings.Contains(lower, "manifest for ") && strings.Contains(lower, "not found") {
		return dockerErrorImageNotFound
	}

	return dockerErrorUnknown
}
