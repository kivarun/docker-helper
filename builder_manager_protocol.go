package main

import (
	"bytes"
	"errors"
	"strings"
)

// Builder-manager wire protocol (internal backend, not a public surface).
//
// One request per connection, one response line:
//
//	START <operation_id>\n
//	STOP <operation_id>\n
//	PURGE\n
//
// The operation ID grammar is the canonical Operation ID validator
// (isOperationID) owned by operation.go — no second grammar exists.
// Responses come exactly from the fixed vocabulary below; the protocol
// never carries filesystem paths, PIDs, argv, or internal errors.
//
// The success vocabulary is command-specific:
//
//	START  →  "OK " + the canonical category token (builderCategory.String();
//	          validated exclusively by parseBuilderCategory on the client) —
//	          the authoritative per-operation MCS category allocated for
//	          exactly this START, emitted only after proven manager readiness
//	          (P21-E-A2-C5);
//	STOP   →  "OK" or "OK absent" (unchanged);
//	PURGE  →  "OK" (unchanged).
//
// A success form of one command is malformed for every other command and
// fails closed into the existing ambiguity/refusal machinery (P21-E-A2-C5-C1).
const (
	builderManagerRequestCeiling = 128 // bytes; the grammar needs far less

	builderManagerCmdStart = "START"
	builderManagerCmdStop  = "STOP"
	builderManagerCmdPurge = "PURGE"

	builderManagerRespOK           = "OK"
	builderManagerRespOKAbsent     = "OK absent"
	builderManagerRespBadOpID      = "ERR bad_operation_id"
	builderManagerRespOpExists     = "ERR operation_exists"
	builderManagerRespAtCeiling    = "ERR builder_at_ceiling"
	builderManagerRespInternal     = "ERR internal"
	builderManagerRespBadRequest   = "ERR bad_request"
	builderManagerRespUnknownCmd   = "ERR unknown_command"
	builderManagerRespUnauthorized = "ERR unauthorized"
)

// builderManagerStartSuccessResponse renders the START success response
// "OK <category>": the single emission point of the authoritative
// category token on the wire.
func builderManagerStartSuccessResponse(category builderCategory) string {
	return builderManagerRespOK + " " + category.String()
}

// builderManagerStartCategoryToken extracts the category token from a
// well-formed START success response ("OK <token>"). It reports false for
// every other shape; the token itself is validated by the caller through
// parseBuilderCategory.
func builderManagerStartCategoryToken(line string) (string, bool) {
	return strings.CutPrefix(line, builderManagerRespOK+" ")
}

// builderManagerRequest is one parsed manager request.
type builderManagerRequest struct {
	Command     string // START | STOP | PURGE
	OperationID string // canonical op_ + 32 hex; empty for PURGE
}

// parseBuilderManagerRequest parses one request line (without the
// trailing newline). It rejects unknown commands, extra/missing tokens,
// embedded NULs, and noncanonical operation IDs.
func parseBuilderManagerRequest(line []byte) (builderManagerRequest, string) {
	if bytes.IndexByte(line, 0) >= 0 {
		return builderManagerRequest{}, builderManagerRespBadRequest
	}
	fields := bytes.Fields(line)
	switch len(fields) {
	case 1:
		if string(fields[0]) == builderManagerCmdPurge {
			return builderManagerRequest{Command: builderManagerCmdPurge}, ""
		}
		return builderManagerRequest{}, builderManagerRespBadRequest
	case 2:
		cmd := string(fields[0])
		opID := string(fields[1])
		if cmd == builderManagerCmdPurge {
			// PURGE takes no argument.
			return builderManagerRequest{}, builderManagerRespBadRequest
		}
		if cmd != builderManagerCmdStart && cmd != builderManagerCmdStop {
			return builderManagerRequest{}, builderManagerRespUnknownCmd
		}
		if !isOperationID(opID) {
			return builderManagerRequest{}, builderManagerRespBadOpID
		}
		return builderManagerRequest{Command: cmd, OperationID: opID}, ""
	default:
		return builderManagerRequest{}, builderManagerRespBadRequest
	}
}

var errBuilderManagerUnauthorized = errors.New("builder manager: unauthorized peer")
var errBuilderManagerMalformedResponse = errors.New("builder manager: malformed response")
