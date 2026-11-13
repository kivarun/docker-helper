package main

// builder_manager_client.go implements the root-side internal manager
// client: the ONLY program surface that speaks the builder-manager wire
// protocol. Narrow methods only (Start/Stop/Purge); no generic Do() is
// exported to the rest of the program. Every operation is context/
// deadline aware: manager RPC is a no-child stage, so the P1
// termination latch cannot terminate a blocked Unix RPC.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/user"
	"strconv"
	"time"
)

// Fixed deadlines (implementation constants from the reviewed plan; no
// config).
const (
	builderClientDialTimeout  = 2 * time.Second
	builderClientWriteTimeout = 2 * time.Second
	builderClientStartRead    = 60 * time.Second
	builderClientStopRead     = 10 * time.Second
)

// builderClientAmbiguous reports an outcome where the request bytes MAY
// have reached the manager but the response is unknowable (EOF, read
// timeout, context cancellation, connection reset, malformed/truncated
// response). It is internal to the client; protocol strings never leak.
type builderClientAmbiguous struct {
	cause error
}

func (e *builderClientAmbiguous) Error() string {
	return "builder manager response unknowable: " + e.cause.Error()
}

func (e *builderClientAmbiguous) Unwrap() error { return e.cause }

// builderClientUnreachable reports that the request definitely did not
// reach a manager (dial/connect failure before any write).
type builderClientUnreachable struct{ cause error }

func (e *builderClientUnreachable) Error() string {
	return "builder manager unreachable: " + e.cause.Error()
}

func (e *builderClientUnreachable) Unwrap() error { return e.cause }

// managerError maps a well-formed ERR response to a typed internal error.
// A complete well-formed ERR response is NEVER ambiguous.
type builderManagerError struct {
	kind string // fixed protocol vocabulary value
}

func (e *builderManagerError) Error() string {
	return "builder manager refused: " + e.kind
}

// builderClientManagerUID resolves the expected manager peer UID/GID.
// Injectable for tests; production resolves the canonical builder user.
var builderClientManagerUID = func() (int, int, error) {
	u, err := user.Lookup(builderManagerBuilderUser)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

// builderClientPeerCredentials is the client-side peer-credential seam.
var builderClientPeerCredentials = peerCredentialsUnix

// builderClientSocketPath is the canonical fixed socket path (seam for
// tests to mount a test endpoint; production always uses the constant).
var builderClientSocketPath = builderManagerSocketPath

// builderManagerClient is the root-side internal client.
type builderManagerClient struct{}

// verifyManagerPeer performs the client-side SO_PEERCRED verification
// AFTER connect and BEFORE any request write: the manager endpoint must
// be the resolved builder identity. Defense against a builder-UID
// process impersonating the expected endpoint toward the root daemon.
func (c *builderManagerClient) verifyManagerPeer(conn *net.UnixConn) error {
	uid, gid, _, err := builderClientPeerCredentials(conn)
	if err != nil {
		return err
	}
	wantUID, wantGID, err := builderClientManagerUID()
	if err != nil {
		return err
	}
	if uid != wantUID {
		return fmt.Errorf("manager peer uid %d != builder uid %d", uid, wantUID)
	}
	if gid != wantGID {
		return fmt.Errorf("manager peer gid %d != builder gid %d", gid, wantGID)
	}
	return nil
}

// roundTrip performs one full request/response exchange with the fixed
// deadlines: dial 2s, write 2s, read per command kind. It returns the
// exact response line (trimmed of the trailing newline).
//
// Outcomes:
//   - well-formed response (OK / OK absent / ERR ...): returned as-is;
//   - unreachable before any write: builderClientUnreachable;
//   - written but response unknowable: builderClientAmbiguous.
func (c *builderManagerClient) roundTrip(ctx context.Context, request builderManagerRequest, readTimeout time.Duration) (string, error) {
	dialer := net.Dialer{Timeout: builderClientDialTimeout}
	dialCtx, cancelDial := context.WithTimeout(ctx, builderClientDialTimeout)
	defer cancelDial()
	conn, err := dialer.DialContext(dialCtx, "unix", builderClientSocketPath)
	if err != nil {
		// Nothing was written: definitely did not reach the manager.
		return "", &builderClientUnreachable{cause: err}
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return "", &builderClientUnreachable{cause: errors.New("non-unix connection")}
	}
	defer unixConn.Close()

	// Peer verification BEFORE any request write.
	if err := c.verifyManagerPeer(unixConn); err != nil {
		return "", &builderClientUnreachable{cause: err}
	}

	if err := ctx.Err(); err != nil {
		// Caller context already done before write; nothing sent.
		return "", &builderClientUnreachable{cause: err}
	}

	if err := unixConn.SetWriteDeadline(time.Now().Add(builderClientWriteTimeout)); err != nil {
		return "", &builderClientUnreachable{cause: err}
	}
	if _, err := fmt.Fprintf(unixConn, "%s\n", request.wireLine()); err != nil {
		return "", &builderClientAmbiguous{cause: err}
	}

	// Bounded read with per-command deadline and caller-context
	// cancellation.
	if err := unixConn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return "", &builderClientAmbiguous{cause: err}
	}
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			// Force the read deadline into the past to unblock the read.
			_ = unixConn.SetReadDeadline(time.Unix(1, 0))
		case <-stopWatch:
		}
	}()

	// Bounded complete-line read (P21-E-R1-C1): the response is exactly
	// one newline-terminated line on this connection. The read loop
	// accumulates under the existing per-command deadline and
	// caller-context cancellation (the deadline watcher above unblocks
	// every Read), never interprets an incomplete prefix, rejects EOF
	// before the terminating newline as ambiguous, and enforces the wire
	// ceiling on the line. Bytes after the first newline are ignored (one
	// response line per connection).

	readBuf := make([]byte, builderManagerResponseCeiling+1)
	filled := 0
	var line []byte
	for {
		n, readErr := unixConn.Read(readBuf[filled:])
		filled += n
		if idx := bytes.IndexByte(readBuf[:filled], '\n'); idx >= 0 {
			line = readBuf[:idx]
			break
		}
		if readErr != nil {
			// EOF, timeout, or cancellation before the terminating
			// newline: the response is incomplete — ambiguous.
			return "", &builderClientAmbiguous{cause: readErr}
		}
		if filled == len(readBuf) {
			return "", &builderClientAmbiguous{cause: errors.New("response line exceeds the wire ceiling")}
		}
	}
	text := trimNewlineSuffix(string(line))
	if !isWellFormedManagerResponse(request.Command, text) {
		return "", &builderClientAmbiguous{cause: errors.New("malformed response")}
	}
	return text, nil
}

func trimNewlineSuffix(line string) string {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}

// isWellFormedManagerResponse accepts exactly the per-command response
// vocabulary: the ERR forms are command-independent, while the success
// forms differ — START success is "OK <category>" (the token validated
// exclusively by parseBuilderCategory; a bare "OK" is malformed for
// START), STOP success is "OK"/"OK absent", and PURGE success is "OK".
// A success form of one command is malformed for every other command and
// fails closed into the ambiguity machinery — P21-E-A2-C5-C1.
func isWellFormedManagerResponse(command, line string) bool {
	switch line {
	case builderManagerRespBadOpID,
		builderManagerRespOpExists,
		builderManagerRespAtCeiling,
		builderManagerRespInternal:
		return true
	case builderManagerRespOK:
		return command != builderManagerCmdStart
	case builderManagerRespOKAbsent:
		// "OK absent" is the STOP-only success form: it carries the
		// START/STOP ordering guarantee, which PURGE has no counterpart
		// for and START must never accept (P21-E-R1-C1).
		return command == builderManagerCmdStop
	}
	if command != builderManagerCmdStart {
		return false
	}
	token, ok := builderManagerStartCategoryToken(line)
	if !ok {
		return false
	}
	_, valid := parseBuilderCategory(token)
	return valid
}

// mapManagerResponse maps a well-formed STOP/PURGE response line to a
// typed error or nil. Protocol strings do not leak beyond this internal
// client boundary.
func mapManagerResponse(command, line string) error {
	switch line {
	case builderManagerRespOK:
		if command == builderManagerCmdStart {
			// Unreachable: the START validation never accepts a bare
			// success form; kept defensive so a caller mistake cannot
			// report convergence for the wrong command.
			return &builderManagerError{kind: builderManagerRespInternal}
		}
		return nil
	case builderManagerRespOKAbsent:
		if command == builderManagerCmdStop {
			return nil
		}
		// Unreachable: validation restricts "OK absent" to STOP; kept
		// defensive so a caller mistake cannot report convergence for the
		// wrong command.
		return &builderManagerError{kind: builderManagerRespInternal}
	}
	return mapManagerErrorResponse(line)
}

// mapManagerErrorResponse maps the command-independent ERR vocabulary to
// typed errors.
func mapManagerErrorResponse(line string) error {
	switch line {
	case builderManagerRespOpExists:
		return &builderManagerError{kind: builderManagerRespOpExists}
	case builderManagerRespAtCeiling:
		return &builderManagerError{kind: builderManagerRespAtCeiling}
	case builderManagerRespBadOpID:
		return &builderManagerError{kind: builderManagerRespBadOpID}
	case builderManagerRespInternal:
		return &builderManagerError{kind: builderManagerRespInternal}
	}
	// Unreachable: isWellFormedManagerResponse gates callers.
	return &builderManagerError{kind: builderManagerRespInternal}
}

// mapManagerStartResponse maps a well-formed START response line to the
// authoritative category (nil error) or a typed error. No category is
// ever returned with an error.
func mapManagerStartResponse(line string) (builderCategory, error) {
	if token, ok := builderManagerStartCategoryToken(line); ok {
		category, valid := parseBuilderCategory(token)
		if valid {
			return category, nil
		}
		// Unreachable: the START validation accepted only canonical
		// tokens; kept defensive so a mapping slip cannot fabricate a
		// category.
		return 0, &builderManagerError{kind: builderManagerRespInternal}
	}
	return 0, mapManagerErrorResponse(line)
}

// Start issues START for the canonical operation ID and returns the
// authoritative per-operation MCS category on the typed success response.
// It owns ambiguity cleanup: for every ambiguous outcome (EOF, read
// timeout, context cancellation, connection reset, malformed/truncated
// response) it runs a fresh bounded STOP <same op_id> on a context
// derived from context.Background() — NEVER the cancelled caller context.
// No category is ever returned with an error, on cancellation, on an
// ambiguous START, or on a refused compensation (the zero category is the
// never-issued value).
func (c *builderManagerClient) Start(ctx context.Context, operationID string, excluded *builderCategorySet) (builderCategory, error) {
	if !isOperationID(operationID) {
		return 0, &builderManagerError{kind: builderManagerRespBadOpID}
	}
	request := builderManagerRequest{Command: builderManagerCmdStart, OperationID: operationID}
	if excluded != nil {
		request.ExcludedCategories = *excluded
		request.HasExclusions = true
	}
	line, err := c.roundTrip(ctx, request, builderClientStartRead)
	if err == nil {
		category, responseErr := mapManagerStartResponse(line)
		if responseErr != nil || excluded == nil || !excluded.contains(category) {
			return category, responseErr
		}
		err = &builderClientAmbiguous{cause: errors.New("manager START returned an excluded category")}
	}
	var ambiguous *builderClientAmbiguous
	if !errors.As(err, &ambiguous) {
		return 0, err
	}
	// Ambiguous: the START bytes may have reached the manager. Converge
	// with a fresh bounded STOP on a fresh context. Only a well-formed
	// proven-convergence reply (OK / OK absent) closes the ambiguity: a
	// well-formed ERR reply means the manager answered but could not
	// prove convergence — the operation instance may still be live — and
	// must surface as the explicit refused-compensation failure, never as
	// the proven-convergence verdict.
	stopCtx, cancel := context.WithTimeout(context.Background(), builderClientStopRead)
	defer cancel()
	stopRequest := builderManagerRequest{Command: builderManagerCmdStop, OperationID: operationID}
	stopLine, stopErr := c.roundTrip(stopCtx, stopRequest, builderClientStopRead)
	if stopErr != nil {
		return 0, fmt.Errorf("builder manager START was ambiguous and convergence STOP failed: %w", stopErr)
	}
	if compErr := mapManagerResponse(builderManagerCmdStop, stopLine); compErr != nil {
		return 0, fmt.Errorf("builder manager START was ambiguous and the compensating STOP was refused: %w", compErr)
	}
	return 0, &builderManagerError{kind: builderManagerRespInternal}
}

// Stop issues STOP with the lost-STOP convergence contract: send STOP;
// if the first response is ambiguous, issue ONE fresh bounded STOP
// retry; OK absent is success; if the second attempt is also unknowable,
// return an internal cleanup error. No retries beyond that.
func (c *builderManagerClient) Stop(ctx context.Context, operationID string) error {
	if !isOperationID(operationID) {
		return &builderManagerError{kind: builderManagerRespBadOpID}
	}
	request := builderManagerRequest{Command: builderManagerCmdStop, OperationID: operationID}
	line, err := c.roundTrip(ctx, request, builderClientStopRead)
	if err == nil {
		return mapManagerResponse(builderManagerCmdStop, line)
	}
	var ambiguous *builderClientAmbiguous
	if !errors.As(err, &ambiguous) {
		return err
	}
	retryCtx, cancel := context.WithTimeout(context.Background(), builderClientStopRead)
	defer cancel()
	line, retryErr := c.roundTrip(retryCtx, request, builderClientStopRead)
	if retryErr == nil {
		return mapManagerResponse(builderManagerCmdStop, line)
	}
	var retryAmbiguous *builderClientAmbiguous
	if errors.As(retryErr, &retryAmbiguous) {
		return fmt.Errorf("builder manager STOP twice unknowable: %w", retryErr)
	}
	return retryErr
}

// Purge issues runtime PURGE.
func (c *builderManagerClient) Purge(ctx context.Context) error {
	line, err := c.roundTrip(ctx, builderManagerRequest{Command: builderManagerCmdPurge}, builderClientStopRead)
	if err == nil {
		return mapManagerResponse(builderManagerCmdPurge, line)
	}
	var ambiguous *builderClientAmbiguous
	if !errors.As(err, &ambiguous) {
		return err
	}
	return fmt.Errorf("builder manager PURGE unknowable: %w", err)
}
