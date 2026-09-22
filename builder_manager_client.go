package main

// builder_manager_client.go implements the root-side internal manager
// client: the ONLY program surface that speaks the builder-manager wire
// protocol. Narrow methods only (Start/Stop/Purge); no generic Do() is
// exported to the rest of the program. Every operation is context/
// deadline aware: manager RPC is a no-child stage, so the P1
// termination latch cannot terminate a blocked Unix RPC.

import (
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
func (c *builderManagerClient) roundTrip(ctx context.Context, command, opID string, readTimeout time.Duration) (string, error) {
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

	request := command
	if opID != "" {
		request = command + " " + opID
	}
	if err := unixConn.SetWriteDeadline(time.Now().Add(builderClientWriteTimeout)); err != nil {
		return "", &builderClientUnreachable{cause: err}
	}
	if _, err := fmt.Fprintf(unixConn, "%s\n", request); err != nil {
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

	buf := make([]byte, builderManagerRequestCeiling+1)
	n, readErr := unixConn.Read(buf)
	if readErr != nil {
		return "", &builderClientAmbiguous{cause: readErr}
	}
	line := string(buf[:n])
	line = trimNewlineSuffix(line)
	if !isWellFormedManagerResponse(line) {
		return "", &builderClientAmbiguous{cause: errors.New("malformed response")}
	}
	return line, nil
}

func trimNewlineSuffix(line string) string {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}

// isWellFormedManagerResponse accepts exactly the fixed response
// vocabulary.
func isWellFormedManagerResponse(line string) bool {
	switch line {
	case builderManagerRespOK,
		builderManagerRespOKAbsent,
		builderManagerRespBadOpID,
		builderManagerRespOpExists,
		builderManagerRespAtCeiling,
		builderManagerRespInternal:
		return true
	}
	return false
}

// mapManagerResponse maps a well-formed response line to (typed error or
// nil). Protocol strings do not leak beyond this internal client
// boundary.
func mapManagerResponse(line string) error {
	switch line {
	case builderManagerRespOK, builderManagerRespOKAbsent:
		return nil
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

// Start issues START for the canonical operation ID. It owns ambiguity
// cleanup: for every ambiguous outcome (EOF, read timeout, context
// cancellation, connection reset, malformed/truncated response) it runs
// a fresh bounded STOP <same op_id> on a context derived from
// context.Background() — NEVER the cancelled caller context.
func (c *builderManagerClient) Start(ctx context.Context, operationID string) error {
	if !isOperationID(operationID) {
		return &builderManagerError{kind: builderManagerRespBadOpID}
	}
	line, err := c.roundTrip(ctx, builderManagerCmdStart, operationID, builderClientStartRead)
	if err == nil {
		return mapManagerResponse(line)
	}
	var ambiguous *builderClientAmbiguous
	if !errors.As(err, &ambiguous) {
		return err
	}
	// Ambiguous: the START bytes may have reached the manager. Converge
	// with a fresh bounded STOP on a fresh context.
	stopCtx, cancel := context.WithTimeout(context.Background(), builderClientStopRead)
	defer cancel()
	if _, stopErr := c.roundTrip(stopCtx, builderManagerCmdStop, operationID, builderClientStopRead); stopErr != nil {
		return fmt.Errorf("builder manager START was ambiguous and convergence STOP failed: %w", stopErr)
	}
	return &builderManagerError{kind: builderManagerRespInternal}
}

// Stop issues STOP with the lost-STOP convergence contract: send STOP;
// if the first response is ambiguous, issue ONE fresh bounded STOP
// retry; OK absent is success; if the second attempt is also unknowable,
// return an internal cleanup error. No retries beyond that.
func (c *builderManagerClient) Stop(ctx context.Context, operationID string) error {
	if !isOperationID(operationID) {
		return &builderManagerError{kind: builderManagerRespBadOpID}
	}
	line, err := c.roundTrip(ctx, builderManagerCmdStop, operationID, builderClientStopRead)
	if err == nil {
		return mapManagerResponse(line)
	}
	var ambiguous *builderClientAmbiguous
	if !errors.As(err, &ambiguous) {
		return err
	}
	retryCtx, cancel := context.WithTimeout(context.Background(), builderClientStopRead)
	defer cancel()
	line, retryErr := c.roundTrip(retryCtx, builderManagerCmdStop, operationID, builderClientStopRead)
	if retryErr == nil {
		return mapManagerResponse(line)
	}
	var retryAmbiguous *builderClientAmbiguous
	if errors.As(retryErr, &retryAmbiguous) {
		return fmt.Errorf("builder manager STOP twice unknowable: %w", retryErr)
	}
	return retryErr
}

// Purge issues runtime PURGE.
func (c *builderManagerClient) Purge(ctx context.Context) error {
	line, err := c.roundTrip(ctx, builderManagerCmdPurge, "", builderClientStopRead)
	if err == nil {
		return mapManagerResponse(line)
	}
	var ambiguous *builderClientAmbiguous
	if !errors.As(err, &ambiguous) {
		return err
	}
	return fmt.Errorf("builder manager PURGE unknowable: %w", err)
}
