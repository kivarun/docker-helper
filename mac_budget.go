package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// macTransitionBudget is the fixed Release-2.2 wall-clock security budget of
// ONE serialized MAC transition: one Session create (preparation of every
// issued tree plus its rollback), one Session release (removal of every
// owned boundary plus deferred retries), one startup-reconciliation session
// pass (verification, repair, and stale-boundary cleanup), one workload
// prepare or cleanup, and the trusted-CA restorecon of one configuration
// preparation. Individual external MAC commands consume the REMAINING
// budget: a subprocess started late in a transition inherits only what is
// left, so the whole serialized transition is bounded, not merely each
// subprocess independently. This matters because the reachable command
// multiplication of one transition is bounded only by the Session
// filesystem-roots request grammar (the 16 KiB request-body cap admits
// hundreds of distinct issued trees), so per-command timeouts alone cannot
// prove a bounded hold of lifecycle coordination.
//
// Selected from measurement on the exact supported UAT environments
// (observed ordinary create/release including full backend preparation well
// under one second on both backends; the largest UAT-scale relabel — a
// 50000-entry workspace — is orders of magnitude below the budget):
// 60 seconds keeps every legitimate transition far inside the budget while
// bounding an emergency administrative disable's delay to at most one
// budget. It is an internal security constant, not a configuration surface:
// no config key, CLI flag, or API field may change it. Tests may narrow it
// deterministically through this seam (never in parallel tests).
var macTransitionBudget = 60 * time.Second

// ErrMACTransitionBudgetExceeded is returned when an external MAC command
// was terminated because it exhausted the fixed MAC transition budget. A
// budget-expired command is a failure, never successful MAC preparation:
// ownership state on the host is either proven restored or explicitly
// retained fail-closed for the canonical retry/reconciliation owners.
var ErrMACTransitionBudgetExceeded = errors.New("external MAC command terminated: fixed MAC transition budget exhausted")

// newMACTransitionContext returns the daemon-owned budget context for ONE
// serialized MAC transition. The context is always derived from
// context.Background(): the daemon owns the budget, so a client disconnect
// can neither extend nor replace it (the request lifetime is not the
// security owner).
func newMACTransitionContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), macTransitionBudget)
}

// macCommandError classifies the outcome of one context-bounded external
// MAC command execution. When the transition context expired, the result is
// the typed budget error regardless of the raw exec error (the process was
// killed); otherwise the caller's own error carries through unchanged.
func macCommandError(ctx context.Context, command string, err error) error {
	if err != nil && ctx.Err() != nil {
		return fmt.Errorf("%w: %s: %v", ErrMACTransitionBudgetExceeded, command, ctx.Err())
	}
	return err
}

// configureMACCommandSysProcAttr applies the platform kill guarantee of
// bounded MAC command execution. Production command owners MUST apply it to
// every external MAC command: the daemon must never leave an external MAC
// child behind, whatever happens to the daemon process itself.
func configureMACCommandSysProcAttr(cmd *exec.Cmd) error {
	return setMACCommandPdeathsig(cmd)
}
