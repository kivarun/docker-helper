//go:build linux

package main

import (
	"fmt"
)

// wrapperFifoConstraintStatement is the exact canonical loaded-policy
// rendering of the shipped FIFO read/write isolation constraint (the
// distribution-evidenced candidate: the MNB35 compiled CIL measured
// through the MNB36 live gate). seinfo --constrain renders each policy
// constraint statement on its own entry line; leading indentation is
// normalized before comparison, the statement text itself must match
// byte for byte.
const wrapperFifoConstraintStatement = "mlsconstrain fifo_file { read write } (h1 dom h2 or t1 != mcs_constrained_type);"

// wrapperFifoConstraintRemediation names the exact operator repair for a
// missing loaded-policy constraint: the packaged artifact path and the
// fixed priority of the separately owned constraint module.
const wrapperFifoConstraintRemediation = "semodule -X 400 -i /usr/share/selinux/docker-helper-fifo-rw-constraint.cil"

// wrapperFifoConstraintCheck is the injectable constraint admission gate:
// the LOADED policy (the authority that actually decides the workload
// FIFO domain's file accesses) must carry the shipped fifo_file read
// write MCS constraint. The wrapped workload payload category-isolates
// concurrent operations and their FIFO pipes through this constraint; an
// unconstrained kernel policy would silently weaken the category
// isolation every run depends on, so a missing, unmeasurable, or
// otherwise untrusted constraint state refuses every managed run.
// Fail-closed classification: an absent query tool and every query
// failure are trusted-query refusals, never an authoritative allowance.
// Package-global; tests restore it.
var wrapperFifoConstraintCheck = func() error {
	out, err := wrapperSeinfoQuery("fifo constraint", "--constrain", "fifo_file")
	if err != nil {
		return err
	}
	return wrapperFifoConstraintVerdict(out)
}

// wrapperFifoConstraintVerdict is the exact-statement classifier over one
// trusted seinfo --constrain output: the canonical shipped statement must
// appear as an exact (indentation-normalized) entry line; any other
// output is a refusal naming the remediation.
func wrapperFifoConstraintVerdict(out []byte) error {
	if wrapperPolicyExactLine(out, wrapperFifoConstraintStatement) {
		return nil
	}
	return fmt.Errorf(
		"the loaded policy does not carry the shipped fifo_file read/write isolation constraint; refusing the run (repair: %s)",
		wrapperFifoConstraintRemediation,
	)
}
