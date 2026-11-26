//go:build linux

package main

// wrapperFifoConstraintStatement is the exact canonical loaded-policy
// rendering of the shipped FIFO read/write isolation constraint (the
// distribution-evidenced candidate: the MNB35 compiled CIL measured
// through the MNB36 live gate, and re-measured in-process through the
// MNB39a loaded-policy parse). It renders each policy constraint
// statement on one line; the statement text must match byte for byte.
const wrapperFifoConstraintStatement = "mlsconstrain fifo_file { read write } (h1 dom h2 or t1 != mcs_constrained_type);"

// wrapperFifoConstraintRemediation names the exact operator repair for a
// missing loaded-policy constraint: the packaged artifact path and the
// fixed priority of the separately owned constraint module.
const wrapperFifoConstraintRemediation = "semodule -X 400 -i /usr/share/selinux/docker-helper-fifo-rw-constraint.cil"
