//go:build linux

package main

// wrapper_checkcontext_linux.go owns the in-process kernel-native
// validation of the composed workload process context (MNB40): the
// wrapper no longer forks seinfo for the role authorization query; it
// issues one context-validation transaction against the kernel's
// selinuxfs context node and requires the canonical read-back to equal
// the composed context byte-exactly.
//
// transaction semantics (kernel libfs.c + selinuxfs.c, measured in the
// MNB39a round on the enforcing guest):
//
//   - the node is opened O_RDWR (open fails per the caller's security
//     class grant);
//   - exactly ONE write per open is accepted (a second write answers
//     EBUSY); the written payload is NUL-terminated, mirroring the
//     libselinux check_context client (strlen+1);
//   - the write handler first evaluates security_t:security:check_context
//     (EACCES without the grant — a permission question, NEVER an
//     invalid-context verdict), then validates the context against the
//     LOADED policy (unknown type, unauthorized role/type pair, invalid
//     category all answer EINVAL), then returns the canonical context as
//     the read-back payload.
//
// Classification contract — every failure is a typed pre-commit refusal
// and no failure category is ever turned into an allowance:
//
//	unavailable   ENOENT-class open/write failures: the interface is
//	              absent or broken on this kernel
//	permission    EACCES/EPERM at open or write: the check_context
//	              grant is missing (a policy question, not context
//	              validity)
//	invalid       EINVAL at write: the loaded policy rejects the
//	              context (unknown type, unauthorized role/type pair,
//	              invalid sensitivity/category)
//	short-io      a short write or a short read-back
//	broken        any other errno, a non-accepting read, or a read-back
//	              whose canonical form is not the composed context
//
// The validated context is NOT an authorization: a check_context accept
// only proves the context is valid in the loaded policy. The subsequent
// process transition is decided independently by the kernel's own
// transition checks; this gate never substitutes for them.

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// selinuxContextValidationNode is the kernel's selinuxfs context
// transaction node: the interface the MNB39a round proved as the
// check_context semantics carrier on the enforcing guest (the
// non-existent check_context spelling is deliberately absent).
const selinuxContextValidationNode = "/sys/fs/selinux/context"

// The context-validation cell does its own descriptor IO (open, write,
// read, close) for the exact same reasons the own-context read does:
// os package helpers would add stat surfaces outside the measured
// opener family. Package-global seams; tests restore them.
var (
	wrapperContextNodeOpen = func(path string, flags int, perm uint32) (int, error) {
		return unix.Open(path, flags, perm)
	}
	wrapperContextNodeWrite = func(fd int, buf []byte) (int, error) {
		return unix.Write(fd, buf)
	}
	wrapperContextNodeRead = func(fd int, buf []byte) (int, error) {
		return unix.Read(fd, buf)
	}
	wrapperContextNodeClose = func(fd int) error {
		return unix.Close(fd)
	}
)

// checkContextFailure classes the typed refusal causes of the context
// validation transaction. The categories are the observable behavior
// contract of the gate: the wrapper's test suite and the enforcing-VM
// round both address them per class.
type checkContextFailure struct {
	kind string
	err  error
}

func (e *checkContextFailure) Error() string {
	return fmt.Sprintf("the workload context validation cannot be trusted (%s: %v)", e.kind, e.err)
}

func (e *checkContextFailure) Unwrap() error { return e.err }

// checkContextUnavailable is the interface-absence class: the kernel's
// context-validation node cannot be reached at all.
var checkContextUnavailable = &checkContextFailure{kind: "unavailable"}

// checkContextPermission is the missing security_t:security:check_context
// grant class: the kernel denied the CHECK, which is a policy question
// and never speaks to the validity of the submitted context.
var checkContextPermission = &checkContextFailure{kind: "permission"}

// checkContextInvalid is the loaded policy's rejection class (EINVAL):
// unknown type, unauthorized role/type pair, invalid sensitivity or
// category.
var checkContextInvalid = &checkContextFailure{kind: "invalid"}

// checkContextShortIO is the truncated transfer class: a short write or
// a short canonical read-back.
var checkContextShortIO = &checkContextFailure{kind: "short-io"}

// checkContextBroken is everything else: unexpected errno, an
// unclassifiable read result, or a read-back whose canonical form is not
// the composed context.
var checkContextBroken = &checkContextFailure{kind: "broken"}

// checkContextTransaction performs one validation transaction: it opens
// the node O_RDWR, writes the NUL-terminated context, reads the
// canonical response back, and compares it byte-exactly against the
// composed context. A nil return means the kernel validated the context
// and returned exactly it.
func checkContextTransaction(label string) error {
	fd, err := wrapperContextNodeOpen(selinuxContextValidationNode, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return unavailablePermissionOrBroken(err)
	}
	defer func() { _ = wrapperContextNodeClose(fd) }()

	payload := []byte(label)
	form := make([]byte, 0, len(payload)+1)
	form = append(form, payload...)
	form = append(form, 0)
	written, err := wrapperContextNodeWrite(fd, form)
	if err != nil {
		return unavailablePermissionOrBroken(err)
	}
	if written != len(form) {
		return &checkContextFailure{
			kind: checkContextShortIO.kind,
			err: fmt.Errorf("the context write transferred %d of %d bytes",
				written, len(form)),
		}
	}

	// The canonical read-back must equal the composed context INCLUDING
	// the NUL terminator the transaction response carries (the kernel's
	// response buffer is strlen(resp)+1 bytes).
	// the transaction state (the processed request and the response
	// size) lives in the open's private data and a second open would
	// start an empty transaction. The write already ran the kernel's
	// validation synchronously, so the read-back observes it without
	// any coordination.
	var buf [4096]byte
	n, err := wrapperContextNodeRead(fd, buf[:])
	if err != nil {
		return &checkContextFailure{kind: checkContextBroken.kind, err: fmt.Errorf("cannot read the canonical response: %w", err)}
	}
	if n == 0 {
		return &checkContextFailure{
			kind: checkContextShortIO.kind,
			err:  errors.New("the canonical response is empty"),
		}
	}
	if n != len(form) || string(buf[:n]) != string(form) {
		return &checkContextFailure{
			kind: checkContextBroken.kind,
			err: fmt.Errorf("the kernel's canonical context %q does not match the composed workload context",
				string(buf[:n])),
		}
	}
	return nil
}

// unavailablePermissionOrBroken classifies a syscall errno into the
// observable refusal classes. Truncated and odd-valued errno distances
// (Go's syscall error packing) are normalized before classification.
func unavailablePermissionOrBroken(err error) error {
	errno, ok := errnoOf(err)
	if !ok {
		return &checkContextFailure{kind: checkContextBroken.kind, err: err}
	}
	switch errno {
	case unix.ENOENT:
		return &checkContextFailure{
			kind: checkContextUnavailable.kind,
			err:  fmt.Errorf("%w: the context validation node does not exist on this kernel", err),
		}
	case unix.EACCES, unix.EPERM:
		return &checkContextFailure{
			kind: checkContextPermission.kind,
			err:  fmt.Errorf("%w: the loaded policy grants no context-check permission", err),
		}
	case unix.EINVAL:
		return &checkContextFailure{
			kind: checkContextInvalid.kind,
			err:  fmt.Errorf("%w: the loaded policy rejects the composed workload context", err),
		}
	default:
		return &checkContextFailure{kind: checkContextBroken.kind, err: err}
	}
}

// errnoOf extracts the syscall errno from the seam error, working for
// both unix.Errno and os.* (syscall.Errno) error values.
func errnoOf(err error) (unix.Errno, bool) {
	var errno unix.Errno
	if errors.As(err, &errno) {
		return errno, true
	}
	return 0, false
}

// wrapperWorkloadContextCheck is the injectable workload-context
// admission gate: the COMPOSED workload context (kernel-derived own
// context with the fixed workload domain) must validate against the
// LOADED policy through the kernel's own context-validation interface,
// and the canonical read-back must equal the composed context exactly.
// Fail-closed: every failure category above is a refusal; nothing else
// ever proves a context valid. Package-global; tests restore it.
//
// The validation is NOT an authorization: the kernel's transition checks
// for the composed context remain independently authoritative, and an
// accepted validation does not grant, imply, or shortcut any of them.
var wrapperWorkloadContextCheck = func(label string) error {
	if err := checkContextTransaction(label); err != nil {
		return err
	}
	return nil
}
