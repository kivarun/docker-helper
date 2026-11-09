//go:build linux

package main

// wrapper_inspection_linux.go owns the enforced readiness boundary of the
// buildkit-runc wrapper (the P21-E trusted-/dev architecture's enforced
// layer, C5-C1 §4): on EVERY invocation and regardless of caller, the
// wrapper derives the canonical prepared source from its own --bundle
// path, derives its own operation category exclusively from the kernel
// (/proc/self/attr/current — no argument, no environment, no spec field),
// and refuses the invocation when the prepared tree is
//
//   - absent (no <daemonStateRoot>/dev-prep/<op> directory),
//   - incomplete (any of the fixed mandatory entries missing: the three
//     mountpoint directories, the six character devices, the five fixed
//     symlinks), or
//   - category-inconsistent (the tree's persisted security.selinux label
//     is not exactly docker_helper_devprep_t:s0:<own category>).
//
// The refusal is fail-closed: the RUN step fails loudly, no fallback, no
// retry. The check lives at the worker's exec boundary, so it holds for
// any path that reaches the wrapper — buildctl-driven builds, any API
// client driving the daemon, or a compromised in-domain process
// attempting to consume a foreign or unprepared tree. A
// category-inconsistent tree is refused even though the daemon's MCS rows
// would also deny it — the refusal makes the failure loud and immediate
// instead of a downstream denial.
//
// Ownership and trust boundaries:
//
//   - the bundle path is only ever a CORRELATION input: the wrapper
//     decomposes it against the measured canonical executor layout and
//     extracts the operation id through the canonical issued-ID grammar
//     (isOperationID). The prepared-tree path is never accepted from the
//     caller — it is constructed from the fixed daemon state root
//     (devPrepOpDir).
//   - the own category is derived kernel-trust-only: the raw own context
//     is read from /proc/self/attr/current (a bounded direct-syscall read
//     — open and read only, no fstat/getattr; see readOwnContext), its
//     kernel terminal framing is normalized (exactly one optional
//     terminal NUL or newline — both encodings are observed live: the NUL
//     form in the C3 capture, the newline form in the g26 probe), and the
//     category token is validated exclusively through the single parser
//     (parseBuilderCategory). No second grammar, no caller-supplied
//     context is trusted.
//   - the inspection is strictly read-only and narrow: lstat (getattr)
//     for every entry's presence and inode type, and one getxattr for the
//     persisted label — exactly the measured grant family of the
//     devprep_t policy candidate for the wrapper's domain (dir
//     {search getattr}, chr_file getattr, lnk_file getattr). No readdir
//     (dir:read is not granted), no device open, no readlink
//     (lnk_file:read is not granted) — the symlink TARGETS are the
//     preparer's verified contract, and the conditional core symlink is
//     checked for presence and shape only (R3-P2 OBL-5: absence is the
//     expected steady state and is never incompleteness; a present entry
//     must be exactly a symlink).
//
// The wrapper core is intentionally not invoked by any production path
// yet (the integration round wires it into the buildkit-runc replacement
// and adds the measured self-file read singleton the own-context read
// needs under the confined domain — OBL-7).

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// wrapperOwnDomain is the SELinux process type (domain) the wrapper runs
// in: the confined buildkitd domain of the operation, whose own context
// carries the category the prepared tree must match.
const wrapperOwnDomain = "docker_helper_buildkitd_t"

// wrapperBundleIDLength is the measured length of the BuildKit executor
// bundle id (the pinned BuildKit v0.33.0 generator): every captured live
// sample is exactly 25 lowercase alphanumerics (ygn48dtxodtbs22evtqnhhktx
// and 6jinf8i9db2cl6rsdw8zcony9 from the P21-B AVC captures,
// 9ljpl8zdbqwrbx85v3okf4y83 and p8s0i4imq0adpx6apco1pl9ft from the P21-C
// captures, s4pkwc8u4nxm7ihg20z5xu82j and 1qi74uzmkc1qg6izpy1up9h7u from
// the P21-D pid-sampler).
const wrapperBundleIDLength = 25

// wrapperRefuseError is the typed fail-closed refusal of one wrapper
// invocation: the bundle path is not a canonical executor bundle, the own
// context does not yield a pool category, or the prepared tree is absent,
// incomplete, category-inconsistent, or uninspectable. The wrapper never
// proceeds past a refusal.
type wrapperRefuseError struct{ cause error }

func (e *wrapperRefuseError) Error() string {
	return "wrapper: invocation refused: " + e.cause.Error()
}

func (e *wrapperRefuseError) Unwrap() error { return e.cause }

// wrapperBundleOpID derives the operation id from a buildkit-runc bundle
// path. Only the exact canonical executor layout is accepted —
//
//	<builderStateRoot>/ops/<op>/root/runc-native/executor/<bundle>
//
// decomposed structurally, so relative spellings, traversal segments
// ("." / ".."), doubled separators, extra depth, a trailing slash, and
// any non-canonical shape are refused before the derived id is used for
// anything. The operation id is validated through the canonical issued-ID
// grammar; the bundle segment is validated against the measured executor
// id grammar. The bundle path is a correlation input only — it never
// becomes the prepared-tree path.
func wrapperBundleOpID(bundlePath string) (string, error) {
	state := strings.Split(builderStateRoot, "/")
	segs := strings.Split(bundlePath, "/")
	const suffixSegments = 6 // ops, <op>, root, runc-native, executor, <bundle>
	if len(segs) != len(state)+suffixSegments {
		return "", fmt.Errorf("the bundle path %q is not a canonical executor bundle", bundlePath)
	}
	for i, want := range state {
		if segs[i] != want {
			return "", fmt.Errorf("the bundle path %q is not a canonical executor bundle under %q", bundlePath, builderStateRoot)
		}
	}
	if segs[len(state)] != "ops" {
		return "", fmt.Errorf("the bundle path %q is not a canonical executor bundle", bundlePath)
	}
	opID := segs[len(state)+1]
	if !isOperationID(opID) {
		return "", fmt.Errorf("the bundle path %q carries a non-canonical operation id", bundlePath)
	}
	if segs[len(state)+2] != "root" || segs[len(state)+3] != "runc-native" || segs[len(state)+4] != "executor" {
		return "", fmt.Errorf("the bundle path %q is not a canonical executor bundle", bundlePath)
	}
	if !validWrapperBundleID(segs[len(state)+5]) {
		return "", fmt.Errorf("the bundle path %q carries a non-canonical executor bundle id", bundlePath)
	}
	return opID, nil
}

// validWrapperBundleID validates the measured BuildKit executor bundle id
// grammar: exactly wrapperBundleIDLength lowercase alphanumerics.
func validWrapperBundleID(s string) bool {
	if len(s) != wrapperBundleIDLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// wrapperOwnContextReader is the injectable seam for the wrapper's raw
// own-context read (production: the fixed procattr pathname).
type wrapperOwnContextReader interface {
	readOwnContext() ([]byte, error)
}

// linuxWrapperOwnContextReader implements the seam with the real raw read
// of /proc/self/attr/current (the file's label is the reading process's
// own context — the kernel's task_to_inode labeling). The raw bytes are
// returned unnormalized; the framing is the parser's concern.
type linuxWrapperOwnContextReader struct{}

// wrapperAttrOpen, wrapperAttrRead and wrapperAttrClose are the procattr
// read seams (production: the unix syscalls on the fixed procattr
// pathname). Package-global; tests restore them.
var (
	wrapperAttrOpen = func(path string, flags int, perm uint32) (int, error) {
		return unix.Open(path, flags, perm)
	}
	wrapperAttrRead = func(fd int, buf []byte) (int, error) {
		return unix.Read(fd, buf)
	}
	wrapperAttrClose = func(fd int) error {
		return unix.Close(fd)
	}
)

// readOwnContext performs the bounded raw procattr read with direct
// syscalls only — open, read, close. It deliberately does NOT use
// os.ReadFile, whose statOrZero path invokes f.Stat — an fstat of the
// procattr file — before the first read; that would add a self:file
// getattr check outside the measured OBL-7 denial family { read open }.
// The read is bounded by the shared context read ceiling
// (builderObjectContextReadCeiling): more bytes than the ceiling is an
// oversized failure, never a silent truncation. The read is
// close-on-exec: the inspection must not leak the procattr descriptor
// into the exec'd worker.
func (linuxWrapperOwnContextReader) readOwnContext() ([]byte, error) {
	fd, err := wrapperAttrOpen(selinuxAttrPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer wrapperAttrClose(fd)
	buf := make([]byte, builderObjectContextReadCeiling+1)
	total := 0
	for {
		if total > builderObjectContextReadCeiling {
			return nil, fmt.Errorf("the own process context exceeds the %d-byte read ceiling", builderObjectContextReadCeiling)
		}
		n, err := wrapperAttrRead(fd, buf[total:])
		total += n
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if n == 0 {
			return buf[:total], nil
		}
	}
}

// wrapperOwnContextCategory derives the wrapper's own operation category
// from the raw own process context. Exactly one optional kernel terminal
// (NUL or newline) is stripped; empty values, embedded NULs or newlines,
// any other context shape than user:role:type:sensitivity:category, a
// type other than the wrapper's own domain, and any category token that
// is not a canonical pool category (validated exclusively through the
// single parser) are refused — no caller-supplied context is ever
// trusted.
func wrapperOwnContextCategory(raw []byte) (builderCategory, error) {
	ctx := raw
	if n := len(ctx); n > 0 && (ctx[n-1] == '\n' || ctx[n-1] == 0) {
		ctx = ctx[:n-1]
	}
	if len(ctx) == 0 {
		return 0, errors.New("the own process context is empty")
	}
	if bytes.IndexByte(ctx, 0) >= 0 || bytes.IndexByte(ctx, '\n') >= 0 {
		return 0, errors.New("the own process context carries an embedded terminal byte")
	}
	fields := strings.Split(string(ctx), ":")
	if len(fields) != 5 {
		return 0, fmt.Errorf("the own process context %q is not user:role:type:sensitivity:category", ctx)
	}
	if fields[2] != wrapperOwnDomain {
		return 0, fmt.Errorf("the own process context type %q, want %q", fields[2], wrapperOwnDomain)
	}
	category, ok := parseBuilderCategory(fields[4])
	if !ok {
		return 0, fmt.Errorf("the own process context category %q is not a canonical pool category", fields[4])
	}
	return category, nil
}

// wrapperInspectionSyscalls is the narrow inspection seam: exactly the
// two read-only operations the inspection performs — lstat (which never
// follows a final symlink) for every entry's presence and inode type, and
// getxattr for the persisted label. Production is satisfied by
// linuxDevPrepSyscalls; no second syscall surface exists.
type wrapperInspectionSyscalls interface {
	lstat(path string) (os.FileInfo, error)
	getxattr(path, name string) ([]byte, error)
}

// wrapperInspectDevPrep is the production entry of the enforced readiness
// sequence with the real seams.
func wrapperInspectDevPrep(bundlePath string) error {
	return wrapperInspectDevPrepWithSeams(linuxWrapperOwnContextReader{}, linuxDevPrepSyscalls{}, bundlePath)
}

// wrapperInspectDevPrepWithSeams is the full enforced readiness sequence
// of one wrapper invocation: canonical bundle-path derivation, the
// kernel-trust-only own-category derivation, and the fail-closed
// fixed-entry inspection of the prepared tree at its canonical path.
// Every failure is a typed refusal.
func wrapperInspectDevPrepWithSeams(reader wrapperOwnContextReader, seam wrapperInspectionSyscalls, bundlePath string) error {
	opID, err := wrapperBundleOpID(bundlePath)
	if err != nil {
		return &wrapperRefuseError{cause: err}
	}
	raw, err := reader.readOwnContext()
	if err != nil {
		return &wrapperRefuseError{cause: fmt.Errorf("cannot read the own process context: %w", err)}
	}
	category, err := wrapperOwnContextCategory(raw)
	if err != nil {
		return &wrapperRefuseError{cause: err}
	}
	return wrapperInspectPreparedDev(seam, devPrepOpDir(opID), category)
}

// wrapperInspectPreparedDev is the fail-closed inspection of one prepared
// tree: the operation directory must exist as a directory and carry the
// exact categorized dev-prep label, every fixed mandatory entry must be
// present with the exact inode type, and the conditional core symlink
// must be exactly a symlink when present (its absence is normal, never
// incompleteness). The inspection reads nothing but entry metadata and
// the label: no readdir, no device open, no symlink following.
func wrapperInspectPreparedDev(seam wrapperInspectionSyscalls, opDir string, category builderCategory) error {
	refuse := func(err error) error { return &wrapperRefuseError{cause: err} }

	st, err := seam.lstat(opDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return refuse(fmt.Errorf("the prepared tree %s is absent", opDir))
		}
		return refuse(fmt.Errorf("cannot inspect the prepared tree %s: %w", opDir, err))
	}
	if !st.IsDir() {
		return refuse(fmt.Errorf("the prepared tree %s is not a directory", opDir))
	}
	raw, err := seam.getxattr(opDir, "security.selinux")
	if err != nil {
		return refuse(fmt.Errorf("cannot read the label of the prepared tree %s: %w", opDir, err))
	}
	got, err := decodeSELinuxXattrContext(raw)
	if err != nil {
		return refuse(fmt.Errorf("the label of the prepared tree %s is not a context: %w", opDir, err))
	}
	want := builderObjectContext(builderDevPrepObjectType, category)
	if got != want {
		return refuse(fmt.Errorf("the prepared tree %s is category-inconsistent: label %q, want %q", opDir, got, want))
	}

	for _, name := range devPrepMountDirs {
		if err := wrapperRequireEntry(seam, opDir, name, "mount dir", func(m os.FileMode) bool { return m&os.ModeDir != 0 }); err != nil {
			return refuse(err)
		}
	}
	for _, dev := range devPrepDevices {
		if err := wrapperRequireEntry(seam, opDir, dev.name, "device", func(m os.FileMode) bool { return m&os.ModeCharDevice != 0 }); err != nil {
			return refuse(err)
		}
	}
	for _, link := range devPrepSymlinks {
		if err := wrapperRequireEntry(seam, opDir, link.name, "symlink", func(m os.FileMode) bool { return m&os.ModeSymlink != 0 }); err != nil {
			return refuse(err)
		}
	}

	// The conditional core symlink: absence is the expected steady state
	// (R3-P2 OBL-5 — the daemon's existence gate absorbed the
	// /proc/kcore decision at preparation time); a present entry must be
	// exactly a symlink. The target is NOT verified here: readlink is
	// lnk_file:read, outside the wrapper's measured grant family — the
	// target is the preparer's verified contract.
	st, err = seam.lstat(filepath.Join(opDir, devPrepConditionalSymlink.name))
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		return refuse(fmt.Errorf("cannot inspect the conditional core entry: %w", err))
	}
	if st.Mode()&os.ModeSymlink == 0 {
		return refuse(fmt.Errorf("the conditional core entry is not a symlink"))
	}
	return nil
}

// wrapperRequireEntry verifies one fixed entry's presence and inode type
// without following or opening anything.
func wrapperRequireEntry(seam wrapperInspectionSyscalls, opDir, name, kind string, isKind func(os.FileMode) bool) error {
	st, err := seam.lstat(filepath.Join(opDir, name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("the prepared tree is incomplete: %s %s is missing", kind, name)
		}
		return fmt.Errorf("cannot inspect %s in the prepared tree: %w", name, err)
	}
	if !isKind(st.Mode()) {
		return fmt.Errorf("%s %s does not have the required inode type", kind, name)
	}
	return nil
}
