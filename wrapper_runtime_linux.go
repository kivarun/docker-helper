//go:build linux

package main

// wrapper_runtime_linux.go owns the buildkit-runc wrapper's runtime
// dispatch (the R4-P2 implementation of the accepted R4-P1/C1/C2
// contracts): it receives the exact pinned BuildKit invocation forms,
// gates the bundle-consuming `run` command through the accepted R4-P0
// enforced sequence (canonical bundle derivation, kernel-derived own
// category, fail-closed prepared-tree inspection), rewrites the bundle's
// config.json — replacing exactly the one `/dev` tmpfs mount with the
// prepared-tree bind — commits it atomically, and hands off to the real
// runtime through execve. Validated pass-through commands are forwarded
// byte-identically with no prepared-tree or spec access; every other
// invocation shape is refused.
//
// Contract anchors (accepted, not re-derived here):
//
//   - the commit point is the successful rename(2) (R4-P1-C1 §C1):
//     pre-commit failures leave the original config.json byte-unchanged
//     with no wrapper-owned temporary residue and never invoke the real
//     runtime; the single post-commit failure (execve) surfaces loudly
//     and leaves the committed rewrite in place — no rollback, no
//     repair, no retry;
//   - the real runtime is exec'd (PID- and parent-death-preserving) at
//     a fixed, product-owned absolute path — never a PATH lookup; the
//     path decision is integration-owned (D-2) and FAILS CLOSED while
//     it is not established;
//   - the wrapper gates the production BuildKit runtime-resolution
//     path; it is not a universal enforcement boundary against direct
//     execution by a compromised in-domain process (R4-P1-C2, accepted)
//     — SELinux/MCS remains the independent hard isolation boundary;
//   - the /dev replacement shape is the accepted provisional predicate:
//     exactly the pinned containerd v2.3.4 default incumbent (tmpfs/tmpfs
//     with the pinned option sequence, canonical "/dev" spelling, and no
//     extra mount fields), replaced by the bind+nosuid shape — anything
//     else is refused, never silently adopted or discarded (OBL-8 remains
//     mandatory before any integration calibration).
//
// The wrapper core is intentionally not invoked by any production entry
// point yet (the CLI/binary wiring is a later round; the [worker.oci]
// integration is explicitly out of scope here).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

// wrapperRealRuntimePath is the fixed, product-owned absolute path of
// the real runtime the wrapper hands off to (the accepted R4-P3-P0 D-2
// placement): the original pinned upstream buildkit-runc, relocated into
// the dedicated runtime subdirectory. It is never PATH-resolved, never
// caller-controlled, and never a second implementation — the packaged
// bytes are verified against the pinned BuildKit manifest, and the fixed
// directory separates the inode from the wrapper payload path, so the
// handoff can never resolve back to the wrapper itself. The empty-path
// refusal gate below stays as defense-in-depth: if the constant were
// ever cleared, every invocation fails closed again.
var wrapperRealRuntimePath = "/usr/libexec/docker-helper/buildkit/runtime/buildkit-runc"

// wrapperExecRuntime is the injectable exec handoff (production:
// execve — the PID go-runc monitors and the PdeathSignal relationship
// survive only through execve, never fork-and-wait). Package-global;
// tests restore it.
var wrapperExecRuntime = func(path string, argv []string, env []string) error {
	return unix.Exec(path, argv, env)
}

// wrapperCommitRename is the injectable commit primitive (production:
// rename(2) of the temporary spec over config.json in the same bundle
// directory). The successful rename IS the spec commit point
// (R4-P1-C1 §C1). Package-global; tests restore it.
var wrapperCommitRename = func(tempPath, targetPath string) error {
	return os.Rename(tempPath, targetPath)
}

// wrapperSpecTempName is the prefix of the wrapper-owned temporary spec
// file, created with exclusive creation (os.CreateTemp's O_EXCL random
// suffix) in the bundle directory — same filesystem as the target, so
// the commit rename is atomic — and removed again on every pre-commit
// failure. A pre-existing file or symlink at any temporary-path name is
// never opened, adopted, or removed: exclusive creation makes the
// invocation the sole owner of the file it commits.
const wrapperSpecTempName = "config.json.wrapped"

// wrapperLogFileName is the fixed runc log file name of the canonical
// executor tree (the go-runc Log value, buildkit executor.go:127).
const wrapperLogFileName = "runc-log.json"

// wrapperDevBindOptions is the accepted replacement option set for the
// /dev mount: a single-level bind (real mknod nodes are plain entries;
// no recursion is needed) with nosuid, and deliberately WITHOUT nodev
// (the prepared device nodes must stay openable) and without the
// incumbent tmpfs-only options (mode=/size=/strictatime).
var wrapperDevBindOptions = []string{"bind", "nosuid"}

// wrapperDevIncumbentOptions is the exact option sequence of the pinned
// containerd v2.3.4 default /dev mount (client/oci defaultMounts, the
// provisional incumbent of R4-P1/C1). The sequence is the producer's
// deterministic output and is matched element-for-element — reordered,
// modified, missing, or additional options are refused, never silently
// discarded. OBL-8 calibrates this constant against a live generated
// config.json before integration; nothing is broadened speculatively.
var wrapperDevIncumbentOptions = []string{"nosuid", "strictatime", "mode=755", "size=65536k"}

// wrapperCreateTemp is the injectable exclusive temporary-file creation
// (production: os.CreateTemp with the wrapper-owned prefix, inside the
// bundle directory). Exclusive creation (O_CREATE|O_EXCL) means a
// pre-existing file or symlink at a candidate name is never opened or
// adopted. Package-global; tests restore it.
var wrapperCreateTemp = func(dir string) (*os.File, error) {
	return os.CreateTemp(dir, wrapperSpecTempName)
}

// wrapperInvocation is one parsed, validated wrapper invocation.
type wrapperInvocation struct {
	kind       string   // run, delete, state, kill, exec
	logOpID    string   // the op id embedded in the canonical --log path
	bundlePath string   // run only: the canonical bundle path from argv
	bundleOpID string   // run only: the op id derived from the bundle path
	id         string   // the container id (== the bundle basename for run)
	argv       []string // the full original argv, forwarded unchanged
}

// wrapperParseArgv validates one wrapper invocation against the exact
// pinned BuildKit grammar (the observed run/delete forms and the
// source-derived state/kill/exec forms, with the exact canonical global
// prefix) and derives the operation/bundle identity. Only these forms
// are accepted; create, every unknown command, and every noncanonical
// argv shape are refused. No generic runc CLI parser exists here: the
// pinned forms are matched structurally.
func wrapperParseArgv(argv []string) (*wrapperInvocation, error) {
	// The exact global prefix: --log <canonical> --log-format json
	// (go-runc r.args() with the buildkit Runc struct; observed in every
	// live sample). Anything else — missing, extra, reordered, other
	// values — is an unexpected invocation shape.
	if len(argv) < 6 {
		return nil, fmt.Errorf("the invocation is too short to carry the pinned global prefix")
	}
	if argv[1] != "--log" || argv[3] != "--log-format" || argv[4] != "json" {
		return nil, fmt.Errorf("the global prefix %q is not the pinned --log/--log-format json form", argv[1:min(5, len(argv))])
	}
	logOpID, err := wrapperLogOpID(argv[2])
	if err != nil {
		return nil, err
	}
	inv := &wrapperInvocation{kind: argv[5], logOpID: logOpID, argv: argv}
	switch inv.kind {
	case "run":
		if len(argv) != 10 || argv[6] != "--bundle" || argv[8] != "--keep" {
			return nil, fmt.Errorf("the run invocation %q is not the pinned run form", argv)
		}
		inv.bundlePath = argv[7]
		inv.id = argv[9]
		opID, err := wrapperBundleOpID(inv.bundlePath)
		if err != nil {
			return nil, err
		}
		inv.bundleOpID = opID
		if inv.id != filepath.Base(inv.bundlePath) {
			return nil, fmt.Errorf("the run container id %q is not the bundle basename %q", inv.id, filepath.Base(inv.bundlePath))
		}
		if inv.bundleOpID != inv.logOpID {
			return nil, fmt.Errorf("the --log operation %s does not match the --bundle operation %s", inv.logOpID, inv.bundleOpID)
		}
	case "delete", "state":
		if len(argv) != 7 {
			return nil, fmt.Errorf("the %s invocation %q is not the pinned single-id form", inv.kind, argv)
		}
		inv.id = argv[6]
		if !validWrapperBundleID(inv.id) {
			return nil, fmt.Errorf("the %s container id %q is not a canonical executor id", inv.kind, inv.id)
		}
	case "kill":
		if len(argv) != 8 || argv[7] != "9" {
			return nil, fmt.Errorf("the kill invocation %q is not the pinned SIGKILL form", argv)
		}
		inv.id = argv[6]
		if !validWrapperBundleID(inv.id) {
			return nil, fmt.Errorf("the kill container id %q is not a canonical executor id", inv.id)
		}
	case "exec":
		if len(argv) != 11 || argv[6] != "--process" || argv[8] != "--pid-file" {
			return nil, fmt.Errorf("the exec invocation %q is not the pinned process-file form", argv)
		}
		if argv[7] == "" || argv[9] == "" {
			return nil, fmt.Errorf("the exec invocation carries an empty process or pid-file path")
		}
		inv.id = argv[10]
		if !validWrapperBundleID(inv.id) {
			return nil, fmt.Errorf("the exec container id %q is not a canonical executor id", inv.id)
		}
	default:
		// create and every other runc subcommand are unexpected
		// invocation shapes for this product (R4-P1-C1 §C3: the pinned
		// runcexecutor invokes only run/exec/state/kill/delete).
		return nil, fmt.Errorf("the command %q is not a supported wrapper invocation", inv.kind)
	}
	return inv, nil
}

// wrapperLogOpID validates the canonical --log path —
// <builderStateRoot>/ops/<op>/root/runc-native/executor/runc-log.json —
// through the shared executor-tree grammar and returns its op id.
func wrapperLogOpID(logPath string) (string, error) {
	opID, leaf, err := wrapperExecutorTreePath(logPath)
	if err != nil {
		return "", err
	}
	if leaf != wrapperLogFileName {
		return "", fmt.Errorf("the --log path %q is not the canonical executor log path", logPath)
	}
	return opID, nil
}

// wrapperMain is the production dispatch entry with the real seams. It
// is intentionally not invoked by any production entry point yet.
func wrapperMain(argv []string, env []string) error {
	return wrapperMainWithSeams(argv, env, linuxWrapperOwnContextReader{}, linuxDevPrepSyscalls{})
}

// wrapperMainWithSeams is the full dispatch: argv validation and
// identity derivation, then either the run pipeline (inspection, spec
// rewrite, exec handoff) or the validated byte-identical pass-through.
// Every failure is a typed refusal; the real runtime is invoked only
// through the exec seam, only after the pinned grammar and (for run)
// the whole enforced sequence have passed.
func wrapperMainWithSeams(argv []string, env []string, reader wrapperOwnContextReader, seam wrapperInspectionSyscalls) error {
	inv, err := wrapperParseArgv(argv)
	if err != nil {
		return &wrapperRefuseError{cause: err}
	}
	// D-2 fail-closed: the real-runtime path must have been established
	// by the integration-owned boundary before any invocation proceeds.
	if wrapperRealRuntimePath == "" {
		return &wrapperRefuseError{cause: errors.New("the real runtime path is not established; refusing every invocation")}
	}
	if inv.kind == "run" {
		return wrapperRunPipeline(reader, seam, inv, env)
	}
	if err := wrapperExecRuntime(wrapperRealRuntimePath, inv.argv, env); err != nil {
		return &wrapperRefuseError{cause: fmt.Errorf("cannot execute the real runtime: %w", err)}
	}
	return nil
}

// wrapperRunPipeline is the enforced run sequence (R4-P1-C1 §C1 order):
// the kernel-derived own category, the fail-closed prepared-tree
// inspection (the accepted R4-P0 owner), then the spec read/validate/
// rewrite/commit, then the exec handoff. Every failure before the spec
// commit is a pre-commit refusal (the original spec is untouched and no
// temporary residue remains); an exec failure after the commit is the
// single post-commit failure (the committed rewrite remains; no
// rollback).
func wrapperRunPipeline(reader wrapperOwnContextReader, seam wrapperInspectionSyscalls, inv *wrapperInvocation, env []string) error {
	raw, err := reader.readOwnContext()
	if err != nil {
		return &wrapperRefuseError{cause: fmt.Errorf("cannot read the own process context: %w", err)}
	}
	category, err := wrapperOwnContextCategory(raw)
	if err != nil {
		return &wrapperRefuseError{cause: err}
	}
	if err := wrapperInspectPreparedDev(seam, devPrepOpDir(inv.bundleOpID), category); err != nil {
		return err
	}
	if err := wrapperRewriteSpecDevBind(inv.bundlePath, inv.bundleOpID); err != nil {
		return &wrapperRefuseError{cause: err}
	}
	if err := wrapperExecRuntime(wrapperRealRuntimePath, inv.argv, env); err != nil {
		return &wrapperRefuseError{cause: fmt.Errorf("post-commit: cannot execute the real runtime: %w", err)}
	}
	return nil
}

// wrapperRewriteSpecDevBind reads and validates the bundle's config.json
// and replaces exactly the one /dev tmpfs mount with the prepared-tree
// bind, committing the result atomically. The prepared-tree source comes
// exclusively from the canonical path owner (devPrepOpDir) derived from
// the derived operation id — never from argv, environment, or spec
// contents. An already-rewritten /dev bind is never adopted; the
// predicted incumbent shape is a strict provisional predicate (OBL-8
// remains mandatory before any integration calibration).
func wrapperRewriteSpecDevBind(bundlePath, opID string) error {
	specPath := filepath.Join(bundlePath, "config.json")
	original, err := os.ReadFile(specPath)
	if err != nil {
		return fmt.Errorf("cannot read the OCI spec %s: %w", specPath, err)
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(original))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("the OCI spec %s is not a JSON object: %w", specPath, err)
	}
	// The rewrite re-serializes the whole document, so any trailing data
	// would be silently discarded — refuse it instead (runc's own loader
	// tolerates it; the rewrite must not).
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("the OCI spec %s carries trailing data", specPath)
	}
	mounts, ok := doc["mounts"].([]any)
	if !ok {
		return fmt.Errorf("the OCI spec %s has no mounts array", specPath)
	}
	devIndex := -1
	devCount := 0
	for i, entry := range mounts {
		m, ok := entry.(map[string]any)
		if !ok {
			return fmt.Errorf("the OCI spec %s has a non-object mount entry at index %d", specPath, i)
		}
		// Pinned runc v1.4.3 resolves every mount destination lexically
		// (pathrs.LexicallyCleanPath, which for absolute destinations is
		// exactly filepath.Clean) at every /dev-relevant site —
		// needsSetupDev, mountPropagate, finalizeRootfs — so a
		// noncanonical alias such as "/dev/." or "/dev/../dev" denotes
		// the same mountpoint and, placed later in the list, would mount
		// over the prepared tree. /dev recognition therefore uses the
		// normalized destination, while the single accepted entry must
		// additionally use the canonical literal spelling.
		dest, _ := m["destination"].(string)
		if path.Clean(dest) == "/dev" {
			devCount++
			devIndex = i
		}
	}
	if devCount == 0 {
		return fmt.Errorf("the OCI spec %s has no /dev mount", specPath)
	}
	if devCount > 1 {
		return fmt.Errorf("the OCI spec %s has %d /dev mounts (by normalized destination)", specPath, devCount)
	}
	dev := mounts[devIndex].(map[string]any)
	if dest, _ := dev["destination"].(string); dest != "/dev" {
		return fmt.Errorf("the /dev mount of %s has the noncanonical destination %q; only the literal /dev spelling is accepted", specPath, dest)
	}
	mountType, _ := dev["type"].(string)
	mountSource, _ := dev["source"].(string)
	rawOptions, ok := dev["options"].([]any)
	if !ok {
		return fmt.Errorf("the /dev mount of %s has no options array", specPath)
	}
	options := make([]string, 0, len(rawOptions))
	for _, o := range rawOptions {
		s, ok := o.(string)
		if !ok {
			return fmt.Errorf("the /dev mount of %s has a non-string /dev mount option", specPath)
		}
		options = append(options, s)
	}
	for _, o := range options {
		if o == "bind" || o == "rbind" {
			return fmt.Errorf("the /dev mount of %s is already a bind; refusing to adopt a rewritten spec", specPath)
		}
	}
	if mountType == "bind" {
		// A bind TYPE makes runc's conversion produce Device="bind" even
		// without a bind option (specconv: mnt.Device = m.Type) — the
		// needsSetupDev predicate would already see a bind.
		return fmt.Errorf("the /dev mount of %s is already a bind; refusing to adopt a rewritten spec", specPath)
	}
	// The strict provisional incumbent predicate: exactly the
	// containerd-generated tmpfs/tmpfs entry with the pinned option
	// sequence, the canonical "/dev" spelling, and no fields beyond
	// destination/type/source/options (OBL-8 calibrates before
	// integration; nothing is silently broadened or discarded).
	var extraFields []string
	for key := range dev {
		switch key {
		case "destination", "type", "source", "options":
		default:
			extraFields = append(extraFields, key)
		}
	}
	if len(extraFields) > 0 {
		sort.Strings(extraFields)
		return fmt.Errorf("the /dev mount of %s carries unexpected fields %v", specPath, extraFields)
	}
	if mountType != "tmpfs" || mountSource != "tmpfs" {
		return fmt.Errorf("the /dev mount of %s has the unexpected shape type=%q source=%q", specPath, mountType, mountSource)
	}
	optionsDeviant := len(options) != len(wrapperDevIncumbentOptions)
	for i := 0; !optionsDeviant && i < len(options); i++ {
		optionsDeviant = options[i] != wrapperDevIncumbentOptions[i]
	}
	if optionsDeviant {
		return fmt.Errorf("the /dev mount of %s does not carry the pinned provisional incumbent options %v, got %v", specPath, wrapperDevIncumbentOptions, options)
	}
	mounts[devIndex] = map[string]any{
		"destination": "/dev",
		"type":        "bind",
		"source":      devPrepOpDir(opID),
		"options":     optionsToAny(wrapperDevBindOptions),
	}
	rewritten, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("cannot re-serialize the OCI spec %s: %w", specPath, err)
	}
	// Preserve the original file's exposure exactly.
	st, err := os.Stat(specPath)
	if err != nil {
		return fmt.Errorf("cannot stat the OCI spec %s: %w", specPath, err)
	}
	// Exclusive ownership of the temporary file (C3): CreateTemp opens
	// with O_CREATE|O_EXCL under an unpredictable random suffix inside
	// the bundle directory, so a pre-existing symlink or regular file at
	// any temporary-path name is never followed, adopted, or written
	// through — the write can only reach the file this invocation
	// created. The commit point remains the rename(2) below.
	temp, err := wrapperCreateTemp(bundlePath)
	if err != nil {
		return fmt.Errorf("cannot create the rewritten OCI spec temporary file: %w", err)
	}
	tempPath := temp.Name()
	// Pre-commit residue removal covers only the file this invocation
	// created, and a failed removal is surfaced rather than silently
	// discarded or claimed as a clean cleanup.
	discardTemp := func(cause error) error {
		if rmErr := os.Remove(tempPath); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			return fmt.Errorf("%w; additionally the wrapper temporary file %s remains (cleanup failed: %v)", cause, tempPath, rmErr)
		}
		return cause
	}
	if _, err := temp.Write(rewritten); err != nil {
		return discardTemp(fmt.Errorf("cannot write the rewritten OCI spec: %w", err))
	}
	if err := temp.Chmod(st.Mode().Perm()); err != nil {
		return discardTemp(fmt.Errorf("cannot preserve the OCI spec mode on the rewritten file: %w", err))
	}
	if err := temp.Close(); err != nil {
		return discardTemp(fmt.Errorf("cannot close the rewritten OCI spec temporary file: %w", err))
	}
	// THE COMMIT POINT (R4-P1-C1 §C1): a successful rename leaves the
	// rewritten spec in place for every later outcome, including an
	// execve failure — no rollback, no repair, no retry.
	if err := wrapperCommitRename(tempPath, specPath); err != nil {
		return discardTemp(fmt.Errorf("cannot commit the rewritten OCI spec (the original is unchanged): %w", err))
	}
	return nil
}

// optionsToAny renders a []string as the JSON any-form of the mount
// options array.
func optionsToAny(options []string) []any {
	out := make([]any, len(options))
	for i, o := range options {
		out[i] = o
	}
	return out
}
