package main

import (
	"os"
	"path/filepath"
)

// evalSymlinksFn and osStatFn are the single test seams for the privileged
// host-filesystem probes of session-facing pathnames: the Session-create
// workspace admission and resolution and the issuance-time filesystem_roots
// canonicalization (createSessionWithPolicyLocked), the run mount source
// resolution (resolveMount), and the build context and Dockerfile resolution
// (validateBuildRequest). The H3 boundary orders these probes strictly after
// lexical capability admission, and the seam lets a test count or fail the
// probes to prove zero probing for a request spelling that fails admission —
// evidence no equal-HTTP-response assertion can provide. Production default
// is filepath.EvalSymlinks / os.Stat; every other call site (config-root
// canonicalization, staging, pinning) keeps the stdlib functions directly.
var (
	evalSymlinksFn = filepath.EvalSymlinks
	osStatFn       = os.Stat
)
