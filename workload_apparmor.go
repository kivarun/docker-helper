package main

// workload_apparmor.go — the AppArmor workload MAC backend (Release 2.2
// Phase 2.2.6, mechanism accepted by M0-A).
//
// The backend renders one helper-owned workload profile from the final
// container-target/access plan, loads it through apparmor_parser before the
// correlated container can start, and verifies the load through the kernel
// profile inventory. The baseline follows the Moby docker-default AppArmor
// template exactly as proven by the M0-A proof; the only projection is the
// bounded write-denial set for accepted read-only container targets.
//
// The daemon's docker-helper-system profile and its managed workspace
// boundaries are a separate concern; this backend never reads or modifies
// them.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Production AppArmor facts. The parser path matches the shipped daemon
// profile machinery; the kernel profile inventory is the load-state proof.
const (
	appArmorWorkloadProfilePrefix = "docker-helper-workload-"
	appArmorProfilesInventoryPath = "/sys/kernel/security/apparmor/profiles"
	appArmorAbi30Path             = "/etc/apparmor.d/abi/3.0"
)

// aaPathLiteralSafe is the byte set that may appear verbatim in an AppArmor
// quoted AARE literal. Every other byte is emitted as an AppArmor hex
// escape, so no caller-controlled byte can become a quote, comment marker,
// glob, brace expansion, or profile delimiter.
const aaPathLiteralSafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/._-"

// appArmorPathLiteral converts a Linux path into an AppArmor quoted AARE
// literal. Slash and a conservative ASCII set remain readable; every other
// UTF-8 byte is emitted as an AppArmor hex escape. In particular, no caller
// byte can turn into `*`, `?`, `[`, `]`, `{`, `}`, `#`, `"`, `\`, or any
// other AppArmor syntax delimiter.
func appArmorPathLiteral(path string) string {
	out := make([]byte, 0, len(path))
	for i := 0; i < len(path); i++ {
		b := path[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '/' || b == '.' || b == '_' || b == '-' {
			out = append(out, b)
			continue
		}
		out = append(out, '\\', 'x')
		const hexDigits = "0123456789abcdef"
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out)
}

// workloadAppArmorProfileName derives the deterministic internal workload
// profile name from the server-generated Operation ID. Session, Launcher,
// Principal, mount targets, and caller input never participate in profile
// identity. Operation IDs are `op_` + 32 hex characters, so the name stays
// inside a bounded safe character set.
func workloadAppArmorProfileName(operationID string) string {
	return appArmorWorkloadProfilePrefix + operationID
}

// appArmorWorkloadProfileFileName is the helper-owned profile source file
// name inside one operation's durable state directory. The loaded profile
// name and this source path share one correlation owner: the ownership
// record in the same directory.
const appArmorWorkloadProfileFileName = "profile"

// workloadAppArmorBackend is the AppArmor backend for workload MAC
// preparation. It owns profile rendering, loading, unloading, load
// verification, and helper-owned profile state for one Operation.
type workloadAppArmorBackend struct {
	parserPath string
	// runParser executes apparmor_parser with the given arguments.
	// Production shells out to the real parser; tests inject a seam.
	runParser func(parserPath string, args []string) error
	// loadedProfiles returns the names of the profiles currently loaded in
	// the kernel inventory. Production reads
	// /sys/kernel/security/apparmor/profiles; tests inject a seam.
	loadedProfiles func() ([]string, error)
	// abi30Present reports whether the AppArmor ABI 3.0 definition exists
	// on this host (determines the abi include line, as in the M0 proof).
	abi30Present func() bool
}

func newWorkloadAppArmorBackend() *workloadAppArmorBackend {
	return &workloadAppArmorBackend{
		parserPath: appArmorParserPath,
		runParser: func(parserPath string, args []string) error {
			return newProductionParserRunner()(parserPath, args)
		},
		loadedProfiles: appArmorLoadedProfileNames,
		abi30Present:   func() bool { return fileExists(appArmorAbi30Path) },
	}
}

func (b *workloadAppArmorBackend) backend() LSMBackend {
	return LSMAppArmor
}

// appArmorLoadedProfileNames reads the kernel profile inventory and returns
// the loaded profile names. It is the production load-verification owner.
func appArmorLoadedProfileNames() ([]string, error) {
	data, err := os.ReadFile(appArmorProfilesInventoryPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read AppArmor profile inventory: %w", err)
	}
	var names []string
	for _, line := range stringLines(string(data)) {
		// Inventory lines look like: "profile-name (enforce)".
		if idx := indexByte(line, ' '); idx > 0 {
			line = line[:idx]
		}
		if line != "" {
			names = append(names, line)
		}
	}
	return names, nil
}

func stringLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// prepare renders, loads, and verifies the generated workload profile for
// the accepted exposure plan, and returns the prepared result whose
// SecurityOpts explicitly select that profile for the container.
func (b *workloadAppArmorBackend) prepare(p workloadPreparation) (*preparedWorkloadMAC, error) {
	if err := b.ensureParserAvailable(); err != nil {
		return nil, err
	}

	profileName := workloadAppArmorProfileName(p.OperationID)
	roTargets := workloadReadOnlyTargets(p.Exposures)
	profile := renderWorkloadAppArmorProfile(profileName, roTargets, b.abi30Present())
	profilePath := filepath.Join(p.StateDir, appArmorWorkloadProfileFileName)

	if err := atomicWriteFile(profilePath, []byte(profile), 0600); err != nil {
		return nil, fmt.Errorf("cannot write generated workload profile: %w", err)
	}
	if err := b.runParser(b.parserPath, []string{"--replace", "--skip-read-cache", profilePath}); err != nil {
		return nil, fmt.Errorf("cannot load generated workload profile: %w", err)
	}
	if err := b.requireProfileLoaded(profileName); err != nil {
		return nil, fmt.Errorf("generated workload profile is not loaded: %w", err)
	}

	return &preparedWorkloadMAC{
		Backend: LSMAppArmor,
		// Keep the existing SELinux-label-disable behavior of the AppArmor
		// path and explicitly select the generated workload profile; Docker
		// must never rely on an implicit default after preparation.
		SecurityOpts: []string{"label=disable", "apparmor=" + profileName},
		MountSources: p.PinnedSources,
		// The cleanup releases only the kernel MAC state and the backend
		// files that depend on it. The durable ownership record stays
		// behind as the reconciliation retry marker until the run-level
		// finalization boundary proves the dependent cleanup done.
		cleanup: func() error {
			return b.cleanupPrepared(p.StateDir, profileName)
		},
	}, nil
}

// cleanupPrepared unloads the generated profile (only if loaded), removes
// the helper-owned profile file and ownership state, and fails closed: a
// load/unload verification failure retains the owned state.
func (b *workloadAppArmorBackend) cleanupPrepared(stateDir, profileName string) error {
	profilePath := filepath.Join(stateDir, appArmorWorkloadProfileFileName)
	if err := b.unloadProfile(profilePath, profileName); err != nil {
		return err
	}
	// The profile is provably absent; the remaining files are pure state.
	if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove generated profile source: %w", err)
	}
	return nil
}

// unloadProfile removes a loaded generated profile through apparmor_parser
// and verifies the removal in the kernel inventory. An unverified removal
// is an error so the caller retains the owned state.
func (b *workloadAppArmorBackend) unloadProfile(profilePath, profileName string) error {
	loaded, err := b.isProfileLoaded(profileName)
	if err != nil {
		return err
	}
	if !loaded {
		return nil
	}
	if err := b.runParser(b.parserPath, []string{"--remove", profilePath}); err != nil {
		return fmt.Errorf("cannot unload generated workload profile: %w", err)
	}
	stillLoaded, err := b.isProfileLoaded(profileName)
	if err != nil {
		return err
	}
	if stillLoaded {
		return fmt.Errorf("generated workload profile remained loaded after removal")
	}
	return nil
}

// isProfileLoaded reports whether the profile name is currently loaded.
func (b *workloadAppArmorBackend) isProfileLoaded(profileName string) (bool, error) {
	loaded, err := b.loadedProfiles()
	if err != nil {
		return false, fmt.Errorf("cannot verify AppArmor profile inventory: %w", err)
	}
	for _, name := range loaded {
		if name == profileName {
			return true, nil
		}
	}
	return false, nil
}

// requireProfileLoaded fails closed unless the generated profile is verifiably
// loaded before any container may use it.
func (b *workloadAppArmorBackend) requireProfileLoaded(profileName string) error {
	loaded, err := b.isProfileLoaded(profileName)
	if err != nil {
		return err
	}
	if !loaded {
		return fmt.Errorf("generated workload profile was not loaded")
	}
	return nil
}

// ensureParserAvailable fails closed with an actionable operational error
// when the AppArmor parser is missing.
func (b *workloadAppArmorBackend) ensureParserAvailable() error {
	if _, err := os.Stat(b.parserPath); err != nil {
		return fmt.Errorf("apparmor_parser is not available at %s: %w", b.parserPath, err)
	}
	return nil
}

// validateOwnedState proves the durable AppArmor workload state is exact:
// the directory is a helper-owned directory whose record names the current
// backend, and the profile source file — when present — is a helper-owned
// regular file. The profile identity itself is derived from the record's
// operation ID at cleanup time, so a missing profile source is the safely
// classifiable crash window "ownership committed, crash before the profile
// source was written": an empty owned state whose cleanup is a no-op when
// the deterministic profile is absent from the kernel inventory. Anything
// else fails closed.
func (b *workloadAppArmorBackend) validateOwnedState(record workloadMACRecord) error {
	if record.Backend != string(LSMAppArmor) {
		return fmt.Errorf("record backend %q is not apparmor", record.Backend)
	}
	info, err := os.Lstat(filepath.Join(record.StateDirPath(), appArmorWorkloadProfileFileName))
	if err != nil {
		if os.IsNotExist(err) {
			// Ownership committed, crash before the profile source was
			// written: empty owned state, classified by cleanup against the
			// kernel inventory.
			return nil
		}
		return fmt.Errorf("cannot inspect generated profile source: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("generated profile source is not a helper-owned regular file")
	}
	return nil
}

// cleanupOwnedState removes the kernel profile and the helper-owned profile
// file of one owned record. Called only after container absence is proven.
//
// The profile name is derived from the record's operation ID, never read
// from durable state. A loaded deterministic profile without its profile
// source has no safe unload path and fails closed; an absent profile makes
// the remaining owned state empty and its cleanup a pure state removal.
func (b *workloadAppArmorBackend) cleanupOwnedState(record workloadMACRecord) error {
	stateDir := record.StateDirPath()
	profilePath := filepath.Join(stateDir, appArmorWorkloadProfileFileName)
	profileName := workloadAppArmorProfileName(record.OperationID)
	loaded, err := b.isProfileLoaded(profileName)
	if err != nil {
		return err
	}
	if loaded {
		info, err := os.Lstat(profilePath)
		if err != nil {
			return fmt.Errorf("loaded workload profile %s has no profile source for a safe unload: %w", profileName, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("generated profile source is not a helper-owned regular file")
		}
		if err := b.unloadProfile(profilePath, profileName); err != nil {
			return err
		}
	}
	if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove generated profile source: %w", err)
	}
	return nil
}

// renderWorkloadAppArmorProfile renders the deterministic generated workload
// profile for one operation: the Moby docker-default compatibility baseline
// plus one bounded audit-deny rule per accepted read-only container target.
// The output depends only on the profile name, the read-only targets, and
// whether the host publishes AppArmor ABI 3.0 — never on caller-controlled
// identity beyond the target paths, which are literal-encoded.
func renderWorkloadAppArmorProfile(profileName string, roTargets []string, abi30 bool) string {
	var sb strings.Builder
	sb.WriteString("# Generated by docker-helper. Do not edit.\n")
	sb.WriteString("# Helper-owned workload profile; correlated with one run operation.\n")
	if abi30 {
		sb.WriteString("abi <abi/3.0>,\n")
	}
	sb.WriteString("#include <tunables/global>\n\n")
	sb.WriteString("profile \"" + profileName + "\" flags=(attach_disconnected,mediate_deleted) {\n")
	sb.WriteString("  #include <abstractions/base>\n\n")
	sb.WriteString("  network,\n")
	sb.WriteString("  deny network alg,\n")
	sb.WriteString("  deny network vsock,\n")
	sb.WriteString("  capability,\n")
	sb.WriteString("  file,\n")
	sb.WriteString("  umount,\n")
	sb.WriteString("  signal (receive) peer=unconfined,\n")
	sb.WriteString("  signal (receive) peer=runc,\n")
	sb.WriteString("  signal (receive) peer=crun,\n")
	sb.WriteString("  signal (send,receive) peer=\"" + profileName + "\",\n\n")
	sb.WriteString("  deny @{PROC}/* w,\n")
	sb.WriteString("  deny @{PROC}/{[^1-9/],[^1-9/][^0-9/],[^1-9s/][^0-9y/][^0-9s/],[^1-9/][^0-9/][^0-9/][^0-9/]*}/** w,\n")
	sb.WriteString("  deny @{PROC}/sys/[^k]** w,\n")
	sb.WriteString("  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,\n")
	sb.WriteString("  deny @{PROC}/sysrq-trigger rwklx,\n")
	sb.WriteString("  deny @{PROC}/kcore rwklx,\n")
	sb.WriteString("  deny mount,\n")
	sb.WriteString("  deny /sys/[^f]*/** wklx,\n")
	sb.WriteString("  deny /sys/f[^s]*/** wklx,\n")
	sb.WriteString("  deny /sys/fs/[^c]*/** wklx,\n")
	sb.WriteString("  deny /sys/fs/c[^g]*/** wklx,\n")
	sb.WriteString("  deny /sys/firmware/** rwklx,\n")
	sb.WriteString("  deny /sys/devices/virtual/powercap/** rwklx,\n")
	sb.WriteString("  deny /sys/kernel/security/** rwklx,\n")
	sb.WriteString("  ptrace (trace,tracedby,read,readby) peer=\"" + profileName + "\",\n")
	for _, target := range roTargets {
		sb.WriteString("\n  audit deny \"" + appArmorPathLiteral(target) + "/{,**}\" wkl,\n")
	}
	sb.WriteString("}\n")
	return sb.String()
}
