package main

// Live backend verification for Phase 2.2.6 (bounded live evidence gate).
// These tests exercise the PRODUCTION renderers, drivers, and lifecycle
// owners — the real AppArmor parser, real bindfs/FUSE mounts, the real
// kernel LSMs, and the real Docker daemon — to prove the independent MAC
// denial of would-be read-only exposures. They are skipped in ordinary
// test runs and are enabled only by the dedicated live-evidence workflows
// with DOCKER_HELPER_LIVE_WORKLOAD_PROOF=1 on a prepared rootful host
// (GitHub runner for AppArmor, enforcing Tumbleweed VM for SELinux).
//
// The proof follows the release requirement: VFS readonly alone is not MAC
// evidence. After the application decision the read-only exposure is
// deliberately VFS-writable, but the production MAC mechanism (generated
// AppArmor profile / bindfs SELinux projection) denies the mutation, with
// attributable denial evidence.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

const liveProofEnv = "DOCKER_HELPER_LIVE_WORKLOAD_PROOF"

// requiredLiveProof reports whether the caller requested the bounded live
// evidence proof. In required mode every missing mandatory prerequisite is a
// FAIL (non-zero exit), never a Skip: a required proof must not close through
// the skip exit path.
func requiredLiveProof() bool {
	return os.Getenv(liveProofEnv) == "1"
}

func requireLiveProof(t *testing.T) {
	t.Helper()
	if !requiredLiveProof() {
		t.Skip("live workload proof requires " + liveProofEnv + "=1")
	}
	if os.Getuid() != 0 {
		t.Fatalf("required live workload proof must run as root")
	}
}

// requireLiveProofDependency gates one live-proof prerequisite. In required
// mode an unmet prerequisite is a hard failure with non-zero exit; in
// developer/default mode (live proof not requested) it skips so ordinary
// test runs stay green without the live backends.
func requireLiveProofDependency(t *testing.T, ready bool, reason string) {
	t.Helper()
	if requiredLiveProof() {
		if !ready {
			t.Fatalf("required live workload proof prerequisite failed: %s", reason)
		}
		return
	}
	if !ready {
		t.Skip(reason)
	}
}

// dockerLiveAvailable reports whether the real Docker daemon answers.
func dockerLiveAvailable(t *testing.T) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	return cmd.Run() == nil
}

// repoHead returns the tested source commit when the proof binary runs from
// a checkout, empty otherwise.
func repoHead(t *testing.T) string {
	t.Helper()
	if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return "unknown"
}

// containsString reports whether the list contains the exact value.
func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// getenforceLive returns the getenforce output when available.
func getenforceLive() (string, error) {
	out, err := exec.Command("getenforce").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// inodeContextOf returns "<device>:<inode>|<SELinux context>" of a host
// path; equal values before and after preparation and cleanup are the
// no-relabel evidence.
func inodeContextOf(path string) string {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return "stat-error"
	}
	ctx, _ := getxattrSELinux(path)
	return fmt.Sprintf("%d:%d|%s", stat.Dev, stat.Ino, ctx)
}

// runInContainerWithOpts starts one container with the given bind and
// security options, executes the shell snippet inside it, and returns the
// command error (nonzero exit = the denial surfaced inside the container).
func runInContainerWithOpts(t *testing.T, securityOpts []string, bind, snippet string) error {
	t.Helper()
	args := []string{"run", "--rm"}
	for _, opt := range securityOpts {
		args = append(args, "--security-opt", opt)
	}
	if bind != "" {
		args = append(args, "-v", bind)
	}
	args = append(args, "alpine:3.19", "/bin/sh", "-c", snippet)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("container output: %s %s: %w",
			strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), err)
	}
	return nil
}

// runInContainerWithBinds runs one container with several bind mounts and
// the given security options (nonzero exit = the denial surfaced inside
// the container).
func runInContainerWithBinds(t *testing.T, securityOpts []string, binds []string, snippet string) error {
	t.Helper()
	args := []string{"run", "--rm"}
	for _, opt := range securityOpts {
		args = append(args, "--security-opt", opt)
	}
	for _, bind := range binds {
		args = append(args, "-v", bind)
	}
	args = append(args, "alpine:3.19", "/bin/sh", "-c", snippet)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("container output: %s %s: %w",
			strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), err)
	}
	return nil
}

// appArmorDenialLogged scans the kernel log for an AppArmor DENIED record
// attributable to the generated workload profile. The audit.log sink is
// checked first: while auditd drains the kernel audit netlink queue, records
// reach only audit.log, whereas the printk fallback (dmesg, journalctl -k)
// rate-limits and can silently drop the attributable record.
func appArmorDenialLogged(t *testing.T, profileName string) (bool, string) {
	t.Helper()
	sources := [][]string{
		{"cat", "/var/log/audit/audit.log"},
		{"dmesg"},
		{"journalctl", "--no-pager", "-k", "--since", "5 minutes ago"},
	}
	for _, argv := range sources {
		out, err := exec.Command(argv[0], argv[1:]...).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, `apparmor="DENIED"`) && strings.Contains(line, profileName) {
				return true, strings.TrimSpace(line)
			}
		}
	}
	return false, ""
}

// liveContainerProcessLabel runs one container carrying the given security
// options and reports the process label observed inside the container.
func liveContainerProcessLabel(t *testing.T, securityOpts []string) (string, error) {
	t.Helper()
	args := []string{"run", "--rm", "--entrypoint", "/bin/cat"}
	for _, opt := range securityOpts {
		args = append(args, "--security-opt", opt)
	}
	args = append(args, "alpine:3.19", "/proc/self/attr/current")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

// TestLiveWorkloadAppArmor drives the production AppArmor backend through
// prepare (render + real parser load + load verification), runs a container
// with the prepared security options over a deliberately VFS-writable
// would-be read-only target, and proves the attributable AppArmor denial
// plus the unload/state cleanup.
func TestLiveWorkloadAppArmor(t *testing.T) {
	requireLiveProof(t)
	requireLiveProofDependency(t, dockerLiveAvailable(t), "docker daemon unavailable")
	requireLiveProofDependency(t, fileExists(appArmorParserPath), "apparmor_parser unavailable")
	active, lsmErr := appArmorLSMActive()
	requireLiveProofDependency(t, lsmErr == nil && active,
		fmt.Sprintf("AppArmor is not the active LSM: active=%v err=%v", active, lsmErr))
	dir, err := os.MkdirTemp("", "docker-helper-live-aa-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	target := filepath.Join(dir, "inputs")
	// Deliberately world-writable: the VFS view must be writable so the
	// denial observed below is attributable to AppArmor, not the VFS.
	if err := os.Mkdir(target, 0777); err != nil {
		t.Fatal(err)
	}

	b := newWorkloadAppArmorBackend()
	prep := workloadPreparation{
		OperationID:   "op_liveaa1",
		SessionID:     "live",
		StateDir:      filepath.Join(dir, "state", "op_liveaa1"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_liveaa1"),
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}},
		PinnedSources: []string{target},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, prepErr := b.prepare(prep)
	if prepErr != nil {
		t.Fatalf("production AppArmor prepare: %v", prepErr)
	}
	profileName := workloadAppArmorProfileName(prep.OperationID)
	defer prepared.Cleanup()

	// VFS-writable would-be-RO target under the production security
	// options: the write inside the container must fail, and the denial
	// must be attributable to the generated profile.
	writeErr := runInContainerWithOpts(t, prepared.SecurityOpts,
		fmt.Sprintf("%s:/inputs:rw", target),
		"echo live-proof-write > /inputs/probe",
	)
	if writeErr == nil {
		t.Fatal("AppArmor must deny writes through the would-be-RO target (the VFS view is writable)")
	}
	t.Logf("denied write output: %v", writeErr)

	denied, denialLine := appArmorDenialLogged(t, profileName)
	if !denied {
		t.Fatal("attributable AppArmor DENIED record not found")
	}
	t.Logf("attributable denial: %s", denialLine)
	liveEvidence(t, "apparmor-denial.txt", denialLine+"\n")
	liveEvidence(t, "apparmor-summary.txt",
		fmt.Sprintf("TESTED_SOURCE=%s\nPROFILE=%s\nRESULT=CLOSED\n", repoHead(t), profileName))

	if err := prepared.Cleanup(); err != nil {
		t.Fatalf("production AppArmor cleanup: %v", err)
	}
	loaded, err := appArmorLoadedProfileNames()
	if err != nil {
		t.Fatalf("cannot read kernel profile inventory: %v", err)
	}
	if containsString(loaded, profileName) {
		t.Fatal("generated profile must be unloaded after cleanup")
	}
	// The backend cleanup releases the kernel MAC state and the generated
	// profile source; the durable ownership record directory remains as
	// the reconciliation retry marker and is removed only by the
	// coordinator finalization boundary.
	if _, statErr := os.Stat(filepath.Join(dir, "state", "op_liveaa1", appArmorWorkloadProfileFileName)); !os.IsNotExist(statErr) {
		t.Errorf("generated profile source must be removed by the backend cleanup, got %v", statErr)
	}
}

// liveContainerOutput is runInContainerWithOpts with the container stdout
// returned for content proofs (nonzero exit = error with the output).
func liveContainerOutput(t *testing.T, securityOpts []string, bind, snippet string) (string, error) {
	t.Helper()
	args := []string{"run", "--rm"}
	for _, opt := range securityOpts {
		args = append(args, "--security-opt", opt)
	}
	if bind != "" {
		args = append(args, "-v", bind)
	}
	args = append(args, "alpine:3.19", "/bin/sh", "-c", snippet)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("container output: %s %s: %w",
			strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), err)
	}
	return stdout.String(), nil
}

// selinuxAVCMatched returns a recent AVC line involving the projection
// type, the given access, and the exact object class, or "" when none is
// found. The class match keeps each proof's denial evidence attributable
// to its own write instead of a neighboring test's AVC.
func selinuxAVCMatched(t *testing.T, targetType, access, tclass string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ausearch", "-m", "AVC", "-ts", "recent").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, targetType) && strings.Contains(line, access) && strings.Contains(line, "tclass="+tclass) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// TestLiveWorkloadSELinux drives the production SELinux backend end to end:
// pinned source, bindfs projection with the exact mount context, proof
// chain, a container carrying the production label over the deliberately
// VFS-writable projection, the write denial with a matching AVC, no source
// relabel, and cleanup of the owned projection state.
func TestLiveWorkloadSELinux(t *testing.T) {
	requireLiveProof(t)
	requireLiveProofDependency(t, dockerLiveAvailable(t), "docker daemon unavailable")
	_, fuseErr := os.Stat(selinuxDevFusePath)
	requireLiveProofDependency(t, fuseErr == nil, fmt.Sprintf("/dev/fuse unavailable: %v", fuseErr))
	_, bindfsErr := exec.LookPath("bindfs")
	requireLiveProofDependency(t, bindfsErr == nil, fmt.Sprintf("bindfs unavailable: %v", bindfsErr))
	state, enforceErr := getenforceLive()
	requireLiveProofDependency(t, enforceErr == nil && state == "Enforcing",
		fmt.Sprintf("SELinux is not enforcing: state=%q err=%v", state, enforceErr))
	dir, err := os.MkdirTemp("", "docker-helper-live-selinux-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	source := filepath.Join(dir, "backing")
	if err := os.MkdirAll(source, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "seed.txt"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Pin the source through the production mount-pin owner so the
	// projection is built exactly from the kernel materialization source.
	pinned, err := pinWorkspaceMountSource(filepath.Dir(source), source,
		filepath.Join(dir, "runtime"), "op_livesel1", 0)
	if err != nil {
		t.Fatalf("production pin: %v", err)
	}
	defer pinned.Cleanup()

	before := inodeContextOf(source)
	b := newWorkloadSELinuxBackend()
	prep := workloadPreparation{
		OperationID:   "op_livesel1",
		SessionID:     "live",
		StateDir:      filepath.Join(dir, "state", "op_livesel1"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_livesel1"),
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}},
		PinnedSources: []string{pinned.PinnedPath},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, prepErr := b.prepare(prep)
	if prepErr != nil {
		t.Fatalf("production SELinux prepare: %v", prepErr)
	}
	defer prepared.Cleanup()
	if after := inodeContextOf(source); after != before {
		t.Fatalf("source device/inode/context must be preserved: before=%q after=%q", before, after)
	}

	projection := prepared.MountSources[0]
	// Independent-MAC proof precondition: the projection is VFS writable
	// underneath (writable bindfs passthrough) and carries the exact
	// projection type.
	if err := os.WriteFile(filepath.Join(projection, "lower-probe"), []byte("x"), 0600); err != nil {
		t.Fatalf("projection is not VFS-writable for the proof: %v", err)
	}
	if got, err := b.ops.selinuxTypeOf(projection); err != nil || got != selinuxROProjectionType {
		t.Fatalf("projection effective type: got %q (err %v), want %q", got, err, selinuxROProjectionType)
	}

	// Run the container with the production label over the projection and
	// attempt the write: the mutation must be denied by the SELinux type.
	writeErr := runInContainerWithOpts(t, prepared.SecurityOpts,
		fmt.Sprintf("%s:/inputs:rw", projection),
		"echo live-proof-write > /inputs/probe",
	)
	if writeErr == nil {
		t.Fatal("write through the projected read-only exposure must fail under docker_helper_container_t")
	}
	t.Logf("denied write output: %v", writeErr)

	avc := selinuxAVCMatched(t, "docker_helper_ro_projection_t", "write", "dir")
	if avc == "" {
		t.Fatal("matching SELinux AVC not found")
	}
	t.Logf("attributable AVC: %s", avc)
	liveEvidence(t, "selinux-avc.txt", avc+"\n")
	liveEvidence(t, "selinux-summary.txt",
		fmt.Sprintf("TESTED_SOURCE=%s\nRESULT=CLOSED\n", repoHead(t)))

	if err := prepared.Cleanup(); err != nil {
		t.Fatalf("production SELinux cleanup: %v", err)
	}
	if after := inodeContextOf(source); after != before {
		t.Fatalf("source device/inode/context must be unchanged after cleanup: before=%q after=%q", before, after)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "runtime", "op_livesel1", "mount-0")); !os.IsNotExist(statErr) {
		t.Errorf("owned projection runtime state must be removed after cleanup, got %v", statErr)
	}
}

// TestLiveWorkloadSELinuxRegularFile drives the production SELinux
// regular-file mechanism end to end: a real pinned regular file, the
// lower-item bind, the bindfs projection of the lower directory with the
// exact mount context, a container carrying the production label that reads
// the projected item successfully and is denied writing it, an attributable
// AVC, and a cleanup that leaves the backing inode and context unchanged.
func TestLiveWorkloadSELinuxRegularFile(t *testing.T) {
	requireLiveProof(t)
	requireLiveProofDependency(t, dockerLiveAvailable(t), "docker daemon unavailable")
	_, fuseErr := os.Stat(selinuxDevFusePath)
	requireLiveProofDependency(t, fuseErr == nil, fmt.Sprintf("/dev/fuse unavailable: %v", fuseErr))
	_, bindfsErr := exec.LookPath("bindfs")
	requireLiveProofDependency(t, bindfsErr == nil, fmt.Sprintf("bindfs unavailable: %v", bindfsErr))
	state, enforceErr := getenforceLive()
	requireLiveProofDependency(t, enforceErr == nil && state == "Enforcing",
		fmt.Sprintf("SELinux is not enforcing: state=%q err=%v", state, enforceErr))
	dir, err := os.MkdirTemp("", "docker-helper-live-selfile-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	// Deliberately writable parent: the file mutation denial below must be
	// attributable to the projection type, not the VFS.
	if err := os.MkdirAll(filepath.Join(dir, "backing"), 0777); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "backing", "seed.txt")
	if err := os.WriteFile(source, []byte("seed-content\n"), 0666); err != nil {
		t.Fatal(err)
	}

	// Pin the regular file through the production mount-pin owner.
	pinned, err := pinWorkspaceMountSource(filepath.Dir(source), source,
		filepath.Join(dir, "runtime"), "op_liveself1", 0)
	if err != nil {
		t.Fatalf("production pin: %v", err)
	}
	defer pinned.Cleanup()

	before := inodeContextOf(source)
	b := newWorkloadSELinuxBackend()
	prep := workloadPreparation{
		OperationID:   "op_liveself1",
		SessionID:     "live",
		StateDir:      filepath.Join(dir, "state", "op_liveself1"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_liveself1"),
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}},
		PinnedSources: []string{pinned.PinnedPath},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, prepErr := b.prepare(prep)
	if prepErr != nil {
		t.Fatalf("production SELinux regular-file prepare: %v", prepErr)
	}
	defer prepared.Cleanup()
	if after := inodeContextOf(source); after != before {
		t.Fatalf("source device/inode/context must be preserved: before=%q after=%q", before, after)
	}

	projection := prepared.MountSources[0]
	// Read through the projected regular file must succeed and return the
	// pinned content before any proof-side mutation.
	readOut, readErr := liveContainerOutput(t, prepared.SecurityOpts,
		fmt.Sprintf("%s:/inputs:rw", projection),
		"cat /inputs",
	)
	if readErr != nil {
		t.Fatalf("read through the projected regular file must succeed: %v", readErr)
	}
	if strings.TrimSpace(readOut) != "seed-content" {
		t.Fatalf("projected regular file must carry the pinned content, got %q", readOut)
	}
	// Independent-MAC proof precondition: the projected item is VFS
	// writable underneath (a write-only open succeeds; nothing is mutated)
	// and carries the exact projection type.
	probeFD, probeErr := os.OpenFile(projection, os.O_WRONLY, 0)
	if probeErr != nil {
		t.Fatalf("projected item is not VFS-writable for the proof: %v", probeErr)
	}
	probeFD.Close()
	if got, err := b.ops.selinuxTypeOf(projection); err != nil || got != selinuxROProjectionType {
		t.Fatalf("projected item effective type: got %q (err %v), want %q", got, err, selinuxROProjectionType)
	}

	// The write must be denied by the projection type while the VFS view
	// is writable: the shell surfaces the MAC denial as EACCES.
	writeErr := runInContainerWithOpts(t, prepared.SecurityOpts,
		fmt.Sprintf("%s:/inputs:rw", projection),
		"echo live-proof-write > /inputs",
	)
	if writeErr == nil {
		t.Fatal("write through the projected regular file must fail under docker_helper_container_t")
	}
	if !strings.Contains(writeErr.Error(), "Permission denied") {
		t.Fatalf("the regular-file write must be denied by the MAC layer, got %v", writeErr)
	}
	t.Logf("denied write output: %v", writeErr)

	avc := selinuxAVCMatched(t, "docker_helper_ro_projection_t", "write", "file")
	if avc == "" {
		t.Fatal("matching SELinux AVC not found")
	}
	t.Logf("attributable AVC: %s", avc)
	liveEvidence(t, "selinux-regular-file-avc.txt", avc+"\n")
	liveEvidence(t, "selinux-regular-file-summary.txt",
		fmt.Sprintf("TESTED_SOURCE=%s\nRESULT=CLOSED\n", repoHead(t)))

	// The denied write must not have mutated the pinned source content.
	afterContent, readErr := os.ReadFile(source)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(afterContent) != "seed-content\n" {
		t.Fatalf("denied write must not mutate the pinned source, got %q", afterContent)
	}
	if err := prepared.Cleanup(); err != nil {
		t.Fatalf("production SELinux regular-file cleanup: %v", err)
	}
	if after := inodeContextOf(source); after != before {
		t.Fatalf("source device/inode/context must be unchanged after cleanup: before=%q after=%q", before, after)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "runtime", "op_liveself1", "mount-0")); !os.IsNotExist(statErr) {
		t.Errorf("owned projection runtime state must be removed after cleanup, got %v", statErr)
	}
}

// TestLiveWorkloadMCSConcurrentRWRO proves MCS preservation on the same
// backing tree: two containers under the production label, one bound to the
// pinned source read-write (direct bind, no projection) and one bound to
// the production read-only projection, run with different Docker-assigned
// MCS categories, the read-write write succeeds, the read-only write is
// denied, and the backing labels never change.
func TestLiveWorkloadMCSConcurrentRWRO(t *testing.T) {
	requireLiveProof(t)
	requireLiveProofDependency(t, dockerLiveAvailable(t), "docker daemon unavailable")
	_, fuseErr := os.Stat(selinuxDevFusePath)
	requireLiveProofDependency(t, fuseErr == nil, fmt.Sprintf("/dev/fuse unavailable: %v", fuseErr))
	_, bindfsErr := exec.LookPath("bindfs")
	requireLiveProofDependency(t, bindfsErr == nil, fmt.Sprintf("bindfs unavailable: %v", bindfsErr))
	state, enforceErr := getenforceLive()
	requireLiveProofDependency(t, enforceErr == nil && state == "Enforcing",
		fmt.Sprintf("SELinux is not enforcing: state=%q err=%v", state, enforceErr))
	dir, err := os.MkdirTemp("", "docker-helper-live-mcs-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	source := filepath.Join(dir, "backing")
	// Deliberately world-writable: the read-write container write must
	// succeed on the VFS; the read-only denial is attributable to the
	// projection type.
	if err := os.MkdirAll(source, 0777); err != nil {
		t.Fatal(err)
	}
	labelsBefore := inodeContextOf(source)

	pinned, err := pinWorkspaceMountSource(filepath.Dir(source), source,
		filepath.Join(dir, "runtime"), "op_livemcs1", 0)
	if err != nil {
		t.Fatalf("production pin: %v", err)
	}
	defer pinned.Cleanup()

	b := newWorkloadSELinuxBackend()
	prep := workloadPreparation{
		OperationID:   "op_livemcs1",
		SessionID:     "live",
		StateDir:      filepath.Join(dir, "state", "op_livemcs1"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_livemcs1"),
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}},
		PinnedSources: []string{pinned.PinnedPath},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, prepErr := b.prepare(prep)
	if prepErr != nil {
		t.Fatalf("production SELinux prepare: %v", prepErr)
	}
	defer prepared.Cleanup()

	// Read-write container: direct bind of the pinned source, write must
	// succeed.
	rwOpts := []string{"label=type:docker_helper_container_t"}
	if err := runInContainerWithOpts(t, rwOpts,
		fmt.Sprintf("%s:/project:rw", pinned.PinnedPath),
		"echo mcs-rw-proof > /project/rw-write && cat /proc/self/attr/current",
	); err != nil {
		t.Fatalf("read-write container write must succeed: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(source, "rw-write")); statErr != nil {
		t.Fatalf("read-write write must land on the backing tree: %v", statErr)
	}

	// Read-only container: production projection, write must fail and the
	// denial must carry a matching AVC.
	roErr := runInContainerWithOpts(t, prepared.SecurityOpts,
		fmt.Sprintf("%s:/inputs:rw", prepared.MountSources[0]),
		"echo mcs-ro-proof > /inputs/ro-write && cat /proc/self/attr/current",
	)
	if roErr == nil {
		t.Fatal("read-only container write through the projection must be denied")
	}
	t.Logf("denied read-only write output: %v", roErr)
	avc := selinuxAVCMatched(t, "docker_helper_ro_projection_t", "write", "dir")
	if avc == "" {
		t.Fatal("matching SELinux AVC not found")
	}

	// Process labels: both containers must run as docker_helper_container_t
	// with Docker-assigned (therefore distinct) MCS categories.
	rwLabel := containerProcessLabel(t, rwOpts, pinned.PinnedPath)
	roLabel := containerProcessLabel(t, prepared.SecurityOpts, prepared.MountSources[0])
	if !strings.Contains(rwLabel, "docker_helper_container_t") || !strings.Contains(roLabel, "docker_helper_container_t") {
		t.Fatalf("both container processes must run as docker_helper_container_t: rw=%q ro=%q", rwLabel, roLabel)
	}
	if rwLabel == roLabel {
		t.Fatalf("Docker-assigned MCS categories must differ: rw=%q ro=%q", rwLabel, roLabel)
	}
	liveEvidence(t, "mcs-summary.txt", fmt.Sprintf(
		"TESTED_SOURCE=%s\nRW_LABEL=%s\nRO_LABEL=%s\nRESULT=CLOSED\n",
		repoHead(t), rwLabel, roLabel))

	if after := inodeContextOf(source); after != labelsBefore {
		t.Fatalf("backing labels must be unchanged: before=%q after=%q", labelsBefore, after)
	}
}

// containerProcessLabel starts one container with the given bind and
// security options and returns the observed process label.
func containerProcessLabel(t *testing.T, securityOpts []string, bind string) string {
	t.Helper()
	args := []string{"run", "--rm"}
	for _, opt := range securityOpts {
		args = append(args, "--security-opt", opt)
	}
	args = append(args, "-v", fmt.Sprintf("%s:/inputs:ro", bind), "alpine:3.19", "/bin/cat", "/proc/self/attr/current")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("cannot observe container process label: %v: %s", err, strings.TrimSpace(out.String()))
	}
	return strings.TrimSpace(out.String())
}

// liveEvidence writes a proof artifact into WORKLOAD_EVIDENCE_DIR when set,
// mirroring how the M0 live workflows archive their evidence.
func liveEvidence(t *testing.T, name, content string) {
	t.Helper()
	dir := os.Getenv("WORKLOAD_EVIDENCE_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
}

// TestLiveWorkloadAppArmorRegularFile proves F2 with live kernel behavior:
// a read-only exposure whose pinned source is a regular file keeps the
// file readable but denies every mutation semantics (write, delete) of
// the file itself through the generated profile, while the VFS view of
// the same file stays deliberately writable.
func TestLiveWorkloadAppArmorRegularFile(t *testing.T) {
	requireLiveProof(t)
	requireLiveProofDependency(t, dockerLiveAvailable(t), "docker daemon unavailable")
	requireLiveProofDependency(t, fileExists(appArmorParserPath), "apparmor_parser unavailable")
	active, lsmErr := appArmorLSMActive()
	requireLiveProofDependency(t, lsmErr == nil && active,
		fmt.Sprintf("AppArmor is not the active LSM: active=%v err=%v", active, lsmErr))
	dir, err := os.MkdirTemp("", "docker-helper-live-aafile-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	// Deliberately world-writable regular file: the denial observed below
	// is attributable to AppArmor, not the VFS.
	source := filepath.Join(dir, "config.txt")
	if err := os.WriteFile(source, []byte("payload\n"), 0666); err != nil {
		t.Fatal(err)
	}

	b := newWorkloadAppArmorBackend()
	prep := workloadPreparation{
		OperationID:   "op_liveaafile1",
		SessionID:     "live",
		StateDir:      filepath.Join(dir, "state", "op_liveaafile1"),
		RuntimeDir:    filepath.Join(dir, "runtime", "op_liveaafile1"),
		Exposures:     []sessionFilesystemExposure{{Target: "/config.txt", RequestedReadOnly: true}},
		PinnedSources: []string{source},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, prepErr := b.prepare(prep)
	if prepErr != nil {
		t.Fatalf("production AppArmor prepare: %v", prepErr)
	}
	profileName := workloadAppArmorProfileName(prep.OperationID)
	defer prepared.Cleanup()

	readOut, readErr := liveContainerOutput(t, prepared.SecurityOpts,
		fmt.Sprintf("%s:/config.txt:rw", source), "cat /config.txt")
	if readErr != nil {
		t.Fatalf("read through the RO file bind must succeed: %v (%s)", readErr, readOut)
	}
	if !strings.Contains(readOut, "payload") {
		t.Fatalf("unexpected read content %q", readOut)
	}

	writeErr := runInContainerWithOpts(t, prepared.SecurityOpts,
		fmt.Sprintf("%s:/config.txt:rw", source),
		"echo corrupt > /config.txt",
	)
	if writeErr == nil {
		t.Fatal("AppArmor must deny writes to the would-be-RO regular file (the VFS view is writable)")
	}
	t.Logf("denied file write output: %v", writeErr)

	denied, denialLine := appArmorDenialLogged(t, profileName)
	if !denied {
		t.Fatal("attributable AppArmor DENIED record not found for the regular-file write")
	}
	if !strings.Contains(denialLine, "config.txt") {
		t.Fatalf("denial must reference the mediated file path: %s", denialLine)
	}
	t.Logf("attributable denial: %s", denialLine)
	liveEvidence(t, "apparmor-regular-file-denial.txt", denialLine+"\n")
	liveEvidence(t, "apparmor-regular-file-summary.txt",
		fmt.Sprintf("TESTED_SOURCE=%s\nPROFILE=%s\nRESULT=CLOSED\n", repoHead(t), profileName))
}

// TestLiveWorkloadAppArmorNestedRW proves F3 with live kernel behavior:
// with RO /work plus RW /work/output, writes inside the accepted RW
// transition succeed while writes outside it are denied, and a nested RO
// island (RO /work/output/protected) is denied independently of the RW
// transition around it.
func TestLiveWorkloadAppArmorNestedRW(t *testing.T) {
	requireLiveProof(t)
	requireLiveProofDependency(t, dockerLiveAvailable(t), "docker daemon unavailable")
	requireLiveProofDependency(t, fileExists(appArmorParserPath), "apparmor_parser unavailable")
	active, lsmErr := appArmorLSMActive()
	requireLiveProofDependency(t, lsmErr == nil && active,
		fmt.Sprintf("AppArmor is not the active LSM: active=%v err=%v", active, lsmErr))
	dir, err := os.MkdirTemp("", "docker-helper-live-aanest-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	// Region tree, deliberately world-writable everywhere.
	work := filepath.Join(dir, "work")
	output := filepath.Join(work, "output")
	protected := filepath.Join(output, "protected")
	for _, d := range []string{work, output, protected} {
		if err := os.Mkdir(d, 0777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work, "inputs.txt"), []byte("ro\n"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(protected, "guarded.txt"), []byte("ro\n"), 0666); err != nil {
		t.Fatal(err)
	}

	b := newWorkloadAppArmorBackend()
	prep := workloadPreparation{
		OperationID: "op_livaanest1",
		SessionID:   "live",
		StateDir:    filepath.Join(dir, "state", "op_livaanest1"),
		RuntimeDir:  filepath.Join(dir, "runtime", "op_livaanest1"),
		Exposures: []sessionFilesystemExposure{
			{Target: "/work", RequestedReadOnly: true},
			{Target: "/work/output", RequestedReadOnly: false},
		},
		PinnedSources: []string{work, output},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, prepErr := b.prepare(prep)
	if prepErr != nil {
		t.Fatalf("production AppArmor prepare: %v", prepErr)
	}
	profileName := workloadAppArmorProfileName(prep.OperationID)
	defer prepared.Cleanup()

	// The accepted RW transition must stay writable.
	if err := runInContainerWithBinds(t, prepared.SecurityOpts,
		[]string{fmt.Sprintf("%s:/work:rw", work), fmt.Sprintf("%s:/work/output:rw", output)},
		"echo rw-transition > /work/output/probe",
	); err != nil {
		t.Fatalf("accepted RW transition must stay writable: %v", err)
	}
	// The RO region outside the transition must be denied.
	regionErr := runInContainerWithBinds(t, prepared.SecurityOpts,
		[]string{fmt.Sprintf("%s:/work:rw", work), fmt.Sprintf("%s:/work/output:rw", output)},
		"echo outside > /work/inputs.txt",
	)
	if regionErr == nil {
		t.Fatal("AppArmor must deny writes in the RO region outside the RW transition")
	}
	t.Logf("denied RO-region write output: %v", regionErr)

	// The nested RO island must be denied through its own recursive rule.
	islandPrep := workloadPreparation{
		OperationID: "op_livaanest2",
		SessionID:   "live",
		StateDir:    filepath.Join(dir, "state", "op_livaanest2"),
		RuntimeDir:  filepath.Join(dir, "runtime", "op_livaanest2"),
		Exposures: []sessionFilesystemExposure{
			{Target: "/work", RequestedReadOnly: true},
			{Target: "/work/output", RequestedReadOnly: false},
			{Target: "/work/output/protected", RequestedReadOnly: true},
		},
		PinnedSources: []string{work, output, protected},
	}
	if err := os.MkdirAll(islandPrep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(islandPrep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	island, islandErr := b.prepare(islandPrep)
	if islandErr != nil {
		t.Fatalf("production AppArmor prepare (island): %v", islandErr)
	}
	defer island.Cleanup()
	islandName := workloadAppArmorProfileName(islandPrep.OperationID)

	islandRWErr := runInContainerWithBinds(t, island.SecurityOpts,
		[]string{
			fmt.Sprintf("%s:/work:rw", work),
			fmt.Sprintf("%s:/work/output:rw", output),
			fmt.Sprintf("%s:/work/output/protected:rw", protected),
		},
		"echo island > /work/output/protected/probe",
	)
	if islandRWErr == nil {
		t.Fatal("AppArmor must deny writes into the nested RO island")
	}
	t.Logf("denied island write output: %v", islandRWErr)

	denied, denialLine := appArmorDenialLogged(t, profileName)
	if !denied {
		t.Fatal("attributable AppArmor DENIED record not found for the RO-region write")
	}
	t.Logf("attributable denial: %s", denialLine)
	liveEvidence(t, "apparmor-nested-rw-denial.txt", denialLine+"\n")
	liveEvidence(t, "apparmor-nested-rw-summary.txt",
		fmt.Sprintf("TESTED_SOURCE=%s\nPROFILE=%s\nISLAND_PROFILE=%s\nRESULT=CLOSED\n",
			repoHead(t), profileName, islandName))
}

// TestLiveWorkloadAppArmorPrefixCollisionRW proves the prefix-collision
// renderer semantics with live kernel behavior: with RO /work plus the
// prefix-collision RW holes /work/a and /work/ab, writes inside both
// accepted RW subtrees succeed while sibling and continued-prefix names
// beneath the RO parent are denied. The pre-fix renderer emitted a
// `[^class]**` diverge alternative whose negated class matches '/' and
// whose `**` crosses separators, so the generated deny rule matched
// /work/a/file and the accepted RW subtree was wrongly denied.
func TestLiveWorkloadAppArmorPrefixCollisionRW(t *testing.T) {
	requireLiveProof(t)
	requireLiveProofDependency(t, dockerLiveAvailable(t), "docker daemon unavailable")
	requireLiveProofDependency(t, fileExists(appArmorParserPath), "apparmor_parser unavailable")
	active, lsmErr := appArmorLSMActive()
	requireLiveProofDependency(t, lsmErr == nil && active,
		fmt.Sprintf("AppArmor is not the active LSM: active=%v err=%v", active, lsmErr))
	dir, err := os.MkdirTemp("", "docker-helper-live-aapc-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	// Region tree, deliberately world-writable everywhere.
	work := filepath.Join(dir, "work")
	holeA := filepath.Join(work, "a")
	holeAB := filepath.Join(work, "ab")
	for _, d := range []string{work, holeA, holeAB} {
		if err := os.Mkdir(d, 0777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(holeA, "existing"), []byte("rw\n"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "inputs.txt"), []byte("ro\n"), 0666); err != nil {
		t.Fatal(err)
	}

	b := newWorkloadAppArmorBackend()
	prep := workloadPreparation{
		OperationID: "op_livaapc1",
		SessionID:   "live",
		StateDir:    filepath.Join(dir, "state", "op_livaapc1"),
		RuntimeDir:  filepath.Join(dir, "runtime", "op_livaapc1"),
		Exposures: []sessionFilesystemExposure{
			{Target: "/work", RequestedReadOnly: true},
			{Target: "/work/a", RequestedReadOnly: false},
			{Target: "/work/ab", RequestedReadOnly: false},
		},
		PinnedSources: []string{work, holeA, holeAB},
	}
	if err := os.MkdirAll(prep.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prep.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	prepared, prepErr := b.prepare(prep)
	if prepErr != nil {
		t.Fatalf("production AppArmor prepare: %v", prepErr)
	}
	profileName := workloadAppArmorProfileName(prep.OperationID)
	defer prepared.Cleanup()
	binds := []string{
		fmt.Sprintf("%s:/work:rw", work),
		fmt.Sprintf("%s:/work/a:rw", holeA),
		fmt.Sprintf("%s:/work/ab:rw", holeAB),
	}

	// Files inside both accepted prefix-collision RW subtrees must stay
	// writable: creating a new file and mutating an existing one.
	if err := runInContainerWithBinds(t, prepared.SecurityOpts, binds,
		"echo rw-hole-a > /work/a/file && echo rw-hole-ab > /work/ab/file && echo rw-again > /work/a/existing",
	); err != nil {
		t.Fatalf("accepted prefix-collision RW subtrees must stay writable: %v", err)
	}

	// The RO region around the holes must be denied: the sibling name aX,
	// the continued prefix abc, and a plain non-hole file.
	for _, denied := range []struct{ name, path string }{
		{"sibling aX", "/work/aX"},
		{"continued prefix abc", "/work/abc"},
		{"plain RO file", "/work/inputs.txt"},
	} {
		writeErr := runInContainerWithBinds(t, prepared.SecurityOpts, binds,
			"echo outside > "+denied.path)
		if writeErr == nil {
			t.Fatalf("AppArmor must deny writes to the %s path %s", denied.name, denied.path)
		}
		t.Logf("denied %s write output: %v", denied.name, writeErr)
	}

	denied, denialLine := appArmorDenialLogged(t, profileName)
	if !denied {
		t.Fatal("attributable AppArmor DENIED record not found for the prefix-collision RO-region writes")
	}
	if !strings.Contains(denialLine, "aX") && !strings.Contains(denialLine, "abc") && !strings.Contains(denialLine, "inputs") {
		t.Fatalf("denial must reference one of the denied RO paths: %s", denialLine)
	}
	t.Logf("attributable denial: %s", denialLine)
	liveEvidence(t, "apparmor-prefix-collision-denial.txt", denialLine+"\n")
	liveEvidence(t, "apparmor-prefix-collision-summary.txt",
		fmt.Sprintf("TESTED_SOURCE=%s\nPROFILE=%s\nRESULT=CLOSED\n", repoHead(t), profileName))
}

// TestRequiredLiveProofMissingPrerequisiteFailsClosed proves F9 at the
// required-mode entry: with DOCKER_HELPER_LIVE_WORKLOAD_PROOF=1 an unmet
// mandatory prerequisite (here: the proof must run as root) fails the proof
// run with a non-zero exit instead of closing through the skip path.
func TestRequiredLiveProofMissingPrerequisiteFailsClosed(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("unit-level required-mode proof expects a non-root test runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBinary(t), "test", "-count=1", "-run", "^TestLiveWorkloadAppArmor$", ".")
	cmd.Env = append(os.Environ(), liveProofEnv+"=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil {
		t.Fatalf("required live proof with an unmet prerequisite must exit non-zero, output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "required live workload proof") {
		t.Fatalf("failure must name the required live proof contract, output:\n%s", out.String())
	}
}

// goBinary returns the go toolchain binary for subprocess tests.
func goBinary(t *testing.T) string {
	t.Helper()
	goroot := runtime.GOROOT()
	return filepath.Join(goroot, "bin", "go")
}
