package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// newKindAwareTestManager builds a real selinuxFcontextManager with a
// stateful fcontext world: rules added by ensure appear in the listing, and
// every semanage/restorecon invocation is recorded.
type kindAwareManager struct {
	*selinuxFcontextManager
	rules          *[]string
	semanageCalls  *[]string
	restoreconArgs *[]string
}

func newKindAwareTestManager(t *testing.T, active bool, enforcing bool) kindAwareManager {
	t.Helper()
	rules := []string{}
	semanageCalls := []string{}
	restoreconArgs := []string{}
	mgr := newTestManager(func() (bool, bool, error) { return active, enforcing, nil })
	mgr.semanagePath = semanagePath
	mgr.restoreconPath = restoreconPath
	mgr.runCommand = func(_ context.Context, cmd string, args ...string) ([]byte, error) {
		switch {
		case strings.HasSuffix(cmd, "semanage"):
			joined := strings.Join(args, " ")
			semanageCalls = append(semanageCalls, joined)
			switch args[1] {
			case "-l":
				// The listing renders the full record line per stored pattern.
				out := ""
				for _, rule := range rules {
					out += rule + "  gen_context(system_u:object_r:" + selinuxWorkspaceType + ":s0)\n"
				}
				return []byte(out), nil
			case "-a":
				// args: fcontext -a -t TYPE PATTERN
				rules = append(rules, args[len(args)-1])
				return []byte{}, nil
			case "-d":
				// args: fcontext -d PATTERN
				pattern := args[len(args)-1]
				kept := rules[:0]
				for _, rule := range rules {
					if rule != pattern {
						kept = append(kept, rule)
					}
				}
				rules = kept
				return []byte{}, nil
			}
			return []byte{}, nil
		case strings.HasSuffix(cmd, "restorecon"):
			restoreconArgs = append(restoreconArgs, strings.Join(args, " "))
			return []byte{}, nil
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) { return selinuxWorkspaceType, nil }
	return kindAwareManager{selinuxFcontextManager: mgr, rules: &rules, semanageCalls: &semanageCalls, restoreconArgs: &restoreconArgs}
}

// TestSELinuxDriverExternalDirectoryCoverage proves an external issued
// directory creates, verifies, and removes the helper-owned recursive
// fcontext coverage — and that a policy ceiling alone never does.
func TestSELinuxDriverExternalDirectoryCoverage(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryDirectory, nil }
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	coverage, created, err := driver.ensureCoverage(context.Background(), "/opt/michael/cache")
	if err != nil {
		t.Fatalf("ensureCoverage: %v", err)
	}
	if !created || coverage.Boundary != "/opt/michael/cache" || !coverage.HelperOwned {
		t.Fatalf("coverage = %+v created=%v, want the helper-owned exact boundary", coverage, created)
	}
	found := false
	for _, call := range *world.semanageCalls {
		if strings.Contains(call, "fcontext -a -t docker_helper_workspace_t /opt/michael/cache(/.*)?") {
			found = true
		}
	}
	if !found {
		t.Errorf("the directory boundary must create the recursive fcontext rule, semanage calls: %v", *world.semanageCalls)
	}
	for _, arg := range *world.restoreconArgs {
		if !strings.Contains(arg, "-R") {
			t.Errorf("a directory boundary must use the recursive restorecon, got %q", arg)
		}
	}
	if len(*world.restoreconArgs) != 1 {
		t.Errorf("restorecon calls = %d, want exactly one (ensure)", len(*world.restoreconArgs))
	}

	// Idempotent second ensure: the exact rule exists, no new rule.
	_, createdAgain, err := driver.ensureCoverage(context.Background(), "/opt/michael/cache")
	if err != nil {
		t.Fatalf("second ensureCoverage: %v", err)
	}
	if createdAgain {
		t.Error("the second ensure must not report a newly created boundary")
	}

	// Removal: the recursive rule is removed and the tree is restored.
	if err := driver.removeBoundary(context.Background(), "/opt/michael/cache", macBoundaryDirectory); err != nil {
		t.Fatalf("removeBoundary: %v", err)
	}
	if len(*world.rules) != 0 {
		t.Errorf("rules after removal = %v, want empty", *world.rules)
	}
}

// TestSELinuxDriverRegularFileCoverage proves a regular-file issued root
// creates the exact-path fcontext rule (no descendant suffix) and uses the
// plain restorecon form.
func TestSELinuxDriverRegularFileCoverage(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryRegularFile, nil }
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	coverage, created, err := driver.ensureCoverage(context.Background(), "/opt/michael/secrets/token.pem")
	if err != nil {
		t.Fatalf("ensureCoverage: %v", err)
	}
	if !created || coverage.Boundary != "/opt/michael/secrets/token.pem" {
		t.Fatalf("coverage = %+v created=%v, want the exact file boundary", coverage, created)
	}
	found := false
	wantPattern := fcontextPatternFor("/opt/michael/secrets/token.pem", macBoundaryRegularFile)
	for _, call := range *world.semanageCalls {
		if strings.Contains(call, "fcontext -a -t docker_helper_workspace_t "+wantPattern) &&
			!strings.Contains(call, "(/.*)?") {
			found = true
		}
	}
	if !found {
		t.Errorf("a regular-file boundary must map exactly the file (no descendant suffix), semanage calls: %v", *world.semanageCalls)
	}
	for _, arg := range *world.restoreconArgs {
		if strings.Contains(arg, "-R") {
			t.Errorf("a regular-file boundary must not use the recursive restorecon, got %q", arg)
		}
	}

	// Removal: the exact-file rule is found by stem and removed.
	if err := driver.removeBoundary(context.Background(), "/opt/michael/secrets/token.pem", macBoundaryRegularFile); err != nil {
		t.Fatalf("removeBoundary: %v", err)
	}
	if len(*world.rules) != 0 {
		t.Errorf("rules after removal = %v, want empty", *world.rules)
	}
}

// TestSELinuxDriverOperatorRuleNeverClaimedOrDeleted proves an
// operator-owned compatible rule is used as coverage but is never claimed as
// helper-owned and never removed through the session lifecycle.
func TestSELinuxDriverOperatorRuleNeverClaimedOrDeleted(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryDirectory, nil }
	// Operator-local compatible rule.
	*world.rules = append(*world.rules, "/opt/michael(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)")
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	coverage, created, err := driver.ensureCoverage(context.Background(), "/opt/michael/cache")
	if err != nil {
		t.Fatalf("ensureCoverage: %v", err)
	}
	if created {
		t.Error("an existing compatible boundary must not be recreated")
	}
	if coverage.Boundary != "/opt/michael" || coverage.HelperOwned {
		t.Errorf("coverage = %+v, want the operator boundary, never helper-owned", coverage)
	}
	for _, call := range *world.semanageCalls {
		if strings.Contains(call, "fcontext -a") || strings.Contains(call, "fcontext -d") {
			t.Errorf("an operator-owned rule must never be mutated through the session lifecycle: %q", call)
		}
	}
}

// TestSELinuxDriverCeilingNeverTriggersRelabel proves that merely
// authorizing a ceiling does not touch MAC state: the driver refuses /opt as
// a NEW boundary (the exact /opt namespace guard), and ensureCoverage is
// only ever invoked for issued trees — structurally, no policy path calls
// the driver at all.
func TestSELinuxDriverCeilingNeverTriggersRelabel(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryDirectory, nil }
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	_, _, err := driver.ensureCoverage(context.Background(), "/opt")
	if err == nil {
		t.Fatal("ensureCoverage(/opt) must fail: the exact /opt namespace is not a permitted boundary")
	}
	for _, call := range *world.semanageCalls {
		if strings.Contains(call, "fcontext -a") {
			t.Errorf("no fcontext rule may be added for the ceiling itself: %q", call)
		}
	}
}

// TestSELinuxDriverMissingTreeFailsClosed proves a missing issued tree fails
// closed instead of creating coverage for a nonexistent path.
func TestSELinuxDriverMissingTreeFailsClosed(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) {
		return macBoundaryUnknown, errors.New("cannot stat issued tree /gone: no such file")
	}
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	if _, _, err := driver.ensureCoverage(context.Background(), "/gone"); err == nil {
		t.Fatal("a missing issued tree must fail closed")
	}
	if len(*world.semanageCalls) != 0 {
		t.Errorf("no semanage call may happen for a missing tree: %v", *world.semanageCalls)
	}
}

// TestSELinuxFcontextStemExactPattern proves the stem classifier handles the
// exact-file form and still fails closed on unclassifiable patterns.
func TestSELinuxFcontextStemExactPattern(t *testing.T) {
	cases := []struct {
		pattern string
		want    string
	}{
		{"/data(/.*)?", "/data"},
		{"/data", "/data"},
		// The exact-file rule is stored in the escaped form (escapeFcontextPath).
		{"/opt/michael/secrets/token\\.pem", "/opt/michael/secrets/token.pem"},
		// A raw dotted path is not a classifiable literal pattern: '.' is a
		// regex metacharacter, so an unescaped exact rule fails closed.
		{"/opt/michael/secrets/token.pem", ""},
		{"/data\\.test", "/data.test"},
		{"something_else", ""},
		{"/usr/share/.*\\.so", ""},
	}
	for _, tc := range cases {
		if got := fcontextStem(tc.pattern); got != tc.want {
			t.Errorf("fcontextStem(%q) = %q, want %q", tc.pattern, got, tc.want)
		}
	}
}

// TestSELinuxRemovalDeletesOnlyDurableOwnedRuleShape proves the removal
// deletes exactly the helper-owned rule of the DURABLE creation-proven kind,
// never a shape re-derived from the current host object kind: an
// operator-owned compatible rule sharing the stem survives byte-for-byte
// even when the object kind changed between creation and cleanup (the B1
// review defect), and subsequent coverage discovery stays correct.
func TestSELinuxRemovalDeletesOnlyDurableOwnedRuleShape(t *testing.T) {
	cases := []struct {
		name             string
		durableKind      macBoundaryKind
		kindAtCreation   macBoundaryKind
		kindAtRemoval    macBoundaryKind
		helperPattern    string
		operatorRule     string
		removalRestoreon string
	}{
		{
			name:             "helper file rule, object became a directory, operator recursive rule",
			durableKind:      macBoundaryRegularFile,
			kindAtCreation:   macBoundaryRegularFile,
			kindAtRemoval:    macBoundaryDirectory,
			helperPattern:    "/opt/michael/cache",
			operatorRule:     "/opt/michael/cache(/.*)?",
			removalRestoreon: "-R",
		},
		{
			name:             "helper directory rule, object became a file, operator file rule",
			durableKind:      macBoundaryDirectory,
			kindAtCreation:   macBoundaryDirectory,
			kindAtRemoval:    macBoundaryRegularFile,
			helperPattern:    "/opt/michael/cache(/.*)?",
			operatorRule:     "/opt/michael/cache",
			removalRestoreon: "-m",
		},
		{
			name:             "helper directory rule, object still a directory, operator file rule",
			durableKind:      macBoundaryDirectory,
			kindAtCreation:   macBoundaryDirectory,
			kindAtRemoval:    macBoundaryDirectory,
			helperPattern:    "/opt/michael/cache(/.*)?",
			operatorRule:     "/opt/michael/cache",
			removalRestoreon: "-R",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			world := newKindAwareTestManager(t, true, true)
			world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
			// The tree kind is mutable host state: the helper classified the
			// tree at creation, and the object kind changed before cleanup.
			currentKind := tc.kindAtCreation
			world.treeKind = func(string) (macBoundaryKind, error) { return currentKind, nil }
			driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

			// The helper becomes the owner of its own shape first.
			if _, created, err := driver.ensureCoverage(context.Background(), "/opt/michael/cache"); err != nil || !created {
				t.Fatalf("ensureCoverage: created=%v err=%v", created, err)
			}
			if len(*world.rules) != 1 || (*world.rules)[0] != tc.helperPattern {
				t.Fatalf("rules after ensure = %v, want exactly the helper pattern %s", *world.rules, tc.helperPattern)
			}

			// An operator adds a compatible rule with the same stem but the
			// other shape AFTER the helper boundary exists.
			*world.rules = append(*world.rules, tc.operatorRule)
			if len(*world.rules) != 2 {
				t.Fatalf("rules after operator add = %v, want helper and operator rules", *world.rules)
			}

			// The object kind changed (mutable host state); cleanup must
			// still delete exactly the durable owned shape.
			currentKind = tc.kindAtRemoval
			if err := driver.removeBoundary(context.Background(), "/opt/michael/cache", tc.durableKind); err != nil {
				t.Fatalf("removeBoundary: %v", err)
			}

			if len(*world.rules) != 1 {
				t.Fatalf("rules after removal = %v, want exactly the operator rule", *world.rules)
			}
			if got := (*world.rules)[0]; got != tc.operatorRule {
				t.Errorf("operator rule must survive byte-for-byte, got %q", got)
			}
			last := (*world.restoreconArgs)[len(*world.restoreconArgs)-1]
			if !strings.Contains(last, tc.removalRestoreon) {
				t.Errorf("the removal relabel must follow the CURRENT object kind, got %q (want %s)", last, tc.removalRestoreon)
			}

			// Subsequent coverage discovery remains correct: the surviving
			// operator rule still covers sibling trees.
			coverage, created, err := driver.ensureCoverage(context.Background(), "/opt/michael/cache/doc.txt")
			if err != nil {
				t.Fatalf("post-removal ensureCoverage: %v", err)
			}
			if created {
				t.Error("the surviving operator rule must cover the sibling without a new rule")
			}
			if coverage.Boundary != "/opt/michael/cache" {
				t.Errorf("coverage boundary = %q, want the operator stem", coverage.Boundary)
			}
		})
	}
}

// TestSELinuxRemovalMissingTreeDurableKindExact proves proven absence with a
// durable creation-proven kind removes exactly the owned pattern: no
// surviving inode exists to relabel, the same-stem operator rule of the
// other shape survives byte-for-byte, and the ambiguity the legacy
// current-kind derivation needed cannot arise.
func TestSELinuxRemovalMissingTreeDurableKindExact(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryMissing, nil }
	// Both shapes exist at the vanished stem: the durable kind makes the
	// owned shape provable anyway.
	*world.rules = append(*world.rules, "/opt/gone", "/opt/gone(/.*)?")
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	if err := driver.removeBoundary(context.Background(), "/opt/gone", macBoundaryRegularFile); err != nil {
		t.Fatalf("removeBoundary: %v", err)
	}
	if len(*world.rules) != 1 || (*world.rules)[0] != "/opt/gone(/.*)?" {
		t.Errorf("rules after removal = %v, want exactly the operator recursive rule", *world.rules)
	}
	if len(*world.restoreconArgs) != 0 {
		t.Errorf("restorecon calls = %v, want none for a proven-absent tree", *world.restoreconArgs)
	}
}

// TestSELinuxRemovalMissingTreeLegacyAmbiguityRetained proves the legacy
// ownership row without a durable kind keeps its fail-closed contract: two
// same-stem workspace rules for a vanished tree make the owned shape
// unprovable and the removal is refused.
func TestSELinuxRemovalMissingTreeLegacyAmbiguityRetained(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryMissing, nil }
	*world.rules = append(*world.rules, "/opt/gone", "/opt/gone(/.*)?")
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	err := driver.removeBoundary(context.Background(), "/opt/gone", macBoundaryUnknown)
	if err == nil {
		t.Fatal("legacy removal must refuse the ambiguous same-stem rule set")
	}
	if !strings.Contains(err.Error(), "cannot be proven") {
		t.Errorf("removal error = %v, want the unprovable-shape diagnostic", err)
	}
	if len(*world.rules) != 2 {
		t.Errorf("rules after refused removal = %v, want both retained", *world.rules)
	}
}

// TestSELinuxLegacyRemovalRefusesWhenRuleSurvives proves the kind-less
// legacy removal never selects a deleted rule by the mutable host object
// kind at the backend layer: without a proven owned shape, any surviving
// same-stem workspace rule makes the owned shape unprovable and the removal
// is refused with the rule kept byte-for-byte. A directory object here must
// never select the recursive rule for deletion.
func TestSELinuxLegacyRemovalRefusesWhenRuleSurvives(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryDirectory, nil }
	*world.rules = append(*world.rules, "/opt/michael(/.*)?")
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	err := driver.removeBoundary(context.Background(), "/opt/michael", macBoundaryUnknown)
	if err == nil {
		t.Fatal("the legacy removal must refuse a surviving same-stem rule without a proven owned shape")
	}
	if !strings.Contains(err.Error(), "cannot be proven") {
		t.Errorf("removal error = %v, want the unprovable-shape diagnostic", err)
	}
	if len(*world.rules) != 1 || (*world.rules)[0] != "/opt/michael(/.*)?" {
		t.Errorf("rules after refused removal = %v, want the rule untouched", *world.rules)
	}
	if len(*world.restoreconArgs) != 0 {
		t.Errorf("restorecon calls = %v, want none for a refused removal", *world.restoreconArgs)
	}
}

// TestSELinuxLegacyRemovalCompletesWhenRuleGone proves the already-removed
// owned rule is the resumable intermediate state for a kind-less legacy row:
// the removal completes by performing the pending relabel, never by
// requiring the deleted rule to reappear and never by treating the absence
// as ownership drift.
func TestSELinuxLegacyRemovalCompletesWhenRuleGone(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryDirectory, nil }
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	if err := driver.removeBoundary(context.Background(), "/opt/michael", macBoundaryUnknown); err != nil {
		t.Fatalf("removeBoundary: %v", err)
	}
	if len(*world.rules) != 0 {
		t.Errorf("rules after completion = %v, want no rule touched", *world.rules)
	}
	if len(*world.restoreconArgs) != 1 {
		t.Errorf("restorecon calls = %v, want exactly the completion relabel", *world.restoreconArgs)
	}
}

// TestSELinuxLegacyRemovalCompletesWhenTreeGone proves the vanished-tree
// completion for a kind-less legacy row: no surviving inode and no
// surviving rule means nothing is deleted and nothing is relabelled.
func TestSELinuxLegacyRemovalCompletesWhenTreeGone(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryMissing, nil }
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	if err := driver.removeBoundary(context.Background(), "/opt/gone", macBoundaryUnknown); err != nil {
		t.Fatalf("removeBoundary: %v", err)
	}
	if len(*world.rules) != 0 {
		t.Errorf("rules after completion = %v, want no rule touched", *world.rules)
	}
	if len(*world.restoreconArgs) != 0 {
		t.Errorf("restorecon calls = %v, want none for a vanished tree", *world.restoreconArgs)
	}
}

// TestSELinuxLegacyRelabelOnlyRefusesAppearedRule proves the legacy
// relabel-only completion refuses when a same-stem workspace rule appears
// since the proven state: the owned shape is unprovable again and the
// appearing rule is never deleted.
func TestSELinuxLegacyRelabelOnlyRefusesAppearedRule(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryMissing, nil }
	*world.rules = append(*world.rules, "/opt/gone")
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	err := driver.removeBoundary(context.Background(), "/opt/gone", macBoundaryUnknown)
	if err == nil {
		t.Fatal("the legacy relabel-only completion must refuse a same-stem rule that appeared since the proof")
	}
	if !strings.Contains(err.Error(), "cannot be proven") {
		t.Errorf("removal error = %v, want the unprovable-shape diagnostic", err)
	}
	if len(*world.rules) != 1 || (*world.rules)[0] != "/opt/gone" {
		t.Errorf("rules after refused removal = %v, want the rule untouched", *world.rules)
	}
	if len(*world.restoreconArgs) != 0 {
		t.Errorf("restorecon calls = %v, want none for a refused removal", *world.restoreconArgs)
	}
}

// TestSELinuxRemovalRestoreconFailureIsResumable proves the cleanup
// transition is explicitly retryable (the B2 review defect): a one-shot
// restorecon failure after the durable rule deletion surfaces as an error
// and retains ownership; the next attempt recognizes the already-removed
// rule as the legitimate intermediate state (never ownership drift), does
// not recreate the deleted rule, retries the pending relabel, and
// completes.
func TestSELinuxRemovalRestoreconFailureIsResumable(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryDirectory, nil }
	restoreconFailing := 0
	base := world.selinuxFcontextManager.runCommand
	world.selinuxFcontextManager.runCommand = func(_ context.Context, cmd string, args ...string) ([]byte, error) {
		if strings.HasSuffix(cmd, "restorecon") && restoreconFailing > 0 {
			restoreconFailing--
			return nil, fmt.Errorf("restorecon: relabel failed")
		}
		return base(context.Background(), cmd, args...)
	}
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	if _, created, err := driver.ensureCoverage(context.Background(), "/opt/michael/cache"); err != nil || !created {
		t.Fatalf("ensureCoverage: created=%v err=%v", created, err)
	}
	restoreconFailing = 1
	err := driver.removeBoundary(context.Background(), "/opt/michael/cache", macBoundaryDirectory)
	if err == nil {
		t.Fatal("a restorecon failure after rule removal must surface as an error")
	}
	if !strings.Contains(err.Error(), "restorecon rollback") {
		t.Errorf("error = %v, want the rollback-restorecon diagnostic", err)
	}
	if len(*world.rules) != 0 {
		t.Fatalf("rules after the failed attempt = %v, want the durable rule deleted (partial success)", *world.rules)
	}

	// Attempt 2: the owned rule is already deleted — the legitimate
	// intermediate state. The retry must not recreate the rule and must
	// complete by performing the pending relabel work.
	restoreconCallsBefore := len(*world.restoreconArgs)
	if err := driver.removeBoundary(context.Background(), "/opt/michael/cache", macBoundaryDirectory); err != nil {
		t.Fatalf("retry removeBoundary: %v", err)
	}
	if len(*world.rules) != 0 {
		t.Errorf("retry must not recreate the deleted rule, rules = %v", *world.rules)
	}
	if len(*world.restoreconArgs) <= restoreconCallsBefore {
		t.Error("the retry must perform the pending relabel work")
	}
}

// TestSELinuxRemovalRuleAbsenceCompletesAfterRelabel proves the owned
// rule's absence in the listing is the resumable already-removed state, not
// ownership drift: with a durable kind the removal completes after the
// relabel succeeds and only the operator rule of the other shape remains
// untouched (the B2 review retraction of the old drift refusal).
func TestSELinuxRemovalRuleAbsenceCompletesAfterRelabel(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryDirectory, nil }
	// The listing carries only an operator rule whose shape differs; the
	// helper-owned recursive pattern is already deleted (a prior attempt's
	// partial success).
	*world.rules = append(*world.rules, "/opt/michael/cache")
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	if err := driver.removeBoundary(context.Background(), "/opt/michael/cache", macBoundaryDirectory); err != nil {
		t.Fatalf("removeBoundary: %v", err)
	}
	if len(*world.rules) != 1 || (*world.rules)[0] != "/opt/michael/cache" {
		t.Errorf("rules after completion = %v, want the operator rule untouched", *world.rules)
	}
	if len(*world.restoreconArgs) != 1 {
		t.Errorf("restorecon calls = %v, want exactly the completion relabel", *world.restoreconArgs)
	}
}

// --- legacy kind-less ownership rows through the coordinator -----------------

// newLegacySELinuxCoordinator builds a coordinator over the real
// selinuxMACDriver with a stateful fcontext world and a seeded kind-less
// (legacy) ownership row, so the cleanup runs through the production
// proof-convergence owner.
func newLegacySELinuxCoordinator(t *testing.T, world kindAwareManager, boundary string) *sessionMACCoordinator {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO mac_boundaries (backend, boundary) VALUES (?, ?)`,
		LSMSELinux, boundary); err != nil {
		t.Fatalf("seed legacy ownership row: %v", err)
	}
	driver := &selinuxMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}
	return newSessionMACCoordinator(db, driver)
}

// legacyCoordinatorOwns reports whether the coordinator still records the
// boundary as helper-owned.
func legacyCoordinatorOwns(t *testing.T, mac *sessionMACCoordinator, boundary string) bool {
	t.Helper()
	mac.mu.Lock()
	defer mac.mu.Unlock()
	owned, err := mac.isBoundaryOwnedByHelper(boundary)
	if err != nil {
		t.Fatalf("isBoundaryOwnedByHelper: %v", err)
	}
	return owned
}

// TestCoordinatorLegacySELinuxAmbiguousRulesFailClosed proves the legacy
// kind-less ownership row never lets the mutable host object kind select the
// deleted rule: with a helper-owned exact file rule and an operator-created
// recursive same-stem rule, and the filesystem object replaced by a
// directory, the cleanup is refused, both rules survive byte-for-byte, and
// the ownership metadata is retained for reconciliation (never falsely
// reported cleaned).
func TestCoordinatorLegacySELinuxAmbiguousRulesFailClosed(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	// The host object changed to a directory after creation; mutable object
	// kind is not ownership evidence.
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryDirectory, nil }
	// The helper historically owned the exact file rule; the operator added
	// the compatible recursive same-stem rule.
	*world.rules = append(*world.rules, "/opt/p", "/opt/p(/.*)?")
	mac := newLegacySELinuxCoordinator(t, world, "/opt/p")

	if err := mac.cleanupStaleBoundaries(context.Background()); err != nil {
		t.Fatalf("cleanupStaleBoundaries: %v", err)
	}

	if len(*world.rules) != 2 {
		t.Errorf("rules after cleanup = %v, want both the helper file rule and the operator recursive rule untouched", *world.rules)
	}
	if !legacyCoordinatorOwns(t, mac, "/opt/p") {
		t.Error("ownership metadata must be retained when the owned shape cannot be proven")
	}
}

// TestCoordinatorLegacySELinuxSymmetricKindChangeFailClosed proves the
// symmetric kind-change ambiguity: a helper-owned recursive directory rule
// plus an operator-created exact file rule at the same stem, with the
// filesystem object replaced by a file, is refused — the operator's file
// rule is never deleted and ownership is retained.
func TestCoordinatorLegacySELinuxSymmetricKindChangeFailClosed(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryRegularFile, nil }
	*world.rules = append(*world.rules, "/opt/p(/.*)?", "/opt/p")
	mac := newLegacySELinuxCoordinator(t, world, "/opt/p")

	if err := mac.cleanupStaleBoundaries(context.Background()); err != nil {
		t.Fatalf("cleanupStaleBoundaries: %v", err)
	}

	if len(*world.rules) != 2 {
		t.Errorf("rules after cleanup = %v, want both the helper recursive rule and the operator file rule untouched", *world.rules)
	}
	if !legacyCoordinatorOwns(t, mac, "/opt/p") {
		t.Error("ownership metadata must be retained when the owned shape cannot be proven")
	}
}

// TestCoordinatorLegacySELinuxCleanupResumesAndConverges proves the legacy
// cleanup transition is resumable and converges the row into the
// durable-kind owner: the first attempt proves the single surviving
// same-stem rule, persists its derived kind before any destructive step,
// deletes exactly that rule, and a relabel failure retains ownership; the
// retry uses the converged durable kind (the deleted rule's absence is the
// legitimate intermediate state), completes the pending relabel, and only
// then forgets the ownership metadata.
func TestCoordinatorLegacySELinuxCleanupResumesAndConverges(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (macBoundaryKind, error) { return macBoundaryDirectory, nil }
	*world.rules = append(*world.rules, "/opt/michael(/.*)?")
	mac := newLegacySELinuxCoordinator(t, world, "/opt/michael")

	// Attempt 1: the relabel fails after the owned rule is deleted.
	restoreconFailing := 0
	base := world.selinuxFcontextManager.runCommand
	world.selinuxFcontextManager.runCommand = func(_ context.Context, cmd string, args ...string) ([]byte, error) {
		if strings.HasSuffix(cmd, "restorecon") && restoreconFailing > 0 {
			restoreconFailing--
			return nil, fmt.Errorf("restorecon: relabel failed")
		}
		return base(context.Background(), cmd, args...)
	}
	restoreconFailing = 1
	if err := mac.cleanupStaleBoundaries(context.Background()); err != nil {
		t.Fatalf("cleanupStaleBoundaries: %v", err)
	}

	if len(*world.rules) != 0 {
		t.Fatalf("rules after the failed attempt = %v, want the owned rule deleted (partial success)", *world.rules)
	}
	kind, err := mac.boundaryOwnedKind("/opt/michael")
	if err != nil {
		t.Fatalf("boundaryOwnedKind: %v", err)
	}
	if kind != macBoundaryDirectory {
		t.Errorf("converged kind = %s, want the proven directory kind persisted before any destructive step", macBoundaryKindName(kind))
	}
	if !legacyCoordinatorOwns(t, mac, "/opt/michael") {
		t.Fatal("ownership must be retained after the failed attempt")
	}

	// Attempt 2: the retry completes the pending relabel with the converged
	// durable kind — it must not recreate the deleted rule and must not
	// treat the absent rule as an ownership mismatch.
	restoreconCallsBefore := len(*world.restoreconArgs)
	if err := mac.cleanupStaleBoundaries(context.Background()); err != nil {
		t.Fatalf("retry cleanupStaleBoundaries: %v", err)
	}
	if len(*world.rules) != 0 {
		t.Errorf("retry must not recreate the deleted rule, rules = %v", *world.rules)
	}
	if len(*world.restoreconArgs) <= restoreconCallsBefore {
		t.Error("the retry must perform the pending relabel work")
	}
	if legacyCoordinatorOwns(t, mac, "/opt/michael") {
		t.Error("ownership metadata must be forgotten only after the completed cleanup")
	}
}
