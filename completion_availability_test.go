package main

import (
	"fmt"
	"slices"
	"testing"
)

func completionScriptWithAvailabilityContext(t *testing.T, authority string, euid int, authorityAvailable bool) string {
	t.Helper()
	script := completionScript(t)
	if authorityAvailable {
		script += fmt.Sprintf("\n_docker_helper_completion_authority() { printf '%%s\\n' %q; }\n", authority)
	} else {
		script += "\n_docker_helper_completion_authority() { return 1; }\n"
	}
	script += fmt.Sprintf("_docker_helper_completion_euid() { printf '%%s\\n' %d; }\n", euid)
	return script
}

func requireCompletionContains(t *testing.T, got []string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !slices.Contains(got, value) {
			t.Errorf("expected completion %q in %v", value, got)
		}
	}
}

func requireCompletionOmits(t *testing.T, got []string, values ...string) {
	t.Helper()
	for _, value := range values {
		if slices.Contains(got, value) {
			t.Errorf("completion must omit %q, got %v", value, got)
		}
	}
}

func TestCompletionAvailabilityMetadataLocalPrivilege(t *testing.T) {
	for _, cmd := range []*Command{
		appArmorRootListCommand,
		appArmorRootAddCommand,
		appArmorRootRemoveCommand,
		appArmorCheckCommand,
		selinuxCheckCommand,
	} {
		if got := completionAvailabilityByCommand[cmd].Local; got != completionPrivilegeRoot {
			t.Errorf("%s local privilege = %v, want root", cmd.Name, got)
		}
	}
	if got := completionAvailabilityByCommand[credentialInstallCommand].Local; got != completionPrivilegeNonRoot {
		t.Errorf("credential install local privilege = %v, want non-root", got)
	}
}

func TestCompletionAvailabilityMetadataAuthority(t *testing.T) {
	admin := completionAuthorityAdmin
	adminPrincipal := completionAuthorityAdmin | completionAuthorityPrincipal
	control := adminPrincipal | completionAuthorityLauncher

	for _, cmd := range []*Command{
		reloadCommand,
		adminTokenRotateCommand,
		principalCreateCommand,
		principalDeleteCommand,
		principalCredentialCreateCommand,
		principalCredentialRevokeCommand,
		mustCompletionSubcommand(credentialCommand, "create"),
		mustCompletionSubcommand(credentialCommand, "revoke"),
	} {
		if got := completionAvailabilityByCommand[cmd].Authorities; got != admin {
			t.Errorf("%s authority mask = %v, want admin", cmd.Name, got)
		}
	}

	for _, cmd := range []*Command{
		principalCredentialListCommand,
		principalCredentialRotateCommand,
		mustCompletionSubcommand(credentialCommand, "list"),
		launcherCreateCommand,
		launcherCredentialRotateCommand,
		completionRootsPrincipalCommand,
	} {
		if got := completionAvailabilityByCommand[cmd].Authorities; got != adminPrincipal {
			t.Errorf("%s authority mask = %v, want admin|principal", cmd.Name, got)
		}
	}

	for _, cmd := range []*Command{
		sessionCreateCommand,
		sessionListCommand,
		sessionDeleteCommand,
		completionRootsSessionCommand,
	} {
		if got := completionAvailabilityByCommand[cmd].Authorities; got != control {
			t.Errorf("%s authority mask = %v, want admin|principal|launcher", cmd.Name, got)
		}
	}
}

func TestCompletionAvailabilityPrincipalNonRoot(t *testing.T) {
	script := completionScriptWithAvailabilityContext(t, "principal", 1000, true)

	root := runCompletion(t, script, []string{"docker-helper", ""})
	requireCompletionContains(t, root, "principal", "launcher", "session", "credential")
	requireCompletionOmits(t, root, "selinux", "apparmor", "admin-token", "reload")

	principal := runCompletion(t, script, []string{"docker-helper", "principal", ""})
	if !slices.Equal(principal, []string{"credential"}) {
		t.Errorf("principal authority should see only principal credential branch, got %v", principal)
	}

	principalCredentials := runCompletion(t, script, []string{"docker-helper", "principal", "credential", ""})
	requireCompletionContains(t, principalCredentials, "list", "rotate")
	requireCompletionOmits(t, principalCredentials, "create", "revoke")

	compatCredentials := runCompletion(t, script, []string{"docker-helper", "credential", ""})
	requireCompletionContains(t, compatCredentials, "list", "install")
	requireCompletionOmits(t, compatCredentials, "create", "revoke")
}

func TestCompletionAvailabilityLauncherNonRoot(t *testing.T) {
	script := completionScriptWithAvailabilityContext(t, "launcher", 1000, true)
	root := runCompletion(t, script, []string{"docker-helper", ""})

	requireCompletionContains(t, root, "session", "credential")
	requireCompletionOmits(t, root, "principal", "launcher", "admin-token", "reload", "selinux", "apparmor")

	credentials := runCompletion(t, script, []string{"docker-helper", "credential", ""})
	if !slices.Equal(credentials, []string{"install"}) {
		t.Errorf("launcher authority should see only local credential install, got %v", credentials)
	}
}

func TestCompletionAvailabilityAdminRoot(t *testing.T) {
	script := completionScriptWithAvailabilityContext(t, "admin", 0, true)
	root := runCompletion(t, script, []string{"docker-helper", ""})

	requireCompletionContains(t, root, "principal", "launcher", "session", "credential", "admin-token", "reload", "selinux", "apparmor")

	credentials := runCompletion(t, script, []string{"docker-helper", "credential", ""})
	requireCompletionContains(t, credentials, "create", "list", "revoke")
	requireCompletionOmits(t, credentials, "install")
}

func TestCompletionAvailabilityAdminNonRootKeepsAuthorityButHidesRootOnly(t *testing.T) {
	script := completionScriptWithAvailabilityContext(t, "admin", 1000, true)
	root := runCompletion(t, script, []string{"docker-helper", ""})

	requireCompletionContains(t, root, "principal", "launcher", "admin-token", "reload")
	requireCompletionOmits(t, root, "selinux", "apparmor")
}

func TestCompletionAvailabilityHelpUsesFullParserTree(t *testing.T) {
	script := completionScriptWithAvailabilityContext(t, "launcher", 1000, true)
	results := runCompletion(t, script, []string{"docker-helper", "help", ""})

	requireCompletionContains(t, results, "principal", "launcher", "admin-token", "reload", "selinux", "apparmor")
}

func TestCompletionAvailabilityQueryFailureFallsBackToStaticTree(t *testing.T) {
	script := completionScriptWithAvailabilityContext(t, "", 1000, false)
	results := runCompletion(t, script, []string{"docker-helper", ""})

	requireCompletionContains(t, results, "principal", "launcher", "admin-token", "reload", "selinux", "apparmor")
}

func TestCompletionAvailabilityDoesNotChangeParserTree(t *testing.T) {
	for _, path := range [][]string{
		{"selinux", "check"},
		{"apparmor", "root", "add"},
		{"admin-token", "rotate"},
		{"principal", "create"},
	} {
		if cmd := completionCommandPath(path); cmd == nil {
			t.Errorf("availability filtering must not remove parser path %v", path)
		}
	}
}

func TestCompletionAvailabilityRecursiveBranchVisibility(t *testing.T) {
	if !completionCommandAvailable(principalCommand, 1000, "principal") {
		t.Error("principal branch must stay visible to Principal authority because credential list/rotate remain available")
	}
	if completionCommandAvailable(principalCommand, 1000, "launcher") {
		t.Error("principal branch must be hidden from Launcher authority")
	}
	if completionCommandAvailable(appArmorCommand, 1000, "admin") {
		t.Error("AppArmor branch must be hidden from non-root even with admin authority")
	}
	if !completionCommandAvailable(appArmorCommand, 0, "admin") {
		t.Error("AppArmor branch must be visible to root")
	}
}
