# SELinux Support Plan

docker-helper system mode currently requires AppArmor.

This document records the plan to add enforcing SELinux as a second
supported mandatory access control backend while preserving the existing
AppArmor backend.

## 1. Goal

System mode must support SELinux hosts.

Supported MAC backends:

- AppArmor
- SELinux

System mode:

- Exactly one supported enforcing backend must be active.
- Neither active — fail closed.
- Both active — fail closed for now.

User mode remains unchanged and must not require MAC confinement.

## 2. Security Contract

| Boundary | AppArmor | SELinux |
|---|---|---|
| Daemon confinement | MAC, path-based profile | MAC, type enforcement |
| Allowed-root boundary | MAC + docker-helper application policy | docker-helper application policy only |
| Workspace defense-in-depth | Path-level AppArmor rules | SELinux type-level access only |

SELinux does not provide per-path workspace isolation for allowed roots.
This is an intentional, documented difference from the AppArmor backend.

SELinux cannot enforce docker-helper allowed roots at path granularity
without relabeling workspace data. See Section 3.

## 3. Workspace-Root Research and Decision

### Rejected: Per-Bind-Mount SELinux Context

We investigated creating a private bind or `open_tree` mount under
`/run/docker-helper` and applying `docker_helper_workspace_t` only to
that view, without changing the source tree's persistent labels.

This approach is not possible for ordinary local filesystems:

- SELinux `context=` is a superblock-level option, not a mount-point
  option.
- Bind mounts and `OPEN_TREE_CLONE` share the source superblock.
- `context=` cannot be applied as an independent per-bind-mount label.
- Remount with `context=` is rejected by the kernel.
- `fsopen`/`fsmount` creates a new filesystem, not a labeled view of an
  existing directory.
- NFS `nosharecache` is filesystem-specific and does not apply to local
  filesystems.
- Overlayfs with `context=` requires a new superblock and is not a
  general solution for arbitrary subdirectories.

Conclusion: there is no Linux kernel primitive that can create a
per-mount SELinux context override for a bind mount of an existing
xattr-supporting filesystem. This is a kernel architectural constraint.

### Rejected for Current Release: Recursive Workspace Relabeling

Do not automatically apply `semanage fcontext` / `restorecon` recursively
to arbitrary allowed roots such as `/home`.

Reasons:

- Destructive change to operator/user filesystem labels.
- Possible conflict with distro or local SELinux policy.
- Complex rollback (must save and restore original labels).
- Unacceptable default UX.

A future opt-in "strict SELinux workspace" mode using dedicated or
relabelled workspace storage may be considered separately.

### Current Release Decision: Path 3

SELinux confines the docker-helper daemon itself.

Allowed-root path containment remains an application-level docker-helper
security boundary.

SELinux may grant only the minimum workspace file types required for
supported workspace locations, providing type-level defense-in-depth.

#### Enforcing UAT: docker_helper_workspace_t

Live enforcing testing on openSUSE Tumbleweed has proven that explicit
`docker_helper_workspace_t` labeling is viable:

- `docker_helper_workspace_t` carries both `user_home_type` and
  `container_file_type` attributes.
- Ordinary user access works after relabel (user_home_type).
- SELinux-confined Docker containers can read/write the bind-mounted
  workspace (container_file_type).
- Files created by the container inherit `docker_helper_workspace_t`.
- Directory bind mounts work.
- Regular-file bind mounts work.
- Host and container read/write both succeeded.
- Only remaining AVCs were intentionally ignored cgroup_t/sysctl_net_t
  probes.

Automatic recursive workspace relabeling is NOT implemented or approved.
Build staging workspace data permissions remain untested and incomplete.

## 4. LSM Abstraction

Planned backend-neutral detection and confinement layer:

```go
type LSMBackend string

const (
    LSMNone     LSMBackend = ""
    LSMAppArmor LSMBackend = "apparmor"
    LSMSelinux  LSMBackend = "selinux"
)
```

Functions:

- `detectLSM()` — returns the active backend or `LSMNone`; errors only
  on detection failure.
- `requireMACBackend()` — fails if no supported backend is active.
- `requireMACConfinement()` — verifies the process is confined under the
  active backend.

Detection semantics:

| AppArmor | SELinux | Result |
|---|---|---|
| active | — | AppArmor |
| — | enforcing | SELinux |
| — | permissive | fail |
| — | — | fail |
| active | enforcing | fail |

Detection errors must not silently downgrade security.

SELinux confinement requires all of:

- SELinux enabled (`/sys/fs/selinux/enforce` exists).
- Enforcing mode (`/sys/fs/selinux/enforce` == `"1"`).
- Current process type is `docker_helper_t` (parsed from
  `/proc/self/attr/current`).

Permissive SELinux is not equivalent to AppArmor enforce mode.

Existing AppArmor behavior must remain unchanged.

## 5. systemd Design

The chosen SELinux execution mechanism:

```ini
SELinuxContext=system_u:system_r:docker_helper_t:s0
```

This is the explicit SELinux execution-context mechanism used by the
service. It is not a fallback.

The common service unit may contain:

```ini
ConditionSecurity=|apparmor
ConditionSecurity=|selinux
```

With both `AppArmorProfile=docker-helper-system` and
`SELinuxContext=system_u:system_r:docker_helper_t:s0` present. Each
directive is a no-op when its LSM is inactive.

Live testing must confirm systemd can enter `docker_helper_t` on both
Fedora/RHEL-family and openSUSE SELinux.

The SELinux policy must permit the required transition or context change.

## 6. SELinux Policy Structure

Planned dedicated types:

| Type | Purpose |
|---|---|
| `docker_helper_t` | Daemon domain |
| `docker_helper_exec_t` | Executable type for `/usr/bin/docker-helper` |
| `docker_helper_config_t` | `/etc/docker-helper/**` |
| `docker_helper_state_t` | `/var/lib/docker-helper/**` |
| `docker_helper_runtime_t` | `/run/docker-helper/**` |

File contexts:

```
/usr/bin/docker-helper            --  system_u:object_r:docker_helper_exec_t:s0
/etc/docker-helper(/.*)?                  system_u:object_r:docker_helper_config_t:s0
/var/lib/docker-helper(/.*)?             system_u:object_r:docker_helper_state_t:s0
/run/docker-helper(/.*)?                 system_u:object_r:docker_helper_runtime_t:s0
```

Constraints:

- Do not use `read_all_files` or similarly broad interfaces.
- SELinux is default-deny; do not add artificial explicit deny capability
  rules corresponding to AppArmor denies.
- Grant only capabilities proven necessary.
- Currently expected candidates include `sys_admin` and `dac_read_search`,
  but the final permission matrix must be derived from enforcing-system
  AVC testing rather than assumptions.

## 7. Workspace Type Policy

Do not pre-grant a generic broad set of types such as:

```
user_home_t
user_home_ro_t
usr_t
var_t
default_t
```

Start with the normal `/home` workspace scenario on a live SELinux system.
Determine the actual file types and add only permissions required by
concrete supported use cases.

Every generic type grant must have a documented reason.

If an allowed root has an SELinux type unsupported by the backend, prefer
a clear validation error rather than automatically broadening the policy.

## 8. SELinux CLI

Do not implement:

```
docker-helper selinux root add
docker-helper selinux root remove
```

SELinux does not independently manage the allowed-root policy in Path 3.
Allowed roots remain managed by docker-helper's existing application
policy.

Provided SELinux command:

```
docker-helper selinux check
```

The check validates static and current state:

- SELinux enabled and enforcing.
- `docker_helper` policy module loaded (`semodule -l`).
- Expected file-context mapping exists (`semanage fcontext -l`).
- `/usr/bin/docker-helper` has the expected actual label (`stat -Z`).
- Running daemon is `docker_helper_t` when applicable
  (`/proc/<pid>/attr/current`).

Do not make historical AVC denials a pass/fail condition. AVC inspection
is diagnostic and live-test information only.

Use valid tools such as `stat -Z` and `matchpathcon`. Do not use
non-existent commands.

## 9. Policy Packaging

The SELinux module is compiled at build or release time. Target machines
do not require policy compiler or development packages.

The `.fc` file is packaged into the policy module via `semodule_package -f`
rather than attempting `semanage fcontext -f FILE` (which is invalid;
`semanage fcontext -f` means file type, not a file containing fcontext
rules).

Installation:

```sh
semodule -i docker-helper.pp
restorecon /usr/bin/docker-helper
```

Only docker-helper-owned paths are relabeled. Never recursively
`restorecon` arbitrary user workspace roots.

Do not directly manipulate `/etc/selinux/.../modules/active`. Use
`semodule`.

`.pp` versus CIL is not finalized until tested across supported
distributions.

## 10. Packaging Lifecycle

Design for each phase separately:

1. Fresh install — load policy, label binary, reload systemd.
2. Upgrade — replace policy, do not remove on upgrade.
3. Normal uninstall (remove) — stop service, do not remove policy
   (preserve for potential reinstall), do not remove config/state.
4. Purge — remove policy, remove config/state.

Invariant: an old package's removal script during an upgrade must not
remove the SELinux policy just installed or required by the new package.

Postinstall detection must have the same dual-LSM fail-closed behavior as
runtime detection. It must not let SELinux detection overwrite a
previously detected AppArmor result.

Backend package and tool names are distro-specific and remain subject to
live testing. Known examples:

| Distribution | SELinux tools package |
|---|---|
| Fedora/RHEL | `policycoreutils-python-utils` |
| openSUSE | `python3-policycoreutils` |
| Debian | `python3-selinux` |

Do not hard-code a cross-distribution packaging assumption until tested.

## 11. Live SELinux Test Matrix

Policy and packaging must be validated on at least:

- Fedora/RHEL-family enforcing SELinux.
- openSUSE enforcing SELinux.

Determine experimentally:

1. Docker socket SELinux type.
2. Docker peer or process types required for Unix socket connection.
3. Normal `/home` workspace file types.
4. Required policy permissions from AVC denials.
5. Whether one policy source or artifact works across both distributions.
6. systemd `SELinuxContext=` behavior.
7. Module install and remove behavior.
8. Package names and tool availability.
9. `.pp` versus CIL portability.

Functional tests:

- `docker-helper init`
- `docker-helper serve`
- Principal management
- `docker-helper run`
- `docker-helper build`
- Mount-pin (`open_tree` / `move_mount` / `umount`)
- CA injection (OpenSSL)
- Docker socket access
- Normal workspace under `/home`

Negative tests must include attempts to access objects that should remain
outside the daemon's SELinux permissions, for example:

- `shadow_t`
- `ssh_home_t`

Where those types exist on the target distribution.

## 12. Implementation Phases and Current Stopping Point

Phase 1: Backend-neutral LSM detection and confinement abstraction, tests,
preserve AppArmor behavior. No policy assumptions.

Phase 2: Live SELinux policy development on enforcing Fedora/RHEL-family.

Phase 3: Test and adapt the same policy on openSUSE SELinux.

Phase 4: SELinux check CLI.

Phase 5: systemd and package integration.

Phase 6: Documentation, security contract finalization, and UAT.

Current decision: it is acceptable to implement only Phase 1 before the
SELinux test environment exists.

Do not implement guessed SELinux permissions or packaging behavior without
live enforcing-system results.

## 13. Future Work

Recorded but not designed or implemented now:

- Optional strict SELinux mode using dedicated or relabelled workspace
  storage.
- Possible architecture using a separate privileged mount broker plus a
  path-restricted worker (e.g. Landlock), if stronger SELinux-mode
  workspace isolation becomes necessary. Note: applying Landlock to the
  current daemon would prevent the mount operations required by mount-pin.

These are explicitly outside the current release.
