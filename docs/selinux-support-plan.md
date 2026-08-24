# SELinux support: decision, implementation, and acceptance

This document is the binding SELinux design record for Release 2. The runtime,
policy, systemd, and RPM integration are implemented. Cross-distribution
acceptance is not complete.

## 1. System-mode MAC contract

System mode requires exactly one supported enforcing backend:

- AppArmor; or
- enforcing SELinux.

Neither active, both active, and permissive SELinux fail closed. User mode does
not require mandatory access control.

| Boundary | AppArmor | SELinux |
|---|---|---|
| Daemon confinement | path-based `docker-helper-system` profile | `docker_helper_t` type enforcement |
| Container label | Docker label disabled | MCS-constrained `docker_helper_container_t` |
| Allowed-root boundary | application policy plus managed path rules | application policy; type-level defense in depth |

SELinux does not enforce each configured allowed root as an independent path.
Canonical docker-helper path validation is the authoritative boundary in both
backends.

## 2. Workspace-root SELinux labeling

### `/home` and descendants

`/home` and any path under `/home` retain their normal host `user_home_type`
labels. docker-helper does not create `semanage fcontext` rules or run
`restorecon` on `/home` paths. The existing `user_home_type` policy grants the
daemon and container domain the necessary workspace permissions.

### Non-home system allowed_roots

A non-home system global allowed root (e.g., `/data`, `/projects/agents`,
`/opt/docker-helper-workspaces`) is managed by docker-helper under a
dedicated SELinux type:

```
docker_helper_workspace_t
```

This type is **not** `usr_t`, `default_t`, `var_t`, or any other generic host
type. The daemon and container domains receive only the permissions required
for workspace access, equivalent to what they have for `user_home_type`.

#### Persistent labeling

When docker-helper initializes or changes a non-home global allowed root under
active SELinux, it:

1. Creates a persistent `semanage fcontext` rule for the canonical root and
   descendants: `<escaped-root>(/.*)? -> docker_helper_workspace_t`
2. Applies the rule recursively with `restorecon -R` (type-only, no `-F`)
3. Verifies the root's actual SELinux type is `docker_helper_workspace_t`

The mapping survives `restorecon` and reboot because it is stored in the
persistent SELinux file-context database.

#### Monotonic managed-label lifecycle (R2)

Once `ensureWorkspaceLabel(ROOT)` returns success, the mapping becomes managed
durable state. Outer init and config code MUST NOT automatically remove it on a
later unrelated failure.

This applies to:
- init core failure (e.g., admin.token creation fails);
- config write/reload/rollback failure.

A stale `docker_helper_workspace_t` mapping is acceptable because:
- it is confinement metadata, not authorization;
- config/principal/session checks remain authoritative;
- old mappings already intentionally persist while sessions may use them;
- session-aware garbage collection remains post-2.0.

Internal rollback inside `ensureWorkspaceLabel` still occurs when the manager
itself fails before returning success (e.g., restorecon fails after adding a
new rule). At that point no successful managed-state transition has been
reported.

#### Existing operator policy

docker-helper does not blindly overwrite an existing conflicting local
`semanage fcontext` rule:

- No matching docker-helper rule: add ours.
- Exact existing rule already maps to `docker_helper_workspace_t`: idempotent
  success.
- Conflicting exact/local operator rule: fail closed with a diagnostic.

`semanage fcontext -m` is not used as an unconditional overwrite.

#### Regex escaping

The root path is correctly escaped when constructing the fcontext regex to
avoid over-matching. For example, `/data` produces a pattern that matches
`/data` and `/data/...` but not `/data/foobar` as a separate root.

#### No Docker :z/:Z or label=disable

docker-helper does not use Docker `:z`/`:Z` mount options or `label=disable`.
The SELinux labeling is managed natively through `semanage fcontext` and
`restorecon`.

#### Previously managed roots

When a global allowed root is removed, docker-helper does NOT automatically remove or
relabel the previous root. Existing sessions may still reference the old root,
and the `docker_helper_workspace_t` label may persist. This is acceptable
because SELinux labeling is confinement metadata, not authorization. The
application/session policy still controls access.

Persistent SELinux metadata (fcontext rules, restored labels) may outlive
authorization changes. This is not a separate authorization or domain layer:
`config allowed-root` and principal/session checks remain authoritative.

Session-aware SELinux label garbage collection is deferred to post-2.0.

#### Type-only restorecon

`restorecon -R` is used (without `-F`) because docker-helper only manages the
SELinux TYPE. The user, role, and MLS/MCS range are not forcibly reset. An
existing customizable label (e.g., from `chcon`) that ordinary `restorecon`
will not replace is correctly treated as a verification failure.

## 3. Detection and confinement

`detectLSM` is the backend-neutral authority. It distinguishes:

| AppArmor | SELinux | Result |
|---|---|---|
| active | absent | AppArmor |
| absent | enforcing | SELinux |
| absent | permissive | fail |
| absent | absent | fail for system mode |
| active | enabled in any mode | fail |

Detection I/O or parse errors never downgrade security. In SELinux mode,
`requireMACConfinement` also verifies that `/proc/self/attr/current` has type
`docker_helper_t`.

The common systemd unit contains OR-ed `ConditionSecurity` checks,
`AppArmorProfile=docker-helper-system`, and:

```ini
SELinuxContext=system_u:system_r:docker_helper_t:s0
```

Each confinement directive is effective only for its active LSM. The policy
permits the systemd transition and inherited journald stream socket used for
both stdout and stderr.

## 4. Policy structure

The compiled module defines:

| Type | Purpose |
|---|---|
| `docker_helper_t` | daemon domain |
| `docker_helper_container_t` | custom MCS-constrained container domain |
| `docker_helper_exec_t` | `/usr/bin/docker-helper` |
| `docker_helper_config_t` | `/etc/docker-helper/**` |
| `docker_helper_state_t` | `/var/lib/docker-helper/**` |
| `docker_helper_runtime_t` | `/run/docker-helper/**` |
| `docker_helper_workspace_t` | non-home system workspace files |

The daemon's `sys_admin` and `dac_read_search` capabilities are required by the
mount-pin and private-workspace design and were proven through enforcing UAT.
Docker socket, Buildx execution/network, system certificate, helper-owned
config/state/runtime, and home-workspace permissions are explicit.

The custom container domain carries the container-selinux `container_domain`
and `mcs_constrained_type` attributes. The module also supplies the rootfs
file-management permissions required by normal container workloads and grants
only this custom domain access to `user_home_type` and `docker_helper_workspace_t`
workspaces. It does not grant global `container_t` access to home or workspace
files.

The daemon and container domains receive workspace permissions for both
`user_home_type` (for `/home` paths) and `docker_helper_workspace_t` (for
non-home system roots). No broad `usr_t`, `default_t`, or `var_t` grants are
added.

This is an explicit compatibility dependency on the installed base policy and
container-selinux. A raw `checkmodule` syntax pass alone does not prove that
dependency across distributions.

## 5. CA hashing and injection under SELinux

Trusted CA injection no longer executes `/usr/bin/openssl` at runtime. The
helper validates one PEM X.509 CA and computes the OpenSSL 3.x
`X509_NAME_hash`-compatible value in Go by canonicalizing the subject name and
using SHA-1, truncated to four bytes and rendered little-endian. This avoids a
broad `bin_t` execute permission solely for CA preparation.

The common-case hash corpus was checked against OpenSSL 3.5.7. Differential
coverage of uncommon ASN.1 string encodings remains a release-hardening task;
see the dated release audit.

## 6. Packaging contract

The policy is compiled during the release build:

```sh
checkmodule -M -m -o docker_helper.mod packaging/selinux/docker-helper.te
semodule_package -o dist/docker-helper.pp \
  -m dist/docker_helper.mod -f packaging/selinux/docker-helper.fc
```

Target hosts need runtime policy tools, not the compiler. The RPM contains
`/usr/share/selinux/docker-helper.pp`. On an enforcing SELinux system its
scriptlet installs/replaces the module and restores only docker-helper-owned
paths. Upgrade preserves the active module; final erase removes it.

The DEB intentionally contains no SELinux module and provisions AppArmor only.

The current RPM hard-depends on both `apparmor-parser` and `policycoreutils`.
Fedora/RHEL portability is future work.

The release workflow must install both `checkmodule` and `semodule_package`
before running `build-packages.sh`; the current isolated release job does not.

## 7. Evidence completed

Live enforcing work on openSUSE Tumbleweed established:

- daemon transition and confinement as `docker_helper_t`;
- Docker socket access;
- normal `/home` hierarchy using `user_home_dir_t`/`user_home_t`;
- build staging, Docker Buildx execution, DNS/registry TLS, and system CA reads;
- directory and regular-file bind mounts;
- custom container rootfs semantics and MCS-constrained type;
- trusted CA auto-injection;
- journald access for inherited stdout/stderr streams.

The detailed host facts and commands are retained in
`packaging/selinux/LIVE-TEST.md`. Harmless cgroup/sysctl probe AVCs were not
converted into broad permissions.

## 8. Release blockers and remaining UAT

### `/opt` and non-home system roots (resolved)

Non-home system `allowed_roots` (e.g., `/data`, `/projects/agents`,
`/opt/docker-helper-workspaces`) are managed under `docker_helper_workspace_t`
with persistent `semanage fcontext` rules and `restorecon -R` (type-only).
The daemon and container domains receive workspace permissions for this type.
`config allowed-root add` updates the authorization ceiling only; it does NOT prepare MAC state.

Exact `/opt` is rejected by `config allowed-root add` in SELinux mode because
it would recursively relabel the entire `/opt` namespace. Use a dedicated child
such as `/opt/docker-helper-workspaces` instead.

Monotonic managed-label lifecycle (R2): once `ensureWorkspaceLabel` returns
success, the mapping is managed durable state. Outer init/config code does NOT
roll it back on subsequent failures. A stale mapping is acceptable because it
is confinement metadata, not authorization.

The Release 2 RPM acceptance target is openSUSE Tumbleweed.

### Required target matrix

Run the following on openSUSE Tumbleweed:

1. clean RPM dependency resolution and install;
2. module install, upgrade, final erase, and file contexts;
3. systemd transition and journald stdout/stderr;
4. init, principal/credential/session flows;
5. pull, build/buildx, run, registry login, mount-pin, and shutdown;
6. `/home` directory and regular-file workspaces;
7. the selected `/opt` acceptance/rejection contract;
8. trusted CA injection;
9. custom container rootfs behavior and MCS isolation;
10. negative access to representative `shadow_t` and `ssh_home_t` objects;
11. compatibility with the installed container-selinux/base policy;
12. `.pp` portability or a documented target-specific replacement.

There is no `docker-helper selinux check` command in the Release 2 CLI. Module,
label, and AVC diagnostics use standard host tools (`semodule`, `matchpathcon`,
`stat -Z`, and `ausearch`) during package acceptance.

## 9. Future work

- An opt-in strict SELinux workspace mode using dedicated or deliberately
  relabelled storage.
- A generated/interface-based policy compatibility layer instead of manually
  reproducing container-selinux file-management semantics.
- A separate privileged mount broker plus a path-restricted worker if stronger
  process separation becomes necessary. Applying Landlock directly to the
  current daemon would conflict with mount-pin operations.

These items are outside Release 2.
