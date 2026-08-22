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

## 2. Workspace-root research and decision

### Rejected: per-bind-mount SELinux context

Creating a private bind or `open_tree` mount under `/run/docker-helper` cannot
apply a distinct SELinux `context=` to that view of an ordinary local
filesystem:

- `context=` is a superblock option, not a bind-mount-point option;
- bind mounts and `OPEN_TREE_CLONE` share the source superblock;
- remounting a bind with a separate context is rejected;
- `fsopen`/`fsmount` creates a new filesystem rather than a labelled view of an
  existing directory;
- overlay and filesystem-specific workarounds are not a general solution for
  arbitrary operator workspaces.

There is therefore no general kernel primitive for a per-path SELinux label on
an existing bind-mounted tree.

### Rejected for Release 2: automatic recursive relabelling

docker-helper does not run `semanage fcontext`/`restorecon` recursively on
operator or user workspaces. That would mutate external filesystem policy,
conflict with local/distro rules, and require complex rollback.

### Implemented decision

Workspaces retain normal host labels. The daemon and custom container domain
receive only the workspace file-type permissions justified by live testing.
The current module uses the `user_home_type` attribute, which covers the proven
`/home` scenario without changing labels.

Automatic workspace relabelling is not implemented or approved.

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

The daemon's `sys_admin` and `dac_read_search` capabilities are required by the
mount-pin and private-workspace design and were proven through enforcing UAT.
Docker socket, Buildx execution/network, system certificate, helper-owned
config/state/runtime, and home-workspace permissions are explicit.

The custom container domain carries the container-selinux `container_domain`
and `mcs_constrained_type` attributes. The module also supplies the rootfs
file-management permissions required by normal container workloads and grants
only this custom domain access to `user_home_type` workspaces. It does not grant
global `container_t` access to home files.

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
paths. Upgrade preserves the active module; final erase removes it. Arbitrary
workspaces are never relabelled.

The DEB intentionally contains no SELinux module and provisions AppArmor only.

The current RPM hard-depends on both `apparmor-parser` and `policycoreutils`.
That is not yet a proven portable dependency contract for Fedora/RHEL-family
hosts and must be resolved before claiming those targets.

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

### `/opt` mismatch

Application policy allows exact `/home` and `/opt` for root initialization.
The SELinux module grants workspace access through `user_home_type` and init
does not validate the selected root's file type. `/opt` is therefore not a
proven SELinux workspace contract.

Do not grant broad `usr_t` access by default. Before Release 2, either reject an
unsupported SELinux root during init, require a dedicated operator-managed
label, or prove a narrow portable type grant on every supported target.

### Required target matrix

Run the following on openSUSE and the selected Fedora/RHEL-family target:

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
