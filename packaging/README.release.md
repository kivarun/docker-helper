# docker-helper Release Bundle

This archive contains a static Linux amd64 build of docker-helper and the
accompanying installation artifacts.

Native packages are also available per release:
- `.deb` — Ubuntu
- `.rpm` — openSUSE Tumbleweed

The RPM carries both AppArmor and SELinux runtime toolchain dependencies
because RPM dependency resolution cannot select packages based on the host's
active LSM. The package supports either active AppArmor or enforcing SELinux
at runtime. The release tarball supports the same MAC-backend-neutral system
deployment: it ships both MAC backend artifacts and its system installer
selects the single active backend. Broader RPM distribution support is
planned post-Release-2.

## Contents

- `docker-helper` — static binary (Linux amd64, musl)
- `install-system.sh` — system installer script (requires root)
- `uninstall-system.sh` — system uninstaller script (requires root)
- `systemd/system/docker-helper.service` — systemd system service unit
- `systemd/system/docker-helper-builder.service` — builder backend service
  unit (the sandboxed per-build-operation BuildKit boundary; recorded
  NoNewPrivileges exception + minimal capability floor)
- `buildkit/` — the pinned upstream BuildKit v0.33.0 payload
  (`buildkitd`, `buildctl`, `buildkit-runc`) with its upstream `LICENSE`
  and the recorded-provenance `MANIFEST`; installed to
  `/usr/libexec/docker-helper/buildkit/` by the installer
- `scripts/provision-builder.sh` — the builder identity + subordinate-ID
  provisioning owner (executed by the installer)
- `apparmor/docker-helper-system` — system AppArmor profile, installed
  as `/etc/apparmor.d/docker-helper-system`
- `apparmor/local/curl` — AppArmor local-profile snippet for curl
- `selinux/docker_helper.pp` — system SELinux policy module (docker_helper)
- `skills/docker-helper/SKILL.md` — agent-facing skill file
- `man/docker-helper.1.gz` — command reference man page (compressed)
- `man/docker-helper-config.5.gz` — configuration file format man page (compressed)

## Deployment

docker-helper supports one daemon deployment: the root-owned system service.

### System mode

System mode installs docker-helper as a root-owned system service with MAC
confinement (AppArmor or enforcing SELinux, whichever single backend is active
on the host).

```bash
sudo ./install-system.sh
```

Non-interactive fresh install:

```bash
sudo ./install-system.sh --yes --allowed-root /srv/workspaces
```

The system installer is MAC-backend neutral. It selects the single supported
active backend from kernel state and configures it:

- AppArmor host (AppArmor active, SELinux not enforcing): installs and loads
  the AppArmor system profile (bundle member `apparmor/docker-helper-system`,
  installed as `/etc/apparmor.d/docker-helper-system`) and prepares the
  managed-boundary state: dynamic helper-owned boundary state lives at
  `/var/lib/docker-helper/apparmor/managed-boundaries`. That state file is
  runtime/persistent helper-owned state, not a bundle member; the installed
  profile includes it.
- SELinux host (enforcing SELinux, AppArmor inactive): loads the bundled
  `selinux/docker_helper.pp` module with `semodule`, installs the policy
  artifact to `/usr/share/selinux/docker_helper.pp`, and applies the narrow
  restorecon behavior (never recursively relabeling `/run/docker-helper`, never
  relabeling the Docker daemon/socket). The installer first establishes the
  installed libselinux implementation is the descriptor-safe floor
  (`libselinux1 >= 3.11`, proven through the rpm package database: restorecon
  links `libselinux.so.1`, the resolved library is owned by `libselinux1`, and
  its version satisfies the floor) and refuses before any SELinux mutation
  when the implementation is older, foreign-owned, or unverifiable — the
  recursive workspace relabeling the daemon performs is delegated to that
  upstream implementation. The RPM expresses the same floor as a hard
  `libselinux1 >= 3.11` dependency.
- No active backend: the installer fails before changing anything — the system
  service must not run unconfined.
- Both AppArmor and enforcing SELinux active: the installer fails before
  changing anything — the dual-active configuration is unsupported.

The installer always:
- Provisions the dedicated builder identity and its subordinate-ID ranges
  through `scripts/provision-builder.sh` (the one provisioning owner;
  idempotent and fail-closed)
- Copies the binary to `/usr/bin/docker-helper`
- Installs the systemd system units (daemon + builder backend) and the
  pinned BuildKit payload to `/usr/libexec/docker-helper/buildkit/`
- Runs `docker-helper init` to create initial configuration
- Enables and starts the service (the main unit's weak `Wants=` pulls the
  builder service in on start)

Uninstall:

```bash
sudo ./uninstall-system.sh
```

The uninstaller is also MAC-neutral: it unloads/removes the installed AppArmor
profile and removes the SELinux `docker_helper` policy module (best-effort, as
in RPM final-erase) plus the tarball-installed policy artifact, without
requiring the currently active LSM to match the backend that was installed.

With `--purge` to also remove config, state, and managed AppArmor boundary
state:

```bash
sudo ./uninstall-system.sh --yes --purge
```

### Non-root clients

Non-root users and agents are first-class clients of the system service. They
authenticate through installed Principal, Launcher, or Session credentials;
no per-user daemon exists. Install the credential with
`docker-helper credential install`, or pass an explicit
`--token-file`/`--endpoint` pair.

Once authenticated, create a Session for a project:

```bash
docker-helper session create /path/to/project
```

Export the session token printed by the command:

```bash
export DOCKER_HELPER_SESSION_TOKEN='dht_...'
```

Verify Docker access through docker-helper:

```bash
docker-helper pull alpine:3.24
docker-helper run alpine:3.24 -- echo "docker-helper works"
```

### Skill installation

The system installer does NOT install the agent skill. The skill is a
user/agent-side artifact, not part of the system daemon installation.

To install the skill manually:

```bash
mkdir -p ~/.claude/skills/docker-helper
cp skills/docker-helper/SKILL.md ~/.claude/skills/docker-helper/SKILL.md
```

### AppArmor-confined curl

On some distributions, `/usr/bin/curl` is confined by its own AppArmor
profile, preventing curl from connecting to docker-helper sockets. The
`docker-helper` CLI works normally; only curl is affected.

The bundled snippet `apparmor/local/curl` contains the rules needed.
To enable curl as a docker-helper HTTP API client:

```bash
sudo sh -c 'cat apparmor/local/curl >> /etc/apparmor.d/local/curl'
sudo apparmor_parser -r /etc/apparmor.d/curl
```

For a native package installation, the snippet is at
`/usr/share/docker-helper/apparmor/local/curl`.

Allowing socket access does not bypass docker-helper authorization.
API requests still require the bearer appropriate for the endpoint:
the admin token, a Principal or Launcher credential, or a Session token.

## Agent-side artifacts

The `skills/docker-helper/SKILL.md` file is an agent-side artifact.
The `docker-helper` binary is installed to `/usr/bin/docker-helper` by
`install-system.sh`.

To use the skill in an agent environment, copy or mount it into the agent's
filesystem. The exact paths depend on your agent runtime:

```bash
# Example: copy skill to an agent container
mkdir -p /path/to/agent/skills/docker-helper
cp skills/docker-helper/SKILL.md \
  /path/to/agent/skills/docker-helper/SKILL.md
```

The agent does not need Docker CLI or docker.sock access — docker-helper
provides Docker operations through its own policy-enforced interface.

## Documentation

Bundled command/config reference:
- `man/docker-helper.1.gz`
- `man/docker-helper-config.5.gz`

Agent usage:
- `skills/docker-helper/SKILL.md`

Full project architecture and API documentation is available in the source repository.
