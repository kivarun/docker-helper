# docker-helper Release Bundle

This archive contains a static Linux amd64 build of docker-helper and the
accompanying installation artifacts.

## Contents

- `docker-helper` — static binary (Linux amd64, musl)
- `install.sh` — user-mode installer script
- `uninstall.sh` — user-mode uninstaller script
- `install-system.sh` — system-mode installer script (requires root)
- `uninstall-system.sh` — system-mode uninstaller script (requires root)
- `systemd/user/docker-helper.service` — systemd user service unit
- `systemd/system/docker-helper.service` — systemd system service unit
- `apparmor/docker-helper` — user-mode AppArmor profile template (manual install)
- `apparmor/docker-helper-system` — system-mode AppArmor profile
- `apparmor/docker-helper.d/managed-roots` — managed workspace roots fragment
- `skills/docker-helper/SKILL.md` — agent-facing skill file
- `man/docker-helper.1.gz` — command reference man page (compressed)
- `man/docker-helper-config.5.gz` — configuration file format man page (compressed)

## Deployment

Two deployment modes are supported:

### System mode (multi-user, Release 2)

System mode installs docker-helper as a root-owned system service with
AppArmor confinement. This is the recommended deployment for shared hosts.

```bash
sudo ./install-system.sh
```

Non-interactive fresh install:

```bash
sudo ./install-system.sh --yes --allowed-root /srv/workspaces
```

The system installer:
- Copies the binary to `/usr/bin/docker-helper`
- Installs the systemd system unit
- Installs and loads the AppArmor system profile
- Runs `docker-helper init` to create initial configuration
- Enables and starts the service

Uninstall:

```bash
sudo ./uninstall-system.sh
```

With `--purge` to also remove config, state, and managed-roots:

```bash
sudo ./uninstall-system.sh --yes --purge
```

### User mode (single-user, Release 1)

User mode installs docker-helper for the current user only. No root required.

```bash
./install.sh
export PATH="$HOME/.local/bin:$PATH"
```

Non-interactive:

```bash
./install.sh --yes
```

Verify that the user service is running:

```bash
systemctl --user status docker-helper
docker-helper version
```

Create a session for a project:

```bash
docker-helper session create --workspace /path/to/project
```

Export the session token printed by the command:

```bash
export DOCKER_HELPER_SESSION_TOKEN='dht_...'
```

Verify Docker access through docker-helper:

```bash
docker-helper pull alpine:3.24
docker-helper run --image alpine:3.24 -- echo "docker-helper works"
```

## Host installation

### User mode

Run the installer from this directory:

```bash
./install.sh
```

For a fully non-interactive installation:

```bash
./install.sh --yes
```

The installer copies the binary to `~/.local/bin/docker-helper`, installs
the systemd user unit, and optionally installs the agent skill.

### System mode

Run the system installer from this directory (requires root):

```bash
sudo ./install-system.sh
```

Non-interactive with explicit allowed root:

```bash
sudo ./install-system.sh --yes --allowed-root /srv/workspaces
```

### Skill installation

`install.sh` offers to install the docker-helper agent skill to
`~/.claude/skills/docker-helper/SKILL.md`. In interactive mode, confirm
with `y`. With `./install.sh --yes`, the skill is installed automatically.

The system installer does NOT install the agent skill. The skill is a
user/agent-side artifact, not part of the system daemon installation.

To install the skill manually:

```bash
mkdir -p ~/.claude/skills/docker-helper
cp skills/docker-helper/SKILL.md ~/.claude/skills/docker-helper/SKILL.md
```

### AppArmor profile (user mode, optional)

The `apparmor/docker-helper` file is a template for an optional user-mode
AppArmor profile. It is **not** installed by `install.sh`. To install it manually:

1. Replace every occurrence of `@@BINARY_PATH@@` with the absolute path to
   the docker-helper binary (e.g., `/home/user/.local/bin/docker-helper`).
2. For workspace access, replace the commented `@@WORKSPACE_RULE@@` line with
   the appropriate AppArmor rules for your `allowed_root`, or leave it
   commented out if workspace access is not needed.
3. Copy the prepared profile to `/etc/apparmor.d/` and load it with
   `apparmor_parser`.

This is a system-level operation that requires sudo and should be performed
by an administrator.

## Agent-side artifacts

The `skills/docker-helper/SKILL.md` file is an agent-side artifact.
The `docker-helper` binary is installed to `~/.local/bin` by `install.sh`
or `/usr/bin/docker-helper` by `install-system.sh`.

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

For full API/CLI documentation, see the project README and
`skills/docker-helper/SKILL.md` in this archive.
