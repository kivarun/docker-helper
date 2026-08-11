# docker-helper Release Bundle

This archive contains a static Linux amd64 build of docker-helper and the
accompanying installation artifacts.

## Contents

- `docker-helper` — static binary (Linux amd64, musl)
- `install.sh` — host installer script
- `uninstall.sh` — host uninstaller script
- `systemd/user/docker-helper.service` — systemd user service unit
- `apparmor/docker-helper` — optional AppArmor profile template (manual install)
- `skills/docker-helper/SKILL.md` — agent-facing skill file

## Quick start

Install and initialize docker-helper:

```bash
./install.sh
export PATH="$HOME/.local/bin:$PATH"
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

### Skill installation

`install.sh` offers to install the docker-helper agent skill to
`~/.claude/skills/docker-helper/SKILL.md`. In interactive mode, confirm
with `y`. With `./install.sh --yes`, the skill is installed automatically.

To install the skill manually:

```bash
mkdir -p ~/.claude/skills/docker-helper
cp skills/docker-helper/SKILL.md ~/.claude/skills/docker-helper/SKILL.md
```

### AppArmor profile (optional)

The `apparmor/docker-helper` file is a template for an optional AppArmor
profile. It is **not** installed by `install.sh`. To install it manually:

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
The `docker-helper` binary is installed to `~/.local/bin` by `install.sh`.

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