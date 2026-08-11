# docker-helper Release Bundle

This archive contains a static Linux amd64 build of docker-helper and the
accompanying installation artifacts.

## Contents

- `docker-helper` — static binary (Linux amd64, musl)
- `install.sh` — host installer script
- `uninstall.sh` — host uninstaller script
- `systemd/user/docker-helper.service` — systemd user service unit
- `apparmor/docker-helper` — optional AppArmor profile template
- `.claude/skills/docker-helper/SKILL.md` — agent-facing skill file

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

For agent use, provide the same session token and Docker Helper Unix socket
to the agent environment. The included `SKILL.md` may be copied or mounted
into a skill directory supported by the agent runtime.

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
the systemd user unit, and optionally installs an AppArmor profile.

## Agent-side artifacts

The `docker-helper` binary and `.claude/skills/docker-helper/SKILL.md` are
agent-side artifacts. They are **not** installed automatically by `install.sh`.

To use them in an agent environment, copy or mount them into the agent's
filesystem. The exact paths depend on your agent runtime:

```bash
# Example: copy binary and skill to an agent container
cp docker-helper /path/to/agent/bin/
mkdir -p /path/to/agent/skills/docker-helper
cp .claude/skills/docker-helper/SKILL.md \
  /path/to/agent/skills/docker-helper/SKILL.md
```

The agent does not need Docker CLI or docker.sock access — docker-helper
provides Docker operations through its own policy-enforced interface.

## Documentation

For full API/CLI documentation, see the project README and
`.claude/skills/docker-helper/SKILL.md` in this archive.