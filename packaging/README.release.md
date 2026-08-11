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
filesystem:

```bash
# Example: copy to an agent container
cp docker-helper /path/to/agent/bin/
cp -r .claude /path/to/agent/
```

The agent does not need Docker CLI or docker.sock access — docker-helper
provides Docker operations through its own policy-enforced interface.

## Documentation

For full API/CLI documentation, see the project README and
`.claude/skills/docker-helper/SKILL.md` in this archive.