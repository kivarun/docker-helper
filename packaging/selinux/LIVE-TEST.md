# SELinux Live-Test Notes — openSUSE Tumbleweed

## Host facts

- Distribution: openSUSE Tumbleweed
- SELinux mode: Enforcing (`/sys/fs/selinux/enforce` = `1`)
- Active LSMs: selinux (no AppArmor)
- Current user context: `unconfined_u:unconfined_r:unconfined_t:s0`

## Docker contexts

- dockerd/containerd domain: `container_runtime_t`
- `/run/docker.sock` type: `container_var_run_t`

## Workspace hierarchy

| Path | Type |
|---|---|
| `/home` | `home_root_t` |
| `/home/michael` | `user_home_dir_t` |
| `/home/michael/docker-helper-selinux-uat` | `user_home_t` |
| workspace subdirectories/files | `user_home_t` |

## Available tools

checkmodule, semodule_package, semodule, semanage, restorecon, audit2allow, ausearch

## Packages

policycoreutils, policycoreutils-python-utils, checkpolicy, selinux-policy,
selinux-policy-targeted, container-selinux

## Policy development

Source files: `packaging/selinux/docker-helper.te`, `packaging/selinux/docker-helper.fc`

### Build commands

```bash
cd packaging/selinux
checkmodule -M -m -o docker-helper.tmp docker-helper.te
semodule_package -o docker-helper.pp -m docker-helper.tmp -f docker-helper.fc
```

### Install / remove

```bash
sudo semodule -i docker-helper.pp
sudo semodule -r docker_helper
```

### Label binary

```bash
sudo restorecon /usr/bin/docker-helper
```

### Verify label

```bash
stat -Z /usr/bin/docker-helper
```

### Start process and check context

```bash
sudo /usr/bin/docker-helper serve &
sudo cat /proc/$!/attr/current
```

### Collect AVCs

```bash
sudo ausearch -m AVC,USER_AVC -ts recent
```

## Permission iteration log

(To be filled during live testing.)
