#!/usr/bin/env bash
# check-selinux-policy.sh — compile and package the SELinux policy module.
#
# Usage:
#   scripts/check-selinux-policy.sh
#
# Exits 0 on success, non-zero on failure.
# Requires: checkmodule, semodule_package
#
# Does NOT install the module (no sudo, no semodule -i).
# Compile/package only — fail closed if tools are missing.

set -euo pipefail

# Resolve repo root independently of current working directory.
repo_root="$(cd "$(dirname "$0")/.." && pwd)"

te_file="${repo_root}/packaging/selinux/docker-helper.te"
fc_file="${repo_root}/packaging/selinux/docker-helper.fc"

# Verify required tools are available.
for cmd in checkmodule semodule_package; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: ${cmd} not found (install policycoreutils-devel or checkpolicy)" >&2
        exit 1
    fi
done

# Verify source files exist.
for f in "$te_file" "$fc_file"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: ${f} not found" >&2
        exit 1
    fi
done

# Create temporary output directory.
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

mod_file="${tmp_dir}/docker_helper.mod"
pp_file="${tmp_dir}/docker-helper.pp"

echo "Compiling SELinux policy module..."
checkmodule -M -m -o "$mod_file" "$te_file"

echo "Packaging SELinux policy module..."
semodule_package -o "$pp_file" -m "$mod_file" -f "$fc_file"

echo "SELinux policy compiled and packaged successfully."
