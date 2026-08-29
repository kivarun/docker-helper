#!/usr/bin/env bash
# check-selinux-policy.sh — compile and package the SELinux policy module.
#
# Usage:
#   scripts/check-selinux-policy.sh
#
# Exits 0 on success, non-zero on failure. Does NOT install the module
# (no sudo, no semodule -i). Compile/package only — fail closed if tools are
# missing.
#
# This delegates to the single canonical SELinux policy build owner
# (build-selinux-policy.sh), the same one used by build-packages.sh and
# build-bundle.sh, so the check always exercises the exact production path.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

"$repo_root/build-selinux-policy.sh" "$tmp_dir"

echo "SELinux policy compiled and packaged successfully."
