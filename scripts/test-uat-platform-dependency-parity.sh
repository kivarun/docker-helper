#!/usr/bin/env bash
#
# test-uat-platform-dependency-parity.sh — deterministic dependency-parity
# regression test for the R7 full-gate corrective (R7-B).
#
# The full artifact gate failed every Ubuntu consumer because the packaged
# runtime dependency contract and the Ubuntu UAT platform provisioning had
# drifted apart: the candidate DEB declares the builder backend's distro-owned
# runtime dependencies (rootlesskit, slirp4netns, uidmap), but
# scripts/uat-platform-ubuntu.sh's platform_install_deps did not provision
# them — dpkg left the DEB unconfigured on every DEB consumer and the tarball
# consumer could not start the builder at all, while the P5AA AppArmor parity
# UAT (which installs the same trio itself) passed on the same bytes.
#
# The invariant protected here: the builder backend's packaged runtime
# dependency contract (packaging/nfpm.yaml) and each platform adapter's
# platform_install_deps provisioning must name the SAME distro-owned runtime
# set. The expected sets are stated here (the single authoritative statement
# of the contract); a packaging or adapter change in either direction fails
# this test until both sides agree:
#
#   deb  (Ubuntu adapter):  rootlesskit slirp4netns uidmap
#   rpm  (openSUSE adapter): rootlesskit slirp4netns
#       (shadow — the newuidmap/newgidmap provider — and kmod are Tumbleweed
#        base per the RPM contract; the openSUSE adapter deliberately does
#        not install base-system packages)
#
# Usage: scripts/test-uat-platform-dependency-parity.sh

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1" >&2; }

NFPM="$SRC_DIR/packaging/nfpm.yaml"
UBUNTU_ADAPTER="$SRC_DIR/scripts/uat-platform-ubuntu.sh"
OPENSUSE_ADAPTER="$SRC_DIR/scripts/uat-platform-opensuse.sh"

for f in "$NFPM" "$UBUNTU_ADAPTER" "$OPENSUSE_ADAPTER"; do
  [ -f "$f" ] || bad "required contract file missing: $f"
done
[ "$FAIL" -eq 0 ] || exit 1

# Extract the deb/rpm depends block of packaging/nfpm.yaml (the lines between
# the "depends:" key and the next key at the same indent level) and require
# each expected package name as a "- <name>" list item there.
nfpm_depends() { # <format: deb|rpm>
  awk -v fmt="$1" '
    $0 ~ "^  " fmt ":" { inblk = 1; next }
    inblk && /^  [a-z]/ { exit }
    inblk && /^      - / {
      name = $NF
      sub(/ .*/, "", name)
      print name
    }
  ' "$NFPM"
}

adapter_installs() { # <adapter file> — the package words of its install list
# platform_install_deps is the single provisioning owner in each adapter;
# its package list is the multi-word continuation of the install command.
  awk '
    /platform_install_deps\(\)/ { inblk = 1 }
    inblk && /apt-get install -y|opensuse_zypper install -y/ { grab = 1 }
    grab {
      raw = $0
      line = raw
      sub(/.*install -y/, "", line)
      cont = (raw ~ /\\[ \t]*$/)
      gsub(/\\/, "", line)
      n = split(line, words, /[ \t]+/)
      for (i = 1; i <= n; i++)
        if (words[i] ~ /^[a-z][a-z0-9+.-]*$/)
          print words[i]
      if (!cont) grab = 0
    }
    inblk && /^}/ { inblk = 0; grab = 0 }
  ' "$1"
}

assert_parity() { # <label> <nfpm format> <adapter> <expected words...>
  local label="$1" fmt="$2" adapter="$3"; shift 3
  local expected="$*" have_nfpm have_adapter word
  have_nfpm="$(nfpm_depends "$fmt")"
  have_adapter="$(adapter_installs "$adapter")"
  for word in $expected; do
    if printf '%s\n' "$have_nfpm" | grep -qxF "$word"; then
      ok "$label: packaging/nfpm.yaml $fmt depends declares '$word'"
    else
      bad "$label: packaging/nfpm.yaml $fmt depends does not declare '$word'"
    fi
    if printf '%s\n' "$have_adapter" | grep -qxF "$word"; then
      ok "$label: platform adapter provisions '$word'"
    else
      bad "$label: platform adapter does not provision '$word' (dependency parity drift)"
    fi
  done
}

assert_parity "ubuntu/deb" deb "$UBUNTU_ADAPTER" rootlesskit slirp4netns uidmap
assert_parity "opensuse/rpm" rpm "$OPENSUSE_ADAPTER" rootlesskit slirp4netns

# The openSUSE adapter deliberately installs no base-system packages: assert
# the RPM contract names shadow (the newuidmap/newgidmap provider) so the
# base-system assumption stays documented in the packaging metadata itself.
if printf '%s\n' "$(nfpm_depends rpm)" | grep -qxF shadow; then
  ok "opensuse/rpm: packaging/nfpm.yaml rpm depends declares 'shadow' (newuidmap/newgidmap owner on Tumbleweed)"
else
  bad "opensuse/rpm: packaging/nfpm.yaml rpm depends does not declare 'shadow'"
fi

echo
echo "=============== dependency parity summary ==============="
echo "passed: $PASS  failed: $FAIL"
echo "========================================================="
[ "$FAIL" -eq 0 ]
