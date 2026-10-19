#!/usr/bin/env bash
#
# test-dev-vm-local.sh — deterministic focused tests for the local persistent
# pentest-VM driver (scripts/dev-vm-local.sh) and the small, explicitly
# configurable extensions it relies on in the canonical harness
# (scripts/uat-vm-tumbleweed.sh): the vm_attach workdir/transport split,
# persistent-cleanup semantics, idempotent image/seed reuse, xorriso seed
# fallback, and the isolation netdev. No real QEMU/KVM and no network are
# required: external tools are replaced by narrow shims.
#
# What this protects (one invariant per test):
#   1. vm_netdev adds restrict=on exactly when VM_NET_ISOLATED is truthy
#      (empty/0 disables it, so DEV_VM_NET_ISOLATED=0 really opens the network)
#      and keeps the loopback-only SSH hostfwd;
#   2. vm_boot hands that netdev to qemu (end-to-end argv);
#   3. vm_write_seed_iso prefers cloud-localds but falls back to the exact
#      xorriso invocation when cloud-localds is absent;
#   4. vm_cleanup keeps the VM/workdir under VM_PERSIST and tears it down
#      otherwise;
#   5. vm_select_accel never chmods in local mode: tcg when forced, kvm when
#      the device is usable, fail-closed when local mode has no KVM;
#   6. vm_ensure_base_image reuses a verified base image and fails closed on a
#      checksum mismatch;
#   7. the driver lifecycle: status on an empty dir, start without create,
#      destroy of nothing, and double-start refusal with a live pidfile.
#
# Usage: scripts/test-dev-vm-local.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HARNESS="$SRC_DIR/scripts/uat-vm-tumbleweed.sh"
DRIVER="$SRC_DIR/scripts/dev-vm-local.sh"
[ -f "$HARNESS" ] || { echo "missing $HARNESS" >&2; exit 1; }
[ -f "$DRIVER" ] || { echo "missing $DRIVER" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
check() { # desc expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2' got '$3')"; fi
}
contains() { # desc needle haystack
  case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2' in '$3')" ;; esac
}
not_contains() { # desc needle haystack
  case "$3" in *"$2"*) bad "$1 (unexpected '$2' in '$3')" ;; *) ok "$1" ;; esac
}

# --- shims -----------------------------------------------------------------
SHIM="$WORK/shim"; mkdir -p "$SHIM"
cat > "$SHIM/qemu-system-x86_64" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$QEMU_ARGS_REC"
pidf=""; prev=""
for a in "$@"; do [ "$prev" = "-pidfile" ] && pidf="$a"; prev="$a"; done
sleep 30 & echo $! > "$pidf"
exit 0
SH
chmod +x "$SHIM/qemu-system-x86_64"

mkdir -p "$WORK/xo" "$WORK/cl"
cat > "$WORK/xo/xorriso" <<'SH'
#!/bin/sh
printf '%s\n' "$*" > "$XORRISO_REC"
exit 0
SH
cat > "$WORK/cl/cloud-localds" <<'SH'
#!/bin/sh
printf '%s\n' "$*" > "$CLOUDLOCALDS_REC"
exit 0
SH
chmod +x "$WORK/xo/xorriso" "$WORK/cl/cloud-localds"

# --- 1. vm_netdev isolation ------------------------------------------------
(
  export VM_SSH_PORT=2345 VM_NET_ISOLATED=1
  # shellcheck source=/dev/null
  source "$HARNESS"
  printf '%s' "$(vm_netdev)" > "$WORK/net.iso"
)
(
  export VM_SSH_PORT=2345
  # shellcheck source=/dev/null
  source "$HARNESS"
  printf '%s' "$(vm_netdev)" > "$WORK/net.noiso"
)
(
  export VM_SSH_PORT=2345 VM_NET_ISOLATED=0
  # shellcheck source=/dev/null
  source "$HARNESS"
  printf '%s' "$(vm_netdev)" > "$WORK/net.zero"
)
check "netdev isolated has restrict=on" "yes" "$(grep -qc restrict=on "$WORK/net.iso" && echo yes || echo no)"
contains "netdev isolated keeps loopback hostfwd" "hostfwd=tcp:127.0.0.1:2345-:22" "$(cat "$WORK/net.iso")"
not_contains "netdev non-isolated has no restrict" "restrict=on" "$(cat "$WORK/net.noiso")"
not_contains "netdev VM_NET_ISOLATED=0 has no restrict" "restrict=on" "$(cat "$WORK/net.zero")"

# --- 2. vm_boot passes the netdev to qemu (end-to-end argv) -----------------
(
  export PATH="$SHIM:$PATH" QEMU_ARGS_REC="$WORK/qemu.args"
  export VM_WORKDIR="$WORK/bootws" VM_SSH_PORT=2345 VM_NET_ISOLATED=1 VM_ACCEL=tcg
  mkdir -p "$VM_WORKDIR"; : > "$VM_WORKDIR/disk.qcow2"; : > "$VM_WORKDIR/seed.iso"
  # shellcheck source=/dev/null
  source "$HARNESS"
  vm_attach
  vm_boot
)
contains "vm_boot argv carries restrict=on" "restrict=on" "$(cat "$WORK/qemu.args" 2>/dev/null || echo)"
contains "vm_boot argv carries loopback hostfwd" "hostfwd=tcp:127.0.0.1:2345-:22" "$(cat "$WORK/qemu.args" 2>/dev/null || echo)"

# --- 3. seed ISO tool selection -------------------------------------------
# PATH is reduced to a single shim dir so tool presence is deterministic:
# no cloud-localds -> xorriso; cloud-localds present -> cloud-localds.
(
  export VM_WORKDIR="$WORK/seedws"; mkdir -p "$VM_WORKDIR"
  : > "$VM_WORKDIR/user-data"; : > "$VM_WORKDIR/meta-data"
  export PATH="$WORK/xo" XORRISO_REC="$WORK/xo.rec"
  # shellcheck source=/dev/null
  source "$HARNESS"
  vm_write_seed_iso
)
contains "seed falls back to xorriso (no cloud-localds)" "-V cidata -J -r" "$(cat "$WORK/xo.rec" 2>/dev/null || echo)"
contains "xorriso seed output is seed.iso" "seed.iso" "$(cat "$WORK/xo.rec" 2>/dev/null || echo)"
(
  export VM_WORKDIR="$WORK/seedws2"; mkdir -p "$VM_WORKDIR"
  : > "$VM_WORKDIR/user-data"; : > "$VM_WORKDIR/meta-data"
  export PATH="$WORK/cl" CLOUDLOCALDS_REC="$WORK/cl.rec"
  # shellcheck source=/dev/null
  source "$HARNESS"
  vm_write_seed_iso
)
contains "seed prefers cloud-localds when present" "seed.iso" "$(cat "$WORK/cl.rec" 2>/dev/null || echo)"

# --- 4. vm_cleanup persistent vs teardown ----------------------------------
(
  export VM_WORKDIR="$WORK/keep"; mkdir -p "$VM_WORKDIR"
  sleep 30 & echo $! > "$VM_WORKDIR/qemu.pid"
  export VM_PERSIST=1
  # shellcheck source=/dev/null
  source "$HARNESS"
  vm_cleanup
)
[ -d "$WORK/keep" ] && ok "vm_cleanup keeps workdir under VM_PERSIST" || bad "vm_cleanup removed workdir under VM_PERSIST"
(
  export VM_WORKDIR="$WORK/gone"; mkdir -p "$VM_WORKDIR"
  sleep 30 & echo $! > "$VM_WORKDIR/qemu.pid"
  # shellcheck source=/dev/null
  source "$HARNESS"
  vm_cleanup
)
[ -d "$WORK/gone" ] && bad "vm_cleanup did not remove workdir without VM_PERSIST" || ok "vm_cleanup removes workdir without VM_PERSIST"

# --- 5. accelerator selection (local mode never chmods) --------------------
: > "$WORK/kvmdev"; chmod 600 "$WORK/kvmdev"
mkdir -p "$WORK/accelws"
accel_of() { # accel kvm_local kvm_dev
  (
    export VM_WORKDIR="$WORK/accelws" VM_ACCEL="$1" VM_KVM_LOCAL="$2" VM_KVM_DEV="$3"
    # shellcheck source=/dev/null
    source "$HARNESS"
    vm_log() { :; }
    vm_select_accel
    printf '%s' "$VM_ACCEL"
  ) 2>/dev/null
}
check "accel tcg forced" "tcg" "$(accel_of tcg '' "$WORK/kvmdev")"
check "accel local+kvm usable -> kvm" "kvm" "$(accel_of '' 1 "$WORK/kvmdev")"
check "accel local no kvm -> fail" "fail" "$(accel_of '' 1 "$WORK/absent" || echo fail)"
check "accel no local no kvm -> tcg" "tcg" "$(accel_of '' '' "$WORK/absent")"

# --- 6. base image reuse + checksum fail-closed ----------------------------
(
  export PATH="$WORK/xo:/usr/bin:/bin"  # no curl needed: files are present
  export VM_WORKDIR="$WORK/imgws"; mkdir -p "$VM_WORKDIR"
  printf 'base' > "$VM_WORKDIR/openSUSE.img"
  printf '%s  openSUSE.img\n' "$(sha256sum "$VM_WORKDIR/openSUSE.img" | awk '{print $1}')" > "$VM_WORKDIR/openSUSE.img.sha256"
  export VM_IMG_NAME=openSUSE.img
  # shellcheck source=/dev/null
  source "$HARNESS"
  vm_ensure_base_image
  printf '%s' "$VM_IMG_SHA256" > "$WORK/img.sha"
)
[ -s "$WORK/img.sha" ] && ok "base image reused + verified without download" || bad "base image reuse failed"
(
  export PATH="$WORK/xo:/usr/bin:/bin"
  export VM_WORKDIR="$WORK/imgws2"; mkdir -p "$VM_WORKDIR"
  printf 'base' > "$VM_WORKDIR/openSUSE.img"
  printf '%s  openSUSE.img\n' "0000000000000000000000000000000000000000000000000000000000000000" > "$VM_WORKDIR/openSUSE.img.sha256"
  export VM_IMG_NAME=openSUSE.img
  # shellcheck source=/dev/null
  source "$HARNESS"
  vm_ensure_base_image
)
[ "$?" = 0 ] && bad "base image mismatch not detected" || ok "base image mismatch fails closed"

# --- 7. driver lifecycle without a VM --------------------------------------
DV_ENV=(env "DEV_VM_DIR=$WORK/dvm" "DEV_VM_SSH_PORT=2399" "DEV_VM_ACCEL=tcg" "PATH=$SHIM:$PATH")
out="$("${DV_ENV[@]}" bash "$DRIVER" status 2>&1)"; rc=$?
check "status empty dir rc" 0 "$rc"
contains "status reports stopped" "state:    stopped" "$out"
[ -d "$WORK/dvm" ] && ok "driver exit leaves workdir (persist)" || bad "driver removed workdir on exit"

if "${DV_ENV[@]}" bash "$DRIVER" start >/dev/null 2>&1; then
  bad "start without create should fail"
else
  ok "start without create fails"
fi

if "${DV_ENV[@]}" bash "$DRIVER" destroy -y >/dev/null 2>&1; then
  ok "destroy of nothing succeeds"
else
  bad "destroy of nothing failed"
fi

# double-start refusal with a live pidfile + disk
mkdir -p "$WORK/dvm"
: > "$WORK/dvm/disk.qcow2"
sleep 30 & dpid=$!
echo "$dpid" > "$WORK/dvm/qemu.pid"
out="$("${DV_ENV[@]}" bash "$DRIVER" start 2>&1)" && rc=0 || rc=$?
check "second start refuses while running" 1 "$rc"
contains "second start names the running pid" "already running" "$out"
kill "$dpid" 2>/dev/null || true

# stale pidfile is reaped (pid no longer alive) then start proceeds to vm_init;
# assert only the reaping message appears (vm_init would need qemu -> fail).
echo "999999" > "$WORK/dvm/qemu.pid"
out="$("${DV_ENV[@]}" bash "$DRIVER" status 2>&1)" || true
contains "stale pidfile reaped" "reaping stale pidfile" "$out"
contains "stale pidfile -> stopped" "state:    stopped" "$out"

echo
printf 'dev-vm-local tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
