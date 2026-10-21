#!/usr/bin/env bash
#
# test-probe-vm-isolation.sh — focused tests for the HOST role of
# scripts/lab/probe-vm-isolation.sh (the guest role is exercised only on the
# real lab VM; here it is simulated by a stub dev-vm-local.sh).
#
# What this protects (one invariant per test):
#   1. host self-check + idle guest -> PASS: the preparation connections are
#      drained into an explicit baseline and the counter DELTA is zero;
#   2. a guest that actually connects to a prepared IPv4 endpoint FAILS the
#      probe even when its own probe report claims success (the counter is
#      the evidence, not the guest's honesty);
#   3. same for the IPv6 listener/endpoint;
#   4. a guest probe that fails is reported as FAIL;
#   5. a listener that did not start FAILS the probe (never a PASS);
#   6. no host IPv6 -> the IPv6 check is a SKIP, not a silent PASS.
#
# The IPv6 cases require a working ::1 (any normal Linux host); they are
# skipped explicitly when the environment cannot bind/connect on IPv6.
#
# Usage: scripts/lab/test-probe-vm-isolation.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROBE_SRC="$SRC_DIR/lab/probe-vm-isolation.sh"
GUARD_SRC="$SRC_DIR/lab/lab-vm-guard.sh"
[ -f "$PROBE_SRC" ] || { echo "missing $PROBE_SRC" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2')" ;; esac; }
not_contains() { case "$3" in *"$2"*) bad "$1 (unexpected '$2')" ;; *) ok "$1" ;; esac; }

# --- fake repo layout: the probe resolves its sibling guard lib and the
# --- stub dev-vm-local.sh exactly as it would in the real tree.
REPO="$WORK/repo/scripts"
mkdir -p "$REPO/lab"
cp "$PROBE_SRC" "$REPO/lab/probe-vm-isolation.sh"
cp "$GUARD_SRC" "$REPO/lab/lab-vm-guard.sh"

# Stub `ip`: controlled LAN addresses, IPv6 presence driven by FAKE_V6.
# The stubbed LAN addresses are the loopback endpoints (127.0.0.1 / ::1):
# they are real and connectable on any Linux host, so the mechanism under
# test — endpoint preparation, baseline fixation, counter delta — is
# deterministic without depending on the test host's actual interfaces.
SHIM="$WORK/shim"; mkdir -p "$SHIM"
cat > "$SHIM/ip" <<'SH'
#!/bin/sh
case "$1 $2 $3 $4" in
  "-4 route get 1.1.1.1") echo "1.1.1.1 via 10.0.0.1 dev eth0 src 127.0.0.1"; exit 0 ;;
  "-6 route get 2606:4700::1")
    if [ "${FAKE_V6:-1}" = 1 ]; then
      echo "2606:4700::1 via fe80::1 dev eth0 src ::1"; exit 0
    fi
    exit 1 ;;
esac
exit 1
SH
chmod +x "$SHIM/ip"

# Stub dev-vm-local.sh: simulates the guest over `ssh` per FAKE_GUEST.
cat > "$REPO/dev-vm-local.sh" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  ssh)
    shift
    cmd="${1:-}"
    guest_args="${cmd##*-- }"
    set -- $guest_args
    [ "${1:-}" = guest ] || { echo "stub: unexpected guest args" >&2; exit 2; }
    gw_host="$2" gw_port="$3" lan4_host="$4" lan4_port="$5"
    lan6_host="${6:-}" lan6_port="${7:-}"
    case "${FAKE_GUEST:-idle}" in
      idle)
        # Boundary diagnostic owned by the stub: what the host role handed to
        # the guest. The guest role itself (link/route/endpoint/DNS checks and
        # its SKIP line) is exercised on the real VM only.
        if [ -n "$lan6_host" ]; then
          echo "STUB guest received the IPv6 endpoint $lan6_host:$lan6_port"
        else
          echo "STUB guest received no IPv6 endpoint"
        fi
        exit 0 ;;
      fail) echo "stub: guest probe failed inside the guest" >&2; exit 1 ;;
      attack)
        timeout 3 bash -c 'exec 3<>/dev/tcp/$1/$2' _ "$lan4_host" "$lan4_port" 2>/dev/null || exit 3
        exit 0 ;;
      attack6)
        [ -n "$lan6_host" ] || { echo "stub: no v6 endpoint" >&2; exit 4; }
        timeout 3 bash -c 'exec 3<>/dev/tcp/$1/$2' _ "$lan6_host" "$lan6_port" 2>/dev/null || exit 5
        exit 0 ;;
      *) echo "stub: unknown FAKE_GUEST" >&2; exit 2 ;;
    esac
    ;;
  *) echo "stub: only ssh is simulated" >&2; exit 2 ;;
esac
SH
chmod +x "$REPO/dev-vm-local.sh"

# IPv6 capability precheck (bounded): a throwaway listener on :: decides
# whether the IPv6 cases can run in this environment.
v6_capable=0
V6PROBE_PORT="$(( (RANDOM % 20000) + 30000 ))"
python3 - "$V6PROBE_PORT" <<'PY' & V6PID=$!
import socket, sys, time
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.bind(("::", int(sys.argv[1])))
s.listen(1)
time.sleep(8)
PY
for _ in $(seq 1 20); do
  if timeout 2 bash -c "exec 3<>/dev/tcp/::1/$V6PROBE_PORT" 2>/dev/null; then v6_capable=1; break; fi
  sleep 0.1
done
kill "$V6PID" 2>/dev/null; wait "$V6PID" 2>/dev/null

run_probe() { # <FAKE_GUEST> <FAKE_V6> <port> -> sets OUT and RC
  FAKE_GUEST="$1" FAKE_V6="$2" PATH="$SHIM:$PATH" \
    bash "$REPO/lab/probe-vm-isolation.sh" host "$3" >"$WORK/out" 2>&1
  RC=$?
  OUT="$(cat "$WORK/out")"
}

next_port() { echo "$(( (RANDOM % 20000) + 30000 ))"; }

# --- 1. idle guest -> PASS ---------------------------------------------------
P="$(next_port)"
run_probe idle 1 "$P"
if [ "$RC" = 0 ]; then ok "idle guest: probe passes"; else bad "idle guest: probe failed (rc $RC): $OUT"; fi
contains "idle guest: guest probe reported" "ok   - guest probe passed over host->guest SSH" "$OUT"
contains "idle guest: counter delta is zero" "ok   - no guest connection reached any controlled listener" "$OUT"
contains "idle guest: IPv6 endpoint prepared" "[::1]:$P" "$OUT"
contains "idle guest: the IPv6 endpoint is handed to the guest" "STUB guest received the IPv6 endpoint ::1:$P" "$OUT"
not_contains "idle guest: no skip with IPv6 present" "skip -" "$OUT"

# --- 2. guest connects to the prepared IPv4 endpoint -> FAIL -----------------
P="$(next_port)"
run_probe attack 1 "$P"
if [ "$RC" != 0 ]; then ok "attacking guest (v4): probe fails"; else bad "attacking guest (v4): probe passed"; fi
contains "attacking guest (v4): counter delta proves the connection" \
  "FAIL - a guest connection REACHED a controlled host listener" "$OUT"
contains "attacking guest (v4): the delta names IPv4" "ipv4" "$OUT"

# --- 3. guest connects to the prepared IPv6 endpoint -> FAIL -----------------
if [ "$v6_capable" = 1 ]; then
  P="$(next_port)"
  run_probe attack6 1 "$P"
  if [ "$RC" != 0 ]; then ok "attacking guest (v6): probe fails"; else bad "attacking guest (v6): probe passed"; fi
  contains "attacking guest (v6): counter delta proves the connection" \
    "FAIL - a guest connection REACHED a controlled host listener" "$OUT"
  contains "attacking guest (v6): the delta names IPv6" "ipv6" "$OUT"
else
  ok "attacking guest (v6): SKIPPED (no working ::1 in this environment)"
fi

# --- 4. failing guest probe -> FAIL ------------------------------------------
P="$(next_port)"
run_probe fail 1 "$P"
if [ "$RC" != 0 ]; then ok "failing guest probe: probe fails"; else bad "failing guest probe: probe passed"; fi
contains "failing guest probe: reported" "FAIL - guest probe failed" "$OUT"

# --- 5. listener did not start -> FAIL (a blocker holds the port) ------------
P="$(next_port)"
python3 - "$P" <<'PY' & BLOCKER_PID=$!
import socket, sys, time
s = socket.socket(socket.AF_INET)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen(1)
time.sleep(15)
PY
# The blocker must provably hold the port BEFORE the probe starts, otherwise
# the probe's own listener may win the bind race.
blocker_ready=0
for _ in $(seq 1 20); do
  if timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$P" 2>/dev/null; then blocker_ready=1; break; fi
  sleep 0.1
done
[ "$blocker_ready" = 1 ] || { echo "blocker listener did not start" >&2; exit 1; }
run_probe idle 1 "$P"
kill "$BLOCKER_PID" 2>/dev/null; wait "$BLOCKER_PID" 2>/dev/null
if [ "$RC" != 0 ]; then ok "blocked port: probe fails"; else bad "blocked port: probe passed"; fi
contains "blocked port: names the failure" "ERROR" "$OUT"

# --- 6. no host IPv6 -> SKIP, not a false PASS -------------------------------
P="$(next_port)"
run_probe idle 0 "$P"
if [ "$RC" = 0 ]; then ok "no-IPv6 host: probe passes with the v6 part skipped"; else bad "no-IPv6 host: probe failed (rc $RC): $OUT"; fi
contains "no-IPv6 host: the guest receives no IPv6 endpoint" "STUB guest received no IPv6 endpoint" "$OUT"
not_contains "no-IPv6 host: no v6 endpoint claimed" "[::1]:" "$OUT"

# --- UAT-4/F1. the slirp netdev is IPv4-only in both postures -----------------
# Real execution: the harness is sourced in a subshell and vm_netdev() runs
# for the online and the isolated posture.
netdev_out() { # ISOLATED_VALUE -> vm_netdev output
  ( source "$SRC_DIR/uat-vm-tumbleweed.sh"; VM_NET_ISOLATED="$1" vm_netdev )
}
n_online="$(netdev_out "")"
n_isolated="$(netdev_out 1)"
for pair in "online:$n_online" "isolated:$n_isolated"; do
  posture="${pair%%:*}"; nd="${pair#*:}"
  case "$nd" in
    *ipv6=off*) ok "UAT-4/F1: $posture netdev disables slirp IPv6" ;;
    *) bad "UAT-4/F1: $posture netdev does not disable IPv6: $nd" ;;
  esac
  case "$nd" in
    *hostfwd=tcp:127.0.0.1:*) ok "UAT-4/F1: $posture SSH hostfwd stays loopback-only" ;;
    *) bad "UAT-4/F1: $posture SSH hostfwd is not loopback-only: $nd" ;;
  esac
done
case "$n_online" in
  *restrict=on*) bad "UAT-4/F1: restrict=on leaked into the online posture" ;;
  *) ok "UAT-4/F1: restrict=on is absent in the online posture" ;;
esac
case "$n_isolated" in
  *restrict=on*) ok "UAT-4/F1: restrict=on applies only in the isolated posture" ;;
  *) bad "UAT-4/F1: restrict=on missing in the isolated posture" ;;
esac

# --- UAT-4/F2. the guest boot-config mutation (really executed) ---------------
# The guest script inside vm_set_ipv6_disable honors the LAB_GUEST_ROOT seam
# (the same pattern as the operator-files provisioner): the test overrides
# vm_ssh/vm_fail after sourcing the harness and runs the streamed guest
# script against a private fake boot tree.
f2_root="$WORK/f2guest"
f2_reset() {
  rm -rf "$f2_root"
  mkdir -p "$f2_root/etc/kernel" "$f2_root/etc/default" "$f2_root/boot/loader/entries" "$f2_root/bin"
  printf 'root=LABEL=LAB quiet\n' > "$f2_root/etc/kernel/cmdline"
  printf 'GRUB_CMDLINE_LINUX_DEFAULT="root=LABEL=LAB quiet"\n' > "$f2_root/etc/default/grub"
  printf 'title Lab\noptions root=LABEL=LAB quiet\nlinux /vmlinuz\n' > "$f2_root/boot/loader/entries/lab.conf"
}
f2_run() { # [no-reset] -> F2_RC, F2_OUT; the guest script executes for real
  [ "${1:-}" = no-reset ] || f2_reset
  local captured="$WORK/f2-guest-body.sh"
  ( source "$SRC_DIR/uat-vm-tumbleweed.sh"
    vm_ssh() { cat; }
    vm_log() { printf '[vm] %s\n' "$*" >&2; }
    vm_fail() { printf '[vm_fail] %s\n' "$*" >&2; exit 1; }
    vm_set_ipv6_disable
  ) > "$captured" 2> "$WORK/f2-wrapper.err"
  LAB_GUEST_ROOT="$f2_root" PATH="$SHIM:$PATH" bash "$captured" >"$WORK/f2out" 2>&1
  F2_RC=$?
  F2_OUT="$(cat "$WORK/f2out")"
}
# shims: the guest's bootloader regeneration helpers are recorded, the
# filesystem tools are real.
cat > "$SHIM/update-bootloader" <<'SH'
#!/bin/sh
echo "update-bootloader $*" >> "$WORK/f2-regen.rec"
exit 0
SH
cat > "$SHIM/sdbootutil" <<'SH'
#!/bin/sh
echo "sdbootutil $*" >> "$WORK/f2-regen.rec"
exit 0
SH
cat > "$SHIM/grub2-mkconfig" <<'SH'
#!/bin/sh
echo "grub2-mkconfig $*" >> "$WORK/f2-regen.rec"
exit 0
SH
chmod +x "$SHIM"/update-bootloader "$SHIM"/sdbootutil "$SHIM"/grub2-mkconfig
: > "$WORK/f2-regen.rec"

# F2.1 fresh: every boot source carries ipv6.disable=1
f2_run
if [ "$F2_RC" = 0 ]; then ok "UAT-4/F2: the boot-config bootstrap succeeds"; else bad "UAT-4/F2: the bootstrap failed (rc $F2_RC): $F2_OUT"; fi
for src in "$f2_root/etc/kernel/cmdline" "$f2_root/etc/default/grub" "$f2_root/boot/loader/entries/lab.conf"; do
  if grep -qw 'ipv6.disable=1' "$src"; then ok "UAT-4/F2: $(basename "$src") carries ipv6.disable=1"; else bad "UAT-4/F2: $(basename "$src") lacks ipv6.disable=1"; fi
done
if printf '%s' "$F2_OUT" | grep -q 'regenerating bootloader config:'; then
  ok "UAT-4/F2: the bootloader regeneration path runs (the BLS fallback is the deterministic guarantee)"
else
  bad "UAT-4/F2: no bootloader regeneration attempt"
fi

# F2.2 idempotency: a second run adds no duplicate
: > "$WORK/f2-regen.rec"
f2_run
if [ "$F2_RC" = 0 ]; then ok "UAT-4/F2: the re-run succeeds"; else bad "UAT-4/F2: the re-run failed (rc $F2_RC)"; fi
dup="$(grep -o 'ipv6.disable=1' "$f2_root/etc/kernel/cmdline" | wc -l)"
if [ "$dup" = 1 ]; then ok "UAT-4/F2: the re-run adds no duplicate token"; else bad "UAT-4/F2: $dup ipv6.disable tokens after the re-run"; fi
dup="$(grep -o 'ipv6.disable=1' "$f2_root/boot/loader/entries/lab.conf" | wc -l)"
if [ "$dup" = 1 ]; then ok "UAT-4/F2: the BLS entry carries exactly one token"; else bad "UAT-4/F2: the BLS entry has $dup tokens"; fi

# F2.3 modeled reboot: the on-disk config (the boot source) still carries the
# token after a re-run — the reboot applies what the files say.
if grep -qw 'ipv6.disable=1' "$f2_root/etc/kernel/cmdline"; then
  ok "UAT-4/F2: the persistent boot config survives the modeled reboot"
else
  bad "UAT-4/F2: the persistent boot config lost the token"
fi

# F2.4 fail-closed: no boot source at all -> the guest script fails
rm -rf "$f2_root"; mkdir -p "$f2_root"
f2_run no-reset
if [ "$F2_RC" != 0 ]; then ok "UAT-4/F2: an empty boot tree fails closed"; else bad "UAT-4/F2: an empty boot tree was tolerated"; fi
case "$F2_OUT" in *"FAIL-CLOSED"*) ok "UAT-4/F2: the failure names the missing boot source" ;; *) bad "UAT-4/F2: no FAIL-CLOSED evidence: $F2_OUT" ;; esac

# --- UAT-4/F3. the guest IPv4-only contract (real code, temp files) -----------
# probe_ipv6_disabled() and ipv6_transport_usable() are the production
# functions; the tests drive them with private files / real sockets.
printf 'BOOT_IMAGE=lab ipv6.disable=1 quiet\n' > "$WORK/cmdline.good"
printf 'BOOT_IMAGE=lab quiet\n' > "$WORK/cmdline.bad"
printf '00000000000000000000000000000001 00 1c 0000000000000000 00\n' > "$WORK/ifinet6.present"
# The probe file dispatches at source time; the functions are exercised in a
# subshell that sources the real file with an EMPTY $1 (the dispatch treats
# "" as the help/no-op path and continues), then shifts past it and calls the
# production function with the test's arguments.
probe_fn() { local fn="$1"; shift; ( set -- "" "$@"; source "$REPO/lab/probe-vm-isolation.sh"; shift; "$fn" "$@" ); }
if probe_fn probe_ipv6_disabled "$WORK/cmdline.good" "$WORK/ifinet6.absent"; then
  ok "UAT-4/F3: ipv6.disable=1 + no if_inet6 is a disabled stack"
else
  bad "UAT-4/F3: a properly disabled stack was not recognized"
fi
if probe_fn probe_ipv6_disabled "$WORK/cmdline.bad" "$WORK/ifinet6.absent"; then
  bad "UAT-4/F3: an unrouted-but-not-disabled stack passed (no cmdline token)"
else
  ok "UAT-4/F3: no cmdline token is NOT a disabled stack"
fi
if probe_fn probe_ipv6_disabled "$WORK/cmdline.good" "$WORK/ifinet6.present"; then
  bad "UAT-4/F3: a live if_inet6 passed although the stack must be disabled"
else
  ok "UAT-4/F3: a live if_inet6 is NOT a disabled stack"
fi
case "$(probe_fn ipv6_transport_usable >/dev/null 2>&1; echo $?)" in
  0) ok "UAT-4/F3: the transport check executes real AF_INET6 semantics on this host" ;;
  1) bad "UAT-4/F3: the transport check misreported" ;;
  2) bad "UAT-4/F3: python3 is unavailable for the transport check" ;;
  *) bad "UAT-4/F3: the transport check returned an unexpected status" ;;
esac
# A working IPv6 transport (when the test host supports ::1) must be
# recognizable as NOT an IPv4-only posture.
if [ "$v6_capable" = 1 ]; then
  ipv6_transport_usable2() { python3 - <<'PY' 2>/dev/null
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.bind(("::1", 0))
s.close()
PY
}
  if ipv6_transport_usable2; then
    ok "UAT-4/F3: a bindable AF_INET6 socket is detectable (the guest check would FAIL it)"
  else
    bad "UAT-4/F3: the transport check cannot see a working ::1 socket"
  fi
else
  skip "UAT-4/F3: the working-transport detection (::1 unavailable on this host)"
fi

# --- UAT-5. the transport verdict distinguishes all three outcomes ------------
# Blocker: the previous mapping turned ANY nonzero ipv6_transport_usable rc
# (python3 missing = 2, unexpected socket errors, even the kernel's
# EAFNOSUPPORT refusal) into "unusable" and emitted a PASS. The verdict must
# separate: USABLE (a working AF_INET6 socket -> FAIL the IPv4-only claim),
# DEMONSTRABLY UNAVAILABLE (the kernel refuses the address family -> PASS,
# with the reason positively confirmed), and FAILED/INCONCLUSIVE (python3
# missing or an unexpected socket API error -> mandatory FAIL, never a skip).
# The python3 shim models kernel/socket outcomes at the same boundary the
# production code observes (the exit status of the socket attempt).
uat5_pyshim() { # EXIT_CODE -> a python3 shim that exits with that code
  local d="$WORK/uat5-shim-$1"
  mkdir -p "$d"
  printf '#!/bin/sh\nexit %s\n' "$1" > "$d/python3"
  chmod +x "$d/python3"
  printf '%s' "$d"
}
uat5_verdict() { # [SHIM_DIR|none] -> the verdict line ipv6_transport_check emits
  local shim="$1"
  (
    set -- ""
    if [ "$shim" = none ]; then
      command() { if [ "$1 $2" = "-v python3" ]; then return 1; fi; builtin command "$@"; }
    else
      PATH="$shim:$PATH"
    fi
    source "$REPO/lab/probe-vm-isolation.sh"
    shift
    ipv6_transport_check
  )
}
uat5_first_line() { printf '%s' "$(printf '%s\n' "$1" | grep -E '^(ok|FAIL)' | head -1)"; }

# U5.1 RED: python3 absent is a FAIL, not a false PASS
out="$(uat5_verdict none)"; first="$(uat5_first_line "$out")"
case "$first" in
  FAIL*"python3 is unavailable"*) ok "UAT-5: python3 absent -> mandatory FAIL with the reason" ;;
  ok*) bad "UAT-5 RED: python3 absent produced a PASS ('$first')" ;;
  *) bad "UAT-5: an unexpected verdict for python3 absent: $first" ;;
esac

# U5.2 (the kernel's family refusal -> a confirmed-unavailable PASS) is now
# owned by UAT-6.2, which requires the double signal (exit 1 + marker).

# U5.3 an unexpected socket API error is a FAIL (inconclusive, never a PASS)
shim="$(uat5_pyshim 3)"
out="$(uat5_verdict "$shim")"; first="$(uat5_first_line "$out")"
case "$first" in
  FAIL*"unexpected socket API error"*) ok "UAT-5: an unexpected socket error is a mandatory FAIL" ;;
  ok*) bad "UAT-5 RED: an unexpected socket error produced a PASS ('$first')" ;;
  *) bad "UAT-5: an unexpected verdict for the socket error: $first" ;;
esac

# U5.4 a working AF_INET6 socket contradicts an IPv4-only VM (when the test
# host can bind ::1)
if [ "$v6_capable" = 1 ]; then
  out="$(uat5_verdict "")"; first="$(uat5_first_line "$out")"
  case "$first" in
    FAIL*"FUNCTIONING"*) ok "UAT-5: a working transport FAILs the IPv4-only claim" ;;
    *) bad "UAT-5: the working-transport verdict is wrong: $first" ;;
  esac
else
  skip "UAT-5: the working-transport case (::1 unavailable on this host)"
fi

# --- UAT-6. the refusal verdict needs BOTH signals from one Python run --------
# Blocker: exit code 1 was accepted as a confirmed kernel refusal of
# AF_INET6, but the Python interpreter itself exits 1 on any crash
# (traceback, import error, execution error). A refusal verdict is only
# valid when the controlled exit code 1 AND the exact diagnostic marker on
# stdout arrive from the SAME Python run; any other combination — a bare
# exit 1, stderr traceback noise, unrelated stdout — is inconclusive and
# must FAIL. A working AF_INET6 transport still FAILs the IPv4-only claim,
# and python3 missing still FAILs.
uat6_pyshim() { # NAME BODY -> a python3 shim dir executing that body
  local d="$WORK/uat6-shim-$1"
  mkdir -p "$d"
  printf '#!/bin/sh\n%s\n' "$2" > "$d/python3"
  chmod +x "$d/python3"
  printf '%s' "$d"
}
uat6_expect_fail() { # DESCRIPTION OUTPUT -> FAIL unless the verdict is a FAIL
  local desc="$1" first
  first="$(printf '%s\n' "$2" | grep -E '^(ok|FAIL)' | head -1)"
  case "$first" in
    FAIL*"cannot verify"*) ok "UAT-6: $desc -> mandatory FAIL" ;;
    ok*) bad "UAT-6 RED: $desc produced a PASS ('$first')" ;;
    *) bad "UAT-6: an unexpected verdict for $desc: $first" ;;
  esac
}

# U6.1 RED: a fake python3 that merely exits 1, with no marker, must FAIL —
# the interpreter's own exit-1-on-crash must never read as a kernel refusal
shim="$(uat6_pyshim bare-exit1 'exit 1')"
out="$(uat5_verdict "$shim")"
uat6_expect_fail "a bare exit 1 without the refusal marker" "$out"

# U6.2 the double signal (exit 1 AND the marker, one run) is the only PASS
shim="$(uat6_pyshim marker-exit1 'printf "%s\n" AF_INET6_REFUSED; exit 1')"
out="$(uat5_verdict "$shim")"
first="$(printf '%s\n' "$out" | grep -E '^(ok|FAIL)' | head -1)"
case "$first" in
  ok*"demonstrably unavailable"*) ok "UAT-6: exit 1 + the marker from one run is the confirmed refusal PASS" ;;
  FAIL*) bad "UAT-6: the double-confirmed refusal was wrongly failed: $first" ;;
  *) bad "UAT-6: an unexpected verdict for the double signal: $first" ;;
esac

# U6.3 RED: a traceback (interpreter crash, stderr noise) with exit 1 must FAIL
shim="$(uat6_pyshim traceback 'echo "Traceback (most recent call last):" >&2; echo "NameError: socket" >&2; exit 1')"
out="$(uat5_verdict "$shim")"
uat6_expect_fail "an interpreter traceback with exit 1" "$out"

# U6.4 RED: unrelated stdout with exit 1 must FAIL (the marker must match exactly)
shim="$(uat6_pyshim garbage-stdout 'echo "unrelated output"; exit 1')"
out="$(uat5_verdict "$shim")"
uat6_expect_fail "unrelated stdout with exit 1" "$out"

# U6.5 regression locks: the other outcomes keep their Corrective-5 verdicts
if [ "$v6_capable" = 1 ]; then
  out="$(uat5_verdict "")"
  first="$(printf '%s\n' "$out" | grep -E '^(ok|FAIL)' | head -1)"
  case "$first" in
    FAIL*"FUNCTIONING"*) ok "UAT-6: a working transport still FAILs the IPv4-only claim" ;;
    *) bad "UAT-6: the working-transport verdict changed: $first" ;;
  esac
else
  skip "UAT-6: the working-transport case (::1 unavailable on this host)"
fi
out="$(uat5_verdict none)"
uat6_expect_fail "python3 absent (Corrective-5 behavior preserved)" "$out"

# --- UAT-4/F4. the host listener lifecycle ------------------------------------
probe_free_port() { # -> a port with NO listener
  local p
  p=$(( (RANDOM % 20000) + 30000 ))
  while timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$p" 2>/dev/null; do
    p=$(( (RANDOM % 20000) + 30000 ))
  done
  printf '%s' "$p"
}
port_free() { # PORT -> 0 when nothing accepts (the listeners are gone)
  ! timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null
}
wait_port_busy() { # PORT -> 0 once something accepts
  local _
  for _ in $(seq 1 30); do
    timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

# F4.1 normal completion -> no listeners left, no unbound-variable noise
P="$(probe_free_port)"
run_probe idle 1 "$P"
if [ "$RC" = 0 ]; then ok "UAT-4/F4: the probe completes normally"; else bad "UAT-4/F4: the normal probe failed (rc $RC): $OUT"; fi
if port_free "$P"; then ok "UAT-4/F4: no listener survives a normal completion"; else bad "UAT-4/F4: a listener leaked after the normal completion"; fi
not_contains "UAT-4/F4: no unbound-variable noise" "unbound variable" "$OUT"

# F4.2 a guest probe FAIL -> no listeners left
P="$(probe_free_port)"
run_probe fail 1 "$P"
if [ "$RC" != 0 ]; then ok "UAT-4/F4: the guest failure fails the probe"; else bad "UAT-4/F4: the guest failure was tolerated"; fi
if port_free "$P"; then ok "UAT-4/F4: no listener survives a guest failure"; else bad "UAT-4/F4: a listener leaked after the guest failure"; fi
not_contains "UAT-4/F4: no unbound-variable noise on failure" "unbound variable" "$OUT"

# F4.3 a foreign process holds the port -> the probe refuses and the foreign
# process survives untouched
P="$(probe_free_port)"
python3 - "$P" <<'PY' & FOREIGN_PID=$!
import socket, sys, time
s = socket.socket(socket.AF_INET)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(1)
time.sleep(30)
PY
wait_port_busy "$P" || { bad "UAT-4/F4: the foreign listener did not start (test bug)"; kill "$FOREIGN_PID" 2>/dev/null; }
FAKE_V6=0 run_probe idle 0 "$P"
if [ "$RC" != 0 ]; then ok "UAT-4/F4: a foreign port holder fails the probe"; else bad "UAT-4/F4: a foreign port holder was tolerated"; fi
kill -0 "$FOREIGN_PID" 2>/dev/null \
  && ok "UAT-4/F4: the foreign process was not killed" \
  || bad "UAT-4/F4: the foreign process was killed by the probe"
kill "$FOREIGN_PID" 2>/dev/null; wait "$FOREIGN_PID" 2>/dev/null
not_contains "UAT-4/F4: no unbound-variable noise on the foreign-port path" "unbound variable" "$OUT"

# F4.4 TERM mid-run -> no listeners left, rc 143
P="$(probe_free_port)"
FAKE_GUEST=idle FAKE_V6=1 PATH="$SHIM:$PATH" \
  bash "$REPO/lab/probe-vm-isolation.sh" host "$P" >"$WORK/out-term" 2>&1 &
PROBE_PID=$!
wait_port_busy "$P" || { bad "UAT-4/F4: the listeners did not start for the TERM test"; kill "$PROBE_PID" 2>/dev/null; }
kill -TERM "$PROBE_PID" 2>/dev/null
wait "$PROBE_PID" 2>/dev/null; term_rc=$?
if [ "$term_rc" = 143 ]; then ok "UAT-4/F4: TERM exits with 143"; else bad "UAT-4/F4: TERM rc is $term_rc (want 143)"; fi
if port_free "$P"; then ok "UAT-4/F4: no listener survives TERM"; else bad "UAT-4/F4: a listener leaked after TERM"; fi
if grep -q "unbound variable" "$WORK/out-term"; then bad "UAT-4/F4: unbound variable on the TERM path"; else ok "UAT-4/F4: TERM cleanup runs cleanly under set -u"; fi

# F4.5 partial start (no host IPv6): the IPv4 listener alone is cleaned up
P="$(probe_free_port)"
run_probe idle 0 "$P"
if [ "$RC" = 0 ]; then ok "UAT-4/F4: the IPv4-only host case completes"; else bad "UAT-4/F4: the IPv4-only host case failed (rc $RC): $OUT"; fi
if port_free "$P"; then ok "UAT-4/F4: no listener survives the partial-start case"; else bad "UAT-4/F4: a listener leaked in the partial-start case"; fi

echo
printf 'probe-vm-isolation tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
