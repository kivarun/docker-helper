#!/usr/bin/env bash
#
# uat-backend-apparmor.sh — AppArmor backend layer for the docker-helper
# black-box UAT. Sourced by scripts/uat-blackbox.sh (the backend-agnostic
# core) when UAT_BACKEND=apparmor.
#
# This layer owns everything that is specific to AppArmor confinement of the
# docker-helper system service:
#   * verifying the AppArmor LSM and apparmor_parser are available;
#   * establishing the kernel-audit window for this UAT run;
#   * resetting the shipped profile for idempotent re-runs;
#   * verifying the running daemon is confined by docker-helper-system
#     (enforce), not unconfined, using the package-installed profile;
#   * verifying the packaged profile artifact is owned by the package;
#   * checking the fresh kernel audit window for unexpected DENIED records
#     under profile docker-helper-system, tolerating a narrow allowlist of
#     demonstrated benign probes;
#   * emitting AppArmor-specific diagnostics on failure.
#
# The AppArmor policy itself is NOT widened here to silence audit records;
# the allowlist below merely tolerates already-demonstrated benign probes.
#
# The generic core defines: say, info, fail_uat, print_diagnostics, REPO_ROOT.

# backend_name prints the backend label used in UAT output.
backend_name() {
  printf 'AppArmor'
}

# backend_audit_start records the start of the kernel-audit window. It must be
# called before ANY docker-helper activity so that only fresh events from this
# UAT window are inspected at the end.
backend_audit_start() {
  AA_AUDIT_START_EPOCH="$(date +%s)"
  AA_AUDIT_START_ISO="$(date -Iseconds)"
}

# backend_preflight fails the UAT unless the AppArmor LSM and the parser are
# available on this host.
backend_preflight() {
  if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null | tr -d '[:space:]')" != "Y" ]; then
    fail_uat "AppArmor LSM is not enabled on this kernel"
  fi
  if ! command -v apparmor_parser >/dev/null 2>&1; then
    fail_uat "apparmor_parser not found"
  fi
  info "backend: $(backend_name) (parser $(apparmor_parser --version 2>&1 | head -1 || true))"
  info "audit window: $AA_AUDIT_START_ISO (epoch $AA_AUDIT_START_EPOCH)"
}

# backend_reset_policy unloads any previously loaded shipped profile so a
# re-run on a persistent VM starts from a clean slate (phase 2 idempotency).
backend_reset_policy() {
  apparmor_parser -R /etc/apparmor.d/docker-helper-system 2>/dev/null || true
}

# backend_verify_policy_packaged fails unless the shipped AppArmor profile
# artifact is installed as part of the docker-helper package.
backend_verify_policy_packaged() {
  dpkg -S /etc/apparmor.d/docker-helper-system >/dev/null 2>&1 \
    || fail_uat "AppArmor profile is not owned by the docker-helper package"
}

# backend_verify_confinement PID fails unless the daemon process is confined
# by docker-helper-system in enforce mode (not unconfined) and the profile is
# loaded. Called after the service is active.
backend_verify_confinement() {
  local pid="$1" attr
  attr="$(cat "/proc/$pid/attr/current" 2>/dev/null || true)"
  [ "$attr" = "docker-helper-system (enforce)" ] \
    || fail_uat "daemon is not confined in docker-helper-system (enforce): got '$attr'"
  aa-status 2>/dev/null | grep -q 'docker-helper-system' \
    || fail_uat "docker-helper-system profile is not loaded"
  info "confinement verified: pid=$pid profile=$attr"
}

# ---- AppArmor kernel-audit helpers ------------------------------------------

# audit_ts extracts the epoch from a kernel audit(...) prefix, or prints
# nothing when the line has no audit timestamp.
audit_ts() {
  sed -n 's/.*audit(\([0-9][0-9]*\)\.[0-9]*:[0-9]*).*/\1/p' | head -1
}

# audit_records returns unique kernel audit records that match the given
# grep filter AND fall inside the UAT audit window. It deliberately uses a
# SINGLE source with fallback — never both — so one kernel audit event can
# never be counted twice.
#
# Preference order:
#  1. dmesg (kernel ring buffer): authoritative for kernel audit records and
#     the reliable source on GitHub-hosted runners (systemd-journald there
#     reports "Collecting audit messages is disabled", so journalctl -k has
#     no AppArmor records while the ring buffer does);
#  2. journalctl -k, only when dmesg is unavailable/restricted (empty output,
#     e.g. kernel.dmesg_restrict=1).
audit_records() {
  local filter="$1" line ts
  if dmesg 2>/dev/null | head -1 | grep -q .; then
    dmesg 2>/dev/null || true
  else
    journalctl -k --since "@${AA_AUDIT_START_EPOCH}" --no-pager 2>/dev/null
  fi | grep -E "$filter" | while IFS= read -r line; do
    ts="$(printf '%s\n' "$line" | audit_ts)"
    if [ -n "$ts" ] && [ "$ts" -ge "$AA_AUDIT_START_EPOCH" ]; then
      printf '%s\n' "$line"
    fi
  done | sort -u
}

# collect_denials prints unique fresh kernel audit records that mention an
# AppArmor DENIED event under profile docker-helper-system.
collect_denials() {
  audit_records 'apparmor="DENIED"' | grep -F 'profile="docker-helper-system"'
}

collect_profile_records() {
  audit_records 'apparmor=' | grep -F 'profile="docker-helper-system"'
}

# is_allowlisted_deny classifies a single deny record against the narrow
# allowlist of demonstrated benign probes. Everything else is unexpected.
# All entries come from demonstrated UAT runs (openSUSE manual + GitHub
# runner); the AppArmor policy is NOT widened to silence them — they are
# merely tolerated here.
is_allowlisted_deny() {
  local line="$1"
  # docker CLI reads its own cgroup cpu.max (best-effort probe, benign).
  if echo "$line" | grep -q 'name="/sys/fs/cgroup/system.slice/docker-helper.service/cpu.max"'; then
    return 0
  fi
  # docker-buildx probes for git(1) (exec deny, benign best-effort probe).
  # The path is distro-specific: /usr/libexec/git/git on openSUSE,
  # /usr/bin/git on Ubuntu.
  if echo "$line" | grep -q 'operation="exec"' \
    && echo "$line" | grep -qE 'name="/(usr/libexec/git|usr/bin)/git"' \
    && echo "$line" | grep -q 'comm="docker-buildx"'; then
    return 0
  fi
  # docker CLI binds an abstract unix socket for the buildx plugin bridge.
  # Best-effort probe: the build proceeds when the bind is denied, and the
  # audit record carries comm="docker" with addr="@docker_cli_<hex>".
  if echo "$line" | grep -q 'operation="bind"' \
    && echo "$line" | grep -q 'class="net"' \
    && echo "$line" | grep -q 'family="unix"' \
    && echo "$line" | grep -q 'addr="@docker_cli_' \
    && echo "$line" | grep -q 'comm="docker"'; then
    return 0
  fi
  # docker-buildx enumerates candidate system TLS root directories. On Ubuntu
  # /etc/ssl/certs is a real directory (vs openSUSE where the paths resolve
  # elsewhere); the denied read of the directory itself is a benign best-effort
  # probe — the build and TLS E2E succeed without it, so it is not granted.
  if echo "$line" | grep -q 'operation="open"' \
    && echo "$line" | grep -q 'name="/etc/ssl/certs/"' \
    && echo "$line" | grep -q 'comm="docker-buildx"'; then
    return 0
  fi
  return 1
}

# backend_audit_check inspects only fresh DENIED records from this UAT window
# under profile docker-helper-system. Any record that is not on the narrow
# allowlist fails the UAT and prints the exact records.
backend_audit_check() {
  say "$(backend_name) audit check (fresh DENIED records for docker-helper-system)"
  local denials
  denials="$(collect_denials)"
  if [ -z "$denials" ]; then
    info "no fresh $(backend_name) DENIED records for docker-helper-system in this window"
    info "(if unexpected, check that kernel audit logging is active on the runner)"
    return 0
  fi

  local unexpected="" allowlisted=0 line
  while IFS= read -r line; do
    if is_allowlisted_deny "$line"; then
      allowlisted=$((allowlisted + 1))
      info "allowlisted benign deny: $line"
    else
      unexpected+="$line"$'\n'
    fi
  done <<< "$denials"

  if [ -n "$unexpected" ]; then
    printf '\n[UAT] UNEXPECTED %s DENIED records:\n' "$(backend_name)" >&2
    printf '%s' "$unexpected" >&2
    fail_uat "unexpected $(backend_name) denials under docker-helper-system"
  fi
  info "$(backend_name) audit check passed (allowlisted=$allowlisted unexpected=0)"
}

# backend_diagnostics appends AppArmor-specific evidence to print_diagnostics.
backend_diagnostics() {
  echo "--- AppArmor status (aa-status) ---"
  aa-status 2>&1 | head -40 || true
  echo "--- docker-helper-system process confinement ---"
  local dh_pid
  dh_pid="$(systemctl show -p MainPID --value docker-helper.service 2>/dev/null || true)"
  if [ -n "$dh_pid" ] && [ "$dh_pid" != "0" ]; then
    printf 'attr/current: '; cat "/proc/$dh_pid/attr/current" 2>&1 || true
  else
    echo "daemon MainPID is empty/zero"
  fi
  echo "--- fresh docker-helper-system audit records ---"
  collect_profile_records 2>&1 | head -60 || true
  echo "--- kernel deny tail (dmesg) ---"
  dmesg 2>/dev/null | tail -40 || true
}
