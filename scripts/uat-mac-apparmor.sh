#!/usr/bin/env bash
#
# uat-mac-apparmor.sh — AppArmor MAC adapter for the docker-helper black-box
# UAT. Sourced by scripts/uat-blackbox.sh (the scenario core) when
# UAT_MAC=apparmor.
#
# This adapter owns everything that is specific to AppArmor confinement of the
# docker-helper system service:
#   * verifying the AppArmor LSM and apparmor_parser are available;
#   * establishing the kernel-audit window for this UAT run;
#   * resetting the shipped profile for idempotent re-runs;
#   * verifying the running daemon is confined by docker-helper-system
#     (enforce), not unconfined, using the installed profile;
#   * checking the fresh kernel audit window for unexpected DENIED records
#     under profile docker-helper-system, tolerating a narrow allowlist of
#     demonstrated benign probes;
#   * emitting AppArmor-specific diagnostics on failure.
#
# Proof that the installed AppArmor profile artifact came from a given install
# path (deb package vs release tarball) is owned by the install adapter
# (uat-install-<name>.sh), not here.
#
# The AppArmor policy itself is NOT widened here to silence audit records;
# the allowlist below merely tolerates already-demonstrated benign probes.
#
# The scenario core defines: say, info, fail_uat, print_diagnostics, REPO_ROOT.

# mac_name prints the MAC adapter label used in UAT output.
mac_name() {
  printf 'AppArmor'
}

# mac_audit_start records the start of the kernel-audit window. It must be
# called before ANY docker-helper activity so that only fresh events from this
# UAT window are inspected at the end.
mac_audit_start() {
  AA_AUDIT_START_EPOCH="$(date +%s)"
  AA_AUDIT_START_ISO="$(date -Iseconds)"
}

# mac_preflight fails the UAT unless the AppArmor LSM and the parser are
# available on this host.
mac_preflight() {
  if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null | tr -d '[:space:]')" != "Y" ]; then
    fail_uat "AppArmor LSM is not enabled on this kernel"
  fi
  if ! command -v apparmor_parser >/dev/null 2>&1; then
    fail_uat "apparmor_parser not found"
  fi
  info "mac: $(mac_name) (parser $(apparmor_parser --version 2>&1 | head -1 || true))"
  info "audit window: $AA_AUDIT_START_ISO (epoch $AA_AUDIT_START_EPOCH)"
}

# mac_reset_policy unloads any previously loaded shipped profile so a re-run
# on a persistent VM starts from a clean slate (phase 2 idempotency).
mac_reset_policy() {
  apparmor_parser -R /etc/apparmor.d/docker-helper-system 2>/dev/null || true
}

# mac_verify_confinement PID fails unless the daemon process is confined by
# docker-helper-system in enforce mode (not unconfined) and the profile is
# loaded. Called after the service is active.
mac_verify_confinement() {
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
#  1. dmesg (kernel ring buffer), preferred when it is readable and non-empty;
#  2. journalctl -k, only when dmesg yields no output (unreadable/restricted
#     or empty ring buffer, e.g. kernel.dmesg_restrict=1).
#
# dmesg is read exactly once into a variable and its availability is decided
# from that single read. This avoids probing dmesg through a pipeline with an
# early-closing reader (e.g. `head`), which under pipefail could SIGPIPE a
# readable, non-empty dmesg and incorrectly fall back to journalctl.
audit_records() {
  local filter="$1" line ts raw
  raw="$(dmesg 2>/dev/null || true)"
  if [ -z "$raw" ]; then
    raw="$(journalctl -k --since "@${AA_AUDIT_START_EPOCH}" --no-pager 2>/dev/null || true)"
  fi
  printf '%s\n' "$raw" \
    | grep -E "$filter" | while IFS= read -r line; do
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

# mac_audit_check inspects only fresh DENIED records from this UAT window under
# profile docker-helper-system. Any record that is not on the narrow allowlist
# fails the UAT and prints the exact records.
mac_audit_check() {
  say "$(mac_name) audit check (fresh DENIED records for docker-helper-system)"
  local denials
  denials="$(collect_denials)"
  if [ -z "$denials" ]; then
    info "no fresh $(mac_name) DENIED records for docker-helper-system in this window"
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
    printf '\n[UAT] UNEXPECTED %s DENIED records:\n' "$(mac_name)" >&2
    printf '%s' "$unexpected" >&2
    fail_uat "unexpected $(mac_name) denials under docker-helper-system"
  fi
  info "$(mac_name) audit check passed (allowlisted=$allowlisted unexpected=0)"
}

# mac_h6_precheck verifies the installed profile gives no generic writable
# config surface before the rotation is attempted: every /etc/docker-helper
# rule must be read-only except the two exact token-replacement pathnames
# (the canonical admin.token and the fixed staging pathname).
mac_h6_precheck() {
  local token_file="$1" config_file="$2"
  local profile="/etc/apparmor.d/docker-helper-system"
  [ -e "$profile" ] || fail_uat "installed AppArmor profile not found at $profile"
  local line path perms bad=""
  while IFS= read -r line; do
    printf '%s' "$line" | grep -q '^[[:space:]]*#' && continue
    path="$(printf '%s' "$line" | awk '{print $1}')"
    printf '%s' "$path" | grep -q '^/etc/docker-helper' || continue
    perms="$(printf '%s' "$line" | awk '{print $NF}' | tr -d ',')"
    printf '%s' "$perms" | grep -qE '[wa]' || continue
    case "$path" in
      /etc/docker-helper/admin.token|/etc/docker-helper/.admin-token.new) ;;
      *) bad+="$line"$'\n' ;;
    esac
  done < "$profile"
  if [ -n "$bad" ]; then
    printf '\n[UAT] write-capable /etc/docker-helper rules beyond the token replacement pathnames:\n%s\n' "$bad" >&2
    fail_uat "installed AppArmor profile grants a generic writable config surface"
  fi
  info "installed profile config write surface: only the admin-token replacement pathnames"
}

# mac_h6_denial_evidence succeeds only when the fresh audit window holds an
# AppArmor DENIED record for the docker-helper-system profile that mentions
# the admin-token replacement lifecycle (any .admin-token* spelling). It is
# the H6 RED discriminator: a rotation failure without such a denial is not
# H6 evidence.
mac_h6_denial_evidence() {
  local staging="$1" token_file="$2"
  local records
  records="$(collect_denials)"
  # The denial name carries the created/replaced token pathname (any
  # .admin-token* spelling: the historical random tempfile or the fixed
  # staging pathname, or the canonical token file at rename time).
  printf '%s\n' "$records" | grep -F 'admin-token' >/dev/null 2>&1 \
    || printf '%s\n' "$records" | grep -F "$(basename "$token_file")" >/dev/null 2>&1
}

# mac_h6_postcheck re-verifies the installed write surface after a successful
# rotation and fails on any fresh AppArmor denial that mentions the token
# replacement lifecycle (a successful lifecycle must produce none).
mac_h6_postcheck() {
  local token_file="$1" config_file="$2" staging="$3"
  [ ! -e "$staging" ] || fail_uat "staging pathname exists after the rotation"
  mac_h6_precheck "$token_file" "$config_file"
  local records
  records="$(collect_denials | grep -F 'admin-token' || true)"
  if [ -n "$records" ]; then
    printf '\n[UAT] AppArmor DENIED records on the token replacement lifecycle:\n%s\n' "$records" >&2
    fail_uat "unexpected AppArmor denials on the successful admin-token rotation"
  fi
  info "AppArmor H6 postcheck ok (no token-replacement denials)"
}

# mac_diagnostics appends AppArmor-specific evidence to print_diagnostics.
mac_diagnostics() {
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
