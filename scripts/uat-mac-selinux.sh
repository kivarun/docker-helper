#!/usr/bin/env bash
#
# uat-mac-selinux.sh — SELinux MAC adapter for the docker-helper black-box UAT.
# Sourced by scripts/uat-blackbox.sh (the scenario core) when UAT_MAC=selinux.
#
# This adapter owns everything that is specific to SELinux confinement of the
# docker-helper system service:
#   * verifying SELinux is the active, enforcing, targeted LSM and that
#     AppArmor is NOT concurrently active;
#   * establishing the kernel-audit window for this UAT run;
#   * resetting the shipped policy module for idempotent re-runs;
#   * verifying the running daemon's real process context is docker_helper_t
#     (the SELinux TYPE, not the whole user:role:type:range context) while the
#     system stays enforcing;
#   * checking the fresh kernel audit window for AVC denies relevant to
#     docker-helper (docker_helper_t / docker_helper_container_t / other
#     docker_helper_* contexts, or an explicit docker-helper process).
#     On the first production SELinux UAT there is deliberately NO allowlist:
#     any fresh relevant deny fails the UAT and the exact records are printed.
#     The policy is NOT widened here to silence records — a deny is evidence
#     of a policy gap to report, never something to paper over.
#   * emitting SELinux-specific diagnostics on failure.
#
# Proof that the installed SELinux policy module artifact came from a given
# install path (RPM) is owned by the install adapter (uat-install-rpm.sh), not
# here.
#
# The scenario core defines: say, info, fail_uat, print_diagnostics, REPO_ROOT.
#
# Audit source: the standard SELinux audit source is ausearch (AVC/USER_AVC
# from the audit daemon). On the minimal Tumbleweed guest the audit daemon is
# not running by default, so the operative source here is the kernel ring
# buffer (dmesg, with journalctl -k as fallback) — the same single-source
# pattern the AppArmor adapter uses on this VM. ausearch is used only when the
# audit daemon is genuinely present and running (it can then never fail
# silently). A single source is used — never both — so one audit event is never
# counted twice.

# mac_name prints the MAC adapter label used in UAT output.
mac_name() {
  printf 'SELinux'
}

# mac_audit_start records the start of the kernel-audit window. It must be
# called before ANY docker-helper activity so that only fresh events from this
# UAT window are inspected at the end.
mac_audit_start() {
  SE_AUDIT_START_EPOCH="$(date +%s)"
  SE_AUDIT_START_ISO="$(date -Iseconds)"
  # ausearch's -ts expects "MM/DD/YYYY HH:MM:SS" (space-separated US format).
  SE_AUDIT_START_AUSEARCH="$(date '+%m/%d/%Y %H:%M:%S')"
}

# mac_preflight fails the UAT unless SELinux is the active, enforcing, targeted
# LSM with AppArmor NOT concurrently active, and the runtime tools this adapter
# actually uses are present. Presence of userspace tools is NOT taken as proof
# of an active SELinux: the LSM/enforce/targeted evidence is checked first.
mac_preflight() {
  local lsm getenf
  lsm="$(cat /sys/kernel/security/lsm 2>/dev/null || true)"
  echo "$lsm" | grep -qw selinux || fail_uat "SELinux is not an active LSM ($lsm)"
  if echo "$lsm" | grep -qw apparmor; then
    fail_uat "AppArmor is a concurrently active LSM ($lsm)"
  fi
  getenf="$(getenforce 2>/dev/null || true)"
  [ "$getenf" = "Enforcing" ] || fail_uat "getenforce != Enforcing (got '$getenf')"
  sestatus 2>/dev/null | grep -qE 'SELinux status:[[:space:]]+enabled' \
    || fail_uat "sestatus: SELinux status != enabled"
  sestatus 2>/dev/null | grep -qE 'Current mode:[[:space:]]+enforcing' \
    || fail_uat "sestatus: current mode != enforcing"
  # libselinux versions differ in the sestatus field name for the configured
  # policy: newer versions report "Loaded policy name:", older "Policy from
  # config file:". Accept both.
  sestatus 2>/dev/null | grep -qE '(Policy from config file|Loaded policy name):[[:space:]]+targeted' \
    || fail_uat "sestatus: policy != targeted"
  for tool in semodule semanage restorecon getenforce sestatus; do
    command -v "$tool" >/dev/null 2>&1 || fail_uat "$tool not found"
  done
  info "mac: $(mac_name) (enforcing, targeted; lsm='$lsm')"
  info "audit window: $SE_AUDIT_START_ISO (epoch $SE_AUDIT_START_EPOCH)"
}

# mac_reset_policy unloads any previously loaded docker_helper module so a
# re-run on a persistent VM starts from a clean slate (phase 2 idempotency).
# Best-effort and idempotent: a missing module is not an error. It does NOT
# relabel the filesystem and does NOT touch unrelated operator SELinux state.
mac_reset_policy() {
  semodule -r docker_helper 2>/dev/null || true
}

# mac_verify_confinement PID fails unless the daemon's real process context is
# docker_helper_t (the SELinux TYPE) and the system is still enforcing. Only the
# type is compared — user/role/range are not part of this contract.
mac_verify_confinement() {
  local pid="$1" attr type enf
  attr="$(cat "/proc/$pid/attr/current" 2>/dev/null || true)"
  [ -n "$attr" ] || fail_uat "cannot read daemon SELinux context (/proc/$pid/attr/current)"
  type="$(printf '%s' "$attr" | cut -d: -f3)"
  [ "$type" = "docker_helper_t" ] \
    || fail_uat "daemon SELinux type != docker_helper_t (got '$type', full context '$attr')"
  enf="$(getenforce 2>/dev/null || true)"
  [ "$enf" = "Enforcing" ] || fail_uat "SELinux not enforcing during confinement check (got '$enf')"
  info "confinement verified: pid=$pid type=$type context=$attr"
}

# ---- SELinux kernel-audit helpers ------------------------------------------

# audit_ts extracts the epoch from a kernel audit(...) prefix, or prints
# nothing when the line has no audit timestamp.
audit_ts() {
  sed -n 's/.*audit(\([0-9][0-9]*\)\.[0-9]*:[0-9]*).*/\1/p' | head -1
}

# audit_records returns unique kernel audit records that match the given grep
# filter AND fall inside the UAT audit window. It deliberately uses a SINGLE
# source with fallback — never both — so one kernel audit event can never be
# counted twice.
#
# Preference order:
#  1. ausearch (AVC/USER_AVC), only when the audit daemon is genuinely
#     present AND running (it can then never fail silently);
#  2. dmesg (kernel ring buffer), the operative source on the minimal
#     Tumbleweed guest (auditd is not running there);
#  3. journalctl -k, only when dmesg yields no output (unreadable/restricted
#     or empty ring buffer, e.g. kernel.dmesg_restrict=1).
#
# dmesg is read exactly once into a variable and its availability is decided
# from that single read, so a readable, non-empty dmesg is never probed
# through an early-closing reader.
audit_records() {
  local filter="$1" line ts raw
  if command -v ausearch >/dev/null 2>&1 && pgrep -x auditd >/dev/null 2>&1; then
    ausearch -m AVC -m USER_AVC -ts "$SE_AUDIT_START_AUSEARCH" 2>/dev/null \
      | grep -E "$filter" | sort -u
    return 0
  fi
  raw="$(dmesg 2>/dev/null || true)"
  if [ -z "$raw" ]; then
    raw="$(journalctl -k --since "@${SE_AUDIT_START_EPOCH}" --no-pager 2>/dev/null || true)"
  fi
  printf '%s\n' "$raw" \
    | grep -E "$filter" | while IFS= read -r line; do
      ts="$(printf '%s\n' "$line" | audit_ts)"
      if [ -n "$ts" ] && [ "$ts" -ge "$SE_AUDIT_START_EPOCH" ]; then
        printf '%s\n' "$line"
      fi
    done | sort -u
}

# collect_denials prints unique fresh kernel audit records that are AVC denies
# (avc: denied) relevant to docker-helper (any docker_helper_* context, which
# covers docker_helper_t, docker_helper_container_t and the helper's own file
# types; container and daemon processes both carry such contexts).
collect_denials() {
  audit_records 'avc:[[:space:]]+denied' | grep -F 'docker_helper_'
}

# collect_relevant prints unique fresh AVC records (denied or not) relevant to
# docker-helper, for diagnostics.
collect_relevant() {
  audit_records 'avc:|type=AVC|type=USER_AVC' | grep -F 'docker_helper_'
}

# mac_audit_check inspects only fresh AVC denies from this UAT window that are
# relevant to docker-helper. On the first production SELinux UAT there is
# deliberately NO allowlist: any fresh relevant deny fails the UAT and the
# exact records are printed.
mac_audit_check() {
  say "$(mac_name) audit check (fresh relevant AVC denies, no allowlist)"
  local denies
  denies="$(collect_denials)"
  if [ -z "$denies" ]; then
    info "no fresh $(mac_name) AVC denies relevant to docker-helper in this window"
    info "(if unexpected, check that kernel audit logging is active on the runner)"
    return 0
  fi
  printf '\n[UAT] FRESH %s AVC DENIES relevant to docker-helper:\n' "$(mac_name)" >&2
  printf '%s\n' "$denies" >&2
  fail_uat "fresh $(mac_name) AVC denies relevant to docker-helper"
}

# mac_h6_precheck verifies the SELinux labeling state around the admin-token
# replacement lifecycle before the rotation is attempted:
#   * fresh-install contract: the canonical admin.token carries the dedicated
#     docker_helper_admin_token_t type and config.json stays
#     docker_helper_config_t;
#   * migration/reinstall contract: an existing token formerly labeled
#     docker_helper_config_t (pre-H6 policy) is migrated to the dedicated
#     type by the shipped packaging restorecon owner with the token VALUE
#     unchanged;
#   * docker_helper_t holds NO write permission on docker_helper_config_t:file
#     (sesearch, when setools are installed).
mac_h6_precheck() {
  local token_file="$1" config_file="$2"
  local tok_ctx cfg_ctx value_before

  # Discriminate the installed policy generation: a pre-H6 policy module does
  # not define the dedicated token type at all, so the fresh-install label
  # contract cannot hold on such an artifact — the stage proceeds to the
  # rotation to capture the H6 RED AVC instead. On a policy that defines the
  # type, the label contract is strict.
  if semanage fcontext -l 2>/dev/null | grep -q 'docker_helper_admin_token_t'; then
    tok_ctx="$(stat -c '%C' "$token_file" 2>/dev/null)" \
      || fail_uat "cannot stat the admin token context"
    printf '%s' "$tok_ctx" | grep -q 'docker_helper_admin_token_t' \
      || fail_uat "fresh-install labeling: admin.token is not docker_helper_admin_token_t (got '$tok_ctx')"
    cfg_ctx="$(stat -c '%C' "$config_file" 2>/dev/null)" \
      || fail_uat "cannot stat config.json context"
    printf '%s' "$cfg_ctx" | grep -q 'docker_helper_config_t' \
      || fail_uat "config.json is not docker_helper_config_t (got '$cfg_ctx')"
    info "fresh-install labeling: admin.token=docker_helper_admin_token_t, config.json=docker_helper_config_t"

    value_before="$(cat "$token_file")"
    [ -n "$value_before" ] || fail_uat "admin.token is empty"
    if command -v chcon >/dev/null 2>&1; then
      chcon -t docker_helper_config_t "$token_file" \
        || fail_uat "cannot stage the pre-upgrade token label (chcon)"
      [ "$(cat "$token_file")" = "$value_before" ] \
        || fail_uat "label staging changed the token value"
      /usr/sbin/restorecon -R /etc/docker-helper \
        || fail_uat "packaging restorecon failed during the label migration"
      printf '%s' "$(stat -c '%C' "$token_file")" | grep -q 'docker_helper_admin_token_t' \
        || fail_uat "packaging restorecon did not migrate admin.token to docker_helper_admin_token_t (got '$(stat -c '%C' "$token_file")')"
      [ "$(cat "$token_file")" = "$value_before" ] \
        || fail_uat "label migration changed the token value"
      info "migration labeling: docker_helper_config_t -> docker_helper_admin_token_t via the packaging restorecon, value unchanged"
    fi
  else
    info "pre-H6 policy module: docker_helper_admin_token_t is not defined — fresh-install/migration labeling deferred to the rotation evidence"
  fi

  # config.json stays non-writable for docker_helper_t in EVERY policy
  # generation (sesearch, when setools are installed).
  if command -v sesearch >/dev/null 2>&1; then
    if sesearch -A -s docker_helper_t -t docker_helper_config_t -c file -p write 2>/dev/null | grep -q 'allow'; then
      fail_uat "docker_helper_t holds a write permission on docker_helper_config_t:file"
    fi
    info "sesearch: no write permission on docker_helper_config_t:file"
  fi
}

# mac_h6_denial_evidence succeeds only when the fresh audit window holds an
# AVC deny for docker_helper_t that mentions the admin-token replacement
# lifecycle (any .admin-token* spelling). It is the H6 RED discriminator: a
# rotation failure without such a denial is not H6 evidence.
mac_h6_denial_evidence() {
  # The auditd userspace log (ausearch) is flushed asynchronously and can
  # lag the kernel ring buffer by tens of seconds on this guest, so the
  # discriminator polls BOTH the adapter audit source and the raw kernel
  # ring buffer. This is an existence check — a single record can never be
  # counted twice — and every candidate record is window-filtered.
  local attempt=0 ts line filtered
  local raws
  while [ "$attempt" -lt 30 ]; do
    raws="$(collect_denials)
$(journalctl -k --since "@${SE_AUDIT_START_EPOCH}" --no-pager 2>/dev/null || true)"
    filtered="$(printf '%s\n' "$raws" \
      | grep 'denied' | grep -E 'docker_helper_config_t|admin-token|admin\\.token' || true)"
    if [ -n "$filtered" ]; then
      while IFS= read -r line; do
        ts="$(printf '%s\n' "$line" | audit_ts)"
        if [ -n "$ts" ] && [ "$ts" -ge "$SE_AUDIT_START_EPOCH" ]; then
          return 0
        fi
      done <<< "$filtered"
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  return 1
}

# mac_h6_postcheck re-verifies the labels after a successful rotation and
# fails on any fresh AVC deny that mentions the token replacement lifecycle
# (a successful lifecycle must produce none).
mac_h6_postcheck() {
  local token_file="$1" config_file="$2" staging="$3"
  [ ! -e "$staging" ] || fail_uat "staging pathname exists after the rotation"
  printf '%s' "$(stat -c '%C' "$token_file" 2>/dev/null)" | grep -q 'docker_helper_admin_token_t' \
    || fail_uat "post-rotation: admin.token is not docker_helper_admin_token_t"
  printf '%s' "$(stat -c '%C' "$config_file" 2>/dev/null)" | grep -q 'docker_helper_config_t' \
    || fail_uat "post-rotation: config.json is not docker_helper_config_t"
  local records
  records="$(collect_denials)"
  local bad=""
  printf '%s\n' "$records" | grep -F 'admin-token' >/dev/null 2>&1 && bad+="token replacement pathnames"$'\n'
  printf '%s\n' "$records" | grep 'denied' | grep -F 'docker_helper_config_t' >/dev/null 2>&1 && bad+="docker_helper_config_t objects"$'\n'
  if [ -n "$bad" ]; then
    printf '\n[UAT] SELinux AVC denies on the token replacement lifecycle:\n%s\n' "$records" >&2
    fail_uat "unexpected SELinux AVCs on the successful admin-token rotation ($bad)"
  fi
  info "SELinux H6 postcheck ok (labels stable, no token-replacement AVCs)"
}

# mac_diagnostics appends SELinux-specific evidence to print_diagnostics.
mac_diagnostics() {
  echo "--- sestatus ---"
  sestatus 2>&1 || true
  echo "--- getenforce ---"
  getenforce 2>&1 || true
  echo "--- /sys/kernel/security/lsm ---"
  cat /sys/kernel/security/lsm 2>&1 || true
  echo "--- docker-helper process context ---"
  local dh_pid
  dh_pid="$(systemctl show -p MainPID --value docker-helper.service 2>/dev/null || true)"
  if [ -n "$dh_pid" ] && [ "$dh_pid" != "0" ]; then
    printf 'attr/current: '; cat "/proc/$dh_pid/attr/current" 2>&1 || true
  else
    echo "daemon MainPID is empty/zero"
  fi
  echo "--- fresh relevant AVC records (window) ---"
  collect_relevant 2>&1 | head -60 || true
  echo "--- loaded docker_helper policy modules ---"
  semodule -l 2>&1 | grep docker_helper || echo "(no docker_helper module listed)"
  echo "--- semanage fcontext rules for docker-helper paths ---"
  semanage fcontext -l 2>&1 | grep -E 'docker-helper|docker_helper' || echo "(no matching fcontext rules)"
  echo "--- SELinux contexts of docker-helper paths (if present) ---"
  for p in /usr/bin/docker-helper /etc/docker-helper /var/lib/docker-helper /run/docker-helper; do
    if [ -e "$p" ]; then
      ls -Zd "$p" 2>&1 || true
    else
      echo "$p: (absent)"
    fi
  done
  echo "--- kernel deny tail (dmesg) ---"
  dmesg 2>/dev/null | tail -40 || true
}
