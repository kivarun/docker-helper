#!/usr/bin/env bash
#
# uat-regressions-runner-selinux.sh — collect-all runner for the Release-2
# targeted UAT regression groups on the Tumbleweed / RPM / SELinux profile
# (groups 1-4). Runs INSIDE the SELinux guest, as root.
#
# It re-ensures the docker-helper system service (the common black-box UAT may
# have stopped it during cleanup) and runs every SELinux regression group,
# capturing rc and recording PASS / FAIL / BLOCKED for each. A failure in one
# group never stops the others (collect-all). It does NOT depend on the common
# black-box UAT reaching its final phase.
#
# Exit codes of the individual regression scripts (contract):
#   0 = PASS, 1 = FAIL, 2 = BLOCKED.
# Exit status of this runner: 0 when no regression failed, nonzero otherwise.

set -uo pipefail

PREFIX="[regressions-selinux]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }
info() { printf '%s %s\n' "$PREFIX" "$*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
[ "$(getenforce 2>/dev/null || true)" = "Enforcing" ] || { echo "error: SELinux not enforcing" >&2; exit 1; }

say "ensure docker-helper service (common black-box may have stopped it)"
systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
for _ in $(seq 1 60); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
if ! systemctl is-active --quiet docker-helper.service; then
  echo "error: docker-helper.service not active; SELinux regressions cannot run" >&2
  exit 1
fi
DH_PID="$(systemctl show -p MainPID --value docker-helper.service)"
info "service active: pid=$DH_PID type=$(cut -d: -f3 "/proc/$DH_PID/attr/current" 2>/dev/null || true)"

# Diagnostic: dump the LOADED policy's docker_helper relabel/getattr grants and
# the installed docker_helper module identity, so a relabel blocker can be
# attributed to the loaded policy (not guessed from the RPM artifact).
info "loaded docker_helper module(s):"
semodule -l 2>&1 | grep docker_helper | sed 's/^/  /' || echo "  (no docker_helper module listed)"
info "module store files for docker_helper (active + tmp):"
for d in /etc/selinux/targeted/modules/active/modules /etc/selinux/targeted/tmp/modules /etc/selinux/targeted/modules/tmp; do
  if [ -d "$d" ]; then
    echo "  [$d]"
    ls -la "$d" 2>&1 | grep -Ei "docker_helper|cil$|pp$|mod$" | sed 's/^/    /' || echo "    (no matching entries)"
  else
    echo "  [$d] absent"
  fi
done
  echo "  find docker_helper module files:"
  find /etc/selinux -iname '*docker_helper*' 2>/dev/null | sed 's/^/    /' || true
  STORE="$(find /etc/selinux -path '*/active/modules/*/docker_helper' 2>/dev/null | head -1)"
  if [ -n "$STORE" ]; then
    info "  module store entry: $STORE (type: $(stat -c '%F' "$STORE" 2>/dev/null || echo '?'))"
    if [ -d "$STORE" ]; then
      echo "    contents:"; ls -la "$STORE" | sed 's/^/      /' || true
      for f in "$STORE"/cil "$STORE"/pp "$STORE"/hll "$STORE"/lang_ext; do
        if [ -e "$f" ]; then
          info "    file $f: $(stat -c '%s bytes' "$f" 2>/dev/null || echo '?')"
          case "$(basename "$f")" in
            cil)
              info "    CIL FULL CONTENT (decompressed if bzip2):"
              if command -v bzip2 >/dev/null 2>&1 && file -b "$f" 2>/dev/null | grep -q 'bzip2'; then
                info "      bzip2 available: yes; attempting decompress"
                bzip2 -dc "$f" >/tmp/dh_store.cil 2>/tmp/dh_bz.err
                info "      decompress rc=$? stderr: $(tr '\n' ' ' < /tmp/dh_bz.err)"
                info "      decompressed: $(wc -l < /tmp/dh_store.cil 2>/dev/null || echo 0) lines, $(wc -c < /tmp/dh_store.cil 2>/dev/null || echo 0) bytes"
                sed -n '1,120p' /tmp/dh_store.cil 2>/dev/null | sed 's/^/      /' || true
                rm -f /tmp/dh_store.cil /tmp/dh_bz.err
              else
                info "      bzip2 not used (unavailable or not bzip2: '$(file -b "$f" 2>/dev/null || echo '?')')"
                sed -n '1,120p' "$f" 2>/dev/null | sed 's/^/      /' || true
              fi
              info "    CIL workspace relabel/getattr rules:"
              if command -v bzip2 >/dev/null 2>&1 && head -c 4 "$f" 2>/dev/null | grep -q 'BZh'; then
                bzip2 -dc "$f" 2>/dev/null | grep -E 'allow docker_helper_t (usr_t|docker_helper_workspace_t) ' \
                  | grep -E 'relabelfrom|relabelto|getattr' | sed 's/^/      /' || echo "      (none)"
              else
                grep -E 'allow docker_helper_t (usr_t|docker_helper_workspace_t) ' "$f" 2>/dev/null \
                  | grep -E 'relabelfrom|relabelto|getattr' | sed 's/^/      /' || echo "      (none)"
              fi
              info "    CIL ALL docker_helper_t allow heads:"
              grep -oE '\(allow docker_helper_t [^ ]+ [^ ]+' "$f" 2>/dev/null | sort | uniq -c | sed 's/^/      /' | head -60 || echo "      (none)"
              ;;
            pp)
              info "    pp section listing:"
              ls -la "$STORE" | sed 's/^/      /' || true
              ;;
            hll)
              info "    hll content type: $(file -b "$f" 2>/dev/null || echo '?')"
              if command -v bzip2 >/dev/null 2>&1 && file -b "$f" 2>/dev/null | grep -q 'bzip2'; then
                info "    hll decompressed (this is the actual installed module source that semodule -E should export):"
                bzip2 -dc "$f" 2>/dev/null | sed -n '1,150p' | sed 's/^/      /' || true
              fi
              ;;
          esac
        fi
      done
    else
      info "    store file bytes: $(stat -c '%s' "$STORE" 2>/dev/null || echo '?')"
    fi
  fi
# The installed module's CIL is exactly what the kernel policy contains.
info "installed docker_helper module CIL export (semodule -E docker_helper):"
if semodule -E docker_helper >/tmp/dh_loaded.cil 2>/tmp/dh_loaded.err; then
  info "  export ok: $(wc -l < /tmp/dh_loaded.cil) lines, $(wc -c < /tmp/dh_loaded.cil) bytes, allow rules: $(grep -c '(allow docker_helper_t' /tmp/dh_loaded.cil || true)"
  info "  export stderr: $(tr '\n' ' ' < /tmp/dh_loaded.err)"
  info "  export CIL raw (first 60 lines):"
  sed -n '1,60p' /tmp/dh_loaded.cil | sed 's/^/    /' || true
else
  info "  semodule -E failed: $(tr '\n' ' ' < /tmp/dh_loaded.err)"
fi
rm -f /tmp/dh_loaded.cil /tmp/dh_loaded.err
# Authoritative: query the LIVE kernel policy (/sys/fs/selinux/policy) for the
# docker_helper_t -> usr_t / docker_helper_workspace_t allows actually enforced.
info "live kernel policy grants (setools, /sys/fs/selinux/policy):"
if command -v python3 >/dev/null 2>&1 && python3 -c 'import setools' 2>/dev/null; then
  python3 - <<'PY' 2>&1 | sed 's/^/  /' || true
import sys
try:
    from setools import SELinuxPolicy, TypeQuery, AVRuleQuery, TypeRuleQuery
    qcls = AVRuleQuery or TypeRuleQuery
    p = SELinuxPolicy("/sys/fs/selinux/policy")
    print("policy version:", getattr(p, "version", "?"))
    try:
        types = sorted(t.name for t in p.types() if t.name in ("docker_helper_t", "docker_helper_workspace_t", "usr_t"))
        print("types present:", types)
    except Exception as e:
        print("types query failed:", e)
    if qcls is None:
        print("no query class available")
    else:
        for tgt in ("usr_t", "docker_helper_workspace_t"):
            for cls in ("dir", "file", "lnk_file", "fifo_file"):
                try:
                    perms = set()
                    for rule in p.query(qcls(source="docker_helper_t", target=tgt, tclass=cls, ruletype="allow")):
                        perms.update(rule.perms)
                    if perms:
                        print(f"docker_helper_t {tgt}:{cls} allow perms = {sorted(perms)}")
                except Exception as e:
                    print(f"  query {tgt}:{cls} failed: {e}")
except Exception as e:
    print(f"setools diagnostic failed: {e}")
PY
else
  info "  python setools not available on guest"
fi

REGRESSIONS=(
  "1:SELinux non-home workspace lifecycle:uat-regression-selinux-workspace-lifecycle.sh"
  "2:SELinux operator-owned boundary:uat-regression-selinux-operator-boundary.sh"
  "3:SELinux restorecon filesystem-boundary:uat-regression-selinux-fs-boundary.sh"
  "4:SELinux mount-boundary guard:uat-regression-selinux-mount-guard.sh"
  "5:SELinux workspace relabel AVC evidence:uat-regression-selinux-relabel-avc.sh"
)

# Fresh AVC/USER_AVC evidence (best-effort; requires auditd started by the
# scope=selinux bootstrap). Dumps a bounded, docker-helper-relevant window of
# denial records since AVC_START.
AVC_START="$(date '+%m/%d/%Y %H:%M:%S')"
info "fresh AVC/USER_AVC evidence window starts $AVC_START"
avc_evidence() { # label
  local label="$1"
  echo "--- AVC evidence: $label ---" >&2
  if command -v ausearch >/dev/null 2>&1; then
    ausearch -m AVC,USER_AVC -ts "$AVC_START" 2>/dev/null \
      | grep -E 'avc:  denied|USER_AVC|scontext=|tcontext=' \
      | grep -Ei 'docker_helper|restorecon|setfiles|filesystem|getattr|denied' \
      | tail -30 || true
  fi
  tail -150 /var/log/audit/audit.log 2>/dev/null \
    | grep -E 'avc:  denied|USER_AVC' \
    | grep -Ei 'docker_helper|restorecon|setfiles|filesystem|getattr|denied' \
    | tail -30 || true
}

declare -A RESULT
declare -A RC_OF
FAILED=0
for entry in "${REGRESSIONS[@]}"; do
  num="${entry%%:*}"
  rest="${entry#*:}"
  label="${rest%%:*}"
  script="${rest#*:}"
  say "== group $num: $label =="
  if ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
    systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
      systemctl is-active --quiet docker-helper.service && break
      sleep 1
    done
  fi
  timeout 900 bash "$SCRIPT_DIR/$script"
  rc=$?
  RC_OF[$num]=$rc
  case "$rc" in
    0) RESULT[$num]="PASS";;
    2) RESULT[$num]="BLOCKED";;
    124) RESULT[$num]="FAIL"; echo "  (group $num timed out after 900s)" >&2;;
    *) RESULT[$num]="FAIL";;
  esac
  if [ "${RESULT[$num]}" = "FAIL" ]; then
    FAILED=1
    echo "--- bounded evidence for group $num ($label) ---" >&2
    journalctl -u docker-helper.service -n 40 --no-pager 2>/dev/null | tail -40 >&2 || true
    avc_evidence "group $num ($label)"
  fi
  printf 'REGRESSION_MAP: %s=%s:%s\n' "$num" "$label" "${RESULT[$num]}"
done
avc_evidence "full regression run"

echo
say "================= REGRESSION SUMMARY (Tumbleweed/RPM/SELinux) ==============="
for entry in "${REGRESSIONS[@]}"; do
  num="${entry%%:*}"
  label="$(printf '%s' "${entry#*:}" | cut -d: -f1)"
  printf '  %s. %-34s %s (rc=%s)\n' "$num" "$label" "${RESULT[$num]}" "${RC_OF[$num]}"
done
echo "======================================================================"

[ "$FAILED" = 0 ] || echo "RESULT: at least one regression FAILED" >&2
exit "$FAILED"
