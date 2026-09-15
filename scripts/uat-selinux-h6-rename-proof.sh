#!/usr/bin/env bash
#
# uat-selinux-h6-rename-proof.sh — exact-policy SELinux proof for the SC1/H6
# admin-token rename-destination scope (PR review round 2 architecture
# warning). Runs as root inside the Tumbleweed SELinux VM AFTER the candidate
# RPM/policy is installed and the black-box UAT has proven the confined
# service healthy.
#
# What it proves, from INSIDE the enforcing docker_helper_t domain:
#   * the exact ".admin-token.new" filename transition labels a freshly
#     created staging inode docker_helper_admin_token_t;
#   * the MEASURED enforcing outcome of renaming that token_t inode to an
#     otherwise UNUSED config-dir pathname (the review hypothesis: the
#     filename transition constrains the CREATED type, not the rename
#     destination). GATE SEMANTICS: an ALLOWED rename is an architecture
#     warning — the shipped-policy statement that "arbitrary new config-dir
#     names cannot become writable token objects" would be false for
#     already-created token_t inodes; the stage fails and the release owner
#     must accept the backend limitation before canonical docs change. A
#     DENIED rename is recorded together with its AVC as regression evidence.
#   * existing docker_helper_config_t objects stay immutable: write-open,
#     unlink, rename-away, and overwrite-by-rename-onto of config.json are
#     denied, and an arbitrary NEW config-dir name cannot be created.
#
# The probe (scripts/uat-h6-rename-proof, host-compiled, UAT_H6_PROOF_BIN)
# runs through a systemd transient service carrying the shipped
# SELinuxContext= with its binary relabeled docker_helper_exec_t by the
# operator — the same confinement mechanism the shipped unit uses, no policy
# change involved. The probe never touches admin.token, never relabels config
# state, and cleans up every object it created.
#
# Env inputs:
#   UAT_H6_PROOF_BIN  host-compiled probe binary (required)
set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

fail() { echo "[h6-rename-proof] FAILED: $*" >&2; exit 1; }

PROOF_BIN="${UAT_H6_PROOF_BIN:-/opt/uat-import/h6-rename-proof}"
[ -f "$PROOF_BIN" ] || fail "probe binary not found: $PROOF_BIN"

for cmd in docker-helper systemctl sha256sum stat systemd-run chcon getenforce; do
  command -v "$cmd" >/dev/null 2>&1 || fail "$cmd not found"
done

echo "== preflight =="
[ "$(getenforce)" = "Enforcing" ] || fail "guest is not enforcing (getenforce=$(getenforce))"
systemctl is-active --quiet docker-helper.service || fail "docker-helper.service is not running"
[ -f /etc/docker-helper/config.json ] || fail "config.json missing"
[ -f /etc/docker-helper/admin.token ] || fail "admin.token missing"
if [ -e /etc/docker-helper/.admin-token.new ]; then
  fail "staging pathname already exists before the proof (unexpected lifecycle residue)"
fi

TOKEN_SHA_BEFORE="$(sha256sum /etc/docker-helper/admin.token | awk '{print $1}')"
CONFIG_SHA_BEFORE="$(sha256sum /etc/docker-helper/config.json | awk '{print $1}')"
TOKEN_CTX_BEFORE="$(stat -c %C /etc/docker-helper/admin.token)"
CONFIG_CTX_BEFORE="$(stat -c %C /etc/docker-helper/config.json)"
echo "token: sha=$TOKEN_SHA_BEFORE ctx=$TOKEN_CTX_BEFORE"
echo "config: sha=$CONFIG_SHA_BEFORE ctx=$CONFIG_CTX_BEFORE"

echo "== stage the probe (operator relabel; same mechanism as the shipped unit) =="
cp "$PROOF_BIN" /opt/uat-import/h6-rename-proof-exec
chmod 0755 /opt/uat-import/h6-rename-proof-exec
chcon -t docker_helper_exec_t /opt/uat-import/h6-rename-proof-exec \
  || fail "cannot relabel the probe binary docker_helper_exec_t"
echo "probe label: $(stat -c %C /opt/uat-import/h6-rename-proof-exec)"
RESULT_FILE=/run/docker-helper/h6-rename-proof.json
rm -f "$RESULT_FILE"

echo "== run the probe inside docker_helper_t (enforcing) =="
UNIT_NAME="uat-h6-rename-proof-$$"
systemd-run --quiet --unit="$UNIT_NAME" --wait \
  --property=Type=oneshot \
  --property=SELinuxContext=system_u:system_r:docker_helper_t:s0 \
  --property=StandardOutput=journal \
  --property=StandardError=journal \
  /opt/uat-import/h6-rename-proof-exec "$RESULT_FILE" \
  || fail "probe service did not run cleanly (systemctl show: $(systemctl show -p Result,ExecMainStatus --value "$UNIT_NAME" 2>/dev/null || true))"
[ -f "$RESULT_FILE" ] || fail "probe did not write a result file"
RES="$(cat "$RESULT_FILE")"
echo "$RES"
rm -f "$RESULT_FILE"

json_get() { # <jq-like path> via python3; single reader of the recorded JSON
  printf '%s' "$RES" | python3 -c "
import json,sys
doc=json.load(sys.stdin)
path='$1'.split('.')
cur=doc
for k in path:
    cur=cur[int(k)] if k.lstrip('-').isdigit() else cur[k]
print(cur if not isinstance(cur,bool) else str(cur).lower())
" 2>/dev/null
}

echo "== assert probe identity gates =="
printf '%s' "$RES" | grep -q 'docker_helper_t' \
  || fail "probe result does not report the docker_helper_t context"
[ "$(json_get enforcing)" = "true" ] || fail "probe reports non-enforcing execution"
DOMAIN_TYPE="$(json_get domain | cut -d: -f3)"
[ "$DOMAIN_TYPE" = "docker_helper_t" ] \
  || fail "probe ran as '$DOMAIN_TYPE', expected docker_helper_t"

echo "== assert the exact filename transition (create-side contract) =="
[ "$(json_get steps.0.ok)" = "true" ] \
  || fail "staging creation failed unexpectedly ($(json_get steps.0.errno))"
STAGING_LABEL="$(json_get steps.1.label)"
printf '%s' "$STAGING_LABEL" | grep -q 'docker_helper_admin_token_t' \
  || fail "created staging inode is not docker_helper_admin_token_t (label '$STAGING_LABEL')"
echo "created inode label: $STAGING_LABEL (exact filename transition proven)"

echo "== assert the config immutability negatives =="
# steps: 0 create-staging, 1 staging-label, 2 rename-token-to-unused,
#        [3 rename-back if moved], then the negatives in fixed order.
NEG_START=3
if [ "$(json_get steps.2.ok)" = "true" ]; then
  NEG_START=4
  RENAME_VERDICT="ALLOWED"
else
  RENAME_VERDICT="DENIED ($(json_get steps.2.errno))"
fi
NEG_EXPECT_EACCES=("$NEG_START" "$((NEG_START+1))" "$((NEG_START+2))" "$((NEG_START+3))" "$((NEG_START+4))")
NEG_OPS=("config-write-open" "config-unlink" "config-rename-away" "token-overwrite-config" "config-create-fresh-name")
for i in "${!NEG_OPS[@]}"; do
  IDX="${NEG_EXPECT_EACCES[$i]}"
  OP="$(json_get "steps.$IDX.op")"
  [ "$OP" = "${NEG_OPS[$i]}" ] \
    || fail "record order mismatch at step $IDX: got '$OP', want '${NEG_OPS[$i]}'"
  if [ "$(json_get "steps.$IDX.ok")" != "false" ]; then
    fail "config immutability broken: ${NEG_OPS[$i]} was ALLOWED by enforcing SELinux"
  fi
  if [ "$(json_get "steps.$IDX.errno")" != "EACCES" ]; then
    echo "note: ${NEG_OPS[$i]} denied with $(json_get "steps.$IDX.errno") (expected EACCES; denial class is still a denial)"
  fi
done
echo "config immutability: write-open/unlink/rename-away/overwrite-by-rename/create-fresh all denied"

echo "== measured rename verdict =="
if [ "$RENAME_VERDICT" = "ALLOWED" ]; then
  echo "VERDICT: ALLOWED — an already-created docker_helper_admin_token_t inode can be"
  echo "renamed to an otherwise unused config-dir pathname under enforcing SELinux."
  echo "The exact filename transition constrains the CREATED type, not the rename"
  echo "destination. This contradicts the shipped-policy claim that arbitrary new"
  echo "config-dir names cannot become writable token objects: an ARCHITECTURE"
  echo "WARNING for the release owner (SELinux backend limitation)."
  AVC_RECENT="$(ausearch -m AVC --start recent 2>/dev/null | tail -40 || true)"
  echo "recent AVC window (for the record):"
  printf '%s\n' "$AVC_RECENT" | grep -E 'docker_helper|h6-unused' || true
  sesearch -A -s docker_helper_t -t docker_helper_admin_token_t -c file -p rename 2>/dev/null || true
  sesearch -A -s docker_helper_t -t docker_helper_config_t -c dir -p add_name 2>/dev/null || true
  rm -f /opt/uat-import/h6-rename-proof-exec
  fail "ARCHITECTURE WARNING: SELinux rename destination scope is unrestricted for created token_t inodes (rename to unused pathname ALLOWED)"
fi
echo "VERDICT: DENIED ($(json_get steps.2.errno)) — a created token_t inode cannot be renamed"
echo "to an unused config-dir pathname. Recording the denial AVC as regression evidence:"
AVC_RECENT="$(ausearch -m AVC --start recent 2>/dev/null | tail -60 || true)"
printf '%s\n' "$AVC_RECENT" | grep -E 'h6-unused|docker_helper' | tail -20 || true

echo "== post-proof invariants =="
[ ! -e /etc/docker-helper/.admin-token.new ] || fail "staging residue left behind by the proof"
[ ! -e /etc/docker-helper/h6-unused-name ] || fail "proof pathname left behind"
[ ! -e /etc/docker-helper/h6-fresh-name ] || fail "fresh-name residue left behind"
[ ! -e /etc/docker-helper/h6-config-renamed ] || fail "config rename residue left behind"
[ "$(sha256sum /etc/docker-helper/admin.token | awk '{print $1}')" = "$TOKEN_SHA_BEFORE" ] \
  || fail "admin.token changed by the proof"
[ "$(sha256sum /etc/docker-helper/config.json | awk '{print $1}')" = "$CONFIG_SHA_BEFORE" ] \
  || fail "config.json changed by the proof"
[ "$(stat -c %C /etc/docker-helper/admin.token)" = "$TOKEN_CTX_BEFORE" ] \
  || fail "admin.token label changed by the proof"
[ "$(stat -c %C /etc/docker-helper/config.json)" = "$CONFIG_CTX_BEFORE" ] \
  || fail "config.json label changed by the proof"
rm -f /opt/uat-import/h6-rename-proof-exec

echo "h6 rename-destination proof PASSED (DENIED rename recorded as regression evidence)"
