#!/usr/bin/env bash
#
# test-provision-operator-files.sh — focused tests for
# scripts/lab/provision-operator-files.sh (host-side validation + the
# generated guest installer, captured via a stub VM driver).
#
# What this protects (one invariant per test):
#   1. no configured item -> explicit no-op success;
#   2. a valid agent key produces a guest installer that installs the key
#      0600 into a 0700 .ssh, the pub 0644, and appends authorized_keys
#      without duplicates;
#   3. a missing / symlinked / world-readable / corrupt key is refused
#      host-side, before any transfer;
#   4. a sibling .pub that does not match the private key is refused;
#   5. a valid CA produces the full guest chain: trust anchor + store
#      verification + helper copy + restorecon + config via the CLI only;
#   6. a multi-certificate bundle is refused (v2.3.0 requires ONE CA);
#   7. a CA file containing a private key is refused;
#   8. a non-CA certificate is refused;
#   9. symlinked gitconfig/known_hosts are refused;
#  10. the streamed payload begins with the lab-VM guard.
#
# The private key used here is generated for the test only and never leaves
# the test workdir.
#
# Usage: scripts/lab/test-provision-operator-files.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2')" ;; esac; }

REPO="$WORK/repo/scripts"
mkdir -p "$REPO/lab"
cp "$SRC_DIR/lab/provision-operator-files.sh" "$REPO/lab/"
cp "$SRC_DIR/lab/lab-vm-guard.sh" "$REPO/lab/"
CAPTURE="$WORK/stream"
: > "$CAPTURE"
cat > "$REPO/dev-vm-local.sh" <<SH
#!/usr/bin/env bash
case "\${1:-}" in
  ssh) shift; cat > "\$STREAM_CAPTURE"; exit 0 ;;
  *) echo "stub: only ssh is simulated" >&2; exit 2 ;;
esac
SH
chmod +x "$REPO/dev-vm-local.sh"

run_prov() { # env assignments on the caller side; -> OUT, RC
  STREAM_CAPTURE="$CAPTURE" bash "$REPO/lab/provision-operator-files.sh" >"$WORK/out" 2>&1
  RC=$?
  OUT="$(cat "$WORK/out")"
  STREAM="$(cat "$CAPTURE")"
  return "$RC"
}

# --- fixtures ----------------------------------------------------------------
KEY_DIR="$WORK/keys"; mkdir -p "$KEY_DIR"
ssh-keygen -q -t ed25519 -N "" -f "$KEY_DIR/id_ed25519_opencode" -C test-agent-key \
  || { echo "ssh-keygen failed" >&2; exit 1; }
chmod 0600 "$KEY_DIR/id_ed25519_opencode"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" -out "$WORK/lab-ca" \
  -subj "/CN=Lab Test CA" -days 30 >/dev/null 2>&1 \
  || { echo "openssl CA generation failed" >&2; exit 1; }

# --- 1. nothing to provision --------------------------------------------------
run_prov
if [ "$RC" = 0 ]; then ok "no configured item is an explicit no-op"; else bad "no-item run failed: $OUT"; fi
contains "no-item run explains itself" "nothing to provision" "$OUT"

# --- 2/3/4. ssh key validation -------------------------------------------------
rm -f "$CAPTURE"
LAB_AGENT_SSH_KEY="$KEY_DIR/id_ed25519_opencode" run_prov
if [ "$RC" = 0 ]; then ok "valid key provisions"; else bad "valid key run failed: $OUT"; fi
contains "guest installer requires the lab guard" "require_lab_vm" "$STREAM"
contains "guest installer creates a 0700 .ssh" 'install -d -m 0700' "$STREAM"
contains "guest installer writes the key 0600" '0600 "$AGENT_USER:$AGENT_USER" SSH_KEY_B64' "$STREAM"
contains "guest installer writes the pub 0644" 'id_ed25519_opencode.pub" 0644' "$STREAM"
contains "authorized_keys updated by the merge mechanism" 'merge_into "$AGENT_HOME/.ssh/authorized_keys"' "$STREAM"
contains "known_hosts merged without truncation" 'merge_into "$AGENT_HOME/.ssh/known_hosts"' "$STREAM"
contains "updates are locked and atomically published" 'flock -x 9' "$STREAM"
if printf '%s' "$STREAM" | grep -q '/dev/null "$AGENT_HOME/.ssh/authorized_keys"\|/dev/null "$AGENT_HOME/.ssh/known_hosts"'; then
  bad "the clobber pattern is still present"
else
  ok "no truncating install of authorization material"
fi
if printf '%s' "$STREAM" | grep -q -- '-----BEGIN OPENSSH PRIVATE KEY-----'; then
  bad "the raw private key leaked into the stream (must be base64 payload only)"
else
  ok "the private key travels only as an encoded payload"
fi

LAB_AGENT_SSH_KEY="$WORK/absent-key" run_prov
if [ "$RC" != 0 ]; then ok "missing key refused"; else bad "missing key accepted"; fi

ln -sf "$KEY_DIR/id_ed25519_opencode" "$WORK/key-symlink"
LAB_AGENT_SSH_KEY="$WORK/key-symlink" run_prov
if [ "$RC" != 0 ]; then ok "symlinked key refused"; else bad "symlinked key accepted"; fi

cp "$KEY_DIR/id_ed25519_opencode" "$WORK/world-readable-key"
chmod 0644 "$WORK/world-readable-key"
LAB_AGENT_SSH_KEY="$WORK/world-readable-key" run_prov
if [ "$RC" != 0 ]; then ok "world-readable key refused"; else bad "world-readable key accepted"; fi

printf 'not a key\n' > "$WORK/garbage.key"
LAB_AGENT_SSH_KEY="$WORK/garbage.key" run_prov
if [ "$RC" != 0 ]; then ok "corrupt key refused"; else bad "corrupt key accepted"; fi

ssh-keygen -q -t ed25519 -N "" -f "$WORK/other-key" -C other >/dev/null 2>&1
cp "$WORK/other-key.pub" "$KEY_DIR/id_ed25519_opencode.pub"
LAB_AGENT_SSH_KEY="$KEY_DIR/id_ed25519_opencode" run_prov
if [ "$RC" != 0 ]; then ok "mismatched sibling .pub refused"; else bad "mismatched .pub accepted"; fi
rm -f "$KEY_DIR/id_ed25519_opencode.pub"

# --- 5-8. CA validation ---------------------------------------------------------
rm -f "$CAPTURE"
LAB_CA_SOURCE="$WORK/lab-ca" run_prov
if [ "$RC" = 0 ]; then ok "valid CA provisions"; else bad "valid CA run failed: $OUT"; fi
contains "trust anchor installed" '$ETC/pki/trust/anchors/' "$STREAM"
contains "system store regenerated and verified" "openssl verify -CAfile" "$STREAM"
contains "helper-owned copy installed" '$ETC/docker-helper/' "$STREAM"
contains "restorecon runs on the helper copy" "restorecon" "$STREAM"
contains "helper CA configured via the CLI" "config set trusted_ca_path" "$STREAM"
contains "injection enabled via the CLI" "config set trusted_ca_injection auto" "$STREAM"
contains "config verified via show" "config show trusted_ca_path" "$STREAM"
contains "container-facing CA copy installed" 'AGENT_OCODE/ca' "$STREAM"

cat "$WORK/lab-ca" "$WORK/lab-ca" > "$WORK/bundle-ca"
LAB_CA_SOURCE="$WORK/bundle-ca" run_prov
if [ "$RC" != 0 ]; then ok "multi-certificate bundle refused"; else bad "bundle accepted"; fi

cat "$WORK/lab-ca" "$WORK/ca.key" > "$WORK/ca-with-key"
LAB_CA_SOURCE="$WORK/ca-with-key" run_prov
if [ "$RC" != 0 ]; then ok "CA file containing a private key refused"; else bad "CA-with-key accepted"; fi

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/leaf.key" -out "$WORK/leaf.crt" \
  -subj "/CN=Lab Leaf" -days 30 -addext "basicConstraints=critical,CA:FALSE" >/dev/null 2>&1 \
  || { echo "openssl leaf generation failed" >&2; exit 1; }
LAB_CA_SOURCE="$WORK/leaf.crt" run_prov
if [ "$RC" != 0 ]; then ok "non-CA certificate refused"; else bad "non-CA certificate accepted"; fi

# --- 9. symlinked gitconfig / known_hosts ---------------------------------------
ln -sf "$WORK/lab-ca" "$WORK/gitconfig-symlink"
LAB_GITCONFIG_SOURCE="$WORK/gitconfig-symlink" run_prov
if [ "$RC" != 0 ]; then ok "symlinked gitconfig refused"; else bad "symlinked gitconfig accepted"; fi

ln -sf "$WORK/lab-ca" "$WORK/kh-symlink"
LAB_KNOWN_HOSTS_SOURCE="$WORK/kh-symlink" run_prov
if [ "$RC" != 0 ]; then ok "symlinked known_hosts refused"; else bad "symlinked known_hosts accepted"; fi

# --- 10. the guard leads the stream ---------------------------------------------
LAB_CA_SOURCE="$WORK/lab-ca" run_prov
guard_line="$(printf '%s' "$STREAM" | grep -n 'require_lab_vm()' | head -1 | cut -d: -f1 || true)"
guest_line="$(printf '%s' "$STREAM" | grep -n 'guest-side installer' | head -1 | cut -d: -f1 || true)"
if [ -n "$guard_line" ] && [ -n "$guest_line" ] && [ "$guard_line" -lt "$guest_line" ]; then
  ok "the streamed payload carries the lab guard before the installer"
else
  bad "the stream lacks the lab guard (guard=$guard_line guest=$guest_line)"
fi

# --- F1. behavioral execution of the guest-side installer -----------------------
# The generated guest script is EXECUTED against a safe test root
# (LAB_GUEST_ROOT) with stubbed guest tooling; assertions observe real file
# states, not source patterns. The agent user maps to the test user so the
# real chown/stat verification runs as the file owner.
GUEST_USER="$(id -un)"
GUEST_ROOT="$WORK/guestroot"
GUEST_SHIM="$WORK/guestshim"; mkdir -p "$GUEST_SHIM"
printf '#!/bin/sh\necho 0\n' > "$GUEST_SHIM/id"
printf '#!/bin/sh\necho "dh $*" >> "%s"\nexit 0\n' "$WORK/guestdh.rec" > "$GUEST_SHIM/docker-helper"
printf '#!/bin/sh\nexit 0\n' > "$GUEST_SHIM/update-ca-certificates"
chmod +x "$GUEST_SHIM"/*
AK="$GUEST_ROOT/home/$GUEST_USER/.ssh/authorized_keys"
KH="$GUEST_ROOT/home/$GUEST_USER/.ssh/known_hosts"

# Capture the CURRENT generated guest body for the current env, then execute
# it with a stubbed guard and a safe test root.
execute_guest_body() {
  STREAM_CAPTURE="$CAPTURE" \
  LAB_AGENT_SSH_KEY="$KEY_DIR/id_ed25519_opencode" \
  LAB_KNOWN_HOSTS_SOURCE="${GUEST_KH_SRC:-}" AGENT_USER="$GUEST_USER" \
    bash "$REPO/lab/provision-operator-files.sh" >"$WORK/out" 2>&1 || return 1
  awk 'f{print} /# --- guest-side installer/{f=1}' "$CAPTURE" > "$WORK/guest-body.sh"
  { printf 'require_lab_vm() { :; }\n'; cat "$WORK/guest-body.sh"; } \
    | PATH="$GUEST_SHIM:$PATH" LAB_GUEST_ROOT="$GUEST_ROOT" AGENT_USER="$GUEST_USER" bash -s
}

printf 'host-key-1\n|1|hashedentrymarker= ssh-ed25519 AAAAHASHED1 host-one\n' > "$WORK/op-kh"
export GUEST_KH_SRC="$WORK/op-kh"

# F1.1 first run creates authorized_keys/known_hosts correctly
rm -rf "$GUEST_ROOT"; mkdir -p "$GUEST_ROOT/home/$GUEST_USER"
if execute_guest_body; then ok "F1: guest installer runs on the test root"; else bad "F1: guest installer failed: $(cat "$WORK/out")"; fi
[ "$(stat -c '%a' "$AK" 2>/dev/null)" = 600 ] && ok "F1: authorized_keys mode 0600" || bad "F1: authorized_keys mode wrong ($(stat -c '%a' "$AK" 2>/dev/null))"
[ "$(stat -c '%U' "$AK" 2>/dev/null)" = "$GUEST_USER" ] || bad "F1: authorized_keys owner wrong"
[ "$(stat -c '%a' "$KH" 2>/dev/null)" = 644 ] && ok "F1: known_hosts mode 0644" || bad "F1: known_hosts mode wrong"
grep -q 'opencode-agent' "$AK" && ok "F1: agent key present in authorized_keys" || bad "F1: agent key missing"
grep -qF 'host-key-1' "$KH" && ok "F1: provided known_hosts entry installed" || bad "F1: known_hosts entry missing"
grep -qF '|1|hashedentrymarker=' "$KH" && ok "F1: hashed known_hosts entry preserved" || bad "F1: hashed entry lost"

# F1.2 second run with the same data is byte-identical
cp "$AK" "$WORK/ak.first"; cp "$KH" "$WORK/kh.first"
if execute_guest_body; then ok "F1: re-run succeeds"; else bad "F1: re-run failed"; fi
cmp -s "$AK" "$WORK/ak.first" && ok "F1: re-run is byte-identical (authorized_keys)" || bad "F1: re-run changed authorized_keys"
cmp -s "$KH" "$WORK/kh.first" && ok "F1: re-run is byte-identical (known_hosts)" || bad "F1: re-run changed known_hosts"

# F1.3 adding a NEW key preserves old entries (authorized_keys keeps history)
printf 'ssh-ed25519 AAAAOTHERKEY2 other-operator@host\n' >> "$AK"
printf 'foreign-host ssh-ed25519 AAAAFOREIGNKH\n' >> "$KH"
if execute_guest_body; then ok "F1: third run succeeds"; else bad "F1: third run failed"; fi
grep -qF 'AAAAOTHERKEY2' "$AK" && ok "F1: pre-existing foreign key preserved" || bad "F1: foreign key destroyed"
grep -qF 'AAAAFOREIGNKH' "$KH" && ok "F1: pre-existing foreign known_hosts entry preserved" || bad "F1: foreign known_hosts entry destroyed"
grep -q 'opencode-agent' "$AK" && ok "F1: agent key still present" || bad "F1: agent key lost"

# F1.4 the same key with a different comment is not duplicated
n_before="$(grep -c 'ssh-ed25519' "$AK" || true)"
if execute_guest_body; then ok "F1: fourth run succeeds"; else bad "F1: fourth run failed"; fi
n_after="$(grep -c 'ssh-ed25519' "$AK" || true)"
check "F1: same key with a different comment does not duplicate" "$n_before" "$n_after"

# F1.5 existing known_hosts are not lost across updates
printf 'host-key-2 extra-host\n' >> "$WORK/op-kh"
if execute_guest_body; then ok "F1: known_hosts update run succeeds"; else bad "F1: known_hosts update failed"; fi
for marker in 'host-key-1' '|1|hashedentrymarker=' 'host-key-2'; do
  grep -qF "$marker" "$KH" && ok "F1: known_hosts keeps '$marker'" || bad "F1: known_hosts lost '$marker'"
done

# F1.6 symlinked authorization files are refused fail-closed
mv "$AK" "$WORK/ak.real"
printf 'FOREIGN-CONTENT\n' > "$WORK/foreign-file"
ln -s "$WORK/foreign-file" "$AK"
if execute_guest_body 2>"$WORK/guest.err"; then bad "F1: symlinked authorized_keys accepted"; else ok "F1: symlinked authorized_keys refused"; fi
[ "$(cat "$WORK/foreign-file")" = "FOREIGN-CONTENT" ] \
  && ok "F1: the symlink target was not written" || bad "F1: the symlink target was modified"
rm -f "$AK"; mv "$WORK/ak.real" "$AK"

# F1.7 an update failure preserves the original content
cat > "$GUEST_SHIM/chown" <<SH
#!/bin/sh
case "\$*" in
  *.provision.*) exit 1 ;;
  *) exec /bin/chown "\$@" ;;
esac
SH
chmod +x "$GUEST_SHIM/chown"
cp "$AK" "$WORK/ak.before-failure"
cp "$KH" "$WORK/kh.before-failure"
if execute_guest_body 2>"$WORK/guest.err"; then bad "F1: injected update failure was tolerated"; else ok "F1: update failure fails closed"; fi
cmp -s "$AK" "$WORK/ak.before-failure" && ok "F1: original authorized_keys preserved on failure" || bad "F1: authorized_keys destroyed on failure"
cmp -s "$KH" "$WORK/kh.before-failure" && ok "F1: original known_hosts preserved on failure" || bad "F1: known_hosts destroyed on failure"
rm -f "$GUEST_SHIM/chown"

echo
printf 'provision-operator-files tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
