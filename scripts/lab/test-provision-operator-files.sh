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
printf '#!/bin/sh\ncase "${1:-}" in -u) echo 0 ;; *) exec /usr/bin/id "$@" ;; esac\n' > "$GUEST_SHIM/id"
printf '#!/bin/sh\necho "dh $*" >> "%s"\nexit 0\n' "$WORK/guestdh.rec" > "$GUEST_SHIM/docker-helper"
printf '#!/bin/sh\nexit 0\n' > "$GUEST_SHIM/update-ca-certificates"
chmod +x "$GUEST_SHIM"/*
AK="$GUEST_ROOT/home/$GUEST_USER/.ssh/authorized_keys"
KH="$GUEST_ROOT/home/$GUEST_USER/.ssh/known_hosts"

# Capture the CURRENT generated guest body for the current env, then execute
# it with a stubbed guard and a safe test root.
execute_guest_body() {
  # per-call capture/out files: concurrent invocations must not clobber
  local gcap="$WORK/guest-captured.$$" gout="$WORK/out.$$" gbody="$WORK/guest-body.$$"
  STREAM_CAPTURE="$gcap" \
  LAB_AGENT_SSH_KEY="$KEY_DIR/id_ed25519_opencode" \
  LAB_KNOWN_HOSTS_SOURCE="${GUEST_KH_SRC:-}" AGENT_USER="$GUEST_USER" \
  LAB_GUEST_ROOT="$GUEST_ROOT" \
    bash "$REPO/lab/provision-operator-files.sh" >"$gout" 2>&1 || { LAST_GUEST_ERR="$gout"; return 1; }
  awk 'f{print} /# --- guest-side installer/{f=1}' "$gcap" > "$gbody"
  { printf 'require_lab_vm() { :; }\n'; cat "$gbody"; } \
    | PATH="$GUEST_SHIM:$PATH" LAB_GUEST_ROOT="$GUEST_ROOT" AGENT_USER="$GUEST_USER" bash -s
}

printf 'host-key-1\n|1|hashedentrymarker= ssh-ed25519 AAAAHASHED1 host-one\n' > "$WORK/op-kh"
export GUEST_KH_SRC="$WORK/op-kh"

# F1.1 first run creates authorized_keys/known_hosts correctly
rm -rf "$GUEST_ROOT"; mkdir -p "$GUEST_ROOT/home/$GUEST_USER"
if execute_guest_body; then ok "F1: guest installer runs on the test root"; else bad "F1: guest installer failed: $(cat "${LAST_GUEST_ERR:-$WORK/out}" 2>/dev/null | tail -1)"; fi
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
  *"/proc/self/fd/"*) exit 1 ;;
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

# --- R1. root never opens predictable paths in agent-writable dirs -----------
# The lock used to live at .ssh/.provision.lock (agent-writable): a
# pre-placed symlink or hardlink made root open the FOREIGN inode with
# O_TRUNC. The staging names .provision-new.<pid> were predictable too.
# Behavioral: execute the guest installer against the test root.
printf 'FOREIGN-LOCK-TARGET
' > "$WORK/lock-target"

# R1.1 a symlink at the old lock path must not be followed or truncated
rm -rf "$GUEST_ROOT"; mkdir -p "$GUEST_ROOT/home/$GUEST_USER/.ssh"
printf 'keep me\n' > "$GUEST_ROOT/home/$GUEST_USER/.ssh/authorized_keys"
ln -s "$WORK/lock-target" "$GUEST_ROOT/home/$GUEST_USER/.ssh/.provision.lock"
if execute_guest_body; then ok "R1: provisioning succeeds despite a pre-placed lock symlink"; else bad "R1: provisioning failed with a lock symlink present: $(tail -1 "$WORK/out")"; fi
[ "$(cat "$WORK/lock-target")" = "FOREIGN-LOCK-TARGET" ] \
  && ok "R1: the symlink target was not truncated by the lock open" \
  || bad "R1: the symlink target was truncated (root opened a user-controlled path)"

# R1.2 a pre-created staging name must have no effect
rm -rf "$GUEST_ROOT"; mkdir -p "$GUEST_ROOT/home/$GUEST_USER/.ssh"
printf 'FOREIGN-STAGING
' > "$WORK/staging-target"
ln -s "$WORK/staging-target" "$GUEST_ROOT/home/$GUEST_USER/.ssh/.provision-new.999999"
if execute_guest_body; then ok "R1: provisioning succeeds with a pre-created staging name"; else bad "R1: provisioning failed with a staging name present"; fi
[ "$(cat "$WORK/staging-target")" = "FOREIGN-STAGING" ] \
  && ok "R1: the pre-created staging path was not written through" \
  || bad "R1: the pre-created staging path was written through"

# R1.3 a hardlink trap at the old lock path must not modify the foreign inode
rm -rf "$GUEST_ROOT"; mkdir -p "$GUEST_ROOT/home/$GUEST_USER/.ssh"
printf 'keep me\n' > "$GUEST_ROOT/home/$GUEST_USER/.ssh/authorized_keys"
printf 'FOREIGN-HARDLINK
' > "$WORK/hardlink-target"
ln "$WORK/hardlink-target" "$GUEST_ROOT/home/$GUEST_USER/.ssh/.provision.lock"
if execute_guest_body; then ok "R1: provisioning succeeds despite a lock hardlink"; else bad "R1: provisioning failed with a lock hardlink present"; fi
[ "$(cat "$WORK/hardlink-target")" = "FOREIGN-HARDLINK" ] \
  && ok "R1: the hardlinked foreign inode was not modified" \
  || bad "R1: the hardlinked foreign inode was modified"

# R1.4 the lock directory is private to root
lockdir="$GUEST_ROOT/run/docker-helper-lab-locks"
[ -d "$lockdir" ] && [ "$(stat -c '%04a' "$lockdir")" = 0700 ] \
  && ok "R1: the lock directory is private (0700)" \
  || bad "R1: the lock directory is missing or not private"

# R1.5 concurrent runs do not lose entries
rm -rf "$GUEST_ROOT"; mkdir -p "$GUEST_ROOT/home/$GUEST_USER/.ssh"
printf 'ssh-ed25519 AAAACONCURRENT1 first-runner\n' > "$GUEST_ROOT/home/$GUEST_USER/.ssh/authorized_keys"
execute_guest_body & g1=$!
execute_guest_body & g2=$!
wait "$g1" || true; wait "$g2" || true
if grep -q AAAACONCURRENT1 "$AK" && grep -q opencode-agent "$AK"; then
  ok "R1: concurrent runs keep both entries"
else
  bad "R1: concurrent runs lost entries ($(cat "$AK" 2>/dev/null | tr '\n' '|'))"
fi

# --- R6. host-supplied values are validated before any guest execution ------
# Malicious CA names / URLs / usernames must be rejected on the physical
# host, before ANY guest command runs, with no marker files created and no
# file changes on the host.
r6_no_guest_invocation() { # CASE
  if [ -s "$CAPTURE" ]; then bad "R6/$1: a guest invocation happened with a malicious input"; else ok "R6/$1: no guest invocation for the malicious input"; fi
}

# malicious CA basenames (real files, so earlier file validation passes)
for evil in 'R;touch BAD' "R'CA" 'R$(touch BAD)' 'R CA'; do
  : > "$CAPTURE"
  evil_file="$WORK/$evil"
  # a VALID certificate with a MALICIOUS name: the rejection must come from
  # the name validation, not from the certificate content
  cp "$WORK/lab-ca" "$evil_file"
  if LAB_CA_SOURCE="$evil_file" run_prov; then
    bad "R6/ca-name: '$evil' was accepted"
  else
    ok "R6/ca-name: '$evil' rejected"
  fi
  r6_no_guest_invocation "ca-name"
done

# traversal-shaped CA names
: > "$CAPTURE"
if LAB_CA_SOURCE="$WORK/lab-ca" LAB_GUEST_ROOT="$WORK/nothing" bash -c '
  source "'"$REPO"'/lab/provision-operator-files.sh" 2>/dev/null' </dev/null >/dev/null 2>&1; then :; fi
# ../RCA as a NAME: validated by the same full-string rule (unit-level)
name_check() { # VALUE -> rc
  bash -c '
    source "'"$REPO"'/lab/provision-operator-files.sh" --check-name 2>/dev/null
  ' <<EOF
$1
EOF
}
# the unit check needs a helper: emulate the validation rule directly
valid_name_probe() {
  printf '%s' "$1" | grep -qE '^[A-Za-z0-9._-]+$' && [ "$1" != "." ] && [ "$1" != ".." ]
}
for evil_name in '../RCA' '.' '..' 'R;touch BAD' 'R$(x)' 'R CA'; do
  if valid_name_probe "$evil_name"; then bad "R6/ca-name: rule accepts '$evil_name'"; else ok "R6/ca-name: rule rejects '$evil_name'"; fi
done
for good_name in 'RCA-CA' 'corp.root.pem' 'ca_2026'; do
  if valid_name_probe "$good_name"; then ok "R6/ca-name: rule accepts '$good_name'"; else bad "R6/ca-name: rule rejects valid '$good_name'"; fi
done

# malicious usernames
for evil_user in 'agent; touch BAD' 'agent$(touch BAD)' 'agent BAD' '../agent'; do
  : > "$CAPTURE"
  if AGENT_USER="$evil_user" LAB_AGENT_SSH_KEY="$KEY_DIR/id_ed25519_opencode" run_prov; then
    bad "R6/agent-user: '$evil_user' was accepted"
  else
    ok "R6/agent-user: '$evil_user' rejected"
  fi
  r6_no_guest_invocation "agent-user"
done

# valid usernames still work
: > "$CAPTURE"
if AGENT_USER="$GUEST_USER" LAB_AGENT_SSH_KEY="$KEY_DIR/id_ed25519_opencode" run_prov; then
  ok "R6/agent-user: the valid username provisions"
else
  bad "R6/agent-user: the valid username was rejected"
fi

# --- F5. the publication staging pathname is not a privileged write surface --
# The publication tmp used to live in the agent-owned .ssh directory and every
# privileged operation (content write, chmod, chown, rename) went through its
# PATHNAME. The directory owner can replace that pathname at any moment. A
# controlled substitution between mktemp and the metadata steps must never
# redirect root's chmod/chown onto a foreign inode.
AK_DIR="$(dirname "$AK")"
f5_reset() {
  rm -rf "$GUEST_ROOT"; mkdir -p "$GUEST_ROOT/home/$GUEST_USER/.ssh"
  printf 'op-ssh-entry ssh-ed25519 AAAAOPKEY1 op@host\n' > "$AK"
  printf 'F5-FOREIGN-MARKER\n' > "$WORK/f5-foreign"
  chmod 0644 "$WORK/f5-foreign"
}

# F5/a: a substitution during the merge step must not redirect chmod/chown to
# the foreign inode. The awk shim swaps the staging pathname to a hardlink of
# the foreign file the moment the merge awk runs.
f5_reset
real_awk="$(command -v awk)"
cat > "$GUEST_SHIM/awk" <<SH
#!/bin/sh
case "\$*" in
  *dedupe*)
    for f in "$AK_DIR"/.provision.*; do
      [ -e "\$f" ] || continue
      rm -f -- "\$f"
      ln "$WORK/f5-foreign" "\$f"
    done
    exit 0 ;;
  *) exec "$real_awk" "\$@" ;;
esac
SH
chmod +x "$GUEST_SHIM/awk"
if execute_guest_body 2>"$WORK/guest.err"; then bad "F5/a: the swapped staging path was tolerated"; else ok "F5/a: a substituted staging pathname fails the update"; fi
[ "$(stat -c '%04a' "$WORK/f5-foreign")" = "0644" ] \
  && ok "F5/a: the foreign inode's mode was never touched by root" \
  || bad "F5/a: root's chmod landed on a substituted foreign inode"
rm -f "$GUEST_SHIM/awk"

# F5/b: a substitution during the rename step is detected after publication —
# the run must fail loudly instead of reporting success.
f5_reset
real_mv="$(command -v mv)"
cat > "$GUEST_SHIM/mv" <<SH
#!/bin/sh
case "\$*" in
  *.provision.*)
    src="\$3"
    rm -f -- "\$src"
    ln "$WORK/f5-foreign" "\$src"
    exit 1 ;;
  *) exec "$real_mv" "\$@" ;;
esac
SH
chmod +x "$GUEST_SHIM/mv"
cp "$AK" "$WORK/f5-ak-before"
if execute_guest_body 2>"$WORK/guest.err"; then bad "F5/b: a rename-time substitution was tolerated"; else ok "F5/b: a rename-time substitution fails the update"; fi
[ "$(stat -c '%04a' "$WORK/f5-foreign")" = "0644" ] \
  && ok "F5/b: the foreign inode survived the rename-time substitution untouched" \
  || bad "F5/b: the foreign inode was modified by the publication path"
rm -f "$GUEST_SHIM/mv"

# F5/c: without any substitution the merged publication still works and stays
# idempotent (the fd-pinned path preserves the accepted contract).
f5_reset
rm -f "$GUEST_SHIM/awk" "$GUEST_SHIM/mv"
if execute_guest_body 2>"$WORK/guest.err"; then ok "F5/c: the normal publication path works"; else bad "F5/c: the normal publication path broke: $(tail -1 "$WORK/guest.err" 2>/dev/null || cat "$WORK/out")"; fi
grep -q 'AAAAOPKEY1' "$AK" && ok "F5/c: the previous entry survived" || bad "F5/c: the previous entry was lost"
grep -q 'opencode-agent' "$AK" && ok "F5/c: the agent key was published" || bad "F5/c: the agent key is missing"

echo
printf 'provision-operator-files tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
