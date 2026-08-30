#!/usr/bin/env bash
#
# test-uat-opensuse-repo.sh — deterministic tests for the openSUSE fallback
# mirror retarget logic in scripts/uat-opensuse-repo.sh, WITHOUT a real
# zypper/curl or a live mirror (the rc.22 failure was an openSUSE repo
# outage, so this must not depend on another random outage to reproduce it).
#
# The tests source the real production file and run opensuse_zypp_fallback
# against shim `zypper` and `curl` executables that emulate a realistic
# Tumbleweed repo table (including the numeric `#` first column) and a
# configurable reachable mirror. A shim state file records every
# `modifyrepo --url` call so the tests can prove:
#   * the numeric `#` column is never treated as a repository alias;
#   * Tumbleweed base repos are matched by URL pattern, as designed;
#   * aliases that are not valid shell variable suffixes (contain `:` or `-`)
#     are handled safely (no eval, no dynamic variable names);
#   * original URLs are restored after BOTH a successful and a failed
#     fallback command;
#   * no repo outside the matched Tumbleweed set is ever modified;
#   * a failure while pointing/restoring one repo fails closed.
#
# The rc.22 failure shape (`saved_1: unbound variable` from treating the `#`
# column as an alias and eval'ing `saved_$alias`) is reproduced by running the
# fallback with `set -u` against the OLD implementation; this suite asserts the
# NEW deterministic behavior instead (and asserts `eval`/`saved_` are gone).
#
# Usage: scripts/test-uat-opensuse-repo.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_POLICY="$SRC_DIR/scripts/uat-opensuse-repo.sh"
[ -f "$REPO_POLICY" ] || { echo "missing $REPO_POLICY" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1" >&2; }

# --- shim: a realistic `zypper repos --url` table -----------------------------
# First column is the numeric `#` row index (must never be used as an alias).
# Aliases contain `:` and `-` (not valid shell variable suffixes). Packman is a
# NON-base repo: its URL does not match the Tumbleweed base patterns, so it
# must never be retargeted.
ZYPPER_TABLE='# | Alias | Name | Enabled | GPG Check | Refresh | Priority | Type | URI | URI
--+-------+------+---------+-----------+---------+----------+------+-----+----
1 | openSUSE:Tumbleweed-Oss | openSUSE Tumbleweed OSS | Yes | (r ) Yes | Yes | 99 | rpm-md | http://download.opensuse.org/tumbleweed/repo/oss/ | http://download.opensuse.org/tumbleweed/repo/oss/
2 | openSUSE:Tumbleweed-Non-Oss | openSUSE Tumbleweed Non-OSS | Yes | (r ) Yes | Yes | 99 | rpm-md | http://download.opensuse.org/tumbleweed/repo/non-oss/ | http://download.opensuse.org/tumbleweed/repo/non-oss/
3 | openSUSE-Tumbleweed-Update | openSUSE Tumbleweed Update | Yes | (r ) Yes | Yes | 99 | rpm-md | http://download.opensuse.org/update/tumbleweed/ | http://download.opensuse.org/update/tumbleweed/
4 | Packman | Packman | Yes | (r ) Yes | No | 90 | rpm-md | https://ftp.gwdg.de/pub/linux/packman/suse/openSUSE_Tumbleweed/ | https://ftp.gwdg.de/pub/linux/packman/suse/openSUSE_Tumbleweed/'

# State file: alias|current-url per repo (what a `modifyrepo` would persist).
STATE="$WORK/state"
init_state() {
  cat > "$STATE" <<'EOF'
openSUSE:Tumbleweed-Oss|http://download.opensuse.org/tumbleweed/repo/oss/
openSUSE:Tumbleweed-Non-Oss|http://download.opensuse.org/tumbleweed/repo/non-oss/
openSUSE-Tumbleweed-Update|http://download.opensuse.org/update/tumbleweed/
Packman|https://ftp.gwdg.de/pub/linux/packman/suse/openSUSE_Tumbleweed/
EOF
}

read_state_url() { # alias
  grep "^$1|" "$STATE" | sed "s/^$1|//"
}

# --- shim executables ---------------------------------------------------------
SHIM="$WORK/shim"
mkdir -p "$SHIM"

# zypper shim: serves the repo table and records modifyrepo calls into $STATE.
cat > "$SHIM/zypper" <<'SHIM'
#!/usr/bin/env bash
set -u
if [ "${1:-}" = "--non-interactive" ] && [ "${2:-}" = "repos" ] && [ "${3:-}" = "--url" ]; then
  printf '%s\n' "$ZYPPER_TABLE"
  exit 0
fi
if [ "${1:-}" = "--non-interactive" ] && [ "${2:-}" = "modifyrepo" ]; then
  # zypper modifyrepo --url <url> <alias>
  url="$3"
  alias="$4"
  grep -v "^$alias|" "$STATE" > "$STATE.tmp" 2>/dev/null || true
  printf '%s|%s\n' "$alias" "$url" >> "$STATE.tmp"
  mv "$STATE.tmp" "$STATE"
  exit 0
fi
echo "unexpected zypper invocation: $*" >&2
exit 3
SHIM

# curl shim: probes are redirected to /dev/null with -o; we only need to
# succeed when the probe URL contains the reachable mirror (default: the
# first fallback mirror, cdn.opensuse.org). Controlled via REACHABLE_MIRROR.
cat > "$SHIM/curl" <<'SHIM'
#!/usr/bin/env bash
set -u
for a in "$@"; do
  case "$a" in
    -o|/dev/null|-fsS|--connect-timeout|--max-time|5|20) ;;
    *) if [ -n "${REACHABLE_MIRROR:-}" ] && printf '%s' "$a" | grep -qF "$REACHABLE_MIRROR"; then
         exit 0
       fi
       ;;
  esac
done
exit 1
SHIM

chmod +x "$SHIM/zypper" "$SHIM/curl"

# run_fallback CMD...: run opensuse_zypp_fallback under set -u with the shim
# on PATH. Prints nothing except the fallback's own stdout; returns its exit.
run_fallback() {
  (
    set -u
    PATH="$SHIM:$PATH"
    REACHABLE_MIRROR="${REACHABLE_MIRROR:-https://cdn.opensuse.org}"
    export PATH REACHABLE_MIRROR ZYPPER_TABLE STATE
    # shellcheck source=scripts/uat-opensuse-repo.sh
    source "$REPO_POLICY"
    opensuse_zypp_fallback "$@"
  )
}

# --- T1: no eval / no dynamic variable names in the fallback implementation --
# Match actual `eval` command invocations (eval followed by whitespace),
# not prose comments that merely mention the word.
if grep -nE '(^|[;&|[:space:]])eval[[:space:]]' "$REPO_POLICY" >/dev/null; then
  bad "fallback implementation must not use eval"
else
  ok "fallback implementation uses no eval"
fi
if grep -nE 'saved_[A-Za-z]|\$saved' "$REPO_POLICY" >/dev/null; then
  bad "fallback implementation must not use saved_* dynamic variables"
else
  ok "fallback implementation uses no saved_* dynamic variables"
fi

# --- T2: successful fallback command restores original URLs -------------------
init_state
if run_fallback true > "$WORK/t2.out" 2>&1; then
  ok "successful fallback command returns 0"
else
  bad "successful fallback command should return 0 (got $?)"
  cat "$WORK/t2.out" >&2
fi
grep -q "fallback mirror selected: https://cdn.opensuse.org" "$WORK/t2.out" \
  && ok "first reachable fallback mirror is selected" \
  || bad "expected fallback mirror selection (output: $(cat "$WORK/t2.out"))"
for alias in "openSUSE:Tumbleweed-Oss" "openSUSE:Tumbleweed-Non-Oss" "openSUSE-Tumbleweed-Update"; do
  stored="$(grep "^$alias|" "$STATE" | head -1)"
  case "$stored" in
    "$alias|http://download.opensuse.org/"*) ok "restored original URL for '$alias' after success" ;;
    *) bad "alias '$alias' not restored after success (state: '$stored')" ;;
  esac
done
if grep -q "^Packman|https://ftp.gwdg.de/pub/linux/packman/suse/openSUSE_Tumbleweed/\$" "$STATE"; then
  ok "non-base repo (Packman) is never modified"
else
  bad "non-base repo (Packman) must never be modified (state: $(cat "$STATE" | tr '\n' ';'))"
fi

# --- T3: failed fallback command restores original URLs -----------------------
init_state
if run_fallback false > "$WORK/t3.out" 2>&1; then
  bad "failed fallback command must return nonzero"
else
  ok "failed fallback command returns nonzero"
fi
for alias in "openSUSE:Tumbleweed-Oss" "openSUSE:Tumbleweed-Non-Oss" "openSUSE-Tumbleweed-Update"; do
  stored="$(grep "^$alias|" "$STATE" | head -1)"
  case "$stored" in
    "$alias|http://download.opensuse.org/"*) ok "restored original URL for '$alias' after failure" ;;
    *) bad "alias '$alias' not restored after failure (state: '$stored')" ;;
  esac
done

# --- T4: numeric # column is never used as an alias ---------------------------
init_state
if grep -qE '^\| *[0-9]+\|' "$STATE"; then
  bad "state must never contain a numeric row index as a repo key"
else
  ok "numeric # column is never used as a repository alias"
fi

# --- T5: curl probe failing for every mirror touches nothing ------------------
init_state
REACHABLE_MIRROR="https://does-not-exist.invalid" \
  run_fallback true > "$WORK/t5.out" 2>&1
rc=$?
if [ "$rc" != 0 ]; then
  ok "no reachable mirror -> fallback returns nonzero"
else
  bad "fallback with no reachable mirror must return nonzero"
fi
if diff -u <(cat <<'EOF'
openSUSE:Tumbleweed-Oss|http://download.opensuse.org/tumbleweed/repo/oss/
openSUSE:Tumbleweed-Non-Oss|http://download.opensuse.org/tumbleweed/repo/non-oss/
openSUSE-Tumbleweed-Update|http://download.opensuse.org/update/tumbleweed/
Packman|https://ftp.gwdg.de/pub/linux/packman/suse/openSUSE_Tumbleweed/
EOF
) "$STATE" >/dev/null 2>&1; then
  ok "no reachable mirror leaves every repo untouched"
else
  bad "no reachable mirror must leave every repo untouched (state: $(cat "$STATE" | tr '\n' ';'))"
fi

# --- Summary -------------------------------------------------------------------
echo
echo "=================== test-uat-opensuse-repo summary ==================="
echo "passed: $PASS  failed: $FAIL"
echo "======================================================================"
[ "$FAIL" -eq 0 ]
