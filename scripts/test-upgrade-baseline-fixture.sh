#!/usr/bin/env bash
#
# test-upgrade-baseline-fixture.sh — deterministic tests for the recovery /
# availability contract of scripts/uat-upgrade-baseline-fixture.sh, using only
# local files and a curl shim (no real network, no v2.0.0 bytes, no live
# GitHub Release dependency).
#
# The tests source the real production fixture and exercise its actual
# recovery logic:
#
#   * upgrade_baseline_verify — strict exact-byte check (the SHA is always the
#     authority);
#   * upgrade_baseline_source_from — local PATH source: copy to a temp file
#     adjacent to DEST, verify the TEMP bytes, then atomically rename; the
#     caller-owned source is NEVER deleted/modified; SRC == DEST is verified in
#     place;
#   * upgrade_baseline_fetch_url — download to temp + verify + atomic rename,
#     no partial download left behind;
#   * upgrade_baseline_fetch_deb / upgrade_baseline_fetch_rpm — deterministic
#     precedence (PATH -> URL -> canonical) and FAIL-CLOSED override behavior:
#     an explicit bad/unavailable override never silently falls back.
#
# A curl shim substitutes ONLY the external download (a legitimate seam); all
# verification/resolution/precedence logic is the production fixture's own. The
# pinned identity wiring (exact v2.0.0 DEB/RPM SHA-256s and single-owner
# invariants) is covered by the Go packaging tests.
#
# Usage: scripts/test-upgrade-baseline-fixture.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE="$SCRIPT_DIR/uat-upgrade-baseline-fixture.sh"
[ -f "$FIXTURE" ] || { echo "missing $FIXTURE" >&2; exit 1; }

WORK="$(mktemp -d)"
SHIM="$WORK/shim"
mkdir -p "$SHIM"
CALL_LOG="$WORK/curl-calls"
: > "$CALL_LOG"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1" >&2; }

# Synthetic "exact baseline" bytes + their SHA. The production helper functions
# take the SHA as a parameter, so the resolution logic can be exercised with
# these synthetic bytes; the pinned identity wiring is tested separately.
printf 'exact upgrade-baseline recovery test bytes\n' > "$WORK/exact.bin"
EXACT_SHA="$(sha256sum "$WORK/exact.bin" | awk '{print $1}')"
WRONG_SHA="$(printf 'wrong' | sha256sum | awk '{print $1}')"

# curl shim: emulates `curl -fsSL -o FILE URL`. Serves GOOD_URL (exact bytes),
# BAD_URL (wrong bytes) and FAIL_URL (unreachable). Every call is logged to
# $CALL_LOG so precedence / no-fallback can be proven.
cat > "$SHIM/curl" <<'SHIM'
#!/usr/bin/env bash
set -u
out=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -f|-s|-S|-L) shift ;;
    *) url="$1"; shift ;;
  esac
done
[ -n "$out" ] && [ -n "$url" ] || exit 2
printf '%s\n' "$url" >> "$CALL_LOG"
case "$url" in
  "$GOOD_URL") cp "$GOOD_FILE" "$out" ;;
  "$BAD_URL")  printf 'wrong recovery bytes\n' > "$out" ;;
  *) exit 1 ;;
esac
SHIM
chmod +x "$SHIM/curl"

# run_fixture_fn FN ARG... — source the production fixture and run FN, with the
# curl shim and a supplied override environment. Preserves the caller env.
run_fixture_fn() {
  local fn="$1"; shift
  PATH="$SHIM:$PATH"
  export PATH CALL_LOG GOOD_URL BAD_URL GOOD_FILE
  # shellcheck source=scripts/uat-upgrade-baseline-fixture.sh
  source "$FIXTURE"
  "$fn" "$@"
}

# --- T1: upgrade_baseline_verify (SHA is the authority) -----------------------
if run_fixture_fn upgrade_baseline_verify "$WORK/exact.bin" "$EXACT_SHA"; then
  ok "verify accepts exact bytes"
else
  bad "verify rejected exact bytes"
fi
if run_fixture_fn upgrade_baseline_verify "$WORK/exact.bin" "$WRONG_SHA"; then
  bad "verify accepted wrong sha"
else
  ok "verify rejects wrong sha"
fi

# --- T2: local PATH source — exact baseline accepted --------------------------
if run_fixture_fn upgrade_baseline_source_from "$WORK/exact.bin" "$EXACT_SHA" "$WORK/dest.bin" >/dev/null; then
  if [ -f "$WORK/dest.bin" ] && cmp -s "$WORK/exact.bin" "$WORK/dest.bin"; then
    ok "local exact baseline copied after verification"
  else
    bad "local exact baseline copy missing or byte-mismatched"
  fi
else
  bad "local exact baseline rejected"
fi

# --- T2b: local PATH source — SRC == DEST verified in place, never removed ----
cp "$WORK/exact.bin" "$WORK/same.bin"
SAME_BEFORE="$(sha256sum "$WORK/same.bin" | awk '{print $1}')"
if run_fixture_fn upgrade_baseline_source_from "$WORK/same.bin" "$EXACT_SHA" "$WORK/same.bin" >/dev/null; then
  if [ -f "$WORK/same.bin" ] \
      && [ "$(sha256sum "$WORK/same.bin" | awk '{print $1}')" = "$SAME_BEFORE" ]; then
    ok "SRC == DEST succeeds without deleting/modifying the file"
  else
    bad "SRC == DEST deleted or modified the file"
  fi
else
  bad "SRC == DEST was rejected"
fi
if ls "$WORK"/same.bin.* >/dev/null 2>&1; then
  bad "leftover temp file after SRC == DEST"
else
  ok "no temp file left behind after SRC == DEST"
fi

# --- T2c: local PATH source — SRC == DEST with wrong hash rejected, intact ----
if run_fixture_fn upgrade_baseline_source_from "$WORK/same.bin" "$WRONG_SHA" "$WORK/same.bin" >/dev/null; then
  bad "SRC == DEST with wrong hash was accepted"
else
  ok "SRC == DEST with wrong hash rejected"
fi
if [ -f "$WORK/same.bin" ] \
    && [ "$(sha256sum "$WORK/same.bin" | awk '{print $1}')" = "$SAME_BEFORE" ]; then
  ok "SRC == DEST file intact after wrong-hash rejection"
else
  bad "SRC == DEST file modified/deleted after wrong-hash rejection"
fi

# --- T2d: destination is the verified temp boundary, not a pre-copy SRC check --
# A cp shim corrupts the copied bytes. A verify-SRC-then-copy implementation
# would still land the (unverified) copy in DEST; the temp+verify+rename
# boundary must reject it and leave neither DEST nor a temp file behind.
mkdir -p "$WORK/shim-cp"
cat > "$WORK/shim-cp/cp" <<'SHIM'
#!/usr/bin/env bash
set -u
last=""
for a in "$@"; do last="$a"; done
printf 'corrupted copy bytes\n' > "$last"
SHIM
chmod +x "$WORK/shim-cp/cp"
# Run inside a subshell so the corrupting cp is scoped to this test only: a
# command-prefixed function call would not reliably restore PATH on every bash
# version and could leak shim-cp into later tests' cp lookups.
if ( PATH="$WORK/shim-cp:$PATH"; run_fixture_fn upgrade_baseline_source_from "$WORK/exact.bin" "$EXACT_SHA" "$WORK/corrupt.bin" ) >/dev/null; then
  bad "copy with unverified destination bytes was accepted"
else
  ok "copy with unverified destination bytes rejected (verified temp boundary)"
fi
if [ ! -e "$WORK/corrupt.bin" ]; then
  ok "no unverified destination written"
else
  bad "unverified destination left behind"
fi
if ls "$WORK"/corrupt.bin.* >/dev/null 2>&1; then
  bad "leftover temp file after rejected copy"
else
  ok "no temp file left after rejected copy"
fi

# --- T3: local PATH source — wrong hash rejected, caller source preserved -----
printf 'caller-owned source that must not be deleted\n' > "$WORK/caller.bin"
CALLER_BEFORE="$(sha256sum "$WORK/caller.bin" | awk '{print $1}')"
if run_fixture_fn upgrade_baseline_source_from "$WORK/caller.bin" "$WRONG_SHA" "$WORK/never.bin" >/dev/null; then
  bad "wrong-hash local source was accepted"
else
  ok "wrong-hash local source rejected"
fi
if [ -f "$WORK/caller.bin" ] \
    && [ "$(sha256sum "$WORK/caller.bin" | awk '{print $1}')" = "$CALLER_BEFORE" ]; then
  ok "caller-owned source not deleted on rejection"
else
  bad "caller-owned source modified/deleted on rejection"
fi
if [ ! -e "$WORK/never.bin" ]; then
  ok "no dest written on rejection"
else
  bad "dest was written on rejection"
fi

# --- T4: URL source — good override accepted (identity unchanged) -------------
GOOD_URL="http://recovery.test/good.bin"
BAD_URL="http://recovery.test/bad.bin"
GOOD_FILE="$WORK/exact.bin"
export GOOD_URL BAD_URL GOOD_FILE
if run_fixture_fn upgrade_baseline_fetch_url "$GOOD_URL" "$EXACT_SHA" "$WORK/url-good.bin" >/dev/null; then
  if [ -f "$WORK/url-good.bin" ] && cmp -s "$WORK/exact.bin" "$WORK/url-good.bin"; then
    ok "URL override with exact bytes accepted (identity unchanged)"
  else
    bad "URL override produced byte-mismatched dest"
  fi
else
  bad "URL override with exact bytes rejected"
fi

# --- T5: URL source — bad bytes fail closed, no partial left ------------------
if run_fixture_fn upgrade_baseline_fetch_url "$BAD_URL" "$EXACT_SHA" "$WORK/url-bad.bin" >/dev/null; then
  bad "URL override with wrong bytes was accepted"
else
  ok "URL override with wrong bytes rejected"
fi
if [ ! -e "$WORK/url-bad.bin" ]; then
  ok "no partial download left on bad URL override"
else
  bad "partial download left on bad URL override"
fi

# --- T6: URL source — unreachable override fails, no partial ------------------
if run_fixture_fn upgrade_baseline_fetch_url "http://unreachable.invalid/x" "$EXACT_SHA" "$WORK/url-fail.bin" >/dev/null; then
  bad "unreachable URL override was accepted"
else
  ok "unreachable URL override rejected"
fi
if [ ! -e "$WORK/url-fail.bin" ]; then
  ok "no partial download left on unreachable URL override"
else
  bad "partial download left on unreachable URL override"
fi

# --- T7: wrapper precedence + fail-closed (pinned identity wiring) ------------
# PATH set to a wrong file -> rejected, and curl is NEVER invoked (PATH wins,
# but the pinned SHA is the authority).
: > "$CALL_LOG"
if UAT_UPGRADE_BASELINE_DEB_PATH="$WORK/caller.bin" run_fixture_fn upgrade_baseline_fetch_deb "$WORK/deb-badpath.bin" >/dev/null 2>&1; then
  bad "DEB wrapper accepted a wrong-hash PATH override"
else
  ok "DEB wrapper rejects a wrong-hash PATH override (fail closed)"
fi
if [ -s "$CALL_LOG" ]; then
  bad "DEB wrapper with PATH override must not fall back to a download (curl called)"
else
  ok "DEB wrapper with PATH override never invokes curl (no fallback)"
fi
[ -f "$WORK/caller.bin" ] && ok "caller PATH source preserved after wrapper rejection" \
  || bad "caller PATH source deleted after wrapper rejection"

# URL override with bad bytes -> rejected, canonical URL never requested, no
# partial download left behind.
: > "$CALL_LOG"
if UAT_UPGRADE_BASELINE_DEB_URL="$BAD_URL" run_fixture_fn upgrade_baseline_fetch_deb "$WORK/deb-badurl.bin" >/dev/null 2>&1; then
  bad "DEB wrapper accepted a wrong-bytes URL override"
else
  ok "DEB wrapper rejects a wrong-bytes URL override (fail closed)"
fi
if grep -q "$UPGRADE_BASELINE_DEB_URL" "$CALL_LOG" 2>/dev/null; then
  bad "DEB wrapper silently fell back to the canonical URL after a bad override"
else
  ok "DEB wrapper does not fall back to canonical after a bad URL override"
fi
if [ ! -e "$WORK/deb-badurl.bin" ]; then
  ok "no partial DEB download left on bad URL override"
else
  bad "partial DEB download left on bad URL override"
fi

# RPM wrapper mirrors the same fail-closed semantics on the pinned RPM identity.
: > "$CALL_LOG"
if UAT_UPGRADE_BASELINE_RPM_PATH="$WORK/caller.bin" run_fixture_fn upgrade_baseline_fetch_rpm "$WORK/rpm-badpath.bin" >/dev/null 2>&1; then
  bad "RPM wrapper accepted a wrong-hash PATH override"
else
  ok "RPM wrapper rejects a wrong-hash PATH override (fail closed)"
fi
if [ -s "$CALL_LOG" ]; then
  bad "RPM wrapper with PATH override must not fall back to a download"
else
  ok "RPM wrapper with PATH override never invokes curl"
fi

# --- Summary ------------------------------------------------------------------
echo
echo "=============== test-upgrade-baseline-fixture summary ==============="
echo "passed: $PASS  failed: $FAIL"
echo "====================================================================="
[ "$FAIL" -eq 0 ]
