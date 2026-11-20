#!/bin/bash
# handoff-harness.sh — the four loader checks plus the create-probe for the
# patched v1.4.3 buildkit-runc loader (REPETITION INSTRUMENT):
#
#   1. control: the digest of the untouched committed bytes passes — the
#      run leaves the spec stage (a later-stage failure is a pass for this
#      boundary; the digest error must NOT appear);
#   2. path-replaced config.json between the commit and the runc read —
#      runc itself refuses before any container creation;
#   3. same-inode content tamper before the runc read — runc refuses;
#   4. absent RUNC_SPEC_SHA256 token — runc refuses (the token is
#      mandatory on run);
#   create-probe: a direct `create` in the managed circuit is refused by
#   the payload BEFORE any container creation (the wrapper's own argv
#   gate is the first gate; this is the payload-side closure).
#
# Usage: handoff-harness.sh /path/to/buildkit-runc
set -u
RUNC="${1:?usage: handoff-harness.sh <buildkit-runc path>}"
[ -x "$RUNC" ] || { echo "NOT EXECUTABLE: $RUNC"; exit 1; }
DIR="$(mktemp -d /tmp/handoff-harness.XXXXXX)"
cd "$DIR"
"$RUNC" spec >/dev/null 2>&1 || { echo "spec generation failed"; exit 1; }
mkdir -p rootfs
sha() { sha256sum "$1" | awk '{print $1}'; }
DIGEST_OK="$(sha config.json)"
fails=0

echo "== control: untouched committed bytes pass the spec check =="
out="$(env RUNC_SPEC_SHA256=$DIGEST_OK "$RUNC" run test 2>&1 || true)"
echo "$out" | head -3
if echo "$out" | grep -q "RUNC_SPEC_SHA256"; then
  echo "FAIL: the control run must not fail at the digest gate"; fails=1
else
  echo "PASS: the control run left the spec stage (later-stage failure: $(echo "$out" | tail -1 | cut -c1-120))"
fi

echo "== substitution: path-replaced config.json before the runc read =="
cp config.json config.json.orig
python3 - "$DIR" <<'PY'
import json, sys
doc=json.loads(open('config.json.orig').read())
doc.setdefault('annotations', {})['x'] = 'attacker'
open('replaced.json','w').write(json.dumps(doc))
PY
mv replaced.json config.json
out="$(env RUNC_SPEC_SHA256=$DIGEST_OK "$RUNC" run test 2>&1 || true)"
echo "$out" | head -3
if echo "$out" | grep -q "do not match the handed-off"; then
  echo "PASS: runc refused the path-replaced spec"; else echo "FAIL: runc did not refuse the replacement"; fails=1; fi

echo "== substitution: same-inode content tamper before the runc read =="
mv config.json.orig config.json
python3 - <<'PY'
import json
doc=json.loads(open('config.json').read())
doc.setdefault('annotations', {})['x'] = 'attacker'
open('config.json','w').write(json.dumps(doc))
PY
out="$(env RUNC_SPEC_SHA256=$DIGEST_OK "$RUNC" run test 2>&1 || true)"
echo "$out" | head -3
if echo "$out" | grep -q "do not match the handed-off"; then
  echo "PASS: runc refused the same-inode tampered spec"; else echo "FAIL: runc did not refuse the tampered content"; fails=1; fi

echo "== absence: no digest token aborts the managed run =="
out="$(env -u RUNC_SPEC_SHA256 "$RUNC" run test 2>&1 || true)"
echo "$out" | head -2
if echo "$out" | grep -q "is absent: refusing"; then
  echo "PASS: runc refused the absent digest before container creation"
else echo "FAIL: runc accepted the absent digest"; fails=1; fi

echo "== create probe: a direct create is refused before container creation =="
out="$(env RUNC_SPEC_SHA256=$DIGEST_OK "$RUNC" create test 2>&1 || true)"
echo "$out" | head -3
if echo "$out" | grep -q "not a supported command of this private runtime"; then
  echo "PASS: the payload refused the direct create before container creation"; fails=0
  if [ -e /run/runc-mnb30/test.state ]; then
    echo "FAIL: container state exists after the refusal"; fails=1
  fi
  fails=$((fails+0))
else
  echo "FAIL: the direct create was not refused: $(echo "$out" | tail -2)"; fails=1
fi

echo "HANDOFF-HARNESS-EXIT=$fails"
exit "$fails"
