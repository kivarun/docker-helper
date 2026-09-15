#!/usr/bin/env bash
#
# uat-semanage-grammar-evidence.sh — INVESTIGATION-ONLY diagnostic for
# SC1/M12 (PR review: the semanage fcontext record parser must follow the
# real producer grammar). Runs as root on the openSUSE Tumbleweed SELinux
# VM after the docker-helper RPM (and its docker_helper policy module) is
# installed. It creates local fcontext rules through the REAL semanage
# command for the M12 case matrix, captures the RAW `semanage fcontext
# -l -C -n` bytes unambiguously (printable + od -c + base64), probes the
# trailing-whitespace boundary, and cleans every rule up.
#
# The evidence captured here is the test fixture for the width-independent
# parser repair. This script is diagnostic machinery and is removed once
# the evidence is committed.
set -uo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

echo "=== producer identity ==="
rpm -q policycoreutils policycoreutils-python-utils selinux-policy-targeted 2>&1 || true
SEOBJECT="$(python3 -c 'import seobject,os;print(seobject.__file__)' 2>/dev/null || true)"
echo "seobject: ${SEOBJECT:-absent}"
if [ -n "$SEOBJECT" ]; then
  echo "producer format string (source grammar evidence):"
  grep -n '%-50s' "$SEOBJECT" || true
fi

echo "=== local customizations BEFORE ==="
semanage fcontext -l -C -n > /tmp/m12-before.txt 2>&1 || true
od -c /tmp/m12-before.txt | head -20

P='docker_helper_workspace_t'
add() { # add <pattern>
  echo "semanage fcontext -a -t $P '$1'"
  semanage fcontext -a -t "$P" "$1" 2>&1 && echo "ADD-OK" || echo "ADD-FAIL rc=$?"
}

# M12 case matrix — created through the real semanage producer.
add '/m12-evidence/short(/.*)?'                                     # ordinary short
LONG1="/m12-evidence/$(printf 'a%.0s' $(seq 1 55))(/.*)?"           # beyond the display width
add "$LONG1"
LONG2="/m12-evidence/$(printf 'b%.0s' $(seq 1 200))(/.*)?"          # substantially longer
add "$LONG2"
LONGSP='/m12-evidence/long path with ordinary spaces/and another component/that is quite long indeed(/.*)?'
add "$LONGSP"                                                       # long + ordinary spaces
META='/m12-evidence/meta\.test\+file\[1\](/.*)?'                    # exactly as docker-helper escapes
add "$META"
LONGREG="/m12-evidence/$(printf 'c%.0s' $(seq 1 80))"               # exact regular-file shape, long
add "$LONGREG"

echo "=== equivalence record ==="
echo "semanage fcontext -a -e /m12-evidence/eq-src /m12-evidence/eq-dest"
semanage fcontext -a -e /m12-evidence/eq-src /m12-evidence/eq-dest 2>&1 && echo "EQ-OK" || echo "EQ-FAIL rc=$?"

echo "=== <<None>> probe ==="
echo "semanage fcontext -a -t '<<none>>' /m12-evidence/none-probe"
semanage fcontext -a -t '<<none>>' /m12-evidence/none-probe 2>&1 && echo "NONE-OK" || echo "NONE-FAIL rc=$?"

echo "=== trailing-whitespace boundary probe ==="
echo "semanage fcontext -a -t $P '/m12-evidence/trail ' (trailing space)"
semanage fcontext -a -t "$P" '/m12-evidence/trail ' 2>&1 && echo "TRAIL-OK" || echo "TRAIL-FAIL rc=$?"
echo "semanage fcontext -a -t $P '/m12-evidence/trail' (no trailing space)"
semanage fcontext -a -t "$P" '/m12-evidence/trail' 2>&1 && echo "TRAIL2-OK" || echo "TRAIL2-FAIL rc=$?"
echo "re-add of the trailing-space pattern (duplicate probe):"
semanage fcontext -a -t "$P" '/m12-evidence/trail ' 2>&1 && echo "RETRAIL-OK" || echo "RETRAIL-FAIL rc=$?"

echo "=== RAW semanage fcontext -l -C -n (printable, cat -A) ==="
semanage fcontext -l -C -n > /tmp/m12-list.txt 2>&1
grep -a 'm12-evidence' /tmp/m12-list.txt | cat -A
echo "=== RAW list bytes restricted to m12-evidence records (od -c) ==="
grep -a 'm12-evidence' /tmp/m12-list.txt > /tmp/m12-records.txt
od -c /tmp/m12-records.txt
echo "=== full RAW list (base64, exact bytes) ==="
base64 -w 76 /tmp/m12-list.txt

echo "=== cleanup ==="
for p in '/m12-evidence/short(/.*)?' "$LONG1" "$LONG2" "$LONGSP" "$META" "$LONGREG" '/m12-evidence/none-probe' '/m12-evidence/trail ' '/m12-evidence/trail'; do
  semanage fcontext -d "$p" 2>&1 && echo "DEL-OK '$p'" || echo "DEL-FAIL '$p' rc=$?"
done
semanage fcontext -d /m12-evidence/eq-dest 2>&1 && echo "DELEQ-OK" || echo "DELEQ-FAIL rc=$?"

echo "=== local customizations AFTER (must equal BEFORE) ==="
semanage fcontext -l -C -n > /tmp/m12-after.txt 2>&1 || true
cmp -s /tmp/m12-before.txt /tmp/m12-after.txt && echo "CLEANUP-VERIFIED (no residue)" || {
  echo "CLEANUP-DIFF:"
  diff /tmp/m12-before.txt /tmp/m12-after.txt || true
}
echo "EVIDENCE-DONE"
