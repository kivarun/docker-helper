#!/usr/bin/env bash
#
# Guest-side P5-S2 newuidmap privilege-mechanism diagnosis for openSUSE
# Tumbleweed. INVESTIGATION ONLY — this script must never: switch packages,
# run chkstat/setcap/chmod on the third-party binaries, change the
# permissions machinery, load policy, or install docker-helper. Every
# finding lands in the evidence directory; the run is PASS when all phases
# completed (not when the mapping works — failure IS a finding).
#
#   A  package origin/metadata of /usr/bin/newuidmap + /usr/bin/newgidmap
#      (rpm -qf, version, rpm -V, stat, getcap -v, per-file modes and caps)
#   B  the distro privilege mechanism: the permissions machinery and its
#      profiles for shadow; the account-utils/newidmapd alternative with
#      a zypper --dry-run feasibility check (no switch is executed)
#   C  the control experiment OUTSIDE any docker-helper SELinux domain:
#      a provisioned-equivalent builder identity creates a user namespace
#      and maps the /etc/subuid,/etc/subgid ranges, capturing the actual
#      uid_map/gid_map plus newuidmap/newgidmap exits
#
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-diag-tw]'
EVIDENCE_DIR=/tmp/release-2.4-p5s2-diag-evidence
BUILDER_USER=docker-helper-builder
BUILDER_SUBUID_START=165536
BUILDER_SUBUID_COUNT=65536

log()  { printf '%s %s\n' "$PREFIX" "$*"; }

rm -rf "$EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR"

log 'A: package origin and metadata of newuidmap/newgidmap'
{
  echo "=== rpm -qf ==="
  rpm -qf /usr/bin/newuidmap 2>&1 || true
  rpm -qf /usr/bin/newgidmap 2>&1 || true
  echo "=== stat ==="
  stat /usr/bin/newuidmap /usr/bin/newgidmap 2>&1 || true
  echo "=== getcap -v ==="
  if command -v getcap >/dev/null 2>&1; then
    getcap -v /usr/bin/newuidmap /usr/bin/newgidmap 2>&1
    echo "getcap rc=$?"
  else
    echo "getcap not installed on this image"
  fi
  echo "=== setuid bit present? ==="
  test -u /usr/bin/newuidmap && echo "newuidmap: setuid bit present" || echo "newuidmap: setuid bit ABSENT"
  test -u /usr/bin/newgidmap && echo "newgidmap: setuid bit present" || echo "newgidmap: setuid bit ABSENT"
} >"$EVIDENCE_DIR/binary-origin.txt" 2>&1
cat "$EVIDENCE_DIR/binary-origin.txt" >&2

NUID_PKG="$(rpm -qf /usr/bin/newuidmap)"
{
  echo "=== owning package: $NUID_PKG ==="
  rpm -q --qf 'name=%{NAME}\nversion=%{VERSION}\nrelease=%{RELEASE}\nvendor=%{VENDOR}\n' "$NUID_PKG"
  echo "=== rpm -V (verification) ==="
  rpm -V "$NUID_PKG" 2>&1 || true
  echo "=== per-file modes and capabilities from RPM metadata ==="
  rpm -q --qf '[%{FILENAMES} mode=%{FILEMODES:octal} caps=%{FILECAPS}\n]' "$NUID_PKG" 2>&1 \
    | grep -E 'newuidmap|newgidmap' || echo "no per-file metadata matched"
  echo "=== implementation check: shadow vs account-utils ==="
  rpm -q account-utils 2>&1 || true
  rpm -q shadow 2>&1 || true
  rpm -q shadow-utils 2>&1 || true
} >"$EVIDENCE_DIR/package-metadata.txt" 2>&1
cat "$EVIDENCE_DIR/package-metadata.txt" >&2

log 'B: distro privilege mechanism'
{
  echo "=== permissions.d/shadow entries ==="
  cat /usr/share/permissions/permissions.d/shadow 2>&1 || true
  echo "=== permissions.d/shadow.paranoid entries ==="
  cat /usr/share/permissions/permissions.d/shadow.paranoid 2>&1 || true
  echo "=== grep newuidmap/newgidmap across all permissions sets ==="
  grep -rn 'newuidmap\|newgidmap' /usr/share/permissions /etc/permissions /etc/permissions.local 2>/dev/null || true
  echo "=== active security profile ==="
  grep -i PERMISSIONS_SECURITY /etc/sysconfig/security 2>/dev/null || true
  ls -l /etc/permissions /etc/permissions.secure /etc/permissions.local 2>/dev/null || true
  echo "=== chkstat availability/help ==="
  if command -v chkstat >/dev/null 2>&1; then
    chkstat --help 2>&1 | head -30 || true
    echo "=== chkstat dry-run on the shadow permissions file (no changes) ==="
    chkstat --system --dry-run /usr/share/permissions/permissions.d/shadow 2>&1 || true
  else
    echo "chkstat not installed on this image"
  fi
} >"$EVIDENCE_DIR/permissions-mechanism.txt" 2>&1
cat "$EVIDENCE_DIR/permissions-mechanism.txt" >&2

{
  echo "=== zypper search account-utils ==="
  zypper -n search account-utils 2>&1 || true
  echo "=== zypper info account-utils ==="
  zypper -n info account-utils 2>&1 || true
  echo "=== repoquery file list (newidmapd-related) ==="
  zypper -n repoquery -l account-utils 2>&1 | grep -iE 'newidmap|bin/|\.socket|\.service' || true
  echo "=== repoquery --requires ==="
  zypper -n repoquery --requires account-utils 2>&1 || true
  echo "=== dry-run switch feasibility (NOT executed) ==="
  zypper -n --dry-run install account-utils 2>&1 || true
  echo "=== dry-run switch conflicts check ==="
  zypper -n --dry-run --force-resolution install account-utils 2>&1 | grep -iE 'conflict|remove|deinstall' || true
} >"$EVIDENCE_DIR/account-utils.txt" 2>&1
cat "$EVIDENCE_DIR/account-utils.txt" >&2

log 'C: control experiment outside docker-helper SELinux domains'
# Provision an equivalent builder identity ourselves (the same shape the
# canonical provisioner uses: a system user with subid ranges) — this is
# the user the item asks about; nothing docker-helper is installed here.
useradd -m "$BUILDER_USER" 2>/dev/null || true
grep -q "^$BUILDER_USER:" /etc/subuid || echo "$BUILDER_USER:$BUILDER_SUBUID_START:$BUILDER_SUBUID_COUNT" >> /etc/subuid
grep -q "^$BUILDER_USER:" /etc/subgid || echo "$BUILDER_USER:$BUILDER_SUBUID_START:$BUILDER_SUBUID_COUNT" >> /etc/subgid

{
  echo "=== /etc/subuid ==="
  cat /etc/subuid 2>&1 || true
  echo "=== /etc/subgid ==="
  cat /etc/subgid 2>&1 || true
  echo "=== id of the builder user ==="
  id "$BUILDER_USER" 2>&1 || true
} >"$EVIDENCE_DIR/builder-identity.txt" 2>&1
cat "$EVIDENCE_DIR/builder-identity.txt" >&2

CONTROL_SCRIPT=/tmp/p5s2-diag-control.sh
cat > "$CONTROL_SCRIPT" <<'CEOF'
#!/bin/sh
# Control experiment: run entirely outside any docker-helper MAC domain.
echo "id: $(id)"
echo "=== native mapping control: unshare --user --map-auto (util-linux subid-aware) ==="
unshare --user --map-auto --map-group -- true 2>&1
echo "unshare-map-auto rc=$?"
echo "=== newuidmap/newgidmap on a forked user-namespace child ==="
unshare --user sleep 300 &
CPID=$!
sleep 0.3
echo "child pid: $CPID"
echo "uid_map before: $(cat /proc/$CPID/uid_map 2>&1)"
echo "gid_map before: $(cat /proc/$CPID/gid_map 2>&1)"
newuidmap "$CPID" 0 165536 65536 2>&1
echo "newuidmap rc=$?"
echo "uid_map after newuidmap: $(cat /proc/$CPID/uid_map 2>&1)"
newgidmap "$CPID" 0 165536 65536 2>&1
echo "newgidmap rc=$?"
echo "gid_map after newgidmap: $(cat /proc/$CPID/gid_map 2>&1)"
echo "=== direct uid_map write without helpers (the kernel-subid path) ==="
unshare --user sleep 300 &
CPID2=$!
sleep 0.3
if printf '0 %s %s\n' 165536 65536 > "/proc/$CPID2/uid_map" 2>/dev/null; then
  echo "direct uid_map write OK: $(cat /proc/$CPID2/uid_map)"
else
  echo "direct uid_map write failed rc=$?"
fi
if printf '0 %s %s\n' 165536 65536 > "/proc/$CPID2/gid_map" 2>/dev/null; then
  echo "direct gid_map write OK: $(cat /proc/$CPID2/gid_map)"
else
  echo "direct gid_map write failed rc=$?"
fi
kill "$CPID" "$CPID2" 2>/dev/null || true
wait 2>/dev/null || true
CEOF
chmod 0755 "$CONTROL_SCRIPT"
su -s /bin/sh "$BUILDER_USER" -c "sh $CONTROL_SCRIPT" \
  >"$EVIDENCE_DIR/control-experiment.txt" 2>&1 || true
cat "$EVIDENCE_DIR/control-experiment.txt" >&2

{
  echo "=== is a mapping daemon running? ==="
  systemctl status newidmapd.service 2>&1 | head -5 || true
  systemctl status newidmapd.socket 2>&1 | head -5 || true
} >"$EVIDENCE_DIR/mapping-daemon-status.txt" 2>&1
cat "$EVIDENCE_DIR/mapping-daemon-status.txt" >&2

printf '%s P5S2-DIAG-RESULT=PASS (diagnosis completed; findings are in the evidence)\n' "$PREFIX" >&2
exit 0
