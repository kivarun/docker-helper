#!/bin/sh
# provision-builder.sh — the ONE builder host provisioning owner for
# Release 2.4 (Release-2.4 implementation plan §6). It is executed (not
# re-implemented) by the DEB postinst, the RPM %post scriptlet, and the
# tarball system installer, so every install path provisions the exact
# same builder host state.
#
# Canonical resource stem: docker-helper-builder (user, group, unit,
# runtime dir, state dir — no aliases).
#
# Responsibilities (idempotent, fail-closed, verify-first):
#   1. builder identity: when the docker-helper-builder user exists,
#      verify the nologin shell, that the same-named group exists with
#      the user's primary gid, and the state-root home; anything else
#      fails closed with an actionable message; otherwise create it as a
#      system user (no login, no home creation);
#   2. subordinate IDs: verify the subordinate-ID databases carry a
#      docker-helper-builder entry with a range >= 65536 (the smallest
#      RootlessKit needs to run a full 65536-uid userns mapping); when
#      missing, COMPUTE a collision-free contiguous 65536 range with
#      integer arithmetic over every existing [start, start+count)
#      interval read from BOTH subid databases (one range is written to
#      both, so it must be free in both), and then DELEGATE THE MUTATION
#      to upstream account tooling: `usermod --add-subuids --add-subgids`.
#      docker-helper NEVER writes or rewrites the subid databases
#      directly: the passwd/subid database WRITER is upstream
#      shadow-utils exclusively. Ambiguous state (duplicate entries, an
#      entry smaller than the required range, overlapping allocations,
#      usermod failure) fails closed and prints the conflict — the
#      package scriptlet aborts and reports the failure to the operator;
#   3. the TUN kernel facility (P5-S2 Phase 4C-13): the builder flow's
#      tap setup opens the global /dev/net/tun device node, whose driver
#      (char major:minor 10:200) must already be available on the host.
#      Kernel-module lifecycle stays a HOST/DEPLOYMENT responsibility:
#      this script only verifies the runtime condition
#      (/sys/class/misc/tun/dev == 10:200) and, when it is absent,
#      converges it by delegating to the upstream kmod tool (`modprobe
#      tun`) and re-verifying the sysfs endpoint. It never opens the
#      device to "test" it, never grants the flow domain module-load
#      authority, and never depends on /dev/net/tun's mere existence
#      (the node can exist while no driver backs 10:200). The reboot
#      persistence for the same facility is owned by the package's
#      modules-load.d/docker-helper-builder.conf asset; this script owns
#      the CURRENT-boot convergence (no duplicate activation paths);
#   4. a re-run of the same version is a no-op: every step verifies
#      first and mutates only when missing.
#
# The account and subordinate-ID database paths are read through
# environment-overridable constants so the script's own test suite can
# execute the COMPLETE production flow against fixture databases without
# touching host account state.

set -eu

IDENTITY=docker-helper-builder
BUILDER_HOME="${BUILDER_HOME:-/var/lib/docker-helper-builder}"
BUILDER_SHELL="${BUILDER_SHELL:-/usr/sbin/nologin}"
SUBID_COUNT=65536
# Subordinate-ID allocations conventionally start above the classic static
# uid space (both supported targets' shadow-utils default SUB_UID_MIN).
SUBID_BASE=100000
SUBUID_DB="${SUBUID_DB:-/etc/subuid}"
SUBGID_DB="${SUBGID_DB:-/etc/subgid}"
PW_DB="${PW_DB:-/etc/passwd}"
GROUP_DB="${GROUP_DB:-/etc/group}"
# TUN facility truth: the sysfs endpoint that reports the char device's
# major:minor when the driver is present (built-in or loaded). `tun` is
# char-major 10:200.
TUN_SYSFS="${TUN_SYSFS:-/sys/class/misc/tun/dev}"
TUN_MAJOR_MINOR=10:200
MODPROBE="${MODPROBE:-modprobe}"

log()  { printf 'provision-builder: %s\n' "$*"; }
fail() { printf 'provision-builder: FAILED: %s\n' "$*" >&2; exit 1; }

# --- stage 3: the TUN kernel facility (current-boot convergence) -----------
# Prints the sysfs endpoint value, or "absent" when the endpoint does not
# exist; always exits 0 (the caller decides what the value means).
tun_sysfs_dev() {
    if [ -r "$TUN_SYSFS" ]; then
        cat "$TUN_SYSFS"
    else
        echo absent
    fi
}

converge_tun_facility() {
    dev="$(tun_sysfs_dev)"
    if [ "$dev" = "$TUN_MAJOR_MINOR" ]; then
        log "TUN facility available ($TUN_SYSFS = $TUN_MAJOR_MINOR); nothing to do"
        return 0
    fi
    command -v "$MODPROBE" >/dev/null 2>&1 \
        || fail "modprobe not available; cannot converge the TUN facility ($TUN_SYSFS reports '$dev')"
    "$MODPROBE" tun || fail "modprobe tun failed"
    dev="$(tun_sysfs_dev)"
    [ "$dev" = "$TUN_MAJOR_MINOR" ] \
        || fail "modprobe tun reported success but $TUN_SYSFS reports '${dev}', want $TUN_MAJOR_MINOR"
    log "TUN facility converged ($TUN_SYSFS = $TUN_MAJOR_MINOR)"
}

# --- stage 1: builder identity ---------------------------------------------
user_shell() {
    awk -F: -v u="$1" '$1 == u { print $7; found = 1 } END { if (!found) exit 1 }' "$PW_DB"
}

user_gid() {
    awk -F: -v u="$1" '$1 == u { print $4; found = 1 } END { if (!found) exit 1 }' "$PW_DB"
}

group_gid() {
    awk -F: -v g="$1" '$1 == g { print $3; found = 1 } END { if (!found) exit 1 }' "$GROUP_DB"
}

verify_identity() {
    shell="$(user_shell "$IDENTITY")" || fail "user $IDENTITY vanished mid-provisioning"
    [ "$shell" = "$BUILDER_SHELL" ] || fail "user $IDENTITY has shell $shell, want $BUILDER_SHELL; fix the account and re-run"
    ugid="$(user_gid "$IDENTITY")" || fail "user $IDENTITY vanished mid-provisioning"
    ggid="$(group_gid "$IDENTITY")" || fail "group $IDENTITY missing while user $IDENTITY exists; create the group with gid $ugid and re-run"
    [ "$ugid" = "$ggid" ] || fail "user $IDENTITY gid $ugid != group $IDENTITY gid $ggid; fix the account and re-run"
    # The home is the state root; systemd's StateDirectory= owns its
    # creation and ownership at unit start, so it may legitimately be
    # absent at provisioning time. Nothing to verify beyond the account.
}

converge_identity() {
    command -v useradd >/dev/null 2>&1 || fail "useradd (shadow-utils) not available"
    [ -e "$BUILDER_SHELL" ] || fail "login shell $BUILDER_SHELL does not exist on this system"
    if id "$IDENTITY" >/dev/null 2>&1; then
        log "user $IDENTITY exists; verifying"
        verify_identity
    else
        log "creating system user $IDENTITY (home $BUILDER_HOME, shell $BUILDER_SHELL)"
        useradd --system --home "$BUILDER_HOME" --shell "$BUILDER_SHELL" "$IDENTITY" \
            || fail "useradd failed for $IDENTITY"
        verify_identity
    fi
    uid="$(awk -F: -v u="$IDENTITY" '$1 == u { print $3; found = 1 } END { if (!found) exit 1 }' "$PW_DB")"
    log "provisioned $IDENTITY (uid $uid, subids $SUBID_COUNT)"
}

# --- stage 2: subordinate-ID verification -----------------------------------
# Prints "<start> <count>" for the identity's FIRST entry; fails when more
# than one entry exists (ambiguous provisioning state).
subid_entry() {
    db="$1"
    awk -F: -v u="$IDENTITY" '
        $1 == u {
            n++
            if (n > 1) { print "DUPLICATE"; exit 0 }
            print $2, $3
        }
    ' "$db"
}

verify_subid() {
    db="$1"
    entry="$(subid_entry "$db")" || fail "cannot read $db"
    [ "$entry" != "DUPLICATE" ] || fail "$db holds more than one $IDENTITY entry; resolve the duplicate manually and re-run"
    [ -n "$entry" ] || return 1
    start="$(printf '%s' "$entry" | awk '{print $1}')"
    count="$(printf '%s' "$entry" | awk '{print $2}')"
    case "$start" in
        ''|*[!0-9]*) fail "$db holds a nonnumeric $IDENTITY start ($entry); resolve it manually and re-run" ;;
    esac
    case "$count" in
        ''|*[!0-9]*) fail "$db holds a nonnumeric $IDENTITY count ($entry); resolve it manually and re-run" ;;
    esac
    [ "$count" -ge "$SUBID_COUNT" ] || fail "$db holds $IDENTITY with count $count < $SUBID_COUNT; extend or remove the entry manually and re-run"
    return 0
}

# --- collision-free range computation ---------------------------------------
# Every existing [start, start+count) interval from BOTH databases (one
# numeric range will be written to both). A corrupt/nonnumeric entry fails
# closed BEFORE the collection: the computation must never silently skip an
# allocation. The validation pass deliberately runs without a pipeline so a
# fail-closed exit cannot be swallowed by a pipe's last-command status.
validate_subid_db() {
    db="$1"
    [ -f "$db" ] || return 0
    awk -F: '
        /^[[:space:]]*($|#)/ { next }
        NF >= 3 && ($2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/) {
            print "INVALID:" $0 > "/dev/stderr"
            exit 1
        }
    ' "$db" || fail "$db holds a nonnumeric entry; resolve it manually and re-run"
}

# Output: sorted "start count" lines over both databases.
collect_intervals() {
    for db in "$SUBUID_DB" "$SUBGID_DB"; do
        [ -f "$db" ] || continue
        awk -F: '
            /^[[:space:]]*($|#)/ { next }
            NF >= 3 { print $2, $3 }
        ' "$db"
    done | sort -n
}

# The interval sweep runs inside one awk process (integer arithmetic): no
# subshell state to lose, and zero input still yields the base candidate.
compute_free_start() {
    collect_intervals | awk -v base="$SUBID_BASE" -v need="$SUBID_COUNT" '
        { start[NR] = $1 + 0; count[NR] = $2 + 0 }
        END {
            candidate = base
            for (i = 1; i <= NR; i++) {
                if (candidate + need > start[i] && start[i] + count[i] > candidate) {
                    candidate = start[i] + count[i]
                }
            }
            print candidate
        }
    '
}

converge_subids() {
    command -v usermod >/dev/null 2>&1 || fail "usermod (shadow-utils) not available"
    command -v awk >/dev/null 2>&1     || fail "awk not available"
    need_uid=1
    need_gid=1
    if verify_subid "$SUBUID_DB"; then
        need_uid=0
        log "$SUBUID_DB: $(grep "^$IDENTITY:" "$SUBUID_DB")"
    fi
    if verify_subid "$SUBGID_DB"; then
        need_gid=0
        log "$SUBGID_DB: $(grep "^$IDENTITY:" "$SUBGID_DB")"
    fi
    if [ "$need_uid" = 0 ] && [ "$need_gid" = 0 ]; then
        log "subordinate ranges verified"
        return 0
    fi
    validate_subid_db "$SUBUID_DB"
    validate_subid_db "$SUBGID_DB"
    start="$(compute_free_start)"
    end=$((start + SUBID_COUNT - 1))
    log "computed collision-free subordinate range $start-$end ($SUBID_COUNT ids)"
    # DELEGATION BOUNDARY (§6): the databases are read/validated here, but
    # the WRITER is upstream shadow-utils exclusively.
    usermod --add-subuids "$start-$end" --add-subgids "$start-$end" "$IDENTITY" \
        || fail "usermod --add-subuids/--add-subgids failed for $IDENTITY (this distribution's usermod must support subordinate-ID mutation)"
    verify_subid "$SUBUID_DB" || fail "$SUBUID_DB does not hold the expected $IDENTITY range after usermod"
    verify_subid "$SUBGID_DB" || fail "$SUBGID_DB does not hold the expected $IDENTITY range after usermod"
    log "$SUBUID_DB: $(grep "^$IDENTITY:" "$SUBUID_DB")"
    log "$SUBGID_DB: $(grep "^$IDENTITY:" "$SUBGID_DB")"
}

# --- production flow: every stage, in order, unconditionally. The stage
# order is fixed by the fail-closed contract; no environment switch may
# omit a mandatory responsibility.
converge_identity
converge_subids
converge_tun_facility
exit 0
