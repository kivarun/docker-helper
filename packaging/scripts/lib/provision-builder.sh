#!/bin/sh
# provision-builder.sh — the ONE builder identity + subordinate-ID
# provisioning owner for Release 2.4 (Release-2.4 implementation plan §6).
# It is executed (not re-implemented) by the DEB postinst, the RPM %post
# scriptlet, and the tarball system installer, so every install path
# provisions the exact same dedicated unprivileged builder identity.
#
# Canonical resource stem: docker-helper-builder (user, group, unit,
# runtime dir, state dir — no aliases).
#
# Contract (idempotent, fail-closed):
#   1. when the docker-helper-builder user exists: verify the nologin
#      shell, that the same-named group exists with the user's primary
#      gid, and the state-root home; anything else fails closed with an
#      actionable message;
#   2. otherwise create it as a system user (no login, no home creation);
#   3. verify the subordinate-ID databases carry a docker-helper-builder
#      entry with a range >= 65536 (the smallest RootlessKit needs to run
#      a full 65536-uid userns mapping);
#   4. when missing, COMPUTE a collision-free contiguous 65536 range with
#      integer arithmetic over every existing [start, start+count)
#      interval read from BOTH subid databases (one range is written to
#      both, so it must be free in both), and then DELEGATE THE MUTATION
#      to upstream account tooling: `usermod --add-subuids
#      --add-subgids`. docker-helper NEVER writes or rewrites the
#      subid databases directly: the passwd/subid database WRITER is
#      upstream shadow-utils exclusively;
#   5. ambiguous state (duplicate entries, an entry smaller than the
#      required range, overlapping allocations, usermod failure) fails
#      closed and prints the conflict — the package scriptlet aborts and
#      reports the failure to the operator;
#   6. a re-run of the same version is a no-op: every step verifies
#      first and mutates only when missing.

set -eu

IDENTITY=docker-helper-builder
BUILDER_HOME=/var/lib/docker-helper-builder
BUILDER_SHELL=/usr/sbin/nologin
SUBID_COUNT=65536
# Subordinate-ID allocations conventionally start above the classic static
# uid space (both supported targets' shadow-utils default SUB_UID_MIN).
SUBID_BASE=100000
SUBUID_DB=/etc/subuid
SUBGID_DB=/etc/subgid

log()  { printf 'provision-builder: %s\n' "$*"; }
fail() { printf 'provision-builder: FAILED: %s\n' "$*" >&2; exit 1; }

# --- toolchain preconditions ----------------------------------------------
command -v useradd >/dev/null 2>&1 || fail "useradd (shadow-utils) not available"
command -v usermod >/dev/null 2>&1 || fail "usermod (shadow-utils) not available"
command -v awk >/dev/null 2>&1     || fail "awk not available"
[ -e "$BUILDER_SHELL" ] || fail "login shell $BUILDER_SHELL does not exist on this system"

# --- identity ---------------------------------------------------------------
user_shell() {
    awk -F: -v u="$1" '$1 == u { print $7; found = 1 } END { if (!found) exit 1 }' /etc/passwd
}

user_gid() {
    awk -F: -v u="$1" '$1 == u { print $4; found = 1 } END { if (!found) exit 1 }' /etc/passwd
}

group_gid() {
    awk -F: -v g="$1" '$1 == g { print $3; found = 1 } END { if (!found) exit 1 }' /etc/group
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

if id "$IDENTITY" >/dev/null 2>&1; then
    log "user $IDENTITY exists; verifying"
    verify_identity
else
    log "creating system user $IDENTITY (home $BUILDER_HOME, shell $BUILDER_SHELL)"
    useradd --system --home "$BUILDER_HOME" --shell "$BUILDER_SHELL" "$IDENTITY" \
        || fail "useradd failed for $IDENTITY"
    verify_identity
fi

# --- subordinate-ID verification --------------------------------------------
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
    log "subordinate ranges verified; nothing to do"
    exit 0
fi

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

if [ "$need_uid" = 1 ]; then
    need_range=1
else
    need_range=0
fi
if [ "$need_gid" = 1 ]; then
    need_range=1
fi

if [ "$need_range" = 1 ]; then
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
fi

uid="$(awk -F: -v u="$IDENTITY" '$1 == u { print $3; found = 1 } END { if (!found) exit 1 }' /etc/passwd)"
log "provisioned $IDENTITY (uid $uid, subids $SUBID_COUNT)"
exit 0
