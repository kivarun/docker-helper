#!/usr/bin/env bash
#
# lab-mount-gate.sh — the SINGLE canonical implementation of the mount-source
# safety gate for every lab-managed bind-mount source that Docker may relabel
# (:z/:Z). Both the launcher (agent-aliases.sh) and the online diagnostic
# containers (provision-lab-vm.sh, via /opt/lab) source THIS file; no caller
# keeps its own copy of the checks.
#
# The library is distributed only through the trusted repository and reaches
# the VM through controlled provisioning (/opt/lab copy stage, the agent's
# lib directory installed by setup-agent-user.sh). It is never read from a
# user-writable location inside a root process.
#
# oc_lab_mount_source_ok KIND(dir|file) PATH LAB_ROOT
#
# Checks, in order:
#   1. canonical containment: the fully resolved source stays strictly inside
#      the allowed lab root (no parent-component symlink escape);
#   2. the final path component itself is not a symlink;
#   3. for a directory source: EVERY entry Docker could recursively relabel
#      is a plain, single-link, same-filesystem regular file or directory —
#      symlink entries, hardlink aliases to foreign inodes, foreign
#      filesystems and unsupported object types are refused;
#   4. for a file source: a real regular file with exactly one link.
# Any filesystem traversal error is fail-closed: an INCOMPLETE walk must
# never pass.
#
# Residual TOCTOU (documented): these checks are not atomic with the docker
# invocation. The sources live in the trusted launcher account's own tree,
# which no container mounts writable, so the untrusted model cannot race
# them. readlink -f alone proves nothing — the explicit checks do the work.
oc_lab_mount_source_ok() { # KIND(dir|file) PATH LAB_ROOT
    local kind="$1" path="$2" root="$3"
    local root_real path_real entry root_dev walk_file walk_rc obj_type
    root_real="$(readlink -f -- "$root" 2>/dev/null)" || return 1
    path_real="$(readlink -f -- "$path" 2>/dev/null)" || return 1
    case "$path_real" in
        "$root_real"/*) ;; * ) return 1 ;;
    esac
    [ "$path_real" != "$root_real" ] || return 1
    [ ! -L "$path" ] || return 1
    if [ "$kind" = dir ]; then
        [ -d "$path" ] || return 1
        root_dev="$(stat -c '%d' -- "$path_real")" || return 1
        # R4: the traversal status is checked — a partial walk must fail.
        # find -print0 cannot pass through command substitution (NULs are
        # stripped), so the walk goes through a private temp file. Traversal
        # diagnostics are not suppressed: the caller's refusal message plus
        # find's own error explain the failure.
        walk_file="$(mktemp "${TMPDIR:-/tmp}/lab-walk.XXXXXX")" || return 1
        find "$path_real" -mindepth 1 -print0 > "$walk_file"
        walk_rc=$?
        while IFS= read -r -d '' entry; do
            [ ! -L "$entry" ] || { rm -f -- "$walk_file"; return 1; }
            obj_type="$(stat -c '%F' -- "$entry" 2>/dev/null)" \
                || { rm -f -- "$walk_file"; return 1; }
            case "$obj_type" in
                "regular file"|"directory") ;;
                *) rm -f -- "$walk_file"; return 1 ;;
            esac
            # C7/F4: the device identity is verified for EVERY visited entry,
            # directories included — an empty nested mountpoint of another
            # filesystem contains no files, so the previous file-level check
            # alone could not catch it.
            [ "$(stat -c '%d' -- "$entry")" = "$root_dev" ] \
                || { rm -f -- "$walk_file"; return 1; }
            if [ "$obj_type" != "directory" ]; then
                [ "$(stat -c '%h' -- "$entry")" = 1 ] \
                    || { rm -f -- "$walk_file"; return 1; }
            fi
        done < "$walk_file"
        rm -f -- "$walk_file"
        [ "$walk_rc" = 0 ] || return 1
        return 0
    fi
    [ "$kind" = file ] || return 1
    [ -f "$path" ] || return 1
    [ "$(stat -c '%h' -- "$path")" = 1 ] || return 1
    return 0
}
