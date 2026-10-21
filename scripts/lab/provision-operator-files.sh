#!/usr/bin/env bash
#
# provision-operator-files.sh — validate and transfer OPERATOR-provided files
# from the physical host into the lab VM, and install them guest-side with
# exact ownership and modes.
#
# Every item is OPTIONAL: an unset or empty variable skips it with an explicit
# log. Nothing is hardcoded to a specific workstation — paths come from the
# operator's environment:
#
#   LAB_AGENT_SSH_KEY=/path/to/id_ed25519_opencode   agent SSH private key
#   LAB_CA_SOURCE=/path/to/corporate-ca              ONE PEM X.509 CA certificate
#   LAB_GITCONFIG_SOURCE=/path/to/gitconfig          .gitconfig for the container
#   LAB_KNOWN_HOSTS_SOURCE=/path/to/known_hosts      public SSH host keys
#   AGENT_USER=agent                                 guest account (default agent)
#
# Host-side validation happens BEFORE any transfer:
#   ssh key:      regular file (symlinks refused), owner-only mode (0400/0600),
#                 parses as a private key, ssh-keygen derives the public half
#                 (a sibling .pub must correspond to it);
#   CA:           regular file (symlinks refused), exactly ONE PEM CERTIFICATE
#                 block, no other PEM content (never a bundle, never a key),
#                 openssl parses it and it carries CA:TRUE basic constraints;
#   gitconfig:    regular file (symlinks refused), readable;
#   known_hosts:  regular file (symlinks refused), readable.
#
# Transfer uses the existing SSH channel only: the guest-side installer is
# streamed over stdin together with the lab-vm-guard library (so it refuses to
# run outside the lab VM). The host staging file holding the embedded payloads
# is created with mktemp (0700, private key material included) and removed by
# an EXIT/INT/TERM trap. No secret is printed, logged, or committed.
#
# Guest-side result:
#   /home/<agent>/.ssh/id_ed25519_opencode          0600 agent
#   /home/<agent>/.ssh/id_ed25519_opencode.pub      0644 agent
#   /home/<agent>/.ssh/authorized_keys              0600 agent (pub appended, no duplicates)
#   /home/<agent>/.ssh/known_hosts                  0644 agent (merged, no duplicates)
#   /home/<agent>/.opencode-docker/ssh/known_hosts  0644 agent (container-facing public material)
#   /home/<agent>/.opencode-docker/ca/<name>.crt    0644 agent (container-facing CA copy)
#   /home/<agent>/.opencode-docker/git/gitconfig    0644 agent (container-facing gitconfig)
#   /etc/pki/trust/anchors/<name>                   0644 root + update-ca-certificates
#   /etc/docker-helper/<name>.crt                   0644 root + restorecon on that file only
#   docker-helper config: trusted_ca_path + trusted_ca_injection=auto (via CLI only)
#
# Docker Helper v2.3.0 requires ONE PEM X.509 CA certificate — a bundle is
# refused host-side before anything is transferred.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVVM="$SCRIPT_DIR/../dev-vm-local.sh"
GUARD="$SCRIPT_DIR/lab-vm-guard.sh"

log() { printf '[provision-operator-files] %s\n' "$*"; }
die() { printf '[provision-operator-files] ERROR: %s\n' "$*" >&2; exit 1; }

SSH_KEY_SRC="${LAB_AGENT_SSH_KEY:-}"
CA_SRC="${LAB_CA_SOURCE:-}"
GITCONFIG_SRC="${LAB_GITCONFIG_SOURCE:-}"
KNOWN_HOSTS_SRC="${LAB_KNOWN_HOSTS_SOURCE:-}"
AGENT_USER="${AGENT_USER:-agent}"
LAB_GUEST_ROOT="${LAB_GUEST_ROOT:-}"

[ -f "$DEVVM" ] || die "cannot find scripts/dev-vm-local.sh next to this script"
[ -f "$GUARD" ] || die "cannot find scripts/lab/lab-vm-guard.sh next to this script"

require_regular_file() { # PATH LABEL
  [ -e "$1" ] || die "$2: file not found: $1"
  [ -f "$1" ] || die "$2: not a regular file: $1"
  [ ! -L "$1" ] || die "$2: symlinks are refused: $1"
  [ -r "$1" ] || die "$2: not readable: $1"
}

# R6: host-supplied values are validated as WHOLE strings before anything
# crosses the SSH boundary. The former glob ([A-Za-z0-9._-]*) was a PREFIX
# match and accepted 'R;touch BAD'.
valid_object_name() { # VALUE — a filename/username component
  printf '%s' "$1" | grep -qE '^[A-Za-z0-9._-]+$' \
    && [ "$1" != "." ] && [ "$1" != ".." ]
}
valid_object_name "$AGENT_USER" \
  || die "AGENT_USER must match ^[A-Za-z0-9._-]+\$ (and not . or ..): '$AGENT_USER'"

# --- SSH key validation ------------------------------------------------------
ssh_pub_line=""
if [ -n "$SSH_KEY_SRC" ]; then
  require_regular_file "$SSH_KEY_SRC" "LAB_AGENT_SSH_KEY"
  key_mode="$(stat -c '%a' "$SSH_KEY_SRC")"
  case "$key_mode" in
    400|600) log "ssh key mode ok ($key_mode)" ;;
    *) die "LAB_AGENT_SSH_KEY must be accessible only to the operator (mode $key_mode, want 0400 or 0600)" ;;
  esac
  grep -q "PRIVATE KEY" "$SSH_KEY_SRC" \
    || die "LAB_AGENT_SSH_KEY does not look like a private SSH key"
  command -v ssh-keygen >/dev/null 2>&1 \
    || die "ssh-keygen not found on the physical host (required to validate the key)"
  ssh_pub_line="$(ssh-keygen -y -f "$SSH_KEY_SRC")" \
    || die "ssh-keygen cannot read LAB_AGENT_SSH_KEY (corrupt or unsupported key)"
  [ -n "$ssh_pub_line" ] || die "ssh-keygen derived an empty public key"
  # A sibling .pub must correspond to the private key when it exists.
  if [ -f "$SSH_KEY_SRC.pub" ]; then
    pub_fields="$(awk '{print $1, $2}' "$SSH_KEY_SRC.pub")"
    priv_fields="$(printf '%s' "$ssh_pub_line" | awk '{print $1, $2}')"
    [ "$pub_fields" = "$priv_fields" ] \
      || die "the sibling .pub does not correspond to LAB_AGENT_SSH_KEY"
    log "sibling .pub corresponds to the private key"
  fi
  log "ssh key validated"
fi

# --- CA validation -----------------------------------------------------------
ca_name=""
if [ -n "$CA_SRC" ]; then
  require_regular_file "$CA_SRC" "LAB_CA_SOURCE"
  command -v openssl >/dev/null 2>&1 \
    || die "openssl not found on the physical host (required to validate the CA)"
  blocks="$(grep -c -- '-----BEGIN CERTIFICATE-----' "$CA_SRC" || true)"
  [ "$blocks" = 1 ] || die "LAB_CA_SOURCE must contain exactly ONE PEM CERTIFICATE (found $blocks); Docker Helper v2.3.0 requires a single CA, not a bundle"
  if grep -q -- '-----BEGIN' "$CA_SRC"; then
    non_cert_blocks="$(grep -- '-----BEGIN' "$CA_SRC" | grep -vc -- 'BEGIN CERTIFICATE-----' || true)"
    [ "$non_cert_blocks" = 0 ] || die "LAB_CA_SOURCE contains non-certificate PEM blocks (a key or a bundle?)"
  fi
  openssl x509 -in "$CA_SRC" -noout >/dev/null 2>&1 \
    || die "LAB_CA_SOURCE is not a valid X.509 certificate"
  openssl x509 -in "$CA_SRC" -noout -text | grep -q "CA:TRUE" \
    || die "LAB_CA_SOURCE is not a CA certificate (basicConstraints CA:TRUE missing)"
  ca_name="$(basename -- "$CA_SRC")"
  valid_object_name "$ca_name" \
    || die "LAB_CA_SOURCE base name must match ^[A-Za-z0-9._-]+\$ (and not . or ..): '$ca_name'"
  log "CA validated (single X.509 CA certificate: $ca_name)"
fi

# --- gitconfig / known_hosts validation --------------------------------------
if [ -n "$GITCONFIG_SRC" ]; then
  require_regular_file "$GITCONFIG_SRC" "LAB_GITCONFIG_SOURCE"
  log "gitconfig validated"
fi
if [ -n "$KNOWN_HOSTS_SRC" ]; then
  require_regular_file "$KNOWN_HOSTS_SRC" "LAB_KNOWN_HOSTS_SOURCE"
  log "known_hosts validated"
fi

if [ -z "$SSH_KEY_SRC" ] && [ -z "$CA_SRC" ] && [ -z "$GITCONFIG_SRC" ] && [ -z "$KNOWN_HOSTS_SRC" ]; then
  log "nothing to provision: set LAB_AGENT_SSH_KEY, LAB_CA_SOURCE, LAB_GITCONFIG_SOURCE or LAB_KNOWN_HOSTS_SOURCE"
  exit 0
fi

# --- guest-side installer ----------------------------------------------------
# Generated with the validated payloads embedded (base64) and streamed to the
# guest as root, together with the guard library. The staging file never
# outlives the run.
WORK="$(mktemp -d)" || die "mktemp failed"
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
GUEST="$WORK/guest.sh"

append_payload() { # VAR FILE — embed the file as one base64 assignment line
  { printf '%s="' "$1"; base64 -w0 -- "$2"; printf '"\n'; } >> "$GUEST" \
    || die "cannot embed payload $1"
}

cat > "$GUEST" <<'HDR'
# --- guest-side installer (streamed; runs as root inside the lab VM) ---------
# LAB_GUEST_ROOT is a test seam: when set, every guest filesystem path is
# prefixed with it (behavioral tests execute this installer against a safe
# test root). In the real VM it is unset and the real paths are used.
set -euo pipefail
require_lab_vm
log() { printf '[operator-files] %s\n' "$*"; }
die() { printf '[operator-files] ERROR: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "must run as root in the guest"
command -v openssl >/dev/null 2>&1 || die "openssl not found in the guest"
command -v update-ca-certificates >/dev/null 2>&1 || die "update-ca-certificates not found in the guest"
LAB_GUEST_ROOT="${LAB_GUEST_ROOT:-}"
ETC="$LAB_GUEST_ROOT/etc"
HDR

if [ -n "$SSH_KEY_SRC" ]; then
  append_payload SSH_KEY_B64 "$SSH_KEY_SRC"
  # The public half is derived host-side (already validated against the key)
  # and travels as its own payload; the guest builds the authorized_keys line
  # from it.
  ssh-keygen -y -f "$SSH_KEY_SRC" > "$WORK/agent.pub" \
    || die "cannot derive the public key"
  append_payload SSH_PUB_B64 "$WORK/agent.pub"
fi
if [ -n "$CA_SRC" ]; then
  append_payload CA_B64 "$CA_SRC"
  printf 'CA_NAME=%q\n' "$ca_name" >> "$GUEST"
fi
[ -n "$GITCONFIG_SRC" ] && append_payload GITCONFIG_B64 "$GITCONFIG_SRC"
[ -n "$KNOWN_HOSTS_SRC" ] && append_payload KNOWN_HOSTS_B64 "$KNOWN_HOSTS_SRC"

# R6: the account name travels INSIDE the payload (printf %q), never as an
# inline environment assignment in the remote command line.
printf 'AGENT_USER=%q\n' "$AGENT_USER" >> "$GUEST"
printf 'LAB_GUEST_ROOT=%q\n' "$LAB_GUEST_ROOT" >> "$GUEST"
printf 'AGENT_HOME=%q\n' "$LAB_GUEST_ROOT/home/$AGENT_USER" >> "$GUEST"

# R5: the pinned base image reference is resolved on the HOST from the
# trusted repository copy and embedded as a payload — a root guest process
# never sources an agent-controlled launcher file.
host_base_image="$(SCRIPT_DIR="$SCRIPT_DIR" bash -c '
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/agent-aliases.sh" 2>/dev/null
  printf "%s" "$_OC_BASE"
' 2>/dev/null || true)"
[ -n "$host_base_image" ] && printf 'BASE_IMAGE=%q\n' "$host_base_image" >> "$GUEST"

cat >> "$GUEST" <<'BODY'

AGENT_OCODE="$AGENT_HOME/.opencode-docker"

decode_to() { # DEST MODE OWNER:GROUP b64var
  [ ! -L "$1" ] || die "refusing to write through a symlink: $1"
  printf '%s' "${!4}" | base64 -d > "$1"
  chmod "$2" "$1"
  chown "$3" "$1"
}

# F1/R1: authorization material is append-only. Existing content is never
# truncated; updates run under an exclusive lock, publish atomically
# (temp file + rename inside the target directory) and are verified for the
# final owner/mode. Symlinked targets and symlinked directories are refused,
# and the lock re-checks the target so a concurrent swap cannot slip through.
#
# R1: root never opens predictable paths (with O_TRUNC or otherwise) inside
# an agent-writable directory. The lock lives in a PRIVATE ROOT-ONLY
# directory keyed by a hash of the target path, and every staging file is a
# mktemp() file in that same private directory — a pre-placed symlink or
# hardlink under the agent's control can neither be followed nor truncated.
# Deduplication: authorized_keys compares KEY TYPE + KEY DATA (fields 1 and
# 2), so the same key with a different comment is never duplicated;
# known_hosts compares whole lines, which preserves hashed entries verbatim.
lab_lock_dir() {
  local lockdir="/run/docker-helper-lab-locks"
  [ -z "$LAB_GUEST_ROOT" ] || lockdir="$LAB_GUEST_ROOT/run/docker-helper-lab-locks"
  if [ ! -d "$lockdir" ] || [ -L "$lockdir" ]; then
    rm -rf -- "$lockdir" 2>/dev/null || true
    install -d -m 0700 "$lockdir" || die "cannot create the private lock directory $lockdir"
  fi
  # the directory must be private to the invoking user (root in the VM) and
  # a real directory: anything else is a tampered environment
  [ "$(stat -c '%04a' -- "$lockdir")" = 0700 ] \
    || die "the lock directory $lockdir is not private (mode $(stat -c '%04a' -- "$lockdir" 2>/dev/null || echo unknown))"
  [ "$(stat -c '%U' -- "$lockdir")" = "$(id -un)" ] \
    || die "the lock directory $lockdir is not owned by the invoking user"
  printf '%s' "$lockdir"
}

merge_into() { # TARGET MODE OWNER:GROUP NEWFILE DEDUPE(auth|line)
  local target="$1" mode="$2" owner_group="$3" newfile="$4" dedupe="$5"
  local lockdir lock exist rc tmp
  local dir
  dir="$(dirname -- "$target")"
  [ -d "$dir" ] && [ ! -L "$dir" ] || die "refusing to update: $dir is not a real directory"
  [ ! -L "$target" ] || die "refusing to update through a symlink: $target"
  command -v flock >/dev/null 2>&1 || die "flock is not available in the guest"
  lockdir="$(lab_lock_dir)"
  lock="$lockdir/auth-$(printf '%s' "$target" | sha256sum | awk '{print substr($1, 1, 16)}').lock"
  if [ -f "$target" ]; then exist="$target"; else exist="/dev/null"; fi
  rc=0
  (
    flock -x 9 || exit 4
    # re-check under the lock: another writer may have replaced the target
    [ ! -L "$target" ] || exit 3
    tmp="$(mktemp -- "$dir/.provision.XXXXXX")" || exit 5
    # C7/F5: the directory owner can rename or replace the staging pathname at
    # any moment. Every privileged operation therefore targets the inode
    # pinned by our own file descriptor — content writes, chmod and chown go
    # through the fd (its /proc/self/fd path), never through the pathname.
    exec 8>"$tmp" || { rm -f -- "$tmp"; exit 6; }
    if [ -f "$target" ]; then
      cat -- "$target" >&8 || { rm -f -- "$tmp"; exec 8>&-; exit 6; }
    fi
    if [ -s "$newfile" ]; then
      # FILENAME==ARGV[1] (not NR==FNR): with an empty or absent existing
      # file, NR==FNR misclassifies every record of the new file as the
      # first file's records and silently drops them.
      if ! awk -v dedupe="$dedupe" '
          FILENAME==ARGV[1] { if (dedupe=="auth") seen[$1" "$2]=1; else seen[$0]=1; next }
          { if (dedupe=="auth") { k=$1" "$2; if (!(k in seen)) { seen[k]=1; print } }
            else if (!($0 in seen)) print }' \
        "$exist" "$newfile" >&8; then
        rm -f -- "$tmp"; exec 8>&-; exit 7
      fi
    fi
    chmod "$mode" /proc/self/fd/8 || { rm -f -- "$tmp"; exec 8>&-; exit 8; }
    chown "$owner_group" /proc/self/fd/8 || { rm -f -- "$tmp"; exec 8>&-; exit 9; }
    # Publication is a rename: the staging pathname must still be the pinned
    # inode at rename time, and the target must be the pinned inode
    # afterwards. A substitution between the check and the rename is detected
    # after the fact and fails the run loudly — it is never reported as
    # success.
    [ "$(stat -c '%d:%i' -- "$tmp")" = "$(stat -L -c '%d:%i' -- /proc/self/fd/8)" ] \
        || { rm -f -- "$tmp"; exec 8>&-; exit 11; }
    mv -f -- "$tmp" "$target" || { rm -f -- "$tmp"; exec 8>&-; exit 10; }
    [ "$(stat -c '%d:%i' -- "$target")" = "$(stat -L -c '%d:%i' -- /proc/self/fd/8)" ] \
        || { exec 8>&-; exit 12; }
    exec 8>&-
    exit 0
  ) 9> "$lock" || rc=$?
  [ "$rc" = 0 ] || die "update of $target failed (step $rc)"
  [ "$(stat -c '%04a' -- "$target")" = "$mode" ] || die "mode verification failed for $target"
  [ "$(stat -c '%U:%G' -- "$target")" = "$owner_group" ] || die "owner verification failed for $target"
}

# --- agent ssh key -----------------------------------------------------------
if [ -n "${SSH_KEY_B64:-}" ]; then
  install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_HOME/.ssh"
  decode_to "$AGENT_HOME/.ssh/id_ed25519_opencode" 0600 "$AGENT_USER:$AGENT_USER" SSH_KEY_B64
  decode_to "$AGENT_HOME/.ssh/id_ed25519_opencode.pub" 0644 "$AGENT_USER:$AGENT_USER" SSH_PUB_B64
  # authorized_keys: the agent key is appended by KEY TYPE + KEY DATA, never
  # duplicating and never removing existing entries. R1: the staging file is
  # a mktemp file inside the private lock directory, never a predictable
  # path under the agent's control.
  new_auth="$(mktemp "$(lab_lock_dir)/staging.XXXXXX")" || die "cannot stage the agent key"
  awk '{print $1, $2, "opencode-agent"}' "$AGENT_HOME/.ssh/id_ed25519_opencode.pub" > "$new_auth"
  merge_into "$AGENT_HOME/.ssh/authorized_keys" 0600 "$AGENT_USER:$AGENT_USER" "$new_auth" auth
  rm -f -- "$new_auth"
  log "agent ssh key installed (0600) and authorized_keys updated"
fi

# --- corporate CA ------------------------------------------------------------
if [ -n "${CA_B64:-}" ]; then
  decode_to "$ETC/pki/trust/anchors/$CA_NAME" 0644 "root:root" CA_B64
  if [ -z "$LAB_GUEST_ROOT" ]; then
    update-ca-certificates >/dev/null 2>&1 || die "update-ca-certificates failed"
    # A real positive check: the anchor must be accepted as a trusted root out
    # of the REGENERATED system bundle, not merely exist on disk.
    openssl verify -CAfile "$ETC/ssl/ca-bundle.pem" "$ETC/pki/trust/anchors/$CA_NAME" >/dev/null \
      || die "the CA is not resolvable from the guest trust store"
  fi
  # Helper-owned copy for Docker Helper CA injection (lab-managed file).
  install -d -m 0755 "$ETC/docker-helper"
  decode_to "$ETC/docker-helper/$CA_NAME.crt" 0644 "root:root" CA_B64
  command -v restorecon >/dev/null 2>&1 && restorecon "$ETC/docker-helper/$CA_NAME.crt"
  # Container-facing lab copy (agent-owned; the relabel touches only this copy).
  install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_OCODE/ca"
  decode_to "$AGENT_OCODE/ca/$CA_NAME.crt" 0644 "$AGENT_USER:$AGENT_USER" CA_B64
  # Configure through the supported CLI only; never edit config.json directly.
  docker-helper config set trusted_ca_path "$ETC/docker-helper/$CA_NAME.crt" >/dev/null \
    || die "config set trusted_ca_path failed"
  docker-helper config set trusted_ca_injection auto >/dev/null \
    || die "config set trusted_ca_injection failed"
  docker-helper config show trusted_ca_path >/dev/null 2>&1 || die "config show failed"
  # F6: build the combined trust bundle for the container's non-Node TLS
  # clients. The image's own public CA set is extracted from the pinned base
  # image with a one-off read-only container; the combined file is a
  # self-contained LAB-OWNED artifact — the guest system bundle and the
  # physical host trust store are never modified. If the image bundle cannot
  # be extracted, the combined bundle is NOT created and the launcher falls
  # back to NODE_EXTRA_CA_CERTS only: public trust stays intact, corporate
  # trust for non-Node clients stays unavailable (logged explicitly).
  if [ -z "$LAB_GUEST_ROOT" ]; then
    base_image="${BASE_IMAGE:-}"
    corp_ca="$ETC/docker-helper/$CA_NAME.crt"
    combined="$AGENT_OCODE/ca/combined-ca-bundle.crt"
    built=0
    if [ -n "$base_image" ] && command -v docker >/dev/null 2>&1; then
      img_bundle=""
      for cand in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem; do
        img_out="$(docker run --rm --entrypoint /bin/sh "$base_image" -c "cat '$cand' 2>/dev/null || true")" || img_out=""
        if printf '%s' "$img_out" | grep -q -- '-----BEGIN CERTIFICATE-----'; then
          img_bundle="$img_out"
          break
        fi
      done
      if [ -n "$img_bundle" ]; then
        { printf '%s\n' "$img_bundle"; cat -- "$corp_ca"; } > "$combined" \
          || die "cannot build the combined CA bundle"
        chmod 0644 "$combined"
        chown "$AGENT_USER:$AGENT_USER" "$combined"
        n_certs="$(grep -c -- 'BEGIN CERTIFICATE' "$combined" || true)"
        [ "$n_certs" -gt 1 ] || die "the combined CA bundle does not contain the public CA set"
        openssl verify -CAfile "$combined" "$corp_ca" >/dev/null \
          || die "the corporate CA is not trusted by the combined bundle"
        built=1
        log "combined CA bundle built ($n_certs certificates: image public set + corporate CA)"
      fi
    fi
    if [ "$built" = 0 ]; then
      log "WARNING: the image CA bundle could not be extracted; the launcher will expose the corporate CA only through NODE_EXTRA_CA_CERTS (public trust intact, non-Node corporate trust unavailable)"
    fi
  fi
  log "corporate CA installed (trust store + helper injection + container copy)"
fi

# --- gitconfig ----------------------------------------------------------------
if [ -n "${GITCONFIG_B64:-}" ]; then
  install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_OCODE/git"
  decode_to "$AGENT_OCODE/git/gitconfig" 0644 "$AGENT_USER:$AGENT_USER" GITCONFIG_B64
  log "gitconfig installed for the container"
fi

# --- known_hosts ---------------------------------------------------------------
if [ -n "${KNOWN_HOSTS_B64:-}" ]; then
  install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_HOME/.ssh"
  # Merge WITHOUT truncation into the agent's own known_hosts: existing
  # entries (including hashed ones) survive every run. R1: staging happens
  # in the private lock directory via mktemp.
  new_kh="$(mktemp "$(lab_lock_dir)/staging.XXXXXX")" || die "cannot stage the known_hosts update"
  printf '%s' "${KNOWN_HOSTS_B64}" | base64 -d > "$new_kh"
  merge_into "$AGENT_HOME/.ssh/known_hosts" 0644 "$AGENT_USER:$AGENT_USER" "$new_kh" line
  rm -f -- "$new_kh"
  # Container-facing copy (public material only; mounted read-only). This is
  # a provisioner-owned derived copy: the operator source is its single
  # source of truth, so it is republished (not merged) on every run.
  install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_OCODE/ssh"
  decode_to "$AGENT_OCODE/ssh/known_hosts" 0644 "$AGENT_USER:$AGENT_USER" KNOWN_HOSTS_B64
  log "known_hosts installed (agent + container copy)"
fi

log "operator files provisioned"
BODY

# Sanity: the generated script must exist and be non-trivial.
[ -s "$GUEST" ] || die "guest installer generation failed"

# Stream guard + installer to the guest (root, passwordless sudo for opc).
# R6: no host-supplied value is interpolated into the remote command line.
if { cat "$GUARD"; printf '\n'; cat "$GUEST"; } | "$DEVVM" ssh 'sudo bash -s'; then
  log "provisioned operator files in the lab VM"
else
  die "guest-side installation failed"
fi
