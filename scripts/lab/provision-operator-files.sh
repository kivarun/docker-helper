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

[ -f "$DEVVM" ] || die "cannot find scripts/dev-vm-local.sh next to this script"
[ -f "$GUARD" ] || die "cannot find scripts/lab/lab-vm-guard.sh next to this script"

require_regular_file() { # PATH LABEL
  [ -e "$1" ] || die "$2: file not found: $1"
  [ -f "$1" ] || die "$2: not a regular file: $1"
  [ ! -L "$1" ] || die "$2: symlinks are refused: $1"
  [ -r "$1" ] || die "$2: not readable: $1"
}

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
  case "$ca_name" in
    [A-Za-z0-9._-]*) ;; # safe anchor name
    *) die "LAB_CA_SOURCE base name contains unsafe characters: $ca_name" ;;
  esac
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
set -euo pipefail
require_lab_vm
log() { printf '[operator-files] %s\n' "$*"; }
die() { printf '[operator-files] ERROR: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "must run as root in the guest"
command -v openssl >/dev/null 2>&1 || die "openssl not found in the guest"
command -v update-ca-certificates >/dev/null 2>&1 || die "update-ca-certificates not found in the guest"
AGENT_HOME="/home/$AGENT_USER"
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

cat >> "$GUEST" <<'BODY'

AGENT_OCODE="$AGENT_HOME/.opencode-docker"

decode_to() { # DEST MODE OWNER b64var
  printf '%s' "${!4}" | base64 -d > "$1"
  chmod "$2" "$1"
  chown "$3" "$1"
}

# --- agent ssh key -----------------------------------------------------------
if [ -n "${SSH_KEY_B64:-}" ]; then
  install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_HOME/.ssh"
  decode_to "$AGENT_HOME/.ssh/id_ed25519_opencode" 0600 "$AGENT_USER:$AGENT_USER" SSH_KEY_B64
  decode_to "$AGENT_HOME/.ssh/id_ed25519_opencode.pub" 0644 "$AGENT_USER:$AGENT_USER" SSH_PUB_B64
  # authorized_keys: append the agent public key without duplicates.
  install -m 0600 -o "$AGENT_USER" -g "$AGENT_USER" /dev/null "$AGENT_HOME/.ssh/authorized_keys"
  SSH_PUB_LINE="$(awk '{print $1, $2}' "$AGENT_HOME/.ssh/id_ed25519_opencode.pub") opencode-agent"
  if ! grep -qxF -- "$SSH_PUB_LINE" "$AGENT_HOME/.ssh/authorized_keys"; then
    printf '%s\n' "$SSH_PUB_LINE" >> "$AGENT_HOME/.ssh/authorized_keys"
    chown "$AGENT_USER:$AGENT_USER" "$AGENT_HOME/.ssh/authorized_keys"
  fi
  log "agent ssh key installed (0600) and authorized_keys updated"
fi

# --- corporate CA ------------------------------------------------------------
if [ -n "${CA_B64:-}" ]; then
  decode_to "/etc/pki/trust/anchors/$CA_NAME" 0644 "root:root" CA_B64
  update-ca-certificates >/dev/null 2>&1 || die "update-ca-certificates failed"
  # The system trust store must now resolve this CA (a real positive check:
  # the anchor is accepted as a trusted root out of the regenerated bundle).
  openssl verify -CAfile /etc/ssl/ca-bundle.pem "/etc/pki/trust/anchors/$CA_NAME" >/dev/null \
    || die "the CA is not resolvable from the guest trust store"
  # Helper-owned copy for Docker Helper CA injection (lab-managed file).
  install -d -m 0755 /etc/docker-helper
  decode_to "/etc/docker-helper/$CA_NAME.crt" 0644 "root:root" CA_B64
  command -v restorecon >/dev/null 2>&1 && restorecon "/etc/docker-helper/$CA_NAME.crt"
  # Container-facing lab copy (agent-owned; the relabel touches only this copy).
  install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_OCODE/ca"
  decode_to "$AGENT_OCODE/ca/$CA_NAME.crt" 0644 "$AGENT_USER:$AGENT_USER" CA_B64
  # Configure through the supported CLI only; never edit config.json directly.
  docker-helper config set trusted_ca_path "/etc/docker-helper/$CA_NAME.crt" >/dev/null \
    || die "config set trusted_ca_path failed"
  docker-helper config set trusted_ca_injection auto >/dev/null \
    || die "config set trusted_ca_injection failed"
  docker-helper config show trusted_ca_path >/dev/null 2>&1 || die "config show failed"
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
  # Merge without duplicates into the agent's own known_hosts.
  install -m 0644 -o "$AGENT_USER" -g "$AGENT_USER" /dev/null "$AGENT_HOME/.ssh/known_hosts"
  printf '%s' "${KNOWN_HOSTS_B64}" | base64 -d | while IFS= read -r line; do
    [ -n "$line" ] || continue
    grep -qxF -- "$line" "$AGENT_HOME/.ssh/known_hosts" \
      || printf '%s\n' "$line" >> "$AGENT_HOME/.ssh/known_hosts"
  done
  chown "$AGENT_USER:$AGENT_USER" "$AGENT_HOME/.ssh/known_hosts"
  # Container-facing copy (public material only; mounted read-only).
  install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_OCODE/ssh"
  decode_to "$AGENT_OCODE/ssh/known_hosts" 0644 "$AGENT_USER:$AGENT_USER" KNOWN_HOSTS_B64
  log "known_hosts installed (agent + container copy)"
fi

log "operator files provisioned"
BODY

# Sanity: the generated script must exist and be non-trivial.
[ -s "$GUEST" ] || die "guest installer generation failed"

# Stream guard + installer to the guest (root, passwordless sudo for opc).
if { cat "$GUARD"; printf '\n'; cat "$GUEST"; } | "$DEVVM" ssh "sudo AGENT_USER=$AGENT_USER bash -s"; then
  log "provisioned operator files in the lab VM"
else
  die "guest-side installation failed"
fi
