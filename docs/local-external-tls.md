# Local-only external TLS on the 2.3 code line

This branch is an installation-specific fork of `release/2.3`. Do not
merge it into the release branch and do not publish a release artifact.

## Behavior

The existing Unix socket and `http_address` loopback HTTP listener are
unchanged. Supplying all three keys in `/etc/docker-helper/config.json`
enables **one additional HTTPS-only listener**:

```json
{
  "tls_address": "192.168.1.10:52376",
  "tls_cert_file": "/etc/docker-helper/tls/server.crt",
  "tls_key_file": "/etc/docker-helper/tls/server.key"
}
```

Add these members to the EXISTING JSON object; do not replace existing
`allowed_roots`, `session_ttl`, or other settings. The address must contain
an IP literal (including `0.0.0.0` or bracketed IPv6) and a nonzero port.
All three keys must either be absent or have nonempty values. Certificate and
key paths must be absolute. Files must already exist, be PEM encoded, and
contain a matching certificate/key pair. The certificate must have a SAN
matching the DNS name or IP address used by clients, and its issuer must be
trusted by clients.

TLS uses Go's server implementation with a minimum protocol version of 1.2.
The service loads the certificate and private key at daemon startup; rotate
them externally and restart the service. The binary does not generate them.
Invalid files or a failed TLS bind cause startup to fail, never a plaintext
fallback. The TLS settings are intentionally **file-only, startup-only** for
this one-machine fork: edit the JSON object together, then restart. They are
visible with `config show` but cannot be changed piecemeal via `config set`
or `config unset`. The ordinary `reload` command does not change the
active listeners or the active TLS certificate/key.

The HTTP API and bearer-token authorization are identical on Unix, loopback
HTTP, and external HTTPS. The existing `docker-helper` CLI defaults to the Unix socket, but already
supports `--endpoint http://127.0.0.1:PORT` (operator commands additionally
require `--token-file`). Its Release-2.3 endpoint validator rejects external
IP addresses and `https://`, so this server-only fork does **not** enable
direct remote HTTPS access through the unchanged CLI. External HTTP API callers
can use HTTPS with normal certificate verification; JSON endpoints and bearer
authentication headers are unchanged.

## Build and one-machine install

On the designated Linux host, from this branch:

```sh
go test ./...
go build -o ./docker-helper .
```

Provide your own certificate chain and private key. Keep both under
`/etc/docker-helper/tls/`, for which the shipped AppArmor profile allows
read access; the shipped SELinux file-context rule labels this directory as
`docker_helper_config_t`. Typical permissions: directory `0700`,
certificate `0644`, private key `0600`, root-owned. On an SELinux system
run `restorecon -RF /etc/docker-helper/tls` after placing the files.

Back up the installed 2.3 binary and configuration, stop the service, install
the locally built binary as `/usr/bin/docker-helper` (the path expected by
the packaged service and the MAC policies), and restore its SELinux context
if applicable. Edit `/etc/docker-helper/config.json` with all three TLS
fields before starting the service. No RPM/DEB or release workflow is needed.

## Smoke test

```sh
sudo systemctl restart docker-helper
sudo systemctl status docker-helper
ss -lnt | grep 52376
curl --fail --show-error https://YOUR_CERTIFICATE_HOSTNAME:52376/health
```

The last command must run from another machine using its normal trusted CA
store (or `--cacert /path/to/trusted-ca.pem`) and a hostname/IP covered by
the certificate SAN. Do not use `curl -k` for acceptance. Confirm existing
Unix-socket CLI commands still work, the loopback HTTP port is still bound
only on `127.0.0.1`, an ordinary plaintext HTTP request cannot use the
external port, and the installed TLS certificate chain validates.

**Network exposure is an operator responsibility:** firewall the external
port to the required source addresses, never publish the admin token or
private key, and assume every HTTP API route, including administrative
routes, is reachable by a holder of its appropriate bearer credential.
This is server-authenticated TLS, not mutual TLS.

If the service is enforcing SELinux, also check the journal and AVC logs
when binding an external IP/port; adjust policy only for a confirmed denial.
