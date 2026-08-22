# High-level abstractions

## Result

The Release 2 capability model remains coherent: one HTTP capability API is
shared by user and system deployments, transport does not establish identity,
and principal, launcher-credential, and session-token capabilities remain
separate. The new deployment behavior should be treated as the binding
contract:

- native DEB/RPM packages contain user- and system-mode assets;
- the release tarball installs user mode by default and requires the explicit
  `install-system.sh` path for system mode;
- operator commands select the user socket first and the system socket when the
  user socket is absent, using the corresponding token automatically;
- explicit socket/endpoint and token selection remains available;
- `credential install` stores a launcher credential for non-root clients;
- `init` defaults to the current user's home, or `/home` for root, and root may
  explicitly choose `/home` or `/opt`;
- `credential create --name` is optional and defaults to `default`;
- Bash completion is distributed with native packages and release artifacts.

Remote execution, non-loopback listeners, and TLS are not Release 2 contracts.

## Findings for Release 2

### Credential onboarding violates the first-use contract

`initUserWithSystemDaemon` treats a `nil` result from
`verifyCredentialToken` as “Credential already installed.” The verifier also
returns `nil` when the credential file or path does not exist, so the normal
first non-root init against a running system daemon exits successfully without
writing the supplied token. Split the result into explicit absent/match/conflict
states (or remove the pre-check and let the atomic installer own existence) and
cover the complete CLI path before continuing UAT.

### System initialization has two parallel transactions

`initSystemWithAppArmor` and `initSystemSELinux` separately implement the same
operator-token checks, existing-config checks, root canonicalization, and core
initialization ordering. Only the backend-specific confinement preparation
should differ.

This duplication has already made it harder to see whether both paths preserve
the same transaction and rollback rules. Do not redesign the complete init
subsystem before fixing the credential first-install defect, but extract one
backend-neutral system-init preflight/transaction before the final release if
the fix has to touch these paths materially.

### Endpoint selection is a good abstraction with one scope caveat

`resolveOperatorClient` owns operator endpoint and token selection and keeps
explicit overrides. That is the right boundary. Agent-facing pull/build/run
commands still use `resolveAgentSocketPath`, whose precedence is environment,
user runtime directory, then system socket; it does not probe both sockets.
Documentation must distinguish operator auto-selection from the agent socket
environment contract rather than implying that every command probes both
daemons.

### Completion has no metadata contract for argument values

The command tree is the authority for command names and flags, but completion
hard-codes config fields and several value enumerations. Add declarative
completion metadata to commands/arguments and render Bash from it. This is a
post-2.0 refactor unless a Release 2 CLI change exposes another drift.

## Proposed abstraction changes

| Change | Release fit | Reason |
|---|---|---|
| One system-init transaction with an LSM hook | Before 2.0 only if the credential/root fixes touch init broadly; otherwise next release | Removes two policy-bearing implementations without changing the public contract. |
| Declarative completion metadata | Next release | Prevents config/help/completion drift, but a late renderer rewrite adds little Release 2 value. |
| Bounded command-output collector shared by synchronous Docker calls | Before 2.0 | Pull and registry login currently bypass the bounded operation-log abstraction. |
| Confined CA source contract | Before 2.0 | Keep the current configured path only with a documented helper-owned readable location, or complete the previously accepted managed import. Do not claim arbitrary source paths under system MAC. |
| CA hash/store abstraction with a build-time OpenSSL conformance oracle | Next release | Reduces ownership of OpenSSL internals; a late hash rewrite is riskier than adding conformance coverage now. |
| Generated or interface-based SELinux policy composition | Next release | Avoids copying container-selinux semantics, but requires multi-distribution policy design and UAT. |

No additional top-level capability or control plane is justified for Release 2.
