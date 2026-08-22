# Logging, events, and output audit

## Result

The two-stream design is sound: audit JSONL is written to stdout and includes
`stream=audit`; operational slog JSONL is written to stderr and includes
`stream=operational`. Request IDs and asynchronous operation IDs provide useful
correlation, and sensitive values are excluded.

## Release findings

### Synchronous Docker output is unbounded

`handlePull` captures combined Docker output in an unbounded `bytes.Buffer` and
returns it in the HTTP response. `handleRegistryLogin` also uses unbounded
stdout/stderr buffers, even though it discards their contents. The
`operation_log_max_bytes` limit protects asynchronous build/run only.

Use one bounded collector for synchronous Docker subprocesses. Define whether a
truncated pull response exposes a `truncated` flag or a stable warning. This is
a Release 2 robustness fix because an authenticated caller can provoke large
memory use.

### Correlation field names are inconsistent

Most records use `operation` for an action such as `build`; four build cleanup
logs put the operation ID in `operation`. Emit `operation=build` and
`operation_id=<id>`. Principal/session cleanup logs use `session` where the
rest of the system uses `session_id`. Normalize these fields before the logging
schema is declared stable.

### Startup fallback timestamp has a different precision

The emergency startup-error record uses `time.RFC3339`, while the structured
logging contract uses RFC3339Nano. Change the fallback to RFC3339Nano or
document it as a deliberately smaller emergency schema. A one-line format fix
is appropriate before Release 2.

### Rejected authenticated operations lack a consistent audit event

Authentication failures are audited, but invalid build/run/pull requests after
successful authentication can return before a start/finish audit pair. Decide
whether the audit stream records only accepted capability executions or all
security-relevant attempts. For a multi-user system service, the recommended
Release 2 contract is to audit rejected authenticated Docker-operation requests
with a stable result/code and no sensitive input.

## Dead logging path

The only direct global `slog.Warn` call is inside the unused
`cleanupPrincipalRuntimeDirs`. Delete that dead implementation rather than
introducing a second logging context into it.

## Documentation gaps corrected

- Audit examples now include the mandatory `stream` field.
- The event reference is marked against implemented principal, credential,
  admin-token, session-list, and operation events rather than describing
  implemented events as future work.
- The journald guidance relies on `stream` for separation because both file
  descriptors use the same systemd unit and identifier.

## Next-release work

Create a typed field/event vocabulary shared by operational logging, audit
records, documentation examples, and schema tests. Do not merge the audit and
operational streams: their retention and enablement semantics are intentionally
different.
