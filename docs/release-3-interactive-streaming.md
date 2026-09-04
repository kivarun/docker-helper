# Release 3 Interactive Streaming

## Purpose

This document defines the D6 WebSocket transport for one interactive exec
inside an authorized Managed Container. Common exec authorization, admission,
container-state, concurrency, audit, and lifetime rules are owned by
`release-3-logs-and-exec.md` and are not redefined here.

Interactive streaming is a transient transport, not an Operation, durable
resource, Docker API proxy, or general remote shell service.

This revision freezes the D6 Interactive WebSocket transport contract as an
implementation input.

## Fixed boundary

Release 3 interactive exec:

- always allocates a TTY;
- carries one combined terminal stream;
- accepts an explicit non-empty argv array and never inserts a shell;
- supports terminal resize;
- has no non-TTY WebSocket mode;
- creates no public exec ID, attachment ticket, durable record, reconnect, or
  replay capability.

## Upgrade and start

The public endpoint is:

```text
GET /containers/{container}/exec/interactive
```

The HTTP upgrade authenticates the Session bearer — interactive exec is a
Session data-plane capability and admits no Principal or Launcher credential
— applies the ordinary non-disclosing target-visibility rule, and negotiates
the versioned
`docker-helper.exec.v1` WebSocket subprotocol through
`Sec-WebSocket-Protocol`. Authentication material, argv, environment values,
and working directory never appear in the URL.

After upgrade, the client's first application message must be one UTF-8 JSON
text frame:

```json
{
  "type": "start",
  "argv": ["sh"],
  "env": {},
  "workdir": "/workspace",
  "rows": 40,
  "cols": 120
}
```

The request fields preserve the common exec boundary. `argv` is required;
`env` and `workdir` are optional. Initial `rows` and `cols` describe the TTY
requested by this stream and do not become Managed Container state.

On receipt of `start`, docker-helper validates the message and rechecks the
Session, authorization, exact backend ownership and policy, container state,
lifecycle exclusion, and every exec-concurrency slot immediately before
creating and attaching the Docker exec instance.

The stream becomes an accepted interactive exec only when docker-helper has
created the backend exec, attached its TTY, and sent:

```json
{"type":"started"}
```

An error before `started` is returned as one stable structured JSON error
message followed by WebSocket closure. It creates no accepted exec instance
and releases any partially acquired transient capacity. A client must not send
terminal input or other controls before `started`.

There is no preliminary HTTP create request, attachment ticket, or public exec
identifier. The transient Docker exec ID is backend correlation only and is
never sent to the client, persisted, or accepted as authority.

## Application frames

The public protocol uses the WebSocket message type and direction as its
framing boundary:

| Direction | WebSocket message | Meaning |
| --- | --- | --- |
| client to server | UTF-8 JSON text | initial `start`, then `resize` controls |
| client to server | binary | terminal input bytes |
| server to client | UTF-8 JSON text | `started`, terminal `exit`, or `error` control |
| server to client | binary | combined terminal output bytes |

After `started`, a resize control is:

```json
{"type":"resize","rows":40,"cols":120}
```

Normal process completion is:

```json
{"type":"exit","exit_code":0}
```

The server sends all terminal output it has accepted from the Engine before
the `exit` message, then performs a normal WebSocket close. The protocol does
not include duration: the client can measure its own interaction time, while
server-side timing belongs to audit or metrics rather than terminal transport.

Binary data has no channel byte, base64 wrapper, or Docker attach framing. Its
meaning is unambiguous from message direction. Standard WebSocket ping, pong,
and close control frames provide transport liveness and closure; the
application protocol does not duplicate them as JSON messages.

## Transport time bounds

The WebSocket transport has fixed safety bounds:

| Boundary | Default |
| --- | ---: |
| client connect and HTTP upgrade | 10 seconds |
| first `start` message after upgrade | 10 seconds |
| server ping interval | 30 seconds |
| inbound activity or pong deadline | 60 seconds |
| one outbound message write | 30 seconds |

Any valid inbound application message or WebSocket pong refreshes the inbound
deadline. Therefore an idle terminal remains connected while its peer is
alive; Release 3 has no application inactivity timeout.

Each connection has a bounded 1 MiB outbound queue. Filling the queue applies
backpressure toward the Engine instead of discarding or truncating terminal
output. A peer that stops reading eventually hits the per-message write
deadline and the connection enters the ordinary disconnect path.

These values are deliberate transport constants, not administrator settings.
They bound a local Unix-socket protocol and have no demonstrated operational
tuning requirement. Focused tests may substitute shorter values through an
internal test seam.

## Authorization lifetime

The bearer is authenticated during upgrade, and common exec authorization is
rechecked when processing `start`. An accepted stream is not reauthenticated
on application frames, ping, or pong.

This preserves the Release 2.1 credential contract: rotating, revoking, or
deleting the initiating Principal or Launcher credential prevents later
authentication but does not invalidate an already issued Session or terminate
work already admitted through that Session. The same rule applies when an
administrator credential changes after admission.

Session lifetime remains authoritative. Expiration, explicit Session closure,
or Principal or Launcher lifecycle that invalidates owned Sessions closes the
stream and removes its Managed Container through the common Session cleanup
path. An open stream never renews Session TTL. Explicit Session renewal may
extend the Session while it remains active, without restarting or
reauthenticating the stream.

## Terminal outcome and closure

An `exit` message means that Docker Engine provided a trustworthy terminal
state for the tracked exec process. docker-helper never invents an exit code
from a closed attachment, WebSocket close, timeout, or backend error.

After an accepted stream, a helper or backend failure is reported when
possible with the existing flat error shape plus the frame discriminator:

```json
{
  "type": "error",
  "code": "exec_interrupted",
  "message": "container lifecycle interrupted exec"
}
```

Known Session expiration uses `session_expired`. A known stop, restart, remove,
or non-expiration Session cleanup uses `exec_interrupted`. Loss of the Engine
uses the common `backend_unavailable` category; an unexpected internal relay
failure uses `internal_error`. Exact messages remain stable and sanitized.
They disclose no initiating subject, backend ID, exec ID, host path, argv,
environment value, or terminal data.

The terminal cases are:

| Observation | Last application message | WebSocket close |
| --- | --- | --- |
| trustworthy process exit | `exit` with the actual `exit_code` | `1000` normal closure |
| known Session expiration | `error` with `session_expired` | `1000` after error delivery |
| known container or Session lifecycle interruption | `error` with `exec_interrupted` | `1000` after error delivery |
| daemon graceful shutdown | none required | `1012` service restart |
| backend or relay failure | `error` when delivery remains possible | `1011` internal error |
| transport loss | none possible | transport failure |

Application failure is carried by the JSON `error` message; a following `1000`
means only that its WebSocket close handshake completed normally. Protocol
violations use `1002`, oversized messages use `1009`, unexpected server or
backend failures use `1011`, and daemon shutdown uses `1012`. Release 3 defines
no private close-code range that duplicates the application error vocabulary.

If delivery of the terminal application message fails, docker-helper records
the outcome in audit but does not reinterpret a WebSocket close code as a
process exit. The CLI reports that no trustworthy remote exit status was
received.

## Disconnect cleanup

User keystrokes, including Ctrl-C and Ctrl-D, are ordinary terminal input
bytes. Release 3 has no separate public signal, EOF, detach, or exec-kill
control message.

When the WebSocket disconnects while the process remains active,
docker-helper makes one bounded best-effort cleanup attempt through the still
open Engine attachment:

1. write the terminal Ctrl-C byte;
2. wait up to one second for observed process exit;
3. if still running, write the terminal Ctrl-D byte and close the Engine input;
4. if still running, close the attachment and leave the process inside the
   Managed Container.

This sequence is not reported as guaranteed cancellation. Terminal mode,
process signal handling, or backend failure may prevent either control byte
from terminating the process. docker-helper does not resolve or signal host
PIDs, inject a supervisor, or kill the entire container merely because one
client disconnected.

When possible, the daemon continues observing a detached exec and retains its
transient concurrency slots until process exit or container teardown. A daemon
restart loses that observation and does not create a durable recovery record.
Any surviving process remains inside the Managed Container's cgroups and is
terminated by stop, restart, remove, or Session cleanup.

## Message validation and bounds

The protocol accepts one logical WebSocket message at a time and applies these
fixed bounds after WebSocket fragmentation is reassembled:

| Message | Maximum logical payload |
| --- | ---: |
| client JSON `start` or `resize` | 16 KiB |
| client terminal input | 64 KiB |
| server terminal output message | 64 KiB |
| server JSON control | 16 KiB |

The CLI chunks larger local reads into valid binary input messages. The server
may emit smaller output messages; clients must not depend on a particular
chunk boundary. Empty binary messages have no effect.

JSON controls are one UTF-8 object with a known `type`, no unknown fields, and
no trailing JSON value. A second `start`, binary input before `started`, a
client-sent server message type, or any text control other than `resize` after
start is a protocol error. An invalid control produces a sanitized
`protocol_error` when possible and closes with WebSocket code `1002`. An
oversized logical message closes with code `1009` and is never partially
applied.

Initial `rows` and `cols` may both be omitted, in which case the server uses
`24` rows and `80` columns. Otherwise both are required. Every initial or
resize dimension must be in `1..65535`. A valid resize is fire-and-forget and
has no acknowledgement message.

WebSocket compression is disabled. It adds CPU and memory amplification to a
local terminal channel without a demonstrated need, and compressed terminal
messages must not become part of the public protocol.

## CLI behavior

The API accepts any conforming WebSocket client. The docker-helper CLI exposes
interactive exec only when its stdin is a terminal. Piped stdin is rejected
before connection with a direct instruction to use non-interactive exec; the
CLI never changes exec mode implicitly.

The CLI:

- enters raw terminal mode before forwarding input and restores the original
  mode on every handled completion, error, interrupt, and disconnect path;
- reads the initial terminal size and includes it in `start`, falling back to
  `80x24` only when the size cannot be read;
- sends subsequent sizes on `SIGWINCH` without waiting for an acknowledgement;
- writes server binary messages to stdout, which may itself be redirected;
- forwards Ctrl-C and Ctrl-D as input bytes rather than treating them as local
  cancellation or detach commands;
- returns the remote exit code only after a valid `exit` message;
- returns a local failure and states that the remote exit status is unknown
  after an `error`, timeout, protocol violation, or transport loss.

Release 3 defines no CLI detach-key sequence. Killing or disconnecting the CLI
enters the documented best-effort disconnect path and may leave the process
running until later container teardown.

## Audit and secret boundary

Interactive exec emits one admission audit event and one terminal or
disconnect event. It reuses the common D5 attribution fields and may add the
negotiated protocol version, initial terminal dimensions, terminal reason, and
bytes transferred as non-secret operational metadata.

Audit, daemon logs, and journald never contain terminal input or output, argv
values, environment values, workdir, bearer material, BackendContainerID, or
the Docker exec ID. Resize, ping, pong, and individual data messages do not
produce audit events. Operational warnings are rate-bounded and identify only
public ownership correlations permitted by the common logging policy.

## Implementation boundary

D6 uses `github.com/coder/websocket` for both daemon and CLI WebSocket
transport, plus the common Docker Engine API adapter. The operational
architect pins a reviewed library version during implementation. docker-helper
does not implement WebSocket framing, masking, fragmentation, or the Engine
attach protocol by hand.

All third-party WebSocket types remain inside one package-local transport
adapter in the repository's existing `package main`. The adapter exposes only
docker-helper-owned message-kind and close-code values to the exec core through
a narrow connection contract equivalent to:

```go
type streamConn interface {
    Read(context.Context) (messageType, []byte, error)
    Write(context.Context, messageType, []byte) error
    Ping(context.Context) error
    Close(closeCode, string) error
}
```

The adapter owns dial, upgrade, subprotocol selection, read-limit setup,
compression policy, deadlines, close handling, and conversion of library
errors into docker-helper transport errors. The JSON application protocol and
exec core depend only on the narrow internal contract.

The current HTTP server applies request and response-delivery deadlines before
the WebSocket library hijacks the connection. A successful upgrade must clear
those inherited `net.Conn` deadlines at the docker-helper-owned hijack boundary
before D6 installs its own liveness and per-write bounds. The implementation
must not disable or weaken the ordinary HTTP server timeouts globally. This
compatibility behavior belongs to the transport adapter, because
`github.com/coder/websocket` performs the hijack but does not clear deadlines
installed by docker-helper's response wrapper.

This is a compile-time replacement boundary, not a runtime provider system.
Release 3 ships one WebSocket implementation and no factory registry,
selection setting, optional fallback, or second adapter. A future dependency
replacement may change this adapter and its contract tests but must not change
the public D6 protocol silently.

Raw Docker attach headers or frame markers never cross the public WebSocket
boundary. Exactly one goroutine owns WebSocket reads and one owns WebSocket
writes; application producers feed only the bounded queues owned by that
connection.

## Troubleshooting contract

User-facing help and troubleshooting cover these cases:

| Symptom | Required guidance |
| --- | --- |
| CLI stdin is not a terminal | Use non-interactive exec; Release 3 has no piped interactive mode. |
| rejected before `started` | Show the stable authorization, state, capacity, validation, or start error without backend identifiers. |
| `session_expired` | Create or renew a Session as permitted; the expired Session and its containers are being removed. |
| `exec_interrupted` | Inspect the docker-helper container and Operation state; a lifecycle action won admission. |
| `backend_unavailable` | Restore Docker Engine or helper access; no exit code is known. |
| connection lost with no terminal frame | State that the process may still run; use container stop, restart, or remove if termination is required. |
| output cannot be replayed | Explain that interactive streams are transient and have no reconnect or history endpoint. |

Troubleshooting may direct an administrator to Docker inspection for backend
details. docker-helper does not reproduce `docker inspect` or expose a raw
backend query.

## Verification gates

Implementation is not accepted without focused unit, protocol, race, and
real-Docker tests covering at least:

- upgrade authentication, non-disclosing target visibility, required
  subprotocol negotiation, and rejection of credentials or parameters in URLs;
- first-message timeout, strict `start` validation, atomic common exec
  admission, and slot release on every pre-`started` failure;
- mandatory TTY allocation, explicit argv behavior, binary input and output,
  initial size, repeated resize, and no shell insertion;
- message-size and sequence violations, WebSocket close codes, disabled
  compression, ping/pong liveness, and idle terminals surviving normal silence;
- a healthy interactive stream surviving beyond the ordinary HTTP 30-second
  response-delivery window, while non-WebSocket HTTP responses retain that
  deadline;
- bounded output backpressure without silent loss, a stalled reader reaching
  the write deadline, and no unbounded goroutine or queue growth;
- output-before-`exit` ordering, exact Engine exit-code propagation, and no
  invented exit code on relay or transport failure;
- Ctrl-C, one-second wait, Ctrl-D/input-close disconnect cleanup, including a
  process that ignores both and remains observable until later teardown;
- concurrent exec admission against every D5 ceiling and lifecycle admission
  races where either exec or stop/restart/remove/cleanup wins cleanly;
- Session renewal preserving a stream, Session expiration terminating it, and
  credential rotation or revocation not retroactively terminating it;
- daemon graceful shutdown using service-restart closure without persisting or
  recovering an exec record;
- CLI raw-mode restoration on success, error, local signal, broken stdout, and
  connection loss;
- absence of argv, environment values, terminal bytes, backend IDs, exec IDs,
  and bearer material from audit, daemon logs, journald, and public errors.

Real-Docker tests must exercise both a normal interactive shell and a program
that ignores terminal interruption. Unit-only simulation is insufficient for
TTY resize, attach closure, process observation, and container teardown races.

## Completion criterion

D6 is complete when an authorized caller can open one versioned, bounded TTY
stream through docker-helper; interact and resize without exposure to Docker
framing; receive a trustworthy process exit or explicit transport error; and
disconnect without an unbounded relay, durable exec state, secret-bearing
logs, or a second authorization model.
