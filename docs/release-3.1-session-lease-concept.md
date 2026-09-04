# Release 3.1 Session Lease Concept

## Status

Candidate Release 3.1 feature. Detailed architecture is deferred until Release
3 is complete. This document records the problem, intended direction, and scope
boundary only; it does not define a binding API or persistence contract.

## Problem

Launcher Delegation allows an orchestrator running in one Session to use
another Launcher's credential to create Sessions for delegated agents. Those
Sessions correctly belong to the Launcher whose credential authorized their
creation, not to the orchestrator Session, and may legitimately outlive it.

The orchestrator can therefore expire while delegated work still requires its
coordination. Deriving delegated Session lifetime from the orchestrator would
instead create a false ownership relationship and surprising cascade behavior.

## Intended direction

- preserve `Principal -> Launcher -> Session` ownership;
- evaluate a renewable Session lease with a separate absolute lifetime ceiling,
  provisionally represented by `expires_at` and `not_after`;
- consider allowing a Session bearer to renew only its own Session within that
  pre-authorized ceiling, without changing the ceiling or any other Session;
- keep renewal explicit: ordinary activity and open streams never renew a
  Session;
- attach no lifecycle authority to the Session that happened to initiate a
  request authenticated by another Launcher's credential;
- add no automatic orchestrator extension, inferred cascade deletion,
  reference-counted lifetime, or implicit adoption;
- evaluate temporal limits on delegated Launcher credentials separately from
  Session TTL, because a Launcher bearer does not inherit the lifetime of the
  Session that possesses it;
- keep delegated Sessions independently observable and subject to their own
  explicit expiry and owner-side lifecycle controls.

## Expected outcome

- a live orchestrator can explicitly maintain its own bounded lease;
- an orchestrator that crashes or stops renewing expires deterministically;
- delegated Sessions continue until their own expiry or explicit owner-side
  termination;
- a Session bearer cannot turn its bounded authority into unlimited lifetime;
- nested delegation requires no creator ancestry or fixed depth.

## Release 3 boundary

Release 3 retains its binding explicit owner-only renewal contract: an owning
Principal, owning Launcher, or administrator may renew an active Session, while
the Session bearer cannot renew it. Release 3 does not implement this concept.

The Release 3 implementation should keep renewal in the existing authoritative
Session lifecycle path so Release 3.1 can refine the lifetime model without
adding a parallel renewal mechanism or changing Session ownership.

## Questions for the Release 3.1 design pass

- exact meanings and names for the current lease, renewal interval, and
  absolute ceiling;
- which higher authorities may raise the ceiling and under which effective
  policy limits;
- renewal race, retry, expiry-boundary, and idempotency semantics;
- interaction with credential revocation and Principal/Launcher disable;
- whether delegated Launcher credentials require both a bearer-validity
  deadline and a maximum Session-effect horizon;
- minimal API, CLI, migration, audit, and observability changes.

## Non-goals

- Session-to-Session ownership;
- implicit cascade deletion or reference-counted lifetime;
- orchestration/session groups without a separately proven requirement;
- desired state, automatic resurrection, adoption, or background orchestration;
- durable workflow-result collection, which remains separate from Session
  lifetime.

