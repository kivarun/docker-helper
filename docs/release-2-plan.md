# Release 2 implementation plan

## Goal

Release 2 adds remote image builds through one authenticated HTTPS endpoint.
The client streams a local Docker build context to the selected helper; the
resulting image and build cache remain in that helper's Docker daemon.

The supported deployment remains single-owner and user-managed. Release 2 does
not add remote `run`, mutable remote workspaces, multiple helper contexts,
system-wide deployment, multi-user authorization, or native packages.

## Release branch policy

- `main` contains current development for the next release.
- The latest `release/*` branch is the GitHub default branch and presents the
  README for the current published release.
- Release branches receive release fixes only. The existing `release/**` to
  `main` synchronization keeps those fixes in later development.
- When Release 2 is ready, create `release/2.0` from the final `main`, make it
  the default branch, and tag the release from that state.

Changing the default branch is an operator action and is not part of the code
changes below.

## Phase 0: architecture and repository review

Review the current implementation before changing behavior. Refactoring is an
outcome only where the review identifies a concrete obstacle to Release 2.

### Code architecture

- Trace daemon startup, listener ownership, shutdown, reload, and process lock
  lifecycle.
- Trace how the CLI constructs its HTTP client and where Unix-socket assumptions
  enter command behavior.
- Trace session creation, workspace authorization, and build request handling.
- Trace the async build operation from request decoding through Docker process
  startup, log capture, polling, cancellation, and shutdown.
- Identify the smallest boundary between the HTTP application and its listener.
- Decide whether Unix and HTTPS listeners may be enabled together or are
  mutually exclusive in Release 2.
- Decide how a remote-build session is represented and authorized without
  inventing a server-side workspace.
- Decide how the multipart upload joins the existing async operation lifecycle,
  especially what happens when upload or client connectivity is interrupted.
- Separate server configuration from client connection configuration without
  introducing multiple named contexts.

### Repository architecture

- Review whether the current single `package main` remains workable for the
  Release 2 changes; do not split packages merely for style.
- Review ownership and duplication across README, architecture, roadmap,
  developer instructions, and the agent skill.
- Review CI boundaries for Unix transport, HTTPS transport, protocol, and
  end-to-end tests.
- Review release-branch automation against the branch policy above.
- Review whether generated artifacts, packaging files, and release-only
  documentation are clearly separated from source and operational docs.

### Deliverable

- A review report separating correctness problems, Release 2 blockers, and
  maintenance preferences.
- Explicit decisions for the listener, configuration, session, upload, and
  operation-lifecycle questions above.
- A small set of preparatory refactors only if required by those decisions.
- No external behavior changes during review/refactoring.
- Existing tests remain green.

## Phase 1: network listener lifecycle

- Separate HTTP application construction from Unix-listener creation.
- Preserve the Unix socket as the default local transport.
- Add an explicitly configured TCP bind address.
- Integrate all enabled listeners with one startup, shutdown, and error
  lifecycle.
- Ensure partial startup failure closes already-created listeners and leaves no
  stale Unix socket or process lock.
- Keep plaintext TCP limited to internal loopback tests; do not expose it as a
  supported operator mode.

### Completion criteria

- Existing Unix-socket behavior and contracts are unchanged.
- TCP listener lifecycle tests cover startup, failure, and bounded shutdown.
- Network exposure cannot be enabled accidentally without the TLS configuration
  required by Phase 2.

## Phase 2: TLS configuration and security boundary

- Require a server certificate and private key for the network listener.
- Use HTTPS only for supported network access.
- Require an explicit bind address; do not introduce an implicit `0.0.0.0`
  default.
- Treat bind and certificate settings as startup configuration; runtime reload
  does not replace listeners or certificates in Release 2.
- Preserve the current admin-token and session-token model over TLS.
- Use normal hostname and certificate-chain validation.
- Support system trust and, if required for private infrastructure, one
  explicitly configured additional CA file.
- Do not add insecure TLS or mTLS in Release 2.
- Ensure logs and errors do not expose tokens, authorization headers, or key
  material.

### Completion criteria

- Positive tests cover a trusted CA and matching hostname.
- Negative tests cover unknown CA, hostname mismatch, malformed/missing
  certificate files, plaintext requests, and missing authentication.
- Local Unix operation remains unchanged.

## Phase 3: remote-build protocol

- Preserve the current JSON build request for local workspace builds.
- Add one streaming multipart build request for remote builds:
  1. JSON `metadata` part;
  2. `application/x-tar` `context` part.
- Validate metadata before consuming and forwarding the context.
- Stream the tar body to Docker without buffering the complete context in
  memory or a temporary archive.
- Authorize remote-build sessions server-side for the intended operations; a
  client-side omission of unsupported commands is not sufficient.
- Reuse the current operation registry, status, logs, result, and cancellation
  contract rather than adding upload resources or a second job model.
- Define deterministic cleanup for malformed multipart bodies, interrupted
  uploads, Docker startup failure, and shutdown during upload/build.
- Keep the resulting image and cache on the helper's Docker daemon.

### Completion criteria

- A test HTTP client can upload a context, receive the existing operation
  identity, follow logs/status, and verify build completion.
- Interrupted or rejected uploads leave no orphan Docker process or operation.
- Remote sessions cannot use workspace-dependent operations that are outside
  Release 2.

## Phase 4: network client and launcher integration

- Generalize the API client to use either the local Unix socket or one HTTPS
  endpoint.
- Add minimal client settings for endpoint and trust without named contexts or
  routing.
- Preserve the existing admin-token flow for launcher-driven session creation.
- Build the tar context on the client with Docker-compatible `.dockerignore`
  semantics and preserved file modes, symlinks, empty files, and Dockerfile
  selection.
- Stream multipart output without materializing the full tar in memory or on
  disk.
- Reuse existing polling, log display, result handling, and cancellation UX.
- Reject or omit unsupported remote commands consistently and explain the
  Release 2 limitation in CLI errors/help.

### Completion criteria

- A launcher on one host creates a remote-build session for a helper on another
  host.
- The client builds a local context remotely over HTTPS.
- The image exists on the remote Docker daemon and is not automatically
  downloaded or pushed.

## Phase 5: pre-release cleanup and acceptance

- Run the full Unix-mode regression suite, race tests, vet, formatting, and
  whitespace checks.
- Add an end-to-end test with client and helper on separate hosts or equivalent
  isolated environments.
- Exercise small and large contexts, `.dockerignore`, symlinks, executable
  modes, empty files, alternate Dockerfiles, and private base images.
- Exercise upload interruption, loss of connectivity after operation creation,
  cancellation, daemon shutdown, and restart limitations.
- Review operational and audit logs for secret leakage and useful failure
  diagnostics.
- Reconcile CLI help, config help, README, architecture, roadmap, and the agent
  skill with the final behavior.
- Verify old Release 1 configuration still starts in local Unix mode without
  migration steps.
- Build and test a release candidate before creating `release/2.0` and the
  final tag.

## Deferred beyond Release 2

- Remote `run` and mutable remote workspace synchronization.
- Multiple helper contexts, selection, routing, or helper-to-helper forwarding.
- Separate upload resources, resumable uploads, or a second build-job model.
- Durable operation state and recovery across daemon restarts.
- System service account, multi-user authorization, DEB/RPM packages, package
  repositories, and man pages (Release 3).
- Full remote environment capabilities (Release 4).
