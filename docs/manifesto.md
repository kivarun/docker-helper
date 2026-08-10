# Project Manifesto

## Purpose

docker-helper exists to give sandboxed AI agents a small set of intentional,
policy-controlled host capabilities without exposing the Docker daemon directly.

## Docker is a backend, not the product interface

docker-helper is not a restricted Docker API and is not a Docker socket proxy.
A proxy starts from the Docker API and decides which Docker requests may pass.
docker-helper starts from an agent use case and defines the smallest capability
that safely satisfies it.

The agent-facing contract should express intent such as build, run, inspect
status, or obtain logs. It should not mirror Docker API objects merely because
Docker exposes them.

## Safe by construction

Capabilities should be narrow enough that dangerous behavior is absent from the
contract rather than accepted first and filtered later. Workspace boundaries,
session ownership, mount policy, environment handling, lifecycle rules, audit
semantics, and similar invariants belong to docker-helper itself.

A useful test for every new feature is:

- What concrete agent use case requires this capability?
- What is the minimum contract that satisfies it?
- Which invariants make that contract safe?
- Are we accidentally exposing another piece of Docker rather than adding an
  agent capability?

If a proposal is primarily "allow one more Docker API operation", it is
probably the wrong abstraction for docker-helper.

## Capability service, not control plane

docker-helper should remain one narrow tool for one capability domain.
Standalone first; integration optional. It should not grow into a mandatory
agent runtime, generic host-command service, or general control plane.

Sessions and workspaces are first-class concepts because they describe the
relationship between an agent and allowed host resources. They are not
implementation details inherited from Docker.

## Defense in depth is welcome, duplication is not

Docker-native authorization, socket proxies, AppArmor/SELinux, TLS/SSH
transport, and similar mechanisms may be useful underneath or around
docker-helper. They should be used where they strengthen the boundary.
docker-helper should not reimplement them merely to claim ownership of problems
already solved elsewhere.

Its distinctive value is semantic policy at the capability level.

## Release philosophy

### 1.0 — Local tool

Prove and polish the capability for local agent work: a stable user service,
local Docker access, clear installation, agent integration, and a narrow
security boundary.

### 2.0 — Professional system/server tool

Turn the proven local capability into a system component for controlled access
to server resources. Remote access is the defining goal. System deployment,
multi-user authorization, distribution packaging and delivery, and
server-oriented security are enabling work toward that goal.

### 3.0+ — Use-case-driven development

Do not invent a platform in advance. Develop from observed use cases after 2.0.
A use case demonstrated by one real operator is still evidence; scale of
adoption is not a prerequisite for solving a real problem.

## Architectural constraints

- one tool — one capability;
- standalone first;
- integration optional;
- standardize contracts and conventions, not mandatory shared runtime code;
- preserve remote and multi-session futures without predesigning them;
- prefer the smallest implementation that solves a demonstrated problem;
- keep the agent contract above Docker-specific protocol details where
  practical.
