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

Agent integrations belong at the client edge. Skills, native tool adapters,
and other agent-specific wrappers may translate agent workflows into the stable
capability contract, but they should not introduce agent-specific behavior into
the daemon core.

## Defense in depth is welcome, duplication is not

Docker-native authorization, socket proxies, AppArmor/SELinux, TLS/SSH
transport, and similar mechanisms may be useful underneath or around
docker-helper. They should be used where they strengthen the boundary.
docker-helper should not reimplement them merely to claim ownership of problems
already solved elsewhere.

Its distinctive value is semantic policy at the capability level.

## Simple by default

A user who wants to experiment with agents and containers should not have to
learn the full vocabulary of container runtimes, resource policy, networking,
and infrastructure security before completing a useful workflow.

Common workflows should work with safe, documented defaults and a small stable
product vocabulary. Advanced policy and backend controls should appear only
when a user or operator needs to make an explicit choice. Complexity that
docker-helper must own should not be pushed onto every caller as mandatory
configuration.

This is progressive disclosure, not the removal of control. Operators may tune
the policy boundary, but ordinary users should not have to reproduce that
policy by hand to get started.

## Development philosophy

Develop from demonstrated use cases rather than inventing a platform in
advance. A use case demonstrated by one real operator is still evidence; scale
of adoption is not a prerequisite for solving a real problem.

## Local agent workloads, not production orchestration

docker-helper is designed for local and small shared-host agent workflows where
simple operation, bounded authority, and predictable cleanup matter more than
maximum throughput or continuous availability.

It is not a high-load production orchestrator. It does not promise high
availability, zero-downtime workload management, automatic reconciliation, or
cluster scheduling. Operators with those requirements should use systems built
for them rather than stretching docker-helper into a second orchestration
platform.

## Architectural constraints

- one tool — one capability;
- standalone first;
- integration optional;
- agent-specific integrations live at the client edge, not in the daemon core;
- standardize contracts and conventions, not mandatory shared runtime code;
- preserve remote and multi-session futures without predesigning them;
- prefer the smallest implementation that solves a demonstrated problem;
- keep common workflows simple through safe defaults and progressive
  disclosure;
- keep the agent contract above Docker-specific protocol details where
  practical.
