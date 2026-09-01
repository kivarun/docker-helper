#!/usr/bin/env bash
#
# test-packaging-integration.sh — CI-facing owner of the packaging/build
# integration test group. Runs exactly the packaging integration Go tests with
# DOCKER_HELPER_PACKAGING_INTEGRATION=1 so a missing required packaging tool is
# a hard failure instead of a silent skip.
#
# This is NOT the package acceptance proof: exact-artifact UAT remains the
# authoritative package acceptance proof. This script only verifies the
# packaging integration contract (package build + metadata) executes with its
# required toolchain.
#
# Requires the packaging build toolchain installed on PATH:
#   nfpm musl-gcc checkmodule semodule_package gzip rpm dpkg-deb
# (see scripts/install-nfpm.sh and the packaging-integration CI job).
#
# Usage: scripts/test-packaging-integration.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

export DOCKER_HELPER_PACKAGING_INTEGRATION=1

# Anchored to the exact packaging integration tests so this script never runs
# the entire repository test suite a second time and never silently matches
# zero tests.
go test ./... \
  -run '^(TestPackageMetadataIntegration|TestPackageSELinuxPayloadSeparation|TestPackageBuildIntegration|TestBuildSelinuxPolicyHelperProducesPP|TestPackageMetadataScripts|TestBuildManpagesScriptBuilds|TestPackageMetadataManPages|TestPackageBashCompletion)$'
