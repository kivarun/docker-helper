// Command d01-engine-gate is the instrument for the Release 3 D0.1 Engine
// adapter compatibility gate defined by docs/release-3-d0-execution-plan.md
// ("Docker Engine adapter gate: D0.1").
//
// It is an independent tool module so that the production module does not
// depend on the Engine client before the gate passes. Run the matrix with:
//
//	go test -v ./...
//
// inside this directory. Mechanism-layer tests (credential encoding, exact
// registry-address canonicalization, stream framing, typed error
// classification, adapter option surface) run on any machine. Every
// Engine-dependent test skips with an actionable reason when no Docker
// Engine endpoint is reachable through the environment (DOCKER_HOST or the
// default /var/run/docker.sock); the full matrix run is recorded as D0.1
// evidence in the owning documents.
//
// Run it on the deployment host, or inside a privileged container that has
// the real Docker Engine socket mounted. Never point it at the docker-helper
// API socket: docker-helper does not proxy the Docker Engine API.
package main

import (
	"fmt"
	"runtime"
)

func main() {
	fmt.Println("d01-engine-gate instrument")
	fmt.Printf("go: %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Println("run the gate matrix with: go test -v ./... (in this directory)")
}
