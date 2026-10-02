package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestTunCrossOpVehicleHelpAdvertisesRootlessKitFeatures pins the 4C-37
// vehicle's compatibility handshake with RootlessKit's slirp4netns
// feature detection. RootlessKit execs the helper binary with exactly
// ["--help"] and requires the literal feature strings in the combined
// output; the version line is never parsed. A fake helper without them
// is rejected before the vehicle's real invocation ever runs
// ("slirp4netns seems older than v0.4.0"), which silently turns the
// whole proof into NOT_PROVEN — the regression this test guards against.
func TestTunCrossOpVehicleHelpAdvertisesRootlessKitFeatures(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the 4C-37 cross-operation vehicle is a Linux-only proof artifact")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skipf("cc not found in PATH: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "tun-cross-op-vehicle")
	if out, err := exec.Command(cc, "-O2", "-o", bin, "scripts/tun-cross-op-vehicle.c").CombinedOutput(); err != nil {
		t.Fatalf("vehicle build failed: %v: %s", err, out)
	}
	// The exact invocation shape RootlessKit's DetectFeatures uses: a
	// single "--help" argument, output read via CombinedOutput, so the
	// invocation must exit 0 and carry the feature strings on either
	// stdout or stderr.
	combined, err := exec.Command(bin, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("the --help invocation must exit 0 (RootlessKit rejects a failing helper before the launch): %v: %s", err, combined)
	}
	for _, want := range []string{"--netns-type", "--disable-host-loopback"} {
		if !strings.Contains(string(combined), want) {
			t.Errorf("the fake --help output must advertise %q (RootlessKit requires the literal feature strings); got %q", want, combined)
		}
	}
}
