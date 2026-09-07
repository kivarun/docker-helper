// Command cgroup-feasibility-probe is the instrument for the Release 3
// aggregate-cgroup feasibility gate defined by docs/release-3-resource-constraints.md
// ("Enforcement availability and Phase-0 gate") and
// docs/release-3-d0-execution-plan.md ("Resource-enforcement prerequisite").
//
// It reports the environment facts the gate depends on and, when run with
// sufficient privilege on a supported deployment host, creates one
// disposable child cgroup to prove controller delegation writability.
// It performs no other mutation. It is a single-file probe, not a framework;
// the real gate run (hierarchy creation, Docker placement, aggregate
// enforcement, restart, cleanup) is executed by the D0 resource spike against
// a real host, as recorded in the owning documents.
//
// Run as root on a supported deployment host:
//
//	go run ./scripts/cgroup-feasibility-probe
//
// Every line is printed as a stable key: value fact so a run can be recorded
// verbatim in the gate evidence.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const cgroup2Magic = 0x63677270
const tmpfsMagic = 0x01021994

func main() {
	fmt.Println("\n== kernel / init ==")
	report("/proc/sys/kernel/osrelease", "kernel")
	reportMatching("/etc/os-release", "PRETTY_NAME=", "os")
	report("/proc/1/comm", "pid1-comm")
	reportCmdline("/proc/1/cmdline", "pid1-cmdline")

	fmt.Println("\n== process identity / capabilities ==")
	fmt.Printf("euid: %d\n", os.Geteuid())
	reportCapStatus()

	fmt.Println("\n== cgroup filesystem ==")
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/cgroup", &fs); err != nil {
		fmt.Printf("statfs /sys/fs/cgroup: %v\n", err)
	} else {
		switch fs.Type {
		case cgroup2Magic:
			fmt.Println("cgroup-version: v2 (unified)")
		case tmpfsMagic:
			fmt.Println("cgroup version: v1 (tmpfs tree) or cgroupfs not mounted")
		default:
			fmt.Printf("cgroup filesystem type: 0x%x\n", fs.Type)
		}
	}
	report("/proc/self/cgroup", "self-cgroup")
	for _, name := range []string{"cgroup.controllers", "cgroup.subtree_control", "cgroup.type", "cgroup.events"} {
		report(filepath.Join("/sys/fs/cgroup", name), name)
	}

	fmt.Println("\n== delegation write test ==")
	delegationWriteTest()

	fmt.Println("\n== user namespaces (rootless prerequisite) ==")
	report("/proc/sys/kernel/unprivileged_userns_clone", "unprivileged-userns-clone")
	report("/proc/sys/user/max_user_namespaces", "max-user-namespaces")

	fmt.Println("\n== Docker Engine endpoints ==")
	for _, p := range []string{
		"/var/run/docker.sock", "/run/docker.sock",
		"/var/run/docker.sock.helper", "/run/podman/podman.sock",
	} {
		if _, err := os.Stat(p); err == nil {
			fmt.Printf("socket-present: %s\n", p)
		} else {
			fmt.Printf("socket-absent: %s\n", p)
		}
	}
	if v, ok := os.LookupEnv("DOCKER_HOST"); ok {
		fmt.Printf("DOCKER_HOST: %s\n", v)
	} else {
		fmt.Println("DOCKER_HOST: unset")
	}

	fmt.Println("\n== systemd unit presence ==")
	for _, p := range []string{
		"/etc/systemd/system/docker-helper.service",
		"/usr/lib/systemd/system/docker-helper.service",
	} {
		if _, err := os.Stat(p); err == nil {
			fmt.Printf("unit-present: %s\n", p)
		} else {
			fmt.Printf("unit-absent: %s\n", p)
		}
	}
}

func report(path, label string) {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("%s: unavailable (%v)\n", label, err)
		return
	}
	fmt.Printf("%s: %s\n", label, strings.TrimSpace(string(b)))
}

func reportMatching(path, prefix, label string) {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("%s: unavailable (%v)\n", label, err)
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, prefix) {
			fmt.Printf("%s: %s\n", label, strings.TrimSpace(line))
			return
		}
	}
}

func reportCmdline(path, label string) {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("%s: unavailable (%v)\n", label, err)
		return
	}
	fmt.Printf("%s: %q\n", label, strings.ReplaceAll(string(b), "\x00", " "))
}

func reportCapStatus() {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		fmt.Printf("capabilities: unavailable (%v)\n", err)
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "CapEff:") || strings.HasPrefix(line, "CapPrm:") || strings.HasPrefix(line, "CapBnd:") {
			fmt.Println(strings.TrimSpace(line))
		}
	}
}

func delegationWriteTest() {
	probe := filepath.Join("/sys/fs/cgroup", "dh-cgroup-feasibility-probe")
	if err := os.Mkdir(probe, 0o755); err != nil {
		fmt.Printf("mkdir-child-cgroup: %v\n", err)
		return
	}
	fmt.Println("mkdir-child-cgroup: OK")
	report(filepath.Join(probe, "cgroup.controllers"), "child-cgroup.controllers")
	ctl := filepath.Join(probe, "cgroup.subtree_control")
	if err := os.WriteFile(ctl, []byte("+cpu +memory +pids"), 0o644); err != nil {
		fmt.Printf("enable-child-controllers: %v\n", err)
	} else {
		report(ctl, "enable-child-controllers")
	}
	if err := os.Remove(probe); err != nil {
		fmt.Printf("cleanup-child-cgroup: %v\n", err)
	} else {
		fmt.Println("cleanup-child-cgroup: OK")
	}
}
