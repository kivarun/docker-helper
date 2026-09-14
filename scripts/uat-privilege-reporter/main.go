// Command privilege-reporter prints the executing process's identity and
// effective capabilities for the Release 2.2 hostile workload
// privilege-floor UAT (scenarios W11/W13 and S14/S16): a root-owned SUID
// copy of this binary must report the workload's own uid/euid and an empty
// effective capability set once the server-owned privilege floor
// (no-new-privileges + cap-drop ALL) is enforced, and must never report
// euid=0.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	caps := ""
	if f, err := os.Open("/proc/self/status"); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			t := s.Text()
			if strings.HasPrefix(t, "CapEff:") {
				caps = strings.TrimSpace(strings.TrimPrefix(t, "CapEff:"))
			}
		}
	}
	fmt.Printf("uid=%d euid=%d capEff=%s\n", os.Getuid(), os.Geteuid(), caps)
}
