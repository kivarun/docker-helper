// Command h6-rename-proof is the exact-policy rename-destination probe for the
// SC1/H6 SELinux admin-token lifecycle (PR review round 2, architecture
// warning check). It must run inside the ENFORCING docker_helper_t domain; the
// guest driver starts it through a systemd transient service carrying the
// shipped SELinuxContext= and executes a binary relabeled docker_helper_exec_t
// by the operator, so hosting the probe requires NO policy change: init_t ->
// docker_helper_t transition, entrypoint and execute on docker_helper_exec_t
// are all granted by the shipped module for the real service.
//
// The probe MEASURES, it does not decide the gate. It records the enforcing
// outcome of:
//
//   - creating /etc/docker-helper/.admin-token.new as docker_helper_t (the
//     exact filename transition must label it docker_helper_admin_token_t);
//   - renaming that token_t inode to an otherwise unused config-dir pathname
//     (the review hypothesis: type_transition constrains the CREATED type,
//     not the later rename destination);
//   - the negative proofs that existing docker_helper_config_t objects stay
//     immutable (write-open, unlink, rename away, overwrite by rename onto the
//     existing inode) and that an arbitrary NEW config-dir name cannot be
//     created by the daemon domain;
//
// and writes one JSON document to the result path given as argv[1]. It never
// touches the real admin.token, never relabels config state, and removes every
// object it created. The driver maps the recorded outcomes onto the gate.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const (
	configDir    = "/etc/docker-helper"
	stagingPath  = configDir + "/.admin-token.new"
	unusedPath   = configDir + "/h6-unused-name"
	configPath   = configDir + "/config.json"
	configRename = configDir + "/h6-config-renamed"
	freshPath    = configDir + "/h6-fresh-name"
)

type record struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Dest  string `json:"dest,omitempty"`
	Ok    bool   `json:"ok"`
	Errno string `json:"errno,omitempty"`
	Label string `json:"label,omitempty"`
	Note  string `json:"note,omitempty"`
}

type result struct {
	Domain    string   `json:"domain"`
	Enforcing bool     `json:"enforcing"`
	Steps     []record `json:"steps"`
}

func errnoName(err error) string {
	if err == nil {
		return ""
	}
	switch e := err.(type) {
	case syscall.Errno:
		switch e {
		case syscall.EACCES:
			return "EACCES"
		case syscall.EPERM:
			return "EPERM"
		case syscall.EEXIST:
			return "EEXIST"
		case syscall.ENOENT:
			return "ENOENT"
		case syscall.EISDIR:
			return "EISDIR"
		case syscall.ENOTDIR:
			return "ENOTDIR"
		case syscall.EROFS:
			return "EROFS"
		case syscall.EXDEV:
			return "EXDEV"
		case syscall.EINVAL:
			return "EINVAL"
		case syscall.ENOTEMPTY:
			return "ENOTEMPTY"
		case syscall.ENAMETOOLONG:
			return "ENAMETOOLONG"
		}
		return "errno-" + strconv.Itoa(int(e))
	}
	return "error"
}

func fatal(res *result, code int, msg string) {
	res.Steps = append(res.Steps, record{Op: "fatal", Note: msg})
	emit(res, "")
	fmt.Fprintln(os.Stderr, "fatal: "+msg)
	os.Exit(code)
}

func emit(res *result, outPath string) {
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot marshal result: "+err.Error())
		os.Exit(6)
	}
	data = append(data, '\n')
	fmt.Print(string(data))
	if outPath == "" {
		return
	}
	if err := os.WriteFile(outPath, data, 0600); err != nil {
		fmt.Fprintln(os.Stderr, "cannot write result file "+outPath+": "+err.Error())
		os.Exit(6)
	}
}

func selinuxLabel(path string) string {
	buf := make([]byte, 256)
	n, err := syscall.Getxattr(path, "security.selinux", buf)
	if err != nil || n <= 0 {
		return ""
	}
	return strings.TrimRight(string(buf[:n]), "\x00")
}

func main() {
	res := &result{}
	if len(os.Args) < 2 {
		fatal(res, 6, "usage: h6-rename-proof <result-path>")
	}
	outPath := os.Args[1]

	domain, _ := os.ReadFile("/proc/self/attr/current")
	res.Domain = strings.TrimSpace(string(domain))
	if !strings.Contains(res.Domain, "docker_helper_t") {
		fatal(res, 4, "probe refused to run outside docker_helper_t (context '"+res.Domain+"')")
	}
	enf, err := os.ReadFile("/sys/fs/selinux/enforce")
	res.Enforcing = err == nil && strings.TrimSpace(string(enf)) == "1"
	if !res.Enforcing {
		fatal(res, 3, "probe refused to run outside enforcing mode")
	}

	// 1. Create the exact staging pathname as docker_helper_t. With no other
	// type_transition in the config dir, the kernel must apply the exact
	// ".admin-token.new" filename transition and label the inode
	// docker_helper_admin_token_t.
	fd, err := syscall.Open(stagingPath,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0600)
	res.Steps = append(res.Steps, record{
		Op: "create-staging", Path: stagingPath,
		Ok: err == nil, Errno: errnoName(err),
		Note: "exact filename transition must label the inode docker_helper_admin_token_t",
	})
	if err != nil {
		emit(res, outPath)
		fatal(res, 5, "staging creation failed ("+errnoName(err)+"): the probe cannot measure the rename outcome")
	}
	if err := syscall.Close(fd); err != nil {
		emit(res, outPath)
		fatal(res, 6, "cannot close the staging fd: "+err.Error())
	}
	res.Steps = append(res.Steps, record{
		Op: "staging-label", Path: stagingPath,
		Ok: selinuxLabel(stagingPath) == "unconfined_u:object_r:docker_helper_admin_token_t:s0" ||
			strings.Contains(selinuxLabel(stagingPath), "docker_helper_admin_token_t"),
		Label: selinuxLabel(stagingPath),
		Note:  "created inode type; expected docker_helper_admin_token_t via the exact filename transition",
	})

	// 2. THE MEASURED VERDICT: rename the token_t inode to an otherwise
	// UNUSED config-dir pathname. No destination object exists, so the only
	// required permissions are remove_name/search on the old dir, rename on
	// the token_t inode, and add_name/search on the new dir.
	err = syscall.Rename(stagingPath, unusedPath)
	res.Steps = append(res.Steps, record{
		Op: "rename-token-to-unused", Path: stagingPath, Dest: unusedPath,
		Ok: err == nil, Errno: errnoName(err),
		Note: "MEASURED VERDICT: enforcing outcome of renaming a created token_t inode to an unused config-dir name",
	})
	// 2b. If the rename moved the inode, rename it back to the exact staging
	// pathname so the state is restored for the overwrite negative below.
	if err == nil {
		err = syscall.Rename(unusedPath, stagingPath)
		res.Steps = append(res.Steps, record{
			Op: "rename-token-back-to-staging", Path: unusedPath, Dest: stagingPath,
			Ok: err == nil, Errno: errnoName(err),
			Note: "restore the exact staging pathname for the overwrite negative",
		})
		if err != nil {
			emit(res, outPath)
			fatal(res, 6, "cannot rename the token inode back to the staging pathname ("+errnoName(err)+")")
		}
	}

	// 3. Negative proofs: existing docker_helper_config_t objects must stay
	// immutable, and an arbitrary NEW config-dir name must not be creatable.
	// Every step records the enforcing outcome; the driver asserts the
	// expected EACCES.
	fd, err = syscall.Open(configPath, syscall.O_WRONLY, 0)
	if err == nil {
		syscall.Close(fd)
	}
	res.Steps = append(res.Steps, record{
		Op: "config-write-open", Path: configPath,
		Ok: err == nil, Errno: errnoName(err),
		Note: "expected denied: write on docker_helper_config_t:file is not granted",
	})

	err = syscall.Unlink(configPath)
	res.Steps = append(res.Steps, record{
		Op: "config-unlink", Path: configPath,
		Ok: err == nil, Errno: errnoName(err),
		Note: "expected denied: unlink on docker_helper_config_t:file is not granted",
	})

	err = syscall.Rename(configPath, configRename)
	res.Steps = append(res.Steps, record{
		Op: "config-rename-away", Path: configPath, Dest: configRename,
		Ok: err == nil, Errno: errnoName(err),
		Note: "expected denied: rename on docker_helper_config_t:file is not granted",
	})

	err = syscall.Rename(stagingPath, configPath)
	res.Steps = append(res.Steps, record{
		Op: "token-overwrite-config", Path: stagingPath, Dest: configPath,
		Ok: err == nil, Errno: errnoName(err),
		Note: "expected denied: a rename onto the existing config.json needs unlink on docker_helper_config_t:file, which is not granted",
	})

	fd, err = syscall.Open(freshPath,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0600)
	if err == nil {
		syscall.Close(fd)
	}
	res.Steps = append(res.Steps, record{
		Op: "config-create-fresh-name", Path: freshPath,
		Ok: err == nil, Errno: errnoName(err),
		Note: "expected denied: without a filename transition a fresh config-dir name inherits docker_helper_config_t and create is not granted",
	})

	// 4. Cleanup: remove every object the probe created. Unlink of a
	// token_t object is granted; a failed negative (unexpected allow) is
	// reported honestly rather than hidden.
	cleanup := []string{stagingPath, unusedPath, freshPath}
	for _, p := range cleanup {
		if err := syscall.Unlink(p); err != nil && err != syscall.ENOENT {
			res.Steps = append(res.Steps, record{
				Op: "cleanup", Path: p,
				Ok: false, Errno: errnoName(err),
				Note: "probe cleanup failed; the driver must report this",
			})
		}
	}

	emit(res, outPath)
}
