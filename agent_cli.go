package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	// operationPollInterval is the fixed interval between operation status polls.
	operationPollInterval = 500 * time.Millisecond

	// agentSocketPath is the default Unix socket path for agent-facing CLI commands.
	// Agent containers receive this path via mount; no config.json required.
	agentSocketPath = "/run/docker-helper/docker-helper.sock"
)

// agentClient returns an apiClient configured for the current session.
// It reads the session token from DOCKER_HELPER_SESSION_TOKEN and uses
// the default Unix socket path (no config.json required).
func agentClient() (*apiClient, error) {
	token := os.Getenv("DOCKER_HELPER_SESSION_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("DOCKER_HELPER_SESSION_TOKEN is not set")
	}

	socketPath := os.Getenv("DOCKER_HELPER_SOCKET_PATH")
	if socketPath == "" {
		socketPath = agentSocketPath
	}

	return newUnixAPIClient(socketPath, func() (string, error) {
		return token, nil
	}, nil), nil
}

// waitForOperation polls an operation until it reaches a terminal state.
// It streams logs to stdout as they become available.
// Returns the final operation status response.
func waitForOperation(c *apiClient, opID string, stdout io.Writer) (*operationStatusResponse, error) {
	var offset int64

	for {
		// Fetch and print any new logs.
		logs, err := c.operationLogs(opID, offset)
		if err != nil {
			return nil, err
		}
		if logs.Logs != "" {
			fmt.Fprint(stdout, logs.Logs)
		}
		offset = logs.NextOffset

		// Check operation status.
		status, err := c.operationStatus(opID)
		if err != nil {
			return nil, err
		}

		if status.Status == "succeeded" || status.Status == "failed" {
			// Read remaining logs one final time (always, even if offset == 0).
			finalLogs, err := c.operationLogs(opID, offset)
			if err != nil {
				return nil, err
			}
			if finalLogs.Logs != "" {
				fmt.Fprint(stdout, finalLogs.Logs)
			}
			return status, nil
		}

		time.Sleep(operationPollInterval)
	}
}

var pullCommand = &Command{
	Name:       "pull",
	Summary:    "Pull a Docker image",
	Usage:      "docker-helper pull IMAGE",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				image := fs.Arg(0)

				c, err := agentClient()
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}

				resp, err := c.pull(image)
				if resp != nil && resp.Output != "" {
					fmt.Fprint(stdout, resp.Output)
				}

				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}

				if !resp.OK {
					if resp.Message != "" {
						fmt.Fprintln(stderr, resp.Message)
					}
					return 1
				}

				return 0
			},
		}
	},
}

var buildCommand = &Command{
	Name:    "build",
	Summary: "Build a Docker image",
	Usage:   "docker-helper build --context PATH --dockerfile FILE --image NAME [flags]",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		ctx := fs.String("context", "", "Build context path")
		dockerfile := fs.String("dockerfile", "", "Dockerfile path relative to context")
		image := fs.String("image", "", "Image name and tag")
		var buildArgs stringSlice
		fs.Var(&buildArgs, "build-arg", "Build argument KEY=VALUE (repeatable)")

		return Invocation{
			Validate: func() error {
				if *ctx == "" {
					return fmt.Errorf("--context is required")
				}
				if *dockerfile == "" {
					return fmt.Errorf("--dockerfile is required")
				}
				if *image == "" {
					return fmt.Errorf("--image is required")
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				argsMap := make(map[string]string)
				for _, arg := range buildArgs.vals {
					parts := strings.SplitN(arg, "=", 2)
					if len(parts) != 2 {
						fmt.Fprintf(stderr, "invalid build-arg format: %q (expected KEY=VALUE)\n", arg)
						return 2
					}
					argsMap[parts[0]] = parts[1]
				}

				c, err := agentClient()
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}

				resp, err := c.startBuild(*ctx, *dockerfile, *image, argsMap)
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}

				status, err := waitForOperation(c, resp.OperationID, stdout)
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}

				if status.Status != "succeeded" {
					msg := "build failed"
					if status.ResultCode != "" {
						msg += " (" + status.ResultCode + ")"
					}
					if status.ExitCode != nil {
						msg += fmt.Sprintf(", exit_code=%d", *status.ExitCode)
					}
					fmt.Fprintln(stderr, msg)
					return 1
				}

				return 0
			},
		}
	},
}

// stringSlice is a flag.Value implementation for collecting multiple strings.
type stringSlice struct {
	vals []string
}

func (s *stringSlice) Set(value string) error {
	s.vals = append(s.vals, value)
	return nil
}

func (s *stringSlice) String() string {
	return strings.Join(s.vals, ",")
}

var runContainerCommand = &Command{
	Name:       "run",
	Summary:    "Run a Docker container",
	Usage:      "docker-helper run --image NAME [flags] -- [command]",
	MaxPosArgs: -1, // Unlimited positional args after --
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		image := fs.String("image", "", "Image name and tag")
		entrypoint := fs.String("entrypoint", "", "Container entrypoint")
		workdir := fs.String("workdir", "", "Working directory inside container")
		shmSize := fs.String("shm-size", "", "Size of /dev/shm (e.g. 64m, 1g)")
		var envSlice stringSlice
		var mountSlice stringSlice
		fs.Var(&envSlice, "env", "Environment variable KEY=VALUE (repeatable)")
		fs.Var(&mountSlice, "mount", "Mount SOURCE:TARGET[:ro] (repeatable)")

		return Invocation{
			Validate: func() error {
				if *image == "" {
					return fmt.Errorf("--image is required")
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				// Parse command from remaining args after --
				command := fs.Args()

				envMap := make(map[string]string)
				for _, e := range envSlice.vals {
					parts := strings.SplitN(e, "=", 2)
					if len(parts) != 2 {
						fmt.Fprintf(stderr, "invalid env format: %q (expected KEY=VALUE)\n", e)
						return 2
					}
					envMap[parts[0]] = parts[1]
				}

				var runMounts []startRunMount
				for _, m := range mountSlice.vals {
					parts := strings.Split(m, ":")
					if len(parts) < 2 || len(parts) > 3 {
						fmt.Fprintf(stderr, "invalid mount format: %q (expected SOURCE:TARGET[:ro])\n", m)
						return 2
					}
					rm := startRunMount{
						Source: parts[0],
						Target: parts[1],
					}
					if len(parts) == 3 {
						if parts[2] != "ro" {
							fmt.Fprintf(stderr, "invalid mount option: %q (only 'ro' is supported)\n", parts[2])
							return 2
						}
						rm.ReadOnly = true
					}
					runMounts = append(runMounts, rm)
				}

				c, err := agentClient()
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}

				req := startRunRequest{
					Image:       *image,
					Entrypoint:  *entrypoint,
					Workdir:     *workdir,
					Command:     command,
					Environment: envMap,
					Mounts:      runMounts,
					ShmSize:     *shmSize,
				}

				resp, err := c.startRun(req)
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}

				status, err := waitForOperation(c, resp.OperationID, stdout)
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}

				if status.Status == "succeeded" {
					return 0
				}

				// container_exit_nonzero: return the container's exit code
				if status.ResultCode == "container_exit_nonzero" && status.ExitCode != nil {
					fmt.Fprintf(stderr, "run failed (container_exit_nonzero), exit_code=%d\n", *status.ExitCode)
					return *status.ExitCode
				}

				// Other failures: print diagnostics
				msg := "run failed"
				if status.ResultCode != "" {
					msg += " (" + status.ResultCode + ")"
				}
				if status.ExitCode != nil {
					msg += fmt.Sprintf(", exit_code=%d", *status.ExitCode)
				}
				fmt.Fprintln(stderr, msg)
				return 1
			},
		}
	},
}
