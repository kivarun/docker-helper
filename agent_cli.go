package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// operationPollInterval is the fixed interval between operation status polls.
	operationPollInterval = 500 * time.Millisecond

	// agentSocketPath is the fallback Unix socket path for agent-facing CLI
	// commands when neither DOCKER_HELPER_SOCKET_PATH nor XDG_RUNTIME_DIR
	// are set (system/sandbox default).
	agentSocketPath = "/run/docker-helper/docker-helper.sock"
)

// resolveAgentSocketPath returns the Unix socket path for agent-facing CLI commands.
// Precedence:
//  1. DOCKER_HELPER_SOCKET_PATH if set
//  2. $XDG_RUNTIME_DIR/docker-helper/docker-helper.sock if XDG_RUNTIME_DIR is set
//  3. /run/docker-helper/docker-helper.sock (system/sandbox default)
func resolveAgentSocketPath() string {
	if socketPath := os.Getenv("DOCKER_HELPER_SOCKET_PATH"); socketPath != "" {
		return socketPath
	}
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		return filepath.Join(runtimeDir, "docker-helper", "docker-helper.sock")
	}
	return agentSocketPath
}

// agentClient returns an apiClient configured for the current session.
// It reads the session token from DOCKER_HELPER_SESSION_TOKEN and uses
// the default Unix socket path (no config.json required).
func agentClient() (*apiClient, error) {
	token := os.Getenv("DOCKER_HELPER_SESSION_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("DOCKER_HELPER_SESSION_TOKEN is not set")
	}

	return newUnixAPIClient(resolveAgentSocketPath(), func() (string, error) {
		return token, nil
	}, nil), nil
}

// waitForOperationContext polls an operation until it reaches a terminal state.
// If ctx is cancelled, it returns immediately with ctx.Err().
func waitForOperationContext(ctx context.Context, c *apiClient, opID string, stdout, stderr io.Writer) (*operationStatusResponse, error) {
	var offset int64
	truncated := false

	for {
		// Fetch and print any new logs.
		logs, err := c.operationLogsCtx(ctx, opID, offset)
		if err != nil {
			return nil, err
		}
		if logs.Logs != "" {
			fmt.Fprint(stdout, logs.Logs)
		}
		if logs.Truncated && !truncated {
			truncated = true
			fmt.Fprintln(stderr, "warning: operation log was truncated")
		}
		offset = logs.NextOffset

		// Check operation status.
		status, err := c.operationStatusCtx(ctx, opID)
		if err != nil {
			return nil, err
		}

		if status.Status == operationSucceeded || status.Status == operationFailed {
			// Read remaining logs one final time (always, even if offset == 0).
			finalLogs, err := c.operationLogsCtx(ctx, opID, offset)
			if err != nil {
				return nil, err
			}
			if finalLogs.Logs != "" {
				fmt.Fprint(stdout, finalLogs.Logs)
			}
			if finalLogs.Truncated && !truncated {
				fmt.Fprintln(stderr, "warning: operation log was truncated")
			}
			return status, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(operationPollInterval):
		}
	}
}

// signalExitError indicates the CLI was interrupted by a signal.
// The Signal field holds the received os.Signal.
type signalExitError struct {
	Signal os.Signal
}

func (e *signalExitError) Error() string {
	return fmt.Sprintf("interrupted by %s", e.Signal)
}

// signalExitCode returns the conventional exit code for the given signal.
func signalExitCode(sig os.Signal) int {
	switch sig {
	case syscall.SIGINT:
		return 130
	case syscall.SIGTERM:
		return 143
	default:
		return 1
	}
}

// waitForOperationWithSignal polls an operation while watching for SIGINT/SIGTERM.
// On signal, it fires a best-effort cancel (at most once) and returns a
// signalExitError so the caller can exit with the correct code.
// On normal completion, it returns the operation status as usual.
func waitForOperationWithSignal(c *apiClient, opID string, stdout, stderr io.Writer) (*operationStatusResponse, error) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	return waitForOperationWithSignalCh(c, opID, stdout, stderr, sigCh)
}

// waitForOperationWithSignalCh is the testable core of waitForOperationWithSignal.
// It accepts a pre-configured signal channel so tests can inject signals.
func waitForOperationWithSignalCh(c *apiClient, opID string, stdout, stderr io.Writer, sigCh <-chan os.Signal) (*operationStatusResponse, error) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	var cancelOnce sync.Once

	tryCancel := func() {
		cancelOnce.Do(func() {
			if err := c.cancelOperation(opID); err != nil {
				fmt.Fprintf(stderr, "warning: cancel failed: %v\n", err)
			}
		})
	}

	resultCh := make(chan struct {
		status *operationStatusResponse
		err    error
	}, 1)

	go func() {
		status, err := waitForOperationContext(ctx, c, opID, stdout, stderr)
		resultCh <- struct {
			status *operationStatusResponse
			err    error
		}{status, err}
	}()

	select {
	case sig := <-sigCh:
		cancelCtx() // stop poll goroutine immediately
		tryCancel() // best-effort daemon cancel
		<-resultCh  // wait for goroutine to exit (no orphan)
		return nil, &signalExitError{Signal: sig}
	case res := <-resultCh:
		return res.status, res.err
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
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				resp, err := c.pull(pullRequest{Image: image})
				if resp != nil && resp.Output != "" {
					fmt.Fprint(stdout, resp.Output)
				}

				if resp != nil && resp.Truncated {
					fmt.Fprintln(stderr, "warning: pull output was truncated")
				}

				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
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
	Help:    `SIGINT/SIGTERM cancels the running build operation.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		ctx := fs.String("context", "", "Build context path relative to session workspace")
		dockerfile := fs.String("dockerfile", "", "Dockerfile path relative to context")
		image := fs.String("image", "", "Image name and tag")
		var buildArgs stringSlice
		fs.Var(&buildArgs, "build-arg", "Build argument KEY=VALUE (repeatable)")

		return Invocation{
			Validate: func() error {
				if *ctx == "" {
					return fmt.Errorf("--context is required")
				}
				if filepath.IsAbs(*ctx) {
					return fmt.Errorf("--context must be relative to session workspace")
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
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				resp, err := c.startBuild(buildRequest{
					Context:    *ctx,
					Dockerfile: *dockerfile,
					Image:      *image,
					BuildArgs:  argsMap,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				status, err := waitForOperationWithSignal(c, resp.OperationID, stdout, stderr)
				if err != nil {
					if sigErr, ok := err.(*signalExitError); ok {
						return signalExitCode(sigErr.Signal)
					}
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				if status.Status != operationSucceeded {
					msg := "build failed"
					if status.ResultCode != nil {
						msg += " (" + *status.ResultCode + ")"
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
	Help:       `SIGINT/SIGTERM cancels the running container operation.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		image := fs.String("image", "", "Image name and tag")
		entrypoint := fs.String("entrypoint", "", "Container entrypoint")
		workdir := fs.String("workdir", "", "Absolute working directory inside container")
		shmSize := fs.String("shm-size", "", "Size of /dev/shm (e.g. 64m, 1g); max 2g")
		var envSlice stringSlice
		var mountSlice stringSlice
		fs.Var(&envSlice, "env", "Environment variable KEY=VALUE (repeatable)")
		fs.Var(&mountSlice, "mount", "Mount WORKSPACE_RELATIVE_SOURCE:ABSOLUTE_TARGET[:ro] (repeatable)")

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

				var runMounts []mountRequest
				for _, m := range mountSlice.vals {
					parts := strings.Split(m, ":")
					if len(parts) < 2 || len(parts) > 3 {
						fmt.Fprintf(stderr, "invalid mount format: %q (expected SOURCE:TARGET[:ro])\n", m)
						return 2
					}
					source := parts[0]
					target := parts[1]

					// Validate source is relative to workspace
					if filepath.IsAbs(source) {
						fmt.Fprintf(stderr, "invalid mount source %q: source must be relative to session workspace\n", source)
						return 2
					}

					// Validate target is absolute
					if !filepath.IsAbs(target) {
						fmt.Fprintf(stderr, "invalid mount target %q: target must be an absolute path\n", target)
						return 2
					}

					rm := mountRequest{
						Source: source,
						Target: target,
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
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				req := runRequest{
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
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				status, err := waitForOperationWithSignal(c, resp.OperationID, stdout, stderr)
				if err != nil {
					if sigErr, ok := err.(*signalExitError); ok {
						return signalExitCode(sigErr.Signal)
					}
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				if status.Status == "succeeded" {
					return 0
				}

				// container_exit_nonzero: return the container's exit code
				if status.ResultCode != nil && *status.ResultCode == "container_exit_nonzero" && status.ExitCode != nil {
					fmt.Fprintf(stderr, "run failed (container_exit_nonzero), exit_code=%d\n", *status.ExitCode)
					return *status.ExitCode
				}

				// Other failures: print diagnostics
				msg := "run failed"
				if status.ResultCode != nil {
					msg += " (" + *status.ResultCode + ")"
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
