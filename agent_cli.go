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
)

// agentClientOptions specifies how an agent-facing command connects to a daemon.
// Agent commands authenticate with the Session token (DOCKER_HELPER_SESSION_TOKEN),
// never a Principal credential; these options only select the transport endpoint.
type agentClientOptions struct {
	System   bool   // --system: force the system daemon socket
	Endpoint string // --endpoint: explicit endpoint URL
}

// registerAgentEndpointFlags adds --system and --endpoint to an agent command's
// FlagSet and returns pointers to their values.
func registerAgentEndpointFlags(fs *flag.FlagSet) (system *bool, endpoint *string) {
	system = fs.Bool("system", false, "Connect to system daemon")
	endpoint = fs.String("endpoint", "", "Explicit endpoint (/path/to/socket, unix:///path, or http://127.0.0.1:port)")
	return
}

// resolveAgentSocketPath returns the Unix socket path for agent-facing CLI commands.
// Resolution precedence:
//  1. DOCKER_HELPER_SOCKET_PATH if set
//  2. $XDG_RUNTIME_DIR/docker-helper/docker-helper.sock if that user-mode socket exists
//  3. systemSocketPath (/run/docker-helper/docker-helper.sock, system/sandbox default)
//
// The presence of XDG_RUNTIME_DIR alone does not select a nonexistent user socket;
// agent commands fall back to the system socket when no user-mode daemon is present.
func resolveAgentSocketPath() string {
	if socketPath := os.Getenv("DOCKER_HELPER_SOCKET_PATH"); socketPath != "" {
		return socketPath
	}
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		userSocket := filepath.Join(runtimeDir, "docker-helper", "docker-helper.sock")
		if userSocketExists(userSocket) {
			return userSocket
		}
	}
	return systemSocketPath
}

// validateAgentEndpointOptions validates the CLI-only --system/--endpoint
// combination for an agent command. It must run during Invocation.Validate,
// before any runtime authentication lookup, so a usage error is reported with
// exit code 2 even when DOCKER_HELPER_SESSION_TOKEN is unset.
func validateAgentEndpointOptions(opts agentClientOptions) error {
	if opts.System && opts.Endpoint != "" {
		return fmt.Errorf("--system and --endpoint are mutually exclusive")
	}
	if opts.Endpoint != "" {
		return validateEndpoint(opts.Endpoint)
	}
	return nil
}

// resolveAgentClient resolves the agent-facing client for the given endpoint
// options. The Session token is always read from DOCKER_HELPER_SESSION_TOKEN.
// CLI usage conditions (mutual exclusion, endpoint format) are expected to have
// been validated by validateAgentEndpointOptions; this function reports only
// runtime errors such as a missing session token.
func resolveAgentClient(opts agentClientOptions) (*apiClient, error) {
	token := os.Getenv("DOCKER_HELPER_SESSION_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("DOCKER_HELPER_SESSION_TOKEN is not set")
	}
	if tokenHasEmbeddedWhitespace(token) {
		return nil, fmt.Errorf("DOCKER_HELPER_SESSION_TOKEN contains whitespace; expected a single bearer token line")
	}
	tokenSource := func() (string, error) { return token, nil }

	if opts.Endpoint != "" {
		return resolveAgentEndpoint(opts.Endpoint, tokenSource)
	}
	if opts.System {
		return newUnixAPIClient(systemSocketPath, tokenSource, nil), nil
	}
	return newUnixAPIClient(resolveAgentSocketPath(), tokenSource, nil), nil
}

// resolveAgentEndpoint resolves an explicit endpoint for an agent command.
// Unlike operator commands, the authentication token comes from the environment
// (the Session token), so an http endpoint does not require --token-file.
func resolveAgentEndpoint(endpoint string, tokenSource func() (string, error)) (*apiClient, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	if strings.HasPrefix(endpoint, "unix://") {
		return newUnixAPIClient(strings.TrimPrefix(endpoint, "unix://"), tokenSource, nil), nil
	}
	if strings.HasPrefix(endpoint, "/") {
		return newUnixAPIClient(endpoint, tokenSource, nil), nil
	}
	addr := strings.TrimPrefix(endpoint, "http://")
	return newHTTPAPIClient(addr, tokenSource, nil), nil
}

// waitForOperationContext polls an operation until it reaches a terminal state.
// If ctx is cancelled, it returns immediately with ctx.Err().
func waitForOperationContext(ctx context.Context, c *apiClient, opID string, stdout, stderr io.Writer) (*operationStatusResponse, error) {
	var offset int64
	truncated := false

	for {
		// Fetch and print any new logs.
		logs, err := c.operationLogs(ctx, opID, offset)
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
		status, err := c.operationStatus(ctx, opID)
		if err != nil {
			return nil, err
		}

		if status.Status == operationSucceeded || status.Status == operationFailed {
			// Read remaining logs one final time (always, even if offset == 0).
			finalLogs, err := c.operationLogs(ctx, opID, offset)
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
// On signal, it stops polling, performs an at-most-once bounded synchronous
// best-effort cancel, waits for the polling goroutine to exit, and returns a
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
		tryCancel() // bounded synchronous best-effort daemon cancel
		<-resultCh  // wait for goroutine to exit (no orphan)
		return nil, &signalExitError{Signal: sig}
	case res := <-resultCh:
		return res.status, res.err
	}
}

var pullCommand = &Command{
	Name:       "pull",
	Summary:    "Pull a Docker image",
	Usage:      "docker-helper pull [--system] [--endpoint ENDPOINT] IMAGE",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint := registerAgentEndpointFlags(fs)
		return Invocation{
			Validate: func() error {
				return validateAgentEndpointOptions(agentClientOptions{System: *system, Endpoint: *endpoint})
			},
			Run: func(stdout, stderr io.Writer) int {
				image := fs.Arg(0)

				c, err := resolveAgentClient(agentClientOptions{System: *system, Endpoint: *endpoint})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				resp, err := c.pull(pullRequest{Image: image})
				if resp != nil && resp.Output != "" {
					// On success, pull progress is the requested command
					// result and stays on stdout (docker-pull compatible and
					// preserved for scripts). On failure, the docker error
					// diagnostic is routed to stderr with the summary error.
					if err != nil {
						fmt.Fprint(stderr, resp.Output)
					} else {
						fmt.Fprint(stdout, resp.Output)
					}
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
	Help:    `SIGINT/SIGTERM cancels the running build request.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint := registerAgentEndpointFlags(fs)
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
				if err := validateAgentEndpointOptions(agentClientOptions{System: *system, Endpoint: *endpoint}); err != nil {
					return err
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

				c, err := resolveAgentClient(agentClientOptions{System: *system, Endpoint: *endpoint})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				// SIGINT/SIGTERM cancels the in-flight build request; the
				// daemon returns the terminal cancelled result.
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
				defer signal.Stop(sigCh)

				reqCtx, cancelReq := context.WithCancel(context.Background())
				defer cancelReq()

				var cancelOnce sync.Once
				tryCancel := func() {
					cancelOnce.Do(func() {
						cancelReq()
					})
				}

				type buildOutcome struct {
					resp *buildResponse
					err  error
				}
				resultCh := make(chan buildOutcome, 1)
				go func() {
					resp, err := c.build(reqCtx, buildRequest{
						Context:    *ctx,
						Dockerfile: *dockerfile,
						Image:      *image,
						BuildArgs:  argsMap,
					})
					resultCh <- buildOutcome{resp, err}
				}()

				select {
				case sig := <-sigCh:
					tryCancel()
					outcome := <-resultCh
					if outcome.err != nil && outcome.resp == nil {
						fmt.Fprintf(stderr, "warning: build did not return a result: %v\n", outcome.err)
					}
					return signalExitCode(sig)
				case outcome := <-resultCh:
					resp, err := outcome.resp, outcome.err
					if err != nil {
						fmt.Fprintf(stderr, "error: %v\n", err)
						if resp != nil && resp.Output != "" {
							fmt.Fprintf(stderr, "build output:\n%s", resp.Output)
							if resp.Truncated {
								fmt.Fprintln(stderr, "build output truncated")
							}
						}
						return 1
					}

					if resp.Truncated {
						fmt.Fprintln(stderr, "build output truncated")
					}
					fmt.Fprint(stdout, resp.Output)
					return 0
				}
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
		system, endpoint := registerAgentEndpointFlags(fs)
		image := fs.String("image", "", "Image name and tag")
		entrypoint := fs.String("entrypoint", "", "Container entrypoint")
		workdir := fs.String("workdir", "", "Absolute working directory inside container")
		shmSize := fs.String("shm-size", "", "Size of /dev/shm (e.g. 64m, 1g); max 2g")
		helperSocket := fs.Bool("helper-socket", false, "Make the helper socket reachable in the container (system mode)")
		var envSlice stringSlice
		var envFromSlice stringSlice
		var mountSlice stringSlice
		fs.Var(&envSlice, "env", "Environment variable KEY=VALUE (repeatable)")
		fs.Var(&envFromSlice, "env-from", "Environment variable DEST=SOURCE; value comes from this process environment (repeatable)")
		fs.Var(&mountSlice, "mount", "Mount WORKSPACE_RELATIVE_SOURCE:ABSOLUTE_TARGET[:ro] (repeatable)")

		return Invocation{
			Validate: func() error {
				if *image == "" {
					return fmt.Errorf("--image is required")
				}
				return validateAgentEndpointOptions(agentClientOptions{System: *system, Endpoint: *endpoint})
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

				// Resolve --env-from entries: DEST takes its value from this
				// CLI process environment. Resolution is local and fail-closed:
				// an unset SOURCE stops the command before any run Operation
				// is created. A resolved value exists only in the request body
				// (the existing run environment contract); it is not placed in
				// this CLI process's argv, is not printed in CLI diagnostics,
				// and the daemon does not log environment values. Known 2.1.x
				// limitation: the legacy run implementation passes the value
				// to the daemon-side docker CLI as --env argv, so the value
				// can appear in that child process's argv
				// (see docs/architecture.md).
				for _, spec := range envFromSlice.vals {
					parts := strings.SplitN(spec, "=", 2)
					if len(parts) != 2 {
						fmt.Fprintf(stderr, "invalid env-from format: %q (expected DEST=SOURCE)\n", spec)
						return 2
					}
					value, ok := os.LookupEnv(parts[1])
					if !ok {
						fmt.Fprintf(stderr, "environment variable %q is not set\n", parts[1])
						return 2
					}
					envMap[parts[0]] = value
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

				c, err := resolveAgentClient(agentClientOptions{System: *system, Endpoint: *endpoint})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				req := runRequest{
					Image:        *image,
					Entrypoint:   *entrypoint,
					Workdir:      *workdir,
					Command:      command,
					Environment:  envMap,
					Mounts:       runMounts,
					ShmSize:      *shmSize,
					HelperSocket: *helperSocket,
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
