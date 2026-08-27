package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

var registryCommand = &Command{
	Name:    "registry",
	Summary: "Registry operations",
	Subcommands: []*Command{
		registryLoginCommand,
	},
}

var registryLoginCommand = &Command{
	Name:    "login",
	Summary: "Log in to a container registry",
	Usage:   "docker-helper registry login --registry REGISTRY --username USER",
	Help: `Log in to a container registry for the current session.

Credentials are session-scoped and ephemeral. They are stored in the
session's Docker config directory and are not inherited from the host
~/.docker/config.json.

Session token is read from DOCKER_HELPER_SESSION_TOKEN.

Password input:
  - Interactive: when stdin is a terminal and --password-stdin is not
    supplied, the password is prompted without echo.
  - Automation: pipe the password via stdin with --password-stdin.

Examples:

  Interactive:
    DOCKER_HELPER_SESSION_TOKEN="$TOKEN" \
    docker-helper registry login \
      --registry registry.example.com \
      --username user

  Automation:
    printf '%s\n' "$REGISTRY_PASSWORD" |
    DOCKER_HELPER_SESSION_TOKEN="$TOKEN" \
    docker-helper registry login \
      --registry registry.example.com \
      --username user \
      --password-stdin`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint := registerAgentEndpointFlags(fs)
		registry := fs.String("registry", "", "Registry address")
		username := fs.String("username", "", "Registry username")
		passwordStdin := fs.Bool("password-stdin", false, "Read password from stdin")
		jsonOut := fs.Bool("json", false, "Output in JSON format")

		return Invocation{
			Validate: func() error {
				if *registry == "" || strings.HasPrefix(*registry, "-") {
					return fmt.Errorf("--registry is required")
				}
				if *username == "" || strings.HasPrefix(*username, "-") {
					return fmt.Errorf("--username is required")
				}
				return validateAgentEndpointOptions(agentClientOptions{System: *system, Endpoint: *endpoint})
			},
			Run: func(stdout, stderr io.Writer) int {
				var password string
				var err error

				if *passwordStdin {
					password, err = readPasswordFromStdin()
				} else if term.IsTerminal(int(os.Stdin.Fd())) {
					password, err = promptPassword(stderr)
				} else {
					fmt.Fprintln(stderr, "error: use --password-stdin to read password from stdin in non-interactive mode")
					return 1
				}

				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				client, err := resolveAgentClient(agentClientOptions{System: *system, Endpoint: *endpoint})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				result, err := client.registryLogin(*registry, *username, password)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				if *jsonOut {
					enc := json.NewEncoder(stdout)
					enc.SetIndent("", "  ")
					if err := enc.Encode(result); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode JSON: %v\n", err)
						return 1
					}
					return 0
				}

				fmt.Fprintf(stdout, "Login succeeded for %s\n", *registry)
				return 0
			},
		}
	},
}

func readPasswordFromStdin() (string, error) {
	// Read exactly one line from stdin, removing the trailing line ending.
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return "", fmt.Errorf("failed to read password from stdin")
	}
	return scanner.Text(), nil
}

func promptPassword(stderr io.Writer) (string, error) {
	fmt.Fprint(stderr, "Registry password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(password), nil
}

func init() {
	rootCommand.Subcommands = append(rootCommand.Subcommands, registryCommand)
}
