package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
)

var principalCommand = &Command{
	Name:    "principal",
	Summary: "Manage principals",
	Subcommands: []*Command{
		principalCreateCommand,
		principalShowCommand,
		principalSetCommand,
		principalAllowedRootCommand,
	},
}

var credentialCommand = &Command{
	Name:    "credential",
	Summary: "Manage principal credentials",
	Subcommands: []*Command{
		credentialCreateCommand,
		credentialListCommand,
		credentialRevokeCommand,
	},
}

var principalCreateCommand = &Command{
	Name:       "create",
	Summary:    "Create a new principal",
	Usage:      "docker-helper principal create USER",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]

				socketPath, adminTokenPath, err := adminAPIPaths()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				tokenSource, err := adminAPITokenSource(adminTokenPath)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				client := newUnixAPIClient(socketPath, tokenSource, nil)

				body, err := json.Marshal(createPrincipalRequest{Username: username})
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot encode request: %v\n", err)
					return 1
				}

				resp, err := client.doAuthenticatedRequest("POST", "/principals", bytes.NewReader(body))
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				defer resp.Body.Close()

				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot read response: %v\n", err)
					return 1
				}

				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					apiErr := parseApiError(resp.StatusCode, respBody)
					fmt.Fprintf(stderr, "error: %v\n", apiErr)
					switch resp.StatusCode {
					case http.StatusConflict:
						return 1
					case http.StatusBadRequest:
						return 1
					default:
						return 1
					}
				}

				var result principalResponse
				if err := json.Unmarshal(respBody, &result); err != nil {
					fmt.Fprintf(stderr, "error: cannot decode response: %v\n", err)
					return 1
				}

				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(result); err != nil {
					fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
					return 1
				}
				return 0
			},
		}
	},
}

var principalShowCommand = &Command{
	Name:       "show",
	Summary:    "Show principal details",
	Usage:      "docker-helper principal show USER [FIELD]",
	MinPosArgs: 1,
	MaxPosArgs: 2,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]

				socketPath, adminTokenPath, err := adminAPIPaths()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				tokenSource, err := adminAPITokenSource(adminTokenPath)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				client := newUnixAPIClient(socketPath, tokenSource, nil)

				resp, err := client.doAuthenticatedRequest("GET", "/principals/"+username, nil)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				defer resp.Body.Close()

				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot read response: %v\n", err)
					return 1
				}

				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					apiErr := parseApiError(resp.StatusCode, respBody)
					fmt.Fprintf(stderr, "error: %v\n", apiErr)
					return 1
				}

				var result principalResponse
				if err := json.Unmarshal(respBody, &result); err != nil {
					fmt.Fprintf(stderr, "error: cannot decode response: %v\n", err)
					return 1
				}

				if len(args) == 2 {
					field := args[1]
					val, ok := extractPrincipalField(&result, field)
					if !ok {
						fmt.Fprintf(stderr, "error: unknown field %q\n", field)
						return 1
					}
					fmt.Fprintln(stdout, val)
					return 0
				}

				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(result); err != nil {
					fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
					return 1
				}
				return 0
			},
		}
	},
}

func extractPrincipalField(p *principalResponse, field string) (string, bool) {
	switch field {
	case "username":
		return p.Username, true
	case "uid":
		return fmt.Sprintf("%d", p.UID), true
	case "gid":
		return fmt.Sprintf("%d", p.GID), true
	case "home":
		return p.Home, true
	case "enabled":
		return fmt.Sprintf("%t", p.Enabled), true
	case "allowed_roots":
		data, err := json.Marshal(p.AllowedRoots)
		if err != nil {
			return "", false
		}
		return string(data), true
	}
	return "", false
}

var principalSetCommand = &Command{
	Name:       "set",
	Summary:    "Modify principal settings",
	Usage:      "docker-helper principal set USER FIELD VALUE",
	MinPosArgs: 3,
	MaxPosArgs: 3,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]
				field := args[1]
				value := args[2]

				if field != "enabled" {
					fmt.Fprintf(stderr, "error: unsupported field %q\n", field)
					return 1
				}

				var enabled bool
				switch value {
				case "true":
					enabled = true
				case "false":
					enabled = false
				default:
					fmt.Fprintf(stderr, "error: invalid value %q for enabled; must be true or false\n", value)
					return 1
				}

				socketPath, adminTokenPath, err := adminAPIPaths()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				tokenSource, err := adminAPITokenSource(adminTokenPath)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				client := newUnixAPIClient(socketPath, tokenSource, nil)

				body, err := json.Marshal(setPrincipalRequest{Enabled: &enabled})
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot encode request: %v\n", err)
					return 1
				}

				resp, err := client.doAuthenticatedRequest("PATCH", "/principals/"+username, bytes.NewReader(body))
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				defer resp.Body.Close()

				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot read response: %v\n", err)
					return 1
				}

				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					apiErr := parseApiError(resp.StatusCode, respBody)
					fmt.Fprintf(stderr, "error: %v\n", apiErr)
					return 1
				}

				var result principalChangedResponse
				if err := json.Unmarshal(respBody, &result); err != nil {
					fmt.Fprintf(stderr, "error: cannot decode response: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "%s %s = %v\n", username, field, enabled)
				if result.Message == "unchanged" {
					fmt.Fprintln(stdout, "(unchanged)")
				}
				return 0
			},
		}
	},
}

var principalAllowedRootCommand = &Command{
	Name:    "allowed-root",
	Summary: "Manage principal allowed roots",
	Subcommands: []*Command{
		principalAllowedRootAddCommand,
		principalAllowedRootRemoveCommand,
	},
}

var principalAllowedRootAddCommand = &Command{
	Name:       "add",
	Summary:    "Add an allowed root for a principal",
	Usage:      "docker-helper principal allowed-root add USER PATH",
	MinPosArgs: 2,
	MaxPosArgs: 2,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]
				path := args[1]

				socketPath, adminTokenPath, err := adminAPIPaths()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				tokenSource, err := adminAPITokenSource(adminTokenPath)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				client := newUnixAPIClient(socketPath, tokenSource, nil)

				body, err := json.Marshal(allowedRootRequest{Path: path})
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot encode request: %v\n", err)
					return 1
				}

				resp, err := client.doAuthenticatedRequest("POST", "/principals/"+username+"/allowed-roots", bytes.NewReader(body))
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				defer resp.Body.Close()

				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot read response: %v\n", err)
					return 1
				}

				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					apiErr := parseApiError(resp.StatusCode, respBody)
					fmt.Fprintf(stderr, "error: %v\n", apiErr)
					return 1
				}

				var result principalChangedResponse
				if err := json.Unmarshal(respBody, &result); err != nil {
					fmt.Fprintf(stderr, "error: cannot decode response: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "added %q to %s\n", path, username)
				if result.Message == "unchanged" {
					fmt.Fprintln(stdout, "(already present)")
				}
				return 0
			},
		}
	},
}

var principalAllowedRootRemoveCommand = &Command{
	Name:       "remove",
	Summary:    "Remove an allowed root for a principal",
	Usage:      "docker-helper principal allowed-root remove USER PATH",
	MinPosArgs: 2,
	MaxPosArgs: 2,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]
				path := args[1]

				socketPath, adminTokenPath, err := adminAPIPaths()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				tokenSource, err := adminAPITokenSource(adminTokenPath)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				client := newUnixAPIClient(socketPath, tokenSource, nil)

				body, err := json.Marshal(allowedRootRequest{Path: path})
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot encode request: %v\n", err)
					return 1
				}

				resp, err := client.doAuthenticatedRequest("DELETE", "/principals/"+username+"/allowed-roots", bytes.NewReader(body))
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				defer resp.Body.Close()

				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot read response: %v\n", err)
					return 1
				}

				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					apiErr := parseApiError(resp.StatusCode, respBody)
					fmt.Fprintf(stderr, "error: %v\n", apiErr)
					return 1
				}

				var result principalChangedResponse
				if err := json.Unmarshal(respBody, &result); err != nil {
					fmt.Fprintf(stderr, "error: cannot decode response: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "removed %q from %s\n", path, username)
				if result.Message == "unchanged" {
					fmt.Fprintln(stdout, "(was not present)")
				}
				return 0
			},
		}
	},
}

var credentialCreateCommand = &Command{
	Name:       "create",
	Summary:    "Create a new credential for a principal",
	Usage:      "docker-helper credential create USER --name NAME",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		name := fs.String("name", "", "Credential name")

		return Invocation{
			Validate: func() error {
				if *name == "" {
					return fmt.Errorf("--name is required")
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]

				socketPath, adminTokenPath, err := adminAPIPaths()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				tokenSource, err := adminAPITokenSource(adminTokenPath)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				client := newUnixAPIClient(socketPath, tokenSource, nil)

				body, err := json.Marshal(createCredentialRequest{Name: *name})
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot encode request: %v\n", err)
					return 1
				}

				resp, err := client.doAuthenticatedRequest("POST", "/principals/"+username+"/credentials", bytes.NewReader(body))
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				defer resp.Body.Close()

				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot read response: %v\n", err)
					return 1
				}

				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					apiErr := parseApiError(resp.StatusCode, respBody)
					fmt.Fprintf(stderr, "error: %v\n", apiErr)
					return 1
				}

				var result createCredentialResponse
				if err := json.Unmarshal(respBody, &result); err != nil {
					fmt.Fprintf(stderr, "error: cannot decode response: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "Credential created for %s\n", username)
				fmt.Fprintf(stdout, "  ID:    %s\n", result.Credential.ID)
				fmt.Fprintf(stdout, "  Name:  %s\n", result.Credential.Name)
				fmt.Fprintf(stdout, "  Token: %s\n", result.Token)
				fmt.Fprintln(stdout, "")
				fmt.Fprintln(stdout, "IMPORTANT: Save the token now. It will not be shown again.")
				return 0
			},
		}
	},
}

var credentialListCommand = &Command{
	Name:       "list",
	Summary:    "List credentials for a principal",
	Usage:      "docker-helper credential list USER",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]

				socketPath, adminTokenPath, err := adminAPIPaths()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				tokenSource, err := adminAPITokenSource(adminTokenPath)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				client := newUnixAPIClient(socketPath, tokenSource, nil)

				resp, err := client.doAuthenticatedRequest("GET", "/principals/"+username+"/credentials", nil)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				defer resp.Body.Close()

				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot read response: %v\n", err)
					return 1
				}

				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					apiErr := parseApiError(resp.StatusCode, respBody)
					fmt.Fprintf(stderr, "error: %v\n", apiErr)
					return 1
				}

				var result listCredentialsResponse
				if err := json.Unmarshal(respBody, &result); err != nil {
					fmt.Fprintf(stderr, "error: cannot decode response: %v\n", err)
					return 1
				}

				if len(result.Credentials) == 0 {
					fmt.Fprintln(stdout, "No credentials for", username)
					return 0
				}

				for _, c := range result.Credentials {
					revoked := "no"
					if c.RevokedAt != nil {
						revoked = *c.RevokedAt
					}
					fmt.Fprintf(stdout, "  %-16s %-12s created=%s revoked=%s\n", c.ID, c.Name, c.CreatedAt, revoked)
				}
				return 0
			},
		}
	},
}

var credentialRevokeCommand = &Command{
	Name:       "revoke",
	Summary:    "Revoke a credential",
	Usage:      "docker-helper credential revoke CREDENTIAL_ID",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				id := args[0]

				socketPath, adminTokenPath, err := adminAPIPaths()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				tokenSource, err := adminAPITokenSource(adminTokenPath)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				client := newUnixAPIClient(socketPath, tokenSource, nil)

				resp, err := client.doAuthenticatedRequest("POST", "/credentials/"+id+"/revoke", nil)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				defer resp.Body.Close()

				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot read response: %v\n", err)
					return 1
				}

				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					apiErr := parseApiError(resp.StatusCode, respBody)
					fmt.Fprintf(stderr, "error: %v\n", apiErr)
					return 1
				}

				var result revokeCredentialResponse
				if err := json.Unmarshal(respBody, &result); err != nil {
					fmt.Fprintf(stderr, "error: cannot decode response: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "revoked %s\n", id)
				if result.Message == "unchanged" {
					fmt.Fprintln(stdout, "(was already revoked)")
				}
				return 0
			},
		}
	},
}
