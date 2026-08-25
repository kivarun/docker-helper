package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// apiError is a structured client-side error for non-2xx daemon responses.
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("API error (status %d, code %s): %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("API error: status %d", e.Status)
}

type apiClient struct {
	httpClient  *http.Client
	baseURL     string
	tokenSource func() (string, error)
}

// newUnixAPIClient creates a Unix-socket HTTP client.
// If timeout is nil, no client-level timeout is set.
// If timeout is non-nil, it is applied as http.Client.Timeout.
func newUnixAPIClient(socketPath string, tokenSource func() (string, error), timeout *time.Duration) *apiClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}

	client := &http.Client{Transport: transport}
	if timeout != nil {
		client.Timeout = *timeout
	}

	return &apiClient{
		httpClient:  client,
		baseURL:     "http://localhost",
		tokenSource: tokenSource,
	}
}

// readResponseBody reads the full response body and returns the bytes.
// If the status is non-2xx it returns a structured apiError instead.
func (c *apiClient) readResponseBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseAPIError(resp.StatusCode, body)
	}
	return body, nil
}

// parseAPIError returns an apiError for the given non-2xx status and body.
// It attempts to extract the daemon's structured code and message; on
// malformed or empty bodies it falls back to a stable error that retains
// the HTTP status.
func parseAPIError(status int, body []byte) *apiError {
	var envelope struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.Message != "" {
		return &apiError{
			Status:  status,
			Code:    envelope.Code,
			Message: envelope.Message,
		}
	}
	return &apiError{
		Status: status,
	}
}

func (c *apiClient) doAuthenticatedRequest(method, path string, body io.Reader) (*http.Response, error) {
	return c.doAuthenticatedRequestWithCtx(context.Background(), method, path, body)
}

func (c *apiClient) doAuthenticatedRequestWithCtx(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	token, err := c.tokenSource()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("cannot create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

func (c *apiClient) listSessions() (*listSessionsResponse, error) {
	resp, err := c.doAuthenticatedRequest("GET", "/sessions", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result listSessionsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}

	return &result, nil
}

func (c *apiClient) createSession(workspace string) (*createSessionResponse, error) {
	body, err := json.Marshal(sessionRequest{Workspace: workspace})
	if err != nil {
		return nil, fmt.Errorf("cannot encode request: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("POST", "/sessions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result createSessionResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}

	return &result, nil
}

func (c *apiClient) deleteSession(id string) error {
	resp, err := c.doAuthenticatedRequest("DELETE", "/sessions/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = c.readResponseBody(resp)
	return err
}

type registryLoginResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

func (c *apiClient) registryLogin(registry, username, password string) (*registryLoginResponse, error) {
	body, err := json.Marshal(registryLoginRequest{
		Registry: registry,
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot encode request: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("POST", "/registry/login", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result registryLoginResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}

	return &result, nil
}

// pull sends POST /pull with the given image reference.
// On non-2xx responses, the response body is still parsed so that
// the daemon's "output" field is preserved for diagnostics.
func (c *apiClient) pull(req pullRequest) (*pullResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot encode request: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("POST", "/pull", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read response: %w", err)
	}

	var result pullResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &result, parseAPIError(resp.StatusCode, respBody)
	}

	return &result, nil
}

// startBuild sends POST /build and returns the operation ID.
func (c *apiClient) startBuild(req buildRequest) (*operationCreatedResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot encode request: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("POST", "/build", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result operationCreatedResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

// startRun sends POST /run and returns the operation ID.
func (c *apiClient) startRun(req runRequest) (*operationCreatedResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot encode request: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("POST", "/run", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result operationCreatedResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

// operationStatus returns the current status of the operation, honoring ctx.
func (c *apiClient) operationStatus(ctx context.Context, opID string) (*operationStatusResponse, error) {
	resp, err := c.doAuthenticatedRequestWithCtx(ctx, "GET", "/operations/"+opID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result operationStatusResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

// cancelOperationTimeout is the deadline for a best-effort cancel request.
// The daemon cancel endpoint is blocking: it waits for graceful termination
// (defaultTerminationTimeout=5s) plus force cleanup (defaultForceCleanupTimeout=3s).
// The client timeout covers the daemon worst case with a small margin.
const cancelOperationTimeout = 12 * time.Second

// cancelOperation sends POST /operations/{id}/cancel with a bounded timeout.
// It is best-effort: the caller should not block on the result.
func (c *apiClient) cancelOperation(opID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cancelOperationTimeout)
	defer cancel()

	token, err := c.tokenSource()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/operations/"+opID+"/cancel", nil)
	if err != nil {
		return fmt.Errorf("cannot create cancel request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Reuse the existing transport (which knows the socket path)
	// but create a new client with a bounded timeout.
	timeoutClient := &http.Client{
		Transport: c.httpClient.Transport,
		Timeout:   cancelOperationTimeout,
	}

	resp, err := timeoutClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = c.readResponseBody(resp)
	return err
}

// operationLogs returns the operation logs from the given offset, honoring ctx.
func (c *apiClient) operationLogs(ctx context.Context, opID string, offset int64) (*operationLogsResponse, error) {
	path := "/operations/" + opID + "/logs?offset=" + strconv.FormatInt(offset, 10)
	resp, err := c.doAuthenticatedRequestWithCtx(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result operationLogsResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

func (c *apiClient) createPrincipal(username string) (*principalResponse, error) {
	body, err := json.Marshal(createPrincipalRequest{Username: username})
	if err != nil {
		return nil, fmt.Errorf("cannot encode request: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("POST", "/principals", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result principalResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

func (c *apiClient) showPrincipal(username string) (*principalResponse, error) {
	resp, err := c.doAuthenticatedRequest("GET", "/principals/"+url.PathEscape(username), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result principalResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

func (c *apiClient) listPrincipals() (*listPrincipalsResponse, error) {
	resp, err := c.doAuthenticatedRequest("GET", "/principals", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result listPrincipalsResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

func (c *apiClient) setPrincipalEnabled(username string, enabled bool) (*principalChangedResponse, error) {
	body, err := json.Marshal(setPrincipalRequest{Enabled: &enabled})
	if err != nil {
		return nil, fmt.Errorf("cannot encode request: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("PATCH", "/principals/"+url.PathEscape(username), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result principalChangedResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

func (c *apiClient) addPrincipalAllowedRoot(username, path string) (*principalChangedResponse, error) {
	body, err := json.Marshal(allowedRootRequest{Path: path})
	if err != nil {
		return nil, fmt.Errorf("cannot encode request: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("POST", "/principals/"+url.PathEscape(username)+"/allowed-roots", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result principalChangedResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

func (c *apiClient) removePrincipalAllowedRoot(username, path string) (*principalChangedResponse, error) {
	body, err := json.Marshal(allowedRootRequest{Path: path})
	if err != nil {
		return nil, fmt.Errorf("cannot encode request: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("DELETE", "/principals/"+url.PathEscape(username)+"/allowed-roots", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result principalChangedResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

func (c *apiClient) createPrincipalCredential(username, name string) (*createCredentialResponse, error) {
	body, err := json.Marshal(createCredentialRequest{Name: name})
	if err != nil {
		return nil, fmt.Errorf("cannot encode request: %w", err)
	}

	resp, err := c.doAuthenticatedRequest("POST", "/principals/"+url.PathEscape(username)+"/credentials", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result createCredentialResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

func (c *apiClient) listPrincipalCredentials(username string) (*listCredentialsResponse, error) {
	resp, err := c.doAuthenticatedRequest("GET", "/principals/"+url.PathEscape(username)+"/credentials", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result listCredentialsResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

func (c *apiClient) revokeCredential(id string) (*revokeCredentialResponse, error) {
	resp, err := c.doAuthenticatedRequest("POST", "/credentials/"+url.PathEscape(id)+"/revoke", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result revokeCredentialResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

func (c *apiClient) rotateAdminToken() (*rotateAdminTokenResponse, error) {
	resp, err := c.doAuthenticatedRequest("POST", "/admin/token/rotate", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	var result rotateAdminTokenResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

func (c *apiClient) deletePrincipal(username string) error {
	resp, err := c.doAuthenticatedRequest("DELETE", "/principals/"+url.PathEscape(username), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return parseAPIError(resp.StatusCode, body)
	}
	return nil
}
