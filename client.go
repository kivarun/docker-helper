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
	"os"
	"strings"
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
		return nil, parseApiError(resp.StatusCode, body)
	}
	return body, nil
}

// parseApiError returns an apiError for the given non-2xx status and body.
// It attempts to extract the daemon's structured code and message; on
// malformed or empty bodies it falls back to a stable error that retains
// the HTTP status.
func parseApiError(status int, body []byte) *apiError {
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

func readAdminTokenPlain(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read admin token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("admin token file is empty")
	}
	return token, nil
}

func (c *apiClient) doAuthenticatedRequest(method, path string, body io.Reader) (*http.Response, error) {
	token, err := c.tokenSource()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, c.baseURL+path, body)
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
