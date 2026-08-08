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

type apiClient struct {
	httpClient  *http.Client
	baseURL     string
	tokenSource func() (string, error)
}

func newUnixAPIClient(socketPath string, tokenSource func() (string, error)) *apiClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}

	return &apiClient{
		httpClient:  &http.Client{Transport: transport},
		baseURL:     "http://localhost",
		tokenSource: tokenSource,
	}
}

func newUnixAPIClientWithTimeout(socketPath string, tokenSource func() (string, error), timeout time.Duration) *apiClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}

	return &apiClient{
		httpClient:  &http.Client{Transport: transport, Timeout: timeout},
		baseURL:     "http://localhost",
		tokenSource: tokenSource,
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode)
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode)
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

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API error: status %d", resp.StatusCode)
	}

	return nil
}
