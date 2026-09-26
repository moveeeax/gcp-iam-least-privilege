// Package gcp fetches a project's live IAM policy from the Cloud Resource
// Manager API using Application Default Credentials. It shells out to gcloud
// for the OAuth token so the tool needs no vendored client libraries and works
// wherever an operator has already authenticated.
package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

const resourceManagerBase = "https://cloudresourcemanager.googleapis.com/v1"

// FetchPolicy calls projects.getIamPolicy and returns the raw JSON body.
func FetchPolicy(ctx context.Context, project string) ([]byte, error) {
	token, err := accessToken(ctx)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/projects/%s:getIamPolicy", resourceManagerBase, project)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call getIamPolicy: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getIamPolicy returned %s: %s", resp.Status, apiError(body))
	}
	return body, nil
}

// accessToken obtains an OAuth token via `gcloud auth print-access-token`.
func accessToken(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "gcloud", "auth", "print-access-token")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gcloud auth print-access-token failed (is gcloud installed and authenticated?): %v: %s",
			err, strings.TrimSpace(errb.String()))
	}
	token := strings.TrimSpace(out.String())
	if token == "" {
		return "", fmt.Errorf("gcloud returned an empty access token")
	}
	return token, nil
}

// apiError extracts a readable message from a Google API error envelope.
func apiError(body []byte) string {
	var env struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err == nil && env.Error.Message != "" {
		return env.Error.Message
	}
	return strings.TrimSpace(string(body))
}
