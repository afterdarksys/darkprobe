package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/straticus1/ads-darkapi-io/darkprobe/scanner"
)

type DarkAPIClient struct {
	Endpoint string
	Token    string
	Client   *http.Client
}

type Payload struct {
	Scanner      string                `json:"scanner"`
	Timestamp    string                `json:"timestamp"`
	Subnet       string                `json:"subnet"`
	Hosts        []scanner.Host        `json:"hosts,omitempty"`
	PassiveHosts []scanner.PassiveHost `json:"passive_hosts,omitempty"`
}

func NewClient(endpoint, token string) *DarkAPIClient {
	return &DarkAPIClient{
		Endpoint: endpoint,
		Token:    token,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *DarkAPIClient) Report(ctx context.Context, subnet string, hosts []scanner.Host) error {
	p := Payload{
		Scanner:   "darkprobe",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Subnet:    subnet,
		Hosts:     hosts,
	}

	return c.send(ctx, p)
}

func (c *DarkAPIClient) ReportPassive(ctx context.Context, network string, hosts []scanner.PassiveHost) error {
	p := Payload{
		Scanner:      "darkprobe-passive",
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Subnet:       network,
		PassiveHosts: hosts,
	}
	return c.send(ctx, p)
}

func (c *DarkAPIClient) send(ctx context.Context, p Payload) error {
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("darkapi server returned status %d", resp.StatusCode)
	}

	return nil
}
