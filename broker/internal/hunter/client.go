package hunter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kalana/ebpf-cyber-patrol/broker/internal/events"
)

// Client dispatches events to the Python FastAPI hunter service.
type Client struct {
	baseURL    string
	httpClient *http.Client
	maxRetries int
}

// New constructs a Client with a pooled, timeout-bounded HTTP transport.
// Connection reuse matters here: at sustained event rates we're making
// many short-lived POSTs to the same host, and paying a fresh TCP+TLS
// handshake per request would dominate latency.
func New(baseURL string, timeout time.Duration, maxRetries int) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        64,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		maxRetries: maxRetries,
	}
}

// Evaluate POSTs ev to /v1/evaluate and returns the parsed Verdict, retrying
// transient failures (network errors, non-200s) with exponential backoff.
// It does not retry on ctx cancellation.
func (c *Client) Evaluate(ctx context.Context, ev events.Event) (*Verdict, error) {
	body, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("marshal event: %w", err)
	}

	var lastErr error
	backoff := 200 * time.Millisecond

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}

		verdict, err := c.doRequest(ctx, body)
		if err == nil {
			return verdict, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("hunter unavailable after %d attempt(s): %w", c.maxRetries+1, lastErr)
}

func (c *Client) doRequest(ctx context.Context, body []byte) (*Verdict, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hunter returned HTTP %d", resp.StatusCode)
	}

	var v Verdict
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("decode verdict: %w", err)
	}
	return &v, nil
}
