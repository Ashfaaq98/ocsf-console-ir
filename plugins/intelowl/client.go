package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IntelOwlAPI is an abstraction over IntelOwl interactions.
// Real implementation can leverage github.com/intelowlproject/go-intelowl,
// while tests and dry-run use a mock implementation.
type IntelOwlAPI interface {
	// QueryObservable attempts to retrieve existing results without submitting new jobs.
	QueryObservable(ctx context.Context, obs Observable, analyzers []string) (*IntelOwlResult, error)
	// SubmitAndPoll submits analysis for an observable and waits until completion or timeout.
	SubmitAndPoll(ctx context.Context, obs Observable, analyzers []string, pollInterval, timeout time.Duration) (*IntelOwlResult, error)
	// Close releases any resources.
	Close()
	// Metrics returns internal counters, if any.
	Metrics() PluginMetrics
}

// RateLimiter is a simple token bucket limiter.
type RateLimiter struct {
	tokens     chan struct{}
	quit       chan struct{}
	refillRate time.Duration
}

func NewRateLimiter(rps, burst int) *RateLimiter {
	if rps <= 0 {
		rps = 1
	}
	if burst <= 0 {
		burst = rps
	}
	rl := &RateLimiter{
		tokens:     make(chan struct{}, burst),
		quit:       make(chan struct{}),
		refillRate: time.Second / time.Duration(rps),
	}
	// Fill bucket
	for i := 0; i < cap(rl.tokens); i++ {
		select {
		case rl.tokens <- struct{}{}:
		default:
		}
	}
	// Refill loop
	go func() {
		t := time.NewTicker(rl.refillRate)
		defer t.Stop()
		for {
			select {
			case <-rl.quit:
				return
			case <-t.C:
				select {
				case rl.tokens <- struct{}{}:
				default:
				}
			}
		}
	}()
	return rl
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.tokens:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("rate limit timeout")
	}
}

func (r *RateLimiter) Close() { close(r.quit) }

// RealIntelOwlClient is a minimal HTTP client scaffolding for IntelOwl.
// Note: End-to-end tests and default staging profile use dry-run/mocks.
// Real calls are intentionally conservative here and can be expanded after live testing.
type RealIntelOwlClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
	limiter    *RateLimiter
	logger     *log.Logger

	mu      sync.RWMutex
	metrics PluginMetrics
}

type realClientOpts struct {
	BaseURL    string
	Token      string
	VerifyTLS  bool
	Timeout    time.Duration
	RPS        int
	Burst      int
	Logger     *log.Logger
}

func NewRealIntelOwlClient(opts realClientOpts) *RealIntelOwlClient {
	tr := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
	}
	if !opts.VerifyTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	c := &RealIntelOwlClient{
		baseURL:    strings.TrimRight(opts.BaseURL, "/"),
		token:      opts.Token,
		httpClient: &http.Client{Timeout: opts.Timeout, Transport: tr},
		limiter:    NewRateLimiter(opts.RPS, opts.Burst),
		logger:     opts.Logger,
		metrics:    PluginMetrics{},
	}
	return c
}

func (c *RealIntelOwlClient) Close() {
	if c.limiter != nil {
		c.limiter.Close()
	}
}

func (c *RealIntelOwlClient) Metrics() PluginMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}

func (c *RealIntelOwlClient) recordAPICall(success bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if success {
		c.metrics.APICallsSuccess++
	} else {
		c.metrics.APICallsError++
	}
	c.metrics.LastActivity = time.Now()
}

func (c *RealIntelOwlClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "console-ir-intelowl-plugin/1.0")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.recordAPICall(false)
		return nil, err
	}
	c.recordAPICall(resp.StatusCode < 400)
	return resp, nil
}

// QueryObservable performs a lightweight query for existing results.
// Implementation placeholder: real IntelOwl lookup endpoints to be wired post-live validation.
func (c *RealIntelOwlClient) QueryObservable(ctx context.Context, obs Observable, analyzers []string) (*IntelOwlResult, error) {
	// Basic connectivity probe to avoid silent misconfigurations.
	resp, err := c.do(ctx, http.MethodGet, "/api/health", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("intelowl health check failed: %d %s", resp.StatusCode, string(data))
	}

	// In this initial implementation, return not found to let the upper layer decide about submission.
	return nil, errors.New("no existing results found (placeholder)")
}

// SubmitAndPoll submits and polls until completion (placeholder).
func (c *RealIntelOwlClient) SubmitAndPoll(ctx context.Context, obs Observable, analyzers []string, pollInterval, timeout time.Duration) (*IntelOwlResult, error) {
	// Placeholder: Returning error to ensure we don't accidentally run submissions without explicit follow-up implementation.
	return nil, errors.New("submit-and-poll not implemented against live IntelOwl in this version")
}

// MockIntelOwlClient generates deterministic mock intel for testing and dry-run.
type MockIntelOwlClient struct {
	logger  *log.Logger
	mu      sync.RWMutex
	metrics PluginMetrics
}

func NewMockIntelOwlClient(logger *log.Logger) *MockIntelOwlClient {
	return &MockIntelOwlClient{logger: logger}
}

func (m *MockIntelOwlClient) Close() {}

func (m *MockIntelOwlClient) Metrics() PluginMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metrics
}

func (m *MockIntelOwlClient) record(success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if success {
		m.metrics.APICallsSuccess++
	} else {
		m.metrics.APICallsError++
	}
	m.metrics.LastActivity = time.Now()
}

func (m *MockIntelOwlClient) QueryObservable(ctx context.Context, obs Observable, analyzers []string) (*IntelOwlResult, error) {
	_ = ctx
	m.record(true)
	return m.generate(obs, analyzers, "query"), nil
}

func (m *MockIntelOwlClient) SubmitAndPoll(ctx context.Context, obs Observable, analyzers []string, pollInterval, timeout time.Duration) (*IntelOwlResult, error) {
	_ = pollInterval
	_ = timeout
	select {
	case <-ctx.Done():
		m.record(false)
		return nil, ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}
	m.record(true)
	return m.generate(obs, analyzers, "submit"), nil
}

func (m *MockIntelOwlClient) generate(obs Observable, analyzers []string, mode string) *IntelOwlResult {
	verdict := "unknown"
	conf := "low"
	tags := []string{"mock", "intelowl", "mode:" + mode}
	if obs.Type == "hash" || obs.Type == "url" {
		verdict = "suspicious"
		conf = "medium"
	}
	if obs.Type == "ip" && strings.HasPrefix(obs.Value, "1.") {
		verdict = "benign"
		conf = "low"
	}
	per := map[string]any{
		"example_analyzer": map[string]any{
			"score":      42,
			"confidence": conf,
		},
	}
	return &IntelOwlResult{
		Observable:    obs,
		Verdict:       verdict,
		Confidence:    conf,
		Tags:          tags,
		Analyzers:     append([]string{}, analyzers...),
		Jobs:          []string{"mock-job-123"},
		EvidenceCount: 1,
		Summary:       fmt.Sprintf("Mock IntelOwl %s result for %s %s", mode, obs.Type, obs.Value),
		PerAnalyzer:   per,
		QueryTime:     time.Now(),
	}
}