package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OpenCTIClient handles communication with OpenCTI API
type OpenCTIClient struct {
	baseURL     string
	token       string
	httpClient  *http.Client
	rateLimiter *RateLimiter
	logger      *log.Logger
	
	// Metrics
	mu      sync.RWMutex
	metrics PluginMetrics
}

// RateLimiter implements token bucket algorithm
type RateLimiter struct {
	tokens   chan struct{}
	quit     chan struct{}
	refillRate time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rps int, burst int) *RateLimiter {
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
	
	// Fill initial tokens
	for i := 0; i < burst; i++ {
		select {
		case rl.tokens <- struct{}{}:
		default:
		}
	}
	
	// Start token refill goroutine
	go rl.refillTokens()
	
	return rl
}

// refillTokens refills the token bucket at the specified rate
func (rl *RateLimiter) refillTokens() {
	ticker := time.NewTicker(rl.refillRate)
	defer ticker.Stop()
	
	for {
		select {
		case <-rl.quit:
			return
		case <-ticker.C:
			select {
			case rl.tokens <- struct{}{}:
			default:
				// Bucket is full
			}
		}
	}
}

// Wait waits for a token to become available
func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-rl.tokens:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("rate limit timeout")
	}
}

// Close stops the rate limiter
func (rl *RateLimiter) Close() {
	close(rl.quit)
}

// NewOpenCTIClient creates a new OpenCTI API client
func NewOpenCTIClient(config OpenCTIConfig, logger *log.Logger) (*OpenCTIClient, error) {
	if config.BaseURL == "" {
		return nil, fmt.Errorf("OpenCTI base URL is required")
	}
	if config.Token == "" {
		return nil, fmt.Errorf("OpenCTI token is required")
	}
	
	// Set defaults
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.RateLimitRPS == 0 {
		config.RateLimitRPS = 5
	}
	if config.BurstLimit == 0 {
		config.BurstLimit = config.RateLimitRPS * 2
	}
	
	httpClient := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	
	rateLimiter := NewRateLimiter(config.RateLimitRPS, config.BurstLimit)
	
	client := &OpenCTIClient{
		baseURL:     strings.TrimRight(config.BaseURL, "/"),
		token:       config.Token,
		httpClient:  httpClient,
		rateLimiter: rateLimiter,
		logger:      logger,
		metrics:     PluginMetrics{},
	}
	
	return client, nil
}

// Close closes the client and cleans up resources
func (c *OpenCTIClient) Close() {
	if c.rateLimiter != nil {
		c.rateLimiter.Close()
	}
}

// GetMetrics returns current client metrics
func (c *OpenCTIClient) GetMetrics() PluginMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}

// makeRequest makes an authenticated HTTP request to OpenCTI
func (c *OpenCTIClient) makeRequest(ctx context.Context, method, endpoint string, body interface{}) (*http.Response, error) {
	// Wait for rate limiter
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
	}
	
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}
	
	url := c.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "console-ir-opencti-plugin/1.0")
	
	// Make request with retries
	var resp *http.Response
	var lastErr error
	maxRetries := 3
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		start := time.Now()
		resp, err = c.httpClient.Do(req)
		duration := time.Since(start)
		
		if err != nil {
			lastErr = fmt.Errorf("HTTP request failed: %w", err)
			c.recordAPICall(false, duration)
			
			if attempt < maxRetries-1 {
				// Exponential backoff
				backoff := time.Duration(1<<attempt) * time.Second
				if backoff > 10*time.Second {
					backoff = 10 * time.Second
				}
				c.logger.Printf("Request failed, retrying in %v: %v", backoff, err)
				time.Sleep(backoff)
				continue
			}
			break
		}
		
		// Check for transient errors that should be retried
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("transient error: status %d", resp.StatusCode)
			c.recordAPICall(false, duration)
			
			if attempt < maxRetries-1 {
				backoff := time.Duration(1<<attempt) * time.Second
				if backoff > 10*time.Second {
					backoff = 10 * time.Second
				}
				c.logger.Printf("Transient error %d, retrying in %v", resp.StatusCode, backoff)
				time.Sleep(backoff)
				continue
			}
			break
		}
		
		// Success or non-retryable error
		c.recordAPICall(resp.StatusCode < 400, duration)
		return resp, nil
	}
	
	return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries, lastErr)
}

// recordAPICall records metrics for API calls
func (c *OpenCTIClient) recordAPICall(success bool, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if success {
		c.metrics.APICallsSuccess++
	} else {
		c.metrics.APICallsError++
	}
	
	c.metrics.LastActivity = time.Now()
}

// HealthCheck performs a health check against OpenCTI
func (c *OpenCTIClient) HealthCheck(ctx context.Context) error {
	resp, err := c.makeRequest(ctx, "GET", "/api/settings/about", nil)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health check failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	return nil
}

// SearchObservables searches for cyber observables by value
func (c *OpenCTIClient) SearchObservables(ctx context.Context, observableType, value string) ([]STIXObservable, error) {
	// Build GraphQL query for cyber observables
	query := map[string]interface{}{
		"query": `
			query GetObservables($filters: [StixCyberObservablesFiltering]) {
				stixCyberObservables(filters: $filters) {
					edges {
						node {
							id
							standard_id
							entity_type
							observable_value
							x_opencti_score
							confidence
							created_at
							updated_at
							labels {
								edges {
									node {
										value
									}
								}
							}
							indicators {
								edges {
									node {
										id
										name
										pattern
										labels {
											edges {
												node {
													value
												}
											}
										}
										confidence
										valid_from
										valid_until
									}
								}
							}
						}
					}
				}
			}
		`,
		"variables": map[string]interface{}{
			"filters": []map[string]interface{}{
				{
					"key":    "observable_value",
					"values": []string{value},
				},
			},
		},
	}
	
	resp, err := c.makeRequest(ctx, "POST", "/api/graphql", query)
	if err != nil {
		return nil, fmt.Errorf("search observables request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search observables failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var result struct {
		Data struct {
			StixCyberObservables struct {
				Edges []struct {
					Node STIXObservable `json:"node"`
				} `json:"edges"`
			} `json:"stixCyberObservables"`
		} `json:"data"`
		Errors []APIError `json:"errors"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL errors: %v", result.Errors)
	}
	
	var observables []STIXObservable
	for _, edge := range result.Data.StixCyberObservables.Edges {
		observables = append(observables, edge.Node)
	}
	
	c.logger.Printf("Found %d observables for %s: %s", len(observables), observableType, value)
	return observables, nil
}

// GetRelatedEntities gets entities related to an observable
func (c *OpenCTIClient) GetRelatedEntities(ctx context.Context, observableID string, maxRelations int) (*ThreatIntelligence, error) {
	if maxRelations <= 0 {
		maxRelations = 10
	}
	
	// GraphQL query to get related entities
	query := map[string]interface{}{
		"query": `
			query GetRelatedEntities($id: String!, $first: Int) {
				stixCyberObservable(id: $id) {
					id
					observable_value
					stixCoreRelationships(first: $first) {
						edges {
							node {
								id
								relationship_type
								confidence
								start_time
								stop_time
								to {
									... on ThreatActor {
										id
										name
										aliases
										description
										labels {
											edges {
												node {
													value
												}
											}
										}
										confidence
										x_opencti_sophistication
									}
									... on Malware {
										id
										name
										labels {
											edges {
												node {
													value
												}
											}
										}
										description
										is_family
										capabilities
									}
									... on Campaign {
										id
										name
										description
										first_seen
										last_seen
										confidence
										objectives
									}
									... on AttackPattern {
										id
										name
										description
										external_references {
											edges {
												node {
													url
													external_id
													source_name
												}
											}
										}
										x_mitre_id
										x_mitre_platforms
									}
									... on Indicator {
										id
										name
										pattern
										labels {
											edges {
												node {
													value
												}
											}
										}
										confidence
										valid_from
										valid_until
									}
								}
							}
						}
					}
				}
			}
		`,
		"variables": map[string]interface{}{
			"id":    observableID,
			"first": maxRelations,
		},
	}
	
	resp, err := c.makeRequest(ctx, "POST", "/api/graphql", query)
	if err != nil {
		return nil, fmt.Errorf("get related entities request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get related entities failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	// For now, return empty threat intelligence - we'll implement the full parsing in the next step
	intel := &ThreatIntelligence{
		QueryTime: time.Now(),
	}
	
	c.logger.Printf("Retrieved related entities for observable: %s", observableID)
	return intel, nil
}

// SearchByIOC searches for threat intelligence by IOC (Indicator of Compromise)
func (c *OpenCTIClient) SearchByIOC(ctx context.Context, ioc string) ([]STIXIndicator, error) {
	// Use REST API for indicator search
	endpoint := "/api/indicators"
	params := url.Values{}
	params.Add("search", ioc)
	params.Add("limit", "50")
	
	fullURL := endpoint + "?" + params.Encode()
	
	resp, err := c.makeRequest(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("search IOC request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search IOC failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var indicators []STIXIndicator
	if err := json.NewDecoder(resp.Body).Decode(&indicators); err != nil {
		return nil, fmt.Errorf("failed to decode indicators response: %w", err)
	}
	
	c.logger.Printf("Found %d indicators for IOC: %s", len(indicators), ioc)
	return indicators, nil
}

// GetThreatActors retrieves threat actors related to an observable
func (c *OpenCTIClient) GetThreatActors(ctx context.Context, observableValue string) ([]STIXThreatActor, error) {
	// This would typically involve complex GraphQL queries
	// For now, return empty slice - will be implemented in enrichment logic
	c.logger.Printf("Searching threat actors for observable: %s", observableValue)
	return []STIXThreatActor{}, nil
}

// ValidateToken validates the OpenCTI API token
func (c *OpenCTIClient) ValidateToken(ctx context.Context) error {
	resp, err := c.makeRequest(ctx, "GET", "/api/me", nil)
	if err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid or expired token")
	}
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token validation failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	c.logger.Println("OpenCTI token validation successful")
	return nil
}