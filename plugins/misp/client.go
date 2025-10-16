package main

import (
	"bytes"
	"context"
	"crypto/tls"
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

// MISPClient handles communication with MISP API
type MISPClient struct {
	baseURL     string
	apiKey      string
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

// NewMISPClient creates a new MISP API client
func NewMISPClient(config MISPConfig, logger *log.Logger) (*MISPClient, error) {
	if config.BaseURL == "" {
		return nil, fmt.Errorf("MISP base URL is required")
	}
	if config.APIKey == "" {
		return nil, fmt.Errorf("MISP API key is required")
	}
	
	// Set defaults
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.RateLimitRPS == 0 {
		config.RateLimitRPS = 10
	}
	if config.BurstLimit == 0 {
		config.BurstLimit = config.RateLimitRPS * 2
	}
	
	// Create HTTP client with TLS configuration
	tr := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
	}
	
	if !config.VerifyTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	
	httpClient := &http.Client{
		Timeout:   config.Timeout,
		Transport: tr,
	}
	
	rateLimiter := NewRateLimiter(config.RateLimitRPS, config.BurstLimit)
	
	client := &MISPClient{
		baseURL:     strings.TrimRight(config.BaseURL, "/"),
		apiKey:      config.APIKey,
		httpClient:  httpClient,
		rateLimiter: rateLimiter,
		logger:      logger,
		metrics:     PluginMetrics{},
	}
	
	return client, nil
}

// Close closes the client and cleans up resources
func (c *MISPClient) Close() {
	if c.rateLimiter != nil {
		c.rateLimiter.Close()
	}
}

// GetMetrics returns current client metrics
func (c *MISPClient) GetMetrics() PluginMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}

// makeRequest makes an authenticated HTTP request to MISP
func (c *MISPClient) makeRequest(ctx context.Context, method, endpoint string, body interface{}) (*http.Response, error) {
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
	
	// Set MISP authentication headers
	req.Header.Set("Authorization", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "console-ir-misp-plugin/1.0")
	
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
func (c *MISPClient) recordAPICall(success bool, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if success {
		c.metrics.APICallsSuccess++
	} else {
		c.metrics.APICallsError++
	}
	
	c.metrics.LastActivity = time.Now()
}

// HealthCheck performs a health check against MISP
func (c *MISPClient) HealthCheck(ctx context.Context) error {
	resp, err := c.makeRequest(ctx, "GET", "/servers/getVersion", nil)
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

// ValidateAPIKey validates the MISP API key
func (c *MISPClient) ValidateAPIKey(ctx context.Context) error {
	resp, err := c.makeRequest(ctx, "GET", "/users/view/me", nil)
	if err != nil {
		return fmt.Errorf("API key validation failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid or expired API key")
	}
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API key validation failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	c.logger.Println("MISP API key validation successful")
	return nil
}

// SearchAttributes searches for attributes by value and type
func (c *MISPClient) SearchAttributes(ctx context.Context, observableType, value string, config MISPConfig) ([]MISPAttribute, error) {
	searchRequest := AttributeSearchRequest{
		Value:       value,
		Type:        c.mapObservableTypeToMISP(observableType),
		WithContext: config.IncludeContext,
		Limit:       config.MaxResults,
	}
	
	// Add time filtering
	if config.DaysBack > 0 {
		searchRequest.Last = fmt.Sprintf("%dd", config.DaysBack)
	}
	
	// Add ToIDS filtering
	if config.OnlyToIDS {
		toIDS := true
		searchRequest.ToIDS = &toIDS
	}
	
	// Add required tags
	if len(config.RequiredTags) > 0 {
		searchRequest.Tags = config.RequiredTags
	}
	
	resp, err := c.makeRequest(ctx, "POST", "/attributes/restSearch", searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search attributes request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search attributes failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var result MISPAttributeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	// Filter by excluded organizations
	attributes := c.filterAttributesByOrg(result.Response.Attribute, config.ExcludedOrgs)
	
	c.logger.Printf("Found %d attributes for %s: %s", len(attributes), observableType, value)
	return attributes, nil
}

// SearchEvents searches for events containing specific attributes
func (c *MISPClient) SearchEvents(ctx context.Context, attributeIDs []string, config MISPConfig) ([]MISPEvent, error) {
	var events []MISPEvent
	
	for _, attrID := range attributeIDs {
		if len(attributeIDs) > config.MaxCorrelations {
			break
		}
		
		searchRequest := EventSearchRequest{
			IncludeAttrs: true,
			Limit:        10, // Limit events per attribute
		}
		
		// Add time filtering
		if config.DaysBack > 0 {
			searchRequest.Last = fmt.Sprintf("%dd", config.DaysBack)
		}
		
		resp, err := c.makeRequest(ctx, "POST", "/events/restSearch", searchRequest)
		if err != nil {
			c.logger.Printf("Warning: failed to search events for attribute %s: %v", attrID, err)
			continue
		}
		
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			c.logger.Printf("Warning: event search failed for attribute %s with status %d: %s", attrID, resp.StatusCode, string(body))
			resp.Body.Close()
			continue
		}
		
		var result MISPEventResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			c.logger.Printf("Warning: failed to decode event response for attribute %s: %v", attrID, err)
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		
		events = append(events, result.Response...)
	}
	
	c.logger.Printf("Found %d related events for %d attributes", len(events), len(attributeIDs))
	return events, nil
}

// GetAttributesByEventID retrieves attributes for a specific event
func (c *MISPClient) GetAttributesByEventID(ctx context.Context, eventID string) ([]MISPAttribute, error) {
	endpoint := fmt.Sprintf("/events/view/%s", eventID)
	
	resp, err := c.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("get event request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get event failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var result struct {
		Event MISPEvent `json:"Event"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode event response: %w", err)
	}
	
	return result.Event.Attributes, nil
}

// GetTags retrieves tags for threat intelligence classification
func (c *MISPClient) GetTags(ctx context.Context, tagNames []string) ([]MISPTag, error) {
	var tags []MISPTag
	
	// MISP doesn't have a bulk tag API, so we'll extract tags from the attributes
	// This is a simplified implementation
	for _, tagName := range tagNames {
		tag := MISPTag{
			Name: tagName,
		}
		tags = append(tags, tag)
	}
	
	return tags, nil
}

// GetGalaxyClusters retrieves galaxy clusters for threat actor and malware classification
func (c *MISPClient) GetGalaxyClusters(ctx context.Context, galaxyTags []string) ([]MISPGalaxyCluster, error) {
	var clusters []MISPGalaxyCluster
	
	for _, tag := range galaxyTags {
		if !strings.HasPrefix(tag, "misp-galaxy:") {
			continue
		}
		
		// Parse galaxy tag format: misp-galaxy:threat-actor="APT1"
		parts := strings.Split(tag, ":")
		if len(parts) < 2 {
			continue
		}
		
		galaxyParts := strings.Split(parts[1], "=")
		if len(galaxyParts) < 2 {
			continue
		}
		
		cluster := MISPGalaxyCluster{
			Type:  galaxyParts[0],
			Value: strings.Trim(galaxyParts[1], "\""),
			Tag:   tag,
		}
		clusters = append(clusters, cluster)
	}
	
	c.logger.Printf("Processed %d galaxy clusters from %d tags", len(clusters), len(galaxyTags))
	return clusters, nil
}

// Helper functions

// mapObservableTypeToMISP maps our observable types to MISP attribute types
func (c *MISPClient) mapObservableTypeToMISP(observableType string) string {
	switch observableType {
	case "ip":
		return "ip-dst" // Default to destination IP, could also be ip-src
	case "domain":
		return "domain"
	case "url":
		return "url"
	case "email":
		return "email-src"
	case "hash":
		return "sha256" // Default to SHA256, could detect hash type
	default:
		return ""
	}
}

// filterAttributesByOrg filters out attributes from excluded organizations
func (c *MISPClient) filterAttributesByOrg(attributes []MISPAttribute, excludedOrgs []string) []MISPAttribute {
	if len(excludedOrgs) == 0 {
		return attributes
	}
	
	var filtered []MISPAttribute
	excludeMap := make(map[string]bool)
	for _, org := range excludedOrgs {
		excludeMap[strings.ToLower(org)] = true
	}
	
	for _, attr := range attributes {
		if attr.Event != nil && attr.Event.Org != nil {
			orgName := strings.ToLower(attr.Event.Org.Name)
			if !excludeMap[orgName] {
				filtered = append(filtered, attr)
			}
		} else {
			// Include attributes without organization info
			filtered = append(filtered, attr)
		}
	}
	
	return filtered
}

// parseTime parses MISP timestamp format
func (c *MISPClient) parseTime(timestamp string) (time.Time, error) {
	// MISP uses Unix timestamps
	if timestamp == "" {
		return time.Time{}, nil
	}
	
	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		time.RFC3339,
	}
	
	for _, layout := range layouts {
		if t, err := time.Parse(layout, timestamp); err == nil {
			return t, nil
		}
	}
	
	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", timestamp)
}

// buildSearchURL builds a URL with query parameters for search requests
func (c *MISPClient) buildSearchURL(endpoint string, params map[string]string) string {
	u, err := url.Parse(c.baseURL + endpoint)
	if err != nil {
		return c.baseURL + endpoint
	}
	
	q := u.Query()
	for key, value := range params {
		if value != "" {
			q.Set(key, value)
		}
	}
	u.RawQuery = q.Encode()
	
	return u.String()
}

// extractThreatLevel converts MISP threat level ID to human-readable format
func (c *MISPClient) extractThreatLevel(threatLevelID string) string {
	switch threatLevelID {
	case ThreatLevelHigh:
		return "HIGH"
	case ThreatLevelMedium:
		return "MEDIUM"
	case ThreatLevelLow:
		return "LOW"
	case ThreatLevelUndefined:
		return "UNDEFINED"
	default:
		return "UNKNOWN"
	}
}

// extractAnalysisLevel converts MISP analysis ID to human-readable format
func (c *MISPClient) extractAnalysisLevel(analysisID string) string {
	switch analysisID {
	case AnalysisInitial:
		return "INITIAL"
	case AnalysisOngoing:
		return "ONGOING"
	case AnalysisCompleted:
		return "COMPLETED"
	default:
		return "UNKNOWN"
	}
}