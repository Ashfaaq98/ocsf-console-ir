package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
)

// OpenCTIPlugin represents the OpenCTI enrichment plugin
type OpenCTIPlugin struct {
	client       *redis.Client
	openCTIClient *OpenCTIClient
	cache        *CacheManager
	logger       *log.Logger
	ctx          context.Context
	cancel       context.CancelFunc

	// Configuration
	config       OpenCTIConfig
	redisURL     string
	consumerName string
	groupName    string

	// Metrics
	metrics      PluginMetrics
}

func main() {
	// Parse command line flags
	var (
		redisURL         = flag.String("redis", "redis://localhost:6379", "Redis connection URL")
		consumerName     = flag.String("consumer", "opencti-plugin", "Consumer name for Redis streams")
		groupName        = flag.String("group", "console-ir-opencti", "Redis consumer group name for events stream")
		
		// OpenCTI Configuration
		openCTIURL       = flag.String("opencti-url", "", "OpenCTI base URL (required)")
		openCTIToken     = flag.String("token", "", "OpenCTI API token (required)")
		timeout          = flag.Duration("timeout", 30*time.Second, "OpenCTI API timeout")
		rateLimitRPS     = flag.Int("rate-limit-rps", 5, "OpenCTI API requests per second")
		burstLimit       = flag.Int("burst-limit", 10, "Rate limit burst size")
		
		// Caching Configuration
		cacheTTL         = flag.Duration("cache-ttl", 2*time.Hour, "Cache TTL for threat intelligence")
		cacheSize        = flag.Int("cache-size", 1000, "Maximum cache entries")
		useRedisCache    = flag.Bool("use-redis-cache", true, "Use Redis for caching")
		
		// Enrichment Configuration
		includeRelated   = flag.Bool("include-related", true, "Include related entities in enrichment")
		maxRelations     = flag.Int("max-relations", 5, "Maximum related entities to fetch")
		minConfidence    = flag.Int("min-confidence", 50, "Minimum confidence threshold for results")
		
		// Observable Processing
		processIPs       = flag.Bool("process-ips", true, "Process IP addresses")
		processDomains   = flag.Bool("process-domains", true, "Process domain names")
		processHashes    = flag.Bool("process-hashes", true, "Process file hashes")
		processURLs      = flag.Bool("process-urls", false, "Process URLs")
		
		// Debug options
		dryRun          = flag.Bool("dry-run", false, "Don't make actual OpenCTI API calls")
		_               = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	)
	flag.Parse()

	// Initialize logger
	logger := log.New(os.Stdout, "[OpenCTI] ", log.LstdFlags)
	logger.Println("Starting OpenCTI enrichment plugin")

	// Resolve token from environment if not provided
	if *openCTIToken == "" {
		if envToken := os.Getenv("OPENCTI_TOKEN"); envToken != "" {
			*openCTIToken = envToken
		}
	}
	
	// Resolve URL from environment if not provided
	if *openCTIURL == "" {
		if envURL := os.Getenv("OPENCTI_URL"); envURL != "" {
			*openCTIURL = envURL
		}
	}

	// Validate required parameters
	if !*dryRun {
		if *openCTIURL == "" {
			logger.Fatal("OpenCTI URL is required. Use --opencti-url flag or set OPENCTI_URL environment variable")
		}
		if *openCTIToken == "" {
			logger.Fatal("OpenCTI token is required. Use --token flag or set OPENCTI_TOKEN environment variable")
		}
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		logger.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	// Build configuration
	config := OpenCTIConfig{
		BaseURL:        *openCTIURL,
		Token:          *openCTIToken,
		Timeout:        *timeout,
		RateLimitRPS:   *rateLimitRPS,
		BurstLimit:     *burstLimit,
		CacheTTL:       *cacheTTL,
		CacheSize:      *cacheSize,
		UseRedisCache:  *useRedisCache,
		IncludeRelated: *includeRelated,
		MaxRelations:   *maxRelations,
		MinConfidence:  *minConfidence,
		ProcessIPs:     *processIPs,
		ProcessDomains: *processDomains,
		ProcessHashes:  *processHashes,
		ProcessURLs:    *processURLs,
	}

	// Initialize plugin
	plugin := &OpenCTIPlugin{
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		config:       config,
		redisURL:     *redisURL,
		consumerName: *consumerName,
		groupName:    *groupName,
		metrics:      PluginMetrics{},
	}

	// Initialize OpenCTI client
	if !*dryRun {
		if err := plugin.initializeOpenCTIClient(); err != nil {
			logger.Fatalf("Failed to initialize OpenCTI client: %v", err)
		}
		defer plugin.openCTIClient.Close()
	} else {
		logger.Println("Running in dry-run mode - OpenCTI API calls will be simulated")
	}

	// Initialize cache
	if err := plugin.initializeCache(); err != nil {
		logger.Fatalf("Failed to initialize cache: %v", err)
	}
	defer plugin.cache.Close()

	// Connect to Redis
	if err := plugin.connectRedis(); err != nil {
		logger.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer plugin.client.Close()

	// Start processing
	logger.Println("Starting event processing...")
	if err := plugin.run(); err != nil {
		logger.Fatalf("Plugin error: %v", err)
	}

	logger.Println("OpenCTI plugin stopped")
}

// initializeOpenCTIClient creates and validates the OpenCTI client
func (p *OpenCTIPlugin) initializeOpenCTIClient() error {
	client, err := NewOpenCTIClient(p.config, p.logger)
	if err != nil {
		return fmt.Errorf("failed to create OpenCTI client: %w", err)
	}

	// Validate token and connectivity
	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()

	if err := client.ValidateToken(ctx); err != nil {
		client.Close()
		return fmt.Errorf("OpenCTI token validation failed: %w", err)
	}

	if err := client.HealthCheck(ctx); err != nil {
		client.Close()
		return fmt.Errorf("OpenCTI health check failed: %w", err)
	}

	p.openCTIClient = client
	p.logger.Printf("OpenCTI client initialized successfully (URL: %s)", p.config.BaseURL)
	return nil
}

// initializeCache creates the cache manager
func (p *OpenCTIPlugin) initializeCache() error {
	cache, err := NewCacheManager(
		p.config.UseRedisCache,
		p.redisURL,
		p.config.CacheSize,
		p.logger,
	)
	if err != nil {
		return fmt.Errorf("failed to create cache manager: %w", err)
	}

	p.cache = cache
	p.logger.Printf("Cache initialized (Redis: %v, Size: %d, TTL: %v)", 
		p.config.UseRedisCache, p.config.CacheSize, p.config.CacheTTL)
	return nil
}

// connectRedis establishes connection to Redis
func (p *OpenCTIPlugin) connectRedis() error {
	opts, err := redis.ParseURL(p.redisURL)
	if err != nil {
		return fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	p.client = redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
	defer cancel()

	if err := p.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to ping Redis: %w", err)
	}

	p.logger.Println("Connected to Redis")
	return nil
}

// run starts the main processing loop
func (p *OpenCTIPlugin) run() error {
	// Create consumer group if it doesn't exist
	if err := p.createConsumerGroup(); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Start processing events
	return p.processEvents()
}

// createConsumerGroup creates the consumer group for the events stream
func (p *OpenCTIPlugin) createConsumerGroup() error {
	result := p.client.XGroupCreateMkStream(p.ctx, "events", p.groupName, "0")
	if err := result.Err(); err != nil {
		// Ignore error if group already exists
		if !strings.Contains(err.Error(), "BUSYGROUP") {
			return err
		}
	}
	p.logger.Printf("Consumer group ready (group=%s)", p.groupName)
	return nil
}

// processEvents processes events from the Redis stream
func (p *OpenCTIPlugin) processEvents() error {
	p.logger.Printf("Starting event consumer: %s (group=%s)", p.consumerName, p.groupName)

	for {
		select {
		case <-p.ctx.Done():
			p.logger.Println("Stopping event processing")
			return p.ctx.Err()
		default:
			if err := p.readAndProcessEvents(); err != nil {
				if p.ctx.Err() != nil {
					return p.ctx.Err()
				}
				p.logger.Printf("Error processing events: %v", err)
				time.Sleep(5 * time.Second) // Wait before retrying
			}
		}
	}
}

// readAndProcessEvents reads and processes events from the stream
func (p *OpenCTIPlugin) readAndProcessEvents() error {
	// Read messages from the events stream
	result := p.client.XReadGroup(p.ctx, &redis.XReadGroupArgs{
		Group:    p.groupName,
		Consumer: p.consumerName,
		Streams:  []string{"events", ">"},
		Count:    5, // Process fewer events at once due to API calls
		Block:    1 * time.Second,
	})

	if err := result.Err(); err != nil {
		if err == redis.Nil {
			return nil // No messages available
		}
		return err
	}

	// Process each message
	for _, stream := range result.Val() {
		for _, message := range stream.Messages {
			if err := p.processMessage(message); err != nil {
				p.logger.Printf("Error processing message %s: %v", message.ID, err)
				continue
			}

			// Acknowledge the message
			if err := p.client.XAck(p.ctx, "events", p.groupName, message.ID).Err(); err != nil {
				p.logger.Printf("Error acknowledging message %s: %v", message.ID, err)
			}
		}
	}

	return nil
}

// processMessage processes a single event message
func (p *OpenCTIPlugin) processMessage(message redis.XMessage) error {
	start := time.Now()
	
	// Parse event message
	eventMsg := EventMessage{
		EventID:   getStringField(message.Values, "event_id"),
		EventType: getStringField(message.Values, "event_type"),
		RawJSON:   getStringField(message.Values, "raw_json"),
	}

	if timestamp := getStringField(message.Values, "timestamp"); timestamp != "" {
		// Parse timestamp if needed
	}

	p.logger.Printf("Processing event %s (type: %s)", eventMsg.EventID, eventMsg.EventType)

	// Extract observables from the event
	observables := p.extractObservables(eventMsg.RawJSON)
	if len(observables) == 0 {
		p.logger.Printf("No observables found in event %s", eventMsg.EventID)
		return nil
	}

	p.logger.Printf("Found %d observable(s) in event %s: %v", len(observables), eventMsg.EventID, observables)

	// Process each observable
	enrichmentData := make(map[string]string)
	for _, obs := range observables {
		intel, err := p.getOrFetchThreatIntelligence(obs)
		if err != nil {
			p.logger.Printf("Failed to get threat intelligence for %s %s: %v", obs.Type, obs.Value, err)
			continue
		}

		if intel != nil {
			// Convert threat intelligence to enrichment fields
			obsEnrichment := p.convertToEnrichmentFields(obs, intel)
			for k, v := range obsEnrichment {
				enrichmentData[k] = v
			}
			p.logger.Printf("Enriched %s %s with %d field(s)", obs.Type, obs.Value, len(obsEnrichment))
		}
	}

	// Publish enrichment if we have data
	if len(enrichmentData) > 0 {
		if err := p.publishEnrichment(eventMsg.EventID, enrichmentData); err != nil {
			return fmt.Errorf("failed to publish enrichment: %w", err)
		}
		p.metrics.EnrichmentsAdded++
	}

	// Update metrics
	p.metrics.EventsProcessed++
	p.metrics.LastActivity = time.Now()
	duration := time.Since(start)
	if p.metrics.EventsProcessed > 0 {
		p.metrics.AverageProcessTime = time.Duration(int64(p.metrics.AverageProcessTime)*int64(p.metrics.EventsProcessed-1)+int64(duration)) / time.Duration(p.metrics.EventsProcessed)
	} else {
		p.metrics.AverageProcessTime = duration
	}

	return nil
}

// extractObservables extracts observables from event JSON
func (p *OpenCTIPlugin) extractObservables(rawJSON string) []Observable {
	var observables []Observable

	// Parse JSON to extract observables
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(rawJSON), &event); err != nil {
		p.logger.Printf("Failed to parse event JSON: %v", err)
		return observables
	}

	// Extract IP addresses
	if p.config.ProcessIPs {
		ips := p.extractIPs(event)
		for _, ip := range ips {
			observables = append(observables, Observable{Type: "ip", Value: ip})
		}
	}

	// Extract domains
	if p.config.ProcessDomains {
		domains := p.extractDomains(event)
		for _, domain := range domains {
			observables = append(observables, Observable{Type: "domain", Value: domain})
		}
	}

	// Extract file hashes
	if p.config.ProcessHashes {
		hashes := p.extractHashes(event)
		for _, hash := range hashes {
			observables = append(observables, Observable{Type: "hash", Value: hash})
		}
	}

	// Extract URLs
	if p.config.ProcessURLs {
		urls := p.extractURLs(event)
		for _, urlVal := range urls {
			observables = append(observables, Observable{Type: "url", Value: urlVal})
		}
	}

	return p.deduplicateObservables(observables)
}

// extractIPs extracts IP addresses from event data
func (p *OpenCTIPlugin) extractIPs(event map[string]interface{}) []string {
	var ips []string

	// Check common IP fields
	if srcEndpoint, ok := event["src_endpoint"].(map[string]interface{}); ok {
		if srcIP, ok := srcEndpoint["ip"].(string); ok && p.isValidIP(srcIP) {
			ips = append(ips, srcIP)
		}
	}

	if dstEndpoint, ok := event["dst_endpoint"].(map[string]interface{}); ok {
		if dstIP, ok := dstEndpoint["ip"].(string); ok && p.isValidIP(dstIP) {
			ips = append(ips, dstIP)
		}
	}

	if device, ok := event["device"].(map[string]interface{}); ok {
		if deviceIP, ok := device["ip"].(string); ok && p.isValidIP(deviceIP) {
			ips = append(ips, deviceIP)
		}
	}

	return ips
}

// extractDomains extracts domain names from event data
func (p *OpenCTIPlugin) extractDomains(event map[string]interface{}) []string {
	var domains []string

	// Check endpoint hostnames
	if srcEndpoint, ok := event["src_endpoint"].(map[string]interface{}); ok {
		if hostname, ok := srcEndpoint["hostname"].(string); ok {
			if domain := p.extractDomainFromHostname(hostname); domain != "" {
				domains = append(domains, domain)
			}
		}
	}

	if dstEndpoint, ok := event["dst_endpoint"].(map[string]interface{}); ok {
		if hostname, ok := dstEndpoint["hostname"].(string); ok {
			if domain := p.extractDomainFromHostname(hostname); domain != "" {
				domains = append(domains, domain)
			}
		}
	}

	// Check URL fields for domains
	if urlField, ok := event["url"].(string); ok {
		if domain := p.extractDomainFromURL(urlField); domain != "" {
			domains = append(domains, domain)
		}
	}

	return domains
}

// extractHashes extracts file hashes from event data
func (p *OpenCTIPlugin) extractHashes(event map[string]interface{}) []string {
	var hashes []string

	// Check file hash fields
	if file, ok := event["file"].(map[string]interface{}); ok {
		if hashesMap, ok := file["hashes"].(map[string]interface{}); ok {
			for _, hash := range hashesMap {
				if hashStr, ok := hash.(string); ok && p.isValidHash(hashStr) {
					hashes = append(hashes, hashStr)
				}
			}
		}
	}

	// Check process file hashes
	if process, ok := event["process"].(map[string]interface{}); ok {
		if processFile, ok := process["file"].(map[string]interface{}); ok {
			if hashesMap, ok := processFile["hashes"].(map[string]interface{}); ok {
				for _, hash := range hashesMap {
					if hashStr, ok := hash.(string); ok && p.isValidHash(hashStr) {
						hashes = append(hashes, hashStr)
					}
				}
			}
		}
	}

	return hashes
}

// extractURLs extracts URLs from event data
func (p *OpenCTIPlugin) extractURLs(event map[string]interface{}) []string {
	var urls []string

	// Check URL fields
	if urlField, ok := event["url"].(string); ok && p.isValidURL(urlField) {
		urls = append(urls, urlField)
	}

	// Check HTTP request URLs
	if httpRequest, ok := event["http_request"].(map[string]interface{}); ok {
		if reqURL, ok := httpRequest["url"].(string); ok && p.isValidURL(reqURL) {
			urls = append(urls, reqURL)
		}
	}

	return urls
}

// Helper functions for validation and extraction

func (p *OpenCTIPlugin) isValidIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	// Skip private and loopback IPs for threat intelligence
	return !parsed.IsPrivate() && !parsed.IsLoopback()
}

func (p *OpenCTIPlugin) isValidHash(hash string) bool {
	hash = strings.ToLower(strings.TrimSpace(hash))
	// Check for common hash formats (MD5, SHA1, SHA256, SHA512)
	hashRegex := regexp.MustCompile(`^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$|^[a-f0-9]{128}$`)
	return hashRegex.MatchString(hash)
}

func (p *OpenCTIPlugin) isValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func (p *OpenCTIPlugin) extractDomainFromHostname(hostname string) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return ""
	}
	// Basic domain validation
	if strings.Contains(hostname, ".") && net.ParseIP(hostname) == nil {
		return hostname
	}
	return ""
}

func (p *OpenCTIPlugin) extractDomainFromURL(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

func (p *OpenCTIPlugin) deduplicateObservables(observables []Observable) []Observable {
	seen := make(map[string]bool)
	var result []Observable

	for _, obs := range observables {
		key := obs.Type + ":" + obs.Value
		if !seen[key] {
			seen[key] = true
			result = append(result, obs)
		}
	}

	return result
}

// Continued in next part due to length...