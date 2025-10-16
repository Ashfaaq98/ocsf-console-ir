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

// MISPPlugin represents the MISP enrichment plugin
type MISPPlugin struct {
	client      *redis.Client
	mispClient  *MISPClient
	cache       *CacheManager
	logger      *log.Logger
	ctx         context.Context
	cancel      context.CancelFunc

	// Configuration
	config       MISPConfig
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
		consumerName     = flag.String("consumer", "misp-plugin", "Consumer name for Redis streams")
		groupName        = flag.String("group", "console-ir-misp", "Redis consumer group name for events stream")
		
		// MISP Configuration
		mispURL          = flag.String("misp-url", "", "MISP base URL (required)")
		apiKey           = flag.String("api-key", "", "MISP API key (required)")
		verifyTLS        = flag.Bool("verify-tls", true, "Verify TLS certificates")
		timeout          = flag.Duration("timeout", 30*time.Second, "MISP API timeout")
		rateLimitRPS     = flag.Int("rate-limit-rps", 10, "MISP API requests per second")
		burstLimit       = flag.Int("burst-limit", 20, "Rate limit burst size")
		
		// Caching Configuration
		cacheTTL         = flag.Duration("cache-ttl", 4*time.Hour, "Cache TTL for threat intelligence")
		cacheSize        = flag.Int("cache-size", 2000, "Maximum cache entries")
		useRedisCache    = flag.Bool("use-redis-cache", true, "Use Redis for caching")
		
		// Query Configuration
		daysBack         = flag.Int("days-back", 30, "Days back to search for attributes")
		onlyToIDS        = flag.Bool("only-to-ids", true, "Only include attributes marked as indicators")
		includeContext   = flag.Bool("include-context", true, "Include event context in results")
		maxResults       = flag.Int("max-results", 100, "Maximum results per query")
		
		// Event Correlation
		correlateEvents  = flag.Bool("correlate-events", true, "Enable event correlation")
		maxCorrelations  = flag.Int("max-correlations", 10, "Maximum event correlations per observable")
		
		// Observable Processing
		processIPs       = flag.Bool("process-ips", true, "Process IP addresses")
		processDomains   = flag.Bool("process-domains", true, "Process domain names")
		processHashes    = flag.Bool("process-hashes", true, "Process file hashes")
		processURLs      = flag.Bool("process-urls", true, "Process URLs")
		processEmails    = flag.Bool("process-emails", false, "Process email addresses")
		
		// Filtering
		minThreatLevel   = flag.Int("min-threat-level", 3, "Minimum threat level (1=High, 2=Medium, 3=Low, 4=Undefined)")
		excludedOrgs     = flag.String("excluded-orgs", "", "Comma-separated list of organizations to exclude")
		requiredTags     = flag.String("required-tags", "", "Comma-separated list of required tags")
		
		// Debug options
		dryRun          = flag.Bool("dry-run", false, "Don't make actual MISP API calls")
		_               = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	)
	flag.Parse()

	// Initialize logger
	logger := log.New(os.Stdout, "[MISP] ", log.LstdFlags)
	logger.Println("Starting MISP enrichment plugin")

	// Resolve API key from environment if not provided
	if *apiKey == "" {
		if envKey := os.Getenv("MISP_API_KEY"); envKey != "" {
			*apiKey = envKey
		}
	}
	
	// Resolve URL from environment if not provided
	if *mispURL == "" {
		if envURL := os.Getenv("MISP_URL"); envURL != "" {
			*mispURL = envURL
		}
	}

	// Validate required parameters
	if !*dryRun {
		if *mispURL == "" {
			logger.Fatal("MISP URL is required. Use --misp-url flag or set MISP_URL environment variable")
		}
		if *apiKey == "" {
			logger.Fatal("MISP API key is required. Use --api-key flag or set MISP_API_KEY environment variable")
		}
	}

	// Parse comma-separated lists
	var excludedOrgsList, requiredTagsList []string
	if *excludedOrgs != "" {
		excludedOrgsList = strings.Split(*excludedOrgs, ",")
		for i, org := range excludedOrgsList {
			excludedOrgsList[i] = strings.TrimSpace(org)
		}
	}
	if *requiredTags != "" {
		requiredTagsList = strings.Split(*requiredTags, ",")
		for i, tag := range requiredTagsList {
			requiredTagsList[i] = strings.TrimSpace(tag)
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
	config := MISPConfig{
		BaseURL:        *mispURL,
		APIKey:         *apiKey,
		VerifyTLS:      *verifyTLS,
		Timeout:        *timeout,
		RateLimitRPS:   *rateLimitRPS,
		BurstLimit:     *burstLimit,
		CacheTTL:       *cacheTTL,
		CacheSize:      *cacheSize,
		UseRedisCache:  *useRedisCache,
		DaysBack:       *daysBack,
		OnlyToIDS:      *onlyToIDS,
		IncludeContext: *includeContext,
		MaxResults:     *maxResults,
		CorrelateEvents: *correlateEvents,
		MaxCorrelations: *maxCorrelations,
		ProcessIPs:     *processIPs,
		ProcessDomains: *processDomains,
		ProcessHashes:  *processHashes,
		ProcessURLs:    *processURLs,
		ProcessEmails:  *processEmails,
		MinThreatLevel: *minThreatLevel,
		ExcludedOrgs:   excludedOrgsList,
		RequiredTags:   requiredTagsList,
	}

	// Initialize plugin
	plugin := &MISPPlugin{
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		config:       config,
		redisURL:     *redisURL,
		consumerName: *consumerName,
		groupName:    *groupName,
		metrics:      PluginMetrics{},
	}

	// Initialize MISP client
	if !*dryRun {
		if err := plugin.initializeMISPClient(); err != nil {
			logger.Fatalf("Failed to initialize MISP client: %v", err)
		}
		defer plugin.mispClient.Close()
	} else {
		logger.Println("Running in dry-run mode - MISP API calls will be simulated")
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

	logger.Println("MISP plugin stopped")
}

// initializeMISPClient creates and validates the MISP client
func (p *MISPPlugin) initializeMISPClient() error {
	client, err := NewMISPClient(p.config, p.logger)
	if err != nil {
		return fmt.Errorf("failed to create MISP client: %w", err)
	}

	// Validate API key and connectivity
	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()

	if err := client.ValidateAPIKey(ctx); err != nil {
		client.Close()
		return fmt.Errorf("MISP API key validation failed: %w", err)
	}

	if err := client.HealthCheck(ctx); err != nil {
		client.Close()
		return fmt.Errorf("MISP health check failed: %w", err)
	}

	p.mispClient = client
	p.logger.Printf("MISP client initialized successfully (URL: %s)", p.config.BaseURL)
	return nil
}

// initializeCache creates the cache manager
func (p *MISPPlugin) initializeCache() error {
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
func (p *MISPPlugin) connectRedis() error {
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
func (p *MISPPlugin) run() error {
	// Create consumer group if it doesn't exist
	if err := p.createConsumerGroup(); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Start processing events
	return p.processEvents()
}

// createConsumerGroup creates the consumer group for the events stream
func (p *MISPPlugin) createConsumerGroup() error {
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
func (p *MISPPlugin) processEvents() error {
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
func (p *MISPPlugin) readAndProcessEvents() error {
	// Read messages from the events stream
	result := p.client.XReadGroup(p.ctx, &redis.XReadGroupArgs{
		Group:    p.groupName,
		Consumer: p.consumerName,
		Streams:  []string{"events", ">"},
		Count:    8, // Process more events at once than OpenCTI due to faster MISP responses
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
func (p *MISPPlugin) processMessage(message redis.XMessage) error {
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

		if intel != nil && len(intel.Attributes) > 0 {
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

// extractObservables extracts observables from event JSON (reuses OpenCTI logic)
func (p *MISPPlugin) extractObservables(rawJSON string) []Observable {
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

	// Extract emails
	if p.config.ProcessEmails {
		emails := p.extractEmails(event)
		for _, email := range emails {
			observables = append(observables, Observable{Type: "email", Value: email})
		}
	}

	return p.deduplicateObservables(observables)
}

// extractIPs extracts IP addresses from event data
func (p *MISPPlugin) extractIPs(event map[string]interface{}) []string {
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
func (p *MISPPlugin) extractDomains(event map[string]interface{}) []string {
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
func (p *MISPPlugin) extractHashes(event map[string]interface{}) []string {
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
func (p *MISPPlugin) extractURLs(event map[string]interface{}) []string {
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

// extractEmails extracts email addresses from event data
func (p *MISPPlugin) extractEmails(event map[string]interface{}) []string {
	var emails []string

	// Check actor email
	if actor, ok := event["actor"].(map[string]interface{}); ok {
		if user, ok := actor["user"].(map[string]interface{}); ok {
			if email, ok := user["email_addr"].(string); ok && p.isValidEmail(email) {
				emails = append(emails, email)
			}
		}
	}

	// Check user email
	if user, ok := event["user"].(map[string]interface{}); ok {
		if email, ok := user["email_addr"].(string); ok && p.isValidEmail(email) {
			emails = append(emails, email)
		}
	}

	return emails
}

// Helper functions for validation and extraction

func (p *MISPPlugin) isValidIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	// Include all IPs for MISP (including private) as they may be relevant for threat intelligence
	return true
}

func (p *MISPPlugin) isValidHash(hash string) bool {
	hash = strings.ToLower(strings.TrimSpace(hash))
	// Check for common hash formats (MD5, SHA1, SHA256, SHA512)
	hashRegex := regexp.MustCompile(`^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$|^[a-f0-9]{128}$`)
	return hashRegex.MatchString(hash)
}

func (p *MISPPlugin) isValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func (p *MISPPlugin) isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func (p *MISPPlugin) extractDomainFromHostname(hostname string) string {
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

func (p *MISPPlugin) extractDomainFromURL(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

func (p *MISPPlugin) deduplicateObservables(observables []Observable) []Observable {
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

// getStringField extracts a string field from Redis message values
func getStringField(values map[string]interface{}, key string) string {
	if value, ok := values[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}