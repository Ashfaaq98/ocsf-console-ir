package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
)

// GeoIPPlugin represents the GeoIP enrichment plugin
type GeoIPPlugin struct {
	client   *redis.Client
	logger   *log.Logger
	ctx      context.Context
	cancel   context.CancelFunc

	// Provider (ipapi-only for POC)
	provider GeoIPProvider

	// Configuration
	redisURL      string
	consumerName  string
	groupName     string
	apiKey        string // Optional API key for ipapi.co (POC)
	ipapiURL      string
	httpTimeout   time.Duration
	rateLimitRPS  int
	cacheTTL      time.Duration
	cacheSize     int
}

// EventMessage represents an event from the Redis stream
type EventMessage struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	RawJSON   string `json:"raw_json"`
	Timestamp int64  `json:"timestamp"`
}

// EnrichmentMessage represents an enrichment to be published
type EnrichmentMessage struct {
	EventID     string            `json:"event_id"`
	Source      string            `json:"source"`
	Type        string            `json:"type"`
	Data        map[string]string `json:"data"`
	Timestamp   int64             `json:"timestamp"`
	PluginName  string            `json:"plugin_name"`
}

// GeoIPData represents GeoIP enrichment data
type GeoIPData struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	Organization string `json:"organization"`
	ASN         string  `json:"asn"`
	Timezone    string  `json:"timezone"`
}

func main() {
	// Parse command line flags
	var (
		redisURL      = flag.String("redis", "redis://localhost:6379", "Redis connection URL")
		consumerName  = flag.String("consumer", "geoip-plugin", "Consumer name for Redis streams")
		groupName     = flag.String("group", "console-ir-geoip", "Redis consumer group name for events stream")
		apiKey        = flag.String("api-key", "", "ipapi API key (optional)")
		ipapiURL      = flag.String("ipapi-url", "https://ipapi.co", "Base URL for ipapi provider")
		httpTimeout   = flag.Duration("timeout", 2*time.Second, "HTTP client timeout")
		rateLimitRPS  = flag.Int("rate-limit-rps", 2, "Max ipapi requests per second")
		cacheTTL      = flag.Duration("cache-ttl", 6*time.Hour, "TTL for in-memory GeoIP cache")
		cacheSize     = flag.Int("cache-size", 500, "Max entries for in-memory GeoIP cache")
		_             = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	)
	flag.Parse()

	// Initialize logger
	logger := log.New(os.Stdout, "[GeoIP] ", log.LstdFlags)
	logger.Println("Starting GeoIP enrichment plugin")

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

	// Initialize plugin
	plugin := &GeoIPPlugin{
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		redisURL:     *redisURL,
		consumerName: *consumerName,
		groupName:    *groupName,
		apiKey:       *apiKey,
		ipapiURL:     *ipapiURL,
		httpTimeout:  *httpTimeout,
		rateLimitRPS: *rateLimitRPS,
		cacheTTL:     *cacheTTL,
		cacheSize:    *cacheSize,
	}

	// Initialize ipapi provider (POC: only provider)
	ipProvider, err := NewIpapiProvider(IpapiConfig{
		BaseURL:       plugin.ipapiURL,
		APIKey:        plugin.apiKey,
		Timeout:       plugin.httpTimeout,
		RateLimitRPS:  plugin.rateLimitRPS,
		CacheTTL:      plugin.cacheTTL,
		CacheSize:     plugin.cacheSize,
		Logger:        plugin.logger,
	})
	if err != nil {
		logger.Fatalf("Failed to initialize ipapi provider: %v", err)
	}
	plugin.provider = ipProvider
	defer func() { _ = plugin.provider.Close() }()

	// Connect to Redis
	if err := plugin.connect(); err != nil {
		logger.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer plugin.client.Close()

	// Start processing
	logger.Println("Starting event processing...")
	if err := plugin.run(); err != nil {
		logger.Fatalf("Plugin error: %v", err)
	}

	logger.Println("GeoIP plugin stopped")
}

// connect establishes connection to Redis
func (g *GeoIPPlugin) connect() error {
	opts, err := redis.ParseURL(g.redisURL)
	if err != nil {
		return fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	g.client = redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(g.ctx, 5*time.Second)
	defer cancel()

	if err := g.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to ping Redis: %w", err)
	}

	g.logger.Println("Connected to Redis")
	return nil
}

// run starts the main processing loop
func (g *GeoIPPlugin) run() error {
	// Create consumer group if it doesn't exist
	if err := g.createConsumerGroup(); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Start processing events
	return g.processEvents()
}

// createConsumerGroup creates the consumer group for the events stream
func (g *GeoIPPlugin) createConsumerGroup() error {
	result := g.client.XGroupCreateMkStream(g.ctx, "events", g.groupName, "0")
	if err := result.Err(); err != nil {
		// Ignore error if group already exists
		if !strings.Contains(err.Error(), "BUSYGROUP") {
			return err
		}
	}
	g.logger.Printf("Consumer group ready (group=%s)", g.groupName)
	return nil
}

// processEvents processes events from the Redis stream
func (g *GeoIPPlugin) processEvents() error {
	g.logger.Printf("Starting event consumer: %s (group=%s)", g.consumerName, g.groupName)

	for {
		select {
		case <-g.ctx.Done():
			g.logger.Println("Stopping event processing")
			return g.ctx.Err()
		default:
			if err := g.readAndProcessEvents(); err != nil {
				if g.ctx.Err() != nil {
					return g.ctx.Err()
				}
				g.logger.Printf("Error processing events: %v", err)
				time.Sleep(5 * time.Second) // Wait before retrying
			}
		}
	}
}

// readAndProcessEvents reads and processes events from the stream
func (g *GeoIPPlugin) readAndProcessEvents() error {
	// Read messages from the events stream
	result := g.client.XReadGroup(g.ctx, &redis.XReadGroupArgs{
		Group:    g.groupName,
		Consumer: g.consumerName,
		Streams:  []string{"events", ">"},
		Count:    10,
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
			if err := g.processMessage(message); err != nil {
				g.logger.Printf("Error processing message %s: %v", message.ID, err)
				continue
			}

			// Acknowledge the message
			if err := g.client.XAck(g.ctx, "events", g.groupName, message.ID).Err(); err != nil {
				g.logger.Printf("Error acknowledging message %s: %v", message.ID, err)
			}
		}
	}

	return nil
}

// processMessage processes a single event message
func (g *GeoIPPlugin) processMessage(message redis.XMessage) error {
	// Parse event message
	eventMsg := EventMessage{
		EventID:   getStringField(message.Values, "event_id"),
		EventType: getStringField(message.Values, "event_type"),
		RawJSON:   getStringField(message.Values, "raw_json"),
	}

	if timestamp := getStringField(message.Values, "timestamp"); timestamp != "" {
		// Parse timestamp if needed
	}

	g.logger.Printf("Processing event %s (type: %s)", eventMsg.EventID, eventMsg.EventType)

	// Extract IP addresses from the event
	ips := g.extractIPAddresses(eventMsg.RawJSON)
	if len(ips) == 0 {
		g.logger.Printf("No IP addresses found in event %s", eventMsg.EventID)
		return nil
	}

	// Perform GeoIP lookups
	enrichments := make(map[string]string)
	for _, ip := range ips {
		geoData, err := g.performGeoIPLookup(ip)
		if err != nil {
			g.logger.Printf("GeoIP lookup failed for %s: %v", ip, err)
			continue
		}

		// Add enrichment data
		prefix := fmt.Sprintf("geoip_%s", strings.ReplaceAll(ip, ".", "_"))
		enrichments[prefix+"_country"] = geoData.Country
		enrichments[prefix+"_country_code"] = geoData.CountryCode
		enrichments[prefix+"_region"] = geoData.Region
		enrichments[prefix+"_city"] = geoData.City
		enrichments[prefix+"_isp"] = geoData.ISP
		enrichments[prefix+"_asn"] = geoData.ASN
		enrichments[prefix+"_latitude"] = fmt.Sprintf("%.6f", geoData.Latitude)
		enrichments[prefix+"_longitude"] = fmt.Sprintf("%.6f", geoData.Longitude)
		enrichments[prefix+"_timezone"] = geoData.Timezone

		g.logger.Printf("GeoIP enrichment for %s: %s, %s (%s)", ip, geoData.City, geoData.Country, geoData.CountryCode)
	}

	// Publish enrichment if we have data
	if len(enrichments) > 0 {
		return g.publishEnrichment(eventMsg.EventID, enrichments)
	}

	return nil
}

// extractIPAddresses extracts IP addresses from event JSON
func (g *GeoIPPlugin) extractIPAddresses(rawJSON string) []string {
	var ips []string
	
	// Parse JSON to extract IP addresses
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(rawJSON), &event); err != nil {
		g.logger.Printf("Failed to parse event JSON: %v", err)
		return ips
	}

	// Extract source IP
	if srcEndpoint, ok := event["src_endpoint"].(map[string]interface{}); ok {
		if srcIP, ok := srcEndpoint["ip"].(string); ok && g.isValidIP(srcIP) {
			ips = append(ips, srcIP)
		}
	}

	// Extract destination IP
	if dstEndpoint, ok := event["dst_endpoint"].(map[string]interface{}); ok {
		if dstIP, ok := dstEndpoint["ip"].(string); ok && g.isValidIP(dstIP) {
			ips = append(ips, dstIP)
		}
	}

	// Extract device IP
	if device, ok := event["device"].(map[string]interface{}); ok {
		if deviceIP, ok := device["ip"].(string); ok && g.isValidIP(deviceIP) {
			ips = append(ips, deviceIP)
		}
	}

	return g.deduplicateIPs(ips)
}

 // GeoIPProvider defines an interface for GeoIP lookups
 type GeoIPProvider interface {
 	Lookup(ip string) (*GeoIPData, error)
 	Close() error
 }

 // IpapiConfig holds configuration for the IpapiProvider
 type IpapiConfig struct {
 	BaseURL       string
 	APIKey        string
 	Timeout       time.Duration
 	RateLimitRPS  int
 	CacheTTL      time.Duration
 	CacheSize     int
 	Logger        *log.Logger
 }

 // IpapiProvider implements GeoIP lookups via ipapi.co
 type IpapiProvider struct {
 	baseURL string
 	apiKey  string
 	client  *http.Client

 	logger *log.Logger

 	// simple token bucket
 	tokens chan struct{}
 	quit   chan struct{}

 	// simple TTL cache
 	mu    sync.Mutex
 	cache map[string]cacheEntry
 	ttl   time.Duration
 	maxN  int
 }

 type cacheEntry struct {
 	data   *GeoIPData
 	expiry time.Time
 }

 func NewIpapiProvider(cfg IpapiConfig) (*IpapiProvider, error) {
 	if cfg.BaseURL == "" {
 		cfg.BaseURL = "https://ipapi.co"
 	}
 	if cfg.Timeout <= 0 {
 		cfg.Timeout = 2 * time.Second
 	}
 	if cfg.RateLimitRPS <= 0 {
 		cfg.RateLimitRPS = 2
 	}
 	if cfg.CacheTTL <= 0 {
 		cfg.CacheTTL = 6 * time.Hour
 	}
 	if cfg.CacheSize <= 0 {
 		cfg.CacheSize = 500
 	}
 	p := &IpapiProvider{
 		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
 		apiKey:  cfg.APIKey,
 		client:  &http.Client{Timeout: cfg.Timeout},
 		logger:  cfg.Logger,
 		tokens:  make(chan struct{}, cfg.RateLimitRPS),
 		quit:    make(chan struct{}),
 		cache:   make(map[string]cacheEntry),
 		ttl:     cfg.CacheTTL,
 		maxN:    cfg.CacheSize,
 	}

 	// start token refiller
 	go func(rps int) {
 		t := time.NewTicker(time.Second / time.Duration(rps))
 		defer t.Stop()
 		for {
 			select {
 			case <-p.quit:
 				return
 			case <-t.C:
 				select {
 				case p.tokens <- struct{}{}:
 				default:
 					// bucket full
 				}
 			}
 		}
 	}(cfg.RateLimitRPS)

 	return p, nil
 }

 func (p *IpapiProvider) Close() error {
 	close(p.quit)
 	return nil
 }

 func (p *IpapiProvider) Lookup(ipStr string) (*GeoIPData, error) {
 	// basic validation
 	if net.ParseIP(ipStr) == nil {
 		return nil, fmt.Errorf("invalid IP: %s", ipStr)
 	}

 	// cache
 	if data := p.getCached(ipStr); data != nil {
 		if p.logger != nil {
 			p.logger.Printf("ipapi cache hit ip=%s", ipStr)
 		}
 		return data, nil
 	}

 	// rate limit
 	select {
 	case <-p.tokens:
 	case <-time.After(2 * time.Second):
 		return nil, fmt.Errorf("rate limit wait timeout")
 	}

 	// retries with backoff
 	var lastErr error
 	for attempt := 0; attempt < 3; attempt++ {
 		start := time.Now()
 		url := fmt.Sprintf("%s/%s/json/", p.baseURL, ipStr)
 		req, _ := http.NewRequest("GET", url, nil)
 		// ipapi free tier often doesn't require key; if present, pass in header as a placeholder or query param if service supports.
 		if p.apiKey != "" {
 			req.Header.Set("X-API-Key", p.apiKey)
 		}
 		resp, err := p.client.Do(req)
 		lat := time.Since(start).Milliseconds()
 		if err != nil {
 			lastErr = err
 			p.sleepBackoff(attempt)
 			continue
 		}
 		func() { defer resp.Body.Close() }()
 		body, _ := io.ReadAll(resp.Body)
 		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
 			lastErr = fmt.Errorf("ipapi status=%d body=%s", resp.StatusCode, truncate(string(body), 200))
 			p.sleepBackoff(attempt)
 			continue
 		}
 		if resp.StatusCode != 200 {
 			return nil, fmt.Errorf("ipapi non-200 status=%d body=%s", resp.StatusCode, truncate(string(body), 200))
 		}

 		var j map[string]interface{}
 		if err := json.Unmarshal(body, &j); err != nil {
 			return nil, fmt.Errorf("ipapi decode: %w", err)
 		}

 		geo := &GeoIPData{
 			IP:           ipStr,
 			Country:      str(j["country_name"]),
 			CountryCode:  str(j["country"]),
 			Region:       firstNonEmpty(str(j["region"]), str(j["region_code"])),
 			City:         str(j["city"]),
 			Latitude:     float64Num(j["latitude"]),
 			Longitude:    float64Num(j["longitude"]),
 			Timezone:     str(j["timezone"]),
 			ISP:          str(j["org"]),
 			Organization: str(j["org"]),
 			ASN:          str(j["asn"]),
 		}
 		// cache
 		p.setCached(ipStr, geo)
 		if p.logger != nil {
 			p.logger.Printf("ipapi lookup ip=%s status=%d latency_ms=%d", ipStr, resp.StatusCode, lat)
 		}
 		return geo, nil
 	}
 	return nil, lastErr
 }

 func (p *IpapiProvider) sleepBackoff(attempt int) {
 	base := 100 * time.Millisecond
 	backoff := time.Duration(1<<attempt) * base
 	jitter := time.Duration(rand.Intn(100)) * time.Millisecond
 	time.Sleep(backoff + jitter)
 }

 func (p *IpapiProvider) getCached(ip string) *GeoIPData {
 	p.mu.Lock()
 	defer p.mu.Unlock()
 	if ent, ok := p.cache[ip]; ok {
 		if time.Now().Before(ent.expiry) {
 			return ent.data
 		}
 		delete(p.cache, ip)
 	}
 	return nil
 }

 func (p *IpapiProvider) setCached(ip string, data *GeoIPData) {
 	p.mu.Lock()
 	defer p.mu.Unlock()
 	// evict random if over size
 	if len(p.cache) >= p.maxN {
 		for k := range p.cache {
 			delete(p.cache, k)
 			break
 		}
 	}
 	p.cache[ip] = cacheEntry{data: data, expiry: time.Now().Add(p.ttl)}
 }

 func truncate(s string, n int) string {
 	if len(s) <= n {
 		return s
 	}
 	return s[:n] + "..."
 }

 func str(v interface{}) string {
 	if v == nil {
 		return ""
 	}
 	if s, ok := v.(string); ok {
 		return s
 	}
 	return fmt.Sprintf("%v", v)
 }

 func float64Num(v interface{}) float64 {
 	switch t := v.(type) {
 	case float64:
 		return t
 	case float32:
 		return float64(t)
 	case int:
 		return float64(t)
 	case int64:
 		return float64(t)
 	case json.Number:
 		if f, err := t.Float64(); err == nil {
 			return f
 		}
 	}
 	return 0
 }

 // performGeoIPLookup performs GeoIP lookup for an IP address (ipapi-only POC)
 func (g *GeoIPPlugin) performGeoIPLookup(ip string) (*GeoIPData, error) {
 	// Private IPs handled locally (no HTTP call)
 	if g.isPrivateIP(ip) {
 		return &GeoIPData{
 			IP:           ip,
 			Country:      "Private Network",
 			CountryCode:  "XX",
 			Region:       "Private",
 			City:         "Private",
 			Latitude:     0.0,
 			Longitude:    0.0,
 			ISP:          "Private Network",
 			Organization: "Private Network",
 			ASN:          "AS0",
 			Timezone:     "UTC",
 		}, nil
 	}
 	// Provider lookup (ipapi)
 	if g.provider == nil {
 		return nil, fmt.Errorf("no GeoIP provider configured")
 	}
 	return g.provider.Lookup(ip)
 }

// publishEnrichment publishes enrichment data to Redis
func (g *GeoIPPlugin) publishEnrichment(eventID string, data map[string]string) error {
	enrichment := EnrichmentMessage{
		EventID:    eventID,
		Source:     "geoip",
		Type:       "geoip",
		Data:       data,
		Timestamp:  time.Now().Unix(),
		PluginName: "geoip-plugin",
	}

	// Serialize data
	dataJSON, err := json.Marshal(enrichment.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal enrichment data: %w", err)
	}

	// Publish to enrichments stream
	fields := map[string]interface{}{
		"event_id":    enrichment.EventID,
		"source":      enrichment.Source,
		"type":        enrichment.Type,
		"data":        string(dataJSON),
		"timestamp":   enrichment.Timestamp,
		"plugin_name": enrichment.PluginName,
	}

	result := g.client.XAdd(g.ctx, &redis.XAddArgs{
		Stream: "enrichments",
		Values: fields,
	})

	if err := result.Err(); err != nil {
		return fmt.Errorf("failed to publish enrichment: %w", err)
	}

	g.logger.Printf("Published enrichment for event %s", eventID)
	return nil
}

// Helper functions

func getStringField(values map[string]interface{}, key string) string {
	if value, ok := values[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

func (g *GeoIPPlugin) isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func (g *GeoIPPlugin) isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check for private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

func (g *GeoIPPlugin) deduplicateIPs(ips []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}

	return result
}
// Utility: return the first non-empty trimmed string
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}