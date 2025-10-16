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

// IntelOwlPlugin encapsulates runtime state
type IntelOwlPlugin struct {
	client      *redis.Client
	intelClient IntelOwlAPI
	cache       *CacheManager
	logger      *log.Logger
	ctx         context.Context
	cancel      context.CancelFunc

	config       IntelOwlConfig
	redisURL     string
	consumerName string
	groupName    string

	metrics PluginMetrics
}

func main() {
	// Flags
	var (
		redisURL     = flag.String("redis", "redis://localhost:6379", "Redis connection URL")
		consumerName = flag.String("consumer", "intelowl-plugin", "Consumer name for Redis streams")
		groupName    = flag.String("group", "console-ir-intelowl", "Redis consumer group for events stream")

		// IntelOwl configuration
		owlURL     = flag.String("intelowl-url", "", "IntelOwl base URL")
		apiToken   = flag.String("api-key", "", "IntelOwl API token")
		verifyTLS  = flag.Bool("verify-tls", true, "Verify TLS certificates")
		timeout    = flag.Duration("timeout", 30*time.Second, "IntelOwl API timeout")

		// Limits
		rateLimitRPS = flag.Int("rate-limit-rps", 5, "IntelOwl requests per second")
		burstLimit   = flag.Int("burst-limit", 10, "Rate limit burst size")

		// Cache
		cacheTTL      = flag.Duration("cache-ttl", 4*time.Hour, "Cache TTL for intel results")
		cacheSize     = flag.Int("cache-size", 2000, "Maximum cache entries")
		useRedisCache = flag.Bool("use-redis-cache", true, "Use Redis for caching")

		// Mode and polling
		mode         = flag.String("mode", ModeQuery, "Operation mode: query|submit")
		pollInterval = flag.Duration("poll-interval", 2*time.Second, "Polling interval for submit mode")
		pollTimeout  = flag.Duration("poll-timeout", 60*time.Second, "Polling timeout for submit mode")
		maxConc      = flag.Int("max-concurrent", 2, "Max concurrent submissions")

		// Analyzer control
		anIP     = flag.String("analyzers-ip", "", "Comma-separated analyzers for IP")
		anDomain = flag.String("analyzers-domain", "", "Comma-separated analyzers for domain")
		anURL    = flag.String("analyzers-url", "", "Comma-separated analyzers for URL")
		anHash   = flag.String("analyzers-hash", "", "Comma-separated analyzers for file hash")
		anEmail  = flag.String("analyzers-email", "", "Comma-separated analyzers for email")
		exclude  = flag.String("exclude-analyzers", "", "Comma-separated analyzers to exclude")

		// Filters and debug
		minConfidence = flag.String("min-confidence", "low", "Minimum confidence to publish (info|low|medium|high)")
		dryRun        = flag.Bool("dry-run", false, "Enable dry-run with mock IntelOwl")
	)
	flag.Parse()

	// Logger
	logger := log.New(os.Stdout, "[IntelOwl] ", log.LstdFlags)
	logger.Println("Starting IntelOwl enrichment plugin (staging-safe defaults)")

	// Resolve from environment if not provided
	if *apiToken == "" {
		if v := os.Getenv("INTEL_OWL_TOKEN"); v != "" {
			*apiToken = v
		}
	}
	if *owlURL == "" {
		if v := os.Getenv("INTEL_OWL_URL"); v != "" {
			*owlURL = v
		}
	}

	// Build configuration
	config := IntelOwlConfig{
		BaseURL:        *owlURL,
		Token:          *apiToken,
		VerifyTLS:      *verifyTLS,
		Timeout:        *timeout,
		RateLimitRPS:   *rateLimitRPS,
		BurstLimit:     *burstLimit,
		UseRedisCache:  *useRedisCache,
		CacheTTL:       *cacheTTL,
		CacheSize:      *cacheSize,
		Mode:           strings.ToLower(strings.TrimSpace(*mode)),
		PollInterval:   *pollInterval,
		PollTimeout:    *pollTimeout,
		MaxConcurrent:  *maxConc,
		AnalyzersIP:    splitCSV(*anIP),
		AnalyzersDomain: splitCSV(*anDomain),
		AnalyzersURL:   splitCSV(*anURL),
		AnalyzersHash:  splitCSV(*anHash),
		AnalyzersEmail: splitCSV(*anEmail),
		ExcludeAnalyzers: splitCSV(*exclude),
		MinConfidence:  strings.ToLower(strings.TrimSpace(*minConfidence)),
	}

	// Context and signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		logger.Printf("Signal %v received, shutting down...", s)
		cancel()
	}()

	plugin := &IntelOwlPlugin{
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		config:       config,
		redisURL:     *redisURL,
		consumerName: *consumerName,
		groupName:    *groupName,
		metrics:      PluginMetrics{},
	}

	// IntelOwl client selection
	if *dryRun {
		logger.Println("Dry-run enabled: using mock IntelOwl client")
		plugin.intelClient = NewMockIntelOwlClient(logger)
	} else {
		// If submit mode was explicitly requested, warn that live submission isn't implemented in this version.
		if plugin.config.Mode == ModeSubmit {
			logger.Println("Submit mode requested, but live submission is not implemented yet; using mock client for safety")
			plugin.intelClient = NewMockIntelOwlClient(logger)
		} else {
			if plugin.config.BaseURL == "" || plugin.config.Token == "" {
				logger.Println("IntelOwl URL or Token not provided; falling back to mock client")
				plugin.intelClient = NewMockIntelOwlClient(logger)
			} else {
				plugin.intelClient = NewRealIntelOwlClient(realClientOpts{
					BaseURL:   plugin.config.BaseURL,
					Token:     plugin.config.Token,
					VerifyTLS: plugin.config.VerifyTLS,
					Timeout:   plugin.config.Timeout,
					RPS:       plugin.config.RateLimitRPS,
					Burst:     plugin.config.BurstLimit,
					Logger:    plugin.logger,
				})
			}
		}
	}
	defer plugin.intelClient.Close()

	// Cache
	if err := plugin.initializeCache(); err != nil {
		logger.Fatalf("Failed to initialize cache: %v", err)
	}
	defer plugin.cache.Close()

	// Redis
	if err := plugin.connectRedis(); err != nil {
		logger.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer plugin.client.Close()

	// Start processing
	logger.Println("Starting event processing...")
	if err := plugin.run(); err != nil {
		logger.Fatalf("Plugin error: %v", err)
	}
	logger.Println("IntelOwl plugin stopped")
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (p *IntelOwlPlugin) initializeCache() error {
	cache, err := NewCacheManager(
		p.config.UseRedisCache,
		p.redisURL,
		p.config.CacheSize,
		p.logger,
	)
	if err != nil {
		return fmt.Errorf("create cache manager: %w", err)
	}
	p.cache = cache
	p.logger.Printf("Cache initialized (Redis: %v, Size: %d, TTL: %v)", p.config.UseRedisCache, p.config.CacheSize, p.config.CacheTTL)
	return nil
}

func (p *IntelOwlPlugin) connectRedis() error {
	opts, err := redis.ParseURL(p.redisURL)
	if err != nil {
		return fmt.Errorf("parse redis url: %w", err)
	}
	p.client = redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
	defer cancel()
	if err := p.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping: %w", err)
	}
	p.logger.Println("Connected to Redis")
	return nil
}

func (p *IntelOwlPlugin) run() error {
	if err := p.createConsumerGroup(); err != nil {
		return err
	}
	return p.processEvents()
}

func (p *IntelOwlPlugin) createConsumerGroup() error {
	result := p.client.XGroupCreateMkStream(p.ctx, "events", p.groupName, "0")
	if err := result.Err(); err != nil {
		if !strings.Contains(err.Error(), "BUSYGROUP") {
			return err
		}
	}
	p.logger.Printf("Consumer group ready (group=%s)", p.groupName)
	return nil
}

func (p *IntelOwlPlugin) processEvents() error {
	p.logger.Printf("Starting event consumer: %s (group=%s)", p.consumerName, p.groupName)
	for {
		select {
		case <-p.ctx.Done():
			p.logger.Println("Stopping event processing")
			return p.ctx.Err()
		default:
			if err := p.readAndProcess(); err != nil {
				if p.ctx.Err() != nil {
					return p.ctx.Err()
				}
				p.logger.Printf("Error processing events: %v", err)
				time.Sleep(2 * time.Second)
			}
		}
	}
}

func (p *IntelOwlPlugin) readAndProcess() error {
	res := p.client.XReadGroup(p.ctx, &redis.XReadGroupArgs{
		Group:    p.groupName,
		Consumer: p.consumerName,
		Streams:  []string{"events", ">"},
		Count:    4,
		Block:    1 * time.Second,
	})
	if err := res.Err(); err != nil {
		if err == redis.Nil {
			return nil
		}
		return err
	}
	for _, str := range res.Val() {
		for _, msg := range str.Messages {
			if err := p.processMessage(msg); err != nil {
				p.logger.Printf("Message %s error: %v", msg.ID, err)
				continue
			}
			if err := p.client.XAck(p.ctx, "events", p.groupName, msg.ID).Err(); err != nil {
				p.logger.Printf("Ack %s error: %v", msg.ID, err)
			}
		}
	}
	return nil
}

func (p *IntelOwlPlugin) processMessage(message redis.XMessage) error {
	start := time.Now()

	eventMsg := EventMessage{
		EventID:   getString(message.Values, "event_id"),
		EventType: getString(message.Values, "event_type"),
		RawJSON:   getString(message.Values, "raw_json"),
		Timestamp: getString(message.Values, "timestamp"),
	}
	if eventMsg.EventID == "" {
		eventMsg.EventID = "unknown"
	}

	observables := p.extractObservables(eventMsg.RawJSON)
	if len(observables) == 0 {
		return nil
	}

	enrichment := make(map[string]string)
	for _, obs := range observables {
		intel, err := p.getOrFetchIntel(obs)
		if err != nil {
			p.logger.Printf("Intel fetch failed for %s %s: %v", obs.Type, obs.Value, err)
			continue
		}
		if intel == nil {
			continue
		}
		fields := p.convertToEnrichmentFields(obs, intel)
		for k, v := range fields {
			enrichment[k] = v
		}
	}

	if len(enrichment) > 0 {
		if err := p.publishEnrichment(eventMsg.EventID, enrichment); err != nil {
			return err
		}
		p.metrics.EnrichmentsAdded++
	}

	// Metrics
	p.metrics.EventsProcessed++
	p.metrics.LastActivity = time.Now()
	dur := time.Since(start)
	if p.metrics.EventsProcessed > 0 {
		p.metrics.AverageProcessTime = time.Duration(
			(int64(p.metrics.AverageProcessTime)*int64(p.metrics.EventsProcessed-1)+int64(dur))/
				int64(p.metrics.EventsProcessed),
		)
	} else {
		p.metrics.AverageProcessTime = dur
	}

	return nil
}

func getString(values map[string]interface{}, key string) string {
	if v, ok := values[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (p *IntelOwlPlugin) publishEnrichment(eventID string, data map[string]string) error {
	// Publish in the structured format consumed by the core enricher (see internal/bus/redis_bus.go)
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal enrichment data: %w", err)
	}
	fields := map[string]interface{}{
		"event_id":    eventID,
		"source":      "intelowl",
		"type":        "intelowl",
		"data":        string(b),
		"timestamp":   time.Now().Unix(),
		"plugin_name": "intelowl-plugin",
	}
	return p.client.XAdd(p.ctx, &redis.XAddArgs{
		Stream: "enrichments",
		Values: fields,
	}).Err()
}

func (p *IntelOwlPlugin) getOrFetchIntel(obs Observable) (*IntelOwlResult, error) {
	cacheKey := generateCacheKey(obs.Type, obs.Value)
	if intel, ok := p.cache.Get(cacheKey); ok {
		return intel, nil
	}

	var analyzers []string
	switch obs.Type {
	case "ip":
		analyzers = p.config.AnalyzersIP
	case "domain":
		analyzers = p.config.AnalyzersDomain
	case "url":
		analyzers = p.config.AnalyzersURL
	case "hash":
		analyzers = p.config.AnalyzersHash
	case "email":
		analyzers = p.config.AnalyzersEmail
	}

	ctx, cancel := context.WithTimeout(p.ctx, p.config.Timeout)
	defer cancel()

	var intel *IntelOwlResult
	var err error
	if p.config.Mode == ModeQuery {
		intel, err = p.intelClient.QueryObservable(ctx, obs, analyzers)
	} else {
		intel, err = p.intelClient.SubmitAndPoll(ctx, obs, analyzers, p.config.PollInterval, p.config.PollTimeout)
	}

	if err != nil {
		return nil, err
	}
	if intel != nil {
		p.cache.Set(cacheKey, intel, p.config.CacheTTL)
	}
	return intel, nil
}

// Observable extraction — permissive and similar to other plugins

func (p *IntelOwlPlugin) extractObservables(rawJSON string) []Observable {
	var observables []Observable
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(rawJSON), &event); err != nil {
		p.logger.Printf("Parse event JSON error: %v", err)
		return observables
	}

	// IPs
	ips := p.extractIPs(event)
	for _, ip := range ips {
		observables = append(observables, Observable{Type: "ip", Value: ip})
	}

	// Domains
	domains := p.extractDomains(event)
	for _, d := range domains {
		observables = append(observables, Observable{Type: "domain", Value: d})
	}

	// Hashes
	hashes := p.extractHashes(event)
	for _, h := range hashes {
		observables = append(observables, Observable{Type: "hash", Value: h})
	}

	// URLs
	urls := p.extractURLs(event)
	for _, u := range urls {
		observables = append(observables, Observable{Type: "url", Value: u})
	}

	// Emails
	emails := p.extractEmails(event)
	for _, e := range emails {
		observables = append(observables, Observable{Type: "email", Value: e})
	}

	return p.deduplicateObservables(observables)
}

func (p *IntelOwlPlugin) extractIPs(event map[string]interface{}) []string {
	var out []string
	try := func(m map[string]interface{}, key string) {
		if v, ok := m[key].(string); ok && isValidIP(v) {
			out = append(out, v)
		}
	}
	if m, ok := event["src_endpoint"].(map[string]interface{}); ok {
		try(m, "ip")
	}
	if m, ok := event["dst_endpoint"].(map[string]interface{}); ok {
		try(m, "ip")
	}
	if m, ok := event["device"].(map[string]interface{}); ok {
		try(m, "ip")
	}
	return out
}

func (p *IntelOwlPlugin) extractDomains(event map[string]interface{}) []string {
	var out []string
	if m, ok := event["src_endpoint"].(map[string]interface{}); ok {
		if v, ok := m["hostname"].(string); ok {
			if d := extractDomainFromHostname(v); d != "" {
				out = append(out, d)
			}
		}
	}
	if m, ok := event["dst_endpoint"].(map[string]interface{}); ok {
		if v, ok := m["hostname"].(string); ok {
			if d := extractDomainFromHostname(v); d != "" {
				out = append(out, d)
			}
		}
	}
	// From flat URL field
	if v, ok := event["url"].(string); ok {
		if d := extractDomainFromURL(v); d != "" {
			out = append(out, d)
		}
	}
	// Also consider http_request.url if present (to align with URL extraction and tests)
	if httpReq, ok := event["http_request"].(map[string]interface{}); ok {
		if v, ok := httpReq["url"].(string); ok {
			if d := extractDomainFromURL(v); d != "" {
				out = append(out, d)
			}
		}
	}
	return out
}

func (p *IntelOwlPlugin) extractHashes(event map[string]interface{}) []string {
	var out []string
	if f, ok := event["file"].(map[string]interface{}); ok {
		if hm, ok := f["hashes"].(map[string]interface{}); ok {
			for _, h := range hm {
				if s, ok := h.(string); ok && isValidHash(s) {
					out = append(out, s)
				}
			}
		}
	}
	if proc, ok := event["process"].(map[string]interface{}); ok {
		if pf, ok := proc["file"].(map[string]interface{}); ok {
			if hm, ok := pf["hashes"].(map[string]interface{}); ok {
				for _, h := range hm {
					if s, ok := h.(string); ok && isValidHash(s) {
						out = append(out, s)
					}
				}
			}
		}
	}
	return out
}

func (p *IntelOwlPlugin) extractURLs(event map[string]interface{}) []string {
	var out []string
	if v, ok := event["url"].(string); ok && isValidURL(v) {
		out = append(out, v)
	}
	if httpReq, ok := event["http_request"].(map[string]interface{}); ok {
		if v, ok := httpReq["url"].(string); ok && isValidURL(v) {
			out = append(out, v)
		}
	}
	return out
}

func (p *IntelOwlPlugin) extractEmails(event map[string]interface{}) []string {
	var out []string
	if actor, ok := event["actor"].(map[string]interface{}); ok {
		if user, ok := actor["user"].(map[string]interface{}); ok {
			if v, ok := user["email_addr"].(string); ok && isValidEmail(v) {
				out = append(out, v)
			}
		}
	}
	if user, ok := event["user"].(map[string]interface{}); ok {
		if v, ok := user["email_addr"].(string); ok && isValidEmail(v) {
			out = append(out, v)
		}
	}
	return out
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isValidHash(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	re := regexp.MustCompile(`^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$|^[a-f0-9]{128}$`)
	return re.MatchString(h)
}

func isValidURL(u string) bool {
	parsed, err := url.Parse(u)
	return err == nil && parsed.Scheme != "" && parsed.Host != ""
}

func isValidEmail(e string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(e)
}

func extractDomainFromHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return ""
	}
	if strings.Contains(h, ".") && net.ParseIP(h) == nil {
		return h
	}
	return ""
}

func extractDomainFromURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Host)
}

func (p *IntelOwlPlugin) deduplicateObservables(in []Observable) []Observable {
	seen := make(map[string]bool)
	var out []Observable
	for _, o := range in {
		k := o.Type + ":" + o.Value
		if !seen[k] {
			seen[k] = true
			out = append(out, o)
		}
	}
	return out
}