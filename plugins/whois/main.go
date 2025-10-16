package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
	whois "github.com/likexian/whois"
)

type EventMessage struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	RawJSON   string `json:"raw_json"`
	Timestamp int64  `json:"timestamp"`
}

type EnrichmentMessage struct {
	EventID    string            `json:"event_id"`
	Source     string            `json:"source"`
	Type       string            `json:"type"`
	Data       map[string]string `json:"data"`
	Timestamp  int64             `json:"timestamp"`
	PluginName string            `json:"plugin_name"`
}

type WhoisProvider struct {
	clientTimeout time.Duration
	rateLimitRPS  int
	tokens        chan struct{}
	cacheTTL      time.Duration

	mu    chan struct{} // simple mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	data   string
	expiry time.Time
}

func NewWhoisProvider(timeout time.Duration, rps int, ttl time.Duration) *WhoisProvider {
	p := &WhoisProvider{
		clientTimeout: timeout,
		rateLimitRPS:  rps,
		tokens:        make(chan struct{}, rps),
		cacheTTL:      ttl,
		mu:            make(chan struct{}, 1),
		cache:         make(map[string]cacheEntry),
	}
	// refill tokens
	go func() {
		t := time.NewTicker(time.Second / time.Duration(max(1, rps)))
		defer t.Stop()
		for range t.C {
			select {
			case p.tokens <- struct{}{}:
			default:
			}
		}
	}()
	// init mutex
	p.mu <- struct{}{}
	return p
}

func (p *WhoisProvider) getCached(domain string) string {
	<-p.mu
	defer func() { p.mu <- struct{}{} }()
	if ent, ok := p.cache[domain]; ok {
		if time.Now().Before(ent.expiry) {
			return ent.data
		}
		delete(p.cache, domain)
	}
	return ""
}

func (p *WhoisProvider) setCached(domain string, data string) {
	<-p.mu
	defer func() { p.mu <- struct{}{} }()
	if len(p.cache) >= 500 {
		// evict arbitrary
		for k := range p.cache {
			delete(p.cache, k)
			break
		}
	}
	p.cache[domain] = cacheEntry{data: data, expiry: time.Now().Add(p.cacheTTL)}
}

func (p *WhoisProvider) Lookup(domain string) (string, error) {
	// normalize domain
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return "", fmt.Errorf("empty domain")
	}

	// cached?
	if v := p.getCached(domain); v != "" {
		return v, nil
	}

	// rate limit
	select {
	case <-p.tokens:
	case <-time.After(3 * time.Second):
		return "", fmt.Errorf("whois rate limit timeout")
	}

	// perform WHOIS with retries
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		raw, err := whois.Whois(domain)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(100*(1<<attempt)) * time.Millisecond)
			continue
		}
		// cache raw response
		p.setCached(domain, raw)
		return raw, nil
	}
	return "", lastErr
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// extractDomains attempts to find domains in the event raw JSON.
// It looks for common fields (url, domain, host) and falls back to a regex scan.
func extractDomains(raw string) []string {
	var domains []string

	// Try to parse as JSON and look for specific keys
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &obj); err == nil {
		// common fields
		checkStringKey := func(key string) {
			if v, ok := obj[key]; ok {
				if s, ok := v.(string); ok {
					if d := domainFromString(s); d != "" {
						domains = append(domains, d)
					}
				}
			}
		}
		checkStringKey("url")
		checkStringKey("domain")
		checkStringKey("host")
		// nested checks (like network endpoints)
		if ep, ok := obj["dst_endpoint"].(map[string]interface{}); ok {
			if host, ok := ep["host"].(string); ok {
				if d := domainFromString(host); d != "" {
					domains = append(domains, d)
				}
			}
		}
		if ep, ok := obj["src_endpoint"].(map[string]interface{}); ok {
			if host, ok := ep["host"].(string); ok {
				if d := domainFromString(host); d != "" {
					domains = append(domains, d)
				}
			}
		}
	}

	// Fallback: regex scan for domain-like patterns
	reg := regexp.MustCompile(`([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}`)
	matches := reg.FindAllString(raw, -1)
	for _, m := range matches {
		if d := domainFromString(m); d != "" {
			domains = append(domains, d)
		}
	}

	// deduplicate
	seen := make(map[string]bool)
	var out []string
	for _, d := range domains {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// domainFromString extracts the domain from a string that may be a URL or domain.
func domainFromString(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// if it looks like a URL
	if strings.Contains(s, "://") || strings.HasPrefix(s, "www.") {
		u, err := url.Parse(s)
		if err == nil && u.Host != "" {
			host := u.Host
			// strip port
			if idx := strings.Index(host, ":"); idx != -1 {
				host = host[:idx]
			}
			return strings.TrimPrefix(host, "www.")
		}
	}
	// if it's already a hostname/domain, normalize
	// strip possible trailing slashes
	s = strings.TrimSuffix(s, "/")
	// remove leading scheme if present
	if strings.HasPrefix(s, "http") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			return strings.TrimPrefix(u.Host, "www.")
		}
	}
	// naive validation: must contain a dot and letters
	if strings.Count(s, ".") >= 1 {
		return strings.TrimPrefix(s, "www.")
	}
	return ""
}

// normalizeWhois converts parsed WhoIs info into flat map[string]string for enrichment.
func normalizeWhois(domain string, raw string) map[string]string {
	data := make(map[string]string)
	prefix := fmt.Sprintf("whois_%s_", strings.ReplaceAll(domain, ".", "_"))

	// Basic regex extractions: registrar, creation, expiration, nameservers, emails
	// Registrar
	if m := regexp.MustCompile(`(?i)Registrar:\s*(.+)`).FindStringSubmatch(raw); len(m) >= 2 {
		data[prefix+"registrar"] = strings.TrimSpace(m[1])
	}

	// Creation / Registered / Creation Date
	if m := regexp.MustCompile(`(?i)(Creation Date|Registered on|Registered Date|Domain Registration Date):?\s*(.+)`).FindStringSubmatch(raw); len(m) >= 3 {
		data[prefix+"created_date"] = strings.TrimSpace(m[2])
	} else if m := regexp.MustCompile(`(?i)(Created:\s*)(.+)`).FindStringSubmatch(raw); len(m) >= 3 {
		data[prefix+"created_date"] = strings.TrimSpace(m[2])
	}

	// Expiration / Expiry
	if m := regexp.MustCompile(`(?i)(Registry Expiry Date|Expiration Date|Expiry Date|Expires on):?\s*(.+)`).FindStringSubmatch(raw); len(m) >= 3 {
		data[prefix+"expiration_date"] = strings.TrimSpace(m[2])
	}

	// Nameservers (multiple lines)
	nsMatches := regexp.MustCompile(`(?i)Name Server:\s*([^\s\r\n]+)`).FindAllStringSubmatch(raw, -1)
	if len(nsMatches) > 0 {
		var nss []string
		for _, mm := range nsMatches {
			if len(mm) >= 2 {
				nss = append(nss, strings.TrimSpace(mm[1]))
			}
		}
		if len(nss) > 0 {
			data[prefix+"nameservers"] = strings.Join(nss, ",")
		}
	} else if mm := regexp.MustCompile(`(?i)Nameservers?:\s*(.+)`).FindStringSubmatch(raw); len(mm) >= 2 {
		// comma or space separated
		ns := strings.FieldsFunc(mm[1], func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
		for i := range ns {
			ns[i] = strings.TrimSpace(ns[i])
		}
		data[prefix+"nameservers"] = strings.Join(ns, ",")
	}

	// Emails
	emailRe := regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	emails := emailRe.FindAllString(raw, -1)
	if len(emails) > 0 {
		// deduplicate
		seen := make(map[string]bool)
		var uniq []string
		for _, e := range emails {
			if !seen[e] {
				seen[e] = true
				uniq = append(uniq, e)
			}
		}
		data[prefix+"emails"] = strings.Join(uniq, ",")
	}

	// raw snippet
	if len(raw) > 0 {
		snippet := raw
		if len(snippet) > 800 {
			snippet = snippet[:800] + "..."
		}
		data[prefix+"raw_snippet"] = snippet
	}

	return data
}

func publishEnrichment(ctx context.Context, client *redis.Client, eventID string, data map[string]string) error {
	enrichment := EnrichmentMessage{
		EventID:    eventID,
		Source:     "whois",
		Type:       "whois",
		Data:       data,
		Timestamp:  time.Now().Unix(),
		PluginName: "whois-plugin",
	}
	b, err := json.Marshal(enrichment.Data)
	if err != nil {
		return err
	}
	fields := map[string]interface{}{
		"event_id":    enrichment.EventID,
		"source":      enrichment.Source,
		"type":        enrichment.Type,
		"data":        string(b),
		"timestamp":   enrichment.Timestamp,
		"plugin_name": enrichment.PluginName,
	}
	if err := client.XAdd(ctx, &redis.XAddArgs{
		Stream: "enrichments",
		Values: fields,
	}).Err(); err != nil {
		return err
	}
	return nil
}

func createConsumerGroup(ctx context.Context, client *redis.Client, group string) error {
	err := client.XGroupCreateMkStream(ctx, "events", group, "0").Err()
	if err != nil {
		if strings.Contains(err.Error(), "BUSYGROUP") {
			return nil
		}
		return err
	}
	return nil
}

func main() {
	var (
		redisURL     = flag.String("redis", "redis://localhost:6379", "Redis connection URL")
		consumerName = flag.String("consumer", "whois-plugin", "Consumer name for Redis streams")
		groupName    = flag.String("group", "console-ir-whois", "Redis consumer group name for events stream")
		timeout      = flag.Duration("timeout", 5*time.Second, "WHOIS client timeout")
		rateLimitRPS = flag.Int("rate-limit-rps", 1, "WHOIS requests per second")
		cacheTTL     = flag.Duration("cache-ttl", 24*time.Hour, "WHOIS cache TTL")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "[Whois] ", log.LstdFlags)
	logger.Println("Starting WHOIS plugin")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		logger.Println("shutdown signal received")
		cancel()
	}()

	opts, err := redis.ParseURL(*redisURL)
	if err != nil {
		logger.Fatalf("failed to parse redis url: %v", err)
	}
	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		logger.Fatalf("failed to ping redis: %v", err)
	}
	defer client.Close()

	// create consumer group
	if err := createConsumerGroup(ctx, client, *groupName); err != nil {
		logger.Fatalf("failed to create consumer group: %v", err)
	}

	provider := NewWhoisProvider(*timeout, *rateLimitRPS, *cacheTTL)

	logger.Printf("starting event loop (group=%s consumer=%s)", *groupName, *consumerName)
	for {
		select {
		case <-ctx.Done():
			logger.Println("stopping event loop")
			return
		default:
			res := client.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    *groupName,
				Consumer: *consumerName,
				Streams:  []string{"events", ">"},
				Count:    5,
				Block:    2 * time.Second,
			})
			if err := res.Err(); err != nil {
				if err == redis.Nil {
					continue
				}
				logger.Printf("xreadgroup error: %v", err)
				time.Sleep(2 * time.Second)
				continue
			}
			for _, stream := range res.Val() {
				for _, msg := range stream.Messages {
					eventID := getStringField(msg.Values, "event_id")
					raw := getStringField(msg.Values, "raw_json")
					if raw == "" {
						logger.Printf("message %s has no raw_json, skipping", msg.ID)
						_ = client.XAck(ctx, "events", *groupName, msg.ID).Err()
						continue
					}
					domains := extractDomains(raw)
					if len(domains) == 0 {
						logger.Printf("no domains found in event %s", eventID)
						_ = client.XAck(ctx, "events", *groupName, msg.ID).Err()
						continue
					}
					enrich := make(map[string]string)
					for _, d := range domains {
						raw, err := provider.Lookup(d)
						if err != nil {
							logger.Printf("whois lookup failed %s: %v", d, err)
							continue
						}
						n := normalizeWhois(d, raw)
						for k, v := range n {
							enrich[k] = v
						}
						logger.Printf("whois enrichment for %s (fields=%d)", d, len(n))
					}
					if len(enrich) > 0 {
						if err := publishEnrichment(ctx, client, eventID, enrich); err != nil {
							logger.Printf("failed to publish enrichment: %v", err)
						}
					}
					// Ack message
					if err := client.XAck(ctx, "events", *groupName, msg.ID).Err(); err != nil {
						logger.Printf("failed to ack message %s: %v", msg.ID, err)
					}
				}
			}
		}
	}
}

func getStringField(values map[string]interface{}, key string) string {
	if v, ok := values[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}