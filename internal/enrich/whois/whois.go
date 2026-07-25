// Package whois provides an in-process WHOIS enrichment plugin.
//
// It implements the plugins.CorePlugin interface so the enrichment runs
// directly inside the console-ir binary, with no Redis broker or external
// subprocess. The lookup/parse logic is ported verbatim from the former
// standalone plugin at plugins/whois; only the transport (Redis streams) and
// process scaffolding (main, flags, signal handling) were removed.
package whois

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	whoislib "github.com/likexian/whois"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/plugins"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// Default provider tuning, matching the former standalone plugin's flag defaults.
const (
	defaultTimeout      = 5 * time.Second
	defaultRateLimitRPS = 1
	defaultCacheTTL     = 24 * time.Hour
)

// Plugin is the in-process WHOIS enrichment plugin.
type Plugin struct {
	provider *WhoisProvider
	logger   *log.Logger
}

// New creates a WHOIS plugin with default tuning. A nil logger discards output.
func New(logger *log.Logger) *Plugin {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Plugin{
		provider: NewWhoisProvider(defaultTimeout, defaultRateLimitRPS, defaultCacheTTL),
		logger:   logger,
	}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "whois" }

// Description returns a brief description of the plugin.
func (p *Plugin) Description() string { return "WHOIS domain registration enrichment" }

// Version returns the plugin version.
func (p *Plugin) Version() string { return "1.0.0" }

// Start initializes the plugin. The provider is ready on construction, so this
// is a no-op retained to satisfy the CorePlugin contract.
func (p *Plugin) Start(ctx context.Context) error { return nil }

// Stop shuts down the plugin gracefully.
func (p *Plugin) Stop() error { return nil }

// HealthCheck reports plugin health. WHOIS has no external dependency to probe.
func (p *Plugin) HealthCheck(ctx context.Context) error { return nil }

// GetConfig returns the plugin's configuration requirements. WHOIS needs none.
func (p *Plugin) GetConfig() plugins.PluginConfig {
	return plugins.PluginConfig{}
}

// Process extracts domains from the event and enriches them with WHOIS data.
// It returns at most one enrichment, whose Data merges the WHOIS fields for
// every domain found. store.ApplyEnrichment fills in the ID, EventID and
// timestamp, so those are left zero here.
func (p *Plugin) Process(ctx context.Context, event bus.EventMessage) ([]store.Enrichment, error) {
	if event.RawJSON == "" {
		return nil, nil
	}

	domains := extractDomains(event.RawJSON)
	if len(domains) == 0 {
		return nil, nil
	}

	data := make(map[string]string)
	for _, d := range domains {
		raw, err := p.provider.Lookup(d)
		if err != nil {
			p.logger.Printf("whois lookup failed %s: %v", d, err)
			continue
		}
		for k, v := range normalizeWhois(d, raw) {
			data[k] = v
		}
		p.logger.Printf("whois enrichment for %s", d)
	}

	if len(data) == 0 {
		return nil, nil
	}

	return []store.Enrichment{{
		Source: "whois",
		Type:   "whois",
		Data:   data,
	}}, nil
}

// WhoisProvider performs rate-limited, cached WHOIS lookups.
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

// NewWhoisProvider builds a provider with the given timeout, rate limit and cache TTL.
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

// Lookup returns the raw WHOIS response for a domain, using the cache and rate limiter.
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
		raw, err := whoislib.Whois(domain)
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

// normalizeWhois converts a raw WHOIS response into a flat map[string]string for enrichment.
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
