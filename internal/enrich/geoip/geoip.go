// Package geoip provides an in-process GeoIP enrichment plugin.
//
// It implements plugins.CorePlugin so the enrichment runs directly inside the
// console-ir binary, with no Redis broker or external subprocess. The lookup
// logic (ipapi.co provider, in-memory TTL cache, rate limiting, IP extraction)
// is ported verbatim from the former standalone plugin at plugins/geoip; only
// the transport (Redis streams) and process scaffolding (main, flags, signal
// handling) were removed.
package geoip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/plugins"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// Plugin is the in-process GeoIP enrichment plugin.
type Plugin struct {
	provider GeoIPProvider
	logger   *log.Logger
}

// New creates a GeoIP plugin backed by the ipapi.co provider with default
// tuning (matching the former standalone plugin's flag defaults). A nil logger
// discards output.
func New(logger *log.Logger) *Plugin {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	provider, err := NewIpapiProvider(IpapiConfig{Logger: logger})
	if err != nil {
		logger.Printf("geoip: failed to init ipapi provider: %v", err)
	}
	return &Plugin{provider: provider, logger: logger}
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "geoip" }

// Description returns a brief description of the plugin.
func (p *Plugin) Description() string { return "GeoIP location enrichment via ipapi.co" }

// Version returns the plugin version.
func (p *Plugin) Version() string { return "1.0.0" }

// Start initializes the plugin. The provider is ready on construction, so this
// is a no-op retained to satisfy the CorePlugin contract.
func (p *Plugin) Start(ctx context.Context) error { return nil }

// Stop shuts down the plugin, stopping the provider's background rate-limiter.
func (p *Plugin) Stop() error {
	if p.provider != nil {
		return p.provider.Close()
	}
	return nil
}

// HealthCheck reports plugin health.
func (p *Plugin) HealthCheck(ctx context.Context) error { return nil }

// GetConfig returns the plugin's configuration requirements. GeoIP works
// against the ipapi.co free tier with no required configuration.
func (p *Plugin) GetConfig() plugins.PluginConfig {
	return plugins.PluginConfig{
		OptionalEnvVars: []string{"IPAPI_API_KEY"},
	}
}

// Process extracts IP addresses from the event and enriches them with GeoIP
// data. It returns at most one enrichment whose Data merges the location fields
// for every IP found. store.ApplyEnrichment fills in the ID/EventID/timestamp.
func (p *Plugin) Process(ctx context.Context, event bus.EventMessage) ([]store.Enrichment, error) {
	if event.RawJSON == "" {
		return nil, nil
	}

	ips := extractIPAddresses(event.RawJSON)
	if len(ips) == 0 {
		return nil, nil
	}

	data := make(map[string]string)
	for _, ip := range ips {
		geoData, err := p.performGeoIPLookup(ip)
		if err != nil {
			p.logger.Printf("GeoIP lookup failed for %s: %v", ip, err)
			continue
		}

		prefix := fmt.Sprintf("geoip_%s", strings.ReplaceAll(ip, ".", "_"))
		data[prefix+"_country"] = geoData.Country
		data[prefix+"_country_code"] = geoData.CountryCode
		data[prefix+"_region"] = geoData.Region
		data[prefix+"_city"] = geoData.City
		data[prefix+"_isp"] = geoData.ISP
		data[prefix+"_asn"] = geoData.ASN
		data[prefix+"_latitude"] = fmt.Sprintf("%.6f", geoData.Latitude)
		data[prefix+"_longitude"] = fmt.Sprintf("%.6f", geoData.Longitude)
		data[prefix+"_timezone"] = geoData.Timezone
	}

	if len(data) == 0 {
		return nil, nil
	}

	return []store.Enrichment{{
		Source: "geoip",
		Type:   "geoip",
		Data:   data,
	}}, nil
}

// performGeoIPLookup performs a GeoIP lookup for an IP address. Private/reserved
// IPs are resolved locally without any HTTP call.
func (p *Plugin) performGeoIPLookup(ip string) (*GeoIPData, error) {
	if isPrivateIP(ip) {
		return &GeoIPData{
			IP:           ip,
			Country:      "Private Network",
			CountryCode:  "XX",
			Region:       "Private",
			City:         "Private",
			ISP:          "Private Network",
			Organization: "Private Network",
			ASN:          "AS0",
			Timezone:     "UTC",
		}, nil
	}
	if p.provider == nil {
		return nil, fmt.Errorf("no GeoIP provider configured")
	}
	return p.provider.Lookup(ip)
}

// GeoIPData represents GeoIP enrichment data.
type GeoIPData struct {
	IP           string  `json:"ip"`
	Country      string  `json:"country"`
	CountryCode  string  `json:"country_code"`
	Region       string  `json:"region"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	ISP          string  `json:"isp"`
	Organization string  `json:"organization"`
	ASN          string  `json:"asn"`
	Timezone     string  `json:"timezone"`
}

// GeoIPProvider defines an interface for GeoIP lookups.
type GeoIPProvider interface {
	Lookup(ip string) (*GeoIPData, error)
	Close() error
}

// IpapiConfig holds configuration for the IpapiProvider.
type IpapiConfig struct {
	BaseURL      string
	APIKey       string
	Timeout      time.Duration
	RateLimitRPS int
	CacheTTL     time.Duration
	CacheSize    int
	Logger       *log.Logger
}

// IpapiProvider implements GeoIP lookups via ipapi.co.
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

// NewIpapiProvider constructs an ipapi.co-backed provider, applying defaults for
// any zero-valued config field.
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

// Close stops the provider's background rate-limiter goroutine.
func (p *IpapiProvider) Close() error {
	close(p.quit)
	return nil
}

// Lookup resolves an IP to GeoIP data via ipapi.co, using the cache and rate limiter.
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
		// ipapi free tier often doesn't require key; if present, pass in header.
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
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
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

// extractIPAddresses extracts source, destination and device IPs from event JSON.
func extractIPAddresses(rawJSON string) []string {
	var ips []string

	var event map[string]interface{}
	if err := json.Unmarshal([]byte(rawJSON), &event); err != nil {
		return ips
	}

	if srcEndpoint, ok := event["src_endpoint"].(map[string]interface{}); ok {
		if srcIP, ok := srcEndpoint["ip"].(string); ok && isValidIP(srcIP) {
			ips = append(ips, srcIP)
		}
	}
	if dstEndpoint, ok := event["dst_endpoint"].(map[string]interface{}); ok {
		if dstIP, ok := dstEndpoint["ip"].(string); ok && isValidIP(dstIP) {
			ips = append(ips, dstIP)
		}
	}
	if device, ok := event["device"].(map[string]interface{}); ok {
		if deviceIP, ok := device["ip"].(string); ok && isValidIP(deviceIP) {
			ips = append(ips, deviceIP)
		}
	}

	return deduplicateIPs(ips)
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

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

func deduplicateIPs(ips []string) []string {
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

// firstNonEmpty returns the first non-empty trimmed string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
