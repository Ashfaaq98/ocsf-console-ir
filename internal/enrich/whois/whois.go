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
	"sort"
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

// domainPattern matches anything shaped like a dotted hostname.
var domainPattern = regexp.MustCompile(`([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}`)

// hostKeys hold a hostname because the producer said so. Their values are taken
// at face value, at any depth.
var hostKeys = map[string]bool{
	"domain": true, "host": true, "hostname": true, "fqdn": true,
	"url": true, "uri": true, "dns_name": true, "referrer": true,
}

// textKeys hold free text, which may mention a domain. These are pattern-scanned,
// with the filename and truncation filters applied.
var textKeys = map[string]bool{
	"message": true, "cmd_line": true, "command_line": true, "query": true,
	"answer": true, "subject": true, "description": true, "body": true,
	"raw": true,
}

// OCSF observable type_ids worth a WHOIS lookup.
const (
	observableHostname  = 1
	observableURLString = 6
)

// reservedTLDs are never registrable, so a lookup cannot succeed. Internal
// hostnames like corp.local are common in security events, and each one
// otherwise costs a rate-limited lookup and its retries.
var reservedTLDs = map[string]bool{
	"local": true, "localhost": true, "internal": true, "intranet": true,
	"lan": true, "corp": true, "home": true, "invalid": true, "test": true,
	"example": true, "onion": true, "arpa": true,
}

func hasReservedTLD(domain string) bool {
	idx := strings.LastIndex(domain, ".")
	if idx < 0 {
		return true
	}
	return reservedTLDs[strings.ToLower(domain[idx+1:])]
}

// extractDomains finds the domains in an event's raw JSON.
//
// It walks the parsed document by key rather than scanning the raw text. The text
// scan matched OCSF *field names* — process.name, user.name, file.name,
// file.hashes — and since .name is a real TLD those lookups succeeded, so every
// such event stored the .name registry's registrar and abuse contact as if they
// described the event. Keys are never values, so parsing first removes that
// entire class of false positive.
//
// Walking by key also stops the scan reading fields that never hold a hostname
// but often look like one: a "first.last" username, or a file name whose
// extension happens to be a TLD. That trades a little recall for precision, on
// the grounds that fabricated enrichment is worse than absent enrichment — and
// that indicators belong in observables, which are extracted separately.
func extractDomains(raw string) []string {
	var domains []string
	add := func(s string) {
		if d := domainFromString(s); d != "" && !hasReservedTLD(d) {
			domains = append(domains, d)
		}
	}

	var obj map[string]interface{}
	if json.Unmarshal([]byte(raw), &obj) == nil {
		walkForDomains(obj, "", add, func(s string) {
			for _, m := range scanForDomains(s) {
				add(m)
			}
		})
	} else {
		// A non-JSON payload has no keys to be confused by, so scan the text.
		for _, m := range scanForDomains(raw) {
			add(m)
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

// walkForDomains descends a decoded JSON document, handing values under hostKeys
// to trust and values under textKeys to scan. key is the name the current value
// was reached by; array elements inherit their array's key.
func walkForDomains(v interface{}, key string, trust, scan func(string)) {
	switch t := v.(type) {
	case string:
		switch {
		case hostKeys[key]:
			trust(t)
		case textKeys[key]:
			scan(t)
		}
	case map[string]interface{}:
		// Sorted so the domains found — and therefore the enrichment keys
		// written — are stable from one ingest to the next.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "observables" {
				walkObservables(t[k], trust)
				continue
			}
			walkForDomains(t[k], k, trust, scan)
		}
	case []interface{}:
		for _, item := range t {
			walkForDomains(item, key, trust, scan)
		}
	}
}

// walkObservables reads OCSF observables by their declared type rather than
// guessing from shape. Observables are typed, so a User Name ("j.doe") or a File
// Name is skipped outright instead of being looked up because it happens to
// contain a dot.
func walkObservables(v interface{}, trust func(string)) {
	items, ok := v.([]interface{})
	if !ok {
		return
	}
	for _, item := range items {
		o, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		value, _ := o["value"].(string)
		if value == "" || !observableIsHostLike(o) {
			continue
		}
		trust(value)
	}
}

func observableIsHostLike(o map[string]interface{}) bool {
	// type_id is the only required attribute of an OCSF observable, so prefer it.
	if id, ok := o["type_id"].(float64); ok && int(id) != 0 {
		return int(id) == observableHostname || int(id) == observableURLString
	}
	// Fall back to the caption for producers that send only the string form.
	if t, ok := o["type"].(string); ok {
		t = strings.ToLower(t)
		return strings.Contains(t, "hostname") || strings.Contains(t, "domain") || strings.Contains(t, "url")
	}
	return false
}

// scanForDomains returns the hostname-shaped substrings of s that survive the
// filename and truncation filters.
func scanForDomains(s string) []string {
	var out []string
	for _, loc := range domainPattern.FindAllStringIndex(s, -1) {
		m := s[loc[0]:loc[1]]
		// A match that runs straight into another alphanumeric character is a
		// fragment, not a hostname: "invoke.ps1" matches only "invoke.ps", and
		// .ps is a real TLD, so the truncated form would resolve.
		if loc[1] < len(s) && isAlphanumeric(s[loc[1]]) {
			continue
		}
		if looksLikeFilename(m) {
			continue
		}
		out = append(out, m)
	}
	return out
}

func isAlphanumeric(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// fileExtensions are final labels that mean "filename", not "hostname". Several
// are also real TLDs — .zip, .sh, .py, .md — so a filename caught by the pattern
// scan would otherwise resolve, and the unrelated registry's details would be
// stored as if they described the event.
//
// This list is applied only to pattern-scanned matches, never to a producer's
// own url/domain/host fields, so a genuine domain under one of these TLDs still
// enriches when the event actually says it is a domain.
var fileExtensions = map[string]bool{
	// Executables, libraries and scripts
	"exe": true, "dll": true, "sys": true, "drv": true, "ocx": true, "cpl": true,
	"scr": true, "msi": true, "msp": true, "bat": true, "cmd": true, "ps1": true,
	"psm1": true, "vbs": true, "vbe": true, "js": true, "jse": true, "wsf": true,
	"wsh": true, "hta": true, "jar": true, "class": true, "py": true, "pyc": true,
	"pyo": true, "pl": true, "rb": true, "sh": true, "bash": true, "zsh": true,
	"php": true, "asp": true, "aspx": true, "jsp": true, "elf": true, "so": true,
	// Documents and data
	"txt": true, "log": true, "ini": true, "cfg": true, "conf": true, "json": true,
	"xml": true, "yml": true, "yaml": true, "csv": true, "tsv": true, "md": true,
	"doc": true, "docx": true, "xls": true, "xlsx": true, "ppt": true, "pptx": true,
	"pdf": true, "rtf": true, "odt": true, "ods": true,
	// Archives and images
	"zip": true, "tar": true, "gz": true, "bz2": true, "xz": true, "7z": true,
	"rar": true, "cab": true, "iso": true, "img": true, "vhd": true, "vhdx": true,
	"png": true, "jpg": true, "jpeg": true, "gif": true, "bmp": true, "svg": true,
	"ico": true, "webp": true, "mp3": true, "mp4": true, "avi": true, "mov": true,
	"wav": true,
	// Runtime artefacts
	"db": true, "sqlite": true, "dat": true, "bin": true, "tmp": true, "temp": true,
	"bak": true, "old": true, "swp": true, "lnk": true, "pif": true, "reg": true,
	"pdb": true, "dmp": true, "core": true,
}

// looksLikeFilename reports whether a pattern-scanned match is more plausibly a
// file than a host.
func looksLikeFilename(s string) bool {
	idx := strings.LastIndex(s, ".")
	if idx < 0 || idx == len(s)-1 {
		return false
	}
	return fileExtensions[strings.ToLower(s[idx+1:])]
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
