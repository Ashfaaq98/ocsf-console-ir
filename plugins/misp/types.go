package main

import (
	"time"
)

// EventMessage represents an event from the Redis stream
type EventMessage struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	RawJSON   string `json:"raw_json"`
	Timestamp int64  `json:"timestamp"`
}

// EnrichmentMessage represents an enrichment to be published
type EnrichmentMessage struct {
	EventID    string            `json:"event_id"`
	Source     string            `json:"source"`
	Type       string            `json:"type"`
	Data       map[string]string `json:"data"`
	Timestamp  int64             `json:"timestamp"`
	PluginName string            `json:"plugin_name"`
}

// MISPConfig holds configuration for the MISP plugin
type MISPConfig struct {
	// API Configuration
	BaseURL         string        `yaml:"base_url"`
	APIKey          string        `yaml:"api_key"`
	Timeout         time.Duration `yaml:"timeout"`
	VerifyTLS       bool          `yaml:"verify_tls"`
	
	// Rate Limiting
	RateLimitRPS    int           `yaml:"rate_limit_rps"`
	BurstLimit      int           `yaml:"burst_limit"`
	
	// Caching
	CacheTTL        time.Duration `yaml:"cache_ttl"`
	CacheSize       int           `yaml:"cache_size"`
	UseRedisCache   bool          `yaml:"use_redis_cache"`
	
	// Query Settings
	DaysBack        int           `yaml:"days_back"`
	OnlyToIDS       bool          `yaml:"only_to_ids"`
	IncludeContext  bool          `yaml:"include_context"`
	MaxResults      int           `yaml:"max_results"`
	
	// Event Correlation
	CorrelateEvents bool          `yaml:"correlate_events"`
	MaxCorrelations int           `yaml:"max_correlations"`
	
	// Observable Types to Process
	ProcessIPs      bool          `yaml:"process_ips"`
	ProcessDomains  bool          `yaml:"process_domains"`
	ProcessHashes   bool          `yaml:"process_hashes"`
	ProcessURLs     bool          `yaml:"process_urls"`
	ProcessEmails   bool          `yaml:"process_emails"`
	
	// Filtering
	MinThreatLevel  int           `yaml:"min_threat_level"`
	ExcludedOrgs    []string      `yaml:"excluded_orgs"`
	RequiredTags    []string      `yaml:"required_tags"`
}

// Observable represents an extracted observable from an event
type Observable struct {
	Type  string `json:"type"`  // ip, domain, hash, url, email
	Value string `json:"value"`
}

// MISP API Response Types

// MISPResponse represents the standard MISP API response wrapper
type MISPResponse struct {
	Response interface{} `json:"response"`
}

// MISPAttributeResponse represents the response from attribute search
type MISPAttributeResponse struct {
	Response struct {
		Attribute []MISPAttribute `json:"Attribute"`
	} `json:"response"`
}

// MISPEventResponse represents the response from event search
type MISPEventResponse struct {
	Response []MISPEvent `json:"response"`
}

// MISPAttribute represents a MISP attribute
type MISPAttribute struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Category     string    `json:"category"`
	Value        string    `json:"value"`
	ToIDS        bool      `json:"to_ids"`
	UUID         string    `json:"uuid"`
	Timestamp    string    `json:"timestamp"`
	Distribution string    `json:"distribution"`
	Comment      string    `json:"comment"`
	Deleted      bool      `json:"deleted"`
	ObjectID     string    `json:"object_id"`
	EventID      string    `json:"event_id"`
	
	// Related data
	Event        *MISPEventInfo `json:"Event,omitempty"`
	Tags         []MISPTag      `json:"Tag,omitempty"`
	Galaxy       []MISPGalaxy   `json:"Galaxy,omitempty"`
	
	// Timestamps
	FirstSeen    *time.Time     `json:"first_seen,omitempty"`
	LastSeen     *time.Time     `json:"last_seen,omitempty"`
}

// MISPEvent represents a complete MISP event
type MISPEvent struct {
	ID                string         `json:"id"`
	UUID              string         `json:"uuid"`
	Info              string         `json:"info"`
	Date              string         `json:"date"`
	ThreatLevelID     string         `json:"threat_level_id"`
	Published         bool           `json:"published"`
	Analysis          string         `json:"analysis"`
	Distribution      string         `json:"distribution"`
	OrgID             string         `json:"org_id"`
	Timestamp         string         `json:"timestamp"`
	AttributeCount    string         `json:"attribute_count"`
	EventCreatorEmail string         `json:"event_creator_email"`
	
	// Related data
	Org          *MISPOrganization `json:"Org,omitempty"`
	Orgc         *MISPOrganization `json:"Orgc,omitempty"`
	Attributes   []MISPAttribute   `json:"Attribute,omitempty"`
	Tags         []MISPTag         `json:"Tag,omitempty"`
	Galaxy       []MISPGalaxy      `json:"Galaxy,omitempty"`
	RelatedEvent []MISPRelatedEvent `json:"RelatedEvent,omitempty"`
}

// MISPEventInfo represents minimal event information for correlation
type MISPEventInfo struct {
	ID             string            `json:"id"`
	UUID           string            `json:"uuid"`
	Info           string            `json:"info"`
	Date           string            `json:"date"`
	ThreatLevelID  string            `json:"threat_level_id"`
	Analysis       string            `json:"analysis"`
	AttributeCount string            `json:"attribute_count"`
	Org            *MISPOrganization `json:"Org,omitempty"`
	Orgc           *MISPOrganization `json:"Orgc,omitempty"`
}

// MISPOrganization represents an organization in MISP
type MISPOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

// MISPTag represents a tag in MISP
type MISPTag struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Colour       string `json:"colour"`
	Exportable   bool   `json:"exportable"`
	UserID       string `json:"user_id,omitempty"`
	HideTag      bool   `json:"hide_tag"`
	Numerical    bool   `json:"numerical_value,omitempty"`
}

// MISPGalaxy represents a galaxy cluster in MISP
type MISPGalaxy struct {
	ID          string              `json:"id"`
	UUID        string              `json:"uuid"`
	Name        string              `json:"name"`
	Type        string              `json:"type"`
	Description string              `json:"description"`
	Version     string              `json:"version"`
	Icon        string              `json:"icon"`
	Namespace   string              `json:"namespace"`
	
	// Galaxy clusters
	GalaxyCluster []MISPGalaxyCluster `json:"GalaxyCluster,omitempty"`
}

// MISPGalaxyCluster represents a galaxy cluster
type MISPGalaxyCluster struct {
	ID          string                 `json:"id"`
	UUID        string                 `json:"uuid"`
	Type        string                 `json:"type"`
	Value       string                 `json:"value"`
	Tag         string                 `json:"tag_name"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Authors     []string               `json:"authors"`
	Version     string                 `json:"version"`
	
	// Metadata
	Meta        map[string]interface{} `json:"meta,omitempty"`
	Synonyms    []string               `json:"synonyms,omitempty"`
}

// MISPRelatedEvent represents a related event
type MISPRelatedEvent struct {
	ID   string `json:"id"`
	Date string `json:"date"`
	Info string `json:"info"`
	Org  *MISPOrganization `json:"Org,omitempty"`
}

// MISPSharingGroup represents a sharing group
type MISPSharingGroup struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Releasable  bool   `json:"releasable"`
	Description string `json:"description"`
	UUID        string `json:"uuid"`
	OrgID       string `json:"org_id"`
	SyncUserID  string `json:"sync_user_id"`
	Active      bool   `json:"active"`
	Created     string `json:"created"`
	Modified    string `json:"modified"`
}

// Threat Intelligence Types

// MISPThreatIntelligence represents processed threat intelligence for an observable
type MISPThreatIntelligence struct {
	Observable      Observable         `json:"observable"`
	Attributes      []MISPAttribute    `json:"attributes"`
	Events          []MISPEventInfo    `json:"events"`
	Tags            []string           `json:"tags"`
	Categories      []string           `json:"categories"`
	Organizations   []string           `json:"organizations"`
	SharingGroups   []string           `json:"sharing_groups"`
	GalaxyClusters  []MISPGalaxyCluster `json:"galaxy_clusters"`
	ThreatLevel     string             `json:"threat_level"`
	ToIDS           bool               `json:"to_ids"`
	FirstSeen       time.Time          `json:"first_seen"`
	LastSeen        time.Time          `json:"last_seen"`
	RelatedIOCs     []RelatedIOC       `json:"related_iocs"`
	QueryTime       time.Time          `json:"query_time"`
}

// RelatedIOC represents a related indicator of compromise
type RelatedIOC struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	EventID  string `json:"event_id"`
	Category string `json:"category"`
}

// Cache Types

// CacheEntry represents a cached threat intelligence result
type CacheEntry struct {
	Data   *MISPThreatIntelligence `json:"data"`
	Expiry time.Time               `json:"expiry"`
}

// Plugin Metrics

// PluginMetrics holds metrics for monitoring
type PluginMetrics struct {
	EventsProcessed    int64         `json:"events_processed"`
	EnrichmentsAdded   int64         `json:"enrichments_added"`
	CacheHits          int64         `json:"cache_hits"`
	CacheMisses        int64         `json:"cache_misses"`
	APICallsSuccess    int64         `json:"api_calls_success"`
	APICallsError      int64         `json:"api_calls_error"`
	AttributesFound    int64         `json:"attributes_found"`
	EventsCorrelated   int64         `json:"events_correlated"`
	AverageProcessTime time.Duration `json:"average_process_time"`
	LastActivity       time.Time     `json:"last_activity"`
}

// API Request Types

// AttributeSearchRequest represents a request to search for attributes
type AttributeSearchRequest struct {
	Value        string   `json:"value,omitempty"`
	Type         string   `json:"type,omitempty"`
	Category     string   `json:"category,omitempty"`
	ToIDS        *bool    `json:"to_ids,omitempty"`
	Last         string   `json:"last,omitempty"`
	EventID      string   `json:"eventid,omitempty"`
	WithContext  bool     `json:"includeContext,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Limit        int      `json:"limit,omitempty"`
	Page         int      `json:"page,omitempty"`
}

// EventSearchRequest represents a request to search for events
type EventSearchRequest struct {
	EventID      string   `json:"eventid,omitempty"`
	Info         string   `json:"eventinfo,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	DateFrom     string   `json:"datefrom,omitempty"`
	DateUntil    string   `json:"dateuntil,omitempty"`
	Last         string   `json:"last,omitempty"`
	Org          string   `json:"org,omitempty"`
	ThreatLevel  string   `json:"threatlevel,omitempty"`
	Published    *bool    `json:"published,omitempty"`
	IncludeAttrs bool     `json:"includeAttachments,omitempty"`
	Limit        int      `json:"limit,omitempty"`
}

// API Error Types

// MISPError represents an error response from MISP API
type MISPError struct {
	Name    string   `json:"name"`
	Message string   `json:"message"`
	URL     string   `json:"url"`
	Code    int      `json:"code"`
	Errors  []string `json:"errors,omitempty"`
}

// Authentication and Authorization

// MISPUser represents a MISP user for authentication context
type MISPUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Org   *MISPOrganization `json:"Organisation"`
	Role  *MISPRole `json:"Role"`
}

// MISPRole represents a user role
type MISPRole struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	PermPublish  bool   `json:"perm_publish"`
	PermSync     bool   `json:"perm_sync"`
	PermAdmin    bool   `json:"perm_admin"`
	PermAudit    bool   `json:"perm_audit"`
	PermAuth     bool   `json:"perm_auth"`
	PermSiteAdmin bool  `json:"perm_site_admin"`
}

// Threat Level Constants
const (
	ThreatLevelHigh         = "1"
	ThreatLevelMedium       = "2"
	ThreatLevelLow          = "3"
	ThreatLevelUndefined    = "4"
)

// Analysis Level Constants
const (
	AnalysisInitial    = "0"
	AnalysisOngoing    = "1"
	AnalysisCompleted  = "2"
)

// Distribution Level Constants
const (
	DistributionOrganization = "0"
	DistributionCommunity    = "1"
	DistributionConnected    = "2"
	DistributionAll          = "3"
	DistributionSharingGroup = "4"
	DistributionInherit      = "5"
)

// Common MISP Attribute Types
var MISPAttributeTypes = map[string][]string{
	"network": {
		"ip-src", "ip-dst", "hostname", "domain", "url", "uri",
		"user-agent", "AS", "snort", "pattern-in-file",
		"pattern-in-traffic", "pattern-in-memory",
	},
	"file": {
		"md5", "sha1", "sha256", "sha512", "ssdeep", "imphash",
		"filename", "pdb", "pattern-in-file", "mime-type",
		"attachment", "malware-sample",
	},
	"email": {
		"email-src", "email-dst", "email-subject", "email-attachment",
		"email-body", "whois-registrant-email",
	},
	"registry": {
		"regkey", "regkey|value",
	},
	"other": {
		"text", "comment", "other", "link", "target-user",
		"target-email", "target-machine", "target-org",
		"target-location", "target-external",
	},
}