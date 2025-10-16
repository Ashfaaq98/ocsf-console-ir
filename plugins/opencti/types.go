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

// OpenCTIConfig holds configuration for the OpenCTI plugin
type OpenCTIConfig struct {
	// API Configuration
	BaseURL         string        `yaml:"base_url"`
	Token           string        `yaml:"token"`
	Timeout         time.Duration `yaml:"timeout"`
	
	// Rate Limiting
	RateLimitRPS    int           `yaml:"rate_limit_rps"`
	BurstLimit      int           `yaml:"burst_limit"`
	
	// Caching
	CacheTTL        time.Duration `yaml:"cache_ttl"`
	CacheSize       int           `yaml:"cache_size"`
	UseRedisCache   bool          `yaml:"use_redis_cache"`
	
	// Enrichment Settings
	IncludeRelated  bool          `yaml:"include_related"`
	MaxRelations    int           `yaml:"max_relations"`
	MinConfidence   int           `yaml:"min_confidence"`
	
	// Observable Types to Process
	ProcessIPs      bool          `yaml:"process_ips"`
	ProcessDomains  bool          `yaml:"process_domains"`
	ProcessHashes   bool          `yaml:"process_hashes"`
	ProcessURLs     bool          `yaml:"process_urls"`
}

// Observable represents an extracted observable from an event
type Observable struct {
	Type  string `json:"type"`  // ip, domain, hash, url
	Value string `json:"value"`
}

// OpenCTI API Response Types

// STIXObservable represents a STIX cyber observable from OpenCTI
type STIXObservable struct {
	ID            string                 `json:"id"`
	StandardID    string                 `json:"standard_id"`
	EntityType    string                 `json:"entity_type"`
	ObservableValue string               `json:"observable_value"`
	Labels        []string               `json:"labels"`
	Confidence    int                    `json:"confidence"`
	Score         int                    `json:"x_opencti_score"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	Indicators    []STIXIndicator        `json:"indicators"`
	Relationships []STIXRelationship     `json:"relationships"`
	CustomFields  map[string]interface{} `json:"custom_fields"`
}

// STIXIndicator represents a STIX indicator
type STIXIndicator struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Pattern     string    `json:"pattern"`
	Labels      []string  `json:"labels"`
	Confidence  int       `json:"confidence"`
	ValidFrom   time.Time `json:"valid_from"`
	ValidUntil  time.Time `json:"valid_until"`
	KillChain   []string  `json:"kill_chain_phases"`
	Description string    `json:"description"`
}

// STIXThreatActor represents a threat actor
type STIXThreatActor struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases"`
	Description string   `json:"description"`
	Labels      []string `json:"labels"`
	Country     string   `json:"country"`
	Confidence  int      `json:"confidence"`
	Sophistication string `json:"sophistication"`
}

// STIXMalware represents malware information
type STIXMalware struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Labels       []string `json:"labels"`
	Description  string   `json:"description"`
	IsFamily     bool     `json:"is_family"`
	Capabilities []string `json:"capabilities"`
	KillChain    []string `json:"kill_chain_phases"`
}

// STIXCampaign represents a campaign
type STIXCampaign struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Confidence  int       `json:"confidence"`
	Objectives  []string  `json:"objectives"`
}

// STIXAttackPattern represents an attack pattern (MITRE ATT&CK)
type STIXAttackPattern struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	ExternalRefs   []string `json:"external_references"`
	KillChain      []string `json:"kill_chain_phases"`
	MitreID        string   `json:"x_mitre_id"`
	Platforms      []string `json:"x_mitre_platforms"`
	DataSources    []string `json:"x_mitre_data_sources"`
	DefenseBypassed []string `json:"x_mitre_defense_bypassed"`
}

// STIXRelationship represents a relationship between STIX objects
type STIXRelationship struct {
	ID           string    `json:"id"`
	RelationType string    `json:"relationship_type"`
	SourceRef    string    `json:"source_ref"`
	TargetRef    string    `json:"target_ref"`
	Confidence   int       `json:"confidence"`
	StartTime    time.Time `json:"start_time"`
	StopTime     time.Time `json:"stop_time"`
	Description  string    `json:"description"`
}

// OpenCTI API Response wrapper
type OpenCTIResponse struct {
	Data   interface{} `json:"data"`
	Errors []APIError  `json:"errors"`
}

// APIError represents an API error response
type APIError struct {
	Message string `json:"message"`
	Code    string `json:"code"`
	Path    string `json:"path"`
}

// ThreatIntelligence represents processed threat intelligence for an observable
type ThreatIntelligence struct {
	Observable      Observable         `json:"observable"`
	ThreatActors    []STIXThreatActor  `json:"threat_actors"`
	Campaigns       []STIXCampaign     `json:"campaigns"`
	Malware         []STIXMalware      `json:"malware"`
	AttackPatterns  []STIXAttackPattern `json:"attack_patterns"`
	Indicators      []STIXIndicator    `json:"indicators"`
	Relationships   []STIXRelationship `json:"relationships"`
	Confidence      int                `json:"confidence"`
	ThreatLevel     string             `json:"threat_level"`
	FirstSeen       time.Time          `json:"first_seen"`
	LastSeen        time.Time          `json:"last_seen"`
	QueryTime       time.Time          `json:"query_time"`
}

// CacheEntry represents a cached threat intelligence result
type CacheEntry struct {
	Data   *ThreatIntelligence `json:"data"`
	Expiry time.Time           `json:"expiry"`
}

// PluginMetrics holds metrics for monitoring
type PluginMetrics struct {
	EventsProcessed    int64         `json:"events_processed"`
	EnrichmentsAdded   int64         `json:"enrichments_added"`
	CacheHits          int64         `json:"cache_hits"`
	CacheMisses        int64         `json:"cache_misses"`
	APICallsSuccess    int64         `json:"api_calls_success"`
	APICallsError      int64         `json:"api_calls_error"`
	AverageProcessTime time.Duration `json:"average_process_time"`
	LastActivity       time.Time     `json:"last_activity"`
}