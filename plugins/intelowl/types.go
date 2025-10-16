package main

import "time"

// Observable represents a single IOC extracted from events
type Observable struct {
	Type  string // ip|domain|url|hash|email
	Value string
}

// EventMessage represents the envelope from the events stream
type EventMessage struct {
	EventID   string
	EventType string
	RawJSON   string
	Timestamp string
}

// IntelOwlConfig holds all configuration for the plugin
type IntelOwlConfig struct {
	// IntelOwl API
	BaseURL   string
	Token     string
	VerifyTLS bool
	Timeout   time.Duration

	// Rate limiting
	RateLimitRPS int
	BurstLimit   int

	// Caching
	UseRedisCache bool
	CacheTTL      time.Duration
	CacheSize     int

	// Mode of operation
	Mode          string // "query" or "submit"
	PollInterval  time.Duration
	PollTimeout   time.Duration
	MaxConcurrent int

	// Analyzer control
	AnalyzersIP     []string
	AnalyzersDomain []string
	AnalyzersURL    []string
	AnalyzersHash   []string
	AnalyzersEmail  []string
	ExcludeAnalyzers []string

	// Filtering
	MinConfidence string // info|low|medium|high
}

// IntelOwlResult is a normalized intel result used for enrichment
type IntelOwlResult struct {
	Observable    Observable
	Verdict       string            // benign|suspicious|malicious|unknown
	Confidence    string            // info|low|medium|high
	Tags          []string
	Analyzers     []string
	Jobs          []string
	EvidenceCount int
	Summary       string
	PerAnalyzer   map[string]any
	QueryTime     time.Time
}

// PluginMetrics tracks basic runtime metrics
type PluginMetrics struct {
	EventsProcessed     int64
	EnrichmentsAdded    int64
	APICallsSuccess     int64
	APICallsError       int64
	AverageProcessTime  time.Duration
	LastActivity        time.Time
	CacheHits           int64
	CacheMisses         int64
}

// Modes
const (
	ModeQuery  = "query"
	ModeSubmit = "submit"
)