package plugins

import (
	"context"
	"fmt"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// CorePlugin defines the interface for internal Go plugins
type CorePlugin interface {
	// Name returns the plugin name
	Name() string
	
	// Description returns a brief description of the plugin
	Description() string
	
	// Version returns the plugin version
	Version() string
	
	// Process processes an event and returns enrichments
	Process(ctx context.Context, event bus.EventMessage) ([]store.Enrichment, error)
	
	// Start initializes the plugin
	Start(ctx context.Context) error
	
	// Stop shuts down the plugin gracefully
	Stop() error
	
	// HealthCheck returns the plugin's health status
	HealthCheck(ctx context.Context) error
	
	// GetConfig returns the plugin's configuration requirements
	GetConfig() PluginConfig
}

// ExternalPlugin represents a standalone executable plugin
type ExternalPlugin struct {
	Name        string            `json:"name"`
	Command     string            `json:"command"`
	Args        []string          `json:"args,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	Timeout     time.Duration     `json:"timeout,omitempty"`
	Enabled     bool              `json:"enabled"`
	Description string            `json:"description,omitempty"`
	Version     string            `json:"version,omitempty"`
	
	// Runtime state
	process *PluginProcess `json:"-"`
}

// PluginConfig defines configuration requirements for a plugin
type PluginConfig struct {
	RequiredEnvVars []string          `json:"required_env_vars"`
	OptionalEnvVars []string          `json:"optional_env_vars"`
	ConfigFile      string            `json:"config_file,omitempty"`
	Dependencies    []string          `json:"dependencies,omitempty"`
	Resources       ResourceRequirements `json:"resources,omitempty"`
}

// ResourceRequirements defines resource requirements for a plugin
type ResourceRequirements struct {
	MinMemoryMB int `json:"min_memory_mb,omitempty"`
	MaxMemoryMB int `json:"max_memory_mb,omitempty"`
	MinCPU      int `json:"min_cpu,omitempty"`
	MaxCPU      int `json:"max_cpu,omitempty"`
}

// PluginProcess represents a running external plugin process
type PluginProcess struct {
	PID       int       `json:"pid"`
	StartTime time.Time `json:"start_time"`
	Status    string    `json:"status"`
	LastSeen  time.Time `json:"last_seen"`
	Restarts  int       `json:"restarts"`
}

// PluginStatus represents the status of a plugin
type PluginStatus struct {
	Name         string            `json:"name"`
	Type         string            `json:"type"` // "core" or "external"
	Status       string            `json:"status"` // "running", "stopped", "error", "starting"
	LastActivity time.Time         `json:"last_activity"`
	ProcessedEvents int64          `json:"processed_events"`
	Errors       int64             `json:"errors"`
	Uptime       time.Duration     `json:"uptime"`
	MemoryUsage  int64             `json:"memory_usage,omitempty"`
	CPUUsage     float64           `json:"cpu_usage,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// PluginRegistry manages plugin registration and discovery
type PluginRegistry interface {
	// RegisterCorePlugin registers an internal Go plugin
	RegisterCorePlugin(plugin CorePlugin) error
	
	// RegisterExternalPlugin registers an external executable plugin
	RegisterExternalPlugin(plugin *ExternalPlugin) error
	
	// GetCorePlugin returns a core plugin by name
	GetCorePlugin(name string) (CorePlugin, bool)
	
	// GetExternalPlugin returns an external plugin by name
	GetExternalPlugin(name string) (*ExternalPlugin, bool)
	
	// ListCorePlugins returns all registered core plugins
	ListCorePlugins() []CorePlugin
	
	// ListExternalPlugins returns all registered external plugins
	ListExternalPlugins() []*ExternalPlugin
	
	// GetPluginStatus returns the status of a plugin
	GetPluginStatus(name string) (*PluginStatus, error)
	
	// GetAllStatuses returns the status of all plugins
	GetAllStatuses() ([]*PluginStatus, error)
}

// PluginManager manages the lifecycle of plugins
type PluginManager interface {
	// Start starts all enabled plugins
	Start(ctx context.Context) error
	
	// Stop stops all running plugins
	Stop() error
	
	// StartPlugin starts a specific plugin
	StartPlugin(ctx context.Context, name string) error
	
	// StopPlugin stops a specific plugin
	StopPlugin(name string) error
	
	// RestartPlugin restarts a specific plugin
	RestartPlugin(ctx context.Context, name string) error
	
	// GetRegistry returns the plugin registry
	GetRegistry() PluginRegistry
	
	// ProcessEvent processes an event through all applicable plugins
	ProcessEvent(ctx context.Context, event bus.EventMessage) error
	
	// HealthCheck performs health checks on all plugins
	HealthCheck(ctx context.Context) (map[string]error, error)
	
	// GetStats returns plugin statistics
	GetStats() map[string]interface{}
}

// PluginEvent represents an event in the plugin system
type PluginEvent struct {
	Type      string                 `json:"type"`
	Plugin    string                 `json:"plugin"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Error     string                 `json:"error,omitempty"`
}

// PluginEventType defines types of plugin events
type PluginEventType string

const (
	PluginEventStarted    PluginEventType = "started"
	PluginEventStopped    PluginEventType = "stopped"
	PluginEventError      PluginEventType = "error"
	PluginEventProcessed  PluginEventType = "processed"
	PluginEventHealthy    PluginEventType = "healthy"
	PluginEventUnhealthy  PluginEventType = "unhealthy"
	PluginEventRestarted  PluginEventType = "restarted"
)

// EnrichmentType defines types of enrichments
type EnrichmentType string

const (
	EnrichmentGeoIP       EnrichmentType = "geoip"
	EnrichmentThreatIntel EnrichmentType = "threat_intel"
	EnrichmentReputation  EnrichmentType = "reputation"
	EnrichmentDNS         EnrichmentType = "dns"
	EnrichmentWhois       EnrichmentType = "whois"
	EnrichmentFileAnalysis EnrichmentType = "file_analysis"
	EnrichmentBehavioral  EnrichmentType = "behavioral"
	EnrichmentCorrelation EnrichmentType = "correlation"
)

// PluginCapability defines what a plugin can do
type PluginCapability struct {
	EventTypes     []string         `json:"event_types"`     // OCSF event types this plugin handles
	EnrichmentTypes []EnrichmentType `json:"enrichment_types"` // Types of enrichments this plugin provides
	RequiresNetwork bool            `json:"requires_network"` // Whether plugin needs network access
	RequiresStorage bool            `json:"requires_storage"` // Whether plugin needs persistent storage
	Realtime       bool            `json:"realtime"`        // Whether plugin processes events in real-time
	Batch          bool            `json:"batch"`           // Whether plugin supports batch processing
}

// PluginMetrics holds metrics for a plugin
type PluginMetrics struct {
	EventsProcessed   int64         `json:"events_processed"`
	EnrichmentsAdded  int64         `json:"enrichments_added"`
	ErrorCount        int64         `json:"error_count"`
	AverageProcessTime time.Duration `json:"average_process_time"`
	LastProcessTime   time.Duration `json:"last_process_time"`
	TotalProcessTime  time.Duration `json:"total_process_time"`
	StartTime         time.Time     `json:"start_time"`
	LastActivity      time.Time     `json:"last_activity"`
}

// PluginLogger provides logging interface for plugins
type PluginLogger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Fatal(msg string, fields ...interface{})
}

// BasePlugin provides common functionality for core plugins
type BasePlugin struct {
	name         string
	description  string
	version      string
	config       PluginConfig
	metrics      *PluginMetrics
	logger       PluginLogger
	started      bool
	startTime    time.Time
}

// NewBasePlugin creates a new base plugin
func NewBasePlugin(name, description, version string, config PluginConfig, logger PluginLogger) *BasePlugin {
	return &BasePlugin{
		name:        name,
		description: description,
		version:     version,
		config:      config,
		logger:      logger,
		metrics: &PluginMetrics{
			StartTime: time.Now(),
		},
	}
}

// Name returns the plugin name
func (bp *BasePlugin) Name() string {
	return bp.name
}

// Description returns the plugin description
func (bp *BasePlugin) Description() string {
	return bp.description
}

// Version returns the plugin version
func (bp *BasePlugin) Version() string {
	return bp.version
}

// GetConfig returns the plugin configuration
func (bp *BasePlugin) GetConfig() PluginConfig {
	return bp.config
}

// Start marks the plugin as started
func (bp *BasePlugin) Start(ctx context.Context) error {
	bp.started = true
	bp.startTime = time.Now()
	bp.metrics.StartTime = bp.startTime
	bp.logger.Info("Plugin started", "name", bp.name)
	return nil
}

// Stop marks the plugin as stopped
func (bp *BasePlugin) Stop() error {
	bp.started = false
	bp.logger.Info("Plugin stopped", "name", bp.name)
	return nil
}

// HealthCheck performs a basic health check
func (bp *BasePlugin) HealthCheck(ctx context.Context) error {
	if !bp.started {
		return fmt.Errorf("plugin %s is not started", bp.name)
	}
	return nil
}

// GetMetrics returns plugin metrics
func (bp *BasePlugin) GetMetrics() *PluginMetrics {
	return bp.metrics
}

// RecordProcessing records processing metrics
func (bp *BasePlugin) RecordProcessing(duration time.Duration, success bool) {
	bp.metrics.LastActivity = time.Now()
	bp.metrics.LastProcessTime = duration
	bp.metrics.TotalProcessTime += duration
	
	if success {
		bp.metrics.EventsProcessed++
		// Calculate rolling average
		if bp.metrics.EventsProcessed > 0 {
			bp.metrics.AverageProcessTime = bp.metrics.TotalProcessTime / time.Duration(bp.metrics.EventsProcessed)
		}
	} else {
		bp.metrics.ErrorCount++
	}
}

// RecordEnrichment records enrichment metrics
func (bp *BasePlugin) RecordEnrichment() {
	bp.metrics.EnrichmentsAdded++
}

// IsStarted returns whether the plugin is started
func (bp *BasePlugin) IsStarted() bool {
	return bp.started
}

// GetUptime returns plugin uptime
func (bp *BasePlugin) GetUptime() time.Duration {
	if !bp.started {
		return 0
	}
	return time.Since(bp.startTime)
}