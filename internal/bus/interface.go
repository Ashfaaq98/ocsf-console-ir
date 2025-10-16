package bus

import (
	"context"
	"io"
	"log"
)

// Bus defines the interface for event bus implementations
type Bus interface {
	// PublishEvent publishes an event to the events stream
	PublishEvent(ctx context.Context, eventMsg EventMessage) error
	
	// PublishEnrichment publishes an enrichment to the enrichments stream
	PublishEnrichment(ctx context.Context, enrichmentMsg EnrichmentMessage) error
	
	// ReadEnrichmentsStream reads from the enrichments stream
	ReadEnrichmentsStream(ctx context.Context, group, consumer string, handler func(ctx context.Context, enrichment EnrichmentMessage) error) error
	
	// GetStats returns basic statistics about the bus
	GetStats(ctx context.Context) (map[string]interface{}, error)
	
	// HealthCheck performs a health check on the bus connection
	HealthCheck(ctx context.Context) error
	
	// Close closes the bus connection
	Close() error
}

// NewBus creates a new bus instance based on the Redis URL
// If redisURL is empty or invalid, returns a NullBus
func NewBus(redisURL string, logger *log.Logger) Bus {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	if redisURL == "" {
		return NewNullBus(logger)
	}

	// Try to create Redis bus
	if redisBus, err := NewRedisBus(redisURL, logger); err == nil {
		return redisBus
	}

	// Fall back to null bus if Redis fails
	return NewNullBus(logger)
}