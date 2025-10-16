package bus

import (
	"context"
	"log"
)

// NullBus is a no-op implementation of the bus interface for when Redis is disabled
type NullBus struct {
	logger *log.Logger
}

// NewNullBus creates a new null bus instance
func NewNullBus(logger *log.Logger) *NullBus {
	if logger == nil {
		logger = log.New(log.Writer(), "[NullBus] ", log.LstdFlags)
	}

	return &NullBus{
		logger: logger,
	}
}

// Close is a no-op for null bus
func (nb *NullBus) Close() error {
	return nil
}

// PublishEvent logs the event but doesn't actually publish it
func (nb *NullBus) PublishEvent(ctx context.Context, eventMsg EventMessage) error {
	nb.logger.Printf("Would publish event %s (Redis disabled)", eventMsg.EventID)
	return nil
}

// PublishEnrichment logs the enrichment but doesn't actually publish it
func (nb *NullBus) PublishEnrichment(ctx context.Context, enrichmentMsg EnrichmentMessage) error {
	nb.logger.Printf("Would publish enrichment for event %s from plugin %s (Redis disabled)", 
		enrichmentMsg.EventID, enrichmentMsg.PluginName)
	return nil
}

// ReadEnrichmentsStream is a no-op for null bus (never returns)
func (nb *NullBus) ReadEnrichmentsStream(ctx context.Context, group, consumer string, handler func(ctx context.Context, enrichment EnrichmentMessage) error) error {
	nb.logger.Printf("Would read enrichments stream %s:%s (Redis disabled)", group, consumer)
	// Block until context is cancelled since this would normally be a blocking operation
	<-ctx.Done()
	return ctx.Err()
}

// GetStats returns empty stats for null bus
func (nb *NullBus) GetStats(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"type": "null",
		"status": "disabled",
	}, nil
}

// HealthCheck always returns nil for null bus
func (nb *NullBus) HealthCheck(ctx context.Context) error {
	return nil
}