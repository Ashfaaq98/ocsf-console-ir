package bus

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisBus provides Redis Streams-based messaging for plugins
type RedisBus struct {
	client *redis.Client
	logger *log.Logger
}

// StreamMessage represents a message in a Redis Stream
type StreamMessage struct {
	ID     string            `json:"id"`
	Fields map[string]string `json:"fields"`
}

// EventMessage represents an event message published to the events stream
type EventMessage struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	RawJSON   string `json:"raw_json"`
	Timestamp int64  `json:"timestamp"`
}

// EnrichmentMessage represents an enrichment message published to the enrichments stream
type EnrichmentMessage struct {
	EventID     string            `json:"event_id"`
	Source      string            `json:"source"`
	Type        string            `json:"type"`
	Data        map[string]string `json:"data"`
	Timestamp   int64             `json:"timestamp"`
	PluginName  string            `json:"plugin_name"`
}

// StreamHandler is a function that processes stream messages
type StreamHandler func(ctx context.Context, message StreamMessage) error

// NewRedisBus creates a new Redis bus instance
func NewRedisBus(redisURL string, logger *log.Logger) (*RedisBus, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	if logger == nil {
		logger = log.New(log.Writer(), "[RedisBus] ", log.LstdFlags)
	}

	return &RedisBus{
		client: client,
		logger: logger,
	}, nil
}

// Close closes the Redis connection
func (rb *RedisBus) Close() error {
	return rb.client.Close()
}

// PublishEvent publishes an event to the events stream
func (rb *RedisBus) PublishEvent(ctx context.Context, eventMsg EventMessage) error {
	fields := map[string]interface{}{
		"event_id":   eventMsg.EventID,
		"event_type": eventMsg.EventType,
		"raw_json":   eventMsg.RawJSON,
		"timestamp":  eventMsg.Timestamp,
	}

	result := rb.client.XAdd(ctx, &redis.XAddArgs{
		Stream: "events",
		Values: fields,
	})

	if err := result.Err(); err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}

	rb.logger.Printf("Published event %s to events stream", eventMsg.EventID)
	return nil
}

// PublishEnrichment publishes an enrichment to the enrichments stream
func (rb *RedisBus) PublishEnrichment(ctx context.Context, enrichmentMsg EnrichmentMessage) error {
	dataJSON, err := json.Marshal(enrichmentMsg.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal enrichment data: %w", err)
	}

	fields := map[string]interface{}{
		"event_id":    enrichmentMsg.EventID,
		"source":      enrichmentMsg.Source,
		"type":        enrichmentMsg.Type,
		"data":        string(dataJSON),
		"timestamp":   enrichmentMsg.Timestamp,
		"plugin_name": enrichmentMsg.PluginName,
	}

	result := rb.client.XAdd(ctx, &redis.XAddArgs{
		Stream: "enrichments",
		Values: fields,
	})

	if err := result.Err(); err != nil {
		return fmt.Errorf("failed to publish enrichment: %w", err)
	}

	rb.logger.Printf("Published enrichment for event %s from plugin %s", 
		enrichmentMsg.EventID, enrichmentMsg.PluginName)
	return nil
}

// CreateConsumerGroup creates a consumer group for a stream if it doesn't exist
func (rb *RedisBus) CreateConsumerGroup(ctx context.Context, stream, group string) error {
	// Try to create the consumer group, ignore error if it already exists
	result := rb.client.XGroupCreateMkStream(ctx, stream, group, "0")
	if err := result.Err(); err != nil {
		// Check if the error is because the group already exists
		if err.Error() != "BUSYGROUP Consumer Group name already exists" {
			return fmt.Errorf("failed to create consumer group %s for stream %s: %w", group, stream, err)
		}
	}

	rb.logger.Printf("Consumer group %s ready for stream %s", group, stream)
	return nil
}

// ReadStream reads messages from a stream using consumer groups
func (rb *RedisBus) ReadStream(ctx context.Context, stream, group, consumer string, handler StreamHandler) error {
	// Ensure consumer group exists
	if err := rb.CreateConsumerGroup(ctx, stream, group); err != nil {
		return err
	}

	rb.logger.Printf("Starting stream reader for %s (group: %s, consumer: %s)", stream, group, consumer)

	for {
		select {
		case <-ctx.Done():
			rb.logger.Printf("Stream reader for %s stopping due to context cancellation", stream)
			return ctx.Err()
		default:
			// Read messages from the stream
			result := rb.client.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    group,
				Consumer: consumer,
				Streams:  []string{stream, ">"},
				Count:    10,
				Block:    1 * time.Second,
			})

			if err := result.Err(); err != nil {
				if err == redis.Nil {
					// No messages available, continue
					continue
				}
				rb.logger.Printf("Error reading from stream %s: %v", stream, err)
				time.Sleep(5 * time.Second)
				continue
			}

			// Process messages
			for _, stream := range result.Val() {
				for _, message := range stream.Messages {
					streamMsg := StreamMessage{
						ID:     message.ID,
						Fields: make(map[string]string),
					}

					// Convert fields to string map
					for key, value := range message.Values {
						if strValue, ok := value.(string); ok {
							streamMsg.Fields[key] = strValue
						}
					}

					// Process the message
					if err := handler(ctx, streamMsg); err != nil {
						rb.logger.Printf("Error processing message %s: %v", message.ID, err)
						continue
					}

					// Acknowledge the message
					if err := rb.client.XAck(ctx, stream.Stream, group, message.ID).Err(); err != nil {
						rb.logger.Printf("Error acknowledging message %s: %v", message.ID, err)
					}
				}
			}
		}
	}
}

// ReadEventsStream reads from the events stream
func (rb *RedisBus) ReadEventsStream(ctx context.Context, group, consumer string, handler func(ctx context.Context, event EventMessage) error) error {
	streamHandler := func(ctx context.Context, message StreamMessage) error {
		eventMsg := EventMessage{
			EventID:   message.Fields["event_id"],
			EventType: message.Fields["event_type"],
			RawJSON:   message.Fields["raw_json"],
		}

		if timestamp := message.Fields["timestamp"]; timestamp != "" {
			if ts, err := parseTimestamp(timestamp); err == nil {
				eventMsg.Timestamp = ts
			}
		}

		return handler(ctx, eventMsg)
	}

	return rb.ReadStream(ctx, "events", group, consumer, streamHandler)
}

// ReadEnrichmentsStream reads from the enrichments stream
func (rb *RedisBus) ReadEnrichmentsStream(ctx context.Context, group, consumer string, handler func(ctx context.Context, enrichment EnrichmentMessage) error) error {
	streamHandler := func(ctx context.Context, message StreamMessage) error {
		enrichmentMsg := EnrichmentMessage{
			EventID:    message.Fields["event_id"],
			Source:     message.Fields["source"],
			Type:       message.Fields["type"],
			PluginName: message.Fields["plugin_name"],
		}

		// Parse data JSON
		if dataJSON := message.Fields["data"]; dataJSON != "" {
			var data map[string]string
			if err := json.Unmarshal([]byte(dataJSON), &data); err == nil {
				enrichmentMsg.Data = data
			}
		}

		if timestamp := message.Fields["timestamp"]; timestamp != "" {
			if ts, err := parseTimestamp(timestamp); err == nil {
				enrichmentMsg.Timestamp = ts
			}
		}

		return handler(ctx, enrichmentMsg)
	}

	return rb.ReadStream(ctx, "enrichments", group, consumer, streamHandler)
}

// GetStreamInfo returns information about a stream
func (rb *RedisBus) GetStreamInfo(ctx context.Context, stream string) (*redis.XInfoStream, error) {
	result := rb.client.XInfoStream(ctx, stream)
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("failed to get stream info for %s: %w", stream, err)
	}
	return result.Val(), nil
}

// GetConsumerGroupInfo returns information about consumer groups for a stream
func (rb *RedisBus) GetConsumerGroupInfo(ctx context.Context, stream string) ([]redis.XInfoGroup, error) {
	result := rb.client.XInfoGroups(ctx, stream)
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("failed to get consumer group info for %s: %w", stream, err)
	}
	return result.Val(), nil
}

// CleanupOldMessages removes old messages from streams to prevent memory issues
func (rb *RedisBus) CleanupOldMessages(ctx context.Context, stream string, maxLen int64) error {
	result := rb.client.XTrimMaxLen(ctx, stream, maxLen)
	if err := result.Err(); err != nil {
		return fmt.Errorf("failed to trim stream %s: %w", stream, err)
	}

	rb.logger.Printf("Trimmed stream %s to max length %d", stream, maxLen)
	return nil
}

// parseTimestamp parses a timestamp string to int64
func parseTimestamp(timestamp string) (int64, error) {
	if timestamp == "" {
		return time.Now().Unix(), nil
	}

	// Try numeric epoch (seconds or milliseconds)
	if n, err := strconv.ParseInt(timestamp, 10, 64); err == nil {
		// Heuristic: 13+ digits → milliseconds
		if n > 1_000_000_000_000 {
			return n / 1000, nil
		}
		return n, nil
	}

	// Try RFC3339 (seconds precision)
	if ts, err := time.Parse(time.RFC3339, timestamp); err == nil {
		return ts.Unix(), nil
	}

	// Try RFC3339Nano (higher precision)
	if ts, err := time.Parse(time.RFC3339Nano, timestamp); err == nil {
		return ts.Unix(), nil
	}

	// Default to current time on failure
	return time.Now().Unix(), fmt.Errorf("unable to parse timestamp: %s", timestamp)
}

// HealthCheck performs a health check on the Redis connection
func (rb *RedisBus) HealthCheck(ctx context.Context) error {
	return rb.client.Ping(ctx).Err()
}

// GetStats returns basic statistics about the Redis streams
func (rb *RedisBus) GetStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get events stream info
	if eventsInfo, err := rb.GetStreamInfo(ctx, "events"); err == nil {
		stats["events_stream"] = map[string]interface{}{
			"length":          eventsInfo.Length,
			"first_entry_id":  eventsInfo.FirstEntry.ID,
			"last_entry_id":   eventsInfo.LastEntry.ID,
		}
	}

	// Get enrichments stream info
	if enrichmentsInfo, err := rb.GetStreamInfo(ctx, "enrichments"); err == nil {
		stats["enrichments_stream"] = map[string]interface{}{
			"length":          enrichmentsInfo.Length,
			"first_entry_id":  enrichmentsInfo.FirstEntry.ID,
			"last_entry_id":   enrichmentsInfo.LastEntry.ID,
		}
	}

	// Get consumer group info
	if groups, err := rb.GetConsumerGroupInfo(ctx, "events"); err == nil {
		stats["events_consumer_groups"] = len(groups)
	}

	if groups, err := rb.GetConsumerGroupInfo(ctx, "enrichments"); err == nil {
		stats["enrichments_consumer_groups"] = len(groups)
	}

	return stats, nil
}