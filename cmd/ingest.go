package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ingest"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/spf13/cobra"
)

var (
	inputFile   string
	batchSize   int
	skipInvalid bool
)

// ingestCmd represents the ingest command
var ingestCmd = &cobra.Command{
	Use:   "ingest [file]",
	Short: "Ingest OCSF events from file or stdin",
	Long: `Ingest OCSF events from a file or stdin. Supports JSON and JSONL formats.

The ingest command:
1. Parses OCSF events from the input source
2. Normalizes them to the internal event format
3. Saves events to the SQLite database
4. Publishes events to Redis Streams for plugin processing

Examples:
  # Ingest from file
  console-ir ingest events.jsonl

  # Ingest from stdin
  cat events.json | console-ir ingest -

  # Ingest with custom batch size
  console-ir ingest --batch-size 100 events.jsonl

  # Skip invalid events instead of failing
  console-ir ingest --skip-invalid events.jsonl`,
	Args: cobra.MaximumNArgs(1),
	RunE: runIngest,
}

func init() {
	rootCmd.AddCommand(ingestCmd)

	ingestCmd.Flags().StringVarP(&inputFile, "file", "f", "", "Input file path (use '-' for stdin)")
	ingestCmd.Flags().IntVar(&batchSize, "batch-size", 50, "Number of events to process in each batch")
	ingestCmd.Flags().BoolVar(&skipInvalid, "skip-invalid", false, "Skip invalid events instead of failing")
}

func runIngest(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	config := GetConfig()

	// Determine input source
	var input io.Reader
	var inputName string

	if len(args) > 0 {
		inputFile = args[0]
	}

	if inputFile == "" || inputFile == "-" {
		input = os.Stdin
		inputName = "stdin"
	} else {
		file, err := os.Open(inputFile)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer file.Close()
		input = file
		inputName = inputFile
	}

	// Initialize components
	logger := log.New(os.Stderr, "[ingest] ", log.LstdFlags)
	logger.Printf("Starting ingestion from %s", inputName)

	// Initialize store (resolve DB path relative to current working directory, same as serve)
	baseDir := getWorkingDir()
	resolvedDBPath := resolvePathRelativeToBase(baseDir, config.Database.Path)
	logger.Printf("Using database at %s", resolvedDBPath)

	store, err := store.NewStore(resolvedDBPath)
	if err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}
	defer store.Close()

	// Initialize bus (Redis or Null)
	eventBus := bus.NewBus(config.Redis.URL, logger)
	defer eventBus.Close()

	// Initialize OCSF parser
	parser := ingest.NewParser()

	// Process events
	stats, err := processEvents(ctx, input, parser, store, eventBus, logger)
	if err != nil {
		return fmt.Errorf("failed to process events: %w", err)
	}

	// Print statistics
	logger.Printf("Ingestion completed:")
	logger.Printf("  Total events processed: %d", stats.TotalEvents)
	logger.Printf("  Successfully ingested: %d", stats.SuccessfulEvents)
	logger.Printf("  Failed events: %d", stats.FailedEvents)
	logger.Printf("  Skipped events: %d", stats.SkippedEvents)
	logger.Printf("  Processing time: %v", stats.ProcessingTime)

	if stats.FailedEvents > 0 && !skipInvalid {
		return fmt.Errorf("ingestion completed with %d failed events", stats.FailedEvents)
	}

	return nil
}

// IngestStats holds statistics about the ingestion process
type IngestStats struct {
	TotalEvents      int
	SuccessfulEvents int
	FailedEvents     int
	SkippedEvents    int
	ProcessingTime   time.Duration
}

// processEvents processes events from the input reader
func processEvents(ctx context.Context, input io.Reader, parser *ingest.Parser,
	store *store.Store, eventBus bus.Bus, logger *log.Logger) (*IngestStats, error) {
	
	startTime := time.Now()
	stats := &IngestStats{}

	scanner := bufio.NewScanner(input)
	batch := make([][]byte, 0, batchSize)
	lineNumber := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return stats, ctx.Err()
		default:
		}

		lineNumber++
		line := scanner.Bytes()

		// Skip empty lines
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		// Add to batch
		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)
		batch = append(batch, lineCopy)

		// Process batch when full
		if len(batch) >= batchSize {
			batchStats := processBatch(ctx, batch, parser, store, eventBus, logger, lineNumber-len(batch)+1)
			updateStats(stats, batchStats)
			batch = batch[:0] // Reset batch
		}
	}

	// Process remaining events in batch
	if len(batch) > 0 {
		batchStats := processBatch(ctx, batch, parser, store, eventBus, logger, lineNumber-len(batch)+1)
		updateStats(stats, batchStats)
	}

	if err := scanner.Err(); err != nil {
		return stats, fmt.Errorf("error reading input: %w", err)
	}

	stats.ProcessingTime = time.Since(startTime)
	return stats, nil
}

// processBatch processes a batch of events
func processBatch(ctx context.Context, batch [][]byte, parser *ingest.Parser,
	store *store.Store, eventBus bus.Bus, logger *log.Logger, startLine int) *IngestStats {
	
	stats := &IngestStats{}

	for i, eventData := range batch {
		lineNumber := startLine + i
		
		if err := processEvent(ctx, eventData, parser, store, eventBus, lineNumber); err != nil {
			stats.FailedEvents++
			if skipInvalid {
				logger.Printf("Skipping invalid event at line %d: %v", lineNumber, err)
				stats.SkippedEvents++
			} else {
				logger.Printf("Failed to process event at line %d: %v", lineNumber, err)
			}
		} else {
			stats.SuccessfulEvents++
		}
		
		stats.TotalEvents++
	}

	return stats
}

// processEvent processes a single event
func processEvent(ctx context.Context, eventData []byte, parser *ingest.Parser,
	store *store.Store, eventBus bus.Bus, lineNumber int) error {
	
	// Parse the OCSF event
	ocsfEvent, err := parser.ParseEvent(eventData)
	if err != nil {
		return fmt.Errorf("failed to parse OCSF event: %w", err)
	}

	// Save to database
	eventID, err := store.SaveEvent(ctx, ocsfEvent)
	if err != nil {
		return fmt.Errorf("failed to save event to database: %w", err)
	}

	// Publish to Redis stream for plugin processing
	eventMsg := bus.EventMessage{
		EventID:   eventID,
		EventType: string(ocsfEvent.GetEventType()),
		RawJSON:   string(eventData),
		Timestamp: ocsfEvent.Time.Unix(),
	}

	if err := eventBus.PublishEvent(ctx, eventMsg); err != nil {
		// Log the error but don't fail the ingestion
		log.Printf("Warning: failed to publish event %s to bus: %v", eventID, err)
	}

	return nil
}

// updateStats updates the main stats with batch stats
func updateStats(main, batch *IngestStats) {
	main.TotalEvents += batch.TotalEvents
	main.SuccessfulEvents += batch.SuccessfulEvents
	main.FailedEvents += batch.FailedEvents
	main.SkippedEvents += batch.SkippedEvents
}

// detectFormat attempts to detect the input format (JSON vs JSONL)
func detectFormat(data []byte) string {
	// Try to parse as single JSON object
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err == nil {
		// Check if it's an array (JSON) or object (JSONL line)
		if _, isArray := obj.([]interface{}); isArray {
			return "json"
		}
		return "jsonl"
	}
	return "unknown"
}

// validateEvent performs basic validation on the parsed event
func validateEvent(event interface{}) error {
	eventMap, ok := event.(map[string]interface{})
	if !ok {
		return fmt.Errorf("event must be a JSON object")
	}

	// Check for required fields
	if _, hasTime := eventMap["time"]; !hasTime {
		return fmt.Errorf("event missing required 'time' field")
	}

	if _, hasClassUID := eventMap["class_uid"]; !hasClassUID {
		return fmt.Errorf("event missing required 'class_uid' field")
	}

	return nil
}

// createSampleCase creates a sample case for demonstration
func createSampleCase(ctx context.Context, storeInstance *store.Store, eventType string) error {
	sampleCase := store.Case{
		Title:       fmt.Sprintf("Sample %s Investigation", strings.Title(eventType)),
		Description: fmt.Sprintf("Automatically created case for %s events", eventType),
		Severity:    "medium",
		Status:      "open",
		EventCount:  0,
	}

	_, err := storeInstance.CreateOrUpdateCase(ctx, sampleCase)
	return err
}