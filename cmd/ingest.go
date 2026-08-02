package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ingest"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/spf13/cobra"
)

var (
	inputFile   string
	batchSize   int
	skipInvalid bool
	noEnrich    bool
	ingestWatch bool
	ingestCase  string
	ingestGlobs string
)

// ingestCmd represents the ingest command
var ingestCmd = &cobra.Command{
	Use:   "ingest [path]",
	Short: "Ingest OCSF events from a file, a directory, or stdin",
	Long: `Ingest OCSF detections and events. Supports JSON and JSONL.

The path decides what happens, the way cp and tar work:

  a file        ingest that file
  a directory   ingest every matching file in it (--watch to keep tailing)
  -             read from stdin

Records are enriched (GeoIP, WHOIS) as they are ingested. Use --no-enrich to
skip the lookups for a bulk load.

Examples:
  # A file
  console-ir ingest events.jsonl

  # A directory, then keep watching it
  console-ir ingest ./incoming
  console-ir ingest ./incoming --watch

  # From stdin
  cat events.json | console-ir ingest -

  # Bulk load without enrichment lookups
  console-ir ingest --no-enrich big-export.jsonl`,
	Args: cobra.MaximumNArgs(1),
	RunE: runIngest,
}

func init() {
	rootCmd.AddCommand(ingestCmd)

	ingestCmd.Flags().IntVar(&batchSize, "batch-size", 50, "Number of events to process in each batch")
	ingestCmd.Flags().BoolVar(&skipInvalid, "skip-invalid", false, "Skip invalid events instead of failing")
	ingestCmd.Flags().BoolVar(&noEnrich, "no-enrich", false, "Skip GeoIP/WHOIS enrichment")
	ingestCmd.Flags().BoolVar(&ingestWatch, "watch", false, "Keep watching a directory for new records (directories only)")
	ingestCmd.Flags().StringVar(&ingestCase, "case", "", "Attach ingested records to a case with this title")
	ingestCmd.Flags().StringVar(&ingestGlobs, "pattern", "*.jsonl,*.json", "Comma-separated glob patterns to match in a directory")

	// Redis and plugin discovery only matter where enrichment or the bus run.
	ingestCmd.Flags().StringVar(&redisURL, "redis", "", "Redis URL for distributed mode; empty (default) runs standalone")
	ingestCmd.Flags().StringVar(&pluginsDir, "plugins-dir", "./plugins", "Directory containing plugins")

	// Superseded by the positional argument; kept so existing scripts keep working.
	ingestCmd.Flags().StringVarP(&inputFile, "file", "f", "", "Input file path (deprecated: pass the path as an argument)")
	_ = ingestCmd.Flags().MarkDeprecated("file", "pass the path as an argument instead: console-ir ingest <path>")
}

func runIngest(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	config := GetConfig()

	target := inputFile
	if len(args) > 0 {
		target = args[0]
	}

	logger := runtimeLoggerConsole("ingest", os.Stderr)

	baseDir := getWorkingDir()
	resolvedDBPath := resolvePathRelativeToBase(baseDir, config.Database.Path)
	st, err := store.NewStore(resolvedDBPath)
	if err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}
	defer st.Close()

	// One enricher for the whole run, so its worker pool and counters are shared.
	var enricher *syncEnricher
	if !noEnrich {
		enricher = newSyncEnricher(st, logger)
		if err := enricher.Start(ctx); err != nil {
			return fmt.Errorf("failed to start enrichment: %w", err)
		}
		defer enricher.Stop()
	}

	// A directory is a different shape of work: the folder ingestor already
	// handles globbing, offsets and tailing, so reuse it rather than
	// reimplementing directory walking here.
	if isDirectory(target) {
		return runDirectoryIngest(ctx, config, st, enricher, target, logger)
	}

	var input io.Reader
	var inputName string
	if target == "" || target == "-" {
		input = os.Stdin
		inputName = "stdin"
	} else {
		file, err := os.Open(target)
		if err != nil {
			return fmt.Errorf("failed to open input: %w", err)
		}
		defer file.Close()
		input = file
		inputName = target
	}

	logger.Printf("Ingesting from %s into %s", inputName, resolvedDBPath)

	eventBus := bus.NewBus(config.Redis.URL, logger)
	defer eventBus.Close()

	parser := ingest.NewParser()

	stats, err := processEvents(ctx, input, parser, st, eventBus, enricher, logger)
	if err != nil {
		return fmt.Errorf("failed to process events: %w", err)
	}

	// Enrichment is scheduled per record but runs concurrently; wait for it so
	// the command does not exit with lookups still in flight.
	var enrichApplied, enrichFailed int
	if enricher != nil {
		enrichApplied, enrichFailed = enricher.Wait()
	}

	// The summary is this command's result, printed for a person watching it
	// run. A timestamp and a severity belong on a log record, not on the answer
	// to "what did that do" — the same numbers are in the log file either way.
	report(os.Stdout, "Ingested %d of %d events in %s.",
		stats.SuccessfulEvents, stats.TotalEvents, stats.ProcessingTime.Round(time.Millisecond))
	// Records that are not OCSF are reported as their own thing, and the cause
	// is named once rather than per record. Console-IR consumes OCSF and does
	// not convert to it, so "not recognised" is the whole answer — repeating it
	// five hundred times says no more than saying it once.
	if stats.NotOCSFEvents > 0 {
		report(os.Stdout, "  %d not recognised as OCSF", stats.NotOCSFEvents)
		report(os.Stdout, "     no class_uid, so there is no OCSF class to read these as.")
		if stats.NotOCSFSample != "" {
			report(os.Stdout, "     first was: %s", stats.NotOCSFSample)
		}
		report(os.Stdout, "     Console-IR reads OCSF and does not convert to it — map your")
		report(os.Stdout, "     source to OCSF first, or pass --skip-invalid to ingest the rest.")
	}
	if other := stats.FailedEvents - stats.NotOCSFEvents; other > 0 {
		report(os.Stdout, "  %d failed", other)
	}
	if stats.SkippedEvents > 0 {
		report(os.Stdout, "  %d skipped (already ingested)", stats.SkippedEvents)
	}
	if enricher != nil {
		line := fmt.Sprintf("  %d enrichments applied", enrichApplied)
		if enrichFailed > 0 {
			line += fmt.Sprintf(", %s failed (see %s)", plural(enrichFailed, "lookup"), runtimeLogPath())
		}
		report(os.Stdout, "%s", line)
	}

	if stats.FailedEvents > 0 && !skipInvalid {
		// The exit status has to reflect it, or a script sees success on a run
		// that stored nothing usable.
		if stats.NotOCSFEvents == stats.FailedEvents {
			return fmt.Errorf("%d of %d records were not recognised as OCSF",
				stats.NotOCSFEvents, stats.TotalEvents)
		}
		return fmt.Errorf("ingestion completed with %d failed events", stats.FailedEvents)
	}

	return nil
}

// isDirectory reports whether the target path is an existing directory.
func isDirectory(path string) bool {
	if path == "" || path == "-" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// runDirectoryIngest ingests every matching file in a directory, optionally
// tailing it, reusing the same folder ingestor the TUI runs.
func runDirectoryIngest(ctx context.Context, config Config, st *store.Store,
	enricher *syncEnricher, dir string, logger *logging.Logger) error {

	eventBus := bus.NewBus(config.Redis.URL, logger)
	defer eventBus.Close()

	var patterns []string
	for _, p := range strings.Split(ingestGlobs, ",") {
		if s := strings.TrimSpace(p); s != "" {
			patterns = append(patterns, s)
		}
	}
	if len(patterns) == 0 {
		patterns = []string{"*.jsonl", "*.json"}
	}

	opts := ingest.FolderOptions{
		Dir:         dir,
		Watch:       ingestWatch,
		Patterns:    patterns,
		CaseTitle:   ingestCase,
		Logger:      logger,
		TailFromEnd: false,
	}
	if enricher != nil {
		opts.Enricher = enricher
	}

	logger.Info("ingesting directory %s (watch=%v patterns=%v)", dir, ingestWatch, patterns)
	report(os.Stdout, "Watching %s for %s ...", dir, strings.Join(patterns, ", "))

	ingestor := ingest.NewFolderIngestor(ingest.NewParser(), st, eventBus, opts)
	if err := ingestor.Run(ctx); err != nil && err != context.Canceled {
		return fmt.Errorf("directory ingest failed: %w", err)
	}

	if enricher != nil {
		applied, failed := enricher.Wait()
		line := fmt.Sprintf("Directory ingest finished. %d enrichments applied", applied)
		if failed > 0 {
			line += fmt.Sprintf(", %s failed (see %s)", plural(failed, "lookup"), runtimeLogPath())
		}
		report(os.Stdout, "%s.", line)
	} else {
		report(os.Stdout, "Directory ingest finished.")
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

	// NotOCSFEvents counts records that were valid JSON but not OCSF events.
	// Separate from FailedEvents because the cause and the remedy differ: a
	// failed record is a bug or a malformed line, while these are somebody
	// else's log format, and the answer is to convert it first.
	NotOCSFEvents int
	// NotOCSFSample is the first such record, quoted once so the user can tell
	// which of their files it was without reading the log.
	NotOCSFSample string
}

// processEvents processes events from the input reader
func processEvents(ctx context.Context, input io.Reader, parser *ingest.Parser,
	store *store.Store, eventBus bus.Bus, enricher *syncEnricher, logger *logging.Logger) (*IngestStats, error) {

	startTime := time.Now()
	stats := &IngestStats{}

	scanner := bufio.NewScanner(input)
	// Raise the line cap well above the 64 KB default; OCSF events with large
	// cmd_line or observable arrays routinely exceed it, and the default would
	// abort the whole run with "token too long" (unrecoverable by --skip-invalid).
	// Mirrors the folder ingestor's buffer sizing.
	scanner.Buffer(make([]byte, 0, 1<<20), 10<<20)
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
			batchStats := processBatch(ctx, batch, parser, store, eventBus, enricher, logger, lineNumber-len(batch)+1)
			updateStats(stats, batchStats)
			batch = batch[:0] // Reset batch
		}
	}

	// Process remaining events in batch
	if len(batch) > 0 {
		batchStats := processBatch(ctx, batch, parser, store, eventBus, enricher, logger, lineNumber-len(batch)+1)
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
	store *store.Store, eventBus bus.Bus, enricher *syncEnricher, logger *logging.Logger, startLine int) *IngestStats {

	stats := &IngestStats{}

	for i, eventData := range batch {
		lineNumber := startLine + i

		if err := processEvent(ctx, eventData, parser, store, eventBus, enricher, logger, lineNumber); err != nil {
			stats.FailedEvents++
			var notOCSF *ingest.NotOCSFError
			if errors.As(err, &notOCSF) {
				stats.NotOCSFEvents++
				if stats.NotOCSFSample == "" {
					stats.NotOCSFSample = notOCSF.Sample
				}
			}
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
	store *store.Store, eventBus bus.Bus, enricher *syncEnricher, logger *logging.Logger, lineNumber int) error {

	// Parse and route: Findings-category records and alertable events become
	// findings; everything else stays an event.
	rec, err := parser.Parse(eventData)
	if err != nil {
		return fmt.Errorf("failed to parse OCSF event: %w", err)
	}

	// Save to database
	saved, err := store.SaveRecord(ctx, rec)
	if err != nil {
		return fmt.Errorf("failed to save record to database: %w", err)
	}

	recordID := saved.EventID
	if recordID == "" {
		recordID = saved.FindingID
	}

	// Publish to Redis stream for plugin processing
	eventMsg := bus.EventMessage{
		EventID:   recordID,
		EventType: rec.EventType(),
		RawJSON:   string(eventData),
		Timestamp: rec.Timestamp(),
	}

	if err := eventBus.PublishEvent(ctx, eventMsg); err != nil {
		// Log the error but don't fail the ingestion
		logger.Warn("failed to publish event %s to bus: %v", recordID, err)
	}

	// Enrich in-process. Events carry the indicators GeoIP and WHOIS act on;
	// findings are triaged on their own merits and are not enriched here.
	if enricher != nil && saved.EventID != "" {
		enricher.EnqueueEvent(eventMsg)
	}

	return nil
}

// updateStats updates the main stats with batch stats
func updateStats(main, batch *IngestStats) {
	main.TotalEvents += batch.TotalEvents
	main.SuccessfulEvents += batch.SuccessfulEvents
	main.FailedEvents += batch.FailedEvents
	main.SkippedEvents += batch.SkippedEvents
	main.NotOCSFEvents += batch.NotOCSFEvents
	if main.NotOCSFSample == "" {
		main.NotOCSFSample = batch.NotOCSFSample
	}
}

// report writes a line of user-facing command output.
//
// Results go to stdout so they can be piped; the log file keeps its own record
// with timestamps and levels. Mixing the two meant a person reading "did that
// work?" had to parse a log record to find the number.
func report(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, format+"\n", args...)
}

// plural renders a count with its noun, pluralised. Command output is read by
// people, and "1 lookups failed" reads like a bug in the tool reporting the bug.
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
