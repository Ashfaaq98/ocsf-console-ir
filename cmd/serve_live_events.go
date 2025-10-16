package cmd

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ingest"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ui"
	"github.com/spf13/cobra"
)

var (
	liveURL       string
	liveInterval  time.Duration
	liveCaseTitle string
	liveCount     int
	liveJitter    float64
)

// liveEventsCmd represents `console-ir serve live-events`
var liveEventsCmd = &cobra.Command{
	Use:   "live-events",
	Short: "Fetch random OCSF events from a simulator endpoint on an interval and ingest them",
	Long: `Fetch random OCSF events from a simulator endpoint on a fixed interval and ingest them
so they appear in the Events view. This behaves similarly to folder-based ingestion,
but sources events via HTTP instead of files.

The command runs until interrupted (Ctrl+C) or until --count events are ingested (when > 0).

Examples:
  # Default interval (2s) and default simulator URL
  console-ir serve live-events

  # Faster interval with jitter and custom URL
  console-ir serve live-events --interval 1s --jitter 0.1 --url https://schema.ocsf.io/sample/1.6.0/classes/authentication?profiles=cloud

  # Ingest a fixed number of events and exit
  console-ir serve live-events --count 25
`,
	RunE: runLiveEvents,
}

func init() {
	// Register as a subcommand of "serve" without modifying serve.go
	serveCmd.AddCommand(liveEventsCmd)

	// Flags (defaults: interval=2s, no default case assignment)
	liveEventsCmd.Flags().StringVar(&liveURL, "url",
		"https://schema.ocsf.io/sample/1.6.0/classes/account_change?profiles=cloud",
		"OCSF simulator endpoint that returns one event per GET")
	liveEventsCmd.Flags().DurationVar(&liveInterval, "interval", 2*time.Second,
		"Interval between event fetches (e.g. 2s, 500ms)")
	liveEventsCmd.Flags().StringVar(&liveCaseTitle, "case-title", "",
		"Optional: assign ingested events to this case (created if missing)")
	liveEventsCmd.Flags().IntVar(&liveCount, "count", 0,
		"Optional: number of events to ingest before exiting (0 = run until cancelled)")
	liveEventsCmd.Flags().Float64Var(&liveJitter, "jitter", 0.0,
		"Optional: jitter factor 0.0–1.0 to randomize interval by ±jitter")
}

func runLiveEvents(cmd *cobra.Command, args []string) error {
	parentCtx := cmd.Context()
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	// Shared cancellable context for TUI, ingestor, and auto-refresh
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	cfg := GetConfig()

	// Resolve base dir for file logging and paths
	baseDir := getWorkingDir()

	// Prepare a file-backed top-level logger (no console output)
	logDir := filepath.Join(baseDir, "logs")
	_ = os.MkdirAll(logDir, 0755)
	liveLogPath := filepath.Join(logDir, "console-ir-live.log")
	var logger *log.Logger
	if f, ferr := os.OpenFile(liveLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); ferr == nil {
		logger = log.New(f, "[live-events] ", log.LstdFlags)
		defer f.Close()
	} else {
		// If we cannot open the log file, stay silent
		logger = log.New(io.Discard, "", 0)
	}
	logger.Println("Starting live events with embedded TUI")
	resolvedDBPath := resolvePathRelativeToBase(baseDir, cfg.Database.Path)
	logger.Printf("Using database at %s", resolvedDBPath)

	// Initialize store
	st, err := store.NewStore(resolvedDBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	// Initialize bus (silence logs while TUI is active to avoid terminal noise)
	busLogger := log.New(io.Discard, "", 0)
	eventBus := bus.NewBus(cfg.Redis.URL, busLogger)
	defer eventBus.Close()

	// Parser
	parser := ingest.NewParser()

	// Live ingestor options (interval=2s default, no default case)
	opts := ingest.LiveOptions{
		URL:        liveURL,
		Interval:   liveInterval,
		Jitter:     liveJitter,
		CaseTitle:  liveCaseTitle,
		Count:      liveCount,
		Logger:     logger,
		HTTPClient: nil, // use default
	}
	ing := ingest.NewLiveIngestor(parser, st, eventBus, opts)

	// Start live ingestor in the background
	go func() {
		if err := ing.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Printf("Live ingestor exited with error: %v", err)
		} else if ctx.Err() == nil && liveCount > 0 {
			logger.Printf("Live ingestor completed after %d events (TUI remains open)", liveCount)
		}
	}()

	// Prepare a file-backed UI logger to avoid corrupting terminal output
	if err := os.MkdirAll(logDir, 0755); err != nil {
		logger.Printf("Warning: could not create logs directory: %v", err)
	}
	logPath := filepath.Join(logDir, "console-ir-ui.log")
	var uiLogger *log.Logger
	if f, ferr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); ferr == nil {
		defer f.Close()
		uiLogger = log.New(f, "[UI] ", log.LstdFlags)
		uiLogger.Printf("UI logger initialized (path=%s)", logPath)
	} else {
		logger.Printf("Warning: could not create UI log file at %s: %v", logPath, ferr)
		uiLogger = log.New(io.Discard, "[UI] ", log.LstdFlags)
	}

	// Create and start the TUI
	tui := ui.NewUI(ctx, st, nil, uiLogger)

	// Auto-refresh ALL EVENTS every 1s so new live-ingested events appear without manual 'r'
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tui.RefreshAllEventsAsync("live:auto")
			}
		}
	}()

	// Block until the TUI exits; then cancel background workers
	if err := tui.Start(ctx); err != nil {
		// If TUI failed to start for terminal reasons, return the error
		cancel()
		return err
	}

	// TUI exited by user (q/Ctrl+C). Cancel and allow background goroutines to stop.
	cancel()
	logger.Println("TUI exited; stopping live events")
	return nil
}