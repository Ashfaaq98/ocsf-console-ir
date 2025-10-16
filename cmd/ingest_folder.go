package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ingest"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/spf13/cobra"
)

var (
	folderDir      string
	folderWatch    bool
	folderCase     string
	folderPatterns string
)

// ingestFolderCmd represents the ingest-folder command
var ingestFolderCmd = &cobra.Command{
	Use:   "ingest-folder",
	Short: "Ingest OCSF events from files in a directory (optionally watch for changes)",
	Long: `Ingest OCSF events from a directory. Supports JSONL (line-delimited) and JSON files.

Examples:
  # One-shot: ingest existing files and exit
  console-ir ingest-folder --dir ./incoming

  # Watch mode: tail JSONL appends and reprocess JSON changes
  console-ir ingest-folder --dir ./incoming --watch

  # Specify case title and file patterns
  console-ir ingest-folder --dir ./incoming --case "Ingested Events" --pattern "*.jsonl,*.json"`,
	RunE: runIngestFolder,
}

func init() {
	rootCmd.AddCommand(ingestFolderCmd)

	ingestFolderCmd.Flags().StringVar(&folderDir, "dir", "", "Directory to read files from (required)")
	ingestFolderCmd.MarkFlagRequired("dir")

	ingestFolderCmd.Flags().BoolVar(&folderWatch, "watch", false, "Watch directory for changes and tail JSONL files")

	ingestFolderCmd.Flags().StringVar(&folderCase, "case", "Ingested Events", "Case title to assign ingested events to")

	ingestFolderCmd.Flags().StringVar(&folderPatterns, "pattern", "*.jsonl,*.json", "Comma-separated glob patterns to match (e.g. \"*.jsonl,*.json\")")
}

func runIngestFolder(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	cfg := GetConfig()

	// Initialize logger
	logger := log.New(os.Stderr, "[ingest-folder] ", log.LstdFlags)

	// Initialize store
	st, err := store.NewStore(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}
	defer st.Close()

	// Initialize bus
	eventBus := bus.NewBus(cfg.Redis.URL, logger)
	defer eventBus.Close()

	// Initialize parser
	parser := ingest.NewParser()

	// Patterns
	var patterns []string
	for _, p := range strings.Split(folderPatterns, ",") {
		if s := strings.TrimSpace(p); s != "" {
			patterns = append(patterns, s)
		}
	}
	if len(patterns) == 0 {
		patterns = []string{"*.jsonl", "*.json"}
	}

	opts := ingest.FolderOptions{
		Dir:       folderDir,
		Watch:     folderWatch,
		Patterns:  patterns,
		CaseTitle: folderCase,
		Logger:    logger,
	}

	logger.Printf("Starting ingest-folder dir=%s watch=%v case=%q patterns=%v", opts.Dir, opts.Watch, opts.CaseTitle, opts.Patterns)

	ingestor := ingest.NewFolderIngestor(parser, st, eventBus, opts)

	if err := ingestor.Run(ctx); err != nil && err != context.Canceled {
		return fmt.Errorf("ingest-folder error: %w", err)
	}

	logger.Printf("ingest-folder completed")
	return nil
}