package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/demo"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ingest"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/spf13/cobra"
)

var demoKeep bool

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Explore Console-IR with a sample incident, in a throwaway database",
	Long: `Load a sample incident into a temporary database and open it in the TUI.

The demo never touches your real database. Everything lives in a temporary
directory that is removed on exit, so it is safe to run before you have any data
of your own — and safe to run again.

The sample is one coherent incident: a phishing attachment leads to encoded
PowerShell, credential access and C2 beaconing on a single host. That gives the
findings queue, the case model and the indicator pivot something real to show.

Examples:
  # Explore, then throw it away
  console-ir demo

  # Keep the database afterwards to poke at it
  console-ir demo --keep`,
	Args: cobra.NoArgs,
	RunE: runDemo,
}

func init() {
	rootCmd.AddCommand(demoCmd)
	demoCmd.Flags().BoolVar(&demoKeep, "keep", false, "Keep the temporary database instead of deleting it on exit")
}

func runDemo(cmd *cobra.Command, args []string) error {
	logger := runtimeLoggerConsole("demo", os.Stderr)

	// A demo killed rather than quit never runs its cleanup, so tidy up what
	// earlier runs left behind before adding another directory. This is
	// housekeeping, so it is recorded in the log rather than shown on a screen
	// the user is about to hand to the TUI.
	sweepStaleDemoDirs(runtimeLogger("demo"))

	dir, err := os.MkdirTemp("", demoDirPrefix)
	if err != nil {
		return fmt.Errorf("failed to create demo directory: %w", err)
	}
	if !demoKeep {
		defer os.RemoveAll(dir)
	}

	demoDB := filepath.Join(dir, "demo.db")

	fmt.Fprintf(os.Stderr, "Loading %d sample records into a throwaway database...\n", demo.RecordCount())

	if err := seedDemoStore(cmd, demoDB, logger); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Opening the TUI. Press D for findings, A for events, ? for help, q to quit.")

	// Point the TUI at the demo database and its own empty inbox, so a demo run
	// neither reads nor writes anything the user cares about.
	if err := cmd.Flags().Set("db", demoDB); err != nil {
		return err
	}
	dbPath = demoDB
	ingestDir = filepath.Join(dir, "incoming")

	if err := runServe(cmd, nil); err != nil {
		return err
	}

	// The TUI restores the pre-launch screen on exit, so the last thing left on
	// the terminal would otherwise be "press D … q to quit" — instructions for a
	// session that has ended, which reads like a failure to launch. Say what
	// actually happened instead.
	if demoKeep {
		fmt.Fprintf(os.Stderr, "\nDemo finished. Database kept at %s\n", demoDB)
	} else {
		fmt.Fprintln(os.Stderr, "\nDemo finished. The throwaway database was discarded.")
	}
	return nil
}

// demoDirPrefix names the temporary directories a demo run creates.
const demoDirPrefix = "console-ir-demo-"

// staleDemoAge is how old an abandoned demo directory must be before it is
// swept. Generous enough that a concurrent demo is never touched.
const staleDemoAge = 24 * time.Hour

// sweepStaleDemoDirs removes demo directories left by runs that were killed
// before their cleanup could run. Failures are logged and ignored: this is
// housekeeping, not the user's task.
func sweepStaleDemoDirs(logger *logging.Logger) {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		logger.Debug("could not scan the temp directory for stale demos: %v", err)
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), demoDirPrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) < staleDemoAge {
			continue
		}
		path := filepath.Join(os.TempDir(), e.Name())
		if err := os.RemoveAll(path); err != nil {
			logger.Debug("could not remove stale demo directory %s: %v", path, err)
			continue
		}
		logger.Info("removed stale demo directory %s", path)
	}
}

// seedDemoStore ingests the embedded scenario into a fresh database.
// Enrichment is deliberately skipped: it makes network calls, and the demo
// should start instantly and work offline on a jump box or a plane.
func seedDemoStore(cmd *cobra.Command, dbPath string, logger *logging.Logger) error {
	st, err := store.NewStore(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create demo database: %w", err)
	}
	defer st.Close()

	eventBus := bus.NewBus("", logger)
	defer eventBus.Close()

	parser := ingest.NewParser()
	ctx := cmd.Context()

	var ingested, failed int
	for _, line := range bytes.Split(demo.Scenario(), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		rec, err := parser.Parse(line)
		if err != nil {
			failed++
			continue
		}
		if _, err := st.SaveRecord(ctx, rec); err != nil {
			failed++
			continue
		}
		ingested++
	}

	if ingested == 0 {
		return fmt.Errorf("demo data failed to load (%d records rejected)", failed)
	}
	if failed > 0 {
		logger.Printf("warning: %d demo records could not be loaded", failed)
	}
	return nil
}
