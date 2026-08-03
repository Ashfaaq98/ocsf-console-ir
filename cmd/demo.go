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

The sample is a working week in a small estate: a phishing-led intrusion still
being worked, an account compromise nobody has picked up, a cryptominer that was
closed as a true positive, and a scanner's findings closed as false positives —
sitting inside several hundred ordinary events. The story is shifted onto
today's calendar as it loads, so ages, filters and case headers describe a live
investigation rather than an archive.

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
	// File-only: everything the demo prints to the terminal is chosen
	// deliberately below and then erased before the TUI opens, so a stray log
	// line would either be wiped or outlive the session. Real failures are
	// returned as errors, not logged.
	logger := runtimeLogger("demo")

	// A demo killed rather than quit never runs its cleanup, so tidy up what
	// earlier runs left behind before adding another directory.
	sweepStaleDemoDirs(logger)

	dir, err := os.MkdirTemp("", demoDirPrefix)
	if err != nil {
		return fmt.Errorf("failed to create demo directory: %w", err)
	}
	if !demoKeep {
		defer os.RemoveAll(dir)
	}

	demoDB := filepath.Join(dir, "demo.db")

	// Seeding is quick but not instant, so say what is happening. This line is
	// erased before the TUI opens: tcell restores the pre-launch screen on exit,
	// so anything left here outlives the session it describes and ends up as the
	// last thing on the terminal — reading like the app failed to start.
	fmt.Fprintf(os.Stderr, "Loading %d sample records into a throwaway database...\n", demo.RecordCount())

	if err := seedDemoStore(cmd, demoDB, logger); err != nil {
		return err
	}

	clearLines(os.Stderr, 1)

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

	// The only thing the demo leaves behind: what happened to the database.
	if demoKeep {
		fmt.Fprintf(os.Stderr, "Demo finished. Database kept at %s\n", demoDB)
	} else {
		fmt.Fprintln(os.Stderr, "Demo finished. The throwaway database was discarded.")
	}
	return nil
}

// clearLines erases the last n lines written to w.
//
// Only when w is a terminal: redirected output would otherwise receive the
// escape sequences as literal text, which is worse than the tidy-up is worth.
func clearLines(w *os.File, n int) {
	if n <= 0 || !isCharDevice(w) {
		return
	}
	// CSI nF moves to the start of the line n lines up; CSI J clears from there
	// to the end of the screen.
	fmt.Fprintf(w, "\033[%dF\033[J", n)
}

// isCharDevice reports whether f is a terminal. The package already has an
// isTerminal(), but it always inspects stdout; the demo writes to stderr, and
// the check has to follow the writer it guards.
func isCharDevice(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
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

	records := [][]byte{}
	for _, line := range bytes.Split(demo.Scenario(), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		records = append(records, line)
	}

	// Move the story onto today's calendar before anything reads it, so ages,
	// the "last 24 hours" filter and the case header all describe a live
	// investigation rather than an archive.
	shift := demoTimeShift(newestDemoTime(records), time.Now().UTC())

	var ingested, failed int
	for _, line := range records {
		shifted, err := shiftDemoRecord(line, shift)
		if err != nil {
			failed++
			continue
		}
		rec, err := parser.Parse(shifted)
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

	// Cases are not ingested: Console-IR does not yet read OCSF Incident
	// Findings back into cases (roadmap, NEXT). Without this the demo would open
	// on an empty Cases screen and the case room — briefing, timeline, notes,
	// copilot — would have nothing to show.
	if err := seedDemoCases(ctx, st, shift); err != nil {
		return fmt.Errorf("failed to build the demo cases: %w", err)
	}
	return nil
}
