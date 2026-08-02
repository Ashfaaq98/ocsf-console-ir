package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ingest"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ui"
	"github.com/spf13/cobra"
)

// databaseExists reports whether path is an existing, non-empty database file.
//
// This has to be answered before store.NewStore is called. NewStore creates the
// parent directory, and SQLite creates the file as soon as it is opened, so
// after that point the answer is always yes and the Welcome Screen becomes
// unreachable code.
//
// The size check matters as much as the stat: an interrupted first run can
// leave a zero-byte file behind, which is not a database anyone can use.
func databaseExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// runWelcome shows the Welcome Screen and carries out whatever was chosen.
//
// dbPath has already been resolved from --db, --data-dir and --portable, so the
// screen offers to create the database the rest of this process will open.
func runWelcome(cmd *cobra.Command, dbPath string) (ui.WelcomeResult, error) {
	// File-only: the Welcome Screen owns the terminal while it runs, so a log
	// line mirrored to stderr would be painted over its card.
	logger := runtimeLogger("welcome")

	return ui.RunWelcome(ui.WelcomeOptions{
		DBPath:   dbPath,
		WatchDir: resolvePathRelativeToBase(getWorkingDir(), ingestDir),
		Logger:   logger,
		Perform: func(res ui.WelcomeResult, progress func(string)) error {
			return performWelcome(cmd, dbPath, res, logger, progress)
		},
	})
}

// performWelcome does the work behind a Welcome Screen choice. It runs off the
// UI goroutine and reports each stage through progress.
func performWelcome(cmd *cobra.Command, dbPath string, res ui.WelcomeResult,
	logger *logging.Logger, progress func(string)) error {

	if res.Action == ui.WelcomeQuit {
		// Quitting creates nothing. The screen never asks for this, but the
		// contract is worth stating where the database is created.
		return nil
	}

	progress("Creating database…")
	if err := createDatabase(dbPath); err != nil {
		return err
	}
	logger.Info("welcome: created database at %s", dbPath)

	switch res.Action {
	case ui.WelcomeDemo:
		progress("Loading sample incident…")
		return seedDemoStore(cmd, dbPath, logger)

	case ui.WelcomeImport:
		progress(fmt.Sprintf("Importing %s…", filepath.Base(res.Path)))
		return importFile(cmd.Context(), dbPath, res.Path, logger)

	case ui.WelcomeWatch:
		progress(fmt.Sprintf("Preparing %s…", filepath.Base(res.Path)))
		if err := os.MkdirAll(res.Path, 0o755); err != nil {
			return fmt.Errorf("could not create the watch folder: %w", err)
		}
		logger.Info("welcome: watching %s", res.Path)
		return nil
	}

	return nil
}

// createDatabase creates and migrates the database, then closes it. The store
// is reopened by the normal startup path, so this leaves nothing held open.
func createDatabase(path string) error {
	st, err := store.NewStore(path)
	if err != nil {
		return fmt.Errorf("could not create the database: %w", err)
	}
	return st.Close()
}

// importFile ingests a single JSON or JSONL file into a freshly created
// database. Enrichment is skipped: it makes network calls, and the first thing
// a new install does should not depend on being online.
func importFile(ctx context.Context, dbPath, file string, logger *logging.Logger) error {
	info, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("could not read that path: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("that is a folder, not a file — use option 4 to watch a folder")
	}

	st, err := store.NewStore(dbPath)
	if err != nil {
		return fmt.Errorf("could not open the database: %w", err)
	}
	defer st.Close()

	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("could not read that file: %w", err)
	}
	defer f.Close()

	eventBus := bus.NewBus("", logger)
	defer eventBus.Close()

	stats, err := processEvents(ctx, f, ingest.NewParser(), st, eventBus, nil, logger)
	if err != nil {
		return fmt.Errorf("could not import that file: %w", err)
	}
	if stats.SuccessfulEvents == 0 {
		// This is a first run: somebody pointed the tool at their own data and
		// it read nothing. "Rejected" alone sends them looking for a bug in
		// Console-IR, when the answer is almost always that the file is not
		// OCSF — so when that is what happened, say so.
		if stats.NotOCSFEvents > 0 {
			return fmt.Errorf(
				"that file is not OCSF — %d of %d records have no class_uid.\n"+
					"Console-IR reads OCSF and does not convert to it; map your source to OCSF first",
				stats.NotOCSFEvents, stats.TotalEvents)
		}
		return fmt.Errorf("no events could be read from that file (%d records rejected)", stats.FailedEvents)
	}

	logger.Info("welcome: imported %d of %d events from %s",
		stats.SuccessfulEvents, stats.TotalEvents, file)
	return nil
}
