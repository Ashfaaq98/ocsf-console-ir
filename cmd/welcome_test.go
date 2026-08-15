package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ui"
	"github.com/spf13/cobra"
)

func testLogger() *logging.Logger {
	return logging.New(io.Discard, logging.LevelError, "test")
}

func TestDatabaseExists(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing", func(t *testing.T) {
		if databaseExists(filepath.Join(dir, "nothing.db")) {
			t.Error("a path that does not exist reported as a database")
		}
	})

	t.Run("directory", func(t *testing.T) {
		sub := filepath.Join(dir, "adirectory")
		if err := os.MkdirAll(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		if databaseExists(sub) {
			t.Error("a directory reported as a database")
		}
	})

	// An interrupted first run leaves one of these behind. Treating it as a
	// database sends the analyst to an application with nothing to open.
	t.Run("zero length", func(t *testing.T) {
		empty := filepath.Join(dir, "empty.db")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if databaseExists(empty) {
			t.Error("a zero-byte file reported as a database")
		}
	})

	t.Run("real database", func(t *testing.T) {
		path := filepath.Join(dir, "real.db")
		st, err := store.NewStore(path)
		if err != nil {
			t.Fatal(err)
		}
		st.Close()

		if !databaseExists(path) {
			t.Error("a migrated database did not report as one")
		}
	})
}

// The trap this check exists to avoid: NewStore creates the parent directory
// and SQLite creates the file on open, so asking afterwards always answers yes
// and the Welcome Screen becomes unreachable.
//
// If this test ever fails on the "after" assertion, the check has been moved to
// the wrong side of the store and nobody will ever see the first-run screen.
func TestDatabaseExistsMustBeAskedBeforeTheStoreOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "console-ir.db")

	if databaseExists(path) {
		t.Fatal("a fresh path reported as an existing database")
	}

	st, err := store.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if !databaseExists(path) {
		t.Fatal("opening the store did not create the database file")
	}
}

func TestCreateDatabaseProducesAMigratedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "created.db")

	if err := createDatabase(path); err != nil {
		t.Fatalf("createDatabase: %v", err)
	}
	if !databaseExists(path) {
		t.Fatal("no database was created")
	}

	// Migrated, not merely present: reopening and querying is what the UI does
	// a moment later, and an unmigrated file fails there instead of here.
	st, err := store.NewStore(path)
	if err != nil {
		t.Fatalf("could not reopen the created database: %v", err)
	}
	defer st.Close()

	if _, err := st.ListCases(context.Background()); err != nil {
		t.Errorf("the created database has no schema: %v", err)
	}
}

// An unwritable location must surface as an error the screen can show, not as
// a panic or a silent success.
func TestCreateDatabaseReportsAnUnwritableLocation(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The fixture is a directory made unwritable with chmod 0500, which
		// Windows does not honour — so the write succeeds and the test reports
		// the code as broken when it behaved correctly for the platform.
		t.Skip("a directory cannot be made unwritable with chmod on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.MkdirAll(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	err := createDatabase(filepath.Join(dir, "sub", "console-ir.db"))
	if err == nil {
		t.Fatal("creating a database under an unwritable directory reported success")
	}
	if !strings.Contains(err.Error(), "could not create the database") {
		t.Errorf("error = %v, want it to name what failed", err)
	}
}

// The welcome flow creates the database before doing anything else, so every
// action leaves a usable install behind even if its own step fails.
func TestPerformWelcomeCreatesTheDatabaseFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "console-ir.db")
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	var stages []string
	err := performWelcome(cmd, path, ui.WelcomeResult{Action: ui.WelcomeCreate},
		testLogger(), func(s string) { stages = append(stages, s) })
	if err != nil {
		t.Fatalf("performWelcome: %v", err)
	}

	if !databaseExists(path) {
		t.Error("no database was created")
	}
	if len(stages) == 0 || !strings.Contains(stages[0], "Creating database") {
		t.Errorf("stages = %v, want the first one to name the database", stages)
	}
}

func TestPerformWelcomeQuitCreatesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "console-ir.db")
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	if err := performWelcome(cmd, path, ui.WelcomeResult{Action: ui.WelcomeQuit},
		testLogger(), func(string) {}); err != nil {
		t.Fatalf("performWelcome: %v", err)
	}

	if databaseExists(path) {
		t.Error("quitting created a database")
	}
}

func TestPerformWelcomeWatchCreatesTheFolder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "console-ir.db")
	watch := filepath.Join(dir, "incoming")

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	err := performWelcome(cmd, path, ui.WelcomeResult{Action: ui.WelcomeWatch, Path: watch},
		testLogger(), func(string) {})
	if err != nil {
		t.Fatalf("performWelcome: %v", err)
	}

	info, err := os.Stat(watch)
	if err != nil || !info.IsDir() {
		t.Errorf("watch folder was not created: %v", err)
	}
	if !databaseExists(path) {
		t.Error("watching a folder did not create the database")
	}
}

func TestPerformWelcomeImport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "console-ir.db")
	events := filepath.Join(dir, "events.jsonl")

	// One well-formed OCSF record is enough to prove the file reached the store.
	record := `{"class_uid":1001,"class_name":"File System Activity","activity_id":1,` +
		`"category_uid":1,"severity_id":3,"time":1722470400000,"type_uid":100101,` +
		`"metadata":{"version":"1.8.0","product":{"name":"test"}},` +
		`"message":"welcome import test"}`
	if err := os.WriteFile(events, []byte(record+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	err := performWelcome(cmd, path, ui.WelcomeResult{Action: ui.WelcomeImport, Path: events},
		testLogger(), func(string) {})
	if err != nil {
		t.Fatalf("performWelcome: %v", err)
	}

	st, err := store.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	n, err := st.CountEvents(context.Background(), store.EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("imported %d events, want 1", n)
	}
}

// Pointing the import at a folder is a plausible mistake, and the message has
// to say which option to use instead.
func TestPerformWelcomeImportRejectsADirectory(t *testing.T) {
	dir := t.TempDir()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	err := performWelcome(cmd, filepath.Join(dir, "db"),
		ui.WelcomeResult{Action: ui.WelcomeImport, Path: dir},
		testLogger(), func(string) {})

	if err == nil {
		t.Fatal("importing a directory reported success")
	}
	if !strings.Contains(err.Error(), "folder") {
		t.Errorf("error = %v, want it to point at the watch-a-folder option", err)
	}
}

func TestPerformWelcomeImportRejectsAMissingFile(t *testing.T) {
	dir := t.TempDir()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	err := performWelcome(cmd, filepath.Join(dir, "db"),
		ui.WelcomeResult{Action: ui.WelcomeImport, Path: filepath.Join(dir, "absent.jsonl")},
		testLogger(), func(string) {})

	if err == nil {
		t.Fatal("importing a missing file reported success")
	}
}

// A file with nothing usable in it must fail loudly rather than open an empty
// application that looks like the import worked.
func TestPerformWelcomeImportRejectsAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(junk, []byte("this is not JSON at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	err := performWelcome(cmd, filepath.Join(dir, "db"),
		ui.WelcomeResult{Action: ui.WelcomeImport, Path: junk},
		testLogger(), func(string) {})

	if err == nil {
		t.Fatal("importing an unparseable file reported success")
	}
}
