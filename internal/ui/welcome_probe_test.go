package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// "Watch a folder" is the one action whose usefulness depends on a fact the
// analyst cannot see from this screen, so the count has to be real.
func TestWatchFolderStatusCountsWhatIsThere(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.jsonl", "b.json", "c.JSONL"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Neither of these is evidence: one is the wrong kind of file, the other is
	// not a file at all.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "archive"), 0o755); err != nil {
		t.Fatal(err)
	}

	if got := watchFolderStatus(dir); !strings.Contains(got, "3 files waiting") {
		t.Errorf("status = %q, want 3 files", got)
	}
}

// A folder that is not there yet is the ordinary case on a first run — the
// action creates it. Reporting "0 files waiting" would describe a folder that
// does not exist, which reads as the tool having looked and found nothing.
func TestWatchFolderStatusOnAMissingFolder(t *testing.T) {
	got := watchFolderStatus(filepath.Join(t.TempDir(), "not-created-yet"))

	if !strings.Contains(got, "will be created") {
		t.Errorf("status = %q, want it to say the folder will be created", got)
	}
	if strings.Contains(got, "0 file") || strings.Contains(got, "empty") {
		t.Errorf("status = %q, which describes a folder that does not exist", got)
	}
}

func TestWatchFolderStatusOnAnEmptyFolder(t *testing.T) {
	if got := watchFolderStatus(t.TempDir()); !strings.Contains(got, "empty") {
		t.Errorf("status = %q, want it to say the folder is empty", got)
	}
}

// No watch folder configured means the action has nothing to say, and a blank
// detail line is dropped rather than rendered as an empty row.
func TestWatchFolderStatusWithNoFolder(t *testing.T) {
	if got := watchFolderStatus("  "); got != "" {
		t.Errorf("status = %q, want empty", got)
	}
}

// The probe must be total. This screen runs before there is a database, so a
// panic here is a first-run crash with nothing to fall back on.
func TestWatchFolderStatusSurvivesAFileWhereAFolderShouldBe(t *testing.T) {
	file := filepath.Join(t.TempDir(), "incoming")
	if err := os.WriteFile(file, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := watchFolderStatus(file); got == "" {
		t.Error("a file where a folder should be produced no status at all")
	}
}

func TestShortenPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory on this machine")
	}

	full := filepath.Join(home, ".local", "share", "console-ir", "console-ir.db")
	got := shortenPath(full, 44)

	if !strings.HasPrefix(got, "~") {
		t.Errorf("shortenPath(%q) = %q, want the home directory abbreviated", full, got)
	}
	if strings.Contains(got, home) {
		t.Errorf("shortenPath left the home directory in: %q", got)
	}
}

// The tail is kept, because the tail is the filename — the part that says which
// path this is.
func TestShortenPathKeepsTheTail(t *testing.T) {
	long := "/very/deeply/nested/directory/structure/somewhere/console-ir.db"

	got := shortenPath(long, 24)

	if len([]rune(got)) > 24 {
		t.Errorf("shortenPath returned %d columns, want at most 24: %q", len([]rune(got)), got)
	}
	if !strings.HasSuffix(got, "console-ir.db") {
		t.Errorf("shortenPath dropped the filename: %q", got)
	}
}

// The path the first action will write to has to be on the page before it is
// pressed. It used to appear only after creating the database had failed, which
// is the one moment it is too late to be useful.
func TestWelcomeNamesTheDatabaseBeforeCreatingIt(t *testing.T) {
	v := newTestWelcome(t, WelcomeOptions{DBPath: "/srv/evidence/console-ir.db"})
	v.relayout(140, 40)

	text := pageText(v)
	if !strings.Contains(text, "/srv/evidence/console-ir.db") {
		t.Errorf("the page does not say where the database will go:\n%s", text)
	}
	if !strings.Contains(text, welcomeDatabaseLeadB) {
		t.Errorf("the path is on the page with nothing to say what it is:\n%s", text)
	}
}
