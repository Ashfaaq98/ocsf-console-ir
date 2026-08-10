package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// Where a run starts, for the three cases that exist.
//
// The decision lived inside runServe, which cannot be called from a test
// without launching a TUI — so the one branch that a previous version got wrong
// was covered by a tmux session run once, by hand.
func TestShouldShowWelcome(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent.db")
	present := filepath.Join(dir, "present.db")
	if err := os.WriteFile(present, []byte("not empty"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		willUseTUI bool
		path       string
		want       bool
	}{
		{"first run", true, missing, true},
		{"existing database", true, present, false},
		{"headless has no screen to show", false, missing, false},
		{"headless with a database", false, present, false},
	} {
		if got := shouldShowWelcome(tc.willUseTUI, tc.path); got != tc.want {
			t.Errorf("%s: shouldShowWelcome(%v, …) = %v, want %v",
				tc.name, tc.willUseTUI, got, tc.want)
		}
	}
}

// An empty file is not a database.
//
// store.NewStore creates the file, so a check that ran after it would answer
// yes on every run; a zero-byte file left by a crashed first run is the same
// situation and must still route to Welcome.
func TestAnEmptyFileIsNotADatabase(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !shouldShowWelcome(true, empty) {
		t.Error("a zero-byte database file did not route to the welcome screen")
	}

	dir := t.TempDir()
	if !shouldShowWelcome(true, dir) {
		t.Error("a directory in the database's place did not route to the welcome screen")
	}
}
