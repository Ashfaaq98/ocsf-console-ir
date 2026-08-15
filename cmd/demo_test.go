package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
)

// A demo killed rather than quit never runs its deferred cleanup. Two such
// directories were found on a real machine, so the sweep is not hypothetical.
func TestSweepStaleDemoDirs(t *testing.T) {
	tmp := t.TempDir()
	// os.TempDir reads TMPDIR on Unix and TMP or TEMP on Windows. Setting only
	// the first left the sweep scanning the real temporary directory, where it
	// found nothing and the fixture below survived — reported as "an abandoned
	// demo directory was left behind".
	setTempDir(t, tmp)

	mkdir := func(name string, age time.Duration) string {
		p := filepath.Join(tmp, name)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
		return p
	}

	stale := mkdir(demoDirPrefix+"111", 48*time.Hour)
	fresh := mkdir(demoDirPrefix+"222", time.Minute)
	other := mkdir("something-else-333", 48*time.Hour)

	sweepStaleDemoDirs(logging.New(io.Discard, logging.LevelDebug, "test"))

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("an abandoned demo directory was left behind")
	}
	// A concurrent demo must never be swept out from under itself.
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("a recent demo directory was removed: %v", err)
	}
	// Nothing outside our own prefix may be touched — this runs against the
	// shared temp directory.
	if _, err := os.Stat(other); err != nil {
		t.Errorf("an unrelated directory was removed: %v", err)
	}
}

func TestSweepStaleDemoDirsToleratesAnUnreadableTemp(t *testing.T) {
	setTempDir(t, filepath.Join(t.TempDir(), "does-not-exist"))
	// Housekeeping failure must never fail the command.
	sweepStaleDemoDirs(logging.New(io.Discard, logging.LevelDebug, "test"))
}

// The prefix is shared between the sweep and MkdirTemp; if they drift, the
// sweep silently stops matching anything.
func TestDemoDirPrefixMatchesWhatIsCreated(t *testing.T) {
	tmp := t.TempDir()
	setTempDir(t, tmp)

	dir, err := os.MkdirTemp("", demoDirPrefix)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	if !strings.HasPrefix(filepath.Base(dir), demoDirPrefix) {
		t.Errorf("created %q, which the sweep would not match", filepath.Base(dir))
	}
}

// setTempDir points os.TempDir at a directory on every platform.
func setTempDir(t *testing.T, dir string) {
	t.Helper()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, dir)
	}
}
