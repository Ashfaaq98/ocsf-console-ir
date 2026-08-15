package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/paths"
)

// TestRuntimeLoggersShareOneFile is the regression test for the log sprawl this
// replaced: the binary used to write console-ir-ui.log, console-ir-serve.log or
// console-ir-live.log depending on how it was launched. Every subsystem must
// now land in one file, distinguished by prefix — and they must share a single
// rotator, or two of them would fight over the same path.
func TestRuntimeLoggersShareOneFile(t *testing.T) {
	dir := t.TempDir()
	paths.Set(paths.Dirs{Data: dir, Config: dir, State: dir})
	// The log is process-wide and opened once. Left open, the temporary
	// directory cannot be removed on Windows, and the next test inherits this
	// one's file.
	t.Cleanup(closeRuntimeLog)

	serve := runtimeLogger("[serve] ")
	ui := runtimeLogger("[UI] ")
	ingest := runtimeLogger("[ingest] ")

	serve.Println("serve is up")
	ui.Println("ui is up")
	ingest.Println("ingest is up")

	// Exactly one log file, whatever the launch path.
	entries, err := filepath.Glob(filepath.Join(dir, "*.log*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("found %v, want a single %s", entries, logName)
	}
	if got := filepath.Base(entries[0]); got != logName {
		t.Errorf("log file = %q, want %q", got, logName)
	}

	data, err := os.ReadFile(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[serve] ", "[UI] ", "[ingest] "} {
		if !strings.Contains(string(data), want) {
			t.Errorf("%s is missing records from %q", logName, want)
		}
	}

	// All three loggers must be backed by the same rotator instance.
	if runtimeLog() == nil {
		t.Fatal("runtimeLog() is nil after successful writes")
	}
	if got := runtimeLogPath(); got != entries[0] {
		t.Errorf("runtimeLogPath() = %q, want %q", got, entries[0])
	}
}

// TestLogSizeCapIsBounded guards the constants themselves: the point of the
// item is that a long-running install cannot fill a disk.
func TestLogSizeCapIsBounded(t *testing.T) {
	if logMaxBytes <= 0 {
		t.Fatalf("logMaxBytes = %d: rotation is disabled, logs grow unbounded", logMaxBytes)
	}
	if logKeep < 0 {
		t.Fatalf("logKeep = %d", logKeep)
	}
	// (keep + 1) generations at the cap. Keep the ceiling somewhere a user
	// would not notice on a jump box.
	if total := int64(logMaxBytes) * int64(logKeep+1); total > 64<<20 {
		t.Errorf("logs can reach %d bytes, which is more than a jump box should give up", total)
	}
}
