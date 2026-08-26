//go:build !windows

package ingest

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// Named pipes and symlinks are the shapes that make the missing type check
// dangerous, and neither exists in this form on Windows.
// The pattern match only ever looked at the name. A named pipe blocks the open
// forever inside the single ingest goroutine; a symlink to an endless device
// allocates until the runtime dies. Both must be refused before anything opens
// them — and the watcher must keep working afterwards.
func TestNonRegularEntriesAreRefused(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(dir, "endless.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	// A real payload alongside them: the poison must not stop the good file.
	os.WriteFile(filepath.Join(dir, "real.json"), []byte(offsetTestEvent), 0o600)

	st, _ := store.NewStore(":memory:")
	defer st.Close()
	ing := NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
		Dir: dir, Watch: true, CaseTitle: "",
	})

	done := make(chan error, 1)
	go func() { done <- ing.scanOnce(context.Background(), true) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
	case <-timeoutAfter():
		t.Fatal("the scan blocked — an entry was opened that should have been refused")
	}
	if n := countEvents(t, st); n != 1 {
		t.Fatalf("got %d events, want 1 (the real payload, with the poison skipped)", n)
	}
}
