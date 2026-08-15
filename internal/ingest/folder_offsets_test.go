package ingest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

const offsetTestEvent = `{"class_uid":4001,"category_uid":4,"activity_id":1,"type_uid":400101,"severity_id":3,"time":1700000000,"message":"conn","src_endpoint":{"ip":"10.0.0.5"}}`

// runWatchScan simulates a watch-mode startup pass: load persisted offsets,
// process pre-existing files once, then persist offsets — without entering the
// blocking watch loop. This is exactly what Run does before watchLoop.
func runWatchScan(t *testing.T, dir string, st *store.Store) *FolderIngestor {
	t.Helper()
	ing := NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
		Dir:       dir,
		Watch:     true,
		CaseTitle: "", // no case assignment
	})
	ing.loadOffsets()
	if err := ing.scanOnce(context.Background(), true); err != nil {
		t.Fatalf("scanOnce: %v", err)
	}
	ing.saveOffsets()
	return ing
}

func countEvents(t *testing.T, st *store.Store) int {
	t.Helper()
	events, err := st.GetAllEvents(context.Background(), 1000)
	if err != nil {
		t.Fatalf("GetAllEvents: %v", err)
	}
	return len(events)
}

// TestFolderIngest_IngestsPreexistingThenNoDuplicateOnRestart is the A1
// guarantee: a file staged in the folder BEFORE launch is ingested on the first
// pass, and a subsequent restart (second pass) does not re-ingest it.
func TestFolderIngest_IngestsPreexistingThenNoDuplicateOnRestart(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(offsetTestEvent+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	// First launch: the pre-existing file must be ingested.
	runWatchScan(t, dir, st)
	if n := countEvents(t, st); n != 1 {
		t.Fatalf("after first pass: got %d events, want 1", n)
	}

	// A state file should now exist so restarts can resume.
	if _, err := os.Stat(filepath.Join(dir, ".ingest-offsets.state")); err != nil {
		t.Fatalf("expected persisted offset state file: %v", err)
	}

	// Restart: same store, same files, fresh ingestor. Must NOT duplicate.
	runWatchScan(t, dir, st)
	if n := countEvents(t, st); n != 1 {
		t.Fatalf("after restart: got %d events, want 1 (no re-ingest)", n)
	}
}

// TestFolderIngest_TailFromEndSkipsBacklog verifies the opt-in tail-only mode:
// with TailFromEnd set and no prior offset, an existing backlog is skipped.
func TestFolderIngest_TailFromEndSkipsBacklog(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(offsetTestEvent+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	ing := NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
		Dir:         dir,
		Watch:       true,
		TailFromEnd: true,
		CaseTitle:   "",
	})
	ing.loadOffsets()
	if err := ing.scanOnce(context.Background(), true); err != nil {
		t.Fatalf("scanOnce: %v", err)
	}
	if n := countEvents(t, st); n != 0 {
		t.Fatalf("TailFromEnd should skip existing backlog: got %d events, want 0", n)
	}
}
