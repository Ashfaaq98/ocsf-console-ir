package ingest

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// recordingEnricher captures EnqueueEvent calls for assertions.
type recordingEnricher struct {
	mu     sync.Mutex
	events []bus.EventMessage
}

func (r *recordingEnricher) EnqueueEvent(e bus.EventMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// TestFolderIngestorInvokesEnricher proves the ingest->enricher link: a
// one-shot folder ingest of a single OCSF event hands that event to the
// configured Enricher with its stored EventID and raw JSON.
func TestFolderIngestorInvokesEnricher(t *testing.T) {
	dir := t.TempDir()
	line := `{"class_uid":4001,"category_uid":4,"activity_id":1,"type_uid":400101,"severity_id":3,"time":1700000000,"message":"conn","url":"http://example.com/path"}`
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	rec := &recordingEnricher{}
	ing := NewFolderIngestor(NewParser(), st, bus.NewNullBus(nil), FolderOptions{
		Dir:      dir,
		Watch:    false,
		Enricher: rec,
	})
	if err := ing.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.events) != 1 {
		t.Fatalf("expected 1 enqueued event, got %d", len(rec.events))
	}
	if rec.events[0].EventID == "" {
		t.Errorf("enqueued event has empty EventID")
	}
	if rec.events[0].RawJSON == "" {
		t.Errorf("enqueued event has empty RawJSON")
	}
}
