package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/enrich/geoip"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ingest"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/plugins"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// TestFolderIngestProducesEnrichment mirrors the serve wiring end-to-end:
// folder ingest -> Enricher(pluginManager) -> worker -> geoip.Process ->
// store.ApplyEnrichment. It uses a private IP so the geoip lookup resolves
// locally with no network dependency, making the test hermetic.
func TestFolderIngestProducesEnrichment(t *testing.T) {
	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	ctx := context.Background()

	// Plugin manager with geoip registered, wired exactly as serve does.
	pm := plugins.NewPluginManager(bus.NewNullBus(nil), st, "", nil)
	if err := pm.GetRegistry().RegisterCorePlugin(geoip.New(nil)); err != nil {
		t.Fatalf("RegisterCorePlugin: %v", err)
	}
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer pm.Stop()

	// A single OCSF event with a private source IP.
	dir := t.TempDir()
	line := `{"class_uid":4001,"category_uid":4,"activity_id":1,"type_uid":400101,"severity_id":3,"time":1700000000,"message":"conn","src_endpoint":{"ip":"10.0.0.5"}}`
	if err := os.WriteFile(filepath.Join(dir, "e.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// One-shot folder ingest with the enricher wired in.
	ing := ingest.NewFolderIngestor(ingest.NewParser(), st, bus.NewNullBus(nil), ingest.FolderOptions{
		Dir:      dir,
		Watch:    false,
		Enricher: pm,
	})
	if err := ing.Run(ctx); err != nil {
		t.Fatalf("folder Run: %v", err)
	}

	// Find the ingested event.
	events, err := st.GetAllEvents(ctx, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("expected 1 event, got %d (err=%v)", len(events), err)
	}
	eventID := events[0].ID

	// Enrichment is async; poll for it.
	deadline := time.Now().Add(3 * time.Second)
	for {
		enr, err := st.GetEnrichmentsByEvent(ctx, eventID)
		if err != nil {
			t.Fatalf("GetEnrichmentsByEvent: %v", err)
		}
		if len(enr) > 0 {
			if got := enr[0].Data["geoip_10_0_0_5_country"]; got != "Private Network" {
				t.Fatalf("geoip country = %q, want Private Network", got)
			}
			return // success: enrichment produced and stored
		}
		if time.Now().After(deadline) {
			t.Fatalf("no enrichment applied to event %s within deadline", eventID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
