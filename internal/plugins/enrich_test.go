package plugins

import (
	"context"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// stubEnricher is a minimal CorePlugin that returns one canned enrichment,
// letting us exercise the in-process enrichment path without any network I/O.
type stubEnricher struct{}

func (stubEnricher) Name() string                      { return "stub" }
func (stubEnricher) Description() string               { return "test stub" }
func (stubEnricher) Version() string                   { return "0.0.0" }
func (stubEnricher) Start(context.Context) error       { return nil }
func (stubEnricher) Stop() error                       { return nil }
func (stubEnricher) HealthCheck(context.Context) error { return nil }
func (stubEnricher) GetConfig() PluginConfig           { return PluginConfig{} }

func (stubEnricher) Process(_ context.Context, event bus.EventMessage) ([]store.Enrichment, error) {
	return []store.Enrichment{{
		Source: "stub",
		Type:   "test",
		Data:   map[string]string{"event": event.EventID},
	}}, nil
}

// TestEnqueueEventAppliesEnrichment verifies the full in-process wire:
// EnqueueEvent -> worker -> ProcessEvent -> store.ApplyEnrichment.
func TestEnqueueEventAppliesEnrichment(t *testing.T) {
	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	ctx := context.Background()

	// A real event must exist first: enrichments carry a foreign key to events.
	eventID, err := st.SaveEvent(ctx, &ocsf.Event{
		Time:        time.Now(),
		ClassUID:    4001,
		CategoryUID: 4,
		ActivityID:  1,
		TypeUID:     400101,
		SeverityID:  3,
		Message:     "test",
	})
	if err != nil {
		t.Fatalf("SaveEvent: %v", err)
	}

	pm := NewPluginManager(bus.NewNullBus(nil), st, "", nil)
	if err := pm.GetRegistry().RegisterCorePlugin(stubEnricher{}); err != nil {
		t.Fatalf("RegisterCorePlugin: %v", err)
	}
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer pm.Stop()

	pm.EnqueueEvent(bus.EventMessage{EventID: eventID, RawJSON: "{}"})

	// Poll for the enrichment to be applied asynchronously.
	deadline := time.Now().Add(2 * time.Second)
	for {
		enrichments, err := st.GetEnrichmentsByEvent(ctx, eventID)
		if err != nil {
			t.Fatalf("GetEnrichmentsByEvent: %v", err)
		}
		if len(enrichments) == 1 && enrichments[0].Source == "stub" {
			return // success
		}
		if time.Now().After(deadline) {
			t.Fatalf("enrichment not applied within deadline; got %d enrichments", len(enrichments))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
