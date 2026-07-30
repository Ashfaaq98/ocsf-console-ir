package ui

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

func testEvent(t *testing.T, st *store.Store, ctx context.Context, message string) string {
	t.Helper()
	id, err := st.SaveEvent(ctx, &ocsf.Event{
		Time:        time.Now(),
		ClassUID:    4001,
		CategoryUID: 4,
		ActivityID:  1,
		TypeUID:     400101,
		SeverityID:  2,
		Message:     message,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestDetailPaneShowsEnrichmentAfterItArrives is the acceptance test for the
// stale-detail-pane bug: open an event before its lookups finish and the
// enrichment must appear, rather than the pane showing what was true when it was
// opened until the analyst presses 'r'.
func TestDetailPaneShowsEnrichmentAfterItArrives(t *testing.T) {
	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	eventID := testEvent(t, st, ctx, "beacon to 8.8.8.8")

	// A non-nil provider keeps NewUI from loading the user's real LLM settings.
	ui := NewUI(ctx, st, llm.NewLocalStub(), log.New(io.Discard, "", 0), "test")
	ui.events = []store.Event{{ID: eventID, DstIP: "8.8.8.8", Message: "beacon to 8.8.8.8"}}
	ui.selectedEventID = eventID

	// Open the event before any enrichment exists.
	ui.showEventDetails()
	before := ui.eventDetail.GetText(true)
	if strings.Contains(before, "Mountain View") {
		t.Fatal("fixture is wrong: the enrichment is already present")
	}

	// NewUI must have subscribed; this is the wiring the whole feature rests on.
	if err := st.ApplyEnrichment(ctx, eventID, store.Enrichment{
		Source: "geoip",
		Type:   "geoip",
		Data: map[string]string{
			"geoip_8_8_8_8_city":    "Mountain View",
			"geoip_8_8_8_8_country": "United States",
		},
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-ui.enrichNotify:
		if got != eventID {
			t.Fatalf("UI queued a redraw for %q, want %q", got, eventID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("NewUI did not subscribe to enrichment: no redraw was queued for the open event")
	}

	// That queued redraw calls showEventDetails.
	ui.showEventDetails()
	after := ui.eventDetail.GetText(true)

	if !strings.Contains(after, "Mountain View") {
		t.Fatalf("enrichment did not appear:\n%s", after)
	}
	if after == before {
		t.Fatal("the pane text did not change")
	}
}

// The same pane must render the grouped card, not the flat key list it replaced.
func TestDetailPaneRendersGroupedEnrichment(t *testing.T) {
	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	eventID := testEvent(t, st, ctx, "traffic to 8.8.8.8")
	if err := st.ApplyEnrichment(ctx, eventID, store.Enrichment{
		Source: "geoip",
		Type:   "geoip",
		Data: map[string]string{
			"geoip_8_8_8_8_city":         "Mountain View",
			"geoip_8_8_8_8_country":      "United States",
			"geoip_8_8_8_8_country_code": "US",
		},
	}); err != nil {
		t.Fatal(err)
	}

	ui := NewUI(ctx, st, llm.NewLocalStub(), log.New(io.Discard, "", 0), "test")
	ui.events = []store.Event{{ID: eventID, DstIP: "8.8.8.8"}}
	ui.selectedEventID = eventID
	ui.showEventDetails()

	got := ui.eventDetail.GetText(true)

	// One heading naming the indicator...
	if !strings.Contains(got, "8.8.8.8") {
		t.Errorf("no indicator heading:\n%s", got)
	}
	// ...and no raw keys repeating it on every line.
	for _, raw := range []string{"geoip_8_8_8_8_city", "geoip_8_8_8_8_country"} {
		if strings.Contains(got, raw) {
			t.Errorf("still rendering the flat key %q:\n%s", raw, got)
		}
	}
	// Field names survive the split, including one containing an underscore.
	for _, field := range []string{"city", "country", "country_code"} {
		if !strings.Contains(got, field) {
			t.Errorf("missing field %q:\n%s", field, got)
		}
	}
}

// Selecting a different event must retarget the refresh, or a redraw would fire
// for an event that is no longer on screen.
func TestOpenEventIDTracksTheSelection(t *testing.T) {
	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	first := testEvent(t, st, ctx, "first")
	second := testEvent(t, st, ctx, "second")

	ui := NewUI(ctx, st, llm.NewLocalStub(), log.New(io.Discard, "", 0), "test")
	ui.events = []store.Event{{ID: first}, {ID: second}}

	ui.selectedEventID = first
	ui.showEventDetails()
	if got, _ := ui.openEventID.Load().(string); got != first {
		t.Fatalf("openEventID = %q, want %q", got, first)
	}

	ui.selectedEventID = second
	ui.showEventDetails()
	if got, _ := ui.openEventID.Load().(string); got != second {
		t.Fatalf("openEventID = %q after moving the selection, want %q", got, second)
	}

	// An arrival for the event that is no longer open must be ignored.
	drain(ui.enrichNotify)
	ui.enrichmentApplied(first)
	select {
	case got := <-ui.enrichNotify:
		t.Errorf("queued a redraw for %q, which is no longer open", got)
	default:
	}
}

func drain(ch chan string) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}
