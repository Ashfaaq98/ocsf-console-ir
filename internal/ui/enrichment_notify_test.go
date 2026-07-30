package ui

import (
	"testing"
	"time"
)

func timeoutAfterShortWhile() <-chan time.Time { return time.After(2 * time.Second) }

// newNotifyUI builds just enough of a UI to exercise the notifier, which touches
// only openEventID and enrichNotify — no tview application required.
func newNotifyUI(open string) *UI {
	ui := &UI{enrichNotify: make(chan string, 2)}
	ui.openEventID.Store(open)
	return ui
}

func TestEnrichmentAppliedQueuesTheOpenEvent(t *testing.T) {
	ui := newNotifyUI("evt_1")
	ui.enrichmentApplied("evt_1")

	select {
	case got := <-ui.enrichNotify:
		if got != "evt_1" {
			t.Errorf("queued %q, want evt_1", got)
		}
	default:
		t.Fatal("the open event's enrichment was not queued for redraw")
	}
}

// Enrichment fires for every event mid-ingest. Queueing a redraw for events the
// analyst is not looking at would be a redraw storm.
func TestEnrichmentAppliedIgnoresOtherEvents(t *testing.T) {
	ui := newNotifyUI("evt_1")
	ui.enrichmentApplied("evt_2")

	select {
	case got := <-ui.enrichNotify:
		t.Errorf("queued %q for an event that is not open", got)
	default:
	}
}

func TestEnrichmentAppliedIgnoresArrivalsWithNothingOpen(t *testing.T) {
	ui := newNotifyUI("")
	ui.enrichmentApplied("evt_1")

	select {
	case got := <-ui.enrichNotify:
		t.Errorf("queued %q with no event open", got)
	default:
	}
}

// The callback runs on an enrichment worker's goroutine, so a full queue must
// drop rather than block — a stalled worker would stall ingestion.
func TestEnrichmentAppliedNeverBlocksWhenTheQueueIsFull(t *testing.T) {
	ui := newNotifyUI("evt_1")

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Two more than the buffer holds.
		for i := 0; i < cap(ui.enrichNotify)+2; i++ {
			ui.enrichmentApplied("evt_1")
		}
	}()

	select {
	case <-done:
	case <-timeoutAfterShortWhile():
		t.Fatal("enrichmentApplied blocked on a full queue")
	}

	if got := len(ui.enrichNotify); got != cap(ui.enrichNotify) {
		t.Errorf("queue holds %d, want it capped at %d", got, cap(ui.enrichNotify))
	}
}
