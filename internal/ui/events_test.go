package ui

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
)

func seedEvents(t *testing.T, ui *UI, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		ev := &ocsf.Event{
			Time:     time.Now().Add(-time.Duration(i*11) * time.Minute),
			ClassUID: 4001, ActivityID: 1, TypeUID: 400101,
			SeverityID: (i % 5) + 1,
			Message:    fmt.Sprintf("Outbound to 198.51.100.%d", i),
			Device:     &ocsf.Device{Hostname: fmt.Sprintf("ws-%02d", i%3)},
		}
		ev.Metadata.UID = fmt.Sprintf("e%02d", i)
		if _, err := ui.store.SaveEvent(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
}

// Events opens on an event, not on a cluster header.
//
// It selected row 1, and row 1 is always a header — so eventForRow returned
// nil, showEventDetails never fired, and the screen opened with whatever the
// previous one had left in the detail pane.
func TestEventsOpensOnAnEvent(t *testing.T) {
	ui, _ := newTestUI(t)
	seedEvents(t, ui, 9)

	ui.enterScreen(destEvents)
	awaitIdle(t, ui)

	row, _ := ui.eventList.GetSelection()
	if ui.eventForRow(row) == nil {
		t.Fatalf("the cursor is on row %d, which is not an event", row)
	}
	if got := ui.eventDetail.GetText(true); strings.TrimSpace(got) == "" {
		t.Error("the detail pane is empty on a screen that opened with events")
	}
}

// Triage and Events no longer cancel each other's loads.
//
// One flag guarded both, so entering Triage and then Events in quick succession
// made the events load return immediately while the findings load went on to
// repaint the shared table — leaving the Events screen filled with findings.
func TestTriageAndEventsLoadIndependently(t *testing.T) {
	ui, st := newTestUI(t)
	seedEvents(t, ui, 4)
	seedTriageFinding(t, st, "a", "")

	// A findings load in flight must not block an events load.
	if !ui.findingsLoad.begin() {
		t.Fatal("the findings guard was already held")
	}
	if !ui.eventsLoad.begin() {
		t.Error("an events load was blocked by a findings load")
	}
	ui.eventsLoad.end()
	ui.findingsLoad.end()

	// And two loads of the same collection still exclude one another.
	if !ui.eventsLoad.begin() {
		t.Fatal("the events guard was already held")
	}
	if ui.eventsLoad.begin() {
		t.Error("two events loads ran at once")
	}
	ui.eventsLoad.end()
}

// A guard whose holder has vanished is reclaimed rather than wedging the screen.
func TestLoadGuardReclaimsAStuckHolder(t *testing.T) {
	var g loadGuard

	if g.reclaimIfStuck() {
		t.Error("an idle guard reported itself stuck")
	}

	g.begin()
	if g.reclaimIfStuck() {
		t.Error("a load that just started was reclaimed")
	}

	// Backdate it past the watchdog.
	g.startedAt = time.Now().Add(-loadWatchdog - time.Second).UnixNano()
	if !g.reclaimIfStuck() {
		t.Error("a load older than the watchdog was not reclaimed")
	}
	if g.busyNow() {
		t.Error("the guard is still held after being reclaimed")
	}
}

// z and Enter belong to the Events screen; p must not be live on Triage.
func TestEventsOwnsItsKeys(t *testing.T) {
	ui, _ := newTestUI(t)
	seedEvents(t, ui, 6)
	ui.enterScreen(destEvents)
	awaitIdle(t, ui)

	if len(ui.eventClusters) == 0 {
		t.Fatal("nothing was clustered; the fixture proves nothing")
	}
	before := ui.eventGroup
	if ui.eventsKeys(rune_('z')) != nil {
		t.Error("Events did not claim z")
	}
	if ui.eventGroup == before {
		t.Error("z did not cycle the grouping")
	}
}

// p opened a pivot menu on Triage, mapping a findings row through a stale
// row-to-event map, because the global handler had no screen guard.
func TestPivotIsNotLiveOnTriage(t *testing.T) {
	ui, st := newTestUI(t)
	seedEvents(t, ui, 4)
	seedTriageFinding(t, st, "a", "")

	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	ui.eventList.Select(1, 0)

	// Through the real router, as a keypress would arrive.
	if h := ui.screenKeys(); h != nil {
		h(rune_('p'))
	}
	ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, 'p', tcell.ModNone))

	if ui.activeModal != nil {
		t.Error("p opened a pivot menu on the findings queue")
	}
}

// Moving down the case list changes the briefing beside it.
//
// The list had no changed-handler at all, so the briefing was pinned to the
// first case. Its only swap path was a digit typed into the list — and the
// global capture claims 1 to 5 for navigation, so it worked from the sixth case
// onwards and was discoverable by nobody.
func TestArrowingTheCaseListSwapsTheBriefing(t *testing.T) {
	ui, st := newTestUI(t)
	ctx := context.Background()
	for i, title := range []string{"Phishing-led intrusion", "Account compromise", "Cryptominer"} {
		if _, err := st.CreateOrUpdateCase(ctx, store.Case{
			ID: fmt.Sprintf("c%d", i), Title: title, Status: "OPEN",
			CreatedAt: time.Now().Add(-time.Duration(i) * time.Hour), UpdatedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := ui.refreshCases(); err != nil {
		t.Fatal(err)
	}

	ui.enterScreen(destCases)
	awaitIdle(t, ui)
	first := ui.selectedCaseID
	if first == "" {
		t.Fatal("entering Cases selected no case")
	}

	ui.sidebar.SetCurrentItem(1)

	if ui.selectedCaseID == first {
		t.Errorf("moving down the list left the briefing on %q", first)
	}
	if ui.selectedCaseID != ui.cases[1].ID {
		t.Errorf("the briefing shows %q, want the case under the cursor (%q)",
			ui.selectedCaseID, ui.cases[1].ID)
	}
}

// Clearing the list must not be mistaken for a selection: tview fires the
// changed handler with -1, and updateCasesList clears before it repopulates.
func TestClearingTheCaseListIsNotASelection(t *testing.T) {
	ui, st := newTestUI(t)
	if _, err := st.CreateOrUpdateCase(context.Background(), store.Case{
		ID: "c1", Title: "A case", Status: "OPEN", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := ui.refreshCases(); err != nil {
		t.Fatal(err)
	}
	ui.enterScreen(destCases)
	awaitIdle(t, ui)

	// Must not panic or select out of range.
	ui.sidebar.Clear()
	ui.updateCasesList()
}
