package ui

import (
	"context"
	"strings"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"

	"github.com/gdamore/tcell/v2"
)

// homeKey sends one key through the same path a real keypress takes: the
// application-wide capture asks the screen first, then falls through.
//
// Driving homeView.handleKey directly would pass even if nothing called it,
// which is exactly the bug this file exists to prevent — the handler sat in the
// tree unreferenced, so every key it claimed to own belonged to something else.
func homeKey(h *homeView, ev *tcell.EventKey) *tcell.EventKey {
	screen := h.ui.screenKeys()
	if screen == nil {
		return ev
	}
	return screen(ev)
}

func rune_(r rune) *tcell.EventKey { return tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone) }

// The dashboard has to be reachable from the router at all.
func TestHomeOwnsItsKeys(t *testing.T) {
	h, _ := newTestHome(t)
	h.ui.destination = destHome
	h.ui.home = h

	if h.ui.screenKeys() == nil {
		t.Fatal("Home is not registered with the key router, so it owns nothing")
	}

	for _, ev := range []*tcell.EventKey{
		rune_('j'), rune_('k'), rune_('r'), rune_('e'), rune_('v'),
		tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone),
		tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone),
	} {
		if got := homeKey(h, ev); got != nil {
			t.Errorf("Home did not claim %v, so a global binding will take it", ev.Name())
		}
	}
}

// Keys Home does not own must pass through, or the digits stop navigating and
// the dashboard becomes a screen you cannot leave.
func TestHomePassesOnGlobalKeys(t *testing.T) {
	h, _ := newTestHome(t)
	h.ui.destination = destHome
	h.ui.home = h

	for _, r := range []rune{'1', '2', '3', '4', '5', ':', '?', 'q'} {
		if got := homeKey(h, rune_(r)); got == nil {
			t.Errorf("Home swallowed %q, which belongs to global navigation", r)
		}
	}
}

// Tab must be claimed and dropped rather than left to cycleFocus, which cycles
// the sidebar, the event list and the event detail — v0.1 widgets that are not
// in Home's tree, so focus lands on something not on screen.
func TestHomeTabDoesNotReachCycleFocus(t *testing.T) {
	h, _ := newTestHome(t)
	h.ui.destination = destHome
	h.ui.home = h

	tab := tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone)
	if got := homeKey(h, tab); got != nil {
		t.Error("Tab reached the global handler, which would focus a widget Home does not contain")
	}
}

// j and k move the queue. Globally they are move-selection for the events list,
// which is why the dashboard's own cursor never responded to them.
func TestHomeJKMoveTheQueue(t *testing.T) {
	h, st := newTestHome(t)
	h.ui.destination = destHome
	h.ui.home = h
	for i, uid := range []string{"a", "b", "c"} {
		seedTestFinding(t, st, uid, 90-i*10, 1, 1)
	}
	h.loadAndRender(t)
	h.queue.Select(0, 0)

	homeKey(h, rune_('j'))
	if row, _ := h.queue.GetSelection(); row != 1 {
		t.Errorf("j left the cursor on row %d, want 1", row)
	}
	homeKey(h, rune_('k'))
	if row, _ := h.queue.GetSelection(); row != 0 {
		t.Errorf("k left the cursor on row %d, want 0", row)
	}
}

// The selected finding is whatever the showing screen has under its cursor.
// Escalation and verdicts both go through currentFinding, and it used to read
// Triage's table unconditionally — so e on the dashboard found nothing.
func TestCurrentFindingFollowsTheScreen(t *testing.T) {
	h, st := newTestHome(t)
	h.ui.destination = destHome
	h.ui.home = h
	seedTestFinding(t, st, "top", 95, 1, 1)
	h.loadAndRender(t)
	h.queue.Select(0, 0)

	f, ok := h.ui.currentFinding()
	if !ok {
		t.Fatal("no finding is selected on Home, so escalation and verdicts cannot act")
	}
	if f.FindingUID != "top" {
		t.Errorf("currentFinding returned %q, want the one under Home's cursor", f.FindingUID)
	}
}

// Enter carries the selection into Triage. Without it, opening a finding from a
// dashboard of five lands on the first of a hundred and loses the one thing the
// analyst was looking at.
func TestHomeEnterCarriesTheSelection(t *testing.T) {
	h, st := newTestHome(t)
	h.ui.destination = destHome
	h.ui.home = h
	for i, uid := range []string{"a", "b", "c"} {
		seedTestFinding(t, st, uid, 90-i*10, 1, 1)
	}
	h.loadAndRender(t)
	h.queue.Select(1, 0)

	want := h.selectedFinding()
	if want == nil {
		t.Fatal("nothing selected")
	}

	h.openSelected()
	awaitIdle(t, h.ui)

	// The outcome, not the handoff. pendingFindingID is written here and
	// consumed by the load; reading it back races the very goroutine that is
	// supposed to act on it, and what matters is where the cursor ends up.
	row, _ := h.ui.eventList.GetSelection()
	if row < 1 || row-1 >= len(h.ui.findings) {
		t.Fatalf("Triage selected row %d with %d findings loaded", row, len(h.ui.findings))
	}
	if got := h.ui.findings[row-1].ID; got != want.ID {
		t.Errorf("Triage opened on %q, want the finding Home had selected (%q)", got, want.ID)
	}
}

// ... and the Triage list honours it rather than snapping to the top.
func TestTriageSelectsTheCarriedFinding(t *testing.T) {
	h, st := newTestHome(t)
	for i, uid := range []string{"a", "b", "c"} {
		seedTestFinding(t, st, uid, 90-i*10, 1, 1)
	}
	found, err := st.GetFindings(context.Background(), store.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	h.ui.findings = found
	h.ui.showFindings = true
	h.ui.pendingFindingID = found[2].ID

	h.ui.updateFindingsList(len(found))

	row, _ := h.ui.eventList.GetSelection()
	if row != 3 {
		t.Errorf("Triage selected row %d, want row 3 — the finding Home asked for", row)
	}
	if h.ui.pendingFindingID != "" {
		t.Error("the carried selection was not cleared after being honoured")
	}
}

// The dashboard does not answer for keys that belong to the events flow.
//
// c, a and d act on marked events. Handled globally, they answered on screens
// with no events to mark: pressing a on Home replied "No events selected. Use
// Space to select events first", naming a key that does nothing there either.
func TestHomeDoesNotAnswerTheEventsKeys(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	ui.enterScreen(destHome)
	awaitIdle(t, ui)

	for _, key := range []rune{'a', 'c'} {
		ui.setStatusDirect("[white]Analyst Home[-:-:-]")
		ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, key, tcell.ModNone))
		awaitIdle(t, ui)

		got := stripTags(ui.statusBar.GetText(true))
		if strings.Contains(got, "No events selected") {
			t.Errorf("%c on Home answered with the events selection: %s", key, got)
		}
		if ui.activeModal != nil {
			t.Errorf("%c on Home opened a dialog", key)
			ui.closeModal()
		}
	}
}

// On Events the same keys do answer, because there is a selection to make.
func TestEventsStillAnswerTheirOwnKeys(t *testing.T) {
	ui, _ := newTestUI(t)
	seedEvents(t, ui, 3)
	ui.enterScreen(destEvents)
	awaitIdle(t, ui)

	ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, 'c', tcell.ModNone))
	got := stripTags(ui.statusBar.GetText(true))
	if !strings.Contains(got, "Space marks the row") {
		t.Errorf("c on Events with nothing marked says: %s", got)
	}
}

// f on Events opens the events filter, and the bar says so.
func TestEventsAdvertiseTheirFilter(t *testing.T) {
	ui, _ := newTestUI(t)
	seedEvents(t, ui, 3)
	ui.enterScreen(destEvents)
	awaitIdle(t, ui)

	if bar := stripTags(ui.statusBar.GetText(true)); !strings.Contains(bar, "f filter") {
		t.Errorf("the Events bar does not offer the filter: %s", bar)
	}
	if ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, 'f', tcell.ModNone)) != nil {
		t.Fatal("f was not claimed on Events")
	}
	if ui.activeModal == nil {
		t.Error("f on Events opened nothing")
	}
}
