package ui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// openFilterPanel puts Triage on screen, lays it out, and opens the filter.
func openFilterPanel(t *testing.T, ui *UI) *triageFilterModal {
	t.Helper()
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	renderPrimitive(t, ui.eventList, 150, 20)
	ui.updateFindingsList(len(ui.findings))

	ui.showTriageFilter()
	if ui.filterModal == nil {
		t.Fatal("the filter panel did not open")
	}
	return ui.filterModal
}

// pressInPanel drives a key into the panel's list, capture and all.
func pressInPanel(m *triageFilterModal, ev *tcell.EventKey) {
	m.list.InputHandler()(ev, func(tview.Primitive) {})
}

// The panel does not hide what it filters.
//
// The filter was rooted on a canvas of its own, so opening it replaced the
// screen: the queue it was about to narrow was not visible while it was being
// narrowed, and neither was anything else.
func TestTheFilterPanelLeavesTheScreenVisible(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	openFilterPanel(t, ui)

	frame := strings.Join(renderPrimitive(t, ui.activeModal, 150, 34), "\n")
	for _, want := range []string{
		"Filter findings", // the panel
		"FINDINGS",        // the queue behind it
		"NAVIGATION",      // the rail
		"SELECTED FINDING",
	} {
		if !strings.Contains(frame, want) {
			t.Errorf("%q is not on screen with the filter panel open:\n%s", want, frame)
		}
	}
}

// A filter applies where it is chosen, and the panel stays open.
//
// Choosing a chip used to close the panel, so setting two filters meant opening
// it twice and there was no way to see the two combined before committing.
func TestTheFilterPanelTogglesWithoutClosing(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	m := openFilterPanel(t, ui)

	state := ui.triageFilterState()
	before := state.active[chipHasIOC]

	pressInPanel(m, tcell.NewEventKey(tcell.KeyRune, 'i', tcell.ModNone)) // Has IOC
	awaitIdle(t, ui)

	if state.active[chipHasIOC] == before {
		t.Error("the shortcut did not toggle Has IOC")
	}
	if ui.activeModal == nil || ui.filterModal == nil {
		t.Error("choosing a filter closed the panel")
	}

	// And a second one, in the same visit.
	pressInPanel(m, tcell.NewEventKey(tcell.KeyRune, 't', tcell.ModNone)) // Last 24h
	awaitIdle(t, ui)
	if !state.active[chipLast24h] || !state.active[chipHasIOC] {
		t.Errorf("the two filters did not combine: %v", state.describe())
	}
}

// The saved views are reachable from the panel, in both directions, and the
// cycle passes through "no view" so a narrowed queue is never a dead end.
func TestTheFilterPanelCyclesViews(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	m := openFilterPanel(t, ui)
	state := ui.triageFilterState()

	names := []string{}
	for i := 0; i < len(savedViews())+1; i++ {
		pressInPanel(m, tcell.NewEventKey(tcell.KeyRight, 0, tcell.ModNone))
		awaitIdle(t, ui)
		names = append(names, state.viewName())
	}
	if !containsString(names, "All findings") {
		t.Errorf("cycling forward never reaches every finding: %v", names)
	}

	pressInPanel(m, tcell.NewEventKey(tcell.KeyLeft, 0, tcell.ModNone))
	awaitIdle(t, ui)
	if state.viewName() == "" {
		t.Error("cycling back landed on no view at all")
	}
}

// Left and right belong to the view row alone; elsewhere they are the table's.
func TestArrowsOnlyCycleTheViewRow(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	m := openFilterPanel(t, ui)
	state := ui.triageFilterState()

	m.list.SetCurrentItem(2) // a chip row
	was := state.viewName()
	pressInPanel(m, tcell.NewEventKey(tcell.KeyRight, 0, tcell.ModNone))
	awaitIdle(t, ui)

	if state.viewName() != was {
		t.Errorf("an arrow on a chip row changed the saved view to %q", state.viewName())
	}
}

// Clear means clear, including the search field the panel owns.
func TestTheFilterPanelClearsEverything(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	m := openFilterPanel(t, ui)

	state := ui.triageFilterState()
	state.search = "macro"
	m.input.SetText("macro")
	state.active[chipHasIOC] = true

	pressInPanel(m, tcell.NewEventKey(tcell.KeyRune, 'x', tcell.ModNone))
	awaitIdle(t, ui)

	if state.search != "" || len(state.active) != 0 || state.view != viewNone {
		t.Errorf("clear left filters behind: %q", state.describe())
	}
	if got := m.input.GetText(); got != "" {
		t.Errorf("the search field still reads %q after clearing", got)
	}
}

// The panel says how much of the database is left, since it covers the rows
// that would otherwise answer that.
func TestTheFilterPanelCountsWhatIsLeft(t *testing.T) {
	ui, st := newTestUI(t)
	for i := 0; i < 4; i++ {
		seedTriageFinding(t, st, fmt.Sprintf("f%d", i), "")
	}
	m := openFilterPanel(t, ui)

	if got := stripTags(m.count.GetText(true)); !strings.Contains(got, "4") {
		t.Errorf("the panel does not count the queue: %q", got)
	}

	// A filter that matches nothing is still counted, against the total.
	ui.triageFilterState().search = "nothing matches this"
	ui.spawnLoad(ui.loadFindings)
	awaitIdle(t, ui)

	got := stripTags(m.count.GetText(true))
	if !strings.Contains(got, "0 of 4") {
		t.Errorf("the panel does not say what the filter left: %q", got)
	}
}

// Esc closes it, and the panel is forgotten so a later reload does not paint
// into a widget that is no longer on screen.
func TestEscapeClosesTheFilterPanel(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	m := openFilterPanel(t, ui)

	pressInPanel(m, tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone))

	if ui.filterModal != nil {
		t.Error("the panel was not forgotten on close")
	}
	if ui.activeModal != nil {
		t.Error("the modal is still rooted after Esc")
	}
	if got := ui.app.GetFocus(); got != ui.eventList {
		t.Errorf("focus went to %T after closing the filter, want the queue", got)
	}
}

func containsString(haystack []string, want string) bool {
	for _, h := range haystack {
		if h == want {
			return true
		}
	}
	return false
}
