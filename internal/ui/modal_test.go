package ui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// A modal built from a List must suppress the global keys.
//
// isDialogActive used to type-switch on what had focus, and a *tview.List is
// not in that switch — so every global key reached through the pivot menu: q
// quit the application, the digits navigated away, j and k moved the table
// behind it. Adding List to the switch would be wrong, because the case
// sidebar is a List and must not suppress anything.
func TestAListModalSuppressesGlobalKeys(t *testing.T) {
	ui, _ := newTestUI(t)

	if ui.isDialogActive() {
		t.Fatal("a dialog is reported active with nothing rooted")
	}

	list := tview.NewList()
	ui.rootModal(list)

	if !ui.isDialogActive() {
		t.Error("a rooted List modal does not suppress the global keys")
	}
	// The global handler passes everything through while one is up.
	ev := tcell.NewEventKey(tcell.KeyRune, 'q', tcell.ModNone)
	if ui.globalInputCapture(ev) != ev {
		t.Error("q was claimed by the global handler with a modal on screen")
	}

	ui.restoreMainLayout()
	if ui.isDialogActive() {
		t.Error("the modal is still reported active after the layout was restored")
	}
}

// The case sidebar is a List too, and must not suppress anything.
func TestTheSidebarIsNotAModal(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.app.SetFocus(ui.sidebar)

	if ui.isDialogActive() {
		t.Error("focusing the case list suppressed the global keys")
	}
}

// Closing a modal goes through restoreMainLayout, which rebuilds the whole root.
//
// closeModal did SetRoot(ui.layout), and the status bar lives in the flex above
// it — so cancelling the pivot menu left the application without one for the
// rest of the session. tview offers no way to read back the root, so this
// asserts the side effects only restoreMainLayout produces.
func TestClosingAModalRestoresTheWholeLayout(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.helpActive = true

	ui.rootModal(tview.NewList())
	ui.closeModal()

	if ui.activeModal != nil {
		t.Error("the modal was not cleared")
	}
	if ui.helpActive {
		t.Error("closeModal did not go through restoreMainLayout")
	}
}

// Leaving a modal says where you are, not what you closed.
//
// restoreMainLayout announced "Help closed" unconditionally — after a pivot
// menu, after a form, and after leaving a case, none of which involved help.
func TestLeavingAModalDoesNotSayHelpClosed(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.destination = destTriage

	ui.rootModal(tview.NewList())
	ui.closeModal()

	got := stripTags(ui.statusBar.GetText(true))
	if strings.Contains(got, "Help closed") {
		t.Errorf("closing a pivot menu announced the help screen: %s", got)
	}
	if !strings.Contains(got, "Triage") {
		t.Errorf("the bar does not say which screen you are on: %s", got)
	}
}

// Closing a modal returns focus to the screen underneath.
//
// Choosing a filter from the Triage chip menu left the arrow keys doing
// nothing: only half the modal call sites recorded ui.lastFocus, and with none
// recorded the restore fell through to the case sidebar — so the arrows were
// moving an off-screen list while the findings queue sat still.
func TestClosingAModalReturnsFocusToTheQueue(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	seedTriageFinding(t, st, "b", "")
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)

	ui.showTriageChips()
	if ui.app.GetFocus() == ui.eventList {
		t.Fatal("the chip menu did not take focus")
	}

	// In the order the menu's own callback runs them: close, then re-query.
	ui.closeModal()
	ui.toggleTriageChip(chipOpen)
	awaitIdle(t, ui)

	if got := ui.app.GetFocus(); got != ui.eventList {
		t.Errorf("focus went to %T after the filter menu closed, want the findings queue", got)
	}

	// And the arrows now reach it.
	before, _ := ui.eventList.GetSelection()
	handler := ui.eventList.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone), func(tview.Primitive) {})
	if after, _ := ui.eventList.GetSelection(); after == before {
		t.Errorf("the queue did not move on Down: still row %d", before)
	}
}

// A modal opened over a modal must not record the outer one as the thing to
// return to — closing both would leave focus on a primitive that is gone.
func TestNestedModalsRestoreTheScreenBeneath(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.destination = destTriage
	ui.app.SetFocus(ui.eventList)

	outer := tview.NewList()
	ui.rootModal(outer)
	ui.app.SetFocus(outer)
	inner := tview.NewList()
	ui.rootModal(inner)

	ui.closeModal()
	if got := ui.app.GetFocus(); got == outer || got == inner {
		t.Errorf("focus was restored to a closed modal (%p)", got)
	}
	if got := ui.app.GetFocus(); got != ui.eventList {
		t.Errorf("focus went to %T, want the findings queue", got)
	}
}
