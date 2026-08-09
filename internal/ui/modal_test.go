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
