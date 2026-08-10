package ui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rivo/tview"
)

// A form modal must be tall enough for the buttons that dismiss it.
//
// tview draws the first field a row below the top of the inner rect and will
// not draw the buttons at all unless a row remains beneath them, so a form
// sized to the sum of its fields opens with no Save and no Cancel — a dialog
// that cannot be completed or cancelled.
func TestAFormModalKeepsItsButtons(t *testing.T) {
	for _, tc := range []struct {
		fields int
		area   bool
	}{{1, false}, {2, false}, {4, false}, {1, true}, {3, true}} {
		form := tview.NewForm()
		form.SetBorder(true).SetTitle(" probe ")
		for i := 0; i < tc.fields; i++ {
			form.AddInputField(fmt.Sprintf("Field %d", i), "", 20, nil, nil)
		}
		if tc.area {
			form.AddTextArea("Description", "", 30, 3, 0, nil)
		}
		form.AddButton("Save", nil)
		form.AddButton("Cancel", nil)

		out := strings.Join(renderPrimitive(t, form, 64, formHeight(form)), "\n")
		for _, want := range []string{"Save", "Cancel"} {
			if !strings.Contains(out, want) {
				t.Errorf("a form of %d fields (textarea=%v) at height %d has no %s:\n%s",
					tc.fields, tc.area, formHeight(form), want, out)
			}
		}
		// And the last field is on screen, not pushed off the bottom.
		last := fmt.Sprintf("Field %d", tc.fields-1)
		if !strings.Contains(out, last) {
			t.Errorf("a form of %d fields at height %d clips %q:\n%s",
				tc.fields, formHeight(form), last, out)
		}
	}
}

// Every dialog leaves the screen it interrupted visible.
//
// They each rooted themselves, so opening one replaced the screen: the queue a
// status was being set on, the events a case was being filed from, and the
// message's own context all vanished behind it.
func TestDialogsLeaveTheScreenVisible(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	renderPrimitive(t, ui.eventList, 150, 20)
	ui.updateFindingsList(len(ui.findings))
	ui.eventList.Select(1, 0)
	settleInspector(ui)

	for _, tc := range []struct {
		name  string
		open  func()
		title string
	}{
		{"status", ui.showFindingStatusModal, "Set Status"},
		{"verdict", ui.showFindingVerdictModal, "Verdict"},
		{"palette", ui.showCommandPalette, "COMMAND PALETTE"},
		{"message", func() { ui.showModal("Notice", "Something happened.") }, "Something happened"},
	} {
		tc.open()
		if ui.activeModal == nil {
			t.Fatalf("%s did not open", tc.name)
		}
		if _, overlaid := ui.activeModal.(*tview.Pages); !overlaid {
			t.Errorf("%s roots itself instead of overlaying the screen", tc.name)
		}
		frame := strings.Join(renderPrimitive(t, ui.activeModal, 150, 34), "\n")

		if !strings.Contains(frame, tc.title) {
			t.Errorf("%s is not on screen:\n%s", tc.name, frame)
		}
		for _, behind := range []string{"NAVIGATION", "FINDINGS"} {
			if !strings.Contains(frame, behind) {
				t.Errorf("%s hides the screen behind it — no %s:\n%s", tc.name, behind, frame)
			}
		}
		ui.closeModal()
	}
}

// The help screen is deliberately not one of them: it is a reference to read,
// not a dialog about what is on screen, and it is wider than the space a modal
// would leave.
func TestHelpIsAPageNotADialog(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)

	ui.showHelp()
	if ui.activeModal == nil {
		t.Fatal("help did not open")
	}
	// By type rather than by what is on screen: the key reference lists the
	// navigation keys, so every word naming the screen behind also appears in
	// the help itself.
	if _, overlaid := ui.activeModal.(*tview.Pages); overlaid {
		t.Error("help now overlays the screen; if that is intended, this test is what to update")
	}
}

// settleInspector cancels the pending repaints the inspectors have scheduled.
//
// Both debounces fire on their own goroutine, and in tests queueUpdate runs its
// function inline there rather than posting it to an event loop — so a repaint
// can land in the middle of a render that production would have serialised.
func settleInspector(ui *UI) {
	ui.findingInspect.mu.Lock()
	if ui.findingInspect.timer != nil {
		ui.findingInspect.timer.Stop()
		ui.findingInspect.timer = nil
	}
	ui.findingInspect.mu.Unlock()

	if ui.indicators != nil {
		ui.indicators.context.mu.Lock()
		if ui.indicators.context.timer != nil {
			ui.indicators.context.timer.Stop()
			ui.indicators.context.timer = nil
		}
		ui.indicators.context.mu.Unlock()
	}
}
