package ui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// pickerList is the theme picker's list.
func pickerList(t *testing.T, ui *UI) *tview.List {
	t.Helper()
	pages, ok := ui.activeModal.(*tview.Pages)
	if !ok {
		t.Fatalf("the picker is not an overlay: %T", ui.activeModal)
	}
	var found *tview.List
	_ = pages
	// The list is the panel's body; reach it through the focus the picker set.
	if l, ok := ui.app.GetFocus().(*tview.List); ok {
		found = l
	}
	if found == nil {
		t.Fatal("the picker did not focus its list")
	}
	return found
}

// t opens a list rather than cycling blindly.
//
// It cycled alphabetically through six themes, and light and high-contrast sit
// between gruvbox and midnight — so a couple of presses while exploring left
// the application on a palette nobody chose, saved it, and every session after
// that opened on it with nothing on screen to say why.
func TestTheThemeKeyOpensAPicker(t *testing.T) {
	ui, _ := newTestUI(t)
	// Not Home: its clock and refresh ticker repaint from their own goroutine,
	// and in tests queueUpdate runs inline there — so a theme applied from this
	// goroutine races a repaint that production would have serialised through
	// the event loop.
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	was := ui.themeName

	if ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, 't', tcell.ModNone)) != nil {
		t.Fatal("t was not claimed")
	}
	if ui.activeModal == nil {
		t.Fatal("t opened nothing")
	}
	if ui.themeName != was {
		t.Errorf("opening the picker changed the theme to %q", ui.themeName)
	}

	frame := strings.Join(renderPrimitive(t, ui.activeModal, 150, 34), "\n")
	for _, name := range themeNames() {
		if !strings.Contains(frame, name) {
			t.Errorf("the picker does not list %q:\n%s", name, frame)
		}
	}
	if !strings.Contains(frame, "in use") {
		t.Errorf("the picker does not mark the theme in force:\n%s", frame)
	}
}

// Moving the cursor previews.
func TestThePickerPreviewsAsYouMove(t *testing.T) {
	ui, _ := newTestUI(t)
	// Not Home: its clock and refresh ticker repaint from their own goroutine,
	// and in tests queueUpdate runs inline there — so a theme applied from this
	// goroutine races a repaint that production would have serialised through
	// the event loop.
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)

	ui.showThemePicker()
	list := pickerList(t, ui)

	names := themeNames()
	want := names[(indexOfTheme(names, ui.themeName)+1)%len(names)]
	list.SetCurrentItem(indexOfTheme(names, want))

	if ui.themeName != want {
		t.Errorf("moving to %q left the theme at %q", want, ui.themeName)
	}
	if ui.theme.Canvas != themeBuilders[want]().Canvas && ui.hasTrueColor {
		t.Errorf("the preview did not apply %q's colours", want)
	}
}

// Esc puts back what you came in with, and saves it — a preview must not stick.
func TestCancellingThePickerRestoresTheTheme(t *testing.T) {
	ui, _ := newTestUI(t)
	// Not Home: its clock and refresh ticker repaint from their own goroutine,
	// and in tests queueUpdate runs inline there — so a theme applied from this
	// goroutine races a repaint that production would have serialised through
	// the event loop.
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	was := ui.themeName

	ui.showThemePicker()
	list := pickerList(t, ui)
	names := themeNames()
	list.SetCurrentItem(indexOfTheme(names, "light"))
	if ui.themeName != "light" {
		t.Fatalf("the preview did not apply: %q", ui.themeName)
	}

	list.InputHandler()(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone), func(tview.Primitive) {})

	if ui.themeName != was {
		t.Errorf("cancelling left the theme on %q, want %q back", ui.themeName, was)
	}
	if got := loadThemeName(); got != was {
		t.Errorf("cancelling saved %q, want %q", got, was)
	}
	if ui.activeModal != nil {
		t.Error("Esc did not close the picker")
	}
}

// Enter keeps the previewed theme, and a restart would load it.
func TestChoosingAThemeKeepsIt(t *testing.T) {
	ui, _ := newTestUI(t)
	// Not Home: its clock and refresh ticker repaint from their own goroutine,
	// and in tests queueUpdate runs inline there — so a theme applied from this
	// goroutine races a repaint that production would have serialised through
	// the event loop.
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)

	ui.showThemePicker()
	list := pickerList(t, ui)
	list.SetCurrentItem(indexOfTheme(themeNames(), "midnight"))
	list.InputHandler()(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), func(tview.Primitive) {})

	if ui.themeName != "midnight" {
		t.Errorf("choosing left the theme on %q", ui.themeName)
	}
	if got := loadThemeName(); got != "midnight" {
		t.Errorf("a restart would load %q, want midnight", got)
	}
	if ui.activeModal != nil {
		t.Error("Enter did not close the picker")
	}
}

func indexOfTheme(names []string, want string) int {
	for i, n := range names {
		if n == want {
			return i
		}
	}
	return 0
}
