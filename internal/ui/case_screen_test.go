package ui

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
)

func openCase(t *testing.T, ui *UI) *CaseManagement {
	t.Helper()
	c := store.Case{ID: "c1", Title: "Suspected account compromise — m.chen",
		Severity: "high", Status: "open"}
	cm := NewCaseManagement(ui, c)
	ui.activeCM = cm
	t.Cleanup(func() { ui.activeCM = nil })
	// The case reads itself on construction, and that read paints the header
	// and every tab. Rendering before it lands is two goroutines on the same
	// widgets — serialised by the event loop in a real session, not here.
	awaitIdle(t, ui)
	return cm
}

// The tabs are on screen the moment a case opens.
//
// The strip picks between its full form and a compact one by width, and it
// asked the widget — which reports a default of 15 before it has ever been
// drawn. Every case therefore opened compact, on a screen with room for the
// whole strip, and corrected itself only when something re-rendered the bar.
// Which is why the tabs appeared the first time you pressed Tab.
func TestTheTabsAreVisibleWhenACaseOpens(t *testing.T) {
	ui, _ := newTestUI(t)
	cm := openCase(t, ui)

	frame := strings.Join(renderPrimitive(t, cm.layout, 190, 30), "\n")
	for _, name := range caseTabNames {
		if !strings.Contains(frame, name) {
			t.Errorf("tab %q is not on screen when the case opens:\n%s", name, frame)
		}
	}
}

// A screen too narrow for the strip says where you are instead of truncating.
func TestANarrowCaseScreenSaysWhereYouAre(t *testing.T) {
	ui, _ := newTestUI(t)
	cm := openCase(t, ui)

	// Wide first, so the compact form is a decision rather than a starting
	// state — this is the resize the old code could not follow either.
	renderPrimitive(t, cm.layout, 190, 30)
	frame := strings.Join(renderPrimitive(t, cm.layout, 90, 30), "\n")

	if !strings.Contains(frame, "1/7") {
		t.Errorf("a narrow case screen does not say which tab is showing:\n%s", frame)
	}
	if strings.Contains(frame, "Activity") {
		t.Errorf("a 90-column screen drew the full strip and truncated it:\n%s", frame)
	}
}

// Nothing on the case screen paints tview's default.
//
// A widget with no background falls back to a global black, so three quarters
// of this screen painted black while every other screen painted the theme's
// own background.
func TestTheCaseScreenPaintsTheTheme(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.hasTrueColor = true
	ui.setTheme("gruvbox")
	cm := openCase(t, ui)

	for i, name := range caseTabNames {
		cm.activeTab = i
		cm.tabsPages.SwitchToPage(name)

		screen := tcell.NewSimulationScreen("UTF-8")
		if err := screen.Init(); err != nil {
			t.Fatal(err)
		}
		screen.SetSize(140, 30)
		cm.layout.SetRect(0, 0, 140, 30)
		cm.layout.Draw(screen)
		screen.Show()

		cells, w, h := screen.GetContents()
		stray := map[string]int{}
		for j := 0; j < w*h; j++ {
			_, bg, _ := cells[j].Style.Decompose()
			if bg != ui.theme.Bg && bg != ui.theme.Surface && bg != ui.theme.SurfaceRaised &&
				bg != ui.theme.SelectionBg && bg != ui.theme.TableHeaderBg {
				stray[fmt.Sprint(bg)]++
			}
		}
		screen.Fini()

		if len(stray) > 0 {
			t.Errorf("the %s tab paints colours from outside the theme: %v", name, stray)
		}
	}
}

// t changes the theme inside a case.
//
// Show installs the case screen's own capture as the application-wide one, so
// the parent's global keys are unreachable while a case is open — t did
// nothing, and this was the only screen where the theme could not be changed.
func TestTheThemeKeyWorksInsideACase(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.hasTrueColor = true
	ui.setTheme("gruvbox")
	cm := openCase(t, ui)

	was := ui.themeName
	if cm.globalInputCapture == nil {
		t.Fatal("the case screen has no input capture to install")
	}
	if cm.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, 't', tcell.ModNone)) != nil {
		t.Fatal("t was not claimed inside a case")
	}
	if ui.themeName == was {
		t.Errorf("t inside a case left the theme on %q", ui.themeName)
	}
}

// The help lists what the case screen's own handler does, since it owns every
// key while it is open. It used to advertise "escalate to an external system",
// which does not exist; e exports the selected events.
func TestTheCaseHelpNamesRealKeys(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 1)
	ui.selectedCaseID = ui.cases[0].ID
	openCase(t, ui)

	ui.showHelp()
	frame := strings.Join(renderPrimitive(t, ui.activeModal, 150, 44), "\n")

	if strings.Contains(frame, "Escalate to external system") {
		t.Error("the help still advertises a key that does something else")
	}
	for _, want := range []string{"Write the case up as a report", "Change the theme"} {
		if !strings.Contains(frame, want) {
			t.Errorf("the case help does not mention %q", want)
		}
	}
}

// ? opens the key reference from inside a case.
//
// The case screen installs its own application-wide capture, so the parent's ?
// never ran here — help was unreachable from the one screen whose keys it
// documents. And the parent's help closes by restoring the main layout, which
// would have ejected the analyst from the case they were reading about.
func TestHelpOpensInsideACase(t *testing.T) {
	ui, _ := newTestUI(t)
	cm := openCase(t, ui)

	if cm.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, '?', tcell.ModNone)) != nil {
		t.Fatal("? was not claimed inside a case")
	}
	if !cm.modalActive {
		t.Fatal("? opened nothing")
	}
	if len(cm.modalStack) != 1 {
		t.Errorf("the help was not put on the case's own modal stack: %d entries", len(cm.modalStack))
	}
}

// Closing it returns to the case, not to the main layout.
func TestClosingTheCaseHelpReturnsToTheCase(t *testing.T) {
	ui, _ := newTestUI(t)
	cm := openCase(t, ui)

	cm.showCaseHelp()
	if len(cm.modalStack) != 1 {
		t.Fatalf("the help is not on the stack: %d", len(cm.modalStack))
	}

	cm.popModalRoot()

	if len(cm.modalStack) != 0 {
		t.Errorf("closing the help left %d entries on the stack", len(cm.modalStack))
	}
	if cm.modalActive {
		t.Error("the case still reports a modal after the help closed")
	}
}

// Refreshing says what it refreshed.
//
// The line was written from the events tab's point of view and printed on every
// tab, so pressing r on Activity reported a number of events.
func TestRefreshingACaseSaysWhatItRead(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 1)
	cm := NewCaseManagement(ui, ui.cases[0])
	ui.activeCM = cm
	t.Cleanup(func() { ui.activeCM = nil })
	awaitIdle(t, ui)

	cm.refreshCaseData()
	awaitIdle(t, ui)

	got := stripTags(cm.statusBar.GetText(true))
	if !strings.Contains(got, "Case refreshed") {
		t.Errorf("a refresh does not say the case was refreshed: %s", got)
	}
	if strings.Contains(got, "Loaded") && strings.Contains(got, "events for case") {
		t.Errorf("a refresh still reports only the events: %s", got)
	}
	for _, want := range []string{"event", "note", "activity"} {
		if !strings.Contains(got, want) {
			t.Errorf("the refresh does not account for %ss: %s", want, got)
		}
	}
}

// One spelling of the save key, and the view mode does not offer to save
// something that is not being edited.
func TestTheNotesKeysAreDescribedConsistently(t *testing.T) {
	ui, _ := newTestUI(t)
	cm := openCase(t, ui)

	view := stripTags(cm.notesViewStatusText())
	edit := stripTags(cm.notesEditStatusText())

	if strings.Contains(view, "Ctrl") {
		t.Errorf("the notes list offers a save with nothing being edited: %s", view)
	}
	if strings.Contains(view, "Tab=Copilot") || strings.Contains(view, "Tab opens the copilot") {
		t.Errorf("the notes list says Tab opens the copilot; it moves to the next tab: %s", view)
	}
	if !strings.Contains(edit, "Ctrl+S") {
		t.Errorf("the editor does not name the save key as Ctrl+S: %s", edit)
	}
	if strings.Contains(edit, "Ctrl+s") {
		t.Errorf("the editor spells the save key differently from the panel title: %s", edit)
	}
}

// Space says why it did nothing, rather than appearing broken.
//
// It only ever acted on the analyst's own entries — the rest of the list is
// observables pulled out of the case's evidence — while the status line
// advertised it for every row. On a case whose indicators all came from
// evidence, which is most of them, the key looked dead.
func TestSpaceOnAnExtractedIndicatorSaysWhy(t *testing.T) {
	ui, _ := newTestUI(t)
	cm := openCase(t, ui)

	cm.caseIndicators = []store.CaseIndicator{
		{TypeID: 2, Type: "IP Address", Value: "45.147.230.11", Source: "asserted"},
	}
	cm.iocRowToManualID = map[int]string{}
	cm.iocsTable.Select(1, 0)

	cm.toggleManualIOC()

	got := stripTags(cm.statusBar.GetText(true))
	if !strings.Contains(got, "came from the evidence") {
		t.Errorf("Space on an extracted indicator said nothing useful: %s", got)
	}
	if len(cm.selectedManualIOCIDs) != 0 {
		t.Error("an extracted indicator was marked for deletion")
	}
}

// And it works on the analyst's own — through the real path, because Space
// re-renders the list, which rebuilds the row-to-note map from the database.
func TestSpaceSelectsYourOwnIndicator(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 1)
	c := ui.cases[0]

	if _, err := st.AddNote(context.Background(), store.Note{
		CaseID: c.ID, Content: "ioc_type:ip", Author: "analyst",
		LinkedType: "ioc", LinkedID: "10.0.0.1",
	}); err != nil {
		t.Fatal(err)
	}

	cm := NewCaseManagement(ui, c)
	ui.activeCM = cm
	t.Cleanup(func() { ui.activeCM = nil })
	awaitIdle(t, ui)
	cm.renderIOCs()

	row := 0
	for i, ind := range cm.caseIndicators {
		if ind.Value == "10.0.0.1" {
			row = i + 1
		}
	}
	if row == 0 {
		t.Fatalf("the analyst's own indicator is not in the list: %+v", cm.caseIndicators)
	}
	cm.iocsTable.Select(row, 0)

	cm.toggleManualIOC()
	if len(cm.selectedManualIOCIDs) != 1 {
		t.Fatalf("Space selected %d indicators, want the one the analyst added",
			len(cm.selectedManualIOCIDs))
	}
	if got := stripTags(cm.statusBar.GetText(true)); !strings.Contains(got, "1 indicator selected") {
		t.Errorf("selecting one said: %s", got)
	}

	cm.toggleManualIOC()
	if len(cm.selectedManualIOCIDs) != 0 {
		t.Errorf("Space did not deselect: %v", cm.selectedManualIOCIDs)
	}
}

// A pivot asks before it leaves.
//
// It spans the whole database, which a case screen cannot show, so answering it
// closes the case and opens the Events screen. Doing that silently on Enter —
// the key least likely to be read as "leave" — threw the analyst out of the
// investigation they were in.
func TestPivotingFromACaseAsksFirst(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 1)
	cm := NewCaseManagement(ui, ui.cases[0])
	ui.activeCM = cm
	t.Cleanup(func() { ui.activeCM = nil })
	awaitIdle(t, ui)

	cm.caseIndicators = []store.CaseIndicator{
		{TypeID: 2, Type: "IP Address", Value: "45.147.230.11", Source: "asserted"},
	}
	cm.iocsTable.Select(1, 0)

	cm.pivotSelectedIndicator()

	if !cm.modalActive {
		t.Fatal("the pivot left the case without asking")
	}
	if ui.pivot != nil {
		t.Error("the pivot happened before it was confirmed")
	}
}
