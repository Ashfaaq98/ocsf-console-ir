package ui

import (
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
