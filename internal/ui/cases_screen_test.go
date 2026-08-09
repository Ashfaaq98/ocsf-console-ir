package ui

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// seedCases puts n cases in the store and loads them.
func seedCases(t *testing.T, ui *UI, st *store.Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := st.CreateOrUpdateCase(context.Background(), store.Case{
			ID:    fmt.Sprintf("c%d", i),
			Title: fmt.Sprintf("Suspected account compromise — m.chen %d", i),
			// Long enough to be truncated at the old fixed width.
			Severity: "high", Status: "OPEN",
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := ui.refreshCases(); err != nil {
		t.Fatal(err)
	}
}

// Cases has a filter and never said so.
//
// Globally f picks between the case filter and the events filter by asking
// which widget has focus, so the key both worked and did not depending on
// where the cursor was, and the bar advertised neither.
func TestCasesAdvertisesItsFilter(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 2)
	ui.enterScreen(destCases)
	awaitIdle(t, ui)

	bar := stripTags(ui.statusBar.GetText(true))
	if !strings.Contains(bar, "f filter") {
		t.Errorf("the Cases bar does not offer the filter: %s", bar)
	}
}

// f opens the case filter wherever focus is.
func TestFilterOnCasesIsTheCaseFilter(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 2)
	ui.enterScreen(destCases)
	awaitIdle(t, ui)

	// Focus somewhere other than the list, as arrowing into the briefing does.
	ui.app.SetFocus(ui.eventDetail)
	if ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, 'f', tcell.ModNone)) != nil {
		t.Fatal("f was not claimed on Cases")
	}
	if ui.activeModal == nil {
		t.Fatal("f opened nothing")
	}
	title := ui.statusBar.GetText(true)
	if strings.Contains(strings.ToLower(title), "event") {
		t.Errorf("f on Cases opened the events filter: %s", title)
	}
}

// Refreshing the case list must not freeze the arrow keys.
//
// r went through the global handler, which also scheduled an events reload —
// and that load ends by focusing the events table, which is not on this
// screen. Focus landed on a widget nobody could see and the case list stopped
// responding to the arrows.
func TestRefreshOnCasesKeepsTheArrowKeys(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 3)
	ui.enterScreen(destCases)
	awaitIdle(t, ui)
	ui.app.SetFocus(ui.sidebar)

	if ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, 'r', tcell.ModNone)) != nil {
		t.Fatal("r was not claimed on Cases")
	}
	awaitIdle(t, ui)

	if got := ui.app.GetFocus(); got != ui.sidebar {
		t.Fatalf("after refreshing, focus is on %T, not the case list", got)
	}
	before := ui.sidebar.GetCurrentItem()
	ui.sidebar.InputHandler()(tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone), func(tview.Primitive) {})
	if after := ui.sidebar.GetCurrentItem(); after == before {
		t.Errorf("the case list did not move on Down: still item %d", before)
	}
}

// The same guard, at the source: a load for a case's events must not take
// focus on a screen that does not show them.
func TestLoadingCaseEventsDoesNotStealFocus(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 2)
	ui.enterScreen(destCases)
	awaitIdle(t, ui)
	ui.app.SetFocus(ui.sidebar)

	ui.selectedCaseID = "c0"
	ui.spawnLoad(ui.loadCaseEvents)
	awaitIdle(t, ui)

	if got := ui.app.GetFocus(); got != ui.sidebar {
		t.Errorf("loading a case's events moved focus to %T", got)
	}
}

// A refresh keeps your place in the list.
func TestRefreshingCasesKeepsYourPlace(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 4)
	ui.enterScreen(destCases)
	awaitIdle(t, ui)

	ui.sidebar.SetCurrentItem(2)
	want := ui.cases[2].ID

	if err := ui.refreshCases(); err != nil {
		t.Fatal(err)
	}
	awaitIdle(t, ui)

	got := ui.sidebar.GetCurrentItem()
	if got < 0 || got >= len(ui.cases) || ui.cases[got].ID != want {
		t.Errorf("refreshing moved the cursor to item %d, want the case it was on", got)
	}
}

// The list is wide enough for a case title.
func TestTheCaseListFitsATitle(t *testing.T) {
	for _, tc := range []struct{ term, want int }{
		{80, casesListMin},
		{120, 40},
		{190, 63},
		{400, casesListMax},
		{0, casesListMin},
	} {
		if got := casesListWidth(tc.term); got != tc.want {
			t.Errorf("a %d-column terminal gives the case list %d, want %d", tc.term, got, tc.want)
		}
	}

	ui, st := newTestUI(t)
	seedCases(t, ui, st, 1)
	ui.termWidth = 190
	ui.enterScreen(destCases)
	awaitIdle(t, ui)

	main, _ := ui.sidebar.GetItemText(0)
	if strings.Contains(stripTags(main), "…") || strings.Contains(stripTags(main), "...") {
		t.Errorf("a 190-column terminal still truncates the case title: %q", stripTags(main))
	}
}

// The briefing keeps its own border.
//
// Its draw function returned the outer rect, so the text was laid out over the
// panel frame: the first column of every line landed on the left edge and the
// last wrapped past the right, leaving the border visible only on the rows that
// happened to be blank.
func TestTheBriefingDoesNotDrawOverItsBorder(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 1)

	pane := ui.buildCaseBriefingTab(ui.cases[0])
	const w, h = 46, 16
	lines := renderPrimitive(t, pane, w, h)

	for i := 1; i < h-1; i++ {
		row := []rune(lines[i])
		if len(row) < w {
			t.Fatalf("row %d is %d columns, want %d: %q", i, len(row), w, lines[i])
		}
		if row[0] != '│' && row[0] != '║' {
			t.Errorf("row %d has %q where the left border belongs: %q", i, string(row[0]), lines[i])
		}
		if row[w-1] != '│' && row[w-1] != '║' {
			t.Errorf("row %d has %q where the right border belongs: %q", i, string(row[w-1]), lines[i])
		}
	}
}

// And its prompt wraps to the pane rather than to two hard-coded lines.
func TestTheBriefingPromptWrapsToThePane(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 1)

	for _, w := range []int{44, 70, 120} {
		lines := renderPrimitive(t, ui.buildCaseBriefingTab(ui.cases[0]), w, 16)
		joined := strings.Join(lines, "\n")
		if !strings.Contains(joined, "No statement yet") {
			t.Fatalf("at %d columns the briefing lost its prompt:\n%s", w, joined)
		}
		// A word split across the frame is what the hard-coded lines produced.
		for i, l := range lines {
			if strings.Contains(l, "│reconstruct") || strings.Contains(l, "│at happened") {
				t.Errorf("at %d columns row %d breaks a word on the border: %q", w, i, l)
			}
		}
	}
}

// c on Cases opens the new-case form.
//
// It is what the footer has always advertised there. The key reached the
// global handler, which is the events flow — mark events, then file them into a
// case — so on a screen with no events to mark it answered "No events
// selected. Use Space to select events first."
func TestNewCaseOnTheCasesScreenOpensTheForm(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 1)
	ui.enterScreen(destCases)
	awaitIdle(t, ui)

	if ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, 'c', tcell.ModNone)) != nil {
		t.Fatal("c was not claimed on Cases")
	}
	if ui.activeModal == nil {
		t.Fatal("c opened nothing on Cases")
	}
	frame := strings.Join(renderPrimitive(t, ui.activeModal, 150, 34), "\n")
	if !strings.Contains(frame, "Create New Case") {
		t.Errorf("c did not open the new-case form:\n%s", frame)
	}
	if strings.Contains(stripTags(ui.statusBar.GetText(true)), "No events selected") {
		t.Error("c on Cases still complains about an events selection")
	}
}

// A case can be created with nothing attached, which is what that form does on
// the Cases screen.
func TestACaseCanBeCreatedWithNoEvents(t *testing.T) {
	ui, st := newTestUI(t)
	ui.enterScreen(destCases)
	awaitIdle(t, ui)

	ui.createCase("Suspected exfiltration", "", "high", "", nil)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cases, err := st.ListCases(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(cases) == 1 && cases[0].Title == "Suspected exfiltration" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("a case with no events was never created")
}
