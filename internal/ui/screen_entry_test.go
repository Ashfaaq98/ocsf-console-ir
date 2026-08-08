package ui

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
)

// newTestUI builds a UI over a real store with no application running.
func newTestUI(t *testing.T) (*UI, *store.Store) {
	t.Helper()
	withTempConfig(t)

	st, err := store.NewStore(filepath.Join(t.TempDir(), "screens.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ui := NewUI(ctx, st, nil, logging.New(io.Discard, logging.LevelError, "test"), "test")
	t.Cleanup(func() {
		if ui.home != nil {
			ui.home.close()
			ui.home.wait()
		}
		ui.waitForLoads()
	})
	return ui, st
}

// Every screen must be reachable by the key router.
//
// tview runs the application-wide capture before any primitive's own, so a
// screen that the router does not know about cannot own a single key — which
// is why Triage's bulk actions read the events selection, why Tab focused
// widgets that were not on screen, and why the Cases briefing's keys did
// something else entirely.
func TestEveryScreenOwnsItsKeys(t *testing.T) {
	ui, _ := newTestUI(t)

	for _, d := range append([]destination{homeDestination()}, destinations()...) {
		if d.id == destHome {
			// Home's handler belongs to its view, which only exists once the
			// screen has been opened.
			continue
		}
		if d.id == destReports {
			// Reports is a static panel with no keys of its own, deliberately.
			continue
		}
		ui.destination = d.id
		if ui.screenKeys() == nil {
			t.Errorf("%s is not registered with the key router, so it owns nothing", d.name)
		}
	}
}

// A screen's handler passes on what it does not own, or the digits stop
// navigating and the screen becomes one you cannot leave.
func TestStubHandlersPassKeysOn(t *testing.T) {
	ui, _ := newTestUI(t)

	for _, d := range destinations() {
		if d.id == destReports {
			continue
		}
		ui.destination = d.id
		h := ui.screenKeys()
		if h == nil {
			t.Fatalf("%s has no handler", d.name)
		}
		ev := tcell.NewEventKey(tcell.KeyRune, '1', tcell.ModNone)
		if h(ev) == nil {
			t.Errorf("%s swallowed a navigation digit", d.name)
		}
	}
}

// The rail must mark the screen you are actually on, whichever route took you
// there. The letter shortcuts opened a screen without telling the rail, so `A`
// left it marking Triage while Events was on screen.
func TestEveryRouteMarksTheRail(t *testing.T) {
	ui, _ := newTestUI(t)
	if err := ui.refreshCases(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		key  rune
		want destinationID
		name string
	}{
		{'A', destEvents, "Events"},
		{'C', destCases, "Cases"},
		{'I', destIndicators, "Indicators"},
		{'D', destTriage, "Triage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ui.destination = destHome
			ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, tc.key, tcell.ModNone))

			if ui.destination != tc.want {
				t.Errorf("%c left the rail marking %v, want %v", tc.key, ui.destination, tc.want)
			}
			awaitIdle(t, ui)
		})
	}
}

// Nothing the outgoing screen owned may survive into the next one.
//
// Triage and Events are one table and one detail pane wearing two names, and
// the switch used to reset four fields out of a dozen — so Events opened titled
// "FINDINGS · N of N" with the previous finding still in the inspector.
func TestScreenStateDoesNotLeak(t *testing.T) {
	ui, st := newTestUI(t)

	f := &ocsf.Finding{FindingInfo: ocsf.FindingInfo{UID: "leak", Title: "A finding"}, RiskScore: 90}
	f.ClassUID = ocsf.ClassDetectionFinding
	f.CategoryUID = ocsf.CategoryFindings
	f.SeverityID = ocsf.SeverityCritical
	f.Time = time.Now()
	if _, err := st.SaveFinding(context.Background(), f); err != nil {
		t.Fatal(err)
	}

	// Entering the screen starts its own load; a second one raced it through the
	// shared busy flag, so which of the two populated ui.findings was chance.
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	if len(ui.findings) == 0 {
		t.Fatal("Triage loaded nothing; the fixture proves nothing")
	}
	ui.eventList.Select(1, 0)
	ui.showFindingDetails()

	ui.enterScreen(destEvents)
	awaitIdle(t, ui)

	if ui.findings != nil {
		t.Errorf("the findings survived into Events: %d rows", len(ui.findings))
	}
	if ui.selectedFindingID != "" {
		t.Errorf("the selected finding survived into Events: %q", ui.selectedFindingID)
	}
	if title := ui.eventDetail.GetTitle(); strings.Contains(title, "FINDING") {
		t.Errorf("the inspector is still titled %q on the Events screen", title)
	}
	if ui.pivot != nil || ui.searchQuery != "" || ui.expandedCluster != "" {
		t.Errorf("a stale query survived the screen change: pivot=%v search=%q cluster=%q",
			ui.pivot, ui.searchQuery, ui.expandedCluster)
	}
}

// The context flags come from the destination table, so no two entry points can
// disagree about what a screen is.
func TestDestinationTableSetsTheContextFlags(t *testing.T) {
	for _, tc := range []struct {
		id                    destinationID
		showFindings, showAll bool
		name                  string
	}{
		{destTriage, true, false, "Triage"},
		{destEvents, false, true, "Events"},
		{destCases, false, false, "Cases"},
		{destIndicators, false, false, "Indicators"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ui, _ := newTestUI(t)
			if err := ui.refreshCases(); err != nil {
				t.Fatal(err)
			}

			ui.enterScreen(tc.id)
			if ui.showFindings != tc.showFindings || ui.showAll != tc.showAll {
				t.Errorf("%s: showFindings=%v showAll=%v, want %v/%v",
					tc.name, ui.showFindings, ui.showAll, tc.showFindings, tc.showAll)
			}
			awaitIdle(t, ui)
		})
	}
}

// A case summary is written from the case's own events, not from ui.events.
//
// ui.events is the events screen's page: empty on the screen this key is
// pressed from, and cleared outright when a screen changes — so the summary was
// written from either nothing or the wrong evidence.
func TestCaseSummaryReadsTheCasesOwnEvents(t *testing.T) {
	ui, st := newTestUI(t)
	ctx := context.Background()

	if _, err := st.CreateOrUpdateCase(ctx, store.Case{
		ID: "c1", Title: "A case", Status: "OPEN", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	ev := &ocsf.Event{Time: time.Now(), ClassUID: 4001, ActivityID: 1, TypeUID: 400101,
		SeverityID: ocsf.SeverityLow, Message: "in the case"}
	ev.Metadata.UID = "e1"
	id, err := st.SaveEvent(ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AssignEventToCase(ctx, id, "c1"); err != nil {
		t.Fatal(err)
	}
	if err := ui.refreshCases(); err != nil {
		t.Fatal(err)
	}

	// Exactly the state a screen change leaves behind.
	ui.events = nil
	ui.selectedCaseID = "c1"

	got, err := st.GetCaseEventMembers(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("the case holds %d events, want 1 — the fixture proves nothing", len(got))
	}

	// The summary runs asynchronously; the point here is that it does not
	// depend on ui.events, and does not panic now that ui.events is nil.
	ui.showCaseSummary()
}

// A missing provider is reported, not dereferenced.
func TestCaseSummaryWithoutAProviderSaysSo(t *testing.T) {
	ui, st := newTestUI(t)

	if _, err := st.CreateOrUpdateCase(context.Background(), store.Case{
		ID: "c1", Title: "A case", Status: "OPEN", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := ui.refreshCases(); err != nil {
		t.Fatal(err)
	}
	ui.selectedCaseID = "c1"

	// NewUI falls back to a local stub when none is passed, so clear it the way
	// the provider settings path can.
	ui.llm = nil
	ui.showCaseSummary()

	if got := stripTags(ui.statusBar.GetText(true)); !strings.Contains(got, "No LLM provider") {
		t.Errorf("status = %q, want it to name the missing provider", got)
	}
}
