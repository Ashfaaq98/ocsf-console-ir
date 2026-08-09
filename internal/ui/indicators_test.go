package ui

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
)

func seedIndicatorEvents(t *testing.T, ui *UI, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		ev := &ocsf.Event{
			Time:     time.Now().Add(-time.Duration(i*7) * time.Hour),
			ClassUID: 4001, ActivityID: 1, TypeUID: 400101, SeverityID: 2, Message: "seed",
			Device:      &ocsf.Device{Hostname: fmt.Sprintf("workstation-%02d", i%3)},
			SrcEndpoint: &ocsf.Endpoint{IP: fmt.Sprintf("198.51.100.%d", i%4)},
		}
		ev.Metadata.UID = fmt.Sprintf("e%02d", i)
		if _, err := ui.store.SaveEvent(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
}

// The screen shows every observable, not only the ones attached to a case.
//
// It was the case tab pointed at a loop over the case list, so a database full
// of events and no cases rendered an empty screen over a full observables table.
func TestIndicatorsShowObservablesWithNoCase(t *testing.T) {
	ui, _ := newTestUI(t)
	seedIndicatorEvents(t, ui, 9)

	ui.enterScreen(destIndicators)
	awaitIdle(t, ui)

	if len(ui.indicators.rows) == 0 {
		t.Fatal("the screen is empty with observables in the database and no cases")
	}
	values := map[string]bool{}
	for _, r := range ui.indicators.rows {
		values[r.Value] = true
	}
	if !values["workstation-00"] {
		t.Errorf("a host observed on an uncased event is missing: %+v", ui.indicators.rows)
	}
}

// The Cases sidebar's filters must not narrow it. The old screen looped
// ui.cases, which is the filtered list.
func TestIndicatorsIgnoreCaseFilters(t *testing.T) {
	ui, st := newTestUI(t)
	seedIndicatorEvents(t, ui, 6)
	if _, err := st.CreateOrUpdateCase(context.Background(), store.Case{
		ID: "c1", Title: "A case", Status: "OPEN", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := ui.refreshCases(); err != nil {
		t.Fatal(err)
	}

	ui.enterScreen(destIndicators)
	awaitIdle(t, ui)
	before := len(ui.indicators.rows)

	// A filter that matches no case at all.
	ui.caseFilterName = "nothing matches this"
	ui.cases = nil
	ui.spawnLoad(ui.loadIndicators)
	awaitIdle(t, ui)

	if got := len(ui.indicators.rows); got != before {
		t.Errorf("the case filter changed the indicator count from %d to %d", before, got)
	}
}

// Most widely seen first, so the page shown is the useful one.
func TestIndicatorsAreOrderedBySightings(t *testing.T) {
	ui, _ := newTestUI(t)
	seedIndicatorEvents(t, ui, 9)

	ui.enterScreen(destIndicators)
	awaitIdle(t, ui)

	rows := ui.indicators.rows
	for i := 1; i < len(rows); i++ {
		if rows[i].Sightings > rows[i-1].Sightings {
			t.Errorf("row %d has more sightings than the row above it: %+v", i, rows)
		}
	}
}

// Enter pivots to the events carrying the indicator.
//
// The case tab has had this since it was built; the cross-case screen, where it
// matters more, had no Enter at all.
func TestIndicatorsEnterPivots(t *testing.T) {
	ui, _ := newTestUI(t)
	seedIndicatorEvents(t, ui, 6)

	ui.enterScreen(destIndicators)
	awaitIdle(t, ui)
	ui.indicators.table.Select(1, 0)

	want := ui.selectedIndicator()
	if want == nil {
		t.Fatal("nothing selected")
	}

	if ui.indicatorKeys(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)) != nil {
		t.Error("Indicators did not claim Enter")
	}
	awaitIdle(t, ui)

	if ui.pivot == nil {
		t.Fatal("Enter did not pivot")
	}
	if ui.pivot.Value != want.Value {
		t.Errorf("pivoted on %q, want the selected indicator %q", ui.pivot.Value, want.Value)
	}
	if ui.destination != destEvents {
		t.Errorf("a pivot left the rail marking %v, want Events", ui.destination)
	}
}

// The inspector answers what the screen exists to answer: what carries this.
func TestIndicatorInspectorCountsWhatCarriesIt(t *testing.T) {
	ui, _ := newTestUI(t)
	seedIndicatorEvents(t, ui, 9)

	ui.enterScreen(destIndicators)
	awaitIdle(t, ui)
	ui.indicators.table.Select(1, 0)
	ui.renderIndicatorInspector()

	got := stripTags(ui.indicators.inspector.GetText(true))
	for _, want := range []string{"sightings", "carried by", "events"} {
		if !strings.Contains(got, want) {
			t.Errorf("the inspector is missing %q:\n%s", want, got)
		}
	}
}

// / filters by value.
func TestIndicatorsSearchNarrowsTheList(t *testing.T) {
	ui, _ := newTestUI(t)
	seedIndicatorEvents(t, ui, 9)

	ui.enterScreen(destIndicators)
	awaitIdle(t, ui)
	all := len(ui.indicators.rows)

	ui.indicators.filter.Search = "workstation"
	ui.spawnLoad(ui.loadIndicators)
	awaitIdle(t, ui)

	got := len(ui.indicators.rows)
	if got == 0 || got >= all {
		t.Errorf("search matched %d of %d rows, want a strict subset", got, all)
	}
	for _, r := range ui.indicators.rows {
		if !strings.Contains(strings.ToLower(r.Value), "workstation") {
			t.Errorf("a row that does not match the search survived: %q", r.Value)
		}
	}
}

// A sighting time carries its date unless it was today.
//
// A bare clock time collapses every day onto the same twenty-four labels, so on
// a cross-case view two sightings a week apart read as minutes apart.
func TestIndicatorTimestampsCarryTheirDate(t *testing.T) {
	today := stampOrDash(time.Now())
	if strings.Contains(today, "-") {
		t.Errorf("today's sighting shows a date: %q", today)
	}

	old := stampOrDash(time.Now().Add(-72 * time.Hour))
	if !strings.Contains(old, "-") {
		t.Errorf("a sighting from three days ago shows no date: %q", old)
	}
}

// The empty state must not describe a case on a screen that has none.
func TestIndicatorsEmptyStateIsAboutTheDatabase(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.enterScreen(destIndicators)
	awaitIdle(t, ui)

	got := strings.Join(ui.indicatorsEmptyState(), " ")
	if strings.Contains(got, "this case") {
		t.Errorf("the cross-database screen's empty state talks about a case: %s", got)
	}
	if !strings.Contains(got, "database") {
		t.Errorf("the empty state does not say where indicators come from: %s", got)
	}
}
