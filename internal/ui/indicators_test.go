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

// The inspector answers what the screen exists to answer, and only that.
//
// It used to repeat the type, the provenance, the sightings and the seen range
// — every one of them a column two lines above it — so eight rows of panel said
// what was already on screen. What the table cannot show is the cross
// reference, because it is a query per row.
func TestIndicatorInspectorNamesWhatCarriesIt(t *testing.T) {
	ui, _ := newTestUI(t)
	seedIndicatorEvents(t, ui, 9)

	ui.enterScreen(destIndicators)
	awaitIdle(t, ui)
	ui.indicators.table.Select(1, 0)

	ind := ui.selectedIndicator()
	if ind == nil {
		t.Fatal("nothing selected")
	}
	ui.indicators.context.load(ind.TypeID, ind.Value)
	ui.renderIndicatorInspector()

	got := stripTags(ui.indicators.inspector.GetText(true))
	for _, want := range []string{ind.Value, "carried by", "event"} {
		if !strings.Contains(got, want) {
			t.Errorf("the inspector is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "sightings") {
		t.Errorf("the inspector repeats the sightings column:\n%s", got)
	}
}

// And it names the findings, not just how many there are.
func TestIndicatorInspectorNamesTheFindings(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")

	ui.enterScreen(destIndicators)
	awaitIdle(t, ui)

	// The finding's own host observable.
	row := -1
	for i, r := range ui.indicators.rows {
		if r.Value == "workstation-14" {
			row = i + 1
			break
		}
	}
	if row < 0 {
		t.Fatalf("the finding's host is not in the indicators list: %+v", ui.indicators.rows)
	}
	ui.indicators.table.Select(row, 0)

	ind := ui.selectedIndicator()
	ui.indicators.context.load(ind.TypeID, ind.Value)
	ui.renderIndicatorInspector()

	got := stripTags(ui.indicators.inspector.GetText(true))
	if !strings.Contains(got, "Malicious attachment") {
		t.Errorf("the inspector does not name the finding carrying the indicator:\n%s", got)
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

// f is this screen's filter, not the events one.
//
// Unclaimed, f reached the global handler, which opened the events filter —
// time, severity and event type, applied to a list of observables that has
// none of those. F cleared the same filters.
func TestIndicatorsOwnTheirFilterKey(t *testing.T) {
	ui, _ := newTestUI(t)
	seedIndicatorEvents(t, ui, 9)
	ui.enterScreen(destIndicators)
	awaitIdle(t, ui)

	if ui.globalInputCapture(tcell.NewEventKey(tcell.KeyRune, 'f', tcell.ModNone)) != nil {
		t.Fatal("f was not claimed on Indicators")
	}
	if ui.activeModal == nil {
		t.Fatal("f opened nothing")
	}
	frame := strings.Join(renderPrimitive(t, ui.activeModal, 150, 34), "\n")
	if !strings.Contains(frame, "Filter by type") {
		t.Errorf("f on Indicators did not open the type filter:\n%s", frame)
	}
	ui.closeModal()
}

// The type filter narrows the list, and F puts it back.
func TestIndicatorTypeFilterNarrowsTheList(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "") // a hostname and a username
	ui.enterScreen(destIndicators)
	awaitIdle(t, ui)

	all := len(ui.indicators.rows)
	types := indicatorTypesPresent(ui.indicators.rows)
	if len(types) < 2 {
		t.Fatalf("expected several observable types, got %+v", types)
	}

	ui.indicators.filter.TypeIDs = []int{types[0].id}
	ui.spawnLoad(ui.loadIndicators)
	awaitIdle(t, ui)

	narrowed := len(ui.indicators.rows)
	if narrowed >= all || narrowed == 0 {
		t.Errorf("filtering to one type left %d of %d rows", narrowed, all)
	}

	if !ui.clearIndicatorFilters() {
		t.Fatal("clearing reported nothing to clear")
	}
	awaitIdle(t, ui)
	if len(ui.indicators.rows) != all {
		t.Errorf("clearing left %d rows, want all %d back", len(ui.indicators.rows), all)
	}
	if ui.clearIndicatorFilters() {
		t.Error("clearing an unfiltered list reported that it cleared something")
	}
}
