package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

var testNow = time.Date(2026, 8, 1, 14, 0, 0, 0, time.UTC)

// Chips combine with AND. Each one narrows; none replaces another.
func TestChipsAreAdditive(t *testing.T) {
	f := newTriageFilter()
	f.toggle(chipSeverityHigh)
	f.toggle(chipHasIOC)

	got := f.storeFilter(testNow, 200, 0)

	if !got.OpenOnly {
		t.Error("the Open chip stopped applying once another was added")
	}
	if got.MinSeverityID != ocsf.SeverityHigh {
		t.Errorf("MinSeverityID = %d, want High", got.MinSeverityID)
	}
	if !got.HasObservables {
		t.Error("the Has IOC chip did not apply")
	}
}

func TestChipToggleRemoves(t *testing.T) {
	f := newTriageFilter()
	if !f.active[chipOpen] {
		t.Fatal("My queue does not start with the Open chip")
	}

	f.toggle(chipOpen)
	if f.storeFilter(testNow, 200, 0).OpenOnly {
		t.Error("removing the Open chip left OpenOnly applied")
	}

	f.toggle(chipOpen)
	if !f.storeFilter(testNow, 200, 0).OpenOnly {
		t.Error("re-adding the Open chip did not reapply it")
	}
}

// Filtering must re-query. This asserts the state produces a store filter at
// all, which is what makes that possible — the alternative is filtering a
// loaded page in Go, which silently lies once the page is not the whole set.
func TestFilterProducesAStoreQuery(t *testing.T) {
	f := newTriageFilter()
	f.search = "  lsass  "

	got := f.storeFilter(testNow, 200, 40)

	if got.Search != "lsass" {
		t.Errorf("Search = %q, want it trimmed", got.Search)
	}
	if got.Limit != 200 || got.Offset != 40 {
		t.Errorf("limit/offset = %d/%d, want 200/40", got.Limit, got.Offset)
	}
	if got.Sort != store.SortPriority {
		t.Error("Triage does not use the priority ordering, so it disagrees with Home's queue")
	}
}

// Time windows are relative to a supplied clock, never to time.Now inside the
// filter: a test that cannot control the clock cannot test a 24-hour window.
func TestTimeWindows(t *testing.T) {
	f := newTriageFilter()
	f.toggle(chipLast24h)

	got := f.storeFilter(testNow, 200, 0)
	if want := testNow.Add(-24 * time.Hour); !got.SeenAfter.Equal(want) {
		t.Errorf("SeenAfter = %s, want %s", got.SeenAfter, want)
	}
	if !got.SeenBefore.IsZero() {
		t.Error("last 24h set an upper bound as well as a lower one")
	}
}

// Stale is the same field as "last 24h" read the other way, and must not be
// confused with it.
func TestStaleViewBoundsTheOtherEnd(t *testing.T) {
	f := newTriageFilter()
	for i, v := range savedViews() {
		if v.name == "Stale >24h" {
			f.applyView(i)
		}
	}

	got := f.storeFilter(testNow, 200, 0)
	if want := testNow.Add(-24 * time.Hour); !got.SeenBefore.Equal(want) {
		t.Errorf("SeenBefore = %s, want %s", got.SeenBefore, want)
	}
	if !got.SeenAfter.IsZero() {
		t.Error("stale also set a lower bound, so it excludes the very findings it is for")
	}
}

func TestSavedViews(t *testing.T) {
	for _, tc := range []struct {
		view  string
		check func(*testing.T, store.FindingFilter)
	}{
		{"My queue", func(t *testing.T, f store.FindingFilter) {
			if !f.OpenOnly {
				t.Error("My queue is not open-only")
			}
		}},
		{"Critical now", func(t *testing.T, f store.FindingFilter) {
			if f.MinSeverityID != ocsf.SeverityCritical {
				t.Errorf("MinSeverityID = %d, want Critical", f.MinSeverityID)
			}
			if !f.OpenOnly {
				t.Error("Critical now includes closed findings")
			}
		}},
		{"Untriaged", func(t *testing.T, f store.FindingFilter) {
			if len(f.Statuses) != 1 || f.Statuses[0] != ocsf.FindingStatusNew {
				t.Errorf("Statuses = %v, want New only", f.Statuses)
			}
		}},
		{"Suppressed", func(t *testing.T, f store.FindingFilter) {
			if len(f.Statuses) != 1 || f.Statuses[0] != ocsf.FindingStatusSuppressed {
				t.Errorf("Statuses = %v, want Suppressed only", f.Statuses)
			}
			// Suppressed findings are closed by definition, so an open-only
			// view of them is always empty.
			if f.OpenOnly {
				t.Error("the Suppressed view is open-only, so it can never match anything")
			}
		}},
	} {
		t.Run(tc.view, func(t *testing.T) {
			f := newTriageFilter()
			found := false
			for i, v := range savedViews() {
				if v.name == tc.view {
					f.applyView(i)
					found = true
				}
			}
			if !found {
				t.Fatalf("no saved view named %q", tc.view)
			}
			tc.check(t, f.storeFilter(testNow, 200, 0))
		})
	}
}

func TestCycleViewWraps(t *testing.T) {
	f := newTriageFilter()
	first := f.viewName()
	for i := 0; i < len(savedViews()); i++ {
		f.cycleView()
	}
	if f.viewName() != first {
		t.Errorf("cycling all the way round ended on %q, want %q", f.viewName(), first)
	}
}

// The two empty states must be distinguishable, or a filtered-out screen reads
// as lost data and an empty database reads as a broken filter.
//
// The filter alone cannot decide this. The default view carries the Open chip,
// so "is anything filtering?" is true on a fresh install — and Open genuinely
// can be the reason, when every finding is resolved.
func TestEmptyKind(t *testing.T) {
	for _, tc := range []struct {
		name              string
		shown, unfiltered int
		want              triageEmpty
	}{
		{"rows to draw", 5, 12, triageNotEmpty},
		{"fresh database", 0, 0, triageNoFindings},
		{"every finding resolved, Open chip hides them", 0, 12, triageFilteredOut},
		{"search matches nothing", 0, 3, triageFilteredOut},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := emptyKind(tc.shown, tc.unfiltered); got != tc.want {
				t.Errorf("emptyKind(%d, %d) = %v, want %v", tc.shown, tc.unfiltered, got, tc.want)
			}
		})
	}
}

// The empty state has to name what is filtering, or it is a dead end.
func TestDescribeNamesTheActiveFilters(t *testing.T) {
	f := newTriageFilter()
	f.toggle(chipSeverityHigh)
	f.search = "lsass"

	got := f.describe()
	for _, want := range []string{"My queue", "Open", "Sev ≥ High", "lsass"} {
		if !strings.Contains(got, want) {
			t.Errorf("describe() = %q, missing %q", got, want)
		}
	}
}

// Selection is keyed by finding uid, because §7 requires it to survive refresh,
// sort and filter changes — and a row index survives none of those.
func TestSelectionSurvivesReordering(t *testing.T) {
	sel := newTriageSelection()
	sel.toggle("fnd-a")
	sel.toggle("fnd-c")

	before := []store.Finding{
		{FindingUID: "fnd-a", Title: "a"},
		{FindingUID: "fnd-b", Title: "b"},
		{FindingUID: "fnd-c", Title: "c"},
	}
	// The same findings after a re-sort, plus one that arrived since.
	after := []store.Finding{
		{FindingUID: "fnd-c", Title: "c"},
		{FindingUID: "fnd-d", Title: "d"},
		{FindingUID: "fnd-a", Title: "a"},
		{FindingUID: "fnd-b", Title: "b"},
	}

	if got := len(sel.resolve(before)); got != 2 {
		t.Fatalf("resolved %d before reordering, want 2", got)
	}
	got := sel.resolve(after)
	if len(got) != 2 {
		t.Fatalf("resolved %d after reordering, want 2", len(got))
	}
	for _, f := range got {
		if f.FindingUID != "fnd-a" && f.FindingUID != "fnd-c" {
			t.Errorf("selection moved to %s after a re-sort", f.FindingUID)
		}
	}
}

// A selection of rows no longer in the result is not lost, only unresolvable
// against this page. Clearing is explicit.
func TestSelectionCountIsIndependentOfTheLoadedPage(t *testing.T) {
	sel := newTriageSelection()
	sel.toggle("fnd-a")
	sel.toggle("fnd-b")

	if got := sel.count(); got != 2 {
		t.Errorf("count = %d, want 2", got)
	}
	if got := len(sel.resolve(nil)); got != 0 {
		t.Errorf("resolved %d against an empty page, want 0", got)
	}
	if got := sel.count(); got != 2 {
		t.Errorf("count = %d after resolving an empty page, want the selection intact", got)
	}

	sel.clear()
	if sel.count() != 0 {
		t.Error("clear did not empty the selection")
	}
}

func TestSelectionIgnoresEmptyIDs(t *testing.T) {
	sel := newTriageSelection()
	sel.toggle("")
	if sel.count() != 0 {
		t.Error("an empty uid was selected, which would mark every finding without one")
	}
}

// The chip row shows what is applied and what is available.
func TestRenderChips(t *testing.T) {
	f := newTriageFilter()
	f.toggle(chipLast24h)

	got := f.renderChips(themeDark())
	for _, want := range []string{"Open", "Last 24h", "Sev ≥ High", "saved:", "My queue"} {
		if !strings.Contains(got, want) {
			t.Errorf("chip row is missing %q:\n%s", want, got)
		}
	}
	// An applied chip carries its removal affordance.
	if !strings.Contains(got, "✕") {
		t.Errorf("no active chip shows how to remove it:\n%s", got)
	}
}
