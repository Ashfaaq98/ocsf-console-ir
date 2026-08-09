package ui

import (
	"testing"
	"time"
)

// A page index is clamped to the result set it is paging through.
//
// The arithmetic lived inline in both event loaders, in two copies that had
// drifted — one clamped the index before computing the offset and one after —
// and neither could be checked without a database and a screen.
func TestPageOffsetClampsToTheResultSet(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		total, size, index      int
		wantPage, wantOffsetRow int
	}{
		{"first page", 120, 50, 0, 0, 0},
		{"second page", 120, 50, 1, 1, 50},
		{"last partial page", 120, 50, 2, 2, 100},
		{"past the end", 120, 50, 9, 2, 100},
		{"empty result", 0, 50, 3, 0, 0},
		{"exactly one page", 50, 50, 1, 0, 0},
		{"negative index", 120, 50, -4, 0, 0},
		{"no page size", 120, 0, 2, 0, 0},
	} {
		page, offset := pageOffset(tc.total, tc.size, tc.index)
		if page != tc.wantPage || offset != tc.wantOffsetRow {
			t.Errorf("%s: pageOffset(%d, %d, %d) = (%d, %d), want (%d, %d)",
				tc.name, tc.total, tc.size, tc.index,
				page, offset, tc.wantPage, tc.wantOffsetRow)
		}
	}
}

// A load records the totals it actually queried with.
//
// It used to write them from its own goroutine, mid-query, so the status bar
// could read a total from one screen beside a page index from another.
func TestAnEventLoadRecordsItsOwnTotals(t *testing.T) {
	ui, _ := newTestUI(t)
	seedEvents(t, ui, 12)

	ui.enterScreen(destEvents)
	awaitIdle(t, ui)

	// A page index left over from a larger result set. Entering the screen
	// resets it deliberately, so this is set after the way in and reloaded.
	s := ui.getOrInitState(contextAll)
	s.pageSize = 5
	s.pageIndex = 7
	ui.spawnLoad(ui.loadAllEvents)
	awaitIdle(t, ui)

	if s.totalCount != 12 {
		t.Errorf("the load recorded %d events, want 12", s.totalCount)
	}
	if s.pageIndex != 2 {
		t.Errorf("the stale page index was left at %d, want the last page (2)", s.pageIndex)
	}
	if len(ui.events) != 2 {
		t.Errorf("the last page holds %d events, want the 2 that are on it", len(ui.events))
	}
}

// The query context is copied from the screen, legacy time filters included.
func TestPlanningAQueryBridgesTheLegacyFilters(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.filterStart = time.Now().Add(-24 * time.Hour)
	ui.filterEnd = time.Now()

	plan := ui.planEventQuery(contextAll, "")

	if !plan.start.Equal(ui.filterStart) || !plan.end.Equal(ui.filterEnd) {
		t.Errorf("the plan carries %v–%v, want the screen's %v–%v",
			plan.start, plan.end, ui.filterStart, ui.filterEnd)
	}
	// And the bridge is recorded, so the next plan does not depend on the old
	// fields still being set.
	s := ui.getOrInitState(contextAll)
	if !s.filterStart.Equal(ui.filterStart) {
		t.Error("the per-context state did not take the legacy window")
	}
}

// A case the filters remove is no longer the selection.
func TestApplyingCasesDropsAFilteredSelection(t *testing.T) {
	ui, st := newTestUI(t)
	seedCases(t, ui, st, 2)

	ui.selectedCaseID = "gone"
	ui.showAll = false
	ui.applyCases(ui.allCases, 0)

	if ui.selectedCaseID != "" {
		t.Errorf("a case that is not in the list is still selected: %q", ui.selectedCaseID)
	}
	if !ui.showAll {
		t.Error("the events list did not fall back to all events")
	}
}
