package ui

import (
	"time"
)

// What the events loaders read and write, and where.
//
// Both loaders ran their queries on a background goroutine and reached into the
// screen's state from there: the filters and the page index to build the query,
// then the total and the clamped page index to record the result. The status
// bar and the events table read the same fields on the event loop, so a load
// landing while the analyst moved between screens was a genuine data race —
// the kind that shows as a page count from the wrong screen rather than a
// crash, which is worse.
//
// The fix is a seam rather than a lock. A loader now reads everything it needs
// once, on the UI goroutine, works from that copy, and writes the result back
// on the UI goroutine. Between those two points it touches nothing shared.
//
// A lock would have worked and would have been wrong: every one of these fields
// is read while a frame is being drawn, so the mutex would be held on the
// drawing path, and the next person to add a field would have to know to take
// it.

// eventQueryPlan is everything one events query needs, copied from the screen.
type eventQueryPlan struct {
	// contextID is the per-screen state this plan came from: a case's id, or
	// the all-events context.
	contextID string
	// caseID narrows the query to one case. Empty means every event.
	caseID string

	start, end time.Time
	severities []string
	types      []string

	pageSize  int
	pageIndex int
}

// planEventQuery copies the query context out of the screen.
//
// It must run on the UI goroutine. It also does the one write the plan needs —
// bridging the legacy top-level time filters into the per-context state — so
// that write happens where every other write to that state happens.
func (ui *UI) planEventQuery(contextID, caseID string) eventQueryPlan {
	s := ui.getOrInitState(contextID)

	if s.filterStart.IsZero() && !ui.filterStart.IsZero() {
		s.filterStart = ui.filterStart
	}
	if s.filterEnd.IsZero() && !ui.filterEnd.IsZero() {
		s.filterEnd = ui.filterEnd
	}

	return eventQueryPlan{
		contextID:  contextID,
		caseID:     caseID,
		start:      s.filterStart,
		end:        s.filterEnd,
		severities: keysFromMap(s.filterSeverities),
		types:      keysFromMap(s.filterTypes),
		pageSize:   s.pageSize,
		pageIndex:  s.pageIndex,
	}
}

// pageOffset clamps a page to a result set and returns the row to start at.
//
// Pure, so the arithmetic that decides which page an analyst is looking at can
// be checked without a database or a screen. It used to live inline in both
// loaders, in two copies that had drifted: one clamped the index before
// computing the offset and one after.
func pageOffset(total, pageSize, pageIndex int) (page, offset int) {
	if pageSize <= 0 {
		return 0, 0
	}
	pages := (total + pageSize - 1) / pageSize
	if pages < 1 {
		pages = 1
	}
	if pageIndex >= pages {
		pageIndex = pages - 1
	}
	if pageIndex < 0 {
		pageIndex = 0
	}
	return pageIndex, pageIndex * pageSize
}

// recordEventQuery writes a finished query's totals back to the screen.
//
// It must run on the UI goroutine.
func (ui *UI) recordEventQuery(plan eventQueryPlan, total, page int) {
	s := ui.getOrInitState(plan.contextID)
	s.totalCount = total
	s.pageIndex = page
}
