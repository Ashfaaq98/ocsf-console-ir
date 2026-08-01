package ui

import (
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// `/` is search. `:` is command execution. They never overlap.
//
// This used to count matches without performing any: it walked the rendered
// table cells, reported "3/12 matches", and on Enter removed the input box and
// left every row in place. A search box that does not search is worse than no
// search at all, because the analyst believes the list in front of them is the
// answer to what they typed.

// searchDebounce is how long typing settles before a query is issued.
// Searching per keystroke would mean a query per character of a hostname.
const searchDebounce = 150 * time.Millisecond

// searchLimit bounds a search. "Where is this?" is a question about the first
// page, not about every row ever stored.
const searchLimit = 200

// showFilterBar opens the search field over the current collection.
func (ui *UI) showFilterBar() {
	if ui.eventList == nil || ui.mainPanel == nil {
		return
	}

	// Everything needed to put the screen back exactly as it was. Esc restores
	// this rather than reloading, so an active pivot and the scroll position
	// both survive a search that found nothing.
	restore := ui.captureSearchState()

	input := tview.NewInputField().
		SetLabel(" / ").
		SetFieldWidth(48).
		SetFieldBackgroundColor(ui.theme.SurfaceRaised).
		SetFieldTextColor(ui.theme.TextPrimary).
		SetLabelColor(ui.theme.Accent)

	// A generation counter, so a slow query for "power" cannot land after a
	// faster one for "powershell" and replace newer results with older ones.
	generation := 0

	input.SetChangedFunc(func(query string) {
		generation++
		gen := generation
		q := strings.TrimSpace(query)

		if q == "" {
			ui.searchQuery = ""
			ui.applySearchResults(restore.events, "")
			ui.setStatusDirect("[%s]Type to search · Esc to cancel[-:-:-]", ui.theme.TagMuted)
			return
		}

		go func() {
			time.Sleep(searchDebounce)
			if gen != generation {
				return
			}
			// FTS5, not a scan of the rendered cells: the index is what makes
			// this a search of the database rather than of the visible page.
			results, err := ui.store.SearchEvents(ui.ctx, q, searchLimit)
			ui.queueUpdate(func() {
				if gen != generation {
					return
				}
				if err != nil {
					ui.setStatusDirect("[%s]Search failed: %v[-:-:-]", ui.theme.TagError, err)
					return
				}
				ui.searchQuery = q
				ui.applySearchResults(results, q)
			})
		}()
	})

	input.SetDoneFunc(func(key tcell.Key) {
		ui.mainPanel.RemoveItem(input)
		ui.app.SetFocus(ui.eventList)

		if key == tcell.KeyEscape {
			ui.restoreSearchState(restore)
			ui.setStatusDirect("[%s]Search cancelled[-:-:-]", ui.theme.TagMuted)
			return
		}
		ui.setStatusDirect("[%s]%s for %q · F clears[-:-:-]",
			ui.theme.TagAccent, plural(len(ui.events), "result"), ui.searchQuery)
	})

	ui.mainPanel.AddItem(input, 1, 0, true)
	ui.app.SetFocus(input)
}

// searchState is what Esc puts back.
type searchState struct {
	events    []store.Event
	query     string
	expanded  string
	group     groupKey
	rowOffset int
	selected  int
}

func (ui *UI) captureSearchState() searchState {
	row, _ := ui.eventList.GetSelection()
	offset, _ := ui.eventList.GetOffset()
	return searchState{
		events:    ui.events,
		query:     ui.searchQuery,
		expanded:  ui.expandedCluster,
		group:     ui.eventGroup,
		rowOffset: offset,
		selected:  row,
	}
}

// restoreSearchState puts the screen back rather than reloading it. A reload
// would drop an active pivot and return the cursor to the top of a list the
// analyst had scrolled.
func (ui *UI) restoreSearchState(s searchState) {
	ui.events = s.events
	ui.searchQuery = s.query
	ui.expandedCluster = s.expanded
	ui.eventGroup = s.group
	ui.updateEventsList()
	ui.eventList.SetOffset(s.rowOffset, 0)
	if s.selected > 0 && s.selected < ui.eventList.GetRowCount() {
		ui.eventList.Select(s.selected, 0)
	}
}

// applySearchResults renders a result set, leaving the grouping alone: it is
// the analyst's choice and a search has no business discarding it.
func (ui *UI) applySearchResults(events []store.Event, query string) {
	ui.events = events
	// The previously open cluster may not exist in a new result set, so the
	// first one opens rather than none.
	ui.expandedCluster = ""
	ui.updateEventsList()

	if query != "" {
		ui.setStatusDirect("[%s]%s for %q · Enter keeps · Esc restores[-:-:-]",
			ui.theme.TagAccent, plural(len(events), "result"), query)
	}
}

// clearSearch drops the query and reloads the unsearched list.
func (ui *UI) clearSearch() {
	if ui.searchQuery == "" {
		return
	}
	ui.searchQuery = ""
	ui.switchToAllEvents()
}
