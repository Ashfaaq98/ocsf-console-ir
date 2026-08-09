package ui

import (
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Triage's own filter and search.
//
// The chip row above the queue draws four filters and only one of them had a
// key: `o` toggles Open, and Sev ≥ High, Last 24h and Has IOC were rendered,
// applied by the query builder, and reachable by nothing. `f` printed an inert
// sentence about which keys existed.
//
// And `/` opened the events search — full-text over the events table — which
// repainted the shared table as an events list underneath Triage's own chip row
// and selection strip. triageFilter.search was never written by anything, even
// though FindingFilter.Search and GetFindings both honour it.

// showTriageChips opens the filter menu.
//
// A list rather than four more keys: the chips are a set that will grow, and a
// menu keeps `f` meaning "filter" on every screen. `o` stays as the fast path
// for the one that is toggled constantly.
func (ui *UI) showTriageChips() {
	state := ui.triageFilterState()

	list := tview.NewList().ShowSecondaryText(false)
	list.SetBorder(true).SetTitle(" Filter findings ")
	list.SetBackgroundColor(ui.theme.SurfaceRaised)
	list.SetMainTextColor(ui.theme.TextPrimary)
	list.SetSelectedBackgroundColor(ui.theme.SelectionBg)
	list.SetSelectedTextColor(ui.theme.SelectionFg)

	for _, c := range triageChips() {
		c := c
		mark := "  "
		if state.active[c.id] {
			mark = "✓ "
		}
		list.AddItem(mark+c.label, "", 0, func() {
			ui.closeModal()
			ui.toggleTriageChip(c.id)
		})
	}

	list.AddItem("  — clear all —", "", 0, func() {
		ui.closeModal()
		ui.clearTriageFilters()
	})

	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape {
			ui.closeModal()
			return nil
		}
		return ev
	})

	ui.rootModal(centredModal(list, 40, len(triageChips())+3))
	ui.app.SetFocus(list)
}

// centredModal centres a primitive on an otherwise empty canvas.
func centredModal(p tview.Primitive, width, height int) tview.Primitive {
	row := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(p, height, 0, true).
		AddItem(nil, 0, 1, false)
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(row, width, 0, true).
		AddItem(nil, 0, 1, false)
}

// showTriageSearch opens a search field over the findings queue.
//
// It searches findings. `/` used to open the events search here, which replaced
// the queue with an events list while the chip row and the selection strip
// stayed on screen describing a queue that was no longer there.
func (ui *UI) showTriageSearch() {
	if ui.mainPanel == nil {
		return
	}
	state := ui.triageFilterState()

	input := tview.NewInputField().
		SetLabel(" / ").
		SetText(state.search).
		SetFieldBackgroundColor(ui.theme.SurfaceRaised).
		SetFieldTextColor(ui.theme.TextPrimary).
		SetLabelColor(ui.theme.Accent)
	input.SetBackgroundColor(ui.theme.Bg)

	// A generation counter, as the events search uses: a slow query for an
	// earlier prefix must not overwrite the results for what is on screen now.
	ui.triageSearchGen++
	gen := ui.triageSearchGen
	var timer *time.Timer

	apply := func(q string) {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(searchDebounce, func() {
			ui.queueUpdate(func() {
				if gen != ui.triageSearchGen {
					return
				}
				state.search = q
				ui.repaintTriageChrome()
				ui.spawnLoad(ui.loadFindings)
			})
		})
	}

	input.SetChangedFunc(apply)
	input.SetDoneFunc(func(key tcell.Key) {
		if timer != nil {
			timer.Stop()
		}
		switch key {
		case tcell.KeyEscape:
			// Escape abandons the search rather than leaving the queue filtered
			// by something the analyst has stopped looking at.
			ui.triageSearchGen++
			state.search = ""
			ui.closeTriageSearch()
			ui.repaintTriageChrome()
			ui.spawnLoad(ui.loadFindings)
		case tcell.KeyEnter:
			state.search = input.GetText()
			ui.closeTriageSearch()
			ui.repaintTriageChrome()
			ui.spawnLoad(ui.loadFindings)
		}
	})

	ui.triageSearchBar = input
	ui.mainPanel.Clear()
	ui.restoreTriageBody()
	// At the foot, beside the keys, where a prompt belongs — and where it does
	// not push the queue down a row the moment it opens.
	ui.mainPanel.AddItem(input, 1, 0, true)
	ui.app.SetFocus(input)
}

// closeTriageSearch removes the search field and returns focus to the queue.
func (ui *UI) closeTriageSearch() {
	ui.triageSearchBar = nil
	ui.restoreEventsView()
	ui.app.SetFocus(ui.eventList)
}

// restoreTriageBody rebuilds the queue above the search field.
func (ui *UI) restoreTriageBody() {
	ui.mainPanel.AddItem(ui.triageChipRow(), 1, 0, false)
	ui.mainPanel.AddItem(ui.eventList, 0, 2, false)
	ui.mainPanel.AddItem(ui.eventDetail, 0, 1, false)
	ui.mainPanel.AddItem(ui.strip, 1, 0, false)
}
