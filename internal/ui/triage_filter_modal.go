package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Triage's filter panel.
//
// It was a list of four toggles on a root of its own: choosing one closed the
// panel and re-queried, so setting two filters meant opening it twice, the
// saved views could not be reached from it at all, the search lived somewhere
// else entirely, and while it was open the queue it was narrowing was not on
// screen.
//
// This is one panel over the live screen. Every filter the state model has is
// in it, each one applies as it is toggled, and the queue behind redraws — so
// the effect of a filter is visible while it is being chosen rather than after
// the panel has gone.

// triageFilterModal is the panel's widgets and the rows it can toggle.
type triageFilterModal struct {
	ui    *UI
	list  *tview.List
	input *tview.InputField
	count *tview.TextView

	// searchTimer debounces the field, so a query does not run per keystroke.
	searchTimer *time.Timer
}

// The panel's size. Given rather than measured: tview reports a rect a frame
// late, so a self-sizing modal would open at zero height.
const (
	filterModalWidth  = 64
	filterModalHeight = 15
)

// filterRowView is the saved-view row, above the chips.
const filterRowView = 0

// showTriageFilter opens the filter panel over the queue.
func (ui *UI) showTriageFilter() {
	t := ui.theme
	m := &triageFilterModal{ui: ui}

	m.list = tview.NewList().ShowSecondaryText(false)
	m.list.SetBackgroundColor(t.SurfaceRaised)
	m.list.SetMainTextColor(t.TextPrimary)
	m.list.SetShortcutColor(t.TextMuted)
	m.list.SetSelectedBackgroundColor(t.SelectionBg)
	m.list.SetSelectedTextColor(t.SelectionFg)

	// The saved view first: it is the coarse choice, and the chips below it are
	// the adjustments to it.
	m.list.AddItem("", "", 'v', func() { m.cycleView(1) })
	for _, c := range triageChips() {
		c := c
		m.list.AddItem("", "", filterShortcut(c.id), func() { m.toggleChip(c.id) })
	}
	m.list.AddItem("", "", 'x', func() { m.clear() })

	// Left and right cycle the saved view, which is the one row that is a
	// choice among several rather than an on/off.
	m.list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEscape:
			ui.closeModal()
			return nil
		case tcell.KeyTab, tcell.KeyBacktab:
			ui.app.SetFocus(m.input)
			return nil
		case tcell.KeyLeft, tcell.KeyRight:
			if m.list.GetCurrentItem() == filterRowView {
				if ev.Key() == tcell.KeyLeft {
					m.cycleView(-1)
				} else {
					m.cycleView(1)
				}
				return nil
			}
		case tcell.KeyRune:
			// Space toggles what the cursor is on, as it does in the queue.
			if ev.Rune() == ' ' {
				m.activate(m.list.GetCurrentItem())
				return nil
			}
		}
		return ev
	})

	m.input = tview.NewInputField().
		SetLabel("  search  ").
		SetText(ui.triageFilterState().search).
		SetFieldWidth(0).
		SetPlaceholder("title, host, user, analytic…").
		SetFieldBackgroundColor(t.Surface).
		SetFieldTextColor(t.TextPrimary).
		SetLabelColor(t.TextMuted)
	m.input.SetPlaceholderTextColor(t.TextMuted)
	m.input.SetPlaceholderStyle(tcell.StyleDefault.
		Background(t.Surface).Foreground(t.TextMuted))
	m.input.SetBackgroundColor(t.SurfaceRaised)
	m.input.SetChangedFunc(m.searchChanged)
	m.input.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEscape:
			ui.closeModal()
			return nil
		case tcell.KeyTab, tcell.KeyBacktab, tcell.KeyEnter:
			ui.app.SetFocus(m.list)
			return nil
		}
		return ev
	})

	m.count = tview.NewTextView().SetDynamicColors(true)
	m.count.SetBackgroundColor(t.SurfaceRaised)

	footer := tview.NewTextView().SetDynamicColors(true)
	footer.SetBackgroundColor(t.SurfaceRaised)
	footer.SetText(fmt.Sprintf(
		"  [%s]⏎[-:-:-] toggle   [%s]←→[-:-:-] view   [%s]⇥[-:-:-] search   [%s]x[-:-:-] clear   [%s]esc[-:-:-] close",
		t.TagAccent, t.TagAccent, t.TagAccent, t.TagAccent, t.TagAccent))

	body := tview.NewFlex().SetDirection(tview.FlexRow)
	body.AddItem(m.list, len(triageChips())+2, 0, true)
	body.AddItem(blankRow(t.SurfaceRaised), 1, 0, false)
	body.AddItem(m.input, 1, 0, false)
	body.AddItem(blankRow(t.SurfaceRaised), 1, 0, false)
	body.AddItem(m.count, 1, 0, false)
	body.AddItem(footer, 1, 0, false)

	ui.filterModal = m
	m.refresh()
	ui.overlayModal(modalPanel(body, "Filter findings", t), filterModalWidth, filterModalHeight)
	ui.app.SetFocus(m.list)
}

// blankRow is a spacer that paints the panel's own background.
//
// A Flex does not clear, so an empty row in one is a hole through to the screen
// behind it.
func blankRow(colour tcell.Color) *tview.Box {
	b := tview.NewBox()
	b.SetBackgroundColor(colour)
	return b
}

// filterShortcut is the key that toggles a chip from the panel — the same key
// the screen itself uses where it has one.
func filterShortcut(id chipID) rune {
	switch id {
	case chipOpen:
		return 'o'
	case chipSeverityHigh:
		return 's'
	case chipLast24h:
		return 't'
	case chipHasIOC:
		return 'i'
	}
	return 0
}

// activate runs the row's action, for Space as well as Enter.
func (m *triageFilterModal) activate(row int) {
	if row == filterRowView {
		m.cycleView(1)
		return
	}
	chips := triageChips()
	if row-1 < len(chips) {
		m.toggleChip(chips[row-1].id)
		return
	}
	m.clear()
}

// toggleChip flips one filter and re-queries behind the panel.
//
// The panel repaints before the query is spawned, not after: the query runs on
// its own goroutine and repaints the count itself when it lands, so refreshing
// afterwards would be two goroutines painting the same widgets.
func (m *triageFilterModal) toggleChip(id chipID) {
	m.ui.triageFilterState().toggle(id)
	m.ui.repaintTriageChrome()
	m.refresh()
	m.ui.spawnLoad(m.ui.loadFindings)
}

// cycleView moves through the saved views, in either direction.
func (m *triageFilterModal) cycleView(step int) {
	f := m.ui.triageFilterState()
	views := savedViews()

	// The cycle runs through the saved views and then through "no view at all",
	// which is every finding — otherwise the panel can reach a filtered state
	// it cannot leave except by clearing everything.
	next := f.view + step
	switch {
	case f.view == viewNone && step > 0:
		next = 0
	case f.view == viewNone && step < 0:
		next = len(views) - 1
	case next >= len(views), next < 0:
		next = viewNone
	}

	if next == viewNone {
		f.view = viewNone
		f.active = map[chipID]bool{}
	} else {
		f.applyView(next)
	}
	m.ui.repaintTriageChrome()
	m.refresh()
	m.ui.spawnLoad(m.ui.loadFindings)
}

// clear drops every filter, including the search field.
func (m *triageFilterModal) clear() {
	m.ui.triageFilterState().clear()
	m.ui.repaintTriageChrome()
	m.input.SetText("")
	m.refresh()
	m.ui.spawnLoad(m.ui.loadFindings)
}

// searchChanged applies the field, debounced.
func (m *triageFilterModal) searchChanged(q string) {
	if m.searchTimer != nil {
		m.searchTimer.Stop()
	}
	// The same generation counter the search bar uses: a slow query for an
	// earlier prefix must not overwrite the results for what is in the field
	// now.
	m.ui.triageSearchGen++
	gen := m.ui.triageSearchGen
	m.searchTimer = time.AfterFunc(searchDebounce, func() {
		m.ui.queueUpdate(func() {
			if gen != m.ui.triageSearchGen || m.ui.filterModal != m {
				return
			}
			m.ui.triageFilterState().search = q
			m.ui.repaintTriageChrome()
			m.ui.spawnLoad(m.ui.loadFindings)
		})
	})
}

// refresh redraws the panel from the filter state.
func (m *triageFilterModal) refresh() {
	if m == nil || m.list == nil {
		return
	}
	t := m.ui.theme
	f := m.ui.triageFilterState()

	m.list.SetItemText(filterRowView,
		fmt.Sprintf("[%s]saved view[-:-:-]   ‹ [%s]%s[-:-:-] ›", t.TagMuted, t.TagAccent, f.viewName()), "")

	for i, c := range triageChips() {
		mark := "[ ]"
		if f.active[c.id] {
			mark = fmt.Sprintf("[%s][✓][-:-:-]", t.TagSuccess)
		}
		m.list.SetItemText(i+1, mark+"  "+c.label, "")
	}
	m.list.SetItemText(len(triageChips())+1,
		fmt.Sprintf("[%s]clear everything[-:-:-]", t.TagMuted), "")

	m.refreshCount()
}

// refreshCount says how much of the database the filters leave.
//
// The panel sits over the queue, so the number is the queue's own: it is what
// the rows behind the panel already show, said in one line for the case where
// the panel covers them.
func (m *triageFilterModal) refreshCount() {
	if m == nil || m.count == nil {
		return
	}
	t := m.ui.theme
	shown, all := len(m.ui.findings), m.ui.findingsUnfiltered

	line := fmt.Sprintf("  [%s]%d[-:-:-] of [%s]%d[-:-:-] findings", t.TagAccent, shown, t.TagMuted, all)
	if shown == all {
		line = fmt.Sprintf("  [%s]all %d[-:-:-] findings", t.TagAccent, all)
	}
	if d := activeFilterSummary(m.ui); d != "" {
		line += fmt.Sprintf("   [%s]%s[-:-:-]", t.TagMuted, tview.Escape(d))
	}
	m.count.SetText(line)
}

// activeFilterSummary names the active filters, or nothing when none are.
func activeFilterSummary(ui *UI) string {
	d := strings.TrimSpace(ui.triageFilterState().describe())
	if d == "All findings" {
		return ""
	}
	return d
}
