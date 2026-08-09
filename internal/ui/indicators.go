package ui

import (
	"fmt"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// The Indicators screen: every observable in the database, most widely seen
// first, and what else carries it.
//
// It used to be the case tab pointed at a loop over the case list — one
// GetCaseIndicators per case — so it showed only what had already been attached
// to a case. A database full of findings and no cases rendered an empty screen
// over a full observables table, and the Cases sidebar's own filters silently
// narrowed it. Its status line advertised watchlists, which do not exist.
//
// It had no keys, no search, no inspector, and Enter did nothing.

// indicatorPageSize bounds the query. A million distinct observables must not
// be read into a table widget.
const indicatorPageSize = 500

// indicatorsView is the screen's state.
type indicatorsView struct {
	table     *tview.Table
	inspector *tview.TextView
	root      *tview.Flex

	rows   []store.CaseIndicator
	total  int
	filter store.IndicatorFilter

	searchBar *tview.InputField
}

// switchToIndicators opens the screen.
func (ui *UI) switchToIndicators() {
	if ui.indicators == nil {
		ui.indicators = ui.buildIndicatorsView()
	}
	ui.setMainView(ui.indicators.root)
	ui.app.SetFocus(ui.indicators.table)
	ui.setStatusDirect("[%s]Indicators[-:-:-]", ui.theme.TagAccent)
	ui.spawnLoad(ui.loadIndicators)
}

func (ui *UI) buildIndicatorsView() *indicatorsView {
	t := ui.theme
	v := &indicatorsView{}

	v.table = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	// The same bar as the findings queue: this table holds up to
	// indicatorPageSize rows and had no position indicator either.
	attachTableScrollbar(v.table, 1, &ui.theme)
	stylePanel(v.table.Box, "INDICATORS", PanelRolePrimary, t)
	v.table.SetBackgroundColor(t.Bg)
	v.table.SetSelectedStyle(tcell.StyleDefault.
		Background(t.SelectionBg).Foreground(t.SelectionFg))

	v.inspector = tview.NewTextView().SetDynamicColors(true)
	v.inspector.SetWrap(false)
	stylePanel(v.inspector.Box, "SELECTED INDICATOR", PanelRoleInspector, t)
	v.inspector.SetBackgroundColor(t.Surface)

	v.table.SetSelectionChangedFunc(func(int, int) { ui.renderIndicatorInspector() })
	v.table.SetSelectedFunc(func(int, int) { ui.pivotSelectedIndicator() })

	v.root = tview.NewFlex().SetDirection(tview.FlexRow)
	v.root.SetBackgroundColor(t.Bg)
	v.root.AddItem(v.table, 0, 3, true)
	v.root.AddItem(v.inspector, indicatorInspectorRows, 0, false)
	return v
}

// indicatorInspectorRows is the detail panel's height: the value, what carries
// it, where it has been seen, and the pivot — plus its border.
const indicatorInspectorRows = 9

// loadIndicators queries the whole database, off the UI goroutine.
func (ui *UI) loadIndicators() {
	if ui.store == nil || ui.indicators == nil {
		return
	}
	v := ui.indicators
	f := v.filter
	f.Limit = indicatorPageSize

	rows, err := ui.store.ListIndicators(ui.ctx, f)
	if err != nil {
		ui.queueUpdate(func() {
			ui.setStatusDirect("[%s]Could not load indicators: %v[-:-:-]", ui.theme.TagError, err)
		})
		return
	}
	total, _ := ui.store.CountIndicators(ui.ctx, f)

	ui.queueUpdate(func() {
		v.rows, v.total = rows, total
		ui.renderIndicators()
	})
}

func (ui *UI) renderIndicators() {
	v := ui.indicators
	if v == nil {
		return
	}

	renderCaseIndicators(v.table, v.rows, ui.theme, ui.indicatorsEmptyState())

	title := fmt.Sprintf("INDICATORS  ·  %d", len(v.rows))
	if v.total > len(v.rows) {
		title = fmt.Sprintf("INDICATORS  ·  %d of %d", len(v.rows), v.total)
	}
	if q := strings.TrimSpace(v.filter.Search); q != "" {
		title += fmt.Sprintf(`  ·  matching "%s"`, q)
	}
	stylePanel(v.table.Box, title, PanelRolePrimary, ui.theme)

	if len(v.rows) > 0 {
		v.table.Select(1, 0)
	}
	ui.renderIndicatorInspector()
}

// indicatorsEmptyState explains an empty screen for the reason it is empty.
func (ui *UI) indicatorsEmptyState() []string {
	if q := strings.TrimSpace(ui.indicators.filter.Search); q != "" {
		return []string{
			fmt.Sprintf("Nothing matches %q.", q),
			"",
			"Press / to search again, or Esc in the field to clear it.",
		}
	}
	return []string{
		"No indicators yet.",
		"",
		"Indicators are the observables on every event and finding in this",
		"database — hosts, addresses, users, hashes. Ingest evidence and they",
		"appear here without being attached to anything.",
	}
}

// selectedIndicator is the row under the cursor.
func (ui *UI) selectedIndicator() *store.CaseIndicator {
	v := ui.indicators
	if v == nil {
		return nil
	}
	row, _ := v.table.GetSelection()
	if row <= 0 || row-1 >= len(v.rows) {
		return nil
	}
	return &v.rows[row-1]
}

// renderIndicatorInspector paints what carries the selected indicator.
func (ui *UI) renderIndicatorInspector() {
	v := ui.indicators
	if v == nil {
		return
	}
	t := ui.theme

	ind := ui.selectedIndicator()
	if ind == nil {
		v.inspector.SetText(fmt.Sprintf("\n [%s]Select an indicator to see where it appears.[-:-:-]", t.TagMuted))
		return
	}

	glyph, colour, label := provenanceMark(ind.Source, t)
	typeName := ind.Type
	if strings.TrimSpace(typeName) == "" {
		typeName = ocsf.ObservableTypeName(ind.TypeID)
	}

	var b strings.Builder
	fmt.Fprintf(&b, " [%s:-:b]%s[-:-:-]   [%s]%s[-:-:-]   [%s]%s %s[-:-:-]\n\n",
		t.TagTextPrimary, tview.Escape(ind.Value),
		t.TagMuted, tview.Escape(typeName),
		colour, glyph, label)

	fmt.Fprintf(&b, " [%s]%-10s[-:-:-] %s\n", t.TagMuted, "sightings",
		fmt.Sprintf("%d", ind.Sightings))
	fmt.Fprintf(&b, " [%s]%-10s[-:-:-] %s → %s\n", t.TagMuted, "seen",
		stampOrDash(ind.FirstSeen), stampOrDash(ind.LastSeen))

	// What carries it. This is the question the screen exists to answer, and
	// the counts come from queries that already existed and had no caller here.
	if ui.store != nil {
		findings, _ := ui.store.CountFindingsByObservable(ui.ctx, ind.TypeID, ind.Value)
		events, _ := ui.store.CountEventsByObservable(ui.ctx, ind.TypeID, ind.Value)
		fmt.Fprintf(&b, " [%s]%-10s[-:-:-] %s · %s\n", t.TagMuted, "carried by",
			plural(findings, "finding"), plural(events, "event"))
	}

	fmt.Fprintf(&b, "\n [%s]⏎ pivot to the events carrying it[-:-:-]", t.TagAccent)
	v.inspector.SetText(b.String())
}

// pivotSelectedIndicator opens the events carrying the selected indicator.
//
// The case tab has had this since it was built; the cross-case screen, where it
// matters more, had no Enter at all.
func (ui *UI) pivotSelectedIndicator() {
	ind := ui.selectedIndicator()
	if ind == nil {
		return
	}
	ui.pivotTo(pivotTarget{
		TypeID: ind.TypeID,
		Value:  ind.Value,
		Kind:   orDash(ind.Type),
	})
}

// indicatorKeys are the screen's own.
func (ui *UI) indicatorKeys(ev *tcell.EventKey) *tcell.EventKey {
	if ui.indicators == nil {
		return ev
	}
	switch ev.Key() {
	case tcell.KeyEnter:
		ui.pivotSelectedIndicator()
		return nil
	case tcell.KeyRune:
		switch ev.Rune() {
		case 'p':
			ui.pivotSelectedIndicator()
			return nil
		case '/':
			ui.showIndicatorSearch()
			return nil
		case 'r':
			ui.spawnLoad(ui.loadIndicators)
			return nil
		}
	}
	return ev
}

// showIndicatorSearch filters the list by value.
func (ui *UI) showIndicatorSearch() {
	v := ui.indicators
	if v == nil || v.root == nil {
		return
	}

	input := tview.NewInputField().
		SetLabel(" / ").
		SetText(v.filter.Search).
		SetFieldBackgroundColor(ui.theme.SurfaceRaised).
		SetFieldTextColor(ui.theme.TextPrimary).
		SetLabelColor(ui.theme.Accent)
	input.SetBackgroundColor(ui.theme.Bg)

	close := func() {
		v.searchBar = nil
		v.root.Clear()
		v.root.AddItem(v.table, 0, 3, true)
		v.root.AddItem(v.inspector, indicatorInspectorRows, 0, false)
		ui.app.SetFocus(v.table)
	}

	input.SetDoneFunc(func(key tcell.Key) {
		switch key {
		case tcell.KeyEscape:
			v.filter.Search = ""
			close()
			ui.spawnLoad(ui.loadIndicators)
		case tcell.KeyEnter:
			v.filter.Search = input.GetText()
			close()
			ui.spawnLoad(ui.loadIndicators)
		}
	})

	v.searchBar = input
	v.root.Clear()
	v.root.AddItem(input, 1, 0, true)
	v.root.AddItem(v.table, 0, 3, false)
	v.root.AddItem(v.inspector, indicatorInspectorRows, 0, false)
	ui.app.SetFocus(input)
}
