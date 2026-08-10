package ui

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

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

	// context holds what carries the selected indicator, and its debounce.
	context indicatorContext
}

// indicatorContext is what else in the database carries one observable.
//
// It is the answer this screen exists to give — "have I seen this before, and
// where?" — and it is the one thing the table cannot show, because it is a
// query per row rather than a column.
type indicatorContext struct {
	ui *UI

	mu       sync.Mutex
	key      string
	findings []store.Finding
	events   int
	loaded   bool
	timer    *time.Timer
}

// indicatorKey identifies an observable for the cache.
func indicatorKey(typeID int, value string) string {
	return fmt.Sprintf("%d|%s", typeID, value)
}

// schedule loads what carries an indicator, once the cursor has rested.
func (c *indicatorContext) schedule(typeID int, value string, then func()) {
	if c.ui == nil || value == "" {
		return
	}
	key := indicatorKey(typeID, value)

	c.mu.Lock()
	if c.key == key && c.loaded {
		c.mu.Unlock()
		return
	}
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timer = time.AfterFunc(homeInspectorDebounce, func() {
		c.load(typeID, value)
		c.ui.queueUpdate(then)
	})
	c.mu.Unlock()
}

// load runs the two queries. It runs off the UI goroutine.
func (c *indicatorContext) load(typeID int, value string) {
	if c.ui == nil || c.ui.store == nil {
		return
	}
	findings, _ := c.ui.store.FindFindingsByObservable(c.ui.ctx, typeID, value, indicatorCarriersShown+1)
	events, _ := c.ui.store.CountEventsByObservable(c.ui.ctx, typeID, value)

	c.mu.Lock()
	c.key, c.findings, c.events, c.loaded = indicatorKey(typeID, value), findings, events, true
	c.mu.Unlock()
}

// get returns what is known about an indicator, and whether it is this one.
func (c *indicatorContext) get(typeID int, value string) ([]store.Finding, int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded || c.key != indicatorKey(typeID, value) {
		return nil, 0, false
	}
	return c.findings, c.events, true
}

// indicatorCarriersShown is how many findings the panel names before it counts
// the rest.
const indicatorCarriersShown = 3

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

	v.context.ui = ui
	v.table.SetSelectionChangedFunc(func(int, int) {
		ui.renderIndicatorInspector()
		if ind := ui.selectedIndicator(); ind != nil {
			v.context.schedule(ind.TypeID, ind.Value, ui.renderIndicatorInspector)
		}
	})
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

// renderIndicatorInspector names what carries the selected indicator.
//
// Not the row again. It used to repeat the type, the provenance, the sightings
// and the seen range — every one of which is a column two lines above it — so
// the panel cost eight rows to say what was already on screen. What the table
// cannot show is the cross-reference: which findings carry this observable, and
// how many events, both of which are a query per row.
func (ui *UI) renderIndicatorInspector() {
	v := ui.indicators
	if v == nil {
		return
	}
	t := ui.theme

	ind := ui.selectedIndicator()
	if ind == nil {
		v.inspector.SetText(fmt.Sprintf("\n [%s]Select an indicator to see what carries it.[-:-:-]", t.TagMuted))
		return
	}

	var b strings.Builder
	// The whole value, wrapped rather than cut. A hash is only useful entire —
	// 41 of its 64 characters cannot be pasted into anything — and this panel
	// is where an analyst comes to read what the row could not show.
	b.WriteString("\n")
	for _, line := range wrapText(ind.Value, ui.inspectorWidth()-2) {
		fmt.Fprintf(&b, " [%s:-:b]%s[-:-:-]\n", t.TagTextPrimary, tview.Escape(line))
	}

	findings, events, ok := v.context.get(ind.TypeID, ind.Value)
	if !ok {
		fmt.Fprintf(&b, " [%s]looking for what carries it…[-:-:-]", t.TagMuted)
		v.inspector.SetText(b.String())
		return
	}

	shown := findings
	if len(shown) > indicatorCarriersShown {
		shown = shown[:indicatorCarriersShown]
	}
	fmt.Fprintf(&b, " [%s]carried by[-:-:-] [%s]%s[-:-:-] · [%s]%s[-:-:-]\n",
		t.TagMuted, t.TagAccent, plural(len(findings), "finding"),
		t.TagAccent, plural(events, "event"))

	for _, f := range shown {
		fmt.Fprintf(&b, "   %s  [%s]%s[-:-:-]\n",
			formatSeverityBadge(f.Severity, t),
			t.TagTextPrimary, tview.Escape(truncate(f.Title, 52)))
	}
	if extra := len(findings) - len(shown); extra > 0 {
		fmt.Fprintf(&b, "   [%s]and %d more[-:-:-]\n", t.TagMuted, extra)
	}
	if len(findings) == 0 {
		fmt.Fprintf(&b, "   [%s]No finding names it — it appears in events only.[-:-:-]\n", t.TagMuted)
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
		case 'f':
			// This screen's own filter.
			//
			// Unclaimed, f reached the global handler, which opened the events
			// filter — time, severity and event type, applied to a list of
			// observables that has none of those. F cleared the same filters.
			ui.showIndicatorTypeFilter()
			return nil
		case 'F':
			if ui.clearIndicatorFilters() {
				return nil
			}
			return ev
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

// showIndicatorTypeFilter narrows the list to particular observable types.
//
// The types offered are the ones the database actually holds: a menu listing
// every type OCSF defines would be mostly rows that match nothing here.
func (ui *UI) showIndicatorTypeFilter() {
	v := ui.indicators
	if v == nil {
		return
	}
	t := ui.theme

	types := indicatorTypesPresent(v.rows)
	if len(types) == 0 {
		ui.setStatusDirect("[%s]Nothing to filter yet[-:-:-]", t.TagMuted)
		return
	}

	active := map[int]bool{}
	for _, id := range v.filter.TypeIDs {
		active[id] = true
	}

	list := tview.NewList().ShowSecondaryText(false)
	list.SetBackgroundColor(t.SurfaceRaised)
	list.SetMainTextColor(t.TextPrimary)
	list.SetShortcutColor(t.TextMuted)
	list.SetSelectedBackgroundColor(t.SelectionBg)
	list.SetSelectedTextColor(t.SelectionFg)

	var refresh func()
	apply := func() {
		v.filter.TypeIDs = v.filter.TypeIDs[:0]
		for _, ty := range types {
			if active[ty.id] {
				v.filter.TypeIDs = append(v.filter.TypeIDs, ty.id)
			}
		}
		refresh()
		ui.spawnLoad(ui.loadIndicators)
	}

	for _, ty := range types {
		ty := ty
		list.AddItem("", "", 0, func() {
			active[ty.id] = !active[ty.id]
			apply()
		})
	}
	list.AddItem("", "", 'x', func() {
		for id := range active {
			active[id] = false
		}
		apply()
	})

	refresh = func() {
		for i, ty := range types {
			mark := "[ ]"
			if active[ty.id] {
				mark = fmt.Sprintf("[%s][✓][-:-:-]", t.TagSuccess)
			}
			list.SetItemText(i, fmt.Sprintf("%s  %s   [%s]%s[-:-:-]",
				mark, ty.name, t.TagMuted, plural(ty.count, "indicator")), "")
		}
		list.SetItemText(len(types), fmt.Sprintf("[%s]every type[-:-:-]", t.TagMuted), "")
	}
	refresh()

	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape {
			ui.closeModal()
			return nil
		}
		return ev
	})

	body := tview.NewFlex().SetDirection(tview.FlexRow)
	body.AddItem(list, len(types)+1, 0, true)
	footer := tview.NewTextView().SetDynamicColors(true)
	footer.SetBackgroundColor(t.SurfaceRaised)
	footer.SetText(fmt.Sprintf("  [%s]⏎[-:-:-] toggle   [%s]x[-:-:-] every type   [%s]esc[-:-:-] close",
		t.TagAccent, t.TagAccent, t.TagAccent))
	body.AddItem(blankRow(t.SurfaceRaised), 1, 0, false)
	body.AddItem(footer, 1, 0, false)

	ui.overlayModal(modalPanel(body, "Filter by type", t), 52, len(types)+7)
	ui.app.SetFocus(list)
}

// clearIndicatorFilters drops the type filter and the search, and says whether
// there was anything to drop.
func (ui *UI) clearIndicatorFilters() bool {
	v := ui.indicators
	if v == nil {
		return false
	}
	if len(v.filter.TypeIDs) == 0 && strings.TrimSpace(v.filter.Search) == "" {
		return false
	}
	v.filter.TypeIDs = nil
	v.filter.Search = ""
	ui.spawnLoad(ui.loadIndicators)
	return true
}

// indicatorType is one observable type and how much of the list it accounts
// for.
type indicatorType struct {
	id    int
	name  string
	count int
}

// indicatorTypesPresent lists the types in the loaded page, most common first.
func indicatorTypesPresent(rows []store.CaseIndicator) []indicatorType {
	seen := map[int]*indicatorType{}
	for _, r := range rows {
		ty, ok := seen[r.TypeID]
		if !ok {
			name := strings.TrimSpace(r.Type)
			if name == "" {
				name = ocsf.ObservableTypeName(r.TypeID)
			}
			ty = &indicatorType{id: r.TypeID, name: name}
			seen[r.TypeID] = ty
		}
		ty.count++
	}

	out := make([]indicatorType, 0, len(seen))
	for _, ty := range seen {
		out = append(out, *ty)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].name < out[j].name
	})
	return out
}
