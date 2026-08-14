package ui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// The settings panel: categories on the left, rows on the right, and an
// explanation underneath whichever row the cursor is on.
//
// It replaced four unconnected places. There was a two-item panel on `,`, a
// provider form on Shift+L reachable only from inside a case, a theme key, and
// a set of command-line flags nothing surfaced at all — so the answer to "where
// do I change that" depended on which thing it was, and for half of them it was
// "you cannot".
//
// Three decisions shape it:
//
// **Every row says where its value came from.** With defaults, a config file,
// flags and choices made here, the useful question is not what can be changed
// but why a value is what it is.
//
// **A row a flag has decided is shown, not hidden, and refuses politely.** A
// control that accepts a change it cannot keep is worse than one that explains
// itself.
//
// **Changes apply and persist immediately.** There is no Save button, because a
// panel with one has a state where the screen and the file disagree.

const (
	settingsWidth      = 102
	settingsHeight     = 30
	settingsCategoryW  = 15
	settingsSourceW    = 9
	settingsDetailRows = 5
)

// settingsPanel is the open panel's state.
type settingsPanel struct {
	ui         *UI
	categories []settingsCategory
	active     int
	search     string
	searching  bool

	// painting suppresses the selection callbacks while the panel redraws.
	// tview fires SetSelectionChangedFunc from Select, and the render selects
	// — so without this the two call each other until the stack runs out.
	painting bool

	cats    *tview.Table
	rows    *tview.Table
	detail  *tview.TextView
	footer  *tview.TextView
	rowsFor []setting // what the rows table currently shows
}

// showSettings opens the panel over whatever is on screen.
func (ui *UI) showSettings() {
	p := &settingsPanel{ui: ui, categories: settingsCatalog()}
	p.build()
}

func (p *settingsPanel) build() {
	t := p.ui.theme

	p.cats = tview.NewTable().SetSelectable(true, false)
	p.cats.SetBackgroundColor(t.SurfaceRaised)
	p.cats.SetSelectedStyle(tcell.StyleDefault.
		Background(t.SelectionBg).Foreground(t.SelectionFg).Bold(true))

	p.rows = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	p.rows.SetBackgroundColor(t.SurfaceRaised)
	p.rows.SetSelectedStyle(tcell.StyleDefault.
		Background(t.SelectionBg).Foreground(t.SelectionFg))

	p.detail = tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	p.detail.SetBackgroundColor(t.SurfaceRaised)

	p.footer = tview.NewTextView().SetDynamicColors(true)
	p.footer.SetBackgroundColor(t.SurfaceRaised)

	p.rows.SetSelectionChangedFunc(func(row, _ int) {
		if !p.painting {
			p.renderDetail()
		}
	})
	p.rows.SetSelectedFunc(func(row, _ int) { p.activate() })
	p.cats.SetSelectionChangedFunc(func(row, _ int) {
		if p.painting || row < 0 || row >= len(p.categories) || row == p.active {
			return
		}
		p.active = row
		p.renderRows()
	})

	p.cats.SetInputCapture(p.key)
	p.rows.SetInputCapture(p.key)

	panes := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(p.cats, settingsCategoryW, 0, false).
		AddItem(verticalRule(t), 1, 0, false).
		AddItem(p.rows, 0, 1, true)

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(panes, 0, 1, true).
		AddItem(horizontalRule(t), 1, 0, false).
		AddItem(p.detail, settingsDetailRows, 0, false).
		AddItem(p.footer, 1, 0, false)

	p.renderCategories()
	p.renderRows()

	p.ui.overlayModal(modalPanel(body, "Settings", t), settingsWidth, settingsHeight)
	p.ui.app.SetFocus(p.rows)
}

// reopen rebuilds the panel in place after a change, so a new value, a new
// source and a new theme all land at once.
func (p *settingsPanel) reopen() {
	active, searching, search := p.active, p.searching, p.search
	row, _ := p.rows.GetSelection()

	fresh := &settingsPanel{ui: p.ui, categories: settingsCatalog(),
		active: active, searching: searching, search: search}
	fresh.build()

	if row > 0 && row < fresh.rows.GetRowCount() {
		fresh.rows.Select(row, 0)
	}
	fresh.renderDetail()
}

func (p *settingsPanel) renderCategories() {
	t := p.ui.theme
	p.painting = true
	defer func() { p.painting = false }()
	p.cats.Clear()
	for i, c := range p.categories {
		colour := t.TextMuted
		if i == p.active {
			colour = t.TextPrimary
		}
		p.cats.SetCell(i, 0, tview.NewTableCell(" "+c.name).
			SetTextColor(colour).SetExpansion(1))
	}
	if p.active >= 0 && p.active < len(p.categories) {
		p.cats.Select(p.active, 0)
	}
}

// visible is the rows the current category and search leave.
func (p *settingsPanel) visible() []setting {
	if p.search != "" {
		// Search reaches across every category — with six of them, browsing
		// stops being how you find a setting.
		var out []setting
		for _, c := range p.categories {
			for _, s := range c.settings {
				if s.matches(p.search) {
					out = append(out, s)
				}
			}
		}
		return out
	}
	if p.active < 0 || p.active >= len(p.categories) {
		return nil
	}
	return p.categories[p.active].settings
}

func (p *settingsPanel) renderRows() {
	t := p.ui.theme
	p.painting = true
	p.rows.Clear()
	p.rowsFor = p.visible()
	p.renderCategories()

	header := p.categories[p.active].blurb
	if p.search != "" {
		header = fmt.Sprintf("%s across every category", plural(len(p.rowsFor), "match"))
	}
	p.rows.SetCell(0, 0, tview.NewTableCell(" "+header).
		SetTextColor(t.TextMuted).SetSelectable(false).SetExpansion(1))
	p.rows.SetCell(0, 1, tview.NewTableCell("").SetSelectable(false))
	p.rows.SetCell(0, 2, tview.NewTableCell("").SetSelectable(false))

	if len(p.rowsFor) == 0 {
		p.rows.SetCell(1, 0, tview.NewTableCell(" Nothing matches "+p.search).
			SetTextColor(t.TextPrimary).SetSelectable(false).SetExpansion(1))
		setTableCursor(p.rows, false)
		p.painting = false
		p.renderDetail()
		return
	}
	setTableCursor(p.rows, true)

	for i, s := range p.rowsFor {
		row := i + 1
		src := s.source(p.ui)

		name := t.TextPrimary
		if s.readOnly() {
			// A row that cannot be changed reads as different before you try.
			name = t.TextMuted
		}
		p.rows.SetCell(row, 0, tview.NewTableCell(" "+s.name).SetTextColor(name))
		p.rows.SetCell(row, 1, tview.NewTableCell(
			paintTextOn(s.value(p.ui), tagColor(t.TextPrimary), t)).
			SetTextColor(t.TextPrimary).SetExpansion(1))
		// Right-aligned, and not padded: the alignment already holds the column
		// steady, and padding "you" out to nine spent six columns of the value
		// beside it — which is how the receiver's address came to be clipped.
		p.rows.SetCell(row, 2, tview.NewTableCell(
			fmt.Sprintf("[%s]%s ", src.tag(t), src.label())).
			SetAlign(tview.AlignRight).SetMaxWidth(settingsSourceW))
	}
	p.rows.Select(1, 0)
	p.painting = false
	p.renderDetail()
}

func (p *settingsPanel) current() (setting, bool) {
	row, _ := p.rows.GetSelection()
	i := row - 1
	if i < 0 || i >= len(p.rowsFor) {
		return setting{}, false
	}
	return p.rowsFor[i], true
}

func (p *settingsPanel) renderDetail() {
	t := p.ui.theme
	s, ok := p.current()
	if !ok {
		p.detail.SetText("")
		p.renderFooter()
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, " [%s::b]%s[-:-:-]\n", tagColor(t.Header), strings.ToUpper(s.name))
	for _, line := range s.explain(p.ui) {
		fmt.Fprintf(&b, " [%s]%s[-]\n", t.TagTextPrimary, line)
	}
	if s.locked != "" {
		// Why, rather than a refusal at the moment of pressing Enter.
		fmt.Fprintf(&b, " [%s]%s[-]\n", t.TagMuted, s.locked)
	}
	p.detail.SetText(b.String())
	p.renderFooter()
}

func (p *settingsPanel) renderFooter() {
	t := p.ui.theme
	acc, muted := t.TagAccent, t.TagMuted

	if p.searching {
		p.footer.SetText(fmt.Sprintf("  [%s]/%s[-]▏   [%s]⏎[-] keep   [%s]esc[-] clear",
			t.TagTextPrimary, tview.Escape(p.search), acc, acc))
		return
	}

	change := fmt.Sprintf("[%s]⏎[-] change", acc)
	if s, ok := p.current(); ok && s.readOnly() {
		change = fmt.Sprintf("[%s]⏎ set elsewhere[-]", muted)
	}
	p.footer.SetText(fmt.Sprintf(
		"  [%s]↑↓[-] move   [%s]←→[-] category   %s   [%s]/[-] search   [%s]esc[-] close",
		acc, acc, change, acc, acc))
}

// activate runs the row's edit, or explains why there is not one.
func (p *settingsPanel) activate() {
	s, ok := p.current()
	if !ok {
		return
	}
	if s.readOnly() {
		p.ui.setStatusDirect("[%s]%s[-:-:-]", p.ui.theme.TagMuted, firstSentence(s.locked))
		return
	}
	s.edit(p.ui, func() { p.reopen() })
}

func (p *settingsPanel) key(ev *tcell.EventKey) *tcell.EventKey {
	if p.searching {
		return p.searchKey(ev)
	}

	switch ev.Key() {
	case tcell.KeyEscape:
		if p.search != "" {
			p.search = ""
			p.renderRows()
			return nil
		}
		p.ui.closeModal()
		return nil
	case tcell.KeyLeft:
		p.step(-1)
		return nil
	case tcell.KeyRight:
		p.step(1)
		return nil
	case tcell.KeyTab:
		p.step(1)
		return nil
	case tcell.KeyBacktab:
		p.step(-1)
		return nil
	case tcell.KeyRune:
		switch ev.Rune() {
		case '/':
			p.searching = true
			p.renderFooter()
			return nil
		case 'q', 'Q':
			p.ui.closeModal()
			return nil
		case 'h':
			p.step(-1)
			return nil
		case 'l':
			p.step(1)
			return nil
		}
	}
	return ev
}

func (p *settingsPanel) searchKey(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEscape:
		p.searching, p.search = false, ""
		p.renderRows()
		return nil
	case tcell.KeyEnter:
		p.searching = false
		p.renderFooter()
		return nil
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if p.search != "" {
			p.search = p.search[:len(p.search)-1]
			p.renderRows()
		}
		return nil
	case tcell.KeyRune:
		p.search += string(ev.Rune())
		p.renderRows()
		return nil
	}
	return nil
}

// step moves between categories, and clears a search first: the categories
// mean nothing while a search is showing rows from all of them.
func (p *settingsPanel) step(by int) {
	if p.search != "" {
		p.search, p.searching = "", false
	}
	p.active = (p.active + by + len(p.categories)) % len(p.categories)
	p.renderRows()
	p.ui.app.SetFocus(p.rows)
}

// firstSentence trims an explanation to what fits on a status bar.
func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i+1]
	}
	return s
}

// verticalRule and horizontalRule separate the panes.
func verticalRule(t Theme) *tview.TextView {
	rule := tview.NewTextView()
	rule.SetBackgroundColor(t.SurfaceRaised)
	rule.SetDrawFunc(func(screen tcell.Screen, x, y, w, h int) (int, int, int, int) {
		glyph := '│'
		if !supportsUnicode() {
			glyph = '|'
		}
		style := tcell.StyleDefault.Foreground(t.Border).Background(t.SurfaceRaised)
		for row := y; row < y+h; row++ {
			screen.SetContent(x, row, glyph, nil, style)
		}
		return x, y, w, h
	})
	return rule
}

func horizontalRule(t Theme) *tview.TextView {
	rule := tview.NewTextView()
	rule.SetBackgroundColor(t.SurfaceRaised)
	rule.SetDrawFunc(func(screen tcell.Screen, x, y, w, h int) (int, int, int, int) {
		glyph := '─'
		if !supportsUnicode() {
			glyph = '-'
		}
		style := tcell.StyleDefault.Foreground(t.Border).Background(t.SurfaceRaised)
		for col := x; col < x+w; col++ {
			screen.SetContent(col, y, glyph, nil, style)
		}
		return x, y, w, h
	})
	return rule
}
