package ui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// The Welcome Screen's layout: two columns on one page.
//
// The brand is on the left and the choices are on the right, and the brand does
// not move. Every state — the menu, a path prompt, work in progress, a failure —
// changes only the right column, so the page never reflows and the screen never
// has to be told to clear up after itself.
//
// This replaced a centred card. The card stacked the same content, ran to
// fourteen rows, changed height with its state, and left the rest of a wide
// terminal empty.

// Page geometry.
const (
	// welcomePageIndent is the left margin before the brand column.
	welcomePageIndent = 4
	// welcomePageMargin is kept clear on the right.
	welcomePageMargin = 2
	// welcomeGutter is the space the divider sits in, between the columns.
	welcomeGutter = 5
	// welcomeDivider separates the columns. It is deliberately lighter than a
	// border: the two columns are one page, not two panels.
	welcomeDivider = "╎"
	// welcomeDividerASCII is the same rule for a terminal without box drawing.
	welcomeDividerASCII = ":"
	// welcomeStackedGap separates the brand from the choices when the page is
	// too narrow for two columns and they stack instead.
	welcomeStackedGap = 1
)

// welcomeAnchor is where the page sits vertically, in percent of the free rows
// above it. True centring leaves as much space above the page as below, which
// on a tall terminal reads as a small block floating in a void; a little above
// centre reads as composed.
const welcomeAnchor = 38

// welcomeCell is one column's content for one row: the string that reaches the
// screen, and how many columns it occupies once the markup is gone.
//
// The two are tracked separately because they disagree. A tagged string's
// length counts "[yellow]" and "[-:-:-]", none of which is drawn, so padding
// computed from it aligns nothing.
type welcomeCell struct {
	text  string
	width int
}

// textCell is a plain run of text in one colour.
func textCell(s, tag string) welcomeCell {
	return welcomeCell{
		text:  fmt.Sprintf("[%s]%s[-:-:-]", tag, tview.Escape(s)),
		width: len([]rune(s)),
	}
}

// bulletCell is a claim the product makes about itself, marked as one.
func bulletCell(s, tag string) welcomeCell {
	return welcomeCell{
		text:  fmt.Sprintf("[%s]%s %s[-:-:-]", tag, welcomeBullet(), tview.Escape(s)),
		width: len([]rune(s)) + 2,
	}
}

func welcomeBullet() string {
	if supportsUnicode() {
		return "▪"
	}
	return "*"
}

func welcomeDividerRune() string {
	if supportsUnicode() {
		return welcomeDivider
	}
	return welcomeDividerASCII
}

// tagColor renders a theme colour as a dynamic-colour tag value.
//
// The Theme carries ready-made tag strings for the foreground palette only, and
// this screen needs backgrounds too — the key caps and the selection band are
// both defined by what is behind the text. Deriving them here beats adding
// three fields to six theme builders for one screen's use.
func tagColor(c tcell.Color) string {
	h := c.Hex()
	if h < 0 {
		// Not an RGB colour: let the tag fall back to the terminal's default
		// rather than emitting a value tview would read as garbage.
		return "-"
	}
	return fmt.Sprintf("#%06x", h)
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

// pageRows is the whole page, one string per row.
//
// Every row is composed here into a single string rather than laid out from
// several widgets, because tview's escaped-tag state leaks between the lines of
// one TextView: a block written as a single multi-line widget renders with a
// character of the previous line's colour tag bleeding onto each row after it.
// One string per row, one single-line widget per string, and the state resets.
func (v *welcomeView) pageRows() []string {
	left, right := v.leftColumn(), v.rightColumn()
	if v.splitFits(left, right) {
		return v.splitRows(left, right)
	}
	return v.stackedRows(left, right)
}

// splitFits reports whether both columns fit side by side.
//
// The question is asked of the content's own measured width rather than of a
// layout tier, so the page falls back for the reason the fallback exists — the
// text would not fit — and stays right if the copy changes.
func (v *welcomeView) splitFits(left, right []welcomeCell) bool {
	return v.splitWidth(left, right) <= v.width
}

func (v *welcomeView) splitWidth(left, right []welcomeCell) int {
	return welcomePageIndent + widestCell(left) + welcomeGutter +
		widestCell(right) + welcomePageMargin
}

// splitRows lays the columns side by side with the divider between them.
func (v *welcomeView) splitRows(left, right []welcomeCell) []string {
	leftWidth := widestCell(left)
	rows := len(left)
	if len(right) > rows {
		rows = len(right)
	}

	// The divider spans the rows the columns share and stops there, so it reads
	// as a rule between two blocks of text rather than as the edge of a panel.
	dividerFrom, dividerTo := 0, rows-1

	out := make([]string, 0, rows)
	for i := 0; i < rows; i++ {
		out = append(out, v.splitRow(cellAt(left, i), cellAt(right, i), leftWidth,
			i >= dividerFrom && i <= dividerTo))
	}
	return out
}

// splitRow is one row of the split page.
func (v *welcomeView) splitRow(left, right welcomeCell, leftWidth int, divider bool) string {
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", welcomePageIndent))
	b.WriteString(left.text)
	b.WriteString(strings.Repeat(" ", leftWidth-left.width))

	if divider {
		pad := (welcomeGutter - 1) / 2
		b.WriteString(strings.Repeat(" ", pad))
		fmt.Fprintf(&b, "[%s]%s[-:-:-]", v.theme.TagMuted, welcomeDividerRune())
		b.WriteString(strings.Repeat(" ", welcomeGutter-1-pad))
	} else {
		b.WriteString(strings.Repeat(" ", welcomeGutter))
	}

	b.WriteString(right.text)
	return b.String()
}

// stackedRows is the narrow page: the brand, then the choices beneath it.
func (v *welcomeView) stackedRows(left, right []welcomeCell) []string {
	out := make([]string, 0, len(left)+len(right)+welcomeStackedGap)
	indent := strings.Repeat(" ", v.stackedIndent(left, right))
	for _, c := range left {
		out = append(out, indent+c.text)
	}
	for i := 0; i < welcomeStackedGap; i++ {
		out = append(out, "")
	}
	for _, c := range right {
		out = append(out, indent+c.text)
	}
	return out
}

// stackedIndent narrows the margin on a terminal that cannot spare it, rather
// than letting the content run off the right-hand edge.
func (v *welcomeView) stackedIndent(left, right []welcomeCell) int {
	widest := widestCell(left)
	if w := widestCell(right); w > widest {
		widest = w
	}
	for indent := welcomePageIndent; indent > 1; indent-- {
		if indent+widest+welcomePageMargin <= v.width {
			return indent
		}
	}
	return 1
}

func widestCell(cells []welcomeCell) int {
	widest := 0
	for _, c := range cells {
		if c.width > widest {
			widest = c.width
		}
	}
	return widest
}

// cellAt is the cell for a row, or an empty one where that column has run out.
func cellAt(cells []welcomeCell, i int) welcomeCell {
	if i < len(cells) {
		return cells[i]
	}
	return welcomeCell{}
}

// ---------------------------------------------------------------------------
// The columns
// ---------------------------------------------------------------------------

// leftColumn is the brand, and it is the same in every state. Holding it still
// is what keeps the page from reflowing when an action starts, fails, or asks
// for a path.
func (v *welcomeView) leftColumn() []welcomeCell {
	t := v.theme
	cells := v.wordmarkCells()
	cells = append(cells,
		welcomeCell{},
		textCell(v.identityLine(), t.TagMuted),
		welcomeCell{},
		textCell(welcomeDescription, t.TagTextPrimary),
	)

	if !v.short {
		// The privacy statement is the product's main claim about itself, so it
		// is dropped only when there is genuinely no room for it.
		cells = append(cells,
			welcomeCell{},
			bulletCell(welcomePrivacyA, t.TagMuted),
			bulletCell(welcomePrivacyB, t.TagMuted),
		)
	}
	return cells
}

// rightColumn is what this state is asking of the analyst.
func (v *welcomeView) rightColumn() []welcomeCell {
	switch v.state {
	case welcomeStatePrompt:
		return v.promptCells()
	case welcomeStateLoading:
		return v.loadingCells()
	case welcomeStateError:
		return v.errorCells()
	default:
		return v.actionCells()
	}
}

// promptCells asks for the path the chosen action needs. The row the input
// field occupies is empty here and filled with the widget itself; see setPage.
func (v *welcomeView) promptCells() []welcomeCell {
	t := v.theme
	return []welcomeCell{
		textCell(v.promptLabel(), t.TagTextPrimary),
		{},
		{}, // the input field's row
		{},
		textCell("⏎ continue    esc back", t.TagMuted),
	}
}

// promptFieldRow is the index within the right column of the input field's row.
const promptFieldRow = 2

// loadingCells reports work in flight where the actions were, which is where
// the analyst was already looking.
func (v *welcomeView) loadingCells() []welcomeCell {
	return []welcomeCell{{
		text:  loadingState(v.loading, v.theme),
		width: len([]rune(v.loading)) + 2,
	}}
}

// errorCells explains the failure and the two ways out of it.
//
// The path is part of the explanation, not a detail: "could not create the
// database" is unactionable without knowing where it was attempted.
func (v *welcomeView) errorCells() []welcomeCell {
	t := v.theme
	cells := []welcomeCell{
		textCell("✕  Could not "+v.pending.Action.verb()+".", t.TagError),
		{},
	}
	for _, l := range wrapText(v.errorText(), v.errorWidth()) {
		cells = append(cells, textCell(l, t.TagTextPrimary))
	}
	cells = append(cells, welcomeCell{})
	for _, l := range wrapText(v.attemptedPath(), v.errorWidth()) {
		cells = append(cells, textCell(l, t.TagMuted))
	}
	return append(cells,
		welcomeCell{},
		actionCell('r', "Retry", t, false),
		actionCell('q', "Quit", t, false),
	)
}

// errorWidth is how wide the failure text may wrap: whatever the terminal has
// left once the brand column and the margins have taken theirs.
func (v *welcomeView) errorWidth() int {
	w := v.width - welcomePageIndent - widestCell(v.leftColumn()) -
		welcomeGutter - welcomePageMargin
	if w < 24 {
		return 24
	}
	if w > 56 {
		return 56
	}
	return w
}
