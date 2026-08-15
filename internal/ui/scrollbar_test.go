package ui

import (
	"strings"
	"testing"

	"github.com/rivo/tview"
)

// A pane that fits its content shows no bar.
//
// A full-height thumb on a pane that does not scroll is a control that does
// nothing, which is worse than none at all.
func TestScrollbarIsAbsentWhenEverythingFits(t *testing.T) {
	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetBorder(true)
	attachScrollbar(tv, ptrTheme(themeDark()))
	tv.SetText("one\ntwo\nthree")

	lines := renderPrimitive(t, tv, 40, 10)
	for _, l := range lines {
		if strings.Contains(l, scrollThumb) {
			t.Errorf("a scrollbar was drawn on a pane that fits its content:\n%s",
				strings.Join(lines, "\n"))
		}
	}
}

// A pane that holds more than it can show says so.
func TestScrollbarAppearsWhenContentOverflows(t *testing.T) {
	requireUnicode(t)

	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetBorder(true)
	attachScrollbar(tv, ptrTheme(themeDark()))
	tv.SetText(strings.Repeat("a line of text\n", 60))

	lines := renderPrimitive(t, tv, 40, 10)
	found := false
	for _, l := range lines {
		if strings.Contains(l, scrollThumb) {
			found = true
		}
	}
	if !found {
		t.Errorf("no scrollbar on a pane holding sixty lines in ten rows:\n%s",
			strings.Join(lines, "\n"))
	}
}

// The thumb moves with the scroll, and reaches the bottom exactly when the
// content does — computed from the last reachable offset, not from the total,
// because a pane scrolled to the end still shows a screenful.
func TestScrollThumbTracksThePosition(t *testing.T) {
	const height, total = 10, 100

	top, _ := scrollThumbBounds(height, 0, total)
	_, atTop := scrollThumbBounds(height, 0, total)
	if atTop != 0 {
		t.Errorf("at the top the thumb sits at row %d, want 0", atTop)
	}

	size, atEnd := scrollThumbBounds(height, total-height, total)
	if atEnd+size != height {
		t.Errorf("at the end the thumb ends at row %d, want the track's %d", atEnd+size, height)
	}

	_, middle := scrollThumbBounds(height, (total-height)/2, total)
	if middle <= atTop || middle >= atEnd {
		t.Errorf("halfway down the thumb is at %d, not between %d and %d", middle, atTop, atEnd)
	}
	if top < 1 {
		t.Error("the thumb has no height")
	}
}

// However long the document, the thumb stays visible and inside the track.
func TestScrollThumbStaysWithinTheTrack(t *testing.T) {
	for _, total := range []int{11, 50, 1000, 100000} {
		for _, offset := range []int{-5, 0, total / 2, total, total * 2} {
			size, pos := scrollThumbBounds(20, offset, total)
			if size < 1 {
				t.Errorf("total=%d offset=%d: the thumb vanished", total, offset)
			}
			if pos < 0 || pos+size > 20 {
				t.Errorf("total=%d offset=%d: the thumb runs from %d to %d, outside a 20-row track",
					total, offset, pos, pos+size)
			}
		}
	}
}

// The line count has to be the wrapped one.
//
// tview keeps its wrapped-line index private, and GetOriginalLineCount counts
// source lines — so a bar built on it would run off the end of its track as
// soon as anything wrapped.
func TestDisplayedLinesCountsWrapping(t *testing.T) {
	if got := displayedLines("short\nlines\n", 40); got != 3 {
		t.Errorf("three source lines counted as %d", got)
	}
	// Sixty characters at width twenty is three rows.
	if got := displayedLines(strings.Repeat("x", 60), 20); got != 3 {
		t.Errorf("a 60-character line at width 20 counted as %d rows, want 3", got)
	}
	// Colour markup is not drawn and must not be counted.
	plain := displayedLines("hello world", 40)
	tagged := displayedLines("[yellow]hello[-:-:-] [red]world[-:-:-]", 40)
	if plain != tagged {
		t.Errorf("markup changed the line count: %d vs %d", plain, tagged)
	}
}

func ptrTheme(t Theme) *Theme { return &t }

// A pane must not scroll past its own end.
//
// tview clamps the offset downward to zero and upward only after ScrollToEnd,
// so holding Down walks the text off the top and leaves a blank pane with no
// way to tell how far it has gone.
func TestScrollStopsAtTheEnd(t *testing.T) {
	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetBorder(true)
	attachScrollbar(tv, ptrTheme(themeDark()))
	tv.SetText(strings.Repeat("a line\n", 40))

	// Far past the end, as holding the arrow key would.
	tv.ScrollTo(500, 0)
	lines := renderPrimitive(t, tv, 40, 12)

	if got, _ := tv.GetScrollOffset(); got > 40 {
		t.Errorf("the pane scrolled to line %d of a 40-line document", got)
	}

	// And the last line is still on screen rather than off the top.
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "a line") {
		t.Errorf("scrolling to the end emptied the pane:\n%s", joined)
	}
}

// thumbRows is which screen rows carry the scrollbar thumb.
func thumbRows(lines []string) []int {
	var out []int
	for i, l := range lines {
		if strings.Contains(l, scrollThumb) {
			out = append(out, i)
		}
	}
	return out
}

// A table holding more rows than it can show gets a bar too.
//
// The findings queue holds up to 200 rows in a pane around fifteen deep, and
// tview.Table draws no position indicator — so there was no way to tell how far
// down a queue you were, while the detail pane below it had a bar.
func TestTableScrollbarMarksThePosition(t *testing.T) {
	requireUnicode(t)

	tbl := tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	tbl.SetBorder(true)
	attachTableScrollbar(tbl, 1, ptrTheme(themeDark()))
	for row := 0; row < 40; row++ {
		tbl.SetCell(row, 0, tview.NewTableCell("finding"))
	}

	tbl.Select(1, 0)
	top := thumbRows(renderPrimitive(t, tbl, 40, 12))
	if len(top) == 0 {
		t.Fatal("no scrollbar on a table of forty rows in twelve")
	}
	if top[0] != 2 {
		t.Errorf("at the top of the queue the thumb starts at row %d, want row 2 (under the header)", top[0])
	}
}

// And it reaches the bottom when the cursor does.
//
// A Table settles its offset partway through Draw, after the draw function has
// run, so GetOffset returns the previous frame's — a bar built on that trails
// by a row for as long as the key is held, and stops short of the end.
func TestTableScrollbarReachesTheEnd(t *testing.T) {
	requireUnicode(t)

	tbl := tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	tbl.SetBorder(true)
	attachTableScrollbar(tbl, 1, ptrTheme(themeDark()))
	for row := 0; row < 40; row++ {
		tbl.SetCell(row, 0, tview.NewTableCell("finding"))
	}

	tbl.Select(39, 0) // the last row, as End would
	rows := thumbRows(renderPrimitive(t, tbl, 40, 12))
	if len(rows) == 0 {
		t.Fatal("no scrollbar drawn")
	}
	// Inner rect is rows 1..10 of a 12-row box; the track sits below the
	// header, so the last track row is 10.
	if last := rows[len(rows)-1]; last != 10 {
		t.Errorf("with the cursor on the last finding the thumb ends at row %d, want row 10", last)
	}
}

// A table that fits shows no bar, for the same reason a TextView does not.
func TestTableScrollbarIsAbsentWhenEverythingFits(t *testing.T) {
	tbl := tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	tbl.SetBorder(true)
	attachTableScrollbar(tbl, 1, ptrTheme(themeDark()))
	for row := 0; row < 4; row++ {
		tbl.SetCell(row, 0, tview.NewTableCell("finding"))
	}

	lines := renderPrimitive(t, tbl, 40, 12)
	if rows := thumbRows(lines); len(rows) > 0 {
		t.Errorf("a scrollbar was drawn on a table of four rows in twelve:\n%s",
			strings.Join(lines, "\n"))
	}
}

// The bar's column is reserved, not painted over the rows.
func TestTableScrollbarDoesNotOverwriteACell(t *testing.T) {
	tbl := tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	tbl.SetBorder(true)
	attachTableScrollbar(tbl, 1, ptrTheme(themeDark()))
	for row := 0; row < 40; row++ {
		cell := tview.NewTableCell(strings.Repeat("wide", 20))
		cell.SetExpansion(1)
		tbl.SetCell(row, 0, cell)
	}

	lines := renderPrimitive(t, tbl, 40, 12)
	for _, i := range thumbRows(lines) {
		col := screenColumnOf(lines[i], scrollThumb)
		if col != 38 {
			t.Errorf("the thumb landed at column %d of row %d, want the reserved column 38:\n%s",
				col, i, lines[i])
		}
	}
}
