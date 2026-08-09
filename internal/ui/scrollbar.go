package ui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// A scroll indicator for panes that hold more than they can show.
//
// tview draws none. A pane that scrolls with no mark on it gives the analyst no
// way to know there is anything below the fold, how far down they are, or how
// much is left — so the detail below a finding's summary was, in practice,
// invisible.

// Scrollbar glyphs. The track is drawn as well as the thumb: a thumb alone on
// an unmarked column reads as a stray character rather than as a position.
const (
	scrollTrack      = "│"
	scrollThumb      = "█"
	scrollTrackASCII = "|"
	scrollThumbASCII = "#"
)

// attachScrollbar reserves the pane's right-hand column and paints a scroll
// position into it.
//
// It works by narrowing the inner rect the draw function returns: the text is
// then laid out one column short, and that column is ours. Painting over the
// text instead would be overwritten the moment the text was drawn.
func attachScrollbar(tv *tview.TextView, theme *Theme) {
	tv.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
		ix, iy, iw, ih := boxInnerRect(x, y, width, height)
		if iw < 4 || ih < 2 {
			return ix, iy, iw, ih
		}

		// One column for the bar, one blank between it and the text.
		textWidth := iw - 2
		offset, col := tv.GetScrollOffset()
		total := displayedLines(tv.GetText(true), textWidth)

		// Stop the pane scrolling past its own end.
		//
		// tview clamps the offset downward to zero and upward only after
		// ScrollToEnd, so holding Down walks the text off the top and leaves a
		// blank pane with no way to tell how far it has gone. Clamping here
		// catches every route in — the arrows, the page keys and the wheel —
		// because they all arrive as a changed offset by the next draw.
		if max := total - ih; offset > max {
			if max < 0 {
				max = 0
			}
			tv.ScrollTo(max, col)
			offset = max
		}

		drawScrollbar(screen, ix+iw-1, iy, ih, offset, total, theme)
		return ix, iy, textWidth, ih
	})
}

// boxInnerRect is what Box would have returned: inside the border, if there is
// one. A draw function replaces that calculation, so it has to redo it.
func boxInnerRect(x, y, width, height int) (int, int, int, int) {
	if width >= 2 && height >= 2 {
		return x + 1, y + 1, width - 2, height - 2
	}
	return x, y, width, height
}

// attachTableScrollbar does the same for a table, below its fixed header rows.
//
// The findings queue holds up to triagePageSize rows in a pane around fifteen
// deep and a tview.Table draws no position indicator at all — so there was no
// way to tell how far down a queue of two hundred you were, or how much was
// left, while the detail pane directly below it had a bar.
func attachTableScrollbar(t *tview.Table, fixedRows int, theme *Theme) {
	t.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
		ix, iy, iw, ih := boxInnerRect(x, y, width, height)
		if iw < 4 || ih <= fixedRows+1 {
			return ix, iy, iw, ih
		}

		// The header rows are not scrollable, so the track starts below them
		// and measures the rows that are.
		drawScrollbar(screen, ix+iw-1, iy+fixedRows, ih-fixedRows,
			tableRowOffset(t, fixedRows, ih), t.GetRowCount()-fixedRows, theme)
		return ix, iy, iw - 2, ih
	})
}

// tableRowOffset is the offset the table is about to draw at.
//
// Not the offset it reports. A Table settles its own offset partway through
// Draw, after the draw function has run, so GetOffset returns the previous
// frame's — and a bar built on that trails the cursor by one row for as long as
// the analyst holds the key down, which at the foot of the queue means a thumb
// that stops one row short of the bottom. This mirrors the clamp in tview's
// Table.Draw so the bar lands where the rows will.
//
// The exception is the mouse wheel, which moves the offset without moving the
// cursor: until the next keypress the bar marks the cursor rather than the
// viewport.
func tableRowOffset(t *tview.Table, fixedRows, innerHeight int) int {
	offset, _ := t.GetOffset()
	row, _ := t.GetSelection()
	rows := t.GetRowCount()

	if row >= fixedRows && row < fixedRows+offset {
		offset = row - fixedRows
	}
	if row+1-offset >= innerHeight {
		offset = row + 1 - innerHeight
	}
	if rows-offset < innerHeight {
		offset = rows - innerHeight
	}
	if offset < 0 {
		offset = 0
	}
	return offset
}

// drawScrollbar paints the track and the thumb.
func drawScrollbar(screen tcell.Screen, col, top, height, offset, total int, theme *Theme) {
	track, thumb := scrollTrack, scrollThumb
	if !supportsUnicode() {
		track, thumb = scrollTrackASCII, scrollThumbASCII
	}

	trackStyle := tcell.StyleDefault.Foreground(theme.Border).Background(theme.Surface)
	thumbStyle := tcell.StyleDefault.Foreground(theme.Accent).Background(theme.Surface)

	// Everything fits: no bar at all. A full-height thumb on a pane that does
	// not scroll is a control that does nothing, which is worse than none.
	if total <= height {
		return
	}

	size, pos := scrollThumbBounds(height, offset, total)
	for i := 0; i < height; i++ {
		glyph, style := track, trackStyle
		if i >= pos && i < pos+size {
			glyph, style = thumb, thumbStyle
		}
		screen.SetContent(col, top+i, []rune(glyph)[0], nil, style)
	}
}

// scrollThumbBounds is the thumb's size and position within the track.
//
// The thumb is proportional to how much of the content is visible, with a floor
// of one row so it never disappears on a very long document. It reaches the
// bottom of the track exactly when the content does — computed from the last
// reachable offset rather than from the total, because a pane scrolled to the
// end still shows a screenful.
func scrollThumbBounds(height, offset, total int) (size, pos int) {
	size = height * height / total
	if size < 1 {
		size = 1
	}
	if size > height {
		size = height
	}

	maxOffset := total - height
	if maxOffset < 1 {
		return size, 0
	}
	if offset < 0 {
		offset = 0
	}
	if offset > maxOffset {
		offset = maxOffset
	}

	pos = offset * (height - size) / maxOffset
	if pos < 0 {
		pos = 0
	}
	if pos > height-size {
		pos = height - size
	}
	return size, pos
}

// displayedLines is how many rows text occupies once wrapped to width.
//
// tview keeps its wrapped-line index private and GetOriginalLineCount counts
// the source lines, which under-reports whenever anything wrapped — and a
// scrollbar built on an undercount runs off the end of its track.
func displayedLines(text string, width int) int {
	if width < 1 {
		width = 1
	}
	n := 0
	for _, line := range strings.Split(stripTags(text), "\n") {
		w := len([]rune(line))
		if w == 0 {
			n++
			continue
		}
		n += (w + width - 1) / width
	}
	return n
}
