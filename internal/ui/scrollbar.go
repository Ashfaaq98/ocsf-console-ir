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
		inner := func() (int, int, int, int) {
			// What Box would have returned: inside the border, if there is one.
			if width >= 2 && height >= 2 {
				return x + 1, y + 1, width - 2, height - 2
			}
			return x, y, width, height
		}
		ix, iy, iw, ih := inner()
		if iw < 4 || ih < 2 {
			return ix, iy, iw, ih
		}

		// One column for the bar, one blank between it and the text.
		textWidth := iw - 2
		offset, _ := tv.GetScrollOffset()
		total := displayedLines(tv.GetText(true), textWidth)

		drawScrollbar(screen, ix+iw-1, iy, ih, offset, total, theme)
		return ix, iy, textWidth, ih
	})
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
