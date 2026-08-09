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
