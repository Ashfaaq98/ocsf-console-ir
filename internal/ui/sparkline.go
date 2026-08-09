package ui

import (
	"fmt"
	"strings"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// Two small charts, both of which say something a number cannot.

// sparkBlocks are the eight partial blocks, lowest first. The space is not one
// of them: a zero-count hour draws the lowest block rather than a gap, so the
// baseline reads as a line rather than as missing data.
var sparkBlocks = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// sparkASCII is the same shape for a terminal that cannot draw block elements.
var sparkASCII = []rune{'_', '.', '-', '-', '=', '=', '#', '#'}

// sparkline renders counts as a row of blocks, scaled to the largest.
//
// Relative, not absolute: the question it answers is "when did the events
// arrive", and an absolute scale would flatten a quiet day into a blank strip
// and tell you nothing about it.
func sparkline(counts []int, width int) string {
	if width <= 0 || len(counts) == 0 {
		return ""
	}
	counts = resample(counts, width)

	blocks := sparkBlocks
	if !supportsUnicode() {
		blocks = sparkASCII
	}

	peak := 0
	for _, n := range counts {
		if n > peak {
			peak = n
		}
	}

	var b strings.Builder
	for _, n := range counts {
		if peak == 0 {
			b.WriteRune(blocks[0])
			continue
		}
		// Rounded up, so any hour with events in it is visibly above the
		// baseline. An hour that saw activity must not read as one that did not.
		i := (n*(len(blocks)-1) + peak - 1) / peak
		b.WriteRune(blocks[i])
	}
	return b.String()
}

// resample fits counts to width buckets, summing when there are more values
// than columns and repeating when there are fewer.
func resample(counts []int, width int) []int {
	if len(counts) == width {
		return counts
	}
	out := make([]int, width)
	for i := range out {
		lo := i * len(counts) / width
		hi := (i + 1) * len(counts) / width
		if hi <= lo {
			hi = lo + 1
		}
		for j := lo; j < hi && j < len(counts); j++ {
			out[i] += counts[j]
		}
	}
	return out
}

// severityBar renders the open findings as one bar in severity proportion.
//
// The card already gives the numbers. The bar gives the shape, which is the
// thing a glance can read: a bar that is mostly critical and a bar that is
// mostly informational carry the same total and mean entirely different days.
func (h *homeView) severityBar(f store.OpenFindings, width int) string {
	if width <= 0 {
		return ""
	}
	t := h.ui.theme

	total := f.Critical + f.High + f.Medium + f.Low + f.Info
	if total == 0 {
		return fmt.Sprintf("[%s]%s[-:-:-]", t.TagMuted, strings.Repeat("░", width))
	}

	type band struct {
		n   int
		tag string
	}
	bands := []band{
		{f.Critical, t.TagSeverityCritical},
		{f.High, t.TagSeverityHigh},
		{f.Medium, t.TagSeverityMedium},
		{f.Low, t.TagSeverityLow},
		{f.Info, t.TagSeverityInfo},
	}

	glyph := "█"
	if !supportsUnicode() {
		glyph = "#"
	}

	// Widths are apportioned by running total rather than rounded one at a
	// time, so the segments always add up to the bar and a severity with any
	// findings at all is never rounded away to nothing.
	var b strings.Builder
	drawn, seen := 0, 0
	for _, s := range bands {
		if s.n == 0 {
			continue
		}
		seen += s.n
		want := seen * width / total
		if want <= drawn {
			want = drawn + 1
		}
		if want > width {
			want = width
		}
		fmt.Fprintf(&b, "[%s]%s[-:-:-]", s.tag, strings.Repeat(glyph, want-drawn))
		drawn = want
	}
	return b.String()
}
