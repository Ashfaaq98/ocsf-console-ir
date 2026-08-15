package ui

import (
	"strings"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// The sparkline's job is shape. Peaks must read as peaks and troughs as
// troughs, or the strip is decoration.
func TestSparklineReflectsShape(t *testing.T) {
	requireUnicode(t)

	got := []rune(sparkline([]int{0, 1, 5, 20, 5, 1, 0}, 7))

	if len(got) != 7 {
		t.Fatalf("got %d columns, want 7: %q", len(got), string(got))
	}
	peak := got[3]
	for i, r := range got {
		if i == 3 {
			continue
		}
		if r >= peak {
			t.Errorf("column %d (%q) is as tall as the peak (%q): %q", i, r, peak, string(got))
		}
	}
}

// An hour with events in it must never draw the same as an hour without, or the
// chart reports quiet where there was activity.
func TestSparklineNeverHidesActivity(t *testing.T) {
	got := []rune(sparkline([]int{0, 0, 1, 0, 0, 0, 0, 900}, 8))

	if got[2] == got[0] {
		t.Errorf("a single event draws the same as none: %q", string(got))
	}
}

// A flat line is a flat line, not an empty string and not a division by zero.
func TestSparklineOnAnEmptyDay(t *testing.T) {
	requireUnicode(t)

	got := sparkline(make([]int, 24), 12)

	if len([]rune(got)) != 12 {
		t.Fatalf("got %d columns, want 12: %q", len([]rune(got)), got)
	}
	if strings.Count(got, string(sparkBlocks[0])) != 12 {
		t.Errorf("an empty day is not a flat baseline: %q", got)
	}
}

func TestSparklineDegenerateInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		counts []int
		width  int
	}{
		{"no width", []int{1, 2, 3}, 0},
		{"negative width", []int{1, 2, 3}, -4},
		{"no counts", nil, 10},
	} {
		if got := sparkline(tc.counts, tc.width); got != "" {
			t.Errorf("%s produced %q, want nothing", tc.name, got)
		}
	}
}

// More hours than columns: the buckets are summed, not dropped, so a burst
// cannot vanish because it landed in an hour that got resampled away.
func TestSparklineResamplesWithoutLosingEvents(t *testing.T) {
	counts := make([]int, 24)
	counts[23] = 100

	got := []rune(sparkline(counts, 8))

	if len(got) != 8 {
		t.Fatalf("got %d columns, want 8", len(got))
	}
	if got[7] == got[0] {
		t.Errorf("the burst was resampled away: %q", string(got))
	}
}

// The severity bar is proportion, and every severity present has to be visible
// — a critical finding rounded down to nothing is the one that matters most.
func TestSeverityBarShowsEverySeverityPresent(t *testing.T) {
	h, _ := newTestHome(t)

	got := stripTags(h.severityBar(store.OpenFindings{
		Total: 100, Critical: 1, High: 40, Medium: 39, Low: 20,
	}, 14))

	if n := len([]rune(got)); n != 14 {
		t.Errorf("the bar is %d columns, want 14: %q", n, got)
	}

	segments := h.severityBar(store.OpenFindings{
		Total: 100, Critical: 1, High: 40, Medium: 39, Low: 20,
	}, 14)
	for _, tag := range []string{
		h.ui.theme.TagSeverityCritical,
		h.ui.theme.TagSeverityHigh,
		h.ui.theme.TagSeverityMedium,
		h.ui.theme.TagSeverityLow,
	} {
		if !strings.Contains(segments, tag) {
			t.Errorf("the bar dropped the severity coloured %s: %q", tag, segments)
		}
	}
}

// No findings is an empty track, not a blank.
func TestSeverityBarWithNothingOpen(t *testing.T) {
	h, _ := newTestHome(t)

	got := stripTags(h.severityBar(store.OpenFindings{}, 10))

	if n := len([]rune(got)); n != 10 {
		t.Errorf("an empty bar is %d columns, want 10: %q", n, got)
	}
}

// Whatever the mix, the bar is exactly its width — a segment that overran would
// push the card's own border off the screen.
func TestSeverityBarIsAlwaysItsWidth(t *testing.T) {
	h, _ := newTestHome(t)

	for _, f := range []store.OpenFindings{
		{Critical: 1},
		{Critical: 1, High: 1},
		{Critical: 1, High: 1, Medium: 1, Low: 1, Info: 1},
		{Critical: 999, Low: 1},
		{Info: 7},
	} {
		if n := len([]rune(stripTags(h.severityBar(f, 14)))); n != 14 {
			t.Errorf("%+v drew %d columns, want 14", f, n)
		}
	}
}
