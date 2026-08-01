package ui

import (
	"strings"
	"testing"

	"github.com/rivo/tview"
)

// rendered returns what a dynamic-colour string looks like on screen.
func rendered(markup string) string {
	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetText(markup)
	return tv.GetText(true)
}

// Every badge must reach the screen.
//
// `badge` produced "[colour][OPEN][-:-:-]", and tview reads "[OPEN]" as a
// colour tag and swallows it — so every status, verdict, source and count badge
// in the application rendered as an empty string. The case header showed a
// severity (which is built differently) and nothing at all where the status
// belonged.
func TestBadgeLabelsReachTheScreen(t *testing.T) {
	theme := themeDark()
	for _, tc := range []struct {
		kind  BadgeKind
		label string
	}{
		{BadgeKindStatus, "OPEN"},
		{BadgeKindStatus, "investigating"},
		{BadgeKindVerdict, "TRUE_POSITIVE"},
		{BadgeKindVerdict, "FALSE_POSITIVE"},
		{BadgeKindSeverity, "CRITICAL"},
		{BadgeKindSource, "crowdstrike"},
		{BadgeKindCount, "42"},
	} {
		got := rendered(badge(tc.kind, tc.label, theme))
		if !strings.Contains(got, strings.ToUpper(tc.label)) {
			t.Errorf("badge(%v, %q) renders as %q — the label was swallowed",
				tc.kind, tc.label, got)
		}
	}
}

func TestBadgeIsEmptyForAnEmptyLabel(t *testing.T) {
	if got := badge(BadgeKindStatus, "", themeDark()); got != "" {
		t.Errorf("badge with no label = %q, want empty", got)
	}
}

// The helpers built on badge inherit the fix.
func TestStatusAndVerdictHelpersRender(t *testing.T) {
	theme := themeDark()
	if got := rendered(formatCaseStatus("open", theme)); !strings.Contains(got, "OPEN") {
		t.Errorf("formatCaseStatus renders as %q", got)
	}
	if got := rendered(formatVerdict("true_positive", theme)); !strings.Contains(got, "TRUE_POSITIVE") {
		t.Errorf("formatVerdict renders as %q", got)
	}
	// An unset status still says something rather than nothing.
	if got := rendered(formatCaseStatus("", theme)); !strings.Contains(got, "NEW") {
		t.Errorf("formatCaseStatus with no status renders as %q", got)
	}
}

// Severity carries a glyph as well as a colour, so it survives a 16-colour
// terminal.
func TestSeverityBadgeCarriesAGlyph(t *testing.T) {
	got := rendered(formatSeverityBadge("critical", themeDark()))
	if !strings.Contains(got, "●") || !strings.Contains(got, "CRITICAL") {
		t.Errorf("severity badge = %q, want a glyph and a label", got)
	}
}
