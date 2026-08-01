package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

func sampleBriefing() briefingData {
	base := time.Date(2026, 8, 1, 9, 42, 0, 0, time.UTC)
	return briefingData{
		Case: store.Case{Title: "C2 beaconing on FIN-02", FindingCount: 7},
		Brief: store.Briefing{
			Statement: "A phishing attachment on FIN-02 led to encoded PowerShell and outbound C2.",
			Hypotheses: []store.Hypothesis{
				{Text: "Initial access via attachment", Confidence: store.ConfidenceConfirmed},
				{Text: "Credential dumping succeeded", Confidence: store.ConfidenceLikely},
				{Text: "Did egress establish a session?", Confidence: store.ConfidenceOpen},
			},
			NextActions: []store.NextAction{
				{Text: "Isolate FIN-02", Done: true},
				{Text: "Revoke m.chen kerberos tickets"},
			},
			Summary:    "Reviewed 42 events across 3 hosts. Beacon interval 60s.",
			HasSummary: true,
		},
		Events: []store.Event{
			{ID: "e1", Timestamp: base, Host: "FIN-02", UserName: "m.chen", Message: "powershell -enc"},
			{ID: "e2", Timestamp: base.Add(20 * time.Minute), Host: "WS-17", Message: "rundll32"},
		},
		Pinned: map[string]bool{"e1": true},
	}
}

// The briefing is what an analyst would say to a colleague, so every part of it
// has to reach the screen.
func TestBriefingRendersEveryBlock(t *testing.T) {
	got := rendered(renderBriefing(sampleBriefing(), themeDark(), 120))

	for _, want := range []string{
		"INCIDENT STATEMENT",
		"A phishing attachment on FIN-02",
		"SCOPE", "FIN-02, WS-17", "m.chen", "09:42 – 10:02", "7 findings · 2 evidence",
		"WORKING HYPOTHESES", "Confirmed", "Likely", "Open",
		"NEXT ACTIONS", "Isolate FIN-02",
		"AI SUMMARY", "generated, not case truth",
		"PINNED EVIDENCE", "★",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("briefing is missing %q\n%s", want, got)
		}
	}
}

// The briefing is one scrollable TextView, so it must contain no escaped
// brackets at all: tview's escaped-tag state drifts across the lines of a
// single widget, and a "[H] add one" on one row puts a stray "]" at the start
// of the next.
//
// This asserts the rendered output has no stray bracket at the head of a line,
// which is what the drift looks like on screen.
func TestBriefingHasNoTagDrift(t *testing.T) {
	for _, d := range []briefingData{sampleBriefing(), {Case: store.Case{}, Pinned: map[string]bool{}}} {
		for _, width := range []int{120, 70} {
			got := rendered(renderBriefing(d, themeDark(), width))
			for i, line := range strings.Split(got, "\n") {
				trimmed := strings.TrimLeft(line, " ")
				if strings.HasPrefix(trimmed, "]") || strings.HasPrefix(trimmed, ":-]") {
					t.Errorf("width %d line %d starts with colour-tag debris: %q\n%s",
						width, i, line, got)
				}
			}
		}
	}
}

// The affordances still reach the screen, in the house style: the key coloured
// rather than bracketed, as every action bar does it.
func TestBriefingAffordancesReachTheScreen(t *testing.T) {
	got := rendered(renderBriefing(sampleBriefing(), themeDark(), 120))
	for _, want := range []string{"a accept into notes", "r regenerate"} {
		if !strings.Contains(got, want) {
			t.Errorf("briefing is missing %q\n%s", want, got)
		}
	}
	// Checkboxes are glyphs, which need no escaping.
	if !strings.Contains(got, "✓") || !strings.Contains(got, "○") {
		t.Errorf("the checklist has no done/not-done marks\n%s", got)
	}
}

// An empty case is what every existing case shows on first open.
func TestBriefingEmptyStatesAreInstructions(t *testing.T) {
	empty := briefingData{Case: store.Case{Title: "new case"}, Pinned: map[string]bool{}}
	got := rendered(renderBriefing(empty, themeDark(), 120))

	for _, want := range []string{
		"No statement yet", "S write one",
		"Nothing recorded.", "H add one",
		"Nothing outstanding.", "A add one",
		"None generated.", "g generate",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("empty briefing is missing %q\n%s", want, got)
		}
	}
	// With nothing pinned the block is absent rather than empty.
	if strings.Contains(got, "PINNED EVIDENCE") {
		t.Error("an empty pinned block was rendered")
	}
}

// Generated text is always marked as generated, wherever it appears.
func TestSummaryIsAlwaysLabelled(t *testing.T) {
	for _, width := range []int{120, 80} {
		got := rendered(renderBriefing(sampleBriefing(), themeDark(), width))
		if !strings.Contains(got, "generated, not case truth") {
			t.Errorf("at width %d the summary is not labelled as generated", width)
		}
		if !strings.Contains(got, "accept into notes") {
			t.Errorf("at width %d there is no deliberate route into the record", width)
		}
	}
}

// Confidence is a glyph as well as a colour, so it survives 16 colours.
func TestConfidenceCarriesAGlyph(t *testing.T) {
	theme := themeDark()
	for _, tc := range []struct{ confidence, glyph, label string }{
		{store.ConfidenceConfirmed, "●", "Confirmed"},
		{store.ConfidenceLikely, "▲", "Likely"},
		{store.ConfidenceOpen, "◆", "Open"},
		{"", "◆", "Open"},
		{"nonsense", "◆", "Open"},
	} {
		glyph, _, label := confidenceMark(tc.confidence, theme)
		if glyph != tc.glyph || label != tc.label {
			t.Errorf("confidence %q = %s %s, want %s %s", tc.confidence, glyph, label, tc.glyph, tc.label)
		}
	}
}

// Two columns above the threshold, stacked below it — and nothing lost either
// way.
func TestBriefingResponsiveLayout(t *testing.T) {
	wide := rendered(renderBriefing(sampleBriefing(), themeDark(), 120))
	narrow := rendered(renderBriefing(sampleBriefing(), themeDark(), 70))

	// Wide puts the two headings on one line.
	wideHasPair := false
	for _, line := range strings.Split(wide, "\n") {
		if strings.Contains(line, "SCOPE") && strings.Contains(line, "WORKING HYPOTHESES") {
			wideHasPair = true
		}
	}
	if !wideHasPair {
		t.Errorf("at 120 columns the blocks are not side by side\n%s", wide)
	}

	// Narrow stacks them, and still shows everything.
	for _, line := range strings.Split(narrow, "\n") {
		if strings.Contains(line, "SCOPE") && strings.Contains(line, "WORKING HYPOTHESES") {
			t.Error("at 70 columns the blocks are still side by side")
		}
	}
	for _, want := range []string{"SCOPE", "WORKING HYPOTHESES", "NEXT ACTIONS", "AI SUMMARY"} {
		if !strings.Contains(narrow, want) {
			t.Errorf("the narrow layout dropped %q", want)
		}
	}
}

// Padding counts visible columns, not bytes. Every line carries colour markup,
// and one tag is a dozen bytes and zero columns wide.
func TestVisibleWidthIgnoresMarkup(t *testing.T) {
	plain := "hello"
	marked := "[#ff8800]hello[-]"
	if visibleWidth(marked) != len(plain) {
		t.Errorf("visibleWidth(%q) = %d, want %d", marked, visibleWidth(marked), len(plain))
	}
	// An escaped bracket occupies the columns it renders as.
	if got := visibleWidth("[#ff8800]" + "[x[]" + "[-]"); got != 3 {
		t.Errorf("visibleWidth of an escaped [x] = %d, want 3", got)
	}
}

// The scope is derived from the events, and reads the same way twice.
func TestScopeIsDeterministic(t *testing.T) {
	events := []store.Event{
		{Timestamp: time.Now(), Host: "WS-17", UserName: "m.chen"},
		{Timestamp: time.Now(), Host: "FIN-02", UserName: "j.rivera"},
		{Timestamp: time.Now(), Host: "FIN-02"},
	}
	hosts, users, _, _ := scopeOf(events)
	if strings.Join(hosts, ",") != "FIN-02,WS-17" {
		t.Errorf("hosts = %v, want them sorted and deduplicated", hosts)
	}
	if strings.Join(users, ",") != "j.rivera,m.chen" {
		t.Errorf("users = %v, want them sorted", users)
	}
}
