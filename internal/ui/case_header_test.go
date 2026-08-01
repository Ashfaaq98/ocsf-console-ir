package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// newHeaderCase builds only what updateMetadataBar and nextActionPrompt read.
func newHeaderCase(owner string, notes []store.Note) *CaseManagement {
	return &CaseManagement{
		theme:    themeDark(),
		caseData: store.Case{Title: "C2 beaconing", Status: "open", AssignedTo: owner},
		notes:    notes,
	}
}

// The prompt appears only when a case is drifting. A header that always carries
// advice is a header nobody reads.
func TestNextActionPrompt(t *testing.T) {
	now := time.Now()
	fresh := []store.Note{{Content: "looked at it", CreatedAt: now.Add(-time.Hour)}}
	stale := []store.Note{{Content: "looked at it", CreatedAt: now.Add(-48 * time.Hour)}}

	for _, tc := range []struct {
		name   string
		owner  string
		notes  []store.Note
		expect string
	}{
		{"no owner", "", fresh, "no owner"},
		{"owned but never noted", "paolo", nil, "no note yet"},
		{"owned and gone quiet", "paolo", stale, "nothing recorded"},
		{"owned and current", "paolo", fresh, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := newHeaderCase(tc.owner, tc.notes).nextActionPrompt()
			if tc.expect == "" {
				if got != "" {
					t.Errorf("prompt = %q, want none for a case being worked", got)
				}
				return
			}
			if !strings.Contains(got, tc.expect) {
				t.Errorf("prompt = %q, want it to mention %q", got, tc.expect)
			}
		})
	}
}

// Ownership is checked first: a case with no owner and no note has one thing to
// fix, not two.
func TestNextActionPromptNamesOneThing(t *testing.T) {
	got := newHeaderCase("", nil).nextActionPrompt()
	if strings.Contains(got, "note") {
		t.Errorf("prompt = %q, want only the owner named", got)
	}
}

// Tab names are the product's vocabulary, and two of them were renamed to
// remove a collision with OCSF's own use of "evidence".
func TestCaseTabNames(t *testing.T) {
	want := []string{"Briefing", "Findings", "Events", "Timeline", "Indicators", "Notes", "Activity"}
	if len(caseTabNames) != len(want) {
		t.Fatalf("%d tabs, want %d", len(caseTabNames), len(want))
	}
	for i := range want {
		if caseTabNames[i] != want[i] {
			t.Errorf("tab %d = %q, want %q", i, caseTabNames[i], want[i])
		}
	}
	// caseTabPages is indexed by the same constants; a mismatch sends a tab to
	// the wrong page.
	if len(caseTabPages) != len(caseTabNames) {
		t.Errorf("%d pages for %d tabs", len(caseTabPages), len(caseTabNames))
	}
}
