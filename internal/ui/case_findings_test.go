package ui

import (
	"strings"
	"testing"
)

// The tab strip, its bounds, its number keys and its pages all derive from
// caseTabNames. They used to be four hand-maintained lists with a hardcoded
// bound of 5, which is what made adding a tab a landmine.
func TestCaseTabTablesAgree(t *testing.T) {
	if len(caseTabPages) != len(caseTabNames) {
		t.Fatalf("caseTabPages has %d entries, caseTabNames has %d — a tab would open the wrong page",
			len(caseTabPages), len(caseTabNames))
	}

	seenPages := map[string]bool{}
	seenFocus := map[int]bool{}
	for i, p := range caseTabPages {
		if p.page == "" {
			t.Errorf("tab %d (%s) has no page name", i, caseTabNames[i])
		}
		if seenPages[p.page] {
			t.Errorf("tab %d (%s) reuses page %q", i, caseTabNames[i], p.page)
		}
		if seenFocus[p.focus] {
			t.Errorf("tab %d (%s) reuses focus pane %d", i, caseTabNames[i], p.focus)
		}
		seenPages[p.page] = true
		seenFocus[p.focus] = true
	}
}

// Findings sit second, right after Overview: a case is *about* findings, and
// events are only the evidence supporting them.
func TestFindingsTabIsSecond(t *testing.T) {
	if caseTabNames[tabFindings] != "Findings" {
		t.Errorf("tab %d is %q, want Findings", tabFindings, caseTabNames[tabFindings])
	}
	if tabFindings != 1 {
		t.Errorf("tabFindings = %d, want 1 (immediately after Overview)", tabFindings)
	}
	if caseTabPages[tabFindings].page != "findings" {
		t.Errorf("findings tab maps to page %q", caseTabPages[tabFindings].page)
	}
}

// Every tab must be reachable by a number key; '1'–'9' is the range the handler
// accepts, so more tabs than that would be silently unreachable.
func TestEveryTabHasANumberKey(t *testing.T) {
	if len(caseTabNames) > 9 {
		t.Fatalf("%d tabs, but only keys 1-9 are handled", len(caseTabNames))
	}
}

func TestRiskAndDashHelpers(t *testing.T) {
	if got := riskText(0); got != "—" {
		t.Errorf("riskText(0) = %q, want a dash — 0 means unscored, not a score of zero", got)
	}
	if got := riskText(91); got != "91" {
		t.Errorf("riskText(91) = %q", got)
	}
	for _, empty := range []string{"", "   "} {
		if got := dashIfEmpty(empty); got != "—" {
			t.Errorf("dashIfEmpty(%q) = %q", empty, got)
		}
	}
	if got := dashIfEmpty("True Positive"); got != "True Positive" {
		t.Errorf("dashIfEmpty mangled a real value: %q", got)
	}
}

// The empty state has to explain the tab, since a blank pane reads as broken.
func TestEmptyFindingsTabExplainsItself(t *testing.T) {
	cm := &CaseManagement{theme: themeDark()}
	cm.setupCaseFindingsTable()
	cm.renderCaseFindings()

	var sb strings.Builder
	for r := 0; r < cm.findingsTable.GetRowCount(); r++ {
		for c := 0; c < cm.findingsTable.GetColumnCount(); c++ {
			if cell := cm.findingsTable.GetCell(r, c); cell != nil {
				sb.WriteString(cell.Text + " ")
			}
		}
	}
	got := sb.String()
	if !strings.Contains(got, "No findings attached") {
		t.Errorf("empty state missing:\n%s", got)
	}
	if !strings.Contains(got, "escalate") {
		t.Errorf("empty state does not say how to attach a finding:\n%s", got)
	}
}
