package ui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// seedTriageFinding writes a finding carrying everything the inspector reads,
// with a bracketed title — tview parses "[macro]" in dynamic-colour text as a
// style tag, and the old renderer escaped nothing.
func seedTriageFinding(t *testing.T, st *store.Store, uid, caseID string) string {
	t.Helper()
	f := &ocsf.Finding{
		FindingInfo: ocsf.FindingInfo{
			UID:      uid,
			Title:    "Malicious attachment delivered to j.rivera [macro]",
			Analytic: &ocsf.Analytic{Name: "Lookalike Sender With Macro Attachment"},
			Attacks: []ocsf.Attack{{
				Technique:    &ocsf.AttackNode{UID: "T1566", Name: "Phishing"},
				SubTechnique: &ocsf.AttackNode{UID: "T1566.001", Name: "Spearphishing Attachment"},
			}},
		},
		RiskScore: 71, StatusID: ocsf.FindingStatusNew, ConfidenceID: 3,
	}
	f.ClassUID = ocsf.ClassDetectionFinding
	f.CategoryUID = ocsf.CategoryFindings
	f.SeverityID = ocsf.SeverityHigh
	f.Message = "A macro-enabled document arrived from a lookalike sender domain."
	f.Time = time.Now()
	f.Observables = []ocsf.Observable{
		{TypeID: 4, Type: "User Name", Value: "j.rivera"},
		{TypeID: 1, Type: "Hostname", Value: "workstation-14"},
	}
	id, err := st.SaveFinding(context.Background(), f)
	if err != nil {
		t.Fatalf("seed %s: %v", uid, err)
	}
	if caseID != "" {
		if err := st.AssignFindingToCase(context.Background(), id, caseID); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// triageInspect opens Triage, selects the top finding and renders it with its
// context loaded. The debounce is bypassed; no test waits on a clock.
func triageInspect(t *testing.T, ui *UI) string {
	t.Helper()
	ui.termWidth = 200
	ui.currentLayoutMode = LayoutStandard // detail below the list, at full width
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)

	ui.eventList.Select(1, 0)
	f, ok := ui.currentFinding()
	if !ok {
		t.Fatal("nothing selected in Triage")
	}
	ui.findingInspect.loadNow(f.ID, f.CaseID)
	ui.showFindingDetails()
	// GetText(true) is what reaches the screen: colour tags resolved and escaped
	// brackets restored. Running stripTags over it as well would remove the very
	// brackets the escaping test is looking for.
	return ui.eventDetail.GetText(true)
}

// Triage reads a finding in full, using the same renderer as the dashboard.
//
// Every field below was already stored and parsed, and shown only on the
// dashboard — so the screen you glance at said more about a finding than the
// screen you triage on.
func TestTriageInspectorShowsWhatTheRecordCarries(t *testing.T) {
	ui, st := newTestUI(t)
	if _, err := st.CreateOrUpdateCase(context.Background(), store.Case{
		ID: "c1", Title: "Phishing-led intrusion", Status: "INVESTIGATING",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	seedTriageFinding(t, st, "a", "c1")
	seedTriageFinding(t, st, "b", "") // shares the observables

	got := triageInspect(t, ui)

	for _, want := range []string{
		"risk 71",                  // the rank
		"WHY IT MATTERS",           // the narrative
		"lookalike sender domain",  //
		"INDICATORS",               // the pivot points
		"j.rivera",                 //
		"in 1 more",                // ... and their prevalence
		"T1566.001",                // the technique, parsed
		"Spearphishing Attachment", //
		"confidence High",          // stored, never shown here before
		"single occurrence",        // first == last, said once
		"Phishing-led intrusion",   // the case by name
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the Triage inspector is missing %q:\n%s", want, got)
		}
	}
}

// A bracketed title must reach the screen intact.
//
// The old renderer escaped nothing, so tview read "[macro]" as a style tag and
// swallowed it along with whatever followed on that line.
func TestTriageInspectorEscapesTheTitle(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")

	if got := triageInspect(t, ui); !strings.Contains(got, "[macro]") {
		t.Errorf("the bracketed title was parsed as a colour tag:\n%s", got)
	}
}

// It must not advertise a key that does something else.
//
// "j raw OCSF" was printed in the inspector itself; j is the global move-down,
// and there is no raw-OCSF viewer bound anywhere in the application.
func TestTriageInspectorAdvertisesNoDeadKeys(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")

	got := triageInspect(t, ui)

	if strings.Contains(got, "raw OCSF") {
		t.Errorf("the inspector still offers a raw-OCSF key that does not exist:\n%s", got)
	}
	// And the count that was labelled INDICATORS was the ATT&CK technique count.
	if strings.Contains(got, "INDICATORS 1") || strings.Contains(got, "INDICATORS 0") {
		t.Errorf("the ATT&CK count is still labelled INDICATORS:\n%s", got)
	}
}

// The long form stays: artifacts and related events are what Triage has that
// the dashboard does not, and the reason it has a pane rather than a panel.
func TestTriageInspectorKeepsItsLongForm(t *testing.T) {
	ui, st := newTestUI(t)

	f := &ocsf.Finding{
		FindingInfo: ocsf.FindingInfo{UID: "ev", Title: "With artifacts"},
		Evidences: []ocsf.Evidence{{
			Name:    "invoice.docm",
			Process: &ocsf.Process{Name: "WINWORD.EXE", CommandLine: "/q /n"},
		}},
		RiskScore: 50, StatusID: ocsf.FindingStatusNew,
	}
	f.ClassUID = ocsf.ClassDetectionFinding
	f.CategoryUID = ocsf.CategoryFindings
	f.SeverityID = ocsf.SeverityMedium
	f.Time = time.Now()
	if _, err := st.SaveFinding(context.Background(), f); err != nil {
		t.Fatal(err)
	}

	got := triageInspect(t, ui)

	for _, want := range []string{"Evidence Artifacts", "invoice.docm", "WINWORD.EXE", "Class"} {
		if !strings.Contains(got, want) {
			t.Errorf("the long form lost %q:\n%s", want, got)
		}
	}
}

// The first paint needs no query.
//
// The inspector used to call GetObservablesByFinding inline from the table's
// selection callback — one query per row while an arrow key was held down. It
// now paints from the record and fills the context in behind a debounce, so a
// paint with no context loaded still shows the finding.
func TestTriageInspectorPaintsBeforeItsContextArrives(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")

	ui.termWidth = 200
	ui.currentLayoutMode = LayoutStandard
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	ui.eventList.Select(1, 0)

	// No loadNow: exactly the state the first paint is in.
	ui.showFindingDetails()
	got := ui.eventDetail.GetText(true)

	if !strings.Contains(got, "Malicious attachment") {
		t.Errorf("the finding did not paint without its context:\n%s", got)
	}
	if !strings.Contains(got, "…") {
		t.Errorf("the pending indicators are not marked as still loading:\n%s", got)
	}
}
