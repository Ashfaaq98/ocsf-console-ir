package ui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
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

// Marked findings are what the bulk keys act on.
//
// Space marks findings in ui.triageSelection, keyed by finding uid so a mark
// survives a refilter. But c, a, d, Ctrl+A and Ctrl+D all read
// ui.selectedEventIDs — the *events* screen's map — so with three findings
// marked the strip said "3 selected" and c answered "No events selected. Use
// Space to select events first."
func TestTriageBulkKeysActOnTheMarkedFindings(t *testing.T) {
	ui, st := newTestUI(t)
	for _, uid := range []string{"a", "b", "c"} {
		seedTriageFinding(t, st, uid, "")
	}
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	if len(ui.findings) != 3 {
		t.Fatalf("loaded %d findings, want 3", len(ui.findings))
	}

	sel := ui.triageSelection()
	for _, f := range ui.findings[:2] {
		sel.toggle(f.FindingUID)
	}

	got := ui.triageTargets()
	if len(got) != 2 {
		t.Fatalf("the bulk keys would act on %d findings, want the 2 marked", len(got))
	}
	// And it is the marked ones, not the first two rows by accident.
	marked := map[string]bool{ui.findings[0].FindingUID: true, ui.findings[1].FindingUID: true}
	for _, f := range got {
		if !marked[f.FindingUID] {
			t.Errorf("target %q was not marked", f.FindingUID)
		}
	}
}

// With nothing marked, the bulk keys act on the cursor row — so a key does
// something useful without a selection first.
func TestTriageBulkKeysFallBackToTheCursor(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "only", "")
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)
	ui.eventList.Select(1, 0)

	got := ui.triageTargets()
	if len(got) != 1 {
		t.Fatalf("with nothing marked the keys act on %d findings, want the cursor's one", len(got))
	}
	if got[0].FindingUID != "only" {
		t.Errorf("acted on %q, want the finding under the cursor", got[0].FindingUID)
	}
}

// Ctrl+A marks everything loaded; Ctrl+D clears it. Both used to reach into the
// events map and report nothing selected.
func TestTriageSelectAllAndClear(t *testing.T) {
	ui, st := newTestUI(t)
	for _, uid := range []string{"a", "b", "c"} {
		seedTriageFinding(t, st, uid, "")
	}
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)

	ui.triageKeys(tcell.NewEventKey(tcell.KeyCtrlA, 0, tcell.ModNone))
	if got := ui.triageSelection().count(); got != 3 {
		t.Errorf("Ctrl+A marked %d findings, want 3", got)
	}

	ui.triageKeys(tcell.NewEventKey(tcell.KeyCtrlD, 0, tcell.ModNone))
	if got := ui.triageSelection().count(); got != 0 {
		t.Errorf("Ctrl+D left %d findings marked, want none", got)
	}
}

// Triage claims its keys, and passes on what it does not own.
func TestTriageOwnsItsBulkKeys(t *testing.T) {
	ui, _ := newTestUI(t)
	ui.destination = destTriage

	for _, r := range []rune{'c', 'a', 'e', 's', 'v'} {
		if ui.triageKeys(tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone)) != nil {
			t.Errorf("Triage did not claim %q, so a global binding takes it", r)
		}
	}
	for _, r := range []rune{'1', '2', '3', ':', '?', 'q'} {
		if ui.triageKeys(tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone)) == nil {
			t.Errorf("Triage swallowed %q, which belongs to global navigation", r)
		}
	}
}

// Every filter chip is reachable.
//
// Four are drawn above the queue and applied by the query builder; only Open
// had a key. Sev ≥ High, Last 24h and Has IOC were rendered, honoured, and
// impossible to turn on.
func TestEveryTriageChipIsReachable(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)

	state := ui.triageFilterState()
	for _, c := range triageChips() {
		before := state.active[c.id]
		ui.toggleTriageChip(c.id)
		awaitIdle(t, ui)
		if state.active[c.id] == before {
			t.Errorf("the chip %q cannot be toggled", c.label)
		}
	}

	// And f is the way to them, rather than the sentence it used to print.
	ui.destination = destTriage
	if ui.triageKeys(rune_('f')) != nil {
		t.Error("f is not claimed by Triage, so the events filter modal takes it")
	}
	if ui.activeModal == nil {
		t.Error("f did not open the chip menu")
	}
	ui.closeModal()
}

// / searches findings.
//
// It opened the events full-text search, which repainted the shared table as an
// events list while Triage's chip row and selection strip stayed on screen.
// triageFilter.search was never written by anything.
func TestTriageSearchFiltersFindings(t *testing.T) {
	ui, st := newTestUI(t)
	seedTriageFinding(t, st, "a", "")
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)

	if ui.triageKeys(rune_('/')) != nil {
		t.Error("/ is not claimed by Triage, so the events search takes it")
	}
	if ui.triageSearchBar == nil {
		t.Fatal("/ did not open the findings search")
	}

	// The search reaches the store filter, which nothing wrote before.
	ui.triageFilterState().search = "attachment"
	got := ui.triageFilterState().storeFilter(time.Now(), 10, 0)
	if got.Search != "attachment" {
		t.Errorf("the query's Search is %q, want the typed text", got.Search)
	}
	ui.closeTriageSearch()
}

// The Asset column names the host, not a placeholder.
//
// It held the literal string "Endpoint" whenever the raw JSON happened to
// contain the substring "hostname" — the same word for every finding, and a
// word for findings that had no host at all.
func TestFindingAssetComesFromTheEvidence(t *testing.T) {
	withHost := store.Finding{EvidencesJSON: `[{"device":{"hostname":"workstation-14"}}]`}
	if got := findingAsset(withHost); got != "workstation-14" {
		t.Errorf("asset = %q, want the host from the evidence", got)
	}

	withUser := store.Finding{EvidencesJSON: `[{"user":{"name":"m.chen"}}]`}
	if got := findingAsset(withUser); got != "m.chen" {
		t.Errorf("asset = %q, want the user from the evidence", got)
	}

	// The old placeholder fired on the substring alone.
	mentionsButHasNone := store.Finding{EvidencesJSON: `[{"data":{"note":"no hostname was recorded"}}]`}
	if got := findingAsset(mentionsButHasNone); got == "Endpoint" {
		t.Errorf("asset = %q, the placeholder that fired on a substring", got)
	}

	if got := findingAsset(store.Finding{}); got != "—" {
		t.Errorf("asset = %q with no evidence, want a dash", got)
	}
}

// Triage draws one key bar, not two.
//
// The strip under the queue listed the screen's keys, and so does the status
// bar beneath it — two bars, one above the other, that between them offered "/"
// for a filter the other did not mention and disagreed about whether s and v
// were bulk actions. The strip now carries only what the status bar cannot: how
// many findings are marked.
func TestTriageStripCarriesOnlyTheSelection(t *testing.T) {
	ui, st := newTestUI(t)
	for _, uid := range []string{"a", "b"} {
		seedTriageFinding(t, st, uid, "")
	}
	ui.enterScreen(destTriage)
	awaitIdle(t, ui)

	if got := stripTags(ui.renderTriageStrip()); strings.TrimSpace(got) != "" {
		t.Errorf("the strip lists keys with nothing selected: %q", got)
	}

	ui.triageSelection().toggle(ui.findings[0].FindingUID)
	got := stripTags(ui.renderTriageStrip())

	if !strings.Contains(got, "1 finding selected") {
		t.Errorf("the strip does not report the selection: %q", got)
	}
	// The bulk actions, which the status bar cannot know are live.
	for _, want := range []string{"e escalate", "x clear"} {
		if !strings.Contains(got, want) {
			t.Errorf("the strip is missing %q: %q", want, got)
		}
	}
}
