package ui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// seedRichFinding writes a finding carrying everything the inspector reads.
func seedRichFinding(t *testing.T, st *store.Store, uid string) string {
	t.Helper()
	f := &ocsf.Finding{
		FindingInfo: ocsf.FindingInfo{
			UID:      uid,
			Title:    "Malicious attachment delivered to j.rivera",
			Analytic: &ocsf.Analytic{Name: "Lookalike Sender With Macro Attachment"},
			Attacks: []ocsf.Attack{{
				Technique:    &ocsf.AttackNode{UID: "T1566", Name: "Phishing"},
				SubTechnique: &ocsf.AttackNode{UID: "T1566.001", Name: "Spearphishing Attachment"},
			}},
		},
		RiskScore:    71,
		StatusID:     ocsf.FindingStatusNew,
		ConfidenceID: 3,
	}
	f.ClassUID = ocsf.ClassDetectionFinding
	f.CategoryUID = ocsf.CategoryFindings
	f.SeverityID = ocsf.SeverityHigh
	f.Message = "A macro-enabled document arrived from a lookalike sender domain and was not quarantined."
	f.Time = time.Now()
	f.Observables = []ocsf.Observable{
		{TypeID: 4, Type: "User Name", Value: "j.rivera"},
		{TypeID: 1, Type: "Hostname", Value: "workstation-14"},
	}
	id, err := st.SaveFinding(context.Background(), f)
	if err != nil {
		t.Fatalf("seed %s: %v", uid, err)
	}
	return id
}

// inspectSelected loads the context synchronously, which the debounce timer
// would otherwise do after a delay. No test waits on a clock.
func inspectSelected(t *testing.T, h *homeView) string {
	t.Helper()
	f := h.selectedFinding()
	if f == nil {
		t.Fatal("nothing selected")
	}
	h.loadFindingContext(f.ID)
	h.renderInspector()
	return stripTags(h.inspector.GetText(true))
}

// The panel reads the record in full. Every field below was stored and parsed
// and then displayed nowhere, while the panel spent a row on key hints for
// three keys that did not work.
func TestInspectorShowsWhatTheRecordCarries(t *testing.T) {
	h, st := newTestHome(t)
	seedRichFinding(t, st, "rich")
	h.rebuild(120, 40)
	h.loadAndRender(t)
	h.queue.Select(0, 0)

	got := inspectSelected(t, h)

	for _, want := range []string{
		"Malicious attachment delivered to j.rivera", // title
		"risk 71",                     // rank
		"WHY IT MATTERS",              // the narrative
		"lookalike sender domain",     // ... in full
		"INDICATORS",                  // the pivot points
		"j.rivera",                    //
		"workstation-14",              //
		"T1566.001",                   // the technique
		"Spearphishing Attachment",    //
		"Lookalike Sender With Macro", // the analytic
		"confidence High",             // stored, never shown before
		"single occurrence",           // first == last, said once
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the inspector is missing %q:\n%s", want, got)
		}
	}
}

// It must not advertise keys that do nothing. e and v are Home's; the old panel
// also offered "a add to case", which reported no events selected, and "j raw
// OCSF", which moved the cursor down and has no viewer behind it at all.
func TestInspectorAdvertisesNoDeadKeys(t *testing.T) {
	h, st := newTestHome(t)
	seedRichFinding(t, st, "rich")
	h.rebuild(120, 40)
	h.loadAndRender(t)
	h.queue.Select(0, 0)

	got := inspectSelected(t, h)

	for _, dead := range []string{"add to case", "raw OCSF"} {
		if strings.Contains(got, dead) {
			t.Errorf("the inspector still offers %q, which does nothing here:\n%s", dead, got)
		}
	}
}

// A finding in a case is named by the case's title. The identifier is forty
// characters of nothing.
func TestInspectorNamesTheCase(t *testing.T) {
	h, st := newTestHome(t)
	ctx := context.Background()

	id := seedRichFinding(t, st, "rich")
	if _, err := st.CreateOrUpdateCase(ctx, store.Case{
		ID: "c1", Title: "Phishing-led intrusion", Status: "INVESTIGATING",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.AssignFindingToCase(ctx, id, "c1"); err != nil {
		t.Fatal(err)
	}

	h.rebuild(120, 40)
	h.loadAndRender(t)
	h.queue.Select(0, 0)

	got := inspectSelected(t, h)

	if !strings.Contains(got, "Phishing-led intrusion") {
		t.Errorf("the case is not named:\n%s", got)
	}
	if strings.Contains(got, "c1  ") {
		t.Errorf("the raw case identifier reached the screen:\n%s", got)
	}
}

// An indicator seen in other findings is a lead; one seen nowhere else is a
// detail. The count is what separates them, and it is the reason the panel
// issues a query per indicator at all.
func TestInspectorCountsSharedIndicators(t *testing.T) {
	h, st := newTestHome(t)
	seedRichFinding(t, st, "one")
	seedRichFinding(t, st, "two") // same observables
	h.rebuild(120, 40)
	h.loadAndRender(t)
	h.queue.Select(0, 0)

	got := inspectSelected(t, h)

	if !strings.Contains(got, "in 1 more") {
		t.Errorf("a shared indicator is not reported as shared:\n%s", got)
	}
	// "in 1 mores" is what plural() would have produced.
	if strings.Contains(got, "mores") {
		t.Errorf("the count is mis-pluralised:\n%s", got)
	}
}

func TestInspectorReportsAnUnsharedIndicator(t *testing.T) {
	h, st := newTestHome(t)
	seedRichFinding(t, st, "only")
	h.rebuild(120, 40)
	h.loadAndRender(t)
	h.queue.Select(0, 0)

	if got := inspectSelected(t, h); !strings.Contains(got, "first sighting") {
		t.Errorf("an indicator seen nowhere else is not marked as such:\n%s", got)
	}
}

// The indicator columns line up. The type column is padded to a fixed width, so
// a type whose name is longer than it shifts every value on that row.
func TestIndicatorTypeLabelFitsItsColumn(t *testing.T) {
	for _, o := range []store.Observable{
		{TypeID: 1, Type: "Hostname"},
		{TypeID: 4, Type: "User Name"},
		{TypeID: 7, Type: "File Name"},
		{TypeID: 2, Type: "IP Address"},
		{TypeID: 8, Type: "Fingerprint"},
		{TypeID: 0, Type: ""},
	} {
		got := indicatorTypeLabel(o)
		if n := len([]rune(got)); n > indicatorTypeWidth {
			t.Errorf("%q renders as %q, %d columns — the column is %d",
				o.Type, got, n, indicatorTypeWidth)
		}
		if got == "" {
			t.Errorf("%q produced an empty label", o.Type)
		}
	}
}

// Most widely seen first: the panel shows five of however many there are, so
// the order decides which five.
func TestIndicatorsAreRankedBySpread(t *testing.T) {
	in := []indicatorSighting{
		{Type: "file", Findings: 1},
		{Type: "host", Findings: 9},
		{Type: "user", Findings: 4},
	}
	sortIndicators(in)

	if in[0].Findings != 9 || in[1].Findings != 4 || in[2].Findings != 1 {
		t.Errorf("indicators are not ordered by spread: %+v", in)
	}
}

// The technique is on the record as raw JSON and was never rendered.
func TestFindingTechniquesParsesTheAttackBlock(t *testing.T) {
	f := store.Finding{AttacksJSON: `[{"technique":{"uid":"T1059","name":"Command and Scripting Interpreter"},
		"sub_technique":{"uid":"T1059.001","name":"PowerShell"}}]`}

	got := findingTechniques(f)

	if len(got) != 1 {
		t.Fatalf("got %d techniques, want 1: %v", len(got), got)
	}
	// The sub-technique is the specific one, so it wins.
	if !strings.HasPrefix(got[0], "T1059.001") {
		t.Errorf("technique = %q, want the sub-technique", got[0])
	}
}

// Malformed or absent ATT&CK data must not take the panel with it: this runs on
// every cursor movement, on records from producers we do not control.
func TestFindingTechniquesSurvivesBadInput(t *testing.T) {
	for _, raw := range []string{"", "null", "{}", "[", `[{"technique":{}}]`, `["nope"]`} {
		if got := findingTechniques(store.Finding{AttacksJSON: raw}); got != nil && len(got) > 0 {
			t.Errorf("AttacksJSON %q produced %v, want nothing", raw, got)
		}
	}
}

// A moving cursor must not paint one finding's indicators under another's
// title: the queries are asynchronous and the cursor does not wait for them.
func TestInspectorIgnoresContextForAnotherFinding(t *testing.T) {
	h, st := newTestHome(t)
	first := seedRichFinding(t, st, "first")
	h.rebuild(120, 40)
	h.loadAndRender(t)
	h.queue.Select(0, 0)

	h.inspect.ctx = findingContext{findingID: first + "-stale", loaded: true,
		indicators: []indicatorSighting{{Type: "user", Value: "someone-else", Findings: 3}}}

	h.renderInspector()

	if got := stripTags(h.inspector.GetText(true)); strings.Contains(got, "someone-else") {
		t.Errorf("the inspector painted another finding's indicators:\n%s", got)
	}
}
