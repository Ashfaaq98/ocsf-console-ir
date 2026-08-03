package store

import (
	"context"
	"path/filepath"
	"testing"
)

func briefingStore(t *testing.T) (*Store, string) {
	t.Helper()
	st, err := NewStore(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	id, err := st.CreateOrUpdateCase(context.Background(), Case{Title: "C2 beaconing", Status: "open"})
	if err != nil {
		t.Fatal(err)
	}
	return st, id
}

func TestBriefingRoundTrip(t *testing.T) {
	st, caseID := briefingStore(t)
	ctx := context.Background()

	if err := st.SetStatement(ctx, caseID, "paolo", "A phishing attachment led to C2."); err != nil {
		t.Fatal(err)
	}
	if err := st.SetHypotheses(ctx, caseID, "paolo", []Hypothesis{
		{Text: "Initial access via attachment", Confidence: ConfidenceConfirmed},
		{Text: "Credential dumping succeeded", Confidence: ConfidenceLikely},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNextActions(ctx, caseID, "paolo", []NextAction{
		{Text: "Isolate FIN-02", Done: true},
		{Text: "Revoke tickets", Done: false},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetBriefing(ctx, caseID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Statement != "A phishing attachment led to C2." {
		t.Errorf("statement = %q", got.Statement)
	}
	if len(got.Hypotheses) != 2 {
		t.Fatalf("%d hypotheses, want 2", len(got.Hypotheses))
	}
	if got.Hypotheses[0].Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want it preserved", got.Hypotheses[0].Confidence)
	}
	if len(got.NextActions) != 2 || !got.NextActions[0].Done {
		t.Errorf("next actions = %+v, want the done flag preserved", got.NextActions)
	}
}

// Setting replaces rather than appends, which is what ticking a checkbox
// amounts to when the items have no ids of their own.
func TestBriefingSetReplaces(t *testing.T) {
	st, caseID := briefingStore(t)
	ctx := context.Background()

	st.SetNextActions(ctx, caseID, "paolo", []NextAction{{Text: "one"}, {Text: "two"}})
	st.SetNextActions(ctx, caseID, "paolo", []NextAction{{Text: "one", Done: true}, {Text: "two"}})

	got, _ := st.GetBriefing(ctx, caseID)
	if len(got.NextActions) != 2 {
		t.Fatalf("%d actions after a replace, want 2 — they accumulated", len(got.NextActions))
	}
	if !got.NextActions[0].Done {
		t.Error("the tick was not recorded")
	}
}

func TestStatementReplacesRatherThanAccumulates(t *testing.T) {
	st, caseID := briefingStore(t)
	ctx := context.Background()

	st.SetStatement(ctx, caseID, "paolo", "first")
	st.SetStatement(ctx, caseID, "paolo", "second")

	got, _ := st.GetBriefing(ctx, caseID)
	if got.Statement != "second" {
		t.Errorf("statement = %q, want the latest", got.Statement)
	}
}

// One bad row must not blank the whole briefing.
func TestBriefingSkipsMalformedEntries(t *testing.T) {
	st, caseID := briefingStore(t)
	ctx := context.Background()

	st.SetStatement(ctx, caseID, "paolo", "still here")
	// A hypothesis note that is not valid JSON, as an older build might leave.
	if _, err := st.AddNote(ctx, Note{
		CaseID: caseID, Author: "old", Content: "not json at all", LinkedType: NoteTypeHypothesis,
	}); err != nil {
		t.Fatal(err)
	}
	st.AddHypothesis(ctx, caseID, "paolo", Hypothesis{Text: "good one", Confidence: ConfidenceOpen})

	got, err := st.GetBriefing(ctx, caseID)
	if err != nil {
		t.Fatalf("one malformed note failed the whole briefing: %v", err)
	}
	if got.Statement != "still here" {
		t.Error("the statement was lost")
	}
	if len(got.Hypotheses) != 1 || got.Hypotheses[0].Text != "good one" {
		t.Errorf("hypotheses = %+v, want the readable one kept", got.Hypotheses)
	}
}

// Briefing content must not appear in the decision log, or the log fills with
// fragments of the briefing.
func TestBriefingNotesAreDistinguishable(t *testing.T) {
	st, caseID := briefingStore(t)
	ctx := context.Background()

	st.SetStatement(ctx, caseID, "paolo", "the statement")
	st.AddHypothesis(ctx, caseID, "paolo", Hypothesis{Text: "a belief"})
	st.AddNote(ctx, Note{CaseID: caseID, Author: "paolo", Content: "an ordinary note"})

	notes, err := st.GetNotes(ctx, caseID)
	if err != nil {
		t.Fatal(err)
	}
	ordinary := 0
	for _, n := range notes {
		if !IsBriefingNote(n) {
			ordinary++
			if n.Content != "an ordinary note" {
				t.Errorf("note %q was not recognised as briefing content", n.Content)
			}
		}
	}
	if ordinary != 1 {
		t.Errorf("%d ordinary notes, want 1", ordinary)
	}
}

// Accepting a summary makes it an authored note — the only route from generated
// text into the record, and it takes a deliberate action.
func TestAcceptSummaryCreatesAnOrdinaryNote(t *testing.T) {
	st, caseID := briefingStore(t)
	ctx := context.Background()

	if err := st.AcceptSummary(ctx, caseID, "paolo", "Reviewed 42 events across 3 hosts."); err != nil {
		t.Fatal(err)
	}

	notes, _ := st.GetNotes(ctx, caseID)
	if len(notes) != 1 {
		t.Fatalf("%d notes, want 1", len(notes))
	}
	if IsBriefingNote(notes[0]) {
		t.Error("the accepted summary is still tagged as generated content")
	}
	if notes[0].Author != "paolo" {
		t.Errorf("author = %q, want the analyst who accepted it", notes[0].Author)
	}
}

func TestAcceptSummaryRefusesNothing(t *testing.T) {
	st, caseID := briefingStore(t)
	if err := st.AcceptSummary(context.Background(), caseID, "paolo", "   "); err == nil {
		t.Error("accepting an empty summary reported success")
	}
}

// ---------------------------------------------------------------------------

func TestPinnedMembers(t *testing.T) {
	st, caseID := briefingStore(t)
	ctx := context.Background()

	for _, id := range []string{"evt-1", "evt-2", "evt-3"} {
		if err := st.AddCaseMember(ctx, CaseMember{
			CaseID: caseID, MemberType: MemberTypeEvent, MemberID: id, Role: RoleEvidence,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Nothing is pinned until someone pins it.
	pinned, err := st.GetPinnedMemberIDs(ctx, caseID, MemberTypeEvent)
	if err != nil {
		t.Fatal(err)
	}
	if len(pinned) != 0 {
		t.Errorf("%d pinned on a fresh case, want 0", len(pinned))
	}

	if err := st.SetMemberPinned(ctx, caseID, MemberTypeEvent, "evt-2", true); err != nil {
		t.Fatal(err)
	}
	pinned, _ = st.GetPinnedMemberIDs(ctx, caseID, MemberTypeEvent)
	if len(pinned) != 1 || !pinned["evt-2"] {
		t.Errorf("pinned = %v, want evt-2 only", pinned)
	}

	// Unpinning is the same call.
	st.SetMemberPinned(ctx, caseID, MemberTypeEvent, "evt-2", false)
	pinned, _ = st.GetPinnedMemberIDs(ctx, caseID, MemberTypeEvent)
	if len(pinned) != 0 {
		t.Errorf("pinned = %v after unpinning, want none", pinned)
	}
}

// The pin column is additive with a default, so a database created before it
// existed upgrades without a backfill and without losing rows.
func TestPinColumnMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")

	st, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	caseID, _ := st.CreateOrUpdateCase(ctx, Case{Title: "before", Status: "open"})
	st.AddCaseMember(ctx, CaseMember{
		CaseID: caseID, MemberType: MemberTypeEvent, MemberID: "evt-1", Role: RoleEvidence,
	})
	st.SetMemberPinned(ctx, caseID, MemberTypeEvent, "evt-1", true)
	st.Close()

	// Reopening runs every migration again.
	again, err := NewStore(path)
	if err != nil {
		t.Fatalf("reopening after the migration failed: %v", err)
	}
	defer again.Close()

	pinned, err := again.GetPinnedMemberIDs(ctx, caseID, MemberTypeEvent)
	if err != nil {
		t.Fatal(err)
	}
	if !pinned["evt-1"] {
		t.Error("the pin did not survive a reopen")
	}
	if _, err := again.GetCaseEventMembers(ctx, caseID); err != nil {
		t.Errorf("membership is unreadable after re-running the migration: %v", err)
	}
}
