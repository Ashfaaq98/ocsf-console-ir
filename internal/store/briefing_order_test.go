package store

import (
	"context"
	"fmt"
	"testing"
)

// A checklist reads in the order it was written. created_at is stored to the
// second, so a checklist saved in one loop carries one timestamp throughout and
// cannot be ordered by it — without a tiebreaker SQLite returns equal keys in
// whatever order it likes, which is how the same case showed its actions
// reversed on one platform and not another.
func TestAChecklistKeepsTheOrderItWasWrittenIn(t *testing.T) {
	st, caseID := briefingStore(t)
	ctx := context.Background()

	want := []NextAction{
		{Text: "Isolate FIN-02", Done: true},
		{Text: "Revoke tickets", Done: false},
		{Text: "Reset the service account", Done: true},
		{Text: "Brief the duty manager", Done: false},
	}
	if err := st.SetNextActions(ctx, caseID, "paolo", want); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetBriefing(ctx, caseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.NextActions) != len(want) {
		t.Fatalf("got %d actions, want %d", len(got.NextActions), len(want))
	}
	for i := range want {
		if got.NextActions[i] != want[i] {
			t.Errorf("action %d = %+v, want %+v", i, got.NextActions[i], want[i])
		}
	}
}

// The same for hypotheses: the order carries meaning, since the analyst writes
// the leading one first.
func TestHypothesesKeepTheirOrder(t *testing.T) {
	st, caseID := briefingStore(t)
	ctx := context.Background()

	want := []Hypothesis{
		{Text: "Initial access via attachment", Confidence: ConfidenceConfirmed},
		{Text: "Credential dumping succeeded", Confidence: ConfidenceLikely},
		{Text: "Lateral movement to the file server", Confidence: ConfidenceOpen},
	}
	if err := st.SetHypotheses(ctx, caseID, "paolo", want); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetBriefing(ctx, caseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hypotheses) != len(want) {
		t.Fatalf("got %d hypotheses, want %d", len(got.Hypotheses), len(want))
	}
	for i := range want {
		if got.Hypotheses[i] != want[i] {
			t.Errorf("hypothesis %d = %+v, want %+v", i, got.Hypotheses[i], want[i])
		}
	}
}

// Reading the same briefing repeatedly must give the same answer. The original
// defect was not that the order was wrong every time — it was that it was
// undefined, so it differed between drivers and platforms.
func TestReadingABriefingTwiceGivesTheSameOrder(t *testing.T) {
	st, caseID := briefingStore(t)
	ctx := context.Background()

	var actions []NextAction
	for i := 0; i < 12; i++ {
		actions = append(actions, NextAction{Text: fmt.Sprintf("step %02d", i), Done: i%2 == 0})
	}
	if err := st.SetNextActions(ctx, caseID, "paolo", actions); err != nil {
		t.Fatal(err)
	}

	first, err := st.GetBriefing(ctx, caseID)
	if err != nil {
		t.Fatal(err)
	}
	for read := 0; read < 20; read++ {
		got, err := st.GetBriefing(ctx, caseID)
		if err != nil {
			t.Fatal(err)
		}
		for i := range first.NextActions {
			if got.NextActions[i] != first.NextActions[i] {
				t.Fatalf("read %d differed at %d: %+v vs %+v",
					read, i, got.NextActions[i], first.NextActions[i])
			}
		}
	}
	for i := range actions {
		if first.NextActions[i] != actions[i] {
			t.Fatalf("action %d = %+v, want %+v", i, first.NextActions[i], actions[i])
		}
	}
}

// The notes list is newest first, and stays deterministic when several notes
// share a timestamp.
func TestNotesStayNewestFirstAndStable(t *testing.T) {
	st, caseID := briefingStore(t)
	ctx := context.Background()

	for i := 0; i < 8; i++ {
		if _, err := st.AddNote(ctx, Note{
			CaseID: caseID, Author: "paolo", Content: fmt.Sprintf("note %02d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := st.GetNotes(ctx, caseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 8 {
		t.Fatalf("got %d notes, want 8", len(first))
	}
	if first[0].Content != "note 07" {
		t.Errorf("newest note is %q, want %q", first[0].Content, "note 07")
	}
	for read := 0; read < 20; read++ {
		got, _ := st.GetNotes(ctx, caseID)
		for i := range first {
			if got[i].Content != first[i].Content {
				t.Fatalf("read %d differed at %d: %q vs %q", read, i, got[i].Content, first[i].Content)
			}
		}
	}
}
