package ui

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
	"github.com/gdamore/tcell/v2"
)

// mockLLMIOC implements llm.LLMProvider for these tests.
type mockLLMIOC struct{}

func (m *mockLLMIOC) SummarizeCase(ctx context.Context, case_ store.Case, events []store.Event) (string, error) {
	return "summary", nil
}
func (m *mockLLMIOC) AnalyzeEvents(ctx context.Context, events []store.Event) (*llm.EventAnalysis, error) {
	return &llm.EventAnalysis{Summary: "ok", Severity: "medium", Confidence: 0.5}, nil
}
func (m *mockLLMIOC) GenerateRecommendations(ctx context.Context, case_ store.Case, events []store.Event) ([]string, error) {
	return []string{"rec"}, nil
}

// TestIOCTabSelectionToggle_Space verifies space toggling selection on manual IOC rows.
func TestIOCTabSelectionToggle_Space(t *testing.T) {
	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer st.Close()

	// Ensure audit/notes tables exist
	if err := st.SetupAuditTables(); err != nil {
		t.Fatalf("SetupAuditTables: %v", err)
	}

	ctx := context.Background()
	logger := logging.New(os.Stdout, logging.LevelDebug, "test")
	ui := NewUI(ctx, st, &mockLLMIOC{}, logger, "test")

	c := store.Case{ID: "case-ioc", Title: "IOC Manual", Severity: "low", Status: "open"}
	cm := NewCaseManagement(ui, c)
	// The constructor starts the case's reads; they paint the same widgets this
	// test is about to write to.
	awaitIdle(t, ui)

	// Add a manual IOC represented as a Note with LinkedType="ioc"
	note := store.Note{
		CaseID:     c.ID,
		Content:    "ioc_type:ip",
		Author:     "tester",
		Color:      "#80b1d3",
		LinkedType: "ioc",
		LinkedID:   "1.2.3.4",
	}
	noteID, err := st.AddNote(ctx, note)
	if err != nil {
		t.Fatalf("AddNote: %v", err)
	}

	// Load notes into CM and render IOCs
	notes, err := st.GetNotes(ctx, c.ID)
	if err != nil {
		t.Fatalf("GetNotes: %v", err)
	}
	cm.notes = notes
	cm.renderIOCs()

	// Find table row that maps to this manual IOC noteID
	var targetRow int
	found := false
	for row, id := range cm.iocRowToManualID {
		if id == noteID {
			targetRow = row
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("manual IOC note row not found in mapping")
	}

	// Select row and press space to toggle select
	cm.iocsTable.Select(targetRow, 0)
	capture := cm.iocsTable.GetInputCapture()
	if capture == nil {
		t.Fatalf("iocsTable input capture not set")
	}
	ret := capture(tcell.NewEventKey(tcell.KeyRune, ' ', 0))
	if ret != nil {
		t.Fatalf("expected space toggle to be consumed (nil)")
	}

	if cm.selectedManualIOCIDs == nil || !cm.selectedManualIOCIDs[noteID] {
		t.Fatalf("expected manual IOC %s to be selected after space toggle", noteID)
	}
}

// TestIOCTabAddModalPlusKey_OpensModal verifies '+' opens Add IOC modal (no freeze).
func TestIOCTabAddModalPlusKey_OpensModal(t *testing.T) {
	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer st.Close()

	if err := st.SetupAuditTables(); err != nil {
		t.Fatalf("SetupAuditTables: %v", err)
	}

	ctx := context.Background()
	logger := logging.New(os.Stdout, logging.LevelDebug, "test")
	ui := NewUI(ctx, st, &mockLLMIOC{}, logger, "test")

	c := store.Case{ID: "case-ioc-plus", Title: "IOC Plus", Severity: "low", Status: "open"}
	cm := NewCaseManagement(ui, c)
	// The constructor starts the case's reads; they paint the same widgets this
	// test is about to write to.
	awaitIdle(t, ui)

	// Render IOC tab so input capture is attached
	cm.renderIOCs()

	capture := cm.iocsTable.GetInputCapture()
	if capture == nil {
		t.Fatalf("iocsTable input capture not set")
	}

	ret := capture(tcell.NewEventKey(tcell.KeyRune, '+', 0))
	if ret != nil {
		t.Fatalf("expected '+' to be consumed (nil)")
	}
	// Modal should be active now
	if !cm.modalActive {
		t.Fatalf("expected modalActive after '+'")
	}
	// Close modal to avoid affecting subsequent tests
	cm.popModalRoot()
	if cm.modalActive {
		t.Fatalf("expected modal to be closed after popModalRoot")
	}
}

// TestGetCurrentAnalystPriority verifies analyst name resolution order: owner > env > default.
// One name, everywhere.
//
// This screen used to have its own rule for who an action belongs to: the
// case's owner first, then CONSOLE_IR_ANALYST, then a literal "analyst" — while
// the rest of the application read USER. So a note could be signed with one
// name and its audit entry with another, and working someone else's case
// attributed your actions to *them*. An audit trail that says a.novak closed
// this case when p.osei closed it is not a record, it is a falsified one.
func TestActionsAreAttributedToWhoeverIsAtTheKeyboard(t *testing.T) {
	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer st.Close()
	if err := st.SetupAuditTables(); err != nil {
		t.Fatalf("SetupAuditTables: %v", err)
	}

	ctx := context.Background()
	logger := logging.New(os.Stdout, logging.LevelDebug, "test")
	ui := NewUI(ctx, st, &mockLLMIOC{}, logger, "test")

	// Someone else's case.
	c := store.Case{ID: "case-analyst", Title: "Owner First", Severity: "low",
		Status: "open", AssignedTo: "owner.user"}
	cm := NewCaseManagement(ui, c)
	awaitIdle(t, ui)

	ui.prefs.Analyst = "p.osei"
	if got := cm.getCurrentAnalyst(); got != "p.osei" {
		t.Errorf("an action on another analyst's case was attributed to %q, want p.osei", got)
	}

	// And the same answer the rest of the application gives.
	if got, want := cm.getCurrentAnalyst(), ui.currentAnalyst(); got != want {
		t.Errorf("the case screen says %q and the rest says %q", got, want)
	}

	// With nothing set, the environment decides — for both.
	ui.prefs.Analyst = ""
	if got, want := cm.getCurrentAnalyst(), environmentAnalyst(); got != want {
		t.Errorf("unset, the case screen says %q and the environment says %q", got, want)
	}
}

func TestTimelineRender_NoFreeze(t *testing.T) {
	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	logger := logging.New(os.Stdout, logging.LevelDebug, "test")
	ui := NewUI(ctx, st, &mockLLMIOC{}, logger, "test")
	c := store.Case{ID: "case-timeline", Title: "Timeline", Severity: "low", Status: "open"}
	cm := NewCaseManagement(ui, c)
	// The constructor starts the case's reads; they paint the same widgets this
	// test is about to write to.
	awaitIdle(t, ui)

	ev1 := store.Event{ID: "t1", Timestamp: time.Now().Add(-2 * time.Minute), EventType: "auth", Severity: "low", Message: "old", Host: "h1"}
	ev2 := store.Event{ID: "t2", Timestamp: time.Now().Add(-1 * time.Minute), EventType: "net", Severity: "high", Message: "new", Host: "h2"}
	cm.events = []store.Event{ev2, ev1} // out of order on purpose

	// Should not panic or freeze
	cm.updateTimelineView()
}
