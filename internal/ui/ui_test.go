package ui

import (
	"context"
	"log"
	"os"
	"testing"
	"time"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// mockLLMProvider implements llm.LLMProvider for testing
type mockLLMProvider struct{}

func (m *mockLLMProvider) SummarizeCase(ctx context.Context, case_ store.Case, events []store.Event) (string, error) {
	return "Mock case summary", nil
}

func (m *mockLLMProvider) AnalyzeEvents(ctx context.Context, events []store.Event) (*llm.EventAnalysis, error) {
	return &llm.EventAnalysis{
		Summary:    "Mock analysis",
		Severity:   "medium",
		Confidence: 0.8,
	}, nil
}

func (m *mockLLMProvider) GenerateRecommendations(ctx context.Context, case_ store.Case, events []store.Event) ([]string, error) {
	return []string{"Mock recommendation"}, nil
}

func TestNewUI(t *testing.T) {
	// Create temporary database
	tmpDB := "./test_console_ir.db"
	defer os.Remove(tmpDB)

	storeInstance, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer storeInstance.Close()

	ctx := context.Background()
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	mockLLM := &mockLLMProvider{}

	ui := NewUI(ctx, storeInstance, mockLLM, logger)

	// Test initial state
	if ui.selectedEventIDs == nil {
		t.Error("selectedEventIDs map should be initialized")
	}

	if len(ui.selectedEventIDs) != 0 {
		t.Error("selectedEventIDs should be empty initially")
	}

	// Test stats
	stats := ui.GetStats()
	if stats["selected_events"] != 0 {
		t.Error("selected_events should be 0 initially")
	}
}

func TestEventSelection(t *testing.T) {
	// Create temporary database
	tmpDB := "./test_console_ir_selection.db"
	defer os.Remove(tmpDB)

	storeInstance, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer storeInstance.Close()

	ctx := context.Background()
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	mockLLM := &mockLLMProvider{}

	ui := NewUI(ctx, storeInstance, mockLLM, logger)

	// Create test events by manually setting the events slice
	ui.events = make([]store.Event, 2)
	ui.events[0] = store.Event{
		ID:        "event1",
		Timestamp: time.Now(),
		EventType: "test",
		Severity:  "medium",
		Message:   "Test event 1",
		Host:      "testhost1",
	}
	ui.events[1] = store.Event{
		ID:        "event2",
		Timestamp: time.Now(),
		EventType: "test",
		Severity:  "high",
		Message:   "Test event 2",
		Host:      "testhost2",
	}

	// Test selectAllEvents
	ui.selectAllEvents()
	if len(ui.selectedEventIDs) != 2 {
		t.Errorf("Expected 2 selected events, got %d", len(ui.selectedEventIDs))
	}

	if !ui.selectedEventIDs["event1"] || !ui.selectedEventIDs["event2"] {
		t.Error("Both events should be selected")
	}

	// Test deselectAllEvents
	ui.deselectAllEvents()
	if len(ui.selectedEventIDs) != 0 {
		t.Errorf("Expected 0 selected events, got %d", len(ui.selectedEventIDs))
	}

	// Test individual selection
	ui.selectedEventIDs["event1"] = true
	stats := ui.GetStats()
	if stats["selected_events"] != 1 {
		t.Errorf("Expected 1 selected event in stats, got %v", stats["selected_events"])
	}
}

func TestCaseCreation(t *testing.T) {
	// Create temporary database
	tmpDB := "./test_console_ir_case.db"
	defer os.Remove(tmpDB)

	storeInstance, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer storeInstance.Close()

	ctx := context.Background()
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	mockLLM := &mockLLMProvider{}

	ui := NewUI(ctx, storeInstance, mockLLM, logger)

	// Create test OCSF event
	ocsfEvent := &ocsf.Event{
		Time:     time.Now(),
		Message:  "Test event for case creation",
		ClassUID: 1001, // Process activity
		Severity: "medium",
		Device: &ocsf.Device{
			Hostname: "testhost",
		},
	}

	// Save event to database
	eventID, err := storeInstance.SaveEvent(ctx, ocsfEvent)
	if err != nil {
		t.Fatalf("Failed to save test event: %v", err)
	}

	// Select the event
	ui.selectedEventIDs = map[string]bool{eventID: true}

	// Test case creation (this would normally be called by the UI)
	ui.createCaseWithEvents("Test Case", "Test Description", "medium", "test-user")

	// Give some time for the goroutine to complete
	time.Sleep(200 * time.Millisecond)

	// Verify case was created
	cases, err := storeInstance.ListCases(ctx)
	if err != nil {
		t.Fatalf("Failed to list cases: %v", err)
	}

	if len(cases) == 0 {
		t.Error("Expected at least one case to be created")
		return
	}

	// Find our test case
	var testCase *store.Case
	for i := range cases {
		if cases[i].Title == "Test Case" {
			testCase = &cases[i]
			break
		}
	}

	if testCase == nil {
		t.Error("Test case not found")
		return
	}

	if testCase.Description != "Test Description" {
		t.Errorf("Expected description 'Test Description', got '%s'", testCase.Description)
	}

	if testCase.Severity != "medium" {
		t.Errorf("Expected severity 'medium', got '%s'", testCase.Severity)
	}

	if testCase.AssignedTo != "test-user" {
		t.Errorf("Expected assigned to 'test-user', got '%s'", testCase.AssignedTo)
	}

	// Verify event was assigned to case
	events, err := storeInstance.GetEventsByCase(ctx, testCase.ID)
	if err != nil {
		t.Fatalf("Failed to get events for case: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 event assigned to case, got %d", len(events))
	}
}

func TestAddEventsToExistingCase(t *testing.T) {
	// Create temporary database
	tmpDB := "./test_console_ir_add.db"
	defer os.Remove(tmpDB)

	storeInstance, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer storeInstance.Close()

	ctx := context.Background()
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	mockLLM := &mockLLMProvider{}

	ui := NewUI(ctx, storeInstance, mockLLM, logger)

	// Create a test case
	testCase := store.Case{
		Title:       "Existing Case",
		Description: "Test case for adding events",
		Severity:    "high",
		Status:      "open",
	}

	caseID, err := storeInstance.CreateOrUpdateCase(ctx, testCase)
	if err != nil {
		t.Fatalf("Failed to create test case: %v", err)
	}

	// Create test OCSF event
	ocsfEvent := &ocsf.Event{
		Time:     time.Now(),
		Message:  "Test event for adding to case",
		ClassUID: 1001, // Process activity
		Severity: "medium",
	}

	// Save event to database
	eventID, err := storeInstance.SaveEvent(ctx, ocsfEvent)
	if err != nil {
		t.Fatalf("Failed to save test event: %v", err)
	}

	// Set up UI state
	ui.cases = make([]store.Case, 1)
	ui.cases[0] = store.Case{
		ID:          caseID,
		Title:       "Existing Case",
		Description: "Test case for adding events",
		Severity:    "high",
		Status:      "open",
		EventCount:  0,
	}
	
	ui.selectedEventIDs = map[string]bool{eventID: true}

	// Test adding events to existing case
	ui.addEventsToCase("1") // First case in the list

	// Give some time for the goroutine to complete
	time.Sleep(200 * time.Millisecond)

	// Verify event was assigned to case
	events, err := storeInstance.GetEventsByCase(ctx, caseID)
	if err != nil {
		t.Fatalf("Failed to get events for case: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 event assigned to case, got %d", len(events))
	}

	if len(events) > 0 && events[0].CaseID != caseID {
		t.Errorf("Event not properly assigned to case. Expected case ID %s, got %s", caseID, events[0].CaseID)
	}
}

// The following tests validate the context-sensitive 'd' key handling and hints.

func TestGlobalDeleteKey_ContextSensitive(t *testing.T) {
	// Setup temp DB-backed UI
	tmpDB := "./test_console_ir_ui_del.db"
	_ = os.Remove(tmpDB)
	defer os.Remove(tmpDB)

	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store.NewStore error: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	logger := log.New(os.Stdout, "[TEST] ", 0)
	mock := &mockLLMProvider{}
	ui := NewUI(ctx, st, mock, logger)

	// Prepare one case in sidebar without using updateCasesList (which queues UI updates requiring app.Run).
	ui.cases = []store.Case{
		{ID: "case-1", Title: "C1", Severity: "low", Status: "open"},
	}
	ui.sidebar.Clear()
	ui.sidebar.AddItem("C1", "1 events | open", 0, nil)
	ui.sidebar.SetCurrentItem(0)
	ui.app.SetFocus(ui.sidebar)

	if ui.globalInputCapture == nil {
		t.Fatalf("global input handler not initialized")
	}
	if ui.selectedCaseID != "" {
		t.Fatalf("expected no selectedCaseID initially, got %q", ui.selectedCaseID)
	}

	// Press global 'd' while sidebar is focused -> should consume and open delete flow (modal),
	// and pre-derive selectedCaseID from hovered row.
	ev := tcell.NewEventKey(tcell.KeyRune, 'd', 0)
	ret := ui.globalInputCapture(ev)
	if ret != nil {
		t.Fatalf("expected 'd' to be consumed in sidebar context (ret=nil), got non-nil")
	}
	if ui.selectedCaseID == "" {
		t.Fatalf("expected selectedCaseID to be derived after 'd' in sidebar focus")
	}
}

func TestEventListDeleteKey_NoSelectionConsumed(t *testing.T) {
	tmpDB := "./test_console_ir_ui_ev_del.db"
	_ = os.Remove(tmpDB)
	defer os.Remove(tmpDB)

	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store.NewStore error: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	logger := log.New(os.Stdout, "[TEST] ", 0)
	ui := NewUI(ctx, st, &mockLLMProvider{}, logger)

	// Focus events table; ensure no selection and trigger 'd'
	ui.app.SetFocus(ui.eventList)
	capture := ui.eventList.GetInputCapture()
	if capture == nil {
		t.Fatalf("eventList input capture not set")
	}
	ev := tcell.NewEventKey(tcell.KeyRune, 'd', 0)
	ret := capture(ev)
	// With zero selected events, handler should consume the key (status warning), not propagate.
	if ret != nil {
		t.Fatalf("expected eventList handler to consume 'd' when no selection, got non-nil")
	}
}

func TestHintsShowDeleteForEventsSelection(t *testing.T) {
	tmpDB := "./test_console_ir_ui_hints.db"
	_ = os.Remove(tmpDB)
	defer os.Remove(tmpDB)

	st, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store.NewStore error: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	logger := log.New(os.Stdout, "[TEST] ", 0)
	ui := NewUI(ctx, st, &mockLLMProvider{}, logger)

	// Focus events table with a selection so hints include "d:delete"
	ui.app.SetFocus(ui.eventList)
	ui.selectedEventIDs["evt-1"] = true

	hints := ui.buildShortcutHints()
	// Strip tview color tags like [#hex] and [-] so we can assert on plain text tokens.
	strip := func(s string) string {
		var b strings.Builder
		in := false
		for _, r := range s {
			if r == '[' {
				in = true
				continue
			}
			if r == ']' {
				in = false
				continue
			}
			if !in {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	plain := strip(hints)
	if !strings.Contains(plain, "d:delete") {
		t.Fatalf("expected hints to contain 'd:delete' when events are selected; got: %s", plain)
	}
}