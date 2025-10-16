package ui

import (
	"context"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// mockLLM implements llm.LLMProvider for tests
type mockLLM struct{}

func (m *mockLLM) SummarizeCase(ctx context.Context, case_ store.Case, events []store.Event) (string, error) {
	return "summary", nil
}
func (m *mockLLM) AnalyzeEvents(ctx context.Context, events []store.Event) (*llm.EventAnalysis, error) {
	return &llm.EventAnalysis{Summary: "ok", Severity: "medium", Confidence: 0.5}, nil
}
func (m *mockLLM) GenerateRecommendations(ctx context.Context, case_ store.Case, events []store.Event) ([]string, error) {
	return []string{"rec"}, nil
}

// TestToggleEventSelectionUsesCurrentTableSelection verifies that toggleEventSelection()
// acts on the currently highlighted row in the table (via GetSelection), independent
// of any cached index, and supports multi-select across rows reliably.
func TestToggleEventSelectionUsesCurrentTableSelection(t *testing.T) {
	tmp := "./test_cm_toggle.db"
	_ = os.Remove(tmp)
	defer os.Remove(tmp)

	st, err := store.NewStore(tmp)
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	logger := log.New(os.Stdout, "[TEST] ", 0)
	ui := NewUI(ctx, st, &mockLLM{}, logger)

	c := store.Case{ID: "case-1", Title: "Test Case", Severity: "low", Status: "open"}
	cm := NewCaseManagement(ui, c)

	// Provide two events (ensure timestamps sort into a deterministic order: newest first)
	e1 := store.Event{
		ID:        "e1",
		Timestamp: time.Now().Add(-1 * time.Minute),
		EventType: "proc",
		Severity:  "low",
		Message:   "first event",
		Host:      "host1",
	}
	e2 := store.Event{
		ID:        "e2",
		Timestamp: time.Now(),
		EventType: "net",
		Severity:  "high",
		Message:   "second event",
		Host:      "host2",
	}

	cm.events = []store.Event{e1, e2}
	cm.selectedEventIDs = make(map[string]bool)
	cm.updateEventsTable() // renders rows and applies sort (newest first)

	// After sorting, cm.events[0] should be e2 (newest), cm.events[1] should be e1 (older).
	if len(cm.events) != 2 {
		t.Fatalf("expected 2 events in cm.events, got %d", len(cm.events))
	}

	// Select row 1 (first data row) and toggle selection.
	// Header is row 0; data starts at 1.
	cm.eventsTable.Select(1, 0)
	cm.toggleEventSelection()
	if len(cm.selectedEventIDs) != 1 {
		t.Fatalf("expected 1 selected event after first toggle, got %d", len(cm.selectedEventIDs))
	}
	if !cm.selectedEventIDs[cm.events[0].ID] {
		t.Fatalf("expected selected event to be %s", cm.events[0].ID)
	}

	// Move to row 2 (second data row) and toggle selection.
	cm.eventsTable.Select(2, 0)
	cm.toggleEventSelection()
	if len(cm.selectedEventIDs) != 2 {
		t.Fatalf("expected 2 selected events after second toggle, got %d", len(cm.selectedEventIDs))
	}
	if !cm.selectedEventIDs[cm.events[1].ID] {
		t.Fatalf("expected selected event to include %s", cm.events[1].ID)
	}

	// Deselect the first row again to ensure idempotent toggle behavior.
	cm.eventsTable.Select(1, 0)
	cm.toggleEventSelection()
	if len(cm.selectedEventIDs) != 1 {
		t.Fatalf("expected 1 selected event after deselect, got %d", len(cm.selectedEventIDs))
	}
	if cm.selectedEventIDs[cm.events[0].ID] {
		t.Fatalf("did not expect %s to remain selected", cm.events[0].ID)
	}
}

// TestExtractIOCsAggregates ensures basic aggregation across IPs/domains/URLs/hashes.
func TestExtractIOCsAggregates(t *testing.T) {
	tmp := "./test_cm_iocs.db"
	_ = os.Remove(tmp)
	defer os.Remove(tmp)

	st, err := store.NewStore(tmp)
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	logger := log.New(os.Stdout, "[TEST] ", 0)
	ui := NewUI(ctx, st, &mockLLM{}, logger)
	c := store.Case{ID: "case-2", Title: "IOC Case", Severity: "medium", Status: "open"}
	cm := NewCaseManagement(ui, c)

	// Two events referencing the same IP and various domains/URLs/hashes
	hashMD5 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ev1 := store.Event{
		ID:        "ev1",
		Timestamp: time.Now().Add(-2 * time.Minute),
		Message:   "Contact http://example.com/path and IP 10.0.0.1 and hash " + hashMD5,
		Host:      "host.example.com",
	}
	ev2 := store.Event{
		ID:        "ev2",
		Timestamp: time.Now().Add(-1 * time.Minute),
		Message:   "Visit https://evil.example.net/login then 10.0.0.1 and foo.example.com",
	}

	cm.baseEvents = []store.Event{ev1, ev2}
	cm.extractIOCs()

	if cm.iocIndex == nil {
		t.Fatalf("iocIndex not built")
	}

	// helper to find an IOC by type and value
	find := func(typ, val string) (IOCItem, bool) {
		items := cm.iocIndex[typ]
		for _, it := range items {
			if it.Value == val {
				return it, true
			}
		}
		return IOCItem{}, false
	}

	// IP aggregated twice
	if it, ok := find("ip", "10.0.0.1"); !ok {
		t.Fatalf("expected ip 10.0.0.1")
	} else if it.Count != 2 {
		t.Fatalf("expected ip 10.0.0.1 count=2, got %d", it.Count)
	}

	// Domain from URL
	if _, ok := find("domain", "example.com"); !ok {
		// At least one of the domains should be present; accept evil.example.net as alternative if example.com not found.
		if _, ok2 := find("domain", "evil.example.net"); !ok2 {
			t.Fatalf("expected domain example.com or evil.example.net")
		}
	}

	// Domain from host field
	if _, ok := find("domain", "host.example.com"); !ok {
		t.Fatalf("expected domain host.example.com from host field")
	}

	// Hash
	if _, ok := find("hash", hashMD5); !ok {
		t.Fatalf("expected hash %s", hashMD5)
	}
}

// Additional tests for Overview LLM summary feature

// mockLLMChat implements llm.ChatProvider (Chat + LLM) for deterministic tests
type mockLLMChat struct{}

func (m *mockLLMChat) SummarizeCase(ctx context.Context, case_ store.Case, events []store.Event) (string, error) {
	return "summary-fallback", nil
}
func (m *mockLLMChat) AnalyzeEvents(ctx context.Context, events []store.Event) (*llm.EventAnalysis, error) {
	return &llm.EventAnalysis{Summary: "ok", Severity: "medium", Confidence: 0.5}, nil
}
func (m *mockLLMChat) GenerateRecommendations(ctx context.Context, case_ store.Case, events []store.Event) ([]string, error) {
	return []string{"rec"}, nil
}
func (m *mockLLMChat) Chat(ctx context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
	return &llm.ChatResponse{
		Message: llm.ChatMessage{
			Role:      "assistant",
			Content:   "summary-chat",
			Timestamp: time.Now(),
			Persona:   req.Persona,
		},
		TokensUsed: 123,
		Cost:       0.0003,
	}, nil
}
func (m *mockLLMChat) EstimateTokens(text string) int { return 100 }

// TestBuildCaseSummaryPromptBasic verifies prompt composition includes key headers and event details.
func TestBuildCaseSummaryPromptBasic(t *testing.T) {
	tmp := "./test_cm_prompt.db"
	_ = os.Remove(tmp)
	defer os.Remove(tmp)

	st, err := store.NewStore(tmp)
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	logger := log.New(os.Stdout, "[TEST] ", 0)
	ui := NewUI(ctx, st, &mockLLMChat{}, logger)

	c := store.Case{ID: "case-3", Title: "Prompt Case", Severity: "high", Status: "open", AssignedTo: "analyst"}
	cm := NewCaseManagement(ui, c)

	ev := store.Event{
		ID:        "p1",
		Timestamp: time.Now().Add(-30 * time.Minute),
		EventType: "network",
		Severity:  "medium",
		Host:      "hostx",
		Message:   "connection to example.org/login succeeded",
	}
	events := []store.Event{ev}

	prompt := cm.buildCaseSummaryPrompt(events, 5, 2, 3)
	if !strings.Contains(prompt, "Case:") {
		t.Fatalf("expected prompt to contain 'Case:' header, got: %q", prompt)
	}
	if !strings.Contains(prompt, "Events by type") {
		t.Fatalf("expected prompt to contain 'Events by type', got: %q", prompt)
	}
	if !strings.Contains(prompt, ev.EventType) || !strings.Contains(prompt, "connection to") {
		t.Fatalf("expected prompt to include event details, got: %q", prompt)
	}
}

// TestFormatActionDescriptionCaseSummary ensures audit label mapping for 'case_summary'.
func TestFormatActionDescriptionCaseSummary(t *testing.T) {
	tmp := "./test_cm_fmt.db"
	_ = os.Remove(tmp)
	defer os.Remove(tmp)

	st, err := store.NewStore(tmp)
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	logger := log.New(os.Stdout, "[TEST] ", 0)
	ui := NewUI(ctx, st, &mockLLMChat{}, logger)
	c := store.Case{ID: "case-4", Title: "Fmt Case", Severity: "low", Status: "open"}
	cm := NewCaseManagement(ui, c)

	got := cm.formatActionDescription("case_summary", nil)
	if !strings.Contains(got, "Case summary") {
		t.Fatalf("expected friendly description for case_summary, got: %q", got)
	}
}