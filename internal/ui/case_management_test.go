package ui

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/llm"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
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
	logger := logging.New(os.Stdout, logging.LevelDebug, "test")
	ui := NewUI(ctx, st, &mockLLM{}, logger, "test")
	c := store.Case{ID: "case-2", Title: "IOC Case", Severity: "medium", Status: "open"}
	cm := NewCaseManagement(ui, c)
	// The constructor starts the case's reads; they paint the same widgets this
	// test is about to write to.
	awaitIdle(t, ui)

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
	logger := logging.New(os.Stdout, logging.LevelDebug, "test")
	ui := NewUI(ctx, st, &mockLLMChat{}, logger, "test")

	c := store.Case{ID: "case-3", Title: "Prompt Case", Severity: "high", Status: "open", AssignedTo: "analyst"}
	cm := NewCaseManagement(ui, c)
	// The constructor starts the case's reads; they paint the same widgets this
	// test is about to write to.
	awaitIdle(t, ui)

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
	logger := logging.New(os.Stdout, logging.LevelDebug, "test")
	ui := NewUI(ctx, st, &mockLLMChat{}, logger, "test")
	c := store.Case{ID: "case-4", Title: "Fmt Case", Severity: "low", Status: "open"}
	cm := NewCaseManagement(ui, c)
	// The constructor starts the case's reads; they paint the same widgets this
	// test is about to write to.
	awaitIdle(t, ui)

	got := cm.formatActionDescription("case_summary", nil)
	if !strings.Contains(got, "Case summary") {
		t.Fatalf("expected friendly description for case_summary, got: %q", got)
	}
}

// TestExtractIOCsUsesObservables verifies the IOC view reads the observables
// table rather than re-deriving indicators by scraping message text, and that
// producer-asserted indicators are distinguishable from inferred ones.
func TestExtractIOCsUsesObservables(t *testing.T) {
	tmp := "./test_cm_observables.db"
	_ = os.Remove(tmp)
	defer os.Remove(tmp)

	st, err := store.NewStore(tmp)
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer st.Close()

	ctx := context.Background()

	// The message deliberately contains NO indicators: everything found must
	// have come from the observables table.
	ev := &ocsf.Event{
		Time:        time.Now(),
		ClassUID:    4001,
		SeverityID:  3,
		Message:     "connection established",
		SrcEndpoint: &ocsf.Endpoint{IP: "192.168.1.100"},
		Device:      &ocsf.Device{Hostname: "workstation-07"},
		Observables: []ocsf.Observable{
			{Name: "dst_endpoint.ip", TypeID: ocsf.ObservableTypeIPAddress, Value: "8.8.8.8"},
		},
	}
	ev.Metadata.UID = "meta-ui-1"

	eventID, err := st.SaveEvent(ctx, ev)
	if err != nil {
		t.Fatalf("SaveEvent: %v", err)
	}

	stored, err := st.GetAllEvents(ctx, 10)
	if err != nil || len(stored) != 1 {
		t.Fatalf("GetAllEvents: %v (n=%d)", err, len(stored))
	}

	logger := logging.New(os.Stdout, logging.LevelDebug, "test")
	ui := NewUI(ctx, st, &mockLLM{}, logger, "test")
	cm := NewCaseManagement(ui, store.Case{ID: "case-obs", Title: "Obs", Severity: "medium", Status: "open"})
	cm.baseEvents = stored
	cm.extractIOCs()

	find := func(typ, val string) (IOCItem, bool) {
		for _, it := range cm.iocIndex[typ] {
			if it.Value == val {
				return it, true
			}
		}
		return IOCItem{}, false
	}

	// Asserted by the producer.
	dst, ok := find("ip", "8.8.8.8")
	if !ok {
		t.Fatalf("expected asserted observable 8.8.8.8 to appear; message text contains no indicators")
	}
	if !dst.Asserted {
		t.Errorf("8.8.8.8 should be marked asserted")
	}
	if dst.TypeID != ocsf.ObservableTypeIPAddress {
		t.Errorf("expected type_id %d, got %d", ocsf.ObservableTypeIPAddress, dst.TypeID)
	}

	// Derived by Console-IR from a structured field.
	src, ok := find("ip", "192.168.1.100")
	if !ok {
		t.Fatalf("expected derived observable 192.168.1.100")
	}
	if src.Asserted {
		t.Errorf("192.168.1.100 was not asserted by the source and must not be marked as such")
	}

	if host, ok := find("domain", "workstation-07"); !ok {
		t.Errorf("expected device.hostname in the domain bucket")
	} else if host.Asserted {
		t.Errorf("workstation-07 should be derived, not asserted")
	}

	// The indicator pivot resolves back to the event.
	hits, err := st.FindEventsByObservable(ctx, ocsf.ObservableTypeIPAddress, "8.8.8.8", 0)
	if err != nil {
		t.Fatalf("FindEventsByObservable: %v", err)
	}
	if len(hits) != 1 || hits[0].ID != eventID {
		t.Fatalf("expected pivot to return the source event, got %d hits", len(hits))
	}
}
