package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

func newOpenRouterTestServer(t *testing.T) (*httptest.Server, *int, *int) {
	t.Helper()
	chatCalls := 0
	modelsCalls := 0

	mux := http.NewServeMux()

	mux.HandleFunc("/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		chatCalls++
		// Require Authorization header
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		type req struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			MaxTokens int `json:"max_tokens"`
		}
		var body req
		_ = json.NewDecoder(r.Body).Decode(&body)
		if strings.TrimSpace(body.Model) == "" {
			http.Error(w, "model required", http.StatusBadRequest)
			return
		}

		resp := map[string]interface{}{
			"id":      "chatcmpl-test",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   body.Model,
			"choices": []map[string]interface{}{
				{
					"index":         0,
					"finish_reason": "stop",
					"message": map[string]string{
						"role":    "assistant",
						"content": "Hello from OpenRouter mock",
					},
				},
			},
			"usage": map[string]int{
				"prompt_tokens":     7,
				"completion_tokens": 3,
				"total_tokens":      10,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/models", func(w http.ResponseWriter, r *http.Request) {
		modelsCalls++
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		resp := map[string]interface{}{
			"data": []map[string]string{
				{"id": "b-model"},
				{"id": "a-model"},
				{"id": "c-model"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(mux)
	return srv, &chatCalls, &modelsCalls
}

func TestOpenRouterChatSuccess(t *testing.T) {
	srv, chatCalls, _ := newOpenRouterTestServer(t)
	defer srv.Close()

	provider, err := NewOpenRouter(srv.URL, "test-model", "testkey", nil)
	if err != nil {
		t.Fatalf("NewOpenRouter error: %v", err)
	}

	req := ChatRequest{
		Messages: []ChatMessage{
			{Role: "user", Content: "Hi"},
		},
		Persona:   "IR Analyst",
		MaxTokens: 64,
	}

	resp, err := provider.Chat(context.Background(), req)
	if err != nil {
		t.Fatalf("Chat error: %v", err)
	}
	if resp == nil || resp.Error != "" {
		t.Fatalf("Chat returned error response: %+v", resp)
	}
	if resp.Message.Content == "" || !strings.Contains(resp.Message.Content, "OpenRouter mock") {
		t.Errorf("unexpected message content: %q", resp.Message.Content)
	}
	if resp.TokensUsed != 10 {
		t.Errorf("expected tokens=10, got %d", resp.TokensUsed)
	}
	if *chatCalls != 1 {
		t.Errorf("expected 1 chat call, got %d", *chatCalls)
	}
}

func TestOpenRouterChatNoModel(t *testing.T) {
	// Provider with empty model
	provider, err := NewOpenRouter("https://example.com", "", "key", nil)
	if err != nil {
		t.Fatalf("NewOpenRouter error: %v", err)
	}
	resp, err := provider.Chat(context.Background(), ChatRequest{
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Chat unexpected transport error: %v", err)
	}
	if resp == nil || resp.Error == "" {
		t.Fatalf("expected ChatResponse with Error due to empty model, got: %#v", resp)
	}
}

func TestOpenRouterListModelsAndHealthCheck(t *testing.T) {
	srv, _, modelsCalls := newOpenRouterTestServer(t)
	defer srv.Close()

	provider, err := NewOpenRouter(srv.URL, "any-model", "testkey", nil)
	if err != nil {
		t.Fatalf("NewOpenRouter error: %v", err)
	}

	// ListModels
	list, err := provider.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels error: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 models, got %d", len(list))
	}
	// Ensure sorted
	sorted := append([]string(nil), list...)
	sort.Strings(sorted)
	for i := range list {
		if list[i] != sorted[i] {
			t.Errorf("models not sorted: got=%v", list)
			break
		}
	}

	// HealthCheck
	if err := provider.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck error: %v", err)
	}
	if *modelsCalls == 0 {
		t.Errorf("expected at least one /models call, got %d", *modelsCalls)
	}
}

func TestBuildOpenRouterWithEnvAPIKeyAndDiscovery(t *testing.T) {
	srv, _, _ := newOpenRouterTestServer(t)
	defer srv.Close()

	// Ensure env var is used when APIKey is blank
	_ = os.Setenv("OPENROUTER_API_KEY", "env-key")
	defer os.Unsetenv("OPENROUTER_API_KEY")

	cfg := ProviderConfig{
		Provider: "openrouter",
		Endpoint: srv.URL,
		Model:    "m", // model can be anything for discovery/health
		APIKey:   "",  // force env usage
	}
	p, err := Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}

	// Discovery: ListModels + HealthCheck via helpers
	if err := TryHealthCheck(context.Background(), p); err != nil {
		t.Fatalf("TryHealthCheck error: %v", err)
	}
	models, err := TryListModels(context.Background(), p)
	if err != nil {
		t.Fatalf("TryListModels error: %v", err)
	}
	if len(models) == 0 {
		t.Fatalf("expected some models from discovery, got 0")
	}
}

// Basic smoke test for SummarizeCase wiring. We verify it returns content using the mock Chat path.
func TestOpenRouterSummarizeCase(t *testing.T) {
	srv, _, _ := newOpenRouterTestServer(t)
	defer srv.Close()

	p, err := NewOpenRouter(srv.URL, "m", "k", nil)
	if err != nil {
		t.Fatalf("NewOpenRouter: %v", err)
	}

	evs := []store.Event{
		{ID: "1", EventType: "process", Severity: "low", Host: "host1", Message: "proc started", Timestamp: time.Now()},
		{ID: "2", EventType: "network", Severity: "medium", Host: "host2", Message: "conn out", Timestamp: time.Now()},
	}
	sum, err := p.SummarizeCase(context.Background(), store.Case{
		ID:         "C-1",
		Title:      "Case 1",
		Severity:   "medium",
		Status:     "open",
		AssignedTo: "analyst",
	}, evs)
	if err != nil {
		t.Fatalf("SummarizeCase error: %v", err)
	}
	if !strings.Contains(sum, "OpenRouter mock") {
		t.Errorf("unexpected summary content: %q", sum)
	}
}