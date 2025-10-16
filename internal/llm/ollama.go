package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// Ollama implements a real LLM provider backed by a local Ollama server.
// It satisfies LLMProvider, ChatProvider, and Discovery.
type Ollama struct {
	endpoint   string
	model      string
	httpClient *http.Client
	logger     *log.Logger
}

// NewOllama constructs a new Ollama provider.
// endpoint example: http://localhost:11434
// model example: qwen3:0.6b (may be empty when only using discovery)
func NewOllama(endpoint, model string, logger *log.Logger) (*Ollama, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("ollama: endpoint is required")
	}
	cli := &http.Client{
		Timeout: 60 * time.Second,
	}
	return &Ollama{
		endpoint:   strings.TrimRight(endpoint, "/"),
		model:      strings.TrimSpace(model),
		httpClient: cli,
		logger:     logger,
	}, nil
}

// EstimateTokens provides a heuristic token estimate.
func (o *Ollama) EstimateTokens(text string) int {
	return EstimateTokens(text)
}

// Chat sends a chat-style request to Ollama's /api/chat endpoint (non-streaming).
func (o *Ollama) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	if o.model == "" {
		return &ChatResponse{Error: "ollama: model not configured"}, nil
	}

	type ollamaMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type chatReq struct {
		Model    string      `json:"model"`
		Messages []ollamaMsg `json:"messages"`
		Stream   bool        `json:"stream"`
		Thinking struct {
			Type string `json:"type"`
		} `json:"thinking,omitempty"`
	}
	type chatResp struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		// Optional counters present in some builds of Ollama
		EvalCount        int `json:"eval_count"`
		PromptEvalCount  int `json:"prompt_eval_count"`
		TotalDuration    int `json:"total_duration,omitempty"`
		LoadDuration     int `json:"load_duration,omitempty"`
		PromptEvalDur    int `json:"prompt_eval_duration,omitempty"`
		EvalDuration     int `json:"eval_duration,omitempty"`
	}

	msgs := make([]ollamaMsg, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(m.Role))
		if role == "" {
			role = "user"
		}
		msgs = append(msgs, ollamaMsg{
			Role:    role,
			Content: m.Content,
		})
	}
	
	// Prepend persona-specific system prompt when available.
	// This ensures the LLM receives the correct system instruction for the chosen persona.
	prompt := GetSystemPrompt(req.Persona)
	if prompt != "" {
		msgs = append([]ollamaMsg{{Role: "system", Content: prompt}}, msgs...)
	}
	
	payload := chatReq{
		Model:    o.model,
		Messages: msgs,
		Stream:   false,
	}
	// Disable reasoning/thinking content per Ollama thinking API
	payload.Thinking.Type = "disabled"

	data, _ := json.Marshal(payload)

	url := o.endpoint + "/api/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("ollama: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama: request error: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ollama: status %d: %s", resp.StatusCode, truncateString(string(body), 300))
	}

	var cr chatResp
	if err := json.Unmarshal(body, &cr); err != nil {
		return nil, fmt.Errorf("ollama: decode response: %w", err)
	}

	// Sanitize any reasoning/thinking spans from assistant content
	originalContent := cr.Message.Content
	cleanedContent := stripThinkingSections(originalContent)

	assistant := ChatMessage{
		Role:      "assistant",
		Content:   cleanedContent,
		Timestamp: time.Now(),
		Persona:   req.Persona,
		TokensEst: EstimateTokens(cleanedContent),
	}

	// Token/cost estimation based on displayed content (avoid counting hidden thinking)
	var sb strings.Builder
	for _, m := range req.Messages {
		sb.WriteString(m.Content)
		sb.WriteString("\n")
	}
	sb.WriteString(cleanedContent)
	tokens := EstimateTokens(sb.String())
	cost := float64(tokens) * 0.002 / 1000.0

	return &ChatResponse{
		Message:    assistant,
		TokensUsed: tokens,
		Cost:       cost,
	}, nil
}

// SummarizeCase builds a compact summary prompt and delegates to Chat.
func (o *Ollama) SummarizeCase(ctx context.Context, case_ store.Case, events []store.Event) (string, error) {
	// Compact prompt similar in spirit to the UI builder, but simplified.
	var sb strings.Builder
	sb.WriteString("You are an incident response analyst. Produce a concise, structured case summary with sections: Executive Summary, Key Findings, Notable IOCs, Affected Assets, Recommended Actions, Open Questions.\n\n")
	sb.WriteString(fmt.Sprintf("Case ID: %s | Title: %s | Severity: %s | Status: %s | Owner: %s | Events: %d\n",
		case_.ID, case_.Title, case_.Severity, case_.Status, case_.AssignedTo, len(events)))
	// Sort newest first for compactness of tail
	evs := append([]store.Event(nil), events...)
	sortEventsByTimeDesc(evs)
	limit := 120
	if len(evs) < limit {
		limit = len(evs)
	}
	sb.WriteString("\nRecent Events (up to 120):\n")
	for i := 0; i < limit; i++ {
		ev := evs[i]
		sb.WriteString(fmt.Sprintf("- %s | %s | sev=%s | host=%s | %s\n",
			ev.Timestamp.Format("2006-01-02 15:04:05"),
			ev.EventType,
			strings.ToUpper(ev.Severity),
			ev.Host,
			truncateString(ev.Message, 160),
		))
	}
	sb.WriteString("\nGenerate the summary now based on the above.\n")

	req := ChatRequest{
		Messages: []ChatMessage{
			{
				Role:      "user",
				Content:   sb.String(),
				Timestamp: time.Now(),
			},
		},
		Persona:   PersonaSOC,
		MCPMode:   "local",
		MaxTokens: 700,
	}
	resp, err := o.Chat(ctx, req)
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Error != "" {
		if resp != nil && resp.Error != "" {
			return "", fmt.Errorf("ollama: %s", resp.Error)
		}
		return "", fmt.Errorf("ollama: empty response")
	}
	return resp.Message.Content, nil
}

// AnalyzeEvents currently defers to LocalStub heuristics for structured output.
// This keeps a stable JSON-ish shape for callers without having to parse LLM text.
func (o *Ollama) AnalyzeEvents(ctx context.Context, events []store.Event) (*EventAnalysis, error) {
	ls := &LocalStub{}
	return ls.AnalyzeEvents(ctx, events)
}

// GenerateRecommendations currently defers to LocalStub heuristics.
func (o *Ollama) GenerateRecommendations(ctx context.Context, case_ store.Case, events []store.Event) ([]string, error) {
	ls := &LocalStub{}
	return ls.GenerateRecommendations(ctx, case_, events)
}

// ListModels queries Ollama /api/tags and returns available model names.
func (o *Ollama) ListModels(ctx context.Context) ([]string, error) {
	type tagModel struct {
		Name string `json:"name"`
	}
	type tagsResp struct {
		Models []tagModel `json:"models"`
	}

	url := o.endpoint + "/api/tags"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("ollama list models: %w", err)
	}
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama list models: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama list models: status %d: %s", resp.StatusCode, truncateString(string(body), 300))
	}
	body, _ := io.ReadAll(resp.Body)
	var tr tagsResp
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("ollama list models: decode: %w", err)
	}
	out := make([]string, 0, len(tr.Models))
	for _, m := range tr.Models {
		if strings.TrimSpace(m.Name) != "" {
			out = append(out, m.Name)
		}
	}
	return out, nil
}

// HealthCheck performs a lightweight check against /api/tags.
func (o *Ollama) HealthCheck(ctx context.Context) error {
	url := o.endpoint + "/api/tags"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ollama health: status %d: %s", resp.StatusCode, truncateString(string(body), 200))
	}
	return nil
}

// Helper functions

func truncateString(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// stripThinkingSections removes common reasoning/thinking blocks from model output.
// It strips tags like <think>...</think> and <thinking>...</thinking> in a case-insensitive,
// whitespace-tolerant manner, then trims surrounding whitespace.
func stripThinkingSections(s string) string {
	if s == "" {
		return s
	}
	// Remove <think>...</think>
	reThink := regexp.MustCompile(`(?is)<\s*think\s*>.*?<\s*/\s*think\s*>`)
	s = reThink.ReplaceAllString(s, "")
	// Remove <thinking>...</thinking>
	reThinking := regexp.MustCompile(`(?is)<\s*thinking\s*>.*?<\s*/\s*thinking\s*>`)
	s = reThinking.ReplaceAllString(s, "")
	return strings.TrimSpace(s)
}

func sortEventsByTimeDesc(evs []store.Event) {
	// local minimal sort to avoid importing "sort" here repeatedly
	// (kept here to keep file dependency small)
	if len(evs) <= 1 {
		return
	}
	// Simple insertion sort for small slices (N up to a few hundred typical)
	for i := 1; i < len(evs); i++ {
		j := i
		for j > 0 && evs[j-1].Timestamp.Before(evs[j].Timestamp) {
			evs[j-1], evs[j] = evs[j], evs[j-1]
			j--
		}
	}
}