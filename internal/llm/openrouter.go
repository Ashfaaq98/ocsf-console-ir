package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// OpenRouter implements an LLM provider backed by OpenRouter (OpenAI-compatible API).
// Docs: https://openrouter.ai/docs
type OpenRouter struct {
	endpoint   string
	model      string
	apiKey     string
	httpClient *http.Client
	logger     *log.Logger
}

// NewOpenRouter constructs a new OpenRouter provider.
// endpoint example: https://openrouter.ai/api/v1
// model example: "qwen/qwen-2.5-7b-instruct" (OpenRouter model id)
// apiKey is required; when empty this constructor will try OPENROUTER_API_KEY env var.
func NewOpenRouter(endpoint, model, apiKey string, logger *log.Logger) (*OpenRouter, error) {
	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		ep = "https://openrouter.ai/api/v1"
	}
	key := strings.TrimSpace(apiKey)
	if key == "" {
		key = strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY"))
	}
	if key == "" {
		return nil, fmt.Errorf("openrouter: apiKey required (set in settings or OPENROUTER_API_KEY)")
	}
	return &OpenRouter{
		endpoint:   strings.TrimRight(ep, "/"),
		model:      strings.TrimSpace(model),
		apiKey:     key,
		httpClient: &http.Client{Timeout: 60 * time.Second},
		logger:     logger,
	}, nil
}

// EstimateTokens provides a heuristic token estimate.
func (o *OpenRouter) EstimateTokens(text string) int {
	return EstimateTokens(text)
}

// Chat implements ChatProvider using OpenRouter's /chat/completions (OpenAI-style).
func (o *OpenRouter) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	if strings.TrimSpace(o.model) == "" {
		return &ChatResponse{Error: "openrouter: model not configured"}, nil
	}

	// Request/response payloads (OpenAI chat schema)
	type orMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type orReq struct {
		Model     string  `json:"model"`
		Messages  []orMsg `json:"messages"`
		MaxTokens int     `json:"max_tokens,omitempty"`
		// Temperature, top_p etc can be added if needed
	}
	type orChoice struct {
		Index        int   `json:"index"`
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
	}
	type orUsage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	}
	type orResp struct {
		ID      string     `json:"id"`
		Object  string     `json:"object"`
		Created int64      `json:"created"`
		Model   string     `json:"model"`
		Choices []orChoice `json:"choices"`
		Usage   orUsage    `json:"usage"`
		Error   *struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error,omitempty"`
	}

	msgs := make([]orMsg, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(m.Role))
		if role == "" {
			role = "user"
		}
		msgs = append(msgs, orMsg{Role: role, Content: m.Content})
	}

	// Prepend persona-specific system prompt when available
	if sp := GetSystemPrompt(req.Persona); sp != "" {
		msgs = append([]orMsg{{Role: "system", Content: sp}}, msgs...)
	}
	
	payload := orReq{
		Model:     o.model,
		Messages:  msgs,
		MaxTokens: req.MaxTokens,
	}
	data, _ := json.Marshal(payload)

	url := o.endpoint + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("openrouter: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)
	// Optional but recommended by OpenRouter:
	// httpReq.Header.Set("HTTP-Referer", "https://github.com/Ashfaaq98/ocsf-console-ir")
	// httpReq.Header.Set("X-Title", "Console-IR")

	resp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openrouter: request error: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("openrouter: status %d: %s", resp.StatusCode, truncateBody(string(body), 400))
	}

	var parsed orResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("openrouter: decode response: %w", err)
	}
	if parsed.Error != nil {
		return &ChatResponse{Error: parsed.Error.Message}, nil
	}
	if len(parsed.Choices) == 0 {
		return &ChatResponse{Error: "openrouter: empty choices"}, nil
	}
	content := parsed.Choices[0].Message.Content

	assistant := ChatMessage{
		Role:      "assistant",
		Content:   content,
		Timestamp: time.Now(),
		Persona:   req.Persona,
		TokensEst: EstimateTokens(content),
	}
	// Prefer usage tokens if provided
	tokens := parsed.Usage.TotalTokens
	if tokens <= 0 {
		var sb strings.Builder
		for _, m := range req.Messages {
			sb.WriteString(m.Content)
			sb.WriteString("\n")
		}
		sb.WriteString(content)
		tokens = EstimateTokens(sb.String())
	}
	// Cost: OpenRouter does not return cost; keep heuristic consistent with other providers
	cost := float64(tokens) * 0.002 / 1000.0

	return &ChatResponse{
		Message:    assistant,
		TokensUsed: tokens,
		Cost:       cost,
	}, nil
}

// SummarizeCase composes a compact summary prompt and delegates to Chat.
func (o *OpenRouter) SummarizeCase(ctx context.Context, case_ store.Case, events []store.Event) (string, error) {
	var sb strings.Builder
	sb.WriteString("You are an incident response analyst. Produce a concise, structured case summary with sections: Executive Summary, Key Findings, Notable IOCs, Affected Assets, Recommended Actions, Open Questions.\n\n")
	sb.WriteString(fmt.Sprintf("Case ID: %s | Title: %s | Severity: %s | Status: %s | Owner: %s | Events: %d\n",
		case_.ID, case_.Title, case_.Severity, case_.Status, case_.AssignedTo, len(events)))

	// Sort newest first for compactness of tail
	evs := append([]store.Event(nil), events...)
	sort.Slice(evs, func(i, j int) bool { return evs[i].Timestamp.After(evs[j].Timestamp) })
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
			truncateBody(ev.Message, 160),
		))
	}
	sb.WriteString("\nGenerate the summary now based on the above.\n")

	req := ChatRequest{
		Messages: []ChatMessage{
			{Role: "user", Content: sb.String(), Timestamp: time.Now()},
		},
		Persona:   PersonaSOC,
		MCPMode:   "remote",
		MaxTokens: 700,
	}
	r, err := o.Chat(ctx, req)
	if err != nil {
		return "", err
	}
	if r == nil || r.Error != "" {
		if r != nil {
			return "", fmt.Errorf("openrouter: %s", r.Error)
		}
		return "", fmt.Errorf("openrouter: empty response")
	}
	return r.Message.Content, nil
}

// AnalyzeEvents and GenerateRecommendations can delegate to LocalStub heuristics
// to maintain existing structured outputs where needed.
func (o *OpenRouter) AnalyzeEvents(ctx context.Context, events []store.Event) (*EventAnalysis, error) {
	ls := &LocalStub{}
	return ls.AnalyzeEvents(ctx, events)
}

func (o *OpenRouter) GenerateRecommendations(ctx context.Context, case_ store.Case, events []store.Event) ([]string, error) {
	ls := &LocalStub{}
	return ls.GenerateRecommendations(ctx, case_, events)
}

// Discovery: ListModels and HealthCheck

// ListModels queries OpenRouter /models and returns model IDs.
func (o *OpenRouter) ListModels(ctx context.Context) ([]string, error) {
	type mdl struct {
		ID string `json:"id"`
		// name, context_length, etc. exist but we only need id for now
	}
	type mdlResp struct {
		Data []mdl `json:"data"`
	}
	url := o.endpoint + "/models"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("openrouter list models: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openrouter list models: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("openrouter list models: status %d: %s", resp.StatusCode, truncateBody(string(body), 400))
	}
	var parsed mdlResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("openrouter list models: decode: %w", err)
	}
	out := make([]string, 0, len(parsed.Data))
	for _, m := range parsed.Data {
		if strings.TrimSpace(m.ID) != "" {
			out = append(out, m.ID)
		}
	}
	sort.Strings(out)
	return out, nil
}

// HealthCheck performs a lightweight GET /models using the API key.
func (o *OpenRouter) HealthCheck(ctx context.Context) error {
	url := o.endpoint + "/models"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+o.apiKey)
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("openrouter health: status %d: %s", resp.StatusCode, truncateBody(string(body), 300))
	}
	return nil
}

// Helpers

func truncateBody(s string, max int) string {
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