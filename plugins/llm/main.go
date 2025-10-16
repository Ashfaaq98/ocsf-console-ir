package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"
 
	"github.com/go-redis/redis/v8"
)

// LLMPlugin represents the LLM enrichment plugin
type LLMPlugin struct {
	client *redis.Client
	logger *log.Logger
	ctx    context.Context
	cancel context.CancelFunc

	// Configuration
	redisURL         string
	consumerName     string
	groupName        string
	apiKey           string
	apiProvider      string // "openai" or "claude"
	model            string
	temperature      float64
	maxTokens        int
	stopWords        []string
	promptTemplate   *template.Template
	promptFile       string
	// Enhancements
	dryRun           bool
	dryRunResponse   string
	openaiBaseURL    string
	anthropicBaseURL string
	retries          int
}

// EventMessage represents an event from the Redis stream
type EventMessage struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	RawJSON   string `json:"raw_json"`
	Timestamp int64  `json:"timestamp"`
}

// EnrichmentMessage represents an enrichment to be published
type EnrichmentMessage struct {
	EventID    string            `json:"event_id"`
	Source     string            `json:"source"`
	Type       string            `json:"type"`
	Data       map[string]string `json:"data"`
	Timestamp  int64             `json:"timestamp"`
	PluginName string            `json:"plugin_name"`
}

// OpenAI API structures
type OpenAIRequest struct {
	Model       string          `json:"model"`
	Messages    []OpenAIMessage `json:"messages"`
	Temperature float64         `json:"temperature,omitempty"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Stop        []string        `json:"stop,omitempty"`
}

type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIResponse struct {
	Choices []OpenAIChoice `json:"choices"`
	Error   *OpenAIError   `json:"error,omitempty"`
}

type OpenAIChoice struct {
	Message OpenAIMessage `json:"message"`
}

type OpenAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

// Claude API structures
type ClaudeRequest struct {
	Model         string          `json:"model"`
	MaxTokens     int             `json:"max_tokens"`
	Messages      []ClaudeMessage `json:"messages"`
	Temperature   float64         `json:"temperature,omitempty"`
	StopSequences []string        `json:"stop_sequences,omitempty"`
}

type ClaudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ClaudeResponse struct {
	Content []ClaudeContent `json:"content"`
	Error   *ClaudeError    `json:"error,omitempty"`
}

type ClaudeContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type ClaudeError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// PromptData contains data for template rendering
type PromptData struct {
	Event map[string]interface{} `json:"event"`
}

func main() {
	// Parse command line flags
	var (
		redisURL         = flag.String("redis", "redis://localhost:6379", "Redis connection URL")
		consumerName     = flag.String("consumer", "llm-plugin", "Consumer name for Redis streams")
		apiKey           = flag.String("api-key", "", "LLM API key (required unless --dry-run)")
		apiProvider      = flag.String("provider", "openai", "LLM provider (openai or claude)")
		model            = flag.String("model", "gpt-3.5-turbo", "LLM model to use")
		temperature      = flag.Float64("temperature", 0.7, "Temperature for LLM generation (0.0-2.0)")
		maxTokens        = flag.Int("max-tokens", 500, "Maximum tokens for LLM response")
		stopWords        = flag.String("stop-words", "", "Comma-separated stop words")
		promptFile       = flag.String("prompt-file", "console-ir/plugins/llm/prompt_template.txt", "Path to prompt template file")
		dryRun           = flag.Bool("dry-run", false, "Return canned LLM response without network calls")
		dryRunResponse   = flag.String("dry-run-response", "", "Path to canned LLM response file (JSON or text)")
		openaiBaseURL    = flag.String("openai-base-url", "https://api.openai.com", "OpenAI API base URL")
		anthropicBaseURL = flag.String("anthropic-base-url", "https://api.anthropic.com", "Anthropic API base URL")
		retries          = flag.Int("retries", 2, "Retry attempts for transient LLM API errors (e.g., 429/5xx)")
		groupName        = flag.String("group", "console-ir-llm", "Redis consumer group name for events stream")
		_                = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	)
	flag.Parse()

	// Initialize logger (start with stdout so we can report failures creating the log file)
	var logger *log.Logger
	logger = log.New(os.Stdout, "[LLM] ", log.LstdFlags)
	logger.Println("Starting LLM enrichment plugin")
	
	// Ensure logs directory exists and write to both stdout and a log file
	if err := os.MkdirAll("./logs", 0755); err != nil {
		logger.Fatalf("failed to create logs directory: %v", err)
	}
	logFile, err := os.OpenFile("./logs/llm-plugin.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logger.Fatalf("failed to open log file: %v", err)
	}
	// Ensure the file is closed when main exits
	defer func() {
		_ = logFile.Close()
	}()
	mw := io.MultiWriter(os.Stdout, logFile)
	logger = log.New(mw, "[LLM] ", log.LstdFlags)
	logger.Println("Starting LLM enrichment plugin (logging to ./logs/llm-plugin.log)")
	
	// Resolve API key from env if not provided
	if *apiKey == "" {
		if envKey := os.Getenv("LLM_API_KEY"); envKey != "" {
			*apiKey = envKey
		}
	}
	// Validate required parameters (unless dry-run)
	if !*dryRun && *apiKey == "" {
		logger.Fatal("API key is required. Use -api-key flag or set LLM_API_KEY environment variable")
	}

	// Parse stop words
	var stopWordsList []string
	if *stopWords != "" {
		stopWordsList = strings.Split(*stopWords, ",")
		for i, word := range stopWordsList {
			stopWordsList[i] = strings.TrimSpace(word)
		}
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		logger.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	// Initialize plugin
	plugin := &LLMPlugin{
		logger:           logger,
		ctx:              ctx,
		cancel:           cancel,
		redisURL:         *redisURL,
		consumerName:     *consumerName,
		groupName:        *groupName,
		apiKey:           *apiKey,
		apiProvider:      *apiProvider,
		model:            *model,
		temperature:      *temperature,
		maxTokens:        *maxTokens,
		stopWords:        stopWordsList,
		promptFile:       *promptFile,
		dryRun:           *dryRun,
		dryRunResponse:   *dryRunResponse,
		openaiBaseURL:    *openaiBaseURL,
		anthropicBaseURL: *anthropicBaseURL,
		retries:          *retries,
	}

	// Load prompt template
	if err := plugin.loadPromptTemplate(); err != nil {
		logger.Fatalf("Failed to load prompt template: %v", err)
	}

	// Connect to Redis
	if err := plugin.connect(); err != nil {
		logger.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer plugin.client.Close()

	// Start processing
	logger.Println("Starting event processing...")
	if err := plugin.run(); err != nil {
		logger.Fatalf("Plugin error: %v", err)
	}

	logger.Println("LLM plugin stopped")
}

// loadPromptTemplate loads the prompt template from file
func (l *LLMPlugin) loadPromptTemplate() error {
	// Prefer the configured path, but fall back to known locations if missing
	if _, err := os.Stat(l.promptFile); os.IsNotExist(err) {
		// Try alternate locations relative to common CWDs
		alts := []string{
			"console-ir/plugins/llm/prompt_template.txt",
			"plugins/llm/prompt_template.txt",
			"./prompt_template.txt",
		}
		for _, p := range alts {
			if _, err2 := os.Stat(p); err2 == nil {
				l.logger.Printf("Prompt file %s not found; falling back to %s", l.promptFile, p)
				l.promptFile = p
				break
			}
		}
		// After fallbacks, if still missing, create default at the configured path
		if _, err3 := os.Stat(l.promptFile); os.IsNotExist(err3) {
			l.logger.Printf("Prompt file %s not found, creating default template", l.promptFile)
			if err := l.createDefaultPromptTemplate(); err != nil {
				return fmt.Errorf("failed to create default prompt template: %w", err)
			}
		}
	}

	// Read template file
	templateContent, err := os.ReadFile(l.promptFile)
	if err != nil {
		return fmt.Errorf("failed to read prompt template file: %w", err)
	}

	// Parse template
	tmpl, err := template.New("prompt").Parse(string(templateContent))
	if err != nil {
		return fmt.Errorf("failed to parse prompt template: %w", err)
	}

	l.promptTemplate = tmpl
	l.logger.Printf("Loaded prompt template from %s", l.promptFile)
	return nil
}

// createDefaultPromptTemplate creates a default prompt template file
func (l *LLMPlugin) createDefaultPromptTemplate() error {
	defaultTemplate := `Analyze the following security event and provide insights:

Event Type: {{.Event.activity_name}}
{{if .Event.src_endpoint}}Source IP: {{.Event.src_endpoint.ip}}{{end}}
{{if .Event.dst_endpoint}}Destination IP: {{.Event.dst_endpoint.ip}}{{end}}
{{if .Event.device}}Device: {{.Event.device.name}} ({{.Event.device.ip}}){{end}}
{{if .Event.actor}}Actor: {{.Event.actor.user.name}}{{end}}

Raw Event Data:
{{.Event | printf "%+v"}}

Please provide:
1. A brief summary of what happened
2. The security significance of this event
3. Recommended actions or investigation steps
4. Risk level (Low/Medium/High/Critical)

Format your response as structured JSON with the following fields:
- summary: Brief description of the event
- security_significance: Why this event is important from a security perspective
- recommended_actions: List of recommended actions
- risk_level: One of Low, Medium, High, or Critical
- confidence: Your confidence level in this analysis (0.0-1.0)`

	return os.WriteFile(l.promptFile, []byte(defaultTemplate), 0644)
}

// connect establishes connection to Redis
func (l *LLMPlugin) connect() error {
	opts, err := redis.ParseURL(l.redisURL)
	if err != nil {
		return fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	l.client = redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(l.ctx, 5*time.Second)
	defer cancel()

	if err := l.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to ping Redis: %w", err)
	}

	l.logger.Println("Connected to Redis")
	return nil
}

// run starts the main processing loop
func (l *LLMPlugin) run() error {
	// Create consumer group if it doesn't exist
	if err := l.createConsumerGroup(); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Attempt an initial reclaim of stale pending messages
	if err := l.reclaimOnce(60 * time.Second); err != nil {
		l.logger.Printf("Warning: initial pending reclaim failed: %v", err)
	}
	// Start periodic reclaim loop
	go l.reclaimPendingLoop(60*time.Second, 30*time.Second)

	// Start processing events
	return l.processEvents()
}

// reclaimOnce attempts to claim and process pending messages that have been idle for at least minIdle.
// Use a raw XAUTOCLAIM to tolerate both 2-element and 3-element replies across Redis versions.
func (l *LLMPlugin) reclaimOnce(minIdle time.Duration) error {
	start := "0-0"
	minIdleMs := int64(minIdle / time.Millisecond)

	for {
		// XAUTOCLAIM events <group> <consumer> <min-idle> <start> COUNT 10
		res := l.client.Do(l.ctx, "XAUTOCLAIM", "events", l.groupName, l.consumerName, minIdleMs, start, "COUNT", 10)
		if err := res.Err(); err != nil {
			return err
		}

		raw, err := res.Result()
		if err != nil {
			return err
		}

		reply, ok := raw.([]interface{})
		if !ok || len(reply) < 2 {
			return fmt.Errorf("unexpected XAUTOCLAIM reply: %#v", raw)
		}

		// First element is next-start cursor
		nextStart, _ := reply[0].(string)

		// Second element is the array of messages
		msgsRaw, _ := reply[1].([]interface{})
		if len(msgsRaw) == 0 {
			// No more pending messages to claim in this cycle
			break
		}

		l.logger.Printf("Reclaimed %d pending message(s) (start=%s next=%s)", len(msgsRaw), start, nextStart)

		// Parse each message: [id, [field, value, ...]]
		for _, m := range msgsRaw {
			tuple, _ := m.([]interface{})
			if len(tuple) != 2 {
				continue
			}
			id, _ := tuple[0].(string)
			fieldsArr, _ := tuple[1].([]interface{})

			values := make(map[string]interface{}, len(fieldsArr)/2)
			for i := 0; i+1 < len(fieldsArr); i += 2 {
				k, _ := fieldsArr[i].(string)
				v := fieldsArr[i+1]
				switch vv := v.(type) {
				case []byte:
					values[k] = string(vv)
				default:
					values[k] = fmt.Sprint(vv)
				}
			}

			msg := redis.XMessage{ID: id, Values: values}
			err := l.processMessage(msg)
			if err != nil {
				l.logger.Printf("Error processing reclaimed message %s: %v", msg.ID, err)
				
				// Check if this is a recoverable error
				if l.isRecoverableError(err) {
					l.logger.Printf("Recoverable error for reclaimed message %s, leaving unacknowledged for retry", msg.ID)
					continue
				} else {
					l.logger.Printf("Permanent error for reclaimed message %s, acknowledging to prevent infinite retries", msg.ID)
				}
			}
			if err := l.client.XAck(l.ctx, "events", l.groupName, msg.ID).Err(); err != nil {
				l.logger.Printf("Error acknowledging reclaimed message %s: %v", msg.ID, err)
			} else {
				l.logger.Printf("Acknowledged reclaimed message %s", msg.ID)
			}
		}

		// Advance the start cursor
		start = nextStart
		if nextStart == "0-0" {
			break
		}
	}
	return nil
}

// reclaimPendingLoop periodically attempts to reclaim and process stale pending messages.
func (l *LLMPlugin) reclaimPendingLoop(minIdle time.Duration, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			if err := l.reclaimOnce(minIdle); err != nil {
				l.logger.Printf("Pending reclaim error: %v", err)
			}
		}
	}
}
// createConsumerGroup creates the consumer group for the events stream
func (l *LLMPlugin) createConsumerGroup() error {
	result := l.client.XGroupCreateMkStream(l.ctx, "events", l.groupName, "0")
	if err := result.Err(); err != nil {
		// Ignore error if group already exists
		if !strings.Contains(err.Error(), "BUSYGROUP") {
			return err
		}
	}
	l.logger.Printf("Consumer group ready (%s)", l.groupName)
	return nil
}

// processEvents processes events from the Redis stream
func (l *LLMPlugin) processEvents() error {
	l.logger.Printf("Starting event consumer: %s", l.consumerName)

	for {
		select {
		case <-l.ctx.Done():
			l.logger.Println("Stopping event processing")
			return l.ctx.Err()
		default:
			if err := l.readAndProcessEvents(); err != nil {
				if l.ctx.Err() != nil {
					return l.ctx.Err()
				}
				l.logger.Printf("Error processing events: %v", err)
				time.Sleep(5 * time.Second) // Wait before retrying
			}
		}
	}
}

// readAndProcessEvents reads and processes events from the stream
func (l *LLMPlugin) readAndProcessEvents() error {
	// Read messages from the events stream
	result := l.client.XReadGroup(l.ctx, &redis.XReadGroupArgs{
		Group:    l.groupName,
		Consumer: l.consumerName,
		Streams:  []string{"events", ">"},
		Count:    5, // Process fewer events at once due to LLM API calls
		Block:    1 * time.Second,
	})

	if err := result.Err(); err != nil {
		if err == redis.Nil {
			return nil // No messages available
		}
		return err
	}

	// Process each message batch
	val := result.Val()
	totalMessages := 0
	for _, s := range val {
		totalMessages += len(s.Messages)
	}
	l.logger.Printf("Read %d message(s) from events", totalMessages)
	for _, stream := range val {
		for _, message := range stream.Messages {
			err := l.processMessage(message)
			if err != nil {
				l.logger.Printf("Error processing message %s: %v", message.ID, err)
				
				// Check if this is a recoverable error
				if l.isRecoverableError(err) {
					l.logger.Printf("Recoverable error for message %s, leaving unacknowledged for retry", message.ID)
					continue
				} else {
					l.logger.Printf("Permanent error for message %s, acknowledging to prevent infinite retries", message.ID)
				}
			}
	
			// Acknowledge the message (either success or permanent error)
			if err := l.client.XAck(l.ctx, "events", l.groupName, message.ID).Err(); err != nil {
				l.logger.Printf("Error acknowledging message %s: %v", message.ID, err)
			} else {
				l.logger.Printf("Acknowledged message %s", message.ID)
			}
		}
	}

	return nil
}

// processMessage processes a single event message
func (l *LLMPlugin) processMessage(message redis.XMessage) error {
	// Parse event message
	eventMsg := EventMessage{
		EventID:   getStringField(message.Values, "event_id"),
		EventType: getStringField(message.Values, "event_type"),
		RawJSON:   getStringField(message.Values, "raw_json"),
	}

	if timestamp := getStringField(message.Values, "timestamp"); timestamp != "" {
		if ts, err := strconv.ParseInt(timestamp, 10, 64); err == nil {
			eventMsg.Timestamp = ts
		}
	}

	l.logger.Printf("Processing event %s (type: %s)", eventMsg.EventID, eventMsg.EventType)

	// Parse event JSON for template rendering
	var eventData map[string]interface{}
	if err := json.Unmarshal([]byte(eventMsg.RawJSON), &eventData); err != nil {
		return fmt.Errorf("failed to parse event JSON: %w", err)
	}

	// Generate prompt from template
	prompt, err := l.generatePrompt(eventData)
	if err != nil {
		return fmt.Errorf("failed to generate prompt: %w", err)
	}
	// Log a short preview of the generated prompt for debugging (trim long prompts)
	promptPreview := prompt
	if len(promptPreview) > 1000 {
		promptPreview = promptPreview[:1000] + "...[truncated]"
	}
	l.logger.Printf("Generated prompt for event %s (len=%d): %q", eventMsg.EventID, len(prompt), promptPreview)
	
	// Call LLM API
	response, err := l.callLLMAPI(prompt)
	if err != nil {
		l.logger.Printf("LLM API call failed for event %s: %v", eventMsg.EventID, err)
		
		// Log whether this error will allow retries
		if l.isRecoverableError(err) {
			l.logger.Printf("Error is recoverable - event %s will be retried later", eventMsg.EventID)
		} else {
			l.logger.Printf("Error is permanent - event %s will be acknowledged and not retried", eventMsg.EventID)
		}
		
		return fmt.Errorf("LLM API call failed: %w", err)
	}
	// Log a short preview of the LLM response
	respPreview := response
	if len(respPreview) > 1000 {
		respPreview = respPreview[:1000] + "...[truncated]"
	}
	l.logger.Printf("Received LLM response for event %s (len=%d): %q", eventMsg.EventID, len(response), respPreview)
	
	// Extract structured data from response if possible
	enrichmentData := l.extractEnrichmentData(response)
	l.logger.Printf("Extracted %d enrichment field(s) from LLM response for event %s", len(enrichmentData), eventMsg.EventID)
	
	// Publish enrichment
	l.logger.Printf("Publishing enrichment for event %s with keys: %v", eventMsg.EventID, keysList(enrichmentData))
	return l.publishEnrichment(eventMsg.EventID, enrichmentData)
}

// generatePrompt generates a prompt from the template and event data
func (l *LLMPlugin) generatePrompt(eventData map[string]interface{}) (string, error) {
	var buf bytes.Buffer

	promptData := PromptData{
		Event: eventData,
	}

	if err := l.promptTemplate.Execute(&buf, promptData); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// callLLMAPI calls the configured LLM API
func (l *LLMPlugin) callLLMAPI(prompt string) (string, error) {
	// Dry-run mode: return canned response without network
	if l.dryRun {
		if l.dryRunResponse != "" {
			if b, err := os.ReadFile(l.dryRunResponse); err == nil {
				return string(b), nil
			} else {
				l.logger.Printf("dry-run: failed to read response file %s: %v, falling back to default", l.dryRunResponse, err)
			}
		}
		// Default canned JSON response embedded in text
		now := time.Now().Format(time.RFC3339)
		canned := fmt.Sprintf(`{"summary":"Auto-generated dry-run analysis","security_significance":"Simulated significance for testing","recommended_actions":["Isolate host","Block IP","Investigate user activity"],"risk_level":"Medium","confidence":0.9,"threat_type":"Simulation","context":"Dry-run at %s"}`, now)
		return canned, nil
	}

	switch strings.ToLower(l.apiProvider) {
	case "openai":
		return l.callOpenAI(prompt)
	case "claude":
		return l.callClaude(prompt)
	default:
		return "", fmt.Errorf("unsupported API provider: %s", l.apiProvider)
	}
}

// callOpenAI calls the OpenAI API
func (l *LLMPlugin) callOpenAI(prompt string) (string, error) {
	base := strings.TrimRight(l.openaiBaseURL, "/")
	url := base + "/v1/chat/completions"

	request := OpenAIRequest{
		Model: l.model,
		Messages: []OpenAIMessage{
			{Role: "user", Content: prompt},
		},
		Temperature: l.temperature,
		MaxTokens:   l.maxTokens,
	}
	if len(l.stopWords) > 0 {
		request.Stop = l.stopWords
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	attempts := l.retries + 1
	var lastErr error
	for i := 0; i < attempts; i++ {
		req, err := http.NewRequestWithContext(l.ctx, "POST", url, bytes.NewBuffer(requestBody))
		if err != nil {
			return "", fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+l.apiKey)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("HTTP request failed: %w", err)
		} else {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				lastErr = fmt.Errorf("failed to read response body: %w", readErr)
			} else if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
				// transient errors: retry
				lastErr = fmt.Errorf("API transient error status %d: %s", resp.StatusCode, string(body))
			} else if resp.StatusCode != http.StatusOK {
				return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
			} else {
				var response OpenAIResponse
				if err := json.Unmarshal(body, &response); err != nil {
					return "", fmt.Errorf("failed to unmarshal response: %w", err)
				}
				if response.Error != nil {
					return "", fmt.Errorf("API error: %s", response.Error.Message)
				}
				if len(response.Choices) == 0 {
					return "", fmt.Errorf("no choices in response")
				}
				return response.Choices[0].Message.Content, nil
			}
		}
		// Backoff before next attempt
		if i < attempts-1 {
			sleep := time.Duration(1<<i) * time.Second
			if sleep > 10*time.Second {
				sleep = 10 * time.Second
			}
			// Honor Retry-After if present and valid
			// Note: we don't have resp in network error case; skip then.
			time.Sleep(sleep)
		}
	}
	return "", fmt.Errorf("openai request failed after %d attempts: %v", attempts, lastErr)
}

// callClaude calls the Claude API
func (l *LLMPlugin) callClaude(prompt string) (string, error) {
	base := strings.TrimRight(l.anthropicBaseURL, "/")
	url := base + "/v1/messages"

	request := ClaudeRequest{
		Model:       l.model,
		MaxTokens:   l.maxTokens,
		Messages:    []ClaudeMessage{{Role: "user", Content: prompt}},
		Temperature: l.temperature,
	}
	if len(l.stopWords) > 0 {
		request.StopSequences = l.stopWords
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	attempts := l.retries + 1
	var lastErr error
	for i := 0; i < attempts; i++ {
		req, err := http.NewRequestWithContext(l.ctx, "POST", url, bytes.NewBuffer(requestBody))
		if err != nil {
			return "", fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", l.apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("HTTP request failed: %w", err)
		} else {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				lastErr = fmt.Errorf("failed to read response body: %w", readErr)
			} else if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
				lastErr = fmt.Errorf("API transient error status %d: %s", resp.StatusCode, string(body))
			} else if resp.StatusCode != http.StatusOK {
				return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
			} else {
				var response ClaudeResponse
				if err := json.Unmarshal(body, &response); err != nil {
					return "", fmt.Errorf("failed to unmarshal response: %w", err)
				}
				if response.Error != nil {
					return "", fmt.Errorf("API error: %s", response.Error.Message)
				}
				if len(response.Content) == 0 {
					return "", fmt.Errorf("no content in response")
				}
				return response.Content[0].Text, nil
			}
		}
		if i < attempts-1 {
			sleep := time.Duration(1<<i) * time.Second
			if sleep > 10*time.Second {
				sleep = 10 * time.Second
			}
			time.Sleep(sleep)
		}
	}
	return "", fmt.Errorf("claude request failed after %d attempts: %v", attempts, lastErr)
}

// extractEnrichmentData extracts structured data from LLM response
func (l *LLMPlugin) extractEnrichmentData(response string) map[string]string {
	enrichmentData := make(map[string]string)

	// Always store the raw response
	enrichmentData["llm_raw_response"] = response
	enrichmentData["llm_model"] = l.model
	enrichmentData["llm_provider"] = l.apiProvider
	enrichmentData["llm_timestamp"] = fmt.Sprintf("%d", time.Now().Unix())

	// Try to extract JSON from the response
	if jsonData := l.extractJSONFromResponse(response); jsonData != nil {
		for key, value := range jsonData {
			if str, ok := value.(string); ok {
				enrichmentData["llm_"+key] = str
			} else {
				// Convert other types to JSON string
				if jsonBytes, err := json.Marshal(value); err == nil {
					enrichmentData["llm_"+key] = string(jsonBytes)
				}
			}
		}
	}

	// Extract common patterns even if JSON parsing fails
	l.extractPatterns(response, enrichmentData)

	return enrichmentData
}

// extractJSONFromResponse attempts to extract JSON from the LLM response
func (l *LLMPlugin) extractJSONFromResponse(response string) map[string]interface{} {
	// Try to find JSON in the response
	jsonRegex := regexp.MustCompile(`\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}`)
	matches := jsonRegex.FindAllString(response, -1)

	for _, match := range matches {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(match), &data); err == nil {
			return data
		}
	}

	return nil
}

// extractPatterns extracts common patterns from the response using regex
func (l *LLMPlugin) extractPatterns(response string, enrichmentData map[string]string) {
	patterns := map[string]*regexp.Regexp{
		"risk_level":     regexp.MustCompile(`(?i)risk\s*level[:\s]*([a-zA-Z]+)`),
		"confidence":     regexp.MustCompile(`(?i)confidence[:\s]*([0-9.]+)`),
		"threat_type":    regexp.MustCompile(`(?i)threat\s*type[:\s]*([a-zA-Z\s]+)`),
		"severity":       regexp.MustCompile(`(?i)severity[:\s]*([a-zA-Z]+)`),
		"recommendation": regexp.MustCompile(`(?i)recommend(?:ation|ed)[:\s]*([^.]+)`),
	}

	for key, pattern := range patterns {
		if matches := pattern.FindStringSubmatch(response); len(matches) > 1 {
			enrichmentData["llm_"+key] = strings.TrimSpace(matches[1])
		}
	}
}

// publishEnrichment publishes enrichment data to Redis
func (l *LLMPlugin) publishEnrichment(eventID string, data map[string]string) error {
	enrichment := EnrichmentMessage{
		EventID:    eventID,
		Source:     "llm",
		Type:       "llm_analysis",
		Data:       data,
		Timestamp:  time.Now().Unix(),
		PluginName: "llm-plugin",
	}

	// Serialize data
	dataJSON, err := json.Marshal(enrichment.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal enrichment data: %w", err)
	}

	// Publish to enrichments stream
	fields := map[string]interface{}{
		"event_id":    enrichment.EventID,
		"source":      enrichment.Source,
		"type":        enrichment.Type,
		"data":        string(dataJSON),
		"timestamp":   enrichment.Timestamp,
		"plugin_name": enrichment.PluginName,
	}
	// Log payload size and number of fields for debugging
	l.logger.Printf("Publishing enrichment for event %s: payload_bytes=%d field_count=%d", eventID, len(dataJSON), len(enrichment.Data))
	
	result := l.client.XAdd(l.ctx, &redis.XAddArgs{
		Stream: "enrichments",
		Values: fields,
	})
	
	if err := result.Err(); err != nil {
		return fmt.Errorf("failed to publish enrichment: %w", err)
	}
	
	l.logger.Printf("Published LLM enrichment for event %s", eventID)
	return nil
}

// isRecoverableError determines if an error is recoverable and should allow message retry
func (l *LLMPlugin) isRecoverableError(err error) bool {
	if err == nil {
		return false
	}
	
	errStr := strings.ToLower(err.Error())
	
	// API authentication/authorization errors - should be retried in case keys are fixed
	if strings.Contains(errStr, "invalid_api_key") ||
		strings.Contains(errStr, "incorrect api key") ||
		strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "401") {
		return true
	}
	
	// Rate limiting - should be retried later
	if strings.Contains(errStr, "too many requests") ||
		strings.Contains(errStr, "rate limit") ||
		strings.Contains(errStr, "429") {
		return true
	}
	
	// Server errors - should be retried
	if strings.Contains(errStr, "internal server error") ||
		strings.Contains(errStr, "service unavailable") ||
		strings.Contains(errStr, "bad gateway") ||
		strings.Contains(errStr, "gateway timeout") ||
		strings.Contains(errStr, "500") ||
		strings.Contains(errStr, "502") ||
		strings.Contains(errStr, "503") ||
		strings.Contains(errStr, "504") {
		return true
	}
	
	// Network/connection errors - should be retried
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "network") ||
		strings.Contains(errStr, "dns") {
		return true
	}
	
	// Context cancellation (shutdown) - don't retry
	if strings.Contains(errStr, "context canceled") ||
		strings.Contains(errStr, "context deadline exceeded") {
		return false
	}
	
	// JSON parsing errors, template errors, etc. are permanent
	if strings.Contains(errStr, "json") ||
		strings.Contains(errStr, "template") ||
		strings.Contains(errStr, "marshal") ||
		strings.Contains(errStr, "unmarshal") {
		return false
	}
	
	// Default: treat unknown errors as recoverable to be safe
	return true
}

// Helper functions

// keysList returns a sorted list of keys for logging/debugging
func keysList(m map[string]string) []string {
	if m == nil {
		return []string{}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func getStringField(values map[string]interface{}, key string) string {
	if value, ok := values[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}
