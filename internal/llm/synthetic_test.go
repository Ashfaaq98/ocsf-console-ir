package llm

import (
	"context"
	"testing"
)

func TestSyntheticProvider(t *testing.T) {
	// Test NewSynthetic with API key
	apiKey := "test-key-12345"
	endpoint := "https://api.synthetic.new/openai/v1"
	model := "gpt-3.5-turbo"

	provider, err := NewSynthetic(endpoint, model, apiKey, nil)
	if err != nil {
		t.Fatalf("NewSynthetic failed: %v", err)
	}

	if provider == nil {
		t.Fatal("Provider should not be nil")
	}

	if provider.endpoint != "https://api.synthetic.new/openai/v1" {
		t.Errorf("Expected endpoint https://api.synthetic.new/openai/v1, got %s", provider.endpoint)
	}

	if provider.model != model {
		t.Errorf("Expected model %s, got %s", model, provider.model)
	}

	if provider.apiKey != apiKey {
		t.Errorf("Expected apiKey %s, got %s", apiKey, provider.apiKey)
	}
}

func TestSyntheticProviderDefaultEndpoint(t *testing.T) {
	// Test NewSynthetic with default endpoint
	apiKey := "test-key"
	model := "gpt-3.5-turbo"

	provider, err := NewSynthetic("", model, apiKey, nil)
	if err != nil {
		t.Fatalf("NewSynthetic failed: %v", err)
	}

	if provider.endpoint != "https://api.synthetic.new/openai/v1" {
		t.Errorf("Expected default endpoint https://api.synthetic.new/openai/v1, got %s", provider.endpoint)
	}
}

func TestSyntheticProviderNoAPIKey(t *testing.T) {
	// Test NewSynthetic without API key should fail
	t.Setenv("SYNTHETIC_API_KEY", "")
	_, err := NewSynthetic("https://api.synthetic.new/openai/v1", "gpt-3.5-turbo", "", nil)
	if err == nil {
		t.Fatal("Expected error when creating Synthetic provider without API key")
	}
}

func TestBuildSyntheticProvider(t *testing.T) {
	// Test building Synthetic provider through registry
	cfg := ProviderConfig{
		Provider: "synthetic",
		Endpoint: "https://api.synthetic.new/openai/v1",
		Model:    "gpt-3.5-turbo",
		APIKey:   "test-key",
	}

	provider, err := Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if provider == nil {
		t.Fatal("Provider should not be nil")
	}

	// Verify it's the right type
	if _, ok := provider.(*Synthetic); !ok {
		t.Fatalf("Expected *Synthetic provider, got %T", provider)
	}
}

func TestSyntheticEstimateTokens(t *testing.T) {
	provider, err := NewSynthetic("", "gpt-3.5-turbo", "test-key", nil)
	if err != nil {
		t.Fatalf("NewSynthetic failed: %v", err)
	}

	text := "Hello, world!"
	tokens := provider.EstimateTokens(text)
	if tokens <= 0 {
		t.Errorf("Expected positive token count, got %d", tokens)
	}
}
