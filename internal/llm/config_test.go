package llm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Test that DefaultSettings returns sane Ollama defaults.
func TestDefaultSettings(t *testing.T) {
	s := DefaultSettings()
	if s.Active.Provider != "ollama" {
		t.Fatalf("expected default provider=ollama, got %q", s.Active.Provider)
	}
	if s.Active.Endpoint == "" {
		t.Fatalf("expected default ollama endpoint non-empty")
	}
	if s.Active.Model == "" {
		t.Fatalf("expected default ollama model non-empty")
	}
}

// Test that SaveSettings persists and LoadSettings restores, including API key.
func TestSaveLoadSettingsWithAPIKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "llm_settings.json")

	orig := Settings{
		Active: ProviderConfig{
			Provider: "openrouter",
			Endpoint: "https://openrouter.ai/api/v1",
			Model:    "qwen/qwen-2.5-7b-instruct",
			APIKey:   "secret-key",
			Extra:    map[string]string{"note": "test"},
		},
	}
	if err := SaveSettings(path, orig); err != nil {
		t.Fatalf("SaveSettings error: %v", err)
	}
	got, err := LoadSettings(path)
	if err != nil {
		t.Fatalf("LoadSettings error: %v", err)
	}
	if got.Active.Provider != orig.Active.Provider {
		t.Errorf("provider mismatch: got %q want %q", got.Active.Provider, orig.Active.Provider)
	}
	if got.Active.Endpoint != orig.Active.Endpoint {
		t.Errorf("endpoint mismatch: got %q want %q", got.Active.Endpoint, orig.Active.Endpoint)
	}
	if got.Active.Model != orig.Active.Model {
		t.Errorf("model mismatch: got %q want %q", got.Active.Model, orig.Active.Model)
	}
	if got.Active.APIKey != orig.Active.APIKey {
		t.Errorf("api_key mismatch: got %q want %q", got.Active.APIKey, orig.Active.APIKey)
	}
	if got.Active.Extra["note"] != "test" {
		t.Errorf("extra[note] mismatch: got %q", got.Active.Extra["note"])
	}
}

// Test that LoadSettings applies provider-specific default endpoints when endpoint is empty.
// For openrouter: https://openrouter.ai/api/v1
// For ollama: http://localhost:11434
func TestLoadSettingsDefaultEndpoints(t *testing.T) {
	dir := t.TempDir()

	// Case 1: openrouter with empty endpoint
	orPath := filepath.Join(dir, "openrouter.json")
	orSettings := Settings{
		Active: ProviderConfig{
			Provider: "openrouter",
			Endpoint: "",
			Model:    "any",
			APIKey:   "",
		},
	}
	writeJSON(t, orPath, orSettings)
	got, err := LoadSettings(orPath)
	if err != nil {
		t.Fatalf("LoadSettings(openrouter) error: %v", err)
	}
	if got.Active.Endpoint != "https://openrouter.ai/api/v1" {
		t.Errorf("expected openrouter default endpoint, got %q", got.Active.Endpoint)
	}

	// Case 2: ollama with empty endpoint and model
	olPath := filepath.Join(dir, "ollama.json")
	olSettings := Settings{
		Active: ProviderConfig{
			Provider: "ollama",
			Endpoint: "",
			Model:    "",
			APIKey:   "",
		},
	}
	writeJSON(t, olPath, olSettings)
	got2, err := LoadSettings(olPath)
	if err != nil {
		t.Fatalf("LoadSettings(ollama) error: %v", err)
	}
	if got2.Active.Endpoint != "http://localhost:11434" {
		t.Errorf("expected ollama default endpoint, got %q", got2.Active.Endpoint)
	}
	if got2.Active.Model == "" {
		t.Errorf("expected ollama default model to be set")
	}
}

// Test that LoadSettings returns defaults when file does not exist.
func TestLoadSettingsMissingFileReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does_not_exist.json")
	got, err := LoadSettings(path)
	if err != nil {
		t.Fatalf("LoadSettings missing file returned error: %v", err)
	}
	if got.Active.Provider == "" {
		t.Fatalf("expected defaults when file missing")
	}
}

// Helper to write JSON settings to a file.
func writeJSON(t *testing.T, path string, v interface{}) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}