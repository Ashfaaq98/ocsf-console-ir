package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ProviderConfig defines runtime-selectable LLM provider settings.
type ProviderConfig struct {
	Provider string            `json:"provider"` // "local_stub" | "ollama" | future providers
	Endpoint string            `json:"endpoint"` // e.g., "http://localhost:11434" (for Ollama)
	Model    string            `json:"model"`    // e.g., "qwen3:0.6b"
	APIKey   string            `json:"api_key"`  // optional for cloud providers
	Extra    map[string]string `json:"extra"`    // provider-specific settings
}

// Settings is the persisted LLM settings state.
type Settings struct {
	Active ProviderConfig `json:"active"`
}

// DefaultSettings returns a sane default targeting a local Ollama install with qwen3:0.6b.
func DefaultSettings() Settings {
	return Settings{
		Active: ProviderConfig{
			Provider: "ollama",
			Endpoint: "http://localhost:11434",
			Model:    "qwen3:0.6b",
			APIKey:   "",
			Extra:    map[string]string{},
		},
	}
}

// LoadSettings loads settings from the given path. If the file does not exist,
// DefaultSettings() are returned. Any read/parse error (other than not-exist)
// is returned.
func LoadSettings(path string) (Settings, error) {
	if path == "" {
		return Settings{}, errors.New("empty settings path")
	}
	// If file does not exist, return defaults (do not create file here).
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return DefaultSettings(), nil
		}
		return Settings{}, fmt.Errorf("stat settings file: %w", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Settings{}, fmt.Errorf("read settings file: %w", err)
	}
	var s Settings
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}, fmt.Errorf("unmarshal settings: %w", err)
	}
	// Minimal validation/fallbacks
	if s.Active.Provider == "" {
		s.Active.Provider = "ollama"
	}
	if s.Active.Endpoint == "" {
		switch s.Active.Provider {
		case "ollama":
			s.Active.Endpoint = "http://localhost:11434"
		case "openrouter":
			s.Active.Endpoint = "https://openrouter.ai/api/v1"
		}
	}
	if s.Active.Model == "" && s.Active.Provider == "ollama" {
		s.Active.Model = "qwen3:0.6b"
	}
	if s.Active.Extra == nil {
		s.Active.Extra = map[string]string{}
	}
	return s, nil
}

// SaveSettings saves settings to the given path, creating parent directories if needed.
func SaveSettings(path string, s Settings) error {
	if path == "" {
		return errors.New("empty settings path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mk settings dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write settings: %w", err)
	}
	return nil
}