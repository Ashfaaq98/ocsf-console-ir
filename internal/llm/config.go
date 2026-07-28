package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ProviderConfig defines runtime-selectable LLM provider settings.
type ProviderConfig struct {
	Provider string            `json:"provider"` // "ollama" | "openrouter" | "groq" | "synthetic"
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
		case "groq":
			s.Active.Endpoint = "https://api.groq.com/openai/v1"
		case "synthetic":
			s.Active.Endpoint = "https://api.synthetic.new/openai/v1"
		}
	}
	if s.Active.Model == "" && s.Active.Provider == "ollama" {
		s.Active.Model = "qwen3:0.6b"
	}
	if s.Active.Extra == nil {
		s.Active.Extra = map[string]string{}
	}

	// VULN-1: Prefer API key from environment variable over file
	if envKey := os.Getenv("CONSOLE_IR_LLM_API_KEY"); envKey != "" {
		s.Active.APIKey = envKey
	}

	// VULN-5: Validate endpoint to prevent SSRF
	if err := ValidateEndpoint(s.Active.Endpoint); err != nil {
		return Settings{}, fmt.Errorf("invalid LLM endpoint: %w", err)
	}

	return s, nil
}

// SaveSettings saves settings to the given path, creating parent directories if needed.
func SaveSettings(path string, s Settings) error {
	if path == "" {
		return errors.New("empty settings path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mk settings dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write settings: %w", err)
	}
	return nil
}

// blockedHosts are cloud metadata endpoints that must never be used as LLM endpoints.
var blockedHosts = []string{
	"169.254.169.254",
	"metadata.google.internal",
	"metadata.internal",
}

// ValidateEndpoint checks that an LLM endpoint URL is safe, preventing SSRF.
// It allows HTTPS endpoints and plain HTTP only for localhost.
func ValidateEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil // empty is OK, a default will be chosen
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("cannot parse URL: %w", err)
	}
	host := strings.ToLower(u.Hostname())

	// Block known cloud metadata endpoints
	for _, blocked := range blockedHosts {
		if host == blocked {
			return fmt.Errorf("endpoint host %q is blocked (cloud metadata)", host)
		}
	}

	// Allow HTTPS anywhere, HTTP only for localhost
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("HTTP endpoints only allowed for localhost; use HTTPS for %q", host)
	default:
		return fmt.Errorf("unsupported scheme %q; use http or https", u.Scheme)
	}
}
